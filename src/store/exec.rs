//! Running a backend's CLI and getting its bytes back, with a deadline.
//!
//! Every store in this crate is a process, not a library. That is deliberate —
//! see the note in [`keychain`](super::keychain) — and it means every store
//! needs the same three things: spawn, wait with a bound, and turn a failure
//! into a sentence that cannot contain a value.
//!
//! # Why the deadline is not optional, for every store
//!
//! `Command::output` waits forever and reads without a bound. A network-backed
//! store hits that first — a black-holed TCP connection, a captive portal that
//! accepts the SYN and answers nothing, an auth server rewriting a token — but
//! **a local store is not exempt, and assuming it was is how the keychain
//! adapter spent its whole life without a deadline.**
//!
//! The binary a store runs is a path in a config file, not a system guarantee.
//! Measured 2026-08-08 against a `security` stand-in: one that sleeps hangs
//! `keyless run` indefinitely with no child and no message, and one that copies
//! `/dev/zero` to its stdout reaches 2.7 GB resident in twelve seconds and ends
//! as an out-of-memory kill. Neither needs a compromised system tool and neither
//! is slower to arrange than the network case.
//!
//! Without a bound, `keyless run` stops being a wrapper and becomes the reason
//! the terminal is hung — and a tool that hangs gets removed, which is the
//! failure this whole project exists to avoid.
//!
//! So a lookup that runs out of time is **degraded, never fatal**: the caller
//! gets an error describing the timeout, the resolver records the name as
//! unresolved, and `run` spawns the child anyway with an unmodified environment.
//!
//! # Why stdout never reaches an error message
//!
//! stdout is where a value comes from. Every function here that builds a
//! human-readable detail builds it from **stderr only**, and every path that
//! abandons a captured stdout zeroizes it first.

use std::io;
use std::io::Write as _;
use std::os::fd::AsFd as _;
use std::process::{ChildStdin, Command, Stdio};

use crate::error::StoreError;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use zeroize::Zeroize;

/// How much of a backend's stderr is quoted in an error. Enough to diagnose,
/// short enough not to paste a wall of text into an agent's transcript.
pub const MAX_DETAIL: usize = 200;

/// Serialises the act of creating a child, and nothing else.
///
/// # The race this closes, measured rather than assumed
///
/// A `Command` with piped stdio creates its pipes and execs inside one call.
/// Two threads doing that at the same time can have one child inherit the other
/// child's pipe **write** end before it is closed — and a pipe reaches
/// end-of-file only when the last writer closes it. The reader then waits for an
/// end that never comes.
///
/// It is a deadlock, not a slowdown. Measured 2026-08-08 in this crate's own
/// test binary: eleven keychain tests take **0.97 s** with `--test-threads=1`
/// and **hit every deadline** with `--test-threads=4` — five of them, at ten and
/// thirty seconds, on stubs that do nothing but `printf` and exit.
///
/// This became `keyless run`'s problem the moment a run started resolving its
/// names concurrently (see [`crate::cmd::run::resolve_all`]). One thread per
/// name, each spawning a vendor CLI, is exactly the shape above.
///
/// The lock is held across `spawn` and released before the wait, so lookups
/// still overlap: what is serialised is the interval in which a child's
/// descriptors are visible to another `fork`, never the wait for an answer.
/// [`spawn_persistently`] is the only thing that takes it, and the only thing
/// in this crate that creates a process.
///
/// # The gate is short. The QUEUE behind it is not, and that is a different
/// quantity
///
/// One `spawn` costs a fraction of a millisecond on an idle machine, which
/// makes it tempting to call the cost of this lock negligible. It is not, and
/// the arithmetic says why: a lookup's wait here is roughly the number of
/// lookups ahead of it multiplied by what a spawn costs, and BOTH terms grow
/// together on a loaded machine — more concurrency, and each spawn slower
/// because the child it is waiting to see exec cannot get the CPU.
///
/// Measured under a saturated CPU quota, at the concurrency a suite reaches:
/// the queue is the MAJORITY of a lookup's elapsed time, and against a short
/// deadline it exceeds the whole budget on its own. That is not an argument
/// against the lock — it closes a deadlock, and a deadlock has no upper bound
/// at all — but it is the reason [`CaptureError::TimedOut`] reports the queue
/// separately instead of charging it to the backend.
static SPAWNING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// How many times to try again when the machine, not the command, said no.
///
/// Five attempts with [`SPAWN_BACKOFF`] doubling between them spans at most
/// 150 ms of contention. That is the number the guards in this module's tests
/// assert against, so lowering it turns a named test red rather than passing
/// silently.
const SPAWN_ATTEMPTS: u32 = 5;

/// The longest wait before the FIRST retry. Every later wait doubles it.
///
/// **A retry with no wait is a busy-wait, and against a process limit it is
/// worse than one.** `RLIMIT_NPROC` is counted per user, so twenty concurrent
/// agent sessions hit it together and would then re-fork together — the
/// thundering herd the limit exists to prevent. Doubling spreads them out over
/// time, and [`jittered`] spreads them apart from each other.
const SPAWN_BACKOFF: Duration = Duration::from_millis(10);

/// One wait of the backoff schedule, moved by an amount nobody else draws.
///
/// # Why a schedule alone is not enough
///
/// Doubling spreads a herd over TIME; it does not spread its members apart from
/// EACH OTHER. Twenty sessions refused in the same instant retry at the same
/// four instants, so every one of their four chances is spent contending with
/// the same nineteen peers. What each process needs is four samples of the slot
/// count taken at moments no sibling picked, which is what a per-wait random
/// offset buys.
///
/// # Equal jitter, and why not the other two
///
/// The wait is `backoff/2 + U[0, backoff/2)`.
///
/// - **Full jitter** — `U[0, backoff)` — can draw a wait of nearly zero, which
///   re-creates the busy-wait [`SPAWN_BACKOFF`] exists to prevent. A floor is
///   not an optimisation here; it is the property the constant is for.
/// - **Backoff plus up to half** — `backoff + U[0, backoff/2)` — never shortens
///   a wait, but stretches the worst-case window from 150 ms to 225 ms. The
///   window is a stall a user waits through, so growing it is the wrong
///   direction to spend dispersal in.
///
/// Equal jitter keeps a floor AND keeps 150 ms as the ceiling it always was.
///
/// # Where the randomness comes from, and why not a crate or a pid
///
/// The wall clock's nanosecond field, read fresh at every wait. It is the one
/// quantity that already differs between the processes this is dispersing:
/// two sessions refused "in the same millisecond" are still microseconds apart,
/// and each of a process's own waits draws again from a clock that has moved.
/// Measured 2026-08-09 on macOS: `CLOCK_REALTIME` advances in steps of 1 µs, so
/// the smallest span used here — 5 ms — has 5000 distinct values to land on.
///
/// `10^9` is an exact multiple of every half-backoff in this schedule, so the
/// `%` is unbiased for the values actually shipped. It is a scheduling nudge
/// rather than a secret, so a residual bias would cost nothing anyway — which is
/// precisely the reason this does NOT live in [`crate::random`]. That module's
/// contract is "unpredictable to an attacker", and diluting it with a caller
/// that does not need unpredictability is how a credential generator quietly
/// acquires a second, weaker purpose.
///
/// A random-number crate is refused for the same reason [`crate::random`]
/// refuses one: a dependency in the trusted path of a secrets tool has to earn
/// itself, and five lines of arithmetic do not let it.
///
/// **A process id is not a source, and it was the obvious candidate.** It is
/// constant for the life of the process, so it shifts every wait by the same
/// amount and two processes that collide once collide at every step — the exact
/// correlation this removes. It is allocated sequentially on Linux, so a burst
/// of sessions gets ADJACENT pids and a small modulus maps them to adjacent
/// offsets, preserving the clustering. And it restarts at 1 in every container.
fn jittered(backoff: Duration) -> Duration {
    let half = backoff / 2;
    let span = u64::try_from(half.as_nanos()).unwrap_or(u64::MAX);
    if span == 0 {
        // A backoff too small to halve. Jitter would be a rounding error, and
        // the honest answer is the schedule's own wait.
        return backoff;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::from(since.subsec_nanos()));
    half + Duration::from_nanos(nanos % span)
}

/// Whether a spawn failure says "not right now" rather than "not ever".
///
/// `EAGAIN` and `EWOULDBLOCK` are the same number on the platforms this builds
/// for, and std maps it to `WouldBlock`. The raw check is kept beside it so a
/// platform where they differ still retries.
///
/// One function rather than an inline guard, so the test that feeds it a real
/// `fork` errno and the loop that acts on it cannot classify differently.
fn out_of_process_slots(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(nix::libc::EAGAIN)
}

/// Spawn, retrying while the OS is merely out of process slots.
///
/// `EAGAIN` from `fork` means "not right now", never "not ever": the caller is
/// at `RLIMIT_NPROC` and the count drops as soon as anything exits — including
/// the store subprocesses a run has just finished with. Measured 2026-08-08
/// under `RLIMIT_NPROC` of 128, 256 and 512: `keyless run` exited 127 with no
/// child where a fork-depth-matched control shell exited 42. One retry loop
/// closes the whole of that gap, because the condition is transient by
/// definition and this process is not the one holding the slots.
///
/// Bounded rather than unbounded: a limit of 0, or a machine genuinely out of
/// processes, must end as a reported failure and not as a spin.
///
/// # `until`
///
/// The instant past which retrying is no longer this caller's time to spend, or
/// `None` when the caller has no deadline of its own.
///
/// `keyless run`'s own child passes `None`: reaching the spawn IS that call's
/// contract and nothing else is waiting on it. A store lookup passes the
/// deadline it is already running under, because a lookup that spends its whole
/// budget retrying the spawn converts one degrade into a differently-shaped one
/// — and "the process table was full" and "the backend never answered" are the
/// same `DEGRADED` banner to the user and different bugs to whoever reads it.
/// With the default 10 s lookup deadline the whole schedule is 1.5% of the
/// budget and never reaches this clause; with a `timeout_ms` configured shorter
/// than the schedule, the retry stops early and the caller still sees the
/// kernel's own refusal rather than a timeout this loop caused.
///
/// # The one place this crate creates a process
///
/// `command.spawn()` appears here and nowhere else in `src/`, and that is a
/// property worth keeping rather than a coincidence. A second call site would be
/// a spawn with no retry and no [`SPAWNING`] guard, and neither absence shows up
/// as a failure until a machine is under the load that produces both — where the
/// symptom is a lookup that degrades for no visible reason. There was a
/// `spawn_serialised` helper next to this function until 2026-08-09; it existed
/// so a caller could take the mutex without the retry, which is exactly the door
/// that should not exist.
pub fn spawn_persistently(
    command: &mut Command,
    until: Option<Instant>,
) -> io::Result<std::process::Child> {
    persisting(
        || {
            // Held across `spawn` and released before the wait, so lookups still
            // overlap — and re-taken per ATTEMPT, so a retry cannot hold the gate
            // shut across its own backoff.
            //
            // A poisoned lock is ignored: the mutex guards no data, only an
            // interval, so a panic elsewhere has left nothing inconsistent to
            // protect.
            let _guard = SPAWNING
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            command.spawn()
        },
        thread::sleep,
        until,
    )
}

/// The retry itself, with the spawn and the wait handed in.
///
/// # Why this is a separate function
///
/// **A `fork` cannot be made to return `EAGAIN` on demand.** Reaching the real
/// condition means driving the machine to `RLIMIT_NPROC`, which is counted per
/// USER — so a test that did it would take down every other process the user is
/// running, including the rest of the suite. There is no bounded, safe way to
/// exercise this loop through a real `Command`.
///
/// Without a seam the loop is therefore untestable, and it was: changing
/// [`SPAWN_ATTEMPTS`] from 5 to 1 left the whole suite green. That is a
/// never-block guard nothing was holding — a spawn that gives up on the first
/// `EAGAIN` turns a transient resource limit into a dead command, which is the
/// one outcome `keyless run`'s contract forbids.
///
/// The budget is deliberately NOT a parameter. It reads [`SPAWN_ATTEMPTS`] and
/// [`SPAWN_BACKOFF`] directly, so a test exercises the shipped numbers rather
/// than numbers of its own, and a mutation of either constant reaches the
/// assertions. `until` is a different thing and IS a parameter: it is a fact
/// about the caller, not a policy of this loop.
///
/// `pause` is handed in for the same reason a real fork is not: a test that
/// slept the real schedule would spend 150 ms proving something it can prove by
/// recording it, and it could not assert on a wait it did not observe.
fn persisting<T>(
    mut spawn: impl FnMut() -> io::Result<T>,
    mut pause: impl FnMut(Duration),
    until: Option<Instant>,
) -> io::Result<T> {
    let mut backoff = SPAWN_BACKOFF;
    let mut last = None;
    for attempt in 0..SPAWN_ATTEMPTS {
        match spawn() {
            Ok(child) => return Ok(child),
            Err(error) if out_of_process_slots(&error) => {
                last = Some(error);
                if attempt + 1 == SPAWN_ATTEMPTS {
                    break;
                }
                let wait = jittered(backoff);
                // Subtraction rather than `deadline > now + wait`: `Instant +
                // Duration` PANICS on overflow, and this crate's release profile
                // sets `panic = "abort"` — the same trap `deadline_for` exists
                // to keep out of this file.
                if let Some(deadline) = until
                    && wait >= deadline.saturating_duration_since(Instant::now())
                {
                    // Spending the caller's last milliseconds here would end as
                    // a deadline this loop blew rather than as the refusal the
                    // kernel gave, which names the wrong repair.
                    break;
                }
                pause(wait);
                backoff *= 2;
            }
            // Not about the machine. Retrying a command that does not exist
            // only delays the report.
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("the process could not be started")))
}

/// How long to wait for a killed child to be reaped before giving up on it.
///
/// `SIGKILL` cannot be caught, so the process itself is already gone. What can
/// still take a moment is the read side draining: a grandchild that inherited
/// the pipe keeps it open until it exits too. Waiting a little avoids leaving a
/// zombie; not waiting forever is the whole point of being here.
const REAP_GRACE: Duration = Duration::from_secs(2);

/// What a backend process produced.
pub struct Captured {
    /// The child's exit status.
    pub status: std::process::ExitStatus,
    /// The child's stdout. May contain a plaintext value — hand it to
    /// `Secret::from_bytes`, which zeroizes it, rather than reading it twice.
    pub stdout: Vec<u8>,
    /// The child's stderr. Never contains a value on any path this crate uses.
    pub stderr: Vec<u8>,
}

impl std::fmt::Debug for Captured {
    /// Hand-written, and it must stay that way.
    ///
    /// `stdout` is where a plaintext value arrives, so a derived `Debug` would
    /// print a credential the first time anything used `{:?}` — an `assert!`
    /// message, an `expect`, a `dbg!` left in by accident. Only the length is
    /// shown, which is metadata rather than content.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Captured")
            .field("status", &self.status)
            .field(
                "stdout",
                &format_args!("<redacted, {} bytes>", self.stdout.len()),
            )
            .field("stderr", &String::from_utf8_lossy(&self.stderr))
            .finish()
    }
}

impl Drop for Captured {
    fn drop(&mut self) {
        // The success path moves `stdout` out before dropping. This covers
        // every other path — an early return, a `?`, a panic — so a value that
        // was read and then abandoned is not left on the heap.
        self.stdout.zeroize();
    }
}

/// Why a backend process produced nothing usable.
#[derive(Debug)]
pub enum CaptureError {
    /// The binary could not be started: absent, not executable, bad path.
    Spawn(io::Error),
    /// The deadline expired and the child was killed.
    ///
    /// # Why this carries two durations and not one
    ///
    /// One budget covers two different things: getting permission to create a
    /// child — [`SPAWNING`] serialises that across the whole process — and then
    /// waiting for the child to answer. The clock starts before the first, so
    /// time spent queued behind another lookup's spawn is charged to this one.
    ///
    /// Reported as a single number, that reads as a statement about the
    /// BACKEND: `no answer within N ms` says the backend was given N
    /// milliseconds and did not use them. It can be false in the worst way — a
    /// lookup whose whole budget went to the queue creates its child with
    /// nothing left, kills it in the same breath, and blames it for a silence
    /// it was never given time to break. Measured under a saturated CPU quota,
    /// with the concurrency a suite reaches: a majority of every lookup's
    /// elapsed time is queue, and at a short budget the queue alone exceeds the
    /// whole of it.
    ///
    /// That is the class this repository spends its effort on — a fault
    /// reported as the wrong fault — and it has a repair the reader cannot
    /// guess from the sentence, because "the machine is oversubscribed" and
    /// "the backend is not answering" send them to different places.
    ///
    /// So the split is carried and rendered: `starting` is how much of `budget`
    /// was gone before the child existed. It is rendered in milliseconds like
    /// the budget beside it, and the clause appears exactly when it is non-zero
    /// AT THAT RESOLUTION — no threshold, and nothing to tune. An uncontended
    /// spawn costs far less than a millisecond and reads exactly as it always
    /// did; contention makes itself visible in the one message a reader is
    /// already looking at.
    TimedOut {
        /// The whole deadline the caller asked for.
        budget: Duration,
        /// How much of `budget` was spent before the child existed.
        starting: Duration,
    },
    /// The child started but its output could not be collected.
    Collect(io::Error),
    /// The operating system refused a thread.
    ///
    /// A separate variant rather than a `panic`, and that is the whole reason it
    /// exists. `thread::spawn` panics when the OS says no — a process limit, a
    /// thread limit, exhausted address space — and this crate's release profile
    /// sets `panic = "abort"`, so a panic here is an immediate abort with no
    /// child, no exit code and no message. Every lookup on the Infisical and
    /// Proton paths goes through here, which puts that abort **before** the
    /// spawn `keyless run` promises always to reach.
    Threads(io::Error),
    /// The backend produced more than [`MAX_CAPTURE_BYTES`] on one stream.
    ///
    /// A separate variant rather than a truncated success, because the bytes are
    /// a PREFIX of what a backend produced — which is exactly the shape a
    /// truncated credential has, and handing one to a caller would inject a
    /// silently wrong secret. No real value is anywhere near this size, so this
    /// is a statement about the backend and nothing else.
    TooLarge(usize),
    /// The deadline expired with part of the value still unwritten, because
    /// nothing drained the child's stdin.
    ///
    /// A separate variant rather than a [`CaptureError::TimedOut`] for the same
    /// reason [`CaptureError::TooLarge`] is separate from a success: the child
    /// received a PREFIX of a credential, which is the shape a silently wrong
    /// secret has. It also names a different repair — "the backend never read
    /// what it was given" sends a reader somewhere else than "the backend never
    /// answered".
    ///
    /// The counts are lengths, which is metadata. No part of the value reaches
    /// this variant or the sentence built from it.
    InputNotRead {
        /// How many bytes of the value reached the pipe.
        sent: usize,
        /// How many bytes the caller asked to send.
        total: usize,
    },
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::Spawn(source) => write!(f, "cannot run it: {source}"),
            CaptureError::TimedOut { budget, starting } => {
                write!(f, "no answer within {} ms", budget.as_millis())?;
                // The budget is the whole sentence when all of it reached the
                // child. When it did not, saying so is the difference between
                // naming the backend and naming the machine.
                if starting.as_millis() > 0 {
                    write!(
                        f,
                        ", {} ms of which went to starting it",
                        starting.as_millis()
                    )?;
                }
                Ok(())
            }
            CaptureError::Collect(source) => write!(f, "cannot read its output: {source}"),
            CaptureError::Threads(source) => {
                write!(f, "cannot start a thread to read its output: {source}")
            }
            CaptureError::TooLarge(cap) => {
                write!(f, "it produced more than {cap} bytes")
            }
            CaptureError::InputNotRead { sent, total } => {
                write!(f, "it read {sent} of the {total} bytes it was given")
            }
        }
    }
}

impl std::error::Error for CaptureError {}

/// Run `command` to completion, or kill it when `timeout` expires.
///
/// stdin is `/dev/null`: a backend that decides to prompt would otherwise
/// inherit the user's terminal and block behind a question nobody can see,
/// which is a hang wearing a different hat.
///
/// # Errors
///
/// [`CaptureError::Spawn`] when the binary will not start, [`CaptureError::TimedOut`]
/// when the deadline expires, [`CaptureError::Collect`] when the pipes fail.
pub fn capture(mut command: Command, timeout: Duration) -> Result<Captured, CaptureError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut budget = Budget::starting_now(timeout);
    // Under `RLIMIT_NPROC` this is the difference between a lookup and a
    // spurious `DEGRADED` banner — see [`spawn_persistently`]. The deadline is
    // handed in so the retry spends the lookup's own budget and never more.
    let child =
        spawn_persistently(&mut command, Some(budget.until)).map_err(CaptureError::Spawn)?;
    budget.the_child_now_exists();
    Pending::start(child)?.finish(budget)
}

/// One capture's deadline, and how much of it the child never saw.
///
/// Carried as one value rather than as three arguments because two of the three
/// are durations and the third is the instant they are about: a call site that
/// transposed them would compile, and the thing it would get wrong is the
/// number in an error message nobody re-derives.
#[derive(Clone, Copy)]
struct Budget {
    /// The whole deadline the caller asked for. Reported, never enforced —
    /// [`Budget::until`] is what the waits are measured against.
    total: Duration,
    /// When the clock started, which is before anything can ask to spawn.
    began: Instant,
    /// The instant the whole of it expires, fixed before anything is spawned.
    until: Instant,
    /// How long it took for the child to exist. Zero until
    /// [`Budget::the_child_now_exists`] is called.
    ///
    /// **Not clamped to [`Budget::total`], and that is the point.** A lookup can
    /// spend longer queued than its entire budget, and a number capped at the
    /// budget would report that as "all of it" — true, but it throws away the
    /// only figure that says HOW oversubscribed the machine is. A startup
    /// interval larger than the budget it was drawn from is not a contradiction;
    /// it is the measurement.
    starting: Duration,
}

impl Budget {
    /// A budget of `total`, counted from now.
    ///
    /// `Instant + Duration` PANICS on overflow, and this crate's release profile
    /// sets `panic = "abort"` — so a caller passing a duration the clock cannot
    /// hold would end the process with no child, no exit code and no message,
    /// which is the exact failure [`CaptureError::Threads`] exists to avoid.
    /// A timeout no clock can represent is not a timeout anyone meant, so it
    /// becomes one that has already expired: the child is killed and the caller
    /// gets a [`CaptureError::TimedOut`] it can read.
    fn starting_now(total: Duration) -> Self {
        let began = Instant::now();
        Budget {
            total,
            began,
            until: began.checked_add(total).unwrap_or(began),
            starting: Duration::ZERO,
        }
    }

    /// Mark the moment a child exists, closing the startup interval.
    ///
    /// Everything before this is queue and spawn; everything after is the
    /// backend's own silence. Splitting them is the whole reason
    /// [`CaptureError::TimedOut`] carries two numbers.
    fn the_child_now_exists(&mut self) {
        self.starting = self.began.elapsed();
    }

    /// How much of the budget is still unspent.
    fn left(&self) -> Duration {
        self.until.saturating_duration_since(Instant::now())
    }

    /// The deadline as the error that expiring it produces.
    fn expired(&self) -> CaptureError {
        CaptureError::TimedOut {
            budget: self.total,
            starting: self.starting,
        }
    }
}

/// Run `command` with `input` on its stdin, under the same deadline as
/// [`capture`].
///
/// # Why a write verb needs this at all
///
/// A value passed as an argument is readable from the process table for as long
/// as the child lives — the CLI-flag shape, one of the four the README's *Why
/// this exists* names. Both write backends therefore take their value on stdin —
/// `pass-cli item create <type> --from-template -` and
/// `security add-generic-password -w` with no argument — and this is the one
/// function that feeds them.
///
/// # The value is never copied, and never leaves this thread
///
/// `input` stays the caller's and is written straight from the caller's buffer.
/// There is no second copy of the plaintext anywhere in this function, no
/// heap allocation holding it, and no other thread that can see it — so there
/// is no buffer here to abandon, and nothing to scrub on the way out. The
/// caller owns exactly one copy and scrubs exactly one copy. The child's
/// stdout is handled as in [`capture`] — [`Captured`] scrubs it on drop.
///
/// # Why the write is bounded rather than merely concurrent
///
/// A child that reads all of its input before writing any output is
/// indistinguishable, from here, from one that writes first. So the child's
/// stdout and stderr are drained on their own threads for the whole of this
/// call, and the write proceeds against a pipe somebody is emptying — that is
/// what stops the obvious deadlock at the first pipe buffer.
///
/// It is not enough on its own. **A blocking write to a pipe nobody reads waits
/// forever, and no deadline held by another thread can end it**: nothing can
/// safely close a descriptor a second thread is parked inside `write(2)` on,
/// and abandoning that thread would leave a live thread holding a credential
/// with no way to reach it again. Killing the child does not reliably help
/// either — a grandchild that inherited the read end keeps the pipe open, and
/// `/bin/sh -c` produces exactly that on Linux, where dash forks the command
/// macOS's shell execs.
///
/// So the write is bounded **at the descriptor**: [`deliver`] sets `O_NONBLOCK`
/// on the write end and waits in `poll` with the time that is left, which makes
/// its runtime a property of `timeout` rather than of the child's behaviour.
/// The whole call is then bounded by one deadline covering the write and the
/// wait together, instead of the two of them serially.
///
/// # Errors
///
/// The same as [`capture`], plus [`CaptureError::InputNotRead`] when the
/// deadline expires with part of the value still unwritten — a child that took
/// a PREFIX of a credential and a child that took all of it must not be
/// reported the same way.
pub fn capture_with_input(
    mut command: Command,
    timeout: Duration,
    input: &[u8],
) -> Result<Captured, CaptureError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut budget = Budget::starting_now(timeout);
    let mut child =
        spawn_persistently(&mut command, Some(budget.until)).map_err(CaptureError::Spawn)?;
    budget.the_child_now_exists();
    // Taken before the child moves into the collector, which owns it afterwards.
    let stdin = child.stdin.take();
    // The readers are started BEFORE the write, so the child is free to answer
    // while it is still being fed.
    let pending = Pending::start(child)?;

    let sent = match stdin {
        Some(pipe) => deliver(pipe, input, budget.until),
        // Unreachable while the stdio above says `piped`, and a silent success
        // would be a write that never happened.
        None => Delivery::Stalled(0),
    };
    if let Delivery::Stalled(sent) = sent {
        pending.abandon();
        return Err(CaptureError::InputNotRead {
            sent,
            total: input.len(),
        });
    }

    pending.finish(budget)
}

/// What became of the value on its way to the child's stdin.
enum Delivery {
    /// Every byte reached the pipe, or the child stopped reading before the end
    /// of its own accord.
    ///
    /// The two are one outcome deliberately. A backend that reads the lines it
    /// needs and exits — which is what `security` does — closes the pipe on a
    /// write that was still in progress, and that is a normal, successful
    /// exchange rather than a fault. What the child then did with what it read
    /// is reported by its exit status and its stderr, which the caller already
    /// judges.
    Done,
    /// The deadline expired with bytes still unwritten, because nothing drained
    /// the pipe. Carries how many bytes did land.
    Stalled(usize),
}

/// Write `payload` to `pipe`, giving up at `deadline` rather than on the child.
///
/// # Why `O_NONBLOCK` and not a thread with a bound
///
/// This is the one place in the crate where a blocked syscall would hold
/// plaintext. A blocking `write_all` to a pipe nobody reads never returns, and
/// there is no sound way to interrupt it from outside: closing the descriptor
/// under a parked writer is undefined, and scrubbing the buffer under it races
/// a copy the kernel may be making. Bounding a JOIN therefore buys nothing —
/// it converts a hang into a live thread holding a credential forever, which
/// is the worse of the two.
///
/// Non-blocking is the only mechanism that removes the block itself. Every
/// syscall below returns immediately or with a timeout, so this function's
/// runtime is bounded by `deadline` no matter who holds the read end — the
/// child, a grandchild it forked, or a process it passed the descriptor to.
/// That is also why the write runs on the CALLING thread: with nothing that
/// can park, no thread is needed and no copy of the value has to be made to
/// move into one.
///
/// `O_NONBLOCK` is set on the WRITE end only. It is a property of that open
/// file description, not of the pipe, so the child's own reads still block
/// normally and no backend can tell the difference.
///
/// Dropping `pipe` at every exit closes it, which is what tells a child reading
/// to end of input that there is no more — including on the give-up path, where
/// a child left waiting on an EOF that never came would be a second hang.
fn deliver(mut pipe: ChildStdin, payload: &[u8], deadline: Instant) -> Delivery {
    if fcntl(&pipe, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).is_err() {
        // Writing anyway would be a blocking write with no bound, which is the
        // defect this function exists to remove. Refusing to write at all keeps
        // the deadline true; the child gets EOF, fails, and says so.
        return Delivery::Stalled(0);
    }

    let mut sent = 0;
    while sent < payload.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Delivery::Stalled(sent);
        }
        match pipe.write(&payload[sent..]) {
            // Nothing was written and no reason was given. Retrying cannot make
            // progress, and the honest report is that the value did not land.
            Ok(0) => return Delivery::Stalled(sent),
            Ok(written) => sent += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // The pipe is full. Sleep until it drains or the deadline
                // arrives, whichever comes first — never longer.
                let mut watched = [PollFd::new(pipe.as_fd(), PollFlags::POLLOUT)];
                let limit = PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX);
                // An error here is `EINTR` or a descriptor complaint; both are
                // answered by looping, and the deadline check above is what
                // stops the loop.
                let _ = poll(&mut watched, limit);
            }
            // The read end is gone — the child took what it wanted and exited,
            // or it died. Either way there is nobody left to write to.
            Err(_) => return Delivery::Done,
        }
    }
    Delivery::Done
}

/// The most this will hold from one of a backend's streams.
///
/// # Why a deadline is not enough on its own
///
/// The deadline bounds how LONG a flooding backend runs. It does not bound how
/// much arrives in that time, and the two are not the same failure. `Command::
/// output` and `wait_with_output` both read to end of stream into a growing
/// `Vec`, so a `security` copying `/dev/zero` reached 2.7 GB resident in twelve
/// seconds and ended as an out-of-memory kill.
///
/// Adding a ten-second deadline did not fix that, it only capped the exponent —
/// measured in this crate's own suite, a **500 ms** deadline against
/// `dd if=/dev/zero` still allocated and scrubbed enough to blow past a
/// thirty-second wall clock on a loaded machine, intermittently. Memory has to
/// be bounded directly.
///
/// Eight mebibytes is four orders of magnitude above any credential and above
/// every real backend's stderr. Reading past it is a fact about the backend, not
/// about the value, so it becomes [`CaptureError::TooLarge`] rather than a
/// truncated secret.
const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

/// Read to end of stream, keeping at most [`MAX_CAPTURE_BYTES`].
///
/// Draining past the cap rather than stopping at it is deliberate: a reader that
/// stops leaves the child blocked on a full pipe, which turns a bounded overflow
/// into a wait for the deadline. Discarding costs a `memcpy` and lets the child
/// finish saying whatever it was going to say.
///
/// The scratch buffer is scrubbed: a backend's stdout is where a plaintext value
/// arrives, so the bytes that pass through here are as sensitive as the ones
/// that are kept.
fn read_capped<R: io::Read>(mut source: R) -> (Vec<u8>, bool) {
    let mut kept: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 64 * 1024];
    let mut overflowed = false;
    loop {
        match source.read(&mut scratch) {
            Ok(0) => break,
            Ok(read) => {
                let room = MAX_CAPTURE_BYTES.saturating_sub(kept.len());
                if read > room {
                    overflowed = true;
                }
                kept.extend_from_slice(&scratch[..read.min(room)]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    scratch.zeroize();
    (kept, overflowed)
}

/// Scrub bytes a reader thread captured and could not hand back.
///
/// A `send` on an `mpsc` channel FAILS once the receiver is gone, and hands the
/// value back rather than dropping it. That happens on exactly one path and it
/// is the path that matters: [`Pending::abandon`] waits [`REAP_GRACE`] for a
/// killed child and then returns, so a reader still draining a pipe some
/// grandchild holds open finishes afterwards, with nobody left to receive.
///
/// Without this the returned `Vec` would be dropped as an ordinary allocation.
/// For a lookup that is a PARTIAL CREDENTIAL — stdout is where a value arrives
/// — released to the allocator unscrubbed, which is the one thing
/// [`Captured`]'s own `Drop` exists to prevent on every other path.
///
/// Not observable from outside the process, so no test asserts it. It is here
/// because the drop is reachable, not because anything measured it.
fn scrub_unsent(mut bytes: Vec<u8>) {
    bytes.zeroize();
}

/// A child whose streams are being drained, waiting to be waited on.
///
/// Split from the wait so that a caller with something to WRITE can do it while
/// the readers are already running, under one deadline covering both. Started
/// and finished back to back, this is the whole of [`capture`].
struct Pending {
    /// Held rather than re-derived: the collector thread owns the `Child` from
    /// [`Pending::start`] onwards, and killing needs the id.
    pid: Pid,
    errors: Receiver<(Vec<u8>, bool)>,
    done: Receiver<io::Result<(std::process::ExitStatus, Vec<u8>, bool)>>,
}

impl Pending {
    /// Start draining `child`, and return before it has finished.
    ///
    /// # Errors
    ///
    /// [`CaptureError::Threads`] when the operating system refuses a thread.
    /// The child is killed first, because a child nobody is reading and nobody
    /// will wait on is a leak.
    fn start(mut child: std::process::Child) -> Result<Self, CaptureError> {
        let pid = Pid::from_raw(child.id().cast_signed());

        // Both pipes are read CONCURRENTLY, which is the one shape that cannot
        // deadlock on a child that fills one of them while writing to the other.
        // `wait_with_output` gave that for free and is not usable here, because
        // it reads without a bound — see [`MAX_CAPTURE_BYTES`].
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let (errors_read, errors) = mpsc::channel::<(Vec<u8>, bool)>();
        if let Some(pipe) = stderr
            && let Err(source) = thread::Builder::new()
                .name("keyless-store-stderr".to_owned())
                .spawn(move || {
                    if let Err(rejected) = errors_read.send(read_capped(pipe)) {
                        scrub_unsent(rejected.0.0);
                    }
                })
        {
            let _ = kill(pid, Signal::SIGKILL);
            return Err(CaptureError::Threads(source));
        }

        let (finished, done) =
            mpsc::channel::<io::Result<(std::process::ExitStatus, Vec<u8>, bool)>>();
        if let Err(source) = thread::Builder::new()
            .name("keyless-store-output".to_owned())
            .spawn(move || {
                // Drained before the wait: a child cannot exit while blocked on
                // a pipe nobody is reading.
                let (bytes, overflowed) = match stdout {
                    Some(pipe) => read_capped(pipe),
                    None => (Vec::new(), false),
                };
                if let Err(rejected) =
                    finished.send(child.wait().map(|status| (status, bytes, overflowed)))
                    && let Ok((_, bytes, _)) = rejected.0
                {
                    scrub_unsent(bytes);
                }
            })
        {
            // The closure was dropped with the `Child` inside it, and dropping a
            // `Child` neither kills nor reaps. The process is therefore still
            // running and still ours, so its pid cannot have been reused and
            // signalling it is safe rather than a race.
            let _ = kill(pid, Signal::SIGKILL);
            return Err(CaptureError::Threads(source));
        }

        Ok(Pending { pid, errors, done })
    }

    /// Kill the child and scrub whatever was read of its stdout.
    ///
    /// The collector thread still holds the `Child`, so the pid has not been
    /// reaped and cannot yet have been reused by another process. Signalling it
    /// here is therefore safe rather than a race.
    fn abandon(self) {
        let _ = kill(self.pid, Signal::SIGKILL);
        // Collected only to scrub it: a partial value is as sensitive as a
        // whole one.
        if let Ok(Ok((_, mut bytes, _))) = self.done.recv_timeout(REAP_GRACE) {
            bytes.zeroize();
        }
    }

    /// Wait for the child until the budget expires, killing it when it does.
    ///
    /// The wait runs against [`Budget::until`], so time already spent starting
    /// the child or writing to it is time this does not get to spend again —
    /// and [`Budget::starting`] is what stops that from being reported as the
    /// child's own silence.
    ///
    /// # Errors
    ///
    /// [`CaptureError::TimedOut`] at the deadline, [`CaptureError::TooLarge`]
    /// past the capture cap, [`CaptureError::Collect`] when the pipes fail.
    fn finish(self, budget: Budget) -> Result<Captured, CaptureError> {
        let outcome = self.done.recv_timeout(budget.left());
        match outcome {
            Ok(Ok((status, mut bytes, overflowed))) => {
                if overflowed {
                    // Scrubbed rather than returned. The bytes are a prefix of
                    // something a backend produced, which is exactly the shape a
                    // truncated credential has, and no caller has any use for
                    // one.
                    bytes.zeroize();
                    return Err(CaptureError::TooLarge(MAX_CAPTURE_BYTES));
                }
                // A flooded stderr is dropped on the floor rather than waited
                // for: stdout is what a lookup is about, and the whole point of
                // arriving here is not to wait for a stream that will not end.
                let stderr = match self.errors.recv_timeout(REAP_GRACE) {
                    Ok((bytes, false)) => bytes,
                    Ok((mut bytes, true)) => {
                        bytes.zeroize();
                        b"<stderr too large to quote>".to_vec()
                    }
                    Err(_) => Vec::new(),
                };
                Ok(Captured {
                    status,
                    stdout: bytes,
                    stderr,
                })
            }
            Ok(Err(source)) => Err(CaptureError::Collect(source)),
            Err(RecvTimeoutError::Timeout) => {
                self.abandon();
                Err(budget.expired())
            }
            // The sender was dropped without sending, which means the collector
            // thread panicked. Nothing was captured and nothing leaked.
            Err(RecvTimeoutError::Disconnected) => Err(CaptureError::Collect(io::Error::other(
                "the output collector stopped unexpectedly",
            ))),
        }
    }
}

/// Turn a capture failure into a store error.
///
/// Every failure here is `Unavailable` rather than `Backend`, and the split is
/// what `doctor` reports: unavailable means "fix your setup" — the binary is
/// missing, the network is not answering — while backend means "fix your data".
/// A deadline that expired is a reachability problem, so it belongs on this
/// side of that line.
///
/// One function rather than one per adapter: two copies of this mapping would
/// eventually classify the same failure differently, and the classification is
/// what a user reads.
#[must_use]
pub fn unavailable(store: &str, binary: &std::path::Path, error: &CaptureError) -> StoreError {
    let detail = match error {
        CaptureError::Spawn(_) => format!("{} {error}", binary.display()),
        CaptureError::TimedOut { .. }
        | CaptureError::Collect(_)
        | CaptureError::Threads(_)
        | CaptureError::TooLarge(_)
        | CaptureError::InputNotRead { .. } => error.to_string(),
    };
    StoreError::Unavailable {
        store: store.to_owned(),
        detail,
    }
}

/// The first non-empty line of a backend's stderr, capped and UTF-8 safe.
///
/// Lossy on purpose: a backend that writes invalid UTF-8 to stderr must still
/// produce a printable diagnosis rather than an empty one.
#[must_use]
pub fn first_line(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("no detail");
    let trimmed = line.trim();
    if trimmed.len() <= MAX_DETAIL {
        trimmed.to_owned()
    } else {
        let mut cut = MAX_DETAIL;
        while cut > 0 && !trimmed.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &trimmed[..cut])
    }
}

/// A backend's stderr as one line, keeping the cause it put on a later line.
///
/// [`first_line`] is the right function for a vendor that says everything it has
/// to say in one line. `pass-cli` is not one of those, and finding that out cost a
/// wrong diagnosis:
///
/// ```text
/// Error: Error creating login item
///
/// Caused by:
///     Could not perform operation. Reason: NotAllowed
/// ```
///
/// The first line is `Error creating login item`, which says nothing an operator
/// can act on, and the sentence that names the actual fault is three lines down.
/// Measured 2026-08-08 against `pass-cli` 2.2.5: with only the first line quoted,
/// a refusal caused by a token's role was reported as an unexplained failure — so
/// the guidance attached to `NotAllowed` never fired, and the reader would have
/// gone hunting through vault permissions instead.
///
/// So this joins every non-empty line, drops the bare `Caused by:` marker (it is
/// punctuation, not information, once the lines are joined), and applies the same
/// cap as [`first_line`].
///
/// # Colour is removed, because this string stops being terminal output
///
/// A vendor writing to a pipe may still colour its diagnostics — `pass-cli` 2.2.5
/// does, measured 2026-08-08 — and the escape sequences survive into whatever
/// this string is put into. That string is an error message that gets embedded in
/// a longer sentence, printed in the middle of a `doctor` report, and written to
/// the audit log as JSON. Escape codes belong to none of those: in the log they
/// are noise stored forever, and in a report they colour text the report did not
/// choose to colour, in the middle of a line it did not choose to interrupt.
/// They are also the only part of the vendor's stderr that carries no meaning at
/// all, so removing them loses nothing.
///
/// **stderr only, exactly like [`first_line`].** Reading more of it is safe
/// precisely because nothing in this crate lets a value reach stderr; the same
/// change applied to stdout would be a disclosure.
#[must_use]
pub fn summarise(stderr: &[u8]) -> String {
    let text = strip_ansi(&String::from_utf8_lossy(stderr));
    let joined = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "Caused by:")
        .collect::<Vec<_>>()
        .join(": ");
    if joined.is_empty() {
        return "no detail".to_owned();
    }
    if joined.len() <= MAX_DETAIL {
        return joined;
    }
    let mut cut = MAX_DETAIL;
    while cut > 0 && !joined.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &joined[..cut])
}

/// Remove ANSI escape sequences, keeping every printable byte.
///
/// Handles the two forms a CLI actually emits: a CSI sequence (`ESC [` … final
/// byte in `@`–`~`), which is what colour and cursor movement use, and a bare
/// two-character escape. An `ESC` that begins a sequence with no terminator —
/// truncated output, since the capture is bounded — consumes the rest rather
/// than leaking a half-sequence.
///
/// Written here rather than taken as a dependency: it is a dozen lines, and the
/// alternative is another crate in the trusted path of a secrets tool. The same
/// reasoning as [`crate::store::proton::resolve_executable`].
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        // A CSI sequence runs until a byte in `@`–`~`. Any other two-character
        // escape drops both characters, which `chars.next()` has already done.
        if chars.next() == Some('[') {
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        }
    }
    out
}

/// Strip the single trailing newline a line-oriented helper adds.
///
/// `printenv` and `security -w` both terminate their output with a newline of
/// their own. A value whose own last byte is a newline is therefore not
/// distinguishable from one without — an ambiguity that belongs to those
/// interfaces and cannot be resolved here.
pub fn strip_one_newline(bytes: &mut Vec<u8>) {
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CaptureError, MAX_DETAIL, capture, capture_with_input, first_line, strip_one_newline,
    };
    use std::collections::HashSet;
    use std::io;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn input_reaches_the_childs_stdin_and_never_its_argv() {
        // The property the write verbs rest on. `cat` echoes what it was given,
        // and the argv the child could see is asserted to be free of it.
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "cat; printf '%s' \"$*\" >&2"]);
        let captured = capture_with_input(command, Duration::from_secs(10), b"decoy-on-stdin-7788")
            .expect("the shell must run");
        assert_eq!(captured.stdout, b"decoy-on-stdin-7788");
        assert!(
            !String::from_utf8_lossy(&captured.stderr).contains("decoy-on-stdin-7788"),
            "the value reached the child's argument list"
        );
    }

    #[test]
    fn input_larger_than_a_pipe_buffer_does_not_deadlock() {
        // A child that reads everything before writing anything is why the write
        // happens on its own thread. Inline, this blocks forever at 64 KiB.
        let payload = vec![b'x'; 512 * 1024];
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "wc -c"]);
        let captured = capture_with_input(command, Duration::from_secs(20), &payload)
            .expect("the shell must run");
        assert!(
            String::from_utf8_lossy(&captured.stdout).contains("524288"),
            "stdout was {:?}",
            String::from_utf8_lossy(&captured.stdout)
        );
    }

    #[test]
    fn a_child_that_exits_without_reading_its_input_is_not_an_error() {
        // A backend that takes the lines it needs and leaves is normal, and the
        // write end breaking under it is the ordinary end of that exchange. It
        // must not be reported as a value that failed to arrive: `true` never
        // reads a byte, and what decides the outcome is its exit status.
        //
        // The value that never arrived is a different outcome with a different
        // repair, and it is [`CaptureError::InputNotRead`]. Reaching that case
        // needs a reader holding the pipe open past the deadline, which is a
        // process fixture rather than a one-line command — it lives in
        // `tests/hostile.rs`, property 8, where the `within` harness turns a
        // regression into a named failure instead of a suite that never ends.
        let payload = vec![b'z'; 512 * 1024];
        let command = Command::new("/usr/bin/true");
        let captured = capture_with_input(command, Duration::from_secs(10), &payload)
            .expect("a child that ignores its stdin is not a capture failure");
        assert!(captured.status.success());
    }

    #[test]
    fn an_unread_value_is_reported_by_length_and_never_by_content() {
        // The counts are metadata. A sentence built from this variant is put in
        // front of a user and written to the audit log, so the one thing it
        // must never carry is any part of the value.
        let error = CaptureError::InputNotRead {
            sent: 65_536,
            total: 524_288,
        };
        assert_eq!(
            error.to_string(),
            "it read 65536 of the 524288 bytes it was given"
        );
    }

    #[test]
    fn a_quick_command_is_captured_whole() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'out'; printf 'err' >&2; exit 3"]);
        let captured = capture(command, Duration::from_secs(10)).expect("the shell must run");
        assert_eq!(captured.stdout, b"out");
        assert_eq!(captured.stderr, b"err");
        assert_eq!(captured.status.code(), Some(3));
    }

    #[test]
    fn a_missing_binary_is_a_spawn_error_not_a_panic() {
        let command = Command::new("/nonexistent/keyless-test/backend");
        let error = capture(command, Duration::from_secs(1)).expect_err("nothing to run");
        assert!(matches!(error, CaptureError::Spawn(_)));
    }

    #[test]
    fn a_hanging_command_is_killed_at_the_deadline() {
        // The property the never-block invariant rests on for a network store.
        // `sleep 60` stands in for a black-holed connection: it will never
        // finish on its own, so if the deadline is not enforced this test hangs
        // the suite rather than failing it. The elapsed assertion below is what
        // turns that into a clean failure.
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 60"]);

        let started = Instant::now();
        let error = capture(command, Duration::from_millis(300)).expect_err("must not wait 60s");
        let elapsed = started.elapsed();

        assert!(matches!(error, CaptureError::TimedOut { .. }));
        assert!(
            elapsed < Duration::from_secs(5),
            "the deadline was not enforced: waited {elapsed:?}"
        );
    }

    #[test]
    fn a_timeout_says_how_long_it_waited_and_nothing_else() {
        let error = CaptureError::TimedOut {
            budget: Duration::from_millis(2500),
            starting: Duration::ZERO,
        };
        assert_eq!(error.to_string(), "no answer within 2500 ms");
    }

    /// A budget the queue ate must not be reported as the backend's silence.
    ///
    /// [`super::SPAWNING`] serialises every child creation in the process, and
    /// the deadline starts before a lookup can even ask for it. So a lookup can
    /// reach the wait with none of its budget left, create a child, kill it in
    /// the same breath, and — with one number in the sentence — blame it for a
    /// silence it was never given time to break. "The machine is oversubscribed"
    /// and "the backend is not answering" have different repairs, and a reader
    /// cannot tell them apart from `no answer within N ms`.
    #[test]
    fn a_timeout_the_backend_never_saw_says_so() {
        let error = CaptureError::TimedOut {
            budget: Duration::from_millis(300),
            starting: Duration::from_millis(384),
        };
        assert_eq!(
            error.to_string(),
            "no answer within 300 ms, 384 ms of which went to starting it"
        );

        // The prefix is unchanged, which is what lets the clause be added
        // without rewriting every caller that reads the budget out of the
        // sentence.
        assert!(error.to_string().starts_with("no answer within 300 ms"));
    }

    /// The clause is a fact about the run, not a decoration on the variant.
    ///
    /// Its threshold is the resolution the message already prints in: it
    /// appears exactly when the startup interval is non-zero in whole
    /// milliseconds. An uncontended spawn costs far less than one and reads as
    /// it always did, so the clause's presence IS the signal that something
    /// stood between the lookup and its child.
    #[test]
    fn a_startup_too_short_to_print_adds_no_clause() {
        let error = CaptureError::TimedOut {
            budget: Duration::from_millis(2500),
            starting: Duration::from_micros(999),
        };
        assert_eq!(error.to_string(), "no answer within 2500 ms");

        // The control: one microsecond more is a whole millisecond, and the
        // clause appears. Without this the assertion above is satisfied by a
        // Display that never renders the clause at all.
        let error = CaptureError::TimedOut {
            budget: Duration::from_millis(2500),
            starting: Duration::from_micros(1000),
        };
        assert_eq!(
            error.to_string(),
            "no answer within 2500 ms, 1 ms of which went to starting it"
        );
    }

    /// The wiring: the startup interval is MEASURED, not left at zero.
    ///
    /// Every assertion above builds the error by hand, so a `capture` that had
    /// stopped closing the interval would leave all of them green while the
    /// shipped sentence went back to naming the wrong fault. This one drives
    /// the real path.
    ///
    /// The child is spawned behind the real spawn gate, held by this test, so
    /// the startup interval is a genuine queue wait rather than a contrived
    /// number — which is the exact shape the defect has in a run resolving
    /// several names at once.
    ///
    /// The gate is held for several times the lookup's budget, so the assertion
    /// is `starting` LARGER than the whole budget. That is what separates a
    /// measured interval from one clamped at the budget: a clamp reports
    /// exactly the budget and no more, which reads as "all of it" and loses the
    /// figure that says how far past the machine actually was.
    ///
    /// The worker announces itself before it calls [`capture`], and the hold is
    /// long relative to the two statements between that announcement and the
    /// clock starting — the same rendezvous `tty::relay`'s signal tests use.
    #[test]
    fn the_startup_interval_a_real_capture_reports_is_the_time_it_actually_queued() {
        // Short, because it is spent entirely on the queue and never on a
        // child: the gate below is what expires it.
        let budget = Duration::from_millis(100);
        let held = Duration::from_millis(400);

        let gate = super::SPAWNING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (ready, waiting_now) = std::sync::mpsc::channel();
        let waiting = thread::spawn(move || {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf 'out'"]);
            let _ = ready.send(());
            capture(command, budget)
        });
        waiting_now
            .recv_timeout(Duration::from_secs(30))
            .expect("the worker must reach its lookup");
        thread::sleep(held);
        drop(gate);

        let error = waiting
            .join()
            .expect("the queued lookup must not panic")
            .expect_err("a lookup whose whole budget went to the queue cannot succeed");
        let CaptureError::TimedOut { budget, starting } = error else {
            panic!("expected a deadline, got {error:?}");
        };
        assert!(
            starting > budget,
            "the startup interval was {starting:?} against a {budget:?} budget; a lookup that \
             spent longer queued than it had to spend at all is reporting the queue as the \
             backend's own silence"
        );
        // And the sentence a reader gets says it, rather than making them
        // derive it from a variant they cannot see.
        let said = CaptureError::TimedOut { budget, starting }.to_string();
        assert!(
            said.contains("went to starting it"),
            "the message names the backend for a wait it never got: {said}"
        );
    }

    #[test]
    fn detail_extraction_is_bounded_and_utf8_safe() {
        assert_eq!(first_line(b"first\nsecond"), "first");
        assert_eq!(first_line(b""), "no detail");
        assert_eq!(first_line(b"\n\n  real  \n"), "real");
        // Invalid UTF-8 still yields something printable rather than nothing.
        assert!(!first_line(b"\xff\xfe broken").is_empty());
        let long = "é".repeat(400);
        let detail = first_line(long.as_bytes());
        assert!(detail.len() <= MAX_DETAIL + 4);
        assert!(detail.ends_with('…'));
    }

    #[test]
    fn a_summary_keeps_the_cause_the_vendor_put_on_a_later_line() {
        // The exact bytes `pass-cli` 2.2.5 produced on 2026-08-08 when a
        // viewer-role token tried to create an item. The first line alone says
        // nothing actionable; the fourth is the whole diagnosis.
        let stderr = b"Error: Error creating login item\n\nCaused by:\n    Could not perform \
                       operation. Reason: NotAllowed\n";
        let summary = super::summarise(stderr);
        assert!(
            summary.contains("NotAllowed"),
            "the cause was dropped: {summary}"
        );
        assert!(summary.contains("Error creating login item"), "{summary}");
        assert!(
            !summary.contains("Caused by:"),
            "the marker is punctuation once the lines are joined: {summary}"
        );

        // The negative control: `first_line` is what this replaces, and it must
        // still be the thing that loses the cause. Without this, the assertion
        // above could pass on a `first_line` that had quietly started reading
        // more, and the new function would be protecting nothing.
        assert!(!first_line(stderr).contains("NotAllowed"));
    }

    #[test]
    fn a_summary_carries_no_terminal_escape_codes() {
        // Measured 2026-08-08: `pass-cli` 2.2.5 colours its diagnostics even
        // when stderr is a pipe, so this is what a dead session actually looks
        // like from inside a capture. The summary is embedded in a longer
        // sentence, printed mid-report by `doctor`, and stored in the audit log
        // as JSON — none of which is terminal output.
        let stderr = b"\x1b[2m2000-01-01T00:00:00Z\x1b[0m \x1b[31mERROR\x1b[0m no session\n\
                       Error: This operation requires an authenticated client\n";
        let summary = super::summarise(stderr);

        assert!(
            !summary.contains('\x1b'),
            "an escape sequence survived: {summary:?}"
        );
        // Every printable byte is kept, including the parts that sat between
        // two escapes. A strip that ate the words would be worse than one that
        // ate nothing.
        assert!(summary.contains("ERROR"), "{summary}");
        assert!(summary.contains("2000-01-01T00:00:00Z"), "{summary}");
        assert!(summary.contains("authenticated client"), "{summary}");

        // The negative control: the raw bytes DO carry escapes, so the
        // assertion above is testing the strip and not the fixture.
        assert!(String::from_utf8_lossy(stderr).contains('\x1b'));

        // A truncated sequence — the capture is bounded, so stderr can stop
        // mid-escape — must not leak its tail either.
        assert!(!super::summarise(b"live\x1b[3").contains('\x1b'));
    }

    #[test]
    fn a_summary_is_bounded_and_never_empty() {
        assert_eq!(super::summarise(b""), "no detail");
        assert_eq!(super::summarise(b"\n\n  \n"), "no detail");
        let long = "é".repeat(400);
        let summary = super::summarise(long.as_bytes());
        assert!(summary.len() <= MAX_DETAIL + 4);
        assert!(summary.ends_with('…'));
    }

    // -----------------------------------------------------------------------
    // The spawn retry, which is a never-block guard rather than an optimisation.
    //
    // A `fork` refused with `EAGAIN` under `RLIMIT_NPROC` is the machine saying
    // "not right now". Giving up on the first one turns a transient limit into a
    // dead command for `keyless run`, and into a spurious `DEGRADED` banner —
    // and a 401 at exit 0 — for a store lookup. On a machine running ~20
    // concurrent agent sessions that is the condition [`super::SPAWN_ATTEMPTS`]
    // was written for, not a hypothetical.
    //
    // These go through [`super::persisting`] rather than through a real
    // `Command`, because `RLIMIT_NPROC` is counted per USER: a test that reached
    // the real condition would refuse forks to every other process this user is
    // running, the rest of the suite included. The seam is the honest way to
    // reach the loop; the errno fed into it is the real one.
    // -----------------------------------------------------------------------

    /// The half-open window each wait of the schedule must land in, in
    /// milliseconds.
    ///
    /// **By value, and deliberately not derived from [`super::SPAWN_BACKOFF`].**
    /// A bound computed from the constant under test is satisfied by every value
    /// of it, which is exactly how this loop went unguarded in the first place.
    /// Jitter turns the old equality into a range; it does not turn it into a
    /// range the code gets to choose.
    const SCHEDULE_MS: [(u64, u64); 4] = [(5, 10), (10, 20), (20, 40), (40, 80)];

    /// The condition clears, and the child still runs.
    ///
    /// Four consecutive refusals is the worst case the shipped budget of five
    /// attempts is documented to survive. A budget that cannot absorb them has
    /// been cut, and this is what says so — it reds at `SPAWN_ATTEMPTS` of 1, 2,
    /// 3 and 4 alike.
    #[test]
    fn a_spawn_refused_for_want_of_process_slots_is_tried_until_a_slot_appears() {
        let mut refusals = 4_u32;
        let mut waits: Vec<Duration> = Vec::new();

        let outcome = super::persisting(
            || {
                if refusals > 0 {
                    refusals -= 1;
                    // The errno a `fork` reports at `RLIMIT_NPROC`, not a
                    // stand-in for it.
                    return Err(io::Error::from_raw_os_error(nix::libc::EAGAIN));
                }
                Ok("the child")
            },
            |waited| waits.push(waited),
            None,
        );

        assert_eq!(
            outcome.expect(
                "a fork refused four times for want of process slots produced no child at all; \
                 the retry budget no longer covers the contention it was written for"
            ),
            "the child"
        );
        assert_eq!(
            waits.len(),
            4,
            "the child appeared without the machine being given time to drain"
        );
    }

    /// The retry WAITS, waits longer each time, and never waits a whole backoff.
    ///
    /// **This is the thundering-herd guard, and it is the half that a bare retry
    /// count does not give.** `RLIMIT_NPROC` is per user, so twenty sessions hit
    /// it in the same instant; twenty processes re-forking with no wait is the
    /// pile-up the limit exists to prevent.
    ///
    /// Each window is half-open — `[backoff/2, backoff)` — and that is three
    /// assertions in one, none of them weaker than the equality it replaces:
    ///
    /// - the LOWER bound reds when the doubling goes, because 5 ms is legal at
    ///   step one and illegal at step two;
    /// - the UPPER bound reds when the JITTER goes, because an unjittered wait
    ///   is exactly the backoff and the window excludes it;
    /// - the count and the total still bound the whole window at 150 ms.
    ///
    /// What it cannot see is jitter that is CONSTANT — a pid-derived offset sits
    /// inside every window here — and that is
    /// [`a_wait_is_drawn_afresh_rather_than_offset_by_a_constant`].
    #[test]
    fn the_retry_backs_off_rather_than_spinning_on_a_full_machine() {
        let mut attempts = 0_u32;
        let mut waits: Vec<Duration> = Vec::new();

        let outcome = super::persisting(
            || {
                attempts += 1;
                Err::<(), _>(io::Error::from_raw_os_error(nix::libc::EAGAIN))
            },
            |waited| waits.push(waited),
            None,
        );

        // A machine genuinely out of processes must end as a reported failure
        // and not as a spin, so the budget is bounded and the error is the
        // machine's own rather than a substitute.
        let error = outcome.expect_err("a permanently full machine must be reported");
        assert!(
            super::out_of_process_slots(&error),
            "the refusal the caller sees is no longer the one the kernel gave: {error}"
        );
        assert_eq!(
            attempts, 5,
            "the spawn was not attempted the budgeted number of times"
        );

        assert_eq!(
            waits.len(),
            SCHEDULE_MS.len(),
            "the retry no longer waits once between every pair of attempts: {waits:?}"
        );
        for (step, (waited, (floor, ceiling))) in waits.iter().zip(SCHEDULE_MS).enumerate() {
            assert!(
                *waited >= Duration::from_millis(floor),
                "wait {step} was {waited:?}, under the {floor} ms floor; the backoff no longer \
                 doubles, so twenty sessions at the limit re-fork together"
            );
            assert!(
                *waited < Duration::from_millis(ceiling),
                "wait {step} was {waited:?}, at or over the {ceiling} ms ceiling; the wait is no \
                 longer jittered, so twenty sessions refused together retry together"
            );
        }

        let window = waits.iter().sum::<Duration>();
        assert!(
            window >= Duration::from_millis(75) && window < Duration::from_millis(150),
            "the retry window was {window:?}; it must stay inside the 150 ms the budget claims \
             and still cover the contention it was written for"
        );
    }

    /// The jitter is REDRAWN, not an offset the process carries around.
    ///
    /// A process id is the obvious dependency-free candidate and it is the wrong
    /// one. It is constant for the life of the process, so every wait moves by
    /// the same amount: two sessions that collide once collide at every step,
    /// which is the correlation jitter exists to break. It is also allocated
    /// sequentially on Linux — a burst of sessions gets adjacent pids, and a
    /// small modulus maps those to adjacent offsets — and it restarts at 1 in
    /// every container.
    ///
    /// Every such jitter passes [`the_retry_backs_off_rather_than_spinning_on_a_full_machine`],
    /// because a fixed offset lands inside the window like any other. This is
    /// the case that separates them.
    #[test]
    fn a_wait_is_drawn_afresh_rather_than_offset_by_a_constant() {
        let mut drawn: HashSet<Duration> = HashSet::new();
        for _ in 0..64 {
            drawn.insert(super::jittered(super::SPAWN_BACKOFF));
            // Measured 2026-08-09 on macOS: `CLOCK_REALTIME` advances in steps
            // of 1 µs, so back-to-back draws inside one tick are legitimately
            // equal and a tight loop would prove nothing. Stepping well past a
            // tick is what makes "they are all the same" mean a constant.
            thread::sleep(Duration::from_micros(20));
        }
        assert!(
            drawn.len() >= 4,
            "64 waits drawn 20 µs apart produced only {} distinct value(s); the jitter is a \
             constant this process carries, so it shifts the schedule instead of dispersing it",
            drawn.len()
        );
        for wait in &drawn {
            assert!(
                *wait >= Duration::from_millis(5) && *wait < Duration::from_millis(10),
                "a first wait of {wait:?} is outside the window the schedule promises"
            );
        }
    }

    /// The control: retrying is SELECTIVE.
    ///
    /// Without this, a `persisting` that retried every failure would pass both
    /// guards above while making a command that does not exist take 150 ms to
    /// say so.
    #[test]
    fn a_refusal_that_is_not_about_process_slots_is_reported_at_once() {
        let mut attempts = 0_u32;
        let mut waits: Vec<Duration> = Vec::new();

        let outcome = super::persisting(
            || {
                attempts += 1;
                Err::<(), _>(io::Error::from_raw_os_error(nix::libc::ENOENT))
            },
            |waited| waits.push(waited),
            None,
        );

        assert!(outcome.is_err());
        assert_eq!(attempts, 1, "a command that does not exist was tried again");
        assert!(
            waits.is_empty(),
            "the caller was made to wait for a failure that will never clear"
        );
    }

    /// Which errno reaches the loop at all.
    ///
    /// The classifier and the loop share one function, so a test that fed a real
    /// `fork` errno to one cannot disagree with the other.
    #[test]
    fn the_errno_a_fork_reports_at_the_process_limit_is_the_one_that_retries() {
        assert!(super::out_of_process_slots(&io::Error::from_raw_os_error(
            nix::libc::EAGAIN
        )));
        // std's own spelling of the same condition, which is the form
        // `Command::spawn` hands back.
        assert!(super::out_of_process_slots(&io::Error::from(
            io::ErrorKind::WouldBlock
        )));

        // The controls. None of these is the machine being momentarily full, and
        // `E2BIG` in particular has its own repair — see
        // `crate::cmd::run::caused_by_the_environment` — which a retry would
        // bypass.
        for (errno, what) in [
            (nix::libc::ENOENT, "no such file"),
            (nix::libc::EACCES, "not executable"),
            (nix::libc::E2BIG, "the environment is too large"),
        ] {
            assert!(
                !super::out_of_process_slots(&io::Error::from_raw_os_error(errno)),
                "`{what}` was treated as a transient shortage of process slots"
            );
        }
    }

    /// A lookup's retry is spent out of the lookup's OWN budget.
    ///
    /// This is the trade that kept the retry off this path. A store lookup
    /// already carries a deadline, so a retry that ran the full 150 ms inside a
    /// short one would convert a degrade caused by a full process table into a
    /// degrade caused by a blown deadline — the same `DEGRADED` banner to the
    /// user, a different bug to whoever reads it. The loop therefore refuses to
    /// START a wait it can see crossing the deadline, and the caller still gets
    /// the kernel's own refusal rather than a timeout this loop caused.
    ///
    /// The pause really sleeps here: the whole point is the interaction between
    /// the waits and a wall-clock deadline, and a recorded-but-not-taken wait
    /// would leave the clock where it started and the clause never reached.
    #[test]
    fn a_lookups_retry_never_spends_past_the_lookups_own_deadline() {
        // Shorter than the 150 ms schedule on purpose. The default lookup
        // deadline is 10 s, where the schedule is 1.5% of the budget and this
        // clause is never reached; what needs a guard is the configured
        // `timeout_ms` that is smaller than the schedule.
        let budget = Duration::from_millis(60);
        let deadline = Instant::now() + budget;
        let mut waits: Vec<Duration> = Vec::new();

        let outcome = super::persisting(
            || Err::<(), _>(io::Error::from_raw_os_error(nix::libc::EAGAIN)),
            |waited| {
                waits.push(waited);
                thread::sleep(waited);
            },
            Some(deadline),
        );

        let error = outcome.expect_err("a permanently full machine must be reported");
        assert!(
            super::out_of_process_slots(&error),
            "the lookup was told its deadline expired when what happened is that the machine \
             refused a fork: {error}"
        );
        assert!(
            !waits.is_empty(),
            "a lookup with 60 ms left gave up without retrying once; the deadline clause is \
             refusing the whole retry rather than the waits that would cross it"
        );
        let spent = waits.iter().sum::<Duration>();
        assert!(
            spent < budget,
            "the retry spent {spent:?} of a {budget:?} lookup budget; a wait that crosses the \
             deadline must not be started"
        );
    }

    /// The floor of the same rule: a deadline already gone leaves exactly the
    /// one attempt the caller had before any of this existed.
    #[test]
    fn a_deadline_already_past_leaves_the_spawn_the_single_attempt_it_had_before() {
        let mut attempts = 0_u32;
        let mut waits: Vec<Duration> = Vec::new();

        let outcome = super::persisting(
            || {
                attempts += 1;
                Err::<(), _>(io::Error::from_raw_os_error(nix::libc::EAGAIN))
            },
            |waited| waits.push(waited),
            Some(Instant::now()),
        );

        assert!(outcome.is_err());
        assert_eq!(
            attempts, 1,
            "a lookup with no time left was made to retry anyway"
        );
        assert!(
            waits.is_empty(),
            "a lookup with no time left was made to wait: {waits:?}"
        );
    }

    /// The wiring, which the seam tests above cannot see.
    ///
    /// They drive [`super::persisting`] directly, so a `spawn_persistently` that
    /// had stopped calling it would leave every one of them green.
    ///
    /// That every store lookup goes through it is STRUCTURAL rather than tested,
    /// and deliberately so: `spawn_persistently` holds the only `Command::spawn`
    /// call in `src/`, so there is no door into a non-retrying spawn for a test
    /// to guard. Reaching a real `EAGAIN` would mean driving this user's
    /// `RLIMIT_NPROC` to zero, which refuses forks to every other process the
    /// user is running — so the seam above is the only honest way in, and the
    /// wiring is held by construction rather than by assertion.
    #[test]
    fn the_shipped_spawn_path_produces_a_real_child() {
        let mut command = Command::new("/usr/bin/true");
        let mut child = super::spawn_persistently(&mut command, Some(deadline_far_enough()))
            .expect("`true` must run");
        assert!(child.wait().expect("the child must be reapable").success());
    }

    /// A deadline no correct run reaches, for cases that are not about deadlines.
    fn deadline_far_enough() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn only_one_trailing_newline_is_stripped() {
        let mut one = b"value\n".to_vec();
        strip_one_newline(&mut one);
        assert_eq!(one, b"value");

        let mut two = b"value\n\n".to_vec();
        strip_one_newline(&mut two);
        assert_eq!(two, b"value\n", "a value's own newline must survive");

        let mut none = b"value".to_vec();
        strip_one_newline(&mut none);
        assert_eq!(none, b"value");

        let mut empty: Vec<u8> = Vec::new();
        strip_one_newline(&mut empty);
        assert!(empty.is_empty());
    }
}
