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
use std::process::{Command, Stdio};

use crate::error::StoreError;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

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
/// still overlap — what is serialised is the microsecond in which a child's
/// descriptors are visible to another `fork`, never the seconds spent waiting
/// for an answer.
static SPAWNING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Create the child with [`SPAWNING`] held.
///
/// A poisoned lock is ignored: the mutex guards no data, only an interval, so a
/// panic elsewhere has left nothing inconsistent to protect.
pub fn spawn_serialised(command: &mut Command) -> io::Result<std::process::Child> {
    let _guard = SPAWNING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    command.spawn()
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
    TimedOut(Duration),
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
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::Spawn(source) => write!(f, "cannot run it: {source}"),
            CaptureError::TimedOut(after) => {
                write!(f, "no answer within {} ms", after.as_millis())
            }
            CaptureError::Collect(source) => write!(f, "cannot read its output: {source}"),
            CaptureError::Threads(source) => {
                write!(f, "cannot start a thread to read its output: {source}")
            }
            CaptureError::TooLarge(cap) => {
                write!(f, "it produced more than {cap} bytes")
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

    let child = spawn_serialised(&mut command).map_err(CaptureError::Spawn)?;
    collect(child, timeout)
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
/// # What happens to the copy
///
/// `input` stays the caller's; this function makes exactly one copy, hands it to
/// the writer thread, and that thread zeroizes it whether the write succeeded,
/// failed, or died on a closed pipe. The child's stdout is handled exactly as in
/// [`capture`] — [`Captured`] scrubs it on drop.
///
/// The write happens on its own thread because a child that reads all of its
/// input before writing any output is indistinguishable, from here, from one
/// that writes first: doing the write inline would deadlock on the second shape
/// as soon as the value exceeds a pipe buffer.
///
/// # Errors
///
/// The same three as [`capture`]. A child killed at the deadline closes the pipe,
/// so the writer thread ends with an error it discards rather than hanging.
pub fn capture_with_input(
    mut command: Command,
    timeout: Duration,
    input: &[u8],
) -> Result<Captured, CaptureError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = spawn_serialised(&mut command).map_err(CaptureError::Spawn)?;
    // Taken before the child moves into the collector, which owns it afterwards.
    let stdin = child.stdin.take();
    let mut payload = input.to_vec();
    let writer = thread::Builder::new()
        .name("keyless-store-stdin".to_owned())
        .spawn(move || {
            if let Some(mut pipe) = stdin {
                let _ = pipe.write_all(&payload);
                let _ = pipe.flush();
                // Dropping the pipe here closes it, which is what tells a child
                // reading to end of input that there is no more.
            }
            payload.zeroize();
        })
        .map_err(CaptureError::Threads)?;

    let captured = collect(child, timeout);
    // Joined rather than detached so the scrub above is known to have happened
    // before this function returns.
    let _ = writer.join();
    captured
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

/// Wait for `child` with a deadline, killing it when the deadline expires.
fn collect(mut child: std::process::Child, timeout: Duration) -> Result<Captured, CaptureError> {
    // Captured before the child moves into the collector thread, because that
    // thread owns it from then on and killing needs the id.
    let pid = Pid::from_raw(child.id().cast_signed());

    // Both pipes are read CONCURRENTLY, which is the one shape that cannot
    // deadlock on a child that fills one of them while writing to the other.
    // `wait_with_output` gave that for free and is not usable here, because it
    // reads without a bound — see [`MAX_CAPTURE_BYTES`].
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let (errors_read, errors) = mpsc::channel::<(Vec<u8>, bool)>();
    if let Some(pipe) = stderr
        && let Err(source) = thread::Builder::new()
            .name("keyless-store-stderr".to_owned())
            .spawn(move || {
                let _ = errors_read.send(read_capped(pipe));
            })
    {
        let _ = kill(pid, Signal::SIGKILL);
        return Err(CaptureError::Threads(source));
    }

    let (finished, done) = mpsc::channel::<io::Result<(std::process::ExitStatus, Vec<u8>, bool)>>();
    if let Err(source) = thread::Builder::new()
        .name("keyless-store-output".to_owned())
        .spawn(move || {
            // Drained before the wait: a child cannot exit while blocked on a
            // pipe nobody is reading.
            let (bytes, overflowed) = match stdout {
                Some(pipe) => read_capped(pipe),
                None => (Vec::new(), false),
            };
            let _ = finished.send(child.wait().map(|status| (status, bytes, overflowed)));
        })
    {
        // The closure was dropped with the `Child` inside it, and dropping a
        // `Child` neither kills nor reaps. The process is therefore still
        // running and still ours, so its pid cannot have been reused and
        // signalling it is safe rather than a race.
        let _ = kill(pid, Signal::SIGKILL);
        return Err(CaptureError::Threads(source));
    }

    match done.recv_timeout(timeout) {
        Ok(Ok((status, mut bytes, overflowed))) => {
            if overflowed {
                // Scrubbed rather than returned. The bytes are a prefix of
                // something a backend produced, which is exactly the shape a
                // truncated credential has, and no caller has any use for one.
                bytes.zeroize();
                return Err(CaptureError::TooLarge(MAX_CAPTURE_BYTES));
            }
            // A flooded stderr is dropped on the floor rather than waited for:
            // stdout is what a lookup is about, and the whole point of arriving
            // here is not to wait for a stream that will not end.
            let stderr = match errors.recv_timeout(REAP_GRACE) {
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
            // The collector thread still holds the `Child`, so the pid has not
            // been reaped and cannot yet have been reused by another process.
            // Signalling it here is therefore safe rather than a race.
            let _ = kill(pid, Signal::SIGKILL);
            // Collect whatever it managed to read, only to scrub it: a partial
            // value is as sensitive as a whole one.
            if let Ok(Ok((_, mut bytes, _))) = done.recv_timeout(REAP_GRACE) {
                bytes.zeroize();
            }
            Err(CaptureError::TimedOut(timeout))
        }
        // The sender was dropped without sending, which means the collector
        // thread panicked. Nothing was captured and nothing leaked.
        Err(RecvTimeoutError::Disconnected) => Err(CaptureError::Collect(io::Error::other(
            "the output collector stopped unexpectedly",
        ))),
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
        CaptureError::TimedOut(_)
        | CaptureError::Collect(_)
        | CaptureError::Threads(_)
        | CaptureError::TooLarge(_) => error.to_string(),
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
    use std::process::Command;
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
    fn a_child_that_never_reads_its_input_is_still_killed_at_the_deadline() {
        // The writer thread blocks on a full pipe. If the deadline did not also
        // reach it, this hangs the suite rather than failing it.
        let payload = vec![b'y'; 512 * 1024];
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 60"]);
        let started = Instant::now();
        let error = capture_with_input(command, Duration::from_millis(300), &payload)
            .expect_err("must not wait 60s");
        assert!(matches!(error, CaptureError::TimedOut(_)));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline was not enforced"
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

        assert!(matches!(error, CaptureError::TimedOut(_)));
        assert!(
            elapsed < Duration::from_secs(5),
            "the deadline was not enforced: waited {elapsed:?}"
        );
    }

    #[test]
    fn a_timeout_says_how_long_it_waited_and_nothing_else() {
        let error = CaptureError::TimedOut(Duration::from_millis(2500));
        assert_eq!(error.to_string(), "no answer within 2500 ms");
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
