//! `keyless run` — the whole product.
//!
//! Resolve named secrets, put them in a child process's environment, redact
//! them from the child's output, record what happened, and forward the child's
//! exit code.
//!
//! # The invariant
//!
//! This function spawns the child on every path where a child can exist. There
//! is no early return for a missing store, an unknown name, a corrupt config,
//! or a backend that errors — each of those sets [`State::Degraded`], writes one
//! line to stderr, and continues to the spawn. The only two ways out without a
//! child are [`RunError::NoCommand`] (nothing was asked for) and
//! [`RunError::SpawnFailed`] (the command does not exist), and neither is this
//! tool declining to run something it could have run.
//!
//! The reason is not politeness. A tool that occasionally blocks the work gets
//! removed, and what comes back is the plaintext literal on the command line.
//! Degrading loses the protection for one command; failing loses it for good.
//!
//! # What "the command does not exist" now excludes
//!
//! [`RunError::SpawnFailed`] used to absorb failures that were about the
//! ENVIRONMENT rather than the command, and report them against the program: a
//! stored value containing a NUL byte produced `cannot execute /bin/sh: nul byte
//! found`, exit 127, no child. The kernel gets a second say now —
//! [`caused_by_the_environment`] — and its refusal drops the injection and
//! spawns again, degraded. A refusal that says the machine is momentarily out of
//! process slots is retried rather than reported; see [`spawn_persistently`].
//!
//! So `SpawnFailed` means what it says: nothing this tool did to the environment
//! is left in the explanation.
//!
//! # Three things here are bounded on purpose
//!
//! Each was an unbounded wait that ended with the child either never running or
//! never being reported: [`resolve_all`] (N deadlines became one),
//! [`PUMP_DRAIN_GRACE`] (a grandchild holding the pipes), and
//! [`crate::store::exec::spawn_serialised`] (two concurrent spawns deadlocking on
//! an inherited descriptor). Read those three before changing the shape of this
//! function.

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::thread;

use nix::sys::signal::SigSet;
use nix::unistd::Pid;

use crate::audit::{AuditLog, Event};
use crate::error::RunError;
use crate::mask::{Masker, pump};
use crate::secret::Secret;
use crate::store::{Registry, Resolution};
use crate::tty::relay::{Prepared, Relay};
use crate::tty::{self, Pty, TtyError};
use crate::{NAME, State};

/// How many backend failure reasons to print under the degraded banner.
const MAX_REASONS_SHOWN: usize = 3;

/// How `run` decides whether the child gets a pseudo-terminal.
///
/// A pty is only ever considered when there is masking to do. With no secrets
/// to redact the child's stdio is inherited untouched, which is already the
/// most faithful terminal there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtyPolicy {
    /// Allocate one when this process's stdin, stdout **and** stderr are all
    /// terminals. What the binary uses.
    Auto,
    /// Never allocate one; pipe the child's stdout and stderr as before.
    Pipes,
    /// Behave as though a terminal is attached and allocation always fails.
    ///
    /// The fallback that the never-block invariant demands cannot be reached on
    /// demand on a machine where `/dev/ptmx` works, so it is reachable here
    /// instead. This is the only way to test it without breaking the machine.
    SimulateAllocationFailure,
}

impl TtyPolicy {
    fn acquire(self) -> Result<Pty, TtyError> {
        match self {
            TtyPolicy::Pipes => Err(TtyError::NotATerminal),
            TtyPolicy::SimulateAllocationFailure => Err(TtyError::Simulated),
            TtyPolicy::Auto if tty::is_interactive() => tty::allocate(),
            TtyPolicy::Auto => Err(TtyError::NotATerminal),
        }
    }
}

/// One `--secret` request: which name to look up, and which variable to put it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The environment variable the child will see.
    pub env: String,
    /// The name to look up in the stores.
    pub name: String,
}

impl Binding {
    /// Parse `NAME` or `ENV=NAME`.
    ///
    /// The two-part form exists because the store's name for a credential and
    /// the variable a tool reads are often different — `gh` wants
    /// `GITHUB_TOKEN` whatever the item is called.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (env, name) = match spec.split_once('=') {
            Some((env, name)) => (env.trim(), name.trim()),
            None => (spec.trim(), spec.trim()),
        };
        if name.is_empty() {
            return Err(format!("`{spec}` names no secret"));
        }
        if !is_valid_env_name(env) {
            return Err(format!(
                "`{env}` is not a usable environment variable name (letters, digits and underscore, not starting with a digit)"
            ));
        }
        if let Some(reason) = hijacks_the_child(env) {
            return Err(format!(
                "`{env}` cannot be bound to a secret: {reason}. The value would choose what \
                 the child runs, and masking would hide it while it did"
            ));
        }
        Ok(Binding {
            env: env.to_owned(),
            name: name.to_owned(),
        })
    }
}

fn is_valid_env_name(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Variables whose value decides **which code runs**, before the child's own
/// first instruction. Bound to a secret, the store chooses the program.
///
/// # The attack this closes
///
/// ```console
/// $ keyless run -s PATH=DECOY -- sh -c '...'
/// ```
///
/// resolved `DECOY` out of the store, put it in `PATH`, and the `sh` that ran
/// came from the directory the stored VALUE named — not from `/bin`. **And the
/// value is a needle in the masker, so it is redacted out of everything the run
/// prints while it is doing this.** A substitution that is both effective and
/// invisible is the worst combination available, and nothing else in this tool
/// lets a store's contents reach a decision rather than a variable.
///
/// # Why this is a denylist, and why a denylist cannot be complete
///
/// An allowlist is not available: the whole product is binding a value to a
/// variable name that only the caller's tool knows — `GITHUB_TOKEN`,
/// `STRIPE_KEY`, whatever an internal service reads. There is no set of legal
/// names to enumerate.
///
/// So this is a denylist, and a denylist over "variables that cause code to be
/// loaded" is **open-ended by construction**: every interpreter is free to
/// invent one, and `PYTHONPATH`, `NODE_OPTIONS`, `PERL5LIB`, `RUBYOPT`,
/// `JAVA_TOOL_OPTIONS` and `GEM_PATH` are each a code-loading variable belonging
/// to software this crate does not know about and cannot enumerate.
///
/// What this list is therefore scoped to is the boundary `keyless` itself owns:
/// **the variables the operating system's process startup and dynamic linker
/// read, plus the ones the shell reads before it runs the command it was
/// given.** Those decide what happens between this tool's `execve` and the
/// child's first instruction, which is the interval this tool is responsible
/// for. Past that instruction the child is running its own code and its own
/// rules, and a value bound to `NODE_OPTIONS` is the caller's to get right.
///
/// Stated plainly rather than implied, because the alternative is a reader
/// believing the list is exhaustive: **binding a secret to a variable your
/// interpreter treats as code is still possible and is still a bad idea.**
fn hijacks_the_child(env: &str) -> Option<&'static str> {
    // Exact names read by process startup or by a shell before it runs its
    // argument. `IFS` re-splits words; `ENV`, `BASH_ENV` and `ZDOTDIR` name a
    // file the shell SOURCES; `SHELLOPTS` turns options on, `xtrace` among
    // them; `CDPATH` redirects a `cd`.
    const STARTUP: &[&str] = &[
        "PATH",
        "IFS",
        "ENV",
        "BASH_ENV",
        "ZDOTDIR",
        "SHELLOPTS",
        "CDPATH",
    ];
    if STARTUP.contains(&env) {
        return Some("it decides which program the child finds and runs");
    }
    // The dynamic linkers, by prefix: glibc and musl read `LD_PRELOAD`,
    // `LD_LIBRARY_PATH` and `LD_AUDIT`; dyld reads `DYLD_INSERT_LIBRARIES` and
    // `DYLD_LIBRARY_PATH`. A prefix rather than a list, because both families
    // keep adding members and a missed one loads attacker code.
    if env.starts_with("LD_") || env.starts_with("DYLD_") {
        return Some("the dynamic linker loads code named by it, before `main`");
    }
    None
}

/// Everything one `run` needs.
///
/// A struct rather than seven arguments so a caller cannot silently pass the
/// audit log where the registry belongs, and so tests construct exactly what
/// `main` constructs.
pub struct RunRequest<'a> {
    /// Parsed `--secret` requests.
    pub bindings: &'a [Binding],
    /// Requests that could not even be parsed. They count as unresolved, so a
    /// typo degrades the run instead of failing it.
    pub unusable: &'a [String],
    /// The child command and its arguments.
    pub argv: &'a [OsString],
    /// Backends to ask.
    pub registry: &'a Registry,
    /// Where to record what happened. `None` disables recording.
    pub audit: Option<&'a AuditLog>,
    /// Lines to print before anything else — config problems, mostly.
    pub warnings: &'a [String],
    /// Whether the child may be given a pseudo-terminal.
    pub tty: TtyPolicy,
}

/// What a `run` did.
#[derive(Debug)]
pub struct Outcome {
    /// Whether the environment was modified.
    pub state: State,
    /// The child's exit code, or `128 + signal` if it was killed.
    pub exit_code: i32,
    /// Names that were injected. Empty when degraded.
    pub injected: Vec<String>,
    /// Names that were requested and did not arrive.
    pub unresolved: Vec<String>,
}

/// Resolve, inject, spawn, mask, record.
///
/// `notes` receives the human-facing warnings. It is a parameter rather than
/// `eprintln!` so tests can read what a caller would have seen.
pub fn run(request: RunRequest<'_>, notes: &mut dyn Write) -> Result<Outcome, RunError> {
    let Some((program, args)) = request.argv.split_first() else {
        return Err(RunError::NoCommand);
    };

    for warning in request.warnings {
        let _ = writeln!(notes, "{NAME}: warning: {warning}");
    }

    let mut resolved: Vec<(String, Secret)> = Vec::new();
    let mut injected_names: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = request.unusable.to_vec();
    let mut reasons: Vec<String> = Vec::new();
    // Which backends answered, for the audit row. A `run` can only ever reach a
    // reader — the write identities are not in a `Registry` and cannot be —
    // so the row says `<store> (reader)` and a row that ever said `(manager)`
    // could not have come from here.
    let mut identities: Vec<String> = Vec::new();

    for (binding, resolution) in
        request
            .bindings
            .iter()
            .zip(resolve_all(request.registry, request.bindings, notes))
    {
        match resolution {
            Resolution::Found { store, secret } => {
                let usable = !secret.expose().as_bytes().contains(&0);
                // Kept in `resolved` either way, because `resolved` is what the
                // masker is compiled from and a value that resolved is a value
                // worth redacting whether or not it can be injected.
                injected_names.push(binding.name.clone());
                resolved.push((binding.env.clone(), secret));
                if usable {
                    let identity = format!("{store} (reader)");
                    if !identities.contains(&identity) {
                        identities.push(identity);
                    }
                } else {
                    // An environment value is a NUL-terminated C string, so a
                    // value containing a NUL cannot be one. Reaching `execve`
                    // with it is not a degrade, it is `RunError::SpawnFailed`
                    // and exit 127 — the child never runs. Refused here, where
                    // it costs the documented degrade instead.
                    unresolved.push(binding.name.clone());
                    reasons.push(format!(
                        "{}: the value contains a NUL byte, which no environment variable can hold",
                        binding.name
                    ));
                }
            }
            other => {
                unresolved.push(binding.name.clone());
                reasons.push(format!("{}: {}", binding.name, other.reason()));
            }
        }
    }

    // Not final: the kernel gets one more say at the spawn, below.
    let mut state = if unresolved.is_empty() {
        State::Injected
    } else {
        State::Degraded
    };

    // Redaction is compiled from whatever resolved, in BOTH states. In
    // `Degraded` nothing is injected, but a value that resolved is still a
    // value: if the caller typed it on the command line as a literal — the
    // habit this tool replaces — masking keeps it out of the audit log and out
    // of the child's echoed output. Masking more is never worse than masking
    // less; it is injection that is withheld when degraded, not redaction.
    let masker = Arc::new(Masker::from_secrets(
        resolved
            .iter()
            .zip(&injected_names)
            .map(|((_, secret), name)| (name.as_str(), secret)),
    ));

    if state == State::Degraded {
        let _ = writeln!(
            notes,
            "{NAME}: {state} — {} names unresolved: {}",
            unresolved.len(),
            unresolved.join(", ")
        );
        for reason in reasons.iter().take(MAX_REASONS_SHOWN) {
            let _ = writeln!(notes, "{NAME}:   {reason}");
        }
        if reasons.len() > MAX_REASONS_SHOWN {
            let _ = writeln!(
                notes,
                "{NAME}:   ... and {} more",
                reasons.len() - MAX_REASONS_SHOWN
            );
        }
        injected_names.clear();
    }

    // Masking needs the child's output to come through this process, and the
    // question is only what to route it through. A pty preserves everything a
    // terminal means — `isatty`, colour, progress bars, prompts — and a pipe
    // preserves none of it. With nothing to mask, neither is used and the
    // child inherits this process's stdio untouched.
    let masking = !masker.is_empty();
    let mut prepared = if masking {
        acquire_terminal(request.tty, notes)
    } else {
        None
    };

    let mut plan = match prepared.as_mut().and_then(Prepared::take_slave) {
        Some(slave) => StdioPlan::Pty(slave),
        None if masking => StdioPlan::Pipes,
        None => StdioPlan::Inherit,
    };

    let mut command = assemble(program, args, injection(state, &resolved), &mut plan, notes);
    if !matches!(plan, StdioPlan::Pty(_)) {
        // The pty wiring failed and `assemble` fell back to pipes. Dropping the
        // preparation restores the terminal and the signal mask before anything
        // else happens.
        prepared = None;
    }

    let mut child = match spawn_persistently(&mut command) {
        Ok(child) => child,
        // The kernel refused this *environment*, not this command. Both known
        // causes are about size and shape rather than about whether the program
        // exists, and both used to exit 127 with no child — the exact shape the
        // never-block invariant forbids. So the injection is dropped and the
        // command is spawned again, degraded, which is what every other
        // resolution failure already does.
        Err(source) if state == State::Injected && caused_by_the_environment(&source) => {
            let _ = writeln!(
                notes,
                "{NAME}: {} — the child could not be started with the secrets in its \
                 environment ({source}); running it with an unmodified one",
                State::Degraded
            );
            state = State::Degraded;
            unresolved.append(&mut injected_names);
            let mut retry = assemble(program, args, &[], &mut plan, notes);
            if !matches!(plan, StdioPlan::Pty(_)) {
                prepared = None;
            }
            spawn_persistently(&mut retry).map_err(|source| RunError::SpawnFailed {
                program: program.to_string_lossy().into_owned(),
                source,
            })?
        }
        Err(source) => {
            return Err(RunError::SpawnFailed {
                program: program.to_string_lossy().into_owned(),
                source,
            });
        }
    };

    // The plaintext has reached the child. Drop our copies now rather than at
    // the end of the function, so they are not resident for the child's whole
    // life. `Command` keeps its own copy of the environment which std gives us
    // no way to scrub — an honest limit, not a solved problem.
    drop(command);
    resolved.clear();

    // A pty carries one merged stream; pipes carry two. Either way the bytes go
    // through the same masker, and on the pty path through the same pump.
    let mut relay: Option<Relay> = prepared.map(|prepared| {
        prepared.start(Pid::from_raw(child.id().cast_signed()), Arc::clone(&masker))
    });

    // One `finished` message per pump. Threads rather than join handles is not
    // the interesting part — a channel is, because `JoinHandle` has no timed
    // join and the drain below has to be bounded. See [`PUMP_DRAIN_GRACE`].
    let (finished, pumps_done) = mpsc::channel::<()>();
    let mut pumps = 0_usize;
    if relay.is_none() && masking {
        let mut start = |body: Box<dyn FnOnce() + Send>, notes: &mut dyn Write| {
            match thread::Builder::new()
                .name("keyless-mask".to_owned())
                .spawn(body)
            {
                Ok(_) => pumps += 1,
                // The OS refused a thread. The child is already running and its
                // exit code is still owed to the caller, so this costs the
                // masking of one stream and nothing else.
                Err(error) => {
                    let _ = writeln!(
                        notes,
                        "{NAME}: warning: cannot start the output filter ({error}); \
                         one stream of the child's output is not redacted"
                    );
                }
            }
        };
        // `io::stdout()` and not `io::stdout().lock()`, and that is the second
        // half of the bounded drain rather than a style choice. A held lock is
        // released when its guard drops, and a filter abandoned at the deadline
        // never drops anything — it is still blocked on a read of a pipe a
        // grandchild holds open. Holding the process-wide stdout lock for the
        // pump's whole life therefore moved the hang instead of removing it:
        // `run` returned on time, and `main`'s closing `stdout().flush()`
        // blocked forever on the guard nobody would ever drop.
        //
        // Locking per write costs one uncontended acquisition per 8 KiB read and
        // keeps each `write_all` atomic, which is the only atomicity a stream
        // filter needs.
        if let Some(stream) = child.stdout.take() {
            let masker = Arc::clone(&masker);
            let finished = finished.clone();
            start(
                Box::new(move || {
                    let _ = pump(stream, io::stdout(), masker);
                    let _ = finished.send(());
                }),
                notes,
            );
        }
        if let Some(stream) = child.stderr.take() {
            let masker = Arc::clone(&masker);
            let finished = finished.clone();
            start(
                Box::new(move || {
                    let _ = pump(stream, io::stderr(), masker);
                    let _ = finished.send(());
                }),
                notes,
            );
        }
    }
    // The loop's own clone would otherwise keep the channel open forever.
    drop(finished);

    let status = child.wait();

    // Drop order matters: the relay drains the child's remaining output, stops
    // its threads, and only then puts the terminal back. Everything printed
    // after this point is written to a terminal in its normal mode.
    if let Some(relay) = relay.as_mut() {
        relay.drain();
    }
    drop(relay);

    drain_pumps(pumps, &pumps_done, notes);

    let exit_code = match status {
        Ok(status) => exit_code_of(&status),
        Err(error) => {
            let _ = writeln!(notes, "{NAME}: warning: cannot reap child: {error}");
            1
        }
    };

    if let Some(log) = request.audit {
        let event = Event::new("run", state, injected_names.clone(), request.argv, &masker)
            .with_unresolved(unresolved.clone())
            .with_identities(identities.clone())
            .with_exit_code(exit_code);
        if let Err(error) = log.append(&event) {
            let _ = writeln!(notes, "{NAME}: warning: {error}");
        }
    }

    Ok(Outcome {
        state,
        exit_code,
        injected: injected_names,
        unresolved,
    })
}

/// Ask every backend for every name at once.
///
/// # Why this is not a loop
///
/// A lookup's deadline is per-lookup, so sequentially N names that each hit it
/// cost N × the deadline. Measured 2026-08-08 against a backend that never
/// answers: **three names took 36.03 seconds before the child ran.** Thirty
/// names is five minutes of a terminal doing nothing, and the run does still
/// happen at the end of it — which is worse than failing, because nothing on
/// screen says waiting is the correct thing to do.
///
/// Concurrently, N names cost one deadline. That is the difference between a
/// pause and a hang, and the never-block invariant is about the second.
///
/// A backend that the OS will not give a thread for is resolved on this thread
/// instead: slower is not a failure, and [`thread::Builder`] is what makes that
/// a branch rather than a panic.
fn resolve_all(
    registry: &Registry,
    bindings: &[Binding],
    notes: &mut dyn Write,
) -> Vec<Resolution> {
    if bindings.len() < 2 {
        return bindings
            .iter()
            .map(|binding| registry.resolve(&binding.name))
            .collect();
    }

    let mut slots: Vec<Option<Resolution>> = bindings.iter().map(|_| None).collect();
    thread::scope(|scope| {
        let mut running = Vec::new();
        for (index, binding) in bindings.iter().enumerate() {
            let started = thread::Builder::new()
                .name(format!("keyless-resolve-{index}"))
                .spawn_scoped(scope, || registry.resolve(&binding.name));
            match started {
                Ok(handle) => running.push((index, handle)),
                Err(error) => {
                    let _ = writeln!(
                        notes,
                        "{NAME}: warning: cannot look `{}` up concurrently ({error}); \
                         doing it in turn",
                        binding.name
                    );
                    slots[index] = Some(registry.resolve(&binding.name));
                }
            }
        }
        for (index, handle) in running {
            slots[index] = Some(handle.join().unwrap_or_else(|_| {
                Resolution::Failed(vec![crate::error::StoreError::Unavailable {
                    store: "keyless".to_owned(),
                    detail: "the lookup ended unexpectedly".to_owned(),
                }])
            }));
        }
    });

    slots
        .into_iter()
        // Every slot is filled by one of the two arms above; this is the
        // expression that says so without an `unwrap`.
        .map(|slot| slot.unwrap_or(Resolution::NotFound))
        .collect()
}

/// How long the masking filters get to finish after the child has been reaped.
///
/// # Why a bound, when the child has already exited
///
/// A pipe reaches end-of-file when the LAST writer closes it, and the child's
/// own children inherit it. So:
///
/// ```console
/// $ keyless run -s DECOY -- sh -c 'echo ran > proof; sleep 300 &'
/// ```
///
/// reaps `sh` immediately and then waits five minutes on a pipe held open by a
/// grandchild nobody is watching. Measured 2026-08-08: 300 s on this path, 0.20 s
/// with no secret to mask, 0.01 s on a real pty. **The hang belongs to masking
/// plus pipes, which is exactly what a CI job, a script and an agent's shell
/// call all get** — the one caller who would have seen a terminal is the one
/// caller not affected.
///
/// Two seconds is far more than draining a pipe that already has its bytes in it
/// needs, and it is not a wait anybody experiences as a hang. What it costs, in
/// the case above, is the output a backgrounded grandchild writes after its
/// parent exits — which a shell would not have shown either once its pipeline
/// ended.
const PUMP_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Wait for the masking filters, but not forever.
fn drain_pumps(pumps: usize, done: &mpsc::Receiver<()>, notes: &mut dyn Write) {
    let deadline = std::time::Instant::now() + PUMP_DRAIN_GRACE;
    for _ in 0..pumps {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if done.recv_timeout(left).is_err() {
            let _ = writeln!(
                notes,
                "{NAME}: warning: the child exited but something it started still holds its \
                 output open; anything written from here on is not shown"
            );
            return;
        }
    }
}

/// How the child's three standard streams are arranged.
///
/// Named, because the command is assembled from it more than once: a spawn that
/// the kernel refuses because of the ENVIRONMENT is retried without one, and a
/// `Command`'s stdio cannot be read back out of it.
enum StdioPlan {
    /// The child inherits this process's stdio untouched. Nothing to mask.
    Inherit,
    /// Two pipes through the masking filters.
    Pipes,
    /// One pseudo-terminal, held so it can be wired more than once.
    Pty(OwnedFd),
}

/// What actually goes into the child's environment, given the state.
fn injection(state: State, resolved: &[(String, Secret)]) -> &[(String, Secret)] {
    if state == State::Injected {
        resolved
    } else {
        &[]
    }
}

/// Build the command. Never fails — a pty that cannot be wired becomes pipes.
fn assemble(
    program: &std::ffi::OsStr,
    args: &[OsString],
    injected: &[(String, Secret)],
    plan: &mut StdioPlan,
    notes: &mut dyn Write,
) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    for (env, secret) in injected {
        command.env(env, secret.expose());
    }
    match plan {
        StdioPlan::Inherit => {}
        StdioPlan::Pipes => {
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
        }
        StdioPlan::Pty(slave) => {
            if let Err(error) = wire_pty(&mut command, slave) {
                let _ = writeln!(notes, "{NAME}: warning: {error}; falling back to pipes");
                *plan = StdioPlan::Pipes;
                command.stdout(Stdio::piped());
                command.stderr(Stdio::piped());
            }
        }
    }
    command
}

/// How many times to try again when the machine, not the command, said no.
const SPAWN_ATTEMPTS: u32 = 5;

/// Spawn, retrying while the OS is merely out of process slots.
///
/// `EAGAIN` from `fork` means "not right now", never "not ever": the caller is
/// at `RLIMIT_NPROC` and the count drops as soon as anything exits — including
/// the store subprocesses this run has just finished with. Measured 2026-08-08
/// under `RLIMIT_NPROC` of 128, 256 and 512: `keyless run` exited 127 with no
/// child where a fork-depth-matched control shell exited 42. One retry loop
/// closes the whole of that gap, because the condition is transient by
/// definition and this process is not the one holding the slots.
///
/// Bounded rather than unbounded: a limit of 0, or a machine genuinely out of
/// processes, must end as a reported failure and not as a spin.
fn spawn_persistently(command: &mut Command) -> io::Result<std::process::Child> {
    let mut backoff = std::time::Duration::from_millis(10);
    let mut last = None;
    for attempt in 0..SPAWN_ATTEMPTS {
        // Through the same gate the store lookups use. Nothing else should be
        // spawning by now, but "should" is what the fd-inheritance race feeds
        // on, and one uncontended mutex is not a cost worth reasoning about.
        match crate::store::exec::spawn_serialised(command) {
            Ok(child) => return Ok(child),
            // `EAGAIN` and `EWOULDBLOCK` are the same number on the platforms
            // this builds for, and std maps it to `WouldBlock`. The raw check is
            // kept beside it so a platform where they differ still retries.
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(nix::libc::EAGAIN) =>
            {
                last = Some(error);
                if attempt + 1 < SPAWN_ATTEMPTS {
                    thread::sleep(backoff);
                    backoff *= 2;
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("the process could not be started")))
}

/// Whether a spawn failure is about the environment being injected rather than
/// about the command.
///
/// Both members are measured, and each of them used to end the run at exit 127
/// with no child:
///
/// - A value containing a NUL byte. std rejects it before `execve` and reports
///   `InvalidInput` — `cannot execute /bin/sh: nul byte found`, which names the
///   wrong culprit entirely. Also refused earlier, at resolution, where the
///   message can name the secret; this is the backstop.
/// - A value large enough to exceed `ARG_MAX`. `E2BIG`, `Argument list too
///   long`. Measured on macOS: 1.0 MB runs, 1.5 MB does not. **Deliberately not
///   pre-checked**, because the true limit is the kernel's and counts the
///   argument list, the inherited environment and the pointer array together —
///   a guess tight enough to be safe would refuse runs that work today, and the
///   kernel is the only thing that knows the answer exactly. So it is allowed to
///   answer, and the answer is a degrade rather than a failure.
///
/// A retry is sound because neither failure leaves anything behind: std reports
/// an exec failure from the forked child over a pipe, and that child then exits.
/// There is no half-spawned process to collide with.
fn caused_by_the_environment(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::InvalidInput {
        return true;
    }
    error.raw_os_error() == Some(nix::libc::E2BIG)
}

/// The child's exit code, following the shell convention for signals.
fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

/// Obtain a pseudo-terminal, or explain on stderr why the child is getting a
/// pipe instead.
///
/// Never returns an error, by construction. Every failure here is a *degraded
/// experience*, never a refusal: the caller carries on to the spawn either way.
/// The silent case is deliberate — not being at a terminal is the ordinary
/// state of a script, a CI job or an agent's shell call, and announcing it on
/// every invocation would train the reader to ignore this tool's stderr.
fn acquire_terminal(policy: TtyPolicy, notes: &mut dyn Write) -> Option<Prepared> {
    let outcome = policy.acquire().and_then(Prepared::new);
    match outcome {
        Ok(prepared) => Some(prepared),
        Err(TtyError::NotATerminal) => None,
        Err(error) => {
            let _ = writeln!(
                notes,
                "{NAME}: warning: no pseudo-terminal ({error}); the child's output is piped, \
                 so it will behave as though it is not on a terminal"
            );
            None
        }
    }
}

/// Wire the pty slave into the child's three standard streams.
///
/// The duplicates are taken first so a failure leaves `command` untouched and
/// the caller can fall back to pipes with nothing half-configured. The slave is
/// borrowed rather than consumed, because a command refused for its environment
/// is assembled a second time and would otherwise have no terminal left to wire.
fn wire_pty(command: &mut Command, slave: &OwnedFd) -> io::Result<()> {
    let for_stdin = slave.try_clone()?;
    let for_stdout = slave.try_clone()?;
    let for_stderr = slave.try_clone()?;
    command.stdin(Stdio::from(for_stdin));
    command.stdout(Stdio::from(for_stdout));
    command.stderr(Stdio::from(for_stderr));

    // Hoisted out of the `unsafe` block below so its own SAFETY comment still
    // means something: inside that block the compiler would treat this call as
    // already justified, and the reason it is sound would go unstated.
    let enter_pty_session = || -> io::Result<()> {
        // SAFETY: `pre_exec` runs after the standard library has dup'd the
        // configured stdio into place, so fd 0 is the pty slave.
        unsafe { tty::adopt_controlling_terminal() }?;
        // A blocked signal mask survives `exec`. This process blocks five
        // signals so it can `sigwait` on them; inheriting that would leave the
        // child unable to see its own Ctrl-C or its own resize.
        SigSet::empty().thread_set_mask().map_err(io::Error::from)
    };
    // SAFETY: the closure calls only async-signal-safe functions — `setsid`,
    // `ioctl` and `pthread_sigmask` — and allocates nothing, which is the whole
    // of `pre_exec`'s contract.
    unsafe {
        command.pre_exec(enter_pty_session);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Binding;

    #[test]
    fn a_bare_name_binds_to_itself() {
        assert_eq!(
            Binding::parse("GITHUB_TOKEN").expect("valid"),
            Binding {
                env: "GITHUB_TOKEN".to_owned(),
                name: "GITHUB_TOKEN".to_owned()
            }
        );
    }

    #[test]
    fn an_alias_binds_to_a_different_variable() {
        let binding = Binding::parse("GH_TOKEN=work-github-pat").expect("valid");
        assert_eq!(binding.env, "GH_TOKEN");
        assert_eq!(binding.name, "work-github-pat");
    }

    #[test]
    fn an_unusable_variable_name_is_rejected_at_parse_time() {
        assert!(Binding::parse("9LIVES").is_err());
        assert!(Binding::parse("has space=X").is_err());
        assert!(Binding::parse("=X").is_err());
        assert!(Binding::parse("X=").is_err());
    }

    #[test]
    fn underscores_and_digits_are_fine_after_the_first_character() {
        assert!(Binding::parse("_PRIVATE_1").is_ok());
    }
}
