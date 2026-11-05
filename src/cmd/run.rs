//! `keyless run` — the whole product.
//!
//! Resolve named secrets, put them in a child process's environment, redact
//! them from the child's output, record what happened, and forward the child's
//! exit code.
//!
//! # The invariant
//!
//! This function spawns the child on every path where a failure is not the
//! caller's. There is no early return for a missing store, a silent store, a
//! corrupt config, or a backend or daemon that errors — each of those sets
//! [`State::Degraded`], writes one line to stderr, and continues to the spawn.
//!
//! The one deliberate way out without a child is a refused run: a store
//! answered the request, and the answer is that it is wrong — a name the store
//! does not hold, an empty name, or a caller the daemon will not serve. That
//! sets [`State::Refused`] and returns [`EXIT_REFUSED`]; `resolve::fate`
//! decides which verdicts refuse. The other
//! two are [`RunError::NoCommand`] (nothing was asked for) and
//! [`RunError::SpawnFailed`] (the command does not exist).
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
//! [`spawn::caused_by_the_environment`] — and its refusal drops the injection and
//! spawns again, degraded. A refusal that says the machine is momentarily out of
//! process slots is retried rather than reported; see [`spawn::spawn_persistently`].
//!
//! So `SpawnFailed` means what it says: nothing this tool did to the environment
//! is left in the explanation.
//!
//! # Three things here are bounded on purpose
//!
//! Each was an unbounded wait that ended with the child either never running or
//! never being reported: [`resolve::resolve_all`] (N deadlines became one),
//! [`PUMP_DRAIN_GRACE`] (a grandchild holding the pipes), and
//! [`crate::store::exec::spawn_persistently`] (two concurrent spawns deadlocking
//! on an inherited descriptor, and a `fork` refused for want of process slots).
//! Read those three before changing the shape of this function.

use std::ffi::OsString;
use std::io::Write;
use std::sync::{Arc, mpsc};

use nix::unistd::Pid;

use crate::audit::{AuditLog, Event};
use crate::error::RunError;
use crate::mask::Masker;
use crate::store::Registry;
use crate::tty::relay::{Prepared, Relay};
use crate::{NAME, State};

mod binding;
mod filter;
mod resolve;
mod spawn;
mod variables;

#[cfg(test)]
mod binding_tests;
#[cfg(test)]
mod spawn_tests;
#[cfg(test)]
mod variables_tests;

use filter::{drain_pumps, start_filters, warn_output_left_open};
use resolve::{Gathered, gather};
use spawn::{
    StdioPlan, acquire_terminal, assemble, caused_by_the_environment, exit_code_of, injection,
    spawn_persistently,
};
use variables::{deconflict, quoting_warnings};

/// How many backend failure reasons to print under the degraded banner.
const MAX_REASONS_SHOWN: usize = 3;

/// The exit code of a refused run: `EX_USAGE`, because the request was wrong
/// and the child never started, so no exit code of its own exists.
pub const EXIT_REFUSED: i32 = 64;

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

/// One `--secret` request: which name to look up, and which variables to put it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The environment variable the child will see.
    pub env: String,
    /// The name to look up in the stores.
    pub name: String,
    /// The other variables this credential answers to, from its declaration.
    ///
    /// Empty when the caller spelled `ENV=NAME`, and empty for a name no config
    /// declares. See [`Binding::declared`] and [`crate::config::SecretRoute::aliases`].
    pub also: Vec<String>,
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
/// with no secret to mask.
///
/// **The pty path has the same hole and it is bounded by this same number.** A
/// pty master reports end-of-stream on the same rule a pipe does — when the last
/// holder lets go — so [`crate::tty::relay::Relay::drain`] reads this constant
/// too. On Linux the grandchild has to survive the `SIGHUP` that ends the
/// child's session before it can hold the terminal open, which one `trap` does;
/// on macOS it cannot hold it open at all, because XNU revokes a controlling
/// terminal when its session dies. So this bound is load-bearing on exactly one
/// of the two platforms, and unobservable on the other.
///
/// Two seconds is far more than draining a stream that already has its bytes in
/// it needs, and it is not a wait anybody experiences as a hang. What it costs,
/// in the case above, is the output a backgrounded grandchild writes after its
/// parent exits — which a shell would not have shown either once its pipeline
/// ended.
pub(crate) const PUMP_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

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

    // Which variables each request may set, after two requests that would have
    // landed in the same one have been separated. Computed before anything is
    // resolved, because it is a property of what was asked for.
    let plans = deconflict(request.bindings, notes);

    for warning in quoting_warnings(program, args, &plans) {
        let _ = writeln!(notes, "{NAME}: warning: {warning}");
    }

    let Gathered {
        mut resolved,
        mut injected_names,
        mut unresolved,
        reasons,
        identities,
        refusals,
    } = gather(&request, plans, notes);

    // Read after every resolve above has had its turn, never before: a
    // backend's advisory is the reply to the request this run just made, not
    // a standing fact it could have been asked for earlier.
    for advisory in request
        .registry
        .stores()
        .iter()
        .filter_map(|store| store.advisory())
    {
        let _ = writeln!(notes, "{NAME}: warning: {advisory}");
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

    if !refusals.is_empty() {
        return Ok(refuse(&request, &refusals, &masker, notes));
    }

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
        Some(slave) => StdioPlan::Pty(Some(slave)),
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

    // The child holds the pty now, so this process must not. Ordered here, and
    // not at the end of the function where the descriptor would otherwise fall
    // out of scope, because the output filter below cannot reach end-of-stream
    // while any slave copy is open — see `StdioPlan::release_slave` for the
    // platform difference that kept this invisible.
    plan.release_slave();
    // The plaintext has reached the child. Drop our copies now rather than at
    // the end of the function, so they are not resident for the child's whole
    // life. `Command` keeps its own copy of the environment which std gives us
    // no way to scrub — an honest limit, not a solved problem.
    //
    // This is also the second half of the release above: `wire_pty` put three
    // more duplicates of the slave into this command, and they close here.
    drop(command);
    resolved.clear();

    // A pty carries one merged stream; pipes carry two. Either way the bytes go
    // through the same masker, and on the pty path through the same pump.
    let mut relay: Option<Relay> = prepared.map(|prepared| {
        prepared.start(Pid::from_raw(child.id().cast_signed()), Arc::clone(&masker))
    });

    let (pumps, pumps_done) = if relay.is_none() && masking {
        start_filters(&mut child, &masker, notes)
    } else {
        (0, mpsc::channel::<()>().1)
    };

    let status = child.wait();

    // Drop order matters: the relay drains the child's remaining output, stops
    // its threads, and only then puts the terminal back. Everything printed
    // after this point is written to a terminal in its normal mode.
    if let Some(relay) = relay.as_mut()
        && !relay.drain()
    {
        // The pty's own bounded drain gave up. Same sentence as the pipe path,
        // because it is the same event: something the child started is still
        // holding the stream open.
        warn_output_left_open(notes);
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

/// End a run whose request a store declined, without starting its child.
///
/// Every name is reported unresolved, the ones that did resolve included:
/// refusal is all or nothing, so none of them reached a child.
fn refuse(
    request: &RunRequest<'_>,
    refusals: &[String],
    masker: &Masker,
    notes: &mut dyn Write,
) -> Outcome {
    let state = State::Refused;
    let _ = writeln!(
        notes,
        "{NAME}: {state} — {} of {} names refused; the command was not run",
        refusals.len(),
        request.bindings.len() + request.unusable.len()
    );
    for refusal in refusals {
        let _ = writeln!(notes, "{NAME}:   {refusal}");
    }

    let unresolved: Vec<String> = request
        .unusable
        .iter()
        .cloned()
        .chain(request.bindings.iter().map(|binding| binding.name.clone()))
        .collect();
    if let Some(log) = request.audit {
        let event = Event::new("run", state, Vec::new(), request.argv, masker)
            .with_unresolved(unresolved.clone())
            .with_exit_code(EXIT_REFUSED);
        if let Err(error) = log.append(&event) {
            let _ = writeln!(notes, "{NAME}: warning: {error}");
        }
    }

    Outcome {
        state,
        exit_code: EXIT_REFUSED,
        injected: Vec::new(),
        unresolved,
    }
}
