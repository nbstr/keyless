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

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Arc;
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

    for binding in request.bindings {
        match request.registry.resolve(&binding.name) {
            Resolution::Found { store, secret } => {
                injected_names.push(binding.name.clone());
                let identity = format!("{store} (reader)");
                if !identities.contains(&identity) {
                    identities.push(identity);
                }
                resolved.push((binding.env.clone(), secret));
            }
            other => {
                unresolved.push(binding.name.clone());
                reasons.push(format!("{}: {}", binding.name, other.reason()));
            }
        }
    }

    let state = if unresolved.is_empty() {
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

    let mut command = Command::new(program);
    command.args(args);
    if state == State::Injected {
        for (env, secret) in &resolved {
            command.env(env, secret.expose());
        }
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

    match prepared.as_mut().and_then(Prepared::take_slave) {
        Some(slave) => {
            if let Err(error) = wire_pty(&mut command, slave) {
                let _ = writeln!(notes, "{NAME}: warning: {error}; falling back to pipes");
                // Dropping the preparation restores the terminal and the signal
                // mask before anything else happens.
                prepared = None;
                command.stdout(Stdio::piped());
                command.stderr(Stdio::piped());
            }
        }
        None if masking => {
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
        }
        None => {}
    }

    let mut child = command.spawn().map_err(|source| RunError::SpawnFailed {
        program: program.to_string_lossy().into_owned(),
        source,
    })?;

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

    let mut pumps = Vec::new();
    if relay.is_none() && masking {
        if let Some(stream) = child.stdout.take() {
            let masker = Arc::clone(&masker);
            pumps.push(thread::spawn(move || {
                pump(stream, io::stdout().lock(), masker)
            }));
        }
        if let Some(stream) = child.stderr.take() {
            let masker = Arc::clone(&masker);
            pumps.push(thread::spawn(move || {
                pump(stream, io::stderr().lock(), masker)
            }));
        }
    }

    let status = child.wait();

    // Drop order matters: the relay drains the child's remaining output, stops
    // its threads, and only then puts the terminal back. Everything printed
    // after this point is written to a terminal in its normal mode.
    if let Some(relay) = relay.as_mut() {
        relay.drain();
    }
    drop(relay);

    for pump in pumps {
        // A broken pipe downstream is not this tool's problem to report, and a
        // panicked pump must not turn into a panic here.
        let _ = pump.join();
    }

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
/// the caller can fall back to pipes with nothing half-configured.
fn wire_pty(command: &mut Command, slave: OwnedFd) -> io::Result<()> {
    let for_stdin = slave.try_clone()?;
    let for_stdout = slave.try_clone()?;
    command.stdin(Stdio::from(for_stdin));
    command.stdout(Stdio::from(for_stdout));
    command.stderr(Stdio::from(slave));

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
