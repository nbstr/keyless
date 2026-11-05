//! Assembling the child's command, wiring its terminal, and spawning it.

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use nix::sys::signal::SigSet;

use super::TtyPolicy;
use crate::secret::Secret;
use crate::tty::relay::Prepared;
use crate::tty::{self, Pty, TtyError};
use crate::{NAME, State};

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

/// How the child's three standard streams are arranged.
///
/// Named, because the command is assembled from it more than once: a spawn that
/// the kernel refuses because of the ENVIRONMENT is retried without one, and a
/// `Command`'s stdio cannot be read back out of it.
pub(super) enum StdioPlan {
    /// The child inherits this process's stdio untouched. Nothing to mask.
    Inherit,
    /// Two pipes through the masking filters.
    Pipes,
    /// One pseudo-terminal, held so it can be wired more than once.
    ///
    /// `None` once the child has been spawned and this process has closed its
    /// own copy — see [`StdioPlan::release_slave`], which is the step that
    /// decides whether the run ever ends. The variant stays `Pty` either way,
    /// because "the pty wiring survived" is what the caller tests it for.
    Pty(Option<OwnedFd>),
}

impl StdioPlan {
    /// Close this process's copy of the pty slave, now the child has its own.
    ///
    /// # Why this is not housekeeping
    ///
    /// A pty master reports end-of-stream only when the LAST slave descriptor
    /// closes. The output filter reads that master, so one forgotten copy in
    /// this process leaves the filter blocked in `read` forever — after the
    /// child is dead, after it has been reaped, with nothing left to report it.
    ///
    /// **macOS hid this and Linux did not, which is why it shipped.** The child
    /// is a session leader owning the pty, and XNU *revokes* a controlling
    /// terminal when its session ends: every other descriptor onto that
    /// terminal is invalidated and the master is handed an end-of-file it never
    /// earned. Linux performs no such revoke, so the leaked descriptor keeps
    /// the pty open and `keyless run` hangs indefinitely. Measured 2026-08-09
    /// on rust 1.89 / aarch64, parent holding one slave copy, child gone:
    ///
    /// | child owned the tty as session leader | macOS | Linux |
    /// |---|---|---|
    /// | no  | master read blocks | master read blocks |
    /// | yes | master read returns 0 | master read blocks |
    ///
    /// So the macOS column was never evidence that this process had let go. It
    /// is evidence that something else let go on its behalf.
    pub(super) fn release_slave(&mut self) {
        if let StdioPlan::Pty(slave) = self {
            // Dropping the descriptor is the close.
            drop(slave.take());
        }
    }
}

/// What actually goes into the child's environment, given the state.
pub(super) fn injection(
    state: State,
    resolved: &[(Vec<String>, Secret)],
) -> &[(Vec<String>, Secret)] {
    if state == State::Injected {
        resolved
    } else {
        &[]
    }
}

/// Build the command. Never fails — a pty that cannot be wired becomes pipes.
pub(super) fn assemble(
    program: &std::ffi::OsStr,
    args: &[OsString],
    injected: &[(Vec<String>, Secret)],
    plan: &mut StdioPlan,
    notes: &mut dyn Write,
) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    for (variables, secret) in injected {
        for env in variables {
            command.env(env, secret.expose());
        }
    }
    match plan {
        StdioPlan::Inherit => {}
        StdioPlan::Pipes => {
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
        }
        // `None` cannot happen: the plan is only ever re-assembled BEFORE the
        // spawn, and the slave is released only after one. It is still handled
        // as an ordinary wiring failure rather than with an `unwrap`, because
        // falling back to pipes is the right outcome for every other way this
        // step fails and the never-block rule does not make an exception for a
        // case the author believes is unreachable.
        StdioPlan::Pty(None) => {
            let _ = writeln!(
                notes,
                "{NAME}: warning: the pseudo-terminal was already handed to a child; \
                 falling back to pipes"
            );
            *plan = StdioPlan::Pipes;
            command.stdout(Stdio::piped());
            command.stderr(Stdio::piped());
        }
        StdioPlan::Pty(Some(slave)) => {
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

/// Spawn the run's own child, retrying while the OS is merely out of process
/// slots.
///
/// The retry, the backoff and the errno that qualifies for one all live in
/// [`crate::store::exec`], beside the mutex that serialises the act of forking.
/// One place owns "create a child on this machine", so a store lookup and a run
/// cannot disagree about what `EAGAIN` means — and that function holds the only
/// `Command::spawn` call in `src/`, so there is no door into a spawn that skips
/// the retry.
///
/// `None` rather than a deadline: reaching the spawn IS this call's contract,
/// nothing is waiting on it, and a run that gave up early would be the
/// never-block failure the retry exists to remove.
pub(super) fn spawn_persistently(command: &mut Command) -> io::Result<std::process::Child> {
    crate::store::exec::spawn_persistently(command, None)
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
pub(super) fn caused_by_the_environment(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::InvalidInput {
        return true;
    }
    error.raw_os_error() == Some(nix::libc::E2BIG)
}

/// The child's exit code, following the shell convention for signals.
pub(super) fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
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
pub(super) fn acquire_terminal(policy: TtyPolicy, notes: &mut dyn Write) -> Option<Prepared> {
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
