//! Moving bytes between the user's terminal and the child's pty, for the life
//! of one child.
//!
//! Three threads, and each exists for a reason the other two cannot cover:
//!
//! - **output** — pty master → [`crate::mask::pump`] → this process's stdout.
//!   This is the only thread that touches secrets, and it runs the same pump the
//!   pipe path runs, so the carry behaviour cannot drift between the two paths.
//! - **input** — this process's stdin → pty master. Raw, unbuffered, byte for
//!   byte, because the child's line discipline is the one that gets to interpret
//!   Ctrl-C, arrow keys and a bracketed paste.
//! - **signals** — five signals this process takes over while the child lives.
//!
//! # No signal handler exists in this program
//!
//! The signals thread does not *handle* signals; it **waits** for them. The five
//! are blocked in every thread and consumed by `sigwait`, so the code that reacts
//! to a `SIGWINCH` is ordinary code on an ordinary stack. Nothing in `keyless`
//! runs in async-signal context, so nothing has to be async-signal-safe, and the
//! classic bugs of that context — a clobbered `errno`, a non-reentrant call, a
//! lock taken twice — are unreachable rather than avoided.
//!
//! It also buys terminal restoration for free. A `SIGINT` or `SIGTERM` is
//! forwarded to the child rather than acted on; the child dies, `wait` returns
//! in the main thread, and the run leaves through its ordinary exit path with the
//! terminal restored and the exit code intact. There is no path where a signal
//! kills this process with the user's terminal still raw.
//!
//! `Ctrl-C` never reaches this thread at all, and that is correct. The user's
//! terminal is raw, so the driver generates no `SIGINT` from it. The `0x03` byte
//! travels down the input relay into the pty, whose slave-side line discipline
//! *is* in canonical mode, and *that* driver raises `SIGINT` for the child's
//! foreground process group. The child is a session leader owning the pty, so
//! the signal lands exactly where the user aimed it.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::thread::{JoinHandleExt, RawPthread};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::pthread::pthread_kill;
use nix::sys::signal::{
    SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal, killpg, pthread_sigmask, sigaction,
};
use nix::unistd::{Pid, read, write};
use zeroize::Zeroize;

use super::{Pty, RawMode, TtyError, enter_raw_mode};
// One number, not two. How long a masking filter gets after the child has been
// reaped is a single policy, and the pipe path states it: duplicating the value
// here behind an equality test would be duplication with extra steps.
use crate::cmd::run::PUMP_DRAIN_GRACE;
use crate::mask::{Masker, pump};

/// The signals this process takes over while a child owns the terminal.
///
/// `SIGWINCH` is the one that is acted on; the other four are forwarded. They
/// are all in one list because they must all be blocked before any thread is
/// spawned — a signal that is merely *handled* is a signal that can still kill
/// the process while the terminal is raw.
const WATCHED: [Signal; 5] = [
    Signal::SIGWINCH,
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
];

/// A handler that is installed so it will never run.
///
/// See [`SignalGate::install`]. Its body must stay empty: it exists to change
/// `SIGWINCH`'s *disposition*, not to do work.
extern "C" fn catch_and_do_nothing(_signal: nix::libc::c_int) {}

/// The watched signals, blocked for this thread and every thread spawned after
/// it, restored on drop.
///
/// Restoring matters more than it looks: `run` is a library function, and an
/// integration test that called it would otherwise leave its own process unable
/// to be interrupted.
#[derive(Debug)]
struct SignalGate {
    previous_mask: SigSet,
    previous_winch: SigAction,
}

impl SignalGate {
    /// Block the watched signals, and give `SIGWINCH` a disposition that stops
    /// the kernel throwing it away.
    ///
    /// # Why `SIGWINCH` needs a handler that never runs
    ///
    /// POSIX leaves one case unspecified: *"If the action associated with a
    /// blocked signal is to ignore the signal ... it is unspecified whether the
    /// signal is discarded immediately upon generation or remains pending."*
    ///
    /// `SIGWINCH` is precisely that case. Its default action is to ignore, and
    /// this relay blocks it. **macOS resolves the unspecified case by
    /// discarding**, measured with a C probe:
    ///
    /// | disposition while blocked | `sigwait` |
    /// |---|---|
    /// | default (`SIG_DFL`, action = ignore) | never returns — the signal is gone |
    /// | a no-op handler installed | returns with `SIGWINCH` |
    ///
    /// Nothing reports an error on that path. A resize would simply never reach
    /// the child, and the relay's own shutdown wake would never arrive, so a
    /// `keyless run` would hang forever after its child had already exited.
    ///
    /// Installing any handler moves the action from "ignore" to "catch", which
    /// POSIX requires to stay pending. The handler is still never *executed* —
    /// the signal is blocked for the whole life of the relay and `sigwait`
    /// consumes it — so its emptiness is the point, not an oversight.
    ///
    /// The four other watched signals default to terminating rather than being
    /// ignored, so they are never discarded and their dispositions are left
    /// exactly as the caller had them. Giving them a no-op handler too would be
    /// worse than useless: if this relay ever failed to consume one, the no-op
    /// would swallow a `SIGTERM` that should have killed the process.
    fn install() -> Result<Self, TtyError> {
        let catch = SigAction::new(
            SigHandler::Handler(catch_and_do_nothing),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        // SAFETY: the handler is empty, so it is async-signal-safe by
        // construction and has nothing to be re-entrant about.
        let previous_winch = unsafe { sigaction(Signal::SIGWINCH, &catch) }
            .map_err(TtyError::from("sigaction(SIGWINCH)"))?;

        let mut watched = SigSet::empty();
        for signal in WATCHED {
            watched.add(signal);
        }
        let mut previous_mask = SigSet::empty();
        pthread_sigmask(
            SigmaskHow::SIG_BLOCK,
            Some(&watched),
            Some(&mut previous_mask),
        )
        .map_err(TtyError::from("pthread_sigmask"))?;

        Ok(SignalGate {
            previous_mask,
            previous_winch,
        })
    }
}

impl Drop for SignalGate {
    fn drop(&mut self) {
        // Disposition first, then the mask. Restoring in this order means a
        // SIGWINCH still pending when the block lifts is handled the way the
        // caller originally asked for, not by a handler that is on its way out.
        //
        // SAFETY: restoring a disposition this process itself replaced.
        let _ = unsafe { sigaction(Signal::SIGWINCH, &self.previous_winch) };
        let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&self.previous_mask), None);
    }
}

/// Everything a relay needs, acquired **before** the child is spawned.
///
/// The split exists to protect the never-block invariant. Every fallible step —
/// duplicating descriptors, opening the wake pipe, blocking signals, entering
/// raw mode — happens here, while there is still no child. If any of it fails,
/// the caller falls back to pipes and the child runs normally. Once the child
/// exists, the remaining work cannot fail in a way that would leave its output
/// undrained.
#[derive(Debug)]
pub struct Prepared {
    pty: Pty,
    slave: Option<OwnedFd>,
    output_master: OwnedFd,
    input_master: OwnedFd,
    user_input: OwnedFd,
    wake_read: OwnedFd,
    wake_write: OwnedFd,
    gate: SignalGate,
    raw: RawMode,
}

impl Prepared {
    /// Acquire every resource the relay will need.
    ///
    /// Ordered so the visible change — raw mode — comes last. Everything that
    /// can fail has already failed by then, so a failure never leaves the user
    /// looking at a terminal whose settings were changed and changed back.
    pub fn new(mut pty: Pty) -> Result<Self, TtyError> {
        let slave = pty.take_slave();
        let output_master = pty.dup_master()?;
        let input_master = pty.dup_master()?;
        let user_input = io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(TtyError::from_io("dup(stdin)"))?;
        let (wake_read, wake_write) = nix::unistd::pipe().map_err(TtyError::from("pipe"))?;
        let gate = SignalGate::install()?;
        let raw = enter_raw_mode()?;
        Ok(Prepared {
            pty,
            slave,
            output_master,
            input_master,
            user_input,
            wake_read,
            wake_write,
            gate,
            raw,
        })
    }

    /// Take the slave side, to be wired into the child's stdio.
    pub fn take_slave(&mut self) -> Option<OwnedFd> {
        self.slave.take()
    }

    /// Start relaying for `child`.
    ///
    /// The initial window size is pushed here rather than at `openpty` time as
    /// well, because a terminal can be resized between the two.
    #[must_use]
    pub fn start(self, child: Pid, masker: Arc<Masker>) -> Relay {
        let pty = Arc::new(self.pty);
        let done = Arc::new(AtomicBool::new(false));
        let _ = pty.propagate_size();

        // A channel rather than the join handle, because `JoinHandle` has no
        // timed join and [`Relay::drain`] has to be bounded — the same reason,
        // and the same shape, as the pipe path's own drain.
        let (finished, output_done) = mpsc::channel::<()>();
        let output = thread::spawn(move || {
            // `io::stdout()` and NOT `io::stdout().lock()`. A held lock is
            // released when its guard drops, and a filter abandoned at the
            // deadline never drops anything — it is still blocked reading a
            // master that a grandchild holds open. Holding the process-wide
            // stdout lock for this thread's whole life would therefore MOVE the
            // hang rather than remove it: `run` would return on time and
            // `main`'s closing flush would block forever on a guard nobody will
            // ever drop. Locking per write costs one uncontended acquisition
            // per read and keeps each `write_all` atomic, which is the only
            // atomicity a stream filter needs.
            let result = pump(File::from(self.output_master), io::stdout(), masker);
            let _ = finished.send(());
            result
        });

        let input_master = self.input_master;
        let user_input = self.user_input;
        let wake_read = self.wake_read;
        let input = thread::spawn(move || {
            relay_input(&user_input, File::from(input_master), &wake_read);
        });

        let signals = {
            let pty = Arc::clone(&pty);
            let done = Arc::clone(&done);
            thread::spawn(move || watch_signals(&pty, child, &done))
        };
        // Captured now because `Drop` needs it after the handle has been taken.
        let signals_thread = signals.as_pthread_t();

        Relay {
            output: Some(output),
            output_done,
            input: Some(input),
            signals: Some(signals),
            signals_thread,
            wake_write: self.wake_write,
            done,
            _pty: pty,
            _gate: self.gate,
            _raw: self.raw,
        }
    }
}

/// A running relay. Dropping it stops the relay and restores the terminal.
///
/// Field order is load-bearing: `Drop::drop` runs first and joins the threads,
/// then the fields drop in declaration order, so the terminal leaves raw mode
/// and the signal mask is restored only once nothing is still writing to them.
#[derive(Debug)]
pub struct Relay {
    output: Option<JoinHandle<io::Result<()>>>,
    /// One message when the output filter returns. See [`Relay::drain`].
    output_done: mpsc::Receiver<()>,
    input: Option<JoinHandle<()>>,
    signals: Option<JoinHandle<()>>,
    signals_thread: RawPthread,
    wake_write: OwnedFd,
    done: Arc<AtomicBool>,
    _pty: Arc<Pty>,
    _gate: SignalGate,
    _raw: RawMode,
}

impl Relay {
    /// Wait for the child's output to finish arriving — but not forever.
    ///
    /// Returns whether the filter finished. `false` means it was abandoned at
    /// the deadline and some of the child's output will not be shown; the
    /// caller owns saying so, because only the caller has somewhere to say it.
    ///
    /// Call after the child is reaped: the master reports end-of-stream only
    /// once every copy of the slave is closed, which happens when the child
    /// exits. Draining before restoring the terminal is what stops the last few
    /// lines of a run being written into a terminal that is already back in
    /// cooked mode and rendering them with the wrong line endings.
    ///
    /// # Why "when the child exits" is not the whole story
    ///
    /// The child's own children inherit the terminal, and a backgrounded one
    /// outlives its parent:
    ///
    /// ```console
    /// $ keyless run -s DECOY -- sh -c "echo ran; (trap '' HUP; sleep 300) &"
    /// ```
    ///
    /// reaps `sh` at once and then reads a master a grandchild is holding open.
    /// An unbounded join there waits five minutes with the terminal still raw.
    /// Measured 2026-08-09 on Linux: the run never returned.
    ///
    /// The `trap` is not decoration. Without it the grandchild takes the
    /// `SIGHUP` the kernel sends when the child's session ends, dies, and the
    /// case proves nothing — which is why the test that covers this uses
    /// exactly that command.
    // `must_use` because the whole value of the bound is that somebody SAYS the
    // output was cut short. A caller that drops the answer has re-created the
    // silent failure this replaced, and that is a compiler warning rather than a
    // comment asking nicely.
    #[must_use]
    pub fn drain(&mut self) -> bool {
        let Some(output) = self.output.take() else {
            // Already drained. Saying "finished" is right: a second call must
            // not spend the grace again, and `Drop` always makes one.
            return true;
        };
        if self.output_done.recv_timeout(PUMP_DRAIN_GRACE).is_ok() {
            // A panicked pump must not become a panic here, and a downstream
            // broken pipe is not this tool's problem to report.
            let _ = output.join();
            return true;
        }
        // Deliberately detached rather than joined: the thread is blocked in a
        // `read` that nothing in this process can interrupt, and it dies with
        // the process. Dropping the handle is what says so.
        drop(output);
        false
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // Ordinarily a no-op: the caller drains first, so it can report an
        // abandoned filter. This is the backstop, and it cannot report anything.
        let _ = self.drain();
        self.done.store(true, Ordering::Release);
        // One byte wakes the input relay out of `poll`. Interrupting a blocking
        // read on a terminal is not portable; giving it a second thing to wait
        // on is, and it means the thread is joined rather than leaked.
        let _ = write(&self.wake_write, b"\0");
        // Thread-directed, not process-directed. `run` is a library function,
        // so the process may hold threads this relay knows nothing about; a
        // process-directed signal could be delivered to one of those and
        // silently ignored, leaving the join below waiting forever.
        let _ = pthread_kill(self.signals_thread, Signal::SIGWINCH);
        if let Some(input) = self.input.take() {
            let _ = input.join();
        }
        if let Some(signals) = self.signals.take() {
            let _ = signals.join();
        }
    }
}

/// Copy the user's keystrokes into the pty until told to stop.
fn relay_input(user_input: &OwnedFd, mut master: File, wake: &OwnedFd) {
    let mut buf = [0u8; 4096];
    loop {
        let mut watched = [
            PollFd::new(user_input.as_fd(), PollFlags::POLLIN),
            PollFd::new(wake.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut watched, PollTimeout::NONE) {
            Ok(_) => {}
            Err(Errno::EINTR) => continue,
            Err(_) => break,
        }
        let woken = watched[1].revents().unwrap_or_else(PollFlags::empty);
        if !woken.is_empty() {
            break;
        }
        let ready = watched[0].revents().unwrap_or_else(PollFlags::empty);
        if ready.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL | PollFlags::POLLHUP) {
            break;
        }
        if !ready.contains(PollFlags::POLLIN) {
            continue;
        }
        match read(user_input, &mut buf) {
            Ok(0) => break,
            Ok(count) => {
                if master.write_all(&buf[..count]).is_err() {
                    break;
                }
            }
            Err(Errno::EINTR) => continue,
            Err(_) => break,
        }
    }
    // Keystrokes are not this tool's secrets, but they are the user's, and a
    // password typed at a child's prompt passes through this buffer.
    buf.zeroize();
}

/// Consume the watched signals until the relay shuts down.
fn watch_signals(pty: &Pty, child: Pid, done: &AtomicBool) {
    let mut watched = SigSet::empty();
    for signal in WATCHED {
        watched.add(signal);
    }
    loop {
        match watched.wait() {
            Ok(Signal::SIGWINCH) => {
                if done.load(Ordering::Acquire) {
                    break;
                }
                // Setting the pty's size makes the kernel send the child its
                // own SIGWINCH, which is how a resize actually reaches it.
                let _ = pty.propagate_size();
            }
            // Forward, never act. Acting would kill this process with the
            // terminal still raw; forwarding kills the child, which returns the
            // main thread from `wait` and leaves through the normal path.
            Ok(other) => {
                let _ = killpg(child, other);
            }
            Err(Errno::EINTR) => continue,
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SignalGate, WATCHED};
    use nix::sys::pthread::pthread_kill;
    use nix::sys::signal::{SigSet, Signal};
    use std::os::unix::thread::JoinHandleExt;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn a_blocked_sigwinch_still_reaches_sigwait() {
        // The whole reason `SignalGate` installs a handler it never runs. On
        // macOS a blocked SIGWINCH left at its default disposition is DISCARDED
        // at generation — `sigwait` then waits forever, the resize feature is
        // silently dead, and `keyless run` hangs after its child has already
        // exited. Nothing errors; it simply never arrives.
        //
        // Written to FAIL rather than to hang, because a regression here is a
        // hang and a suite that hangs reports nothing at all.
        let gate = SignalGate::install().expect("block the watched signals");

        let (sender, receiver) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let mut watched = SigSet::empty();
            watched.add(Signal::SIGWINCH);
            let _ = sender.send(watched.wait().is_ok());
        });

        // Give the waiter time to enter sigwait, then wake exactly it — a
        // process-directed signal could be taken by a sibling test's thread.
        thread::sleep(Duration::from_millis(100));
        pthread_kill(waiter.as_pthread_t(), Signal::SIGWINCH).expect("signal the waiter");

        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(10)),
            Ok(true),
            "a blocked SIGWINCH was discarded instead of delivered; \
             SignalGate must give it a disposition other than the default"
        );
        let _ = waiter.join();
        drop(gate);
    }

    #[test]
    fn only_sigwinch_has_its_disposition_replaced() {
        // The other four default to TERMINATING, so they are never discarded
        // and need no handler. Giving them one would be actively harmful: if
        // this relay ever failed to consume a SIGTERM, a no-op handler would
        // swallow it and make the process unkillable by ordinary means.
        let mut ignored_by_default = WATCHED.iter().filter(|signal| **signal == Signal::SIGWINCH);
        assert_eq!(ignored_by_default.next(), Some(&Signal::SIGWINCH));
        assert_eq!(
            ignored_by_default.next(),
            None,
            "a signal whose default action is `ignore` was added to the watched \
             set; it needs the same handler treatment as SIGWINCH or it will be \
             discarded while blocked"
        );
    }
}
