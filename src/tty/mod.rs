//! Giving the child a real terminal, without giving up masking.
//!
//! # Why this module exists
//!
//! Masking needs the child's output to pass through this process, and the only
//! way to get it is to hand the child something other than the user's terminal.
//! With a pipe, every program that asks "am I on a terminal?" answers *no*:
//! `npm install` loses its progress bar, `git log` loses its pager and its
//! colour, and anything that prompts changes shape. That is a tax on every
//! single invocation, and a tool with a tax on every invocation gets
//! uninstalled — which brings the plaintext literal back, exactly as the
//! never-block rule says.
//!
//! So when the user really is at a terminal, `keyless` allocates a
//! pseudo-terminal, gives the slave side to the child, and relays bytes between
//! the master side and the user's terminal. The child sees a terminal because it
//! *has* one. The bytes still pass through the masker on the way out.
//!
//! # What this module deliberately does not do
//!
//! It never decides on its own that a terminal exists. [`is_interactive`] asks
//! about all three of stdin, stdout and stderr, and every one of them must be a
//! terminal before a pty is allocated:
//!
//! - **stdout not a terminal** — there is nothing to preserve, and writing
//!   terminal escape sequences into a pipe or a file actively corrupts it.
//! - **stderr not a terminal** — a pty carries ONE stream. Merging the child's
//!   stderr into it would silently defeat a deliberate `2>errors.log`, which is
//!   data loss, not a cosmetic difference.
//! - **stdin not a terminal** — a pty has no end-of-file to deliver. Relaying a
//!   pipe that ends into a pty means synthesising an EOT, whose meaning depends
//!   on the child's line discipline. Getting that subtly wrong truncates input.
//!
//! Any of those three and the existing pipe path runs unchanged. Both paths
//! mask.
//!
//! # Failure is not refusal
//!
//! Nothing in here is allowed to stop a command. Every entry point returns a
//! [`TtyError`] that the caller turns into one line on stderr and a fall back to
//! pipes. `/dev/ptmx` missing, the fd table full, a platform that will not open
//! a pseudo-terminal at all — the child still runs.

pub mod relay;

use std::io::{self, IsTerminal};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Mutex, Once, OnceLock};

use nix::errno::Errno;
use nix::libc;
use nix::pty::Winsize;
use nix::sys::termios::{self, SetArg, Termios};

// The three terminal ioctls. `_bad` in the macro name refers to the request
// constants: on the BSDs (macOS included) they already encode direction and
// size, so nix must not recompute them. Generating these is what the `nix`
// dependency buys — a hand-written request constant compiles, links, and then
// writes the wrong number of bytes through a pointer at runtime.
nix::ioctl_read_bad!(ioctl_get_winsize, libc::TIOCGWINSZ, Winsize);
nix::ioctl_write_ptr_bad!(ioctl_set_winsize, libc::TIOCSWINSZ, Winsize);
nix::ioctl_write_int_bad!(ioctl_set_controlling_tty, libc::TIOCSCTTY);

/// A pseudo-terminal could not be set up.
///
/// Hand-written like every other error in this crate, and for the same reason:
/// a derived `Display` hides what goes into a message. None of these carry
/// anything but a syscall name and an errno.
#[derive(Debug)]
pub enum TtyError {
    /// stdin, stdout and stderr are not all terminals, so there is no terminal
    /// behaviour to preserve.
    NotATerminal,
    /// A syscall failed. `call` names it, so the one stderr line a user sees is
    /// diagnosable rather than decorative.
    Syscall {
        /// The syscall that failed, e.g. `posix_openpt`.
        call: &'static str,
        /// The raw errno it failed with.
        source: Errno,
    },
    /// A caller asked for the allocation failure path on purpose.
    ///
    /// The fallback in the never-block invariant cannot be reached on demand on
    /// a machine where `/dev/ptmx` works, so it is reachable through
    /// [`crate::cmd::run::TtyPolicy::SimulateAllocationFailure`] instead.
    Simulated,
}

impl TtyError {
    /// Tag an `errno` with the syscall that produced it.
    pub(crate) fn from(call: &'static str) -> impl FnOnce(Errno) -> TtyError {
        move |source| TtyError::Syscall { call, source }
    }

    /// The same, for the std wrappers that report `io::Error` instead.
    ///
    /// `EIO` stands in when the error carries no errno at all, which std allows
    /// but no syscall on this path produces.
    pub(crate) fn from_io(call: &'static str) -> impl FnOnce(io::Error) -> TtyError {
        move |error| TtyError::Syscall {
            call,
            source: Errno::from_raw(error.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
}

impl std::fmt::Display for TtyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TtyError::NotATerminal => f.write_str("stdio is not a terminal"),
            TtyError::Syscall { call, source } => write!(f, "{call} failed: {source}"),
            TtyError::Simulated => f.write_str("allocation failure requested by the caller"),
        }
    }
}

impl std::error::Error for TtyError {}

/// Whether this process is attached to a terminal on all three standard streams.
///
/// All three, for the reasons in the module documentation. A single stream
/// being a terminal is not enough to make a pty safe.
#[must_use]
pub fn is_interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal()
}

/// The user's terminal size, read from stdout.
fn parent_size() -> Result<Winsize, TtyError> {
    let mut size = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `size` is a live, correctly typed `winsize`, and the fd is this
    // process's stdout, which `is_interactive` has established is a terminal.
    unsafe { ioctl_get_winsize(io::stdout().as_raw_fd(), &raw mut size) }
        .map_err(TtyError::from("ioctl(TIOCGWINSZ)"))?;
    Ok(size)
}

/// A master/slave pty pair.
///
/// The slave is handed to the child and then dropped by the parent — the master
/// only reports end-of-stream once *every* copy of the slave is closed, so a
/// forgotten copy here would hang the run forever.
#[derive(Debug)]
pub struct Pty {
    master: OwnedFd,
    slave: Option<OwnedFd>,
}

/// Allocate a pty sized and configured like the user's own terminal.
///
/// The parent's `termios` is copied onto the slave so the child starts with the
/// line discipline the user actually has — echo, ONLCR, the erase character —
/// rather than the system default, which is what makes an interactive prompt
/// under `keyless` behave the same as one without it.
pub fn allocate() -> Result<Pty, TtyError> {
    let size = parent_size()?;
    let attrs = termios::tcgetattr(io::stdin()).map_err(TtyError::from("tcgetattr"))?;
    let (master, slave) = open_pty(Some(&size), Some(&attrs))?;
    Ok(Pty {
        master,
        slave: Some(slave),
    })
}

/// Guards `ptsname`, which answers out of a static buffer libc reuses.
///
/// Held across one call and released the moment the name has been copied. It
/// protects that buffer and nothing else — it is deliberately not a "one pty at
/// a time" lock, and taking it says nothing about how many terminals this
/// process may open at once.
static NAMING: Mutex<()> = Mutex::new(());

/// Open a pty pair whose two descriptors are close-on-exec from the instant
/// they exist.
///
/// # Why not `openpty`
///
/// **`openpty` sets `FD_CLOEXEC` on neither descriptor, and an `fcntl` on the
/// far side of it is far too late.** `openpty` takes the master first and then
/// spends the rest of its work — unlocking the pair, opening the slave,
/// configuring the line discipline — with an inheritable descriptor already
/// live. The window is not the gap between two calls; it is the whole body of
/// `openpty`, and any other thread that creates a process during it hands a
/// child a terminal it was never given.
///
/// Setting the flag afterwards is worth nothing, and that is measured rather
/// than argued. One thread opening terminals beside several threads spawning
/// children, each child reporting any descriptor above stderr the kernel calls
/// a terminal:
///
/// | how the pair was opened | children holding a stray terminal |
/// |---|---|
/// | no pty opened at all | none |
/// | `openpty`, then `fcntl(FD_CLOEXEC)` | a large fraction of them |
/// | born with `O_CLOEXEC` | none |
///
/// The first row is what says the detector is not simply always answering; the
/// second is what the `fcntl` bought, and it is indistinguishable from never
/// setting the flag at all. `tests/pty.rs` holds the arrangement.
///
/// So the flag is part of each descriptor's creation. There is no ordering left
/// for a future reader to preserve, which is the whole reason to spend five
/// syscalls here rather than one.
///
/// # What a stray descriptor costs
///
/// Nothing in `keyless run` forks while this function is running — the store
/// lookups are joined before a terminal is asked for — so today this is a
/// window nothing walks through. It is not left to that: the ordering that
/// keeps it shut is in a different module, is not stated anywhere as a
/// requirement, and would be undone by any background thread that ever creates
/// a process. What walks through it, when something does, is two things, and
/// the second is the serious one:
///
/// - A stray *slave* copy is one more holder keeping the pty from ever
///   reporting end-of-stream. This process closes its own after the spawn; a
///   copy that walked into a grandchild cannot be closed by anybody.
/// - A stray *master* copy is a hole in the masking. Everything the filter is
///   about to redact is readable on it, and anything written to it is injected
///   into the user's terminal as though the user had typed it. A child gets a
///   terminal on purpose; it never gets the other end of one.
///
/// The three descriptors the child is *meant* to have are unaffected: they are
/// `try_clone`s handed to `Stdio`, and `dup2` onto 0, 1 and 2 clears the flag
/// on the descriptors it creates.
///
/// # The size and the attributes
///
/// `openpty` takes both as arguments and applies them to the slave, the
/// `termios` first; this does the same to the same descriptor, so the terminal
/// that comes out is the one `openpty` would have produced.
///
/// It differs from `openpty` in one way, on purpose: `openpty` discards a
/// failure from either, and this reports it. [`allocate`] documents that the
/// user's own line discipline reaches the child, and a terminal that silently
/// arrived with the system default instead would break that promise with
/// nothing on screen. Reporting it costs nothing the never-block rule minds —
/// the caller falls back to pipes and the command still runs.
pub(crate) fn open_pty(
    size: Option<&Winsize>,
    attrs: Option<&Termios>,
) -> Result<(OwnedFd, OwnedFd), TtyError> {
    // SAFETY: no pointer arguments to get wrong, and the descriptor is taken
    // into an `OwnedFd` below, which is what closes it on every path from here.
    let raw = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if raw == -1 {
        return Err(TtyError::Syscall {
            call: "posix_openpt",
            source: Errno::last(),
        });
    }
    // SAFETY: a fresh descriptor from `posix_openpt` that nothing else owns.
    let master = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: a live master this function owns.
    if unsafe { libc::grantpt(master.as_raw_fd()) } == -1 {
        return Err(TtyError::Syscall {
            call: "grantpt",
            source: Errno::last(),
        });
    }
    // SAFETY: a live master this function owns.
    if unsafe { libc::unlockpt(master.as_raw_fd()) } == -1 {
        return Err(TtyError::Syscall {
            call: "unlockpt",
            source: Errno::last(),
        });
    }

    let opened = {
        let _naming = NAMING.lock().unwrap_or_else(|error| error.into_inner());
        // SAFETY: a live master, and `_naming` excludes the concurrent call
        // that would overwrite the static buffer before it is copied below.
        let name = unsafe { libc::ptsname(master.as_raw_fd()) };
        if name.is_null() {
            return Err(TtyError::Syscall {
                call: "ptsname",
                source: Errno::last(),
            });
        }
        // SAFETY: libc returned a NUL-terminated string valid until the next
        // call, which the guard still held here excludes.
        let path = unsafe { std::ffi::CStr::from_ptr(name) }.to_owned();
        // SAFETY: a NUL-terminated path, and the flags are a valid mode.
        unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        }
    };
    if opened == -1 {
        return Err(TtyError::Syscall {
            call: "open(the pty slave)",
            source: Errno::last(),
        });
    }
    // SAFETY: a fresh descriptor from `open` that nothing else owns.
    let slave = unsafe { OwnedFd::from_raw_fd(opened) };

    if let Some(attrs) = attrs {
        termios::tcsetattr(&slave, SetArg::TCSAFLUSH, attrs)
            .map_err(TtyError::from("tcsetattr"))?;
    }
    if let Some(size) = size {
        // SAFETY: `size` is a live, correctly typed `winsize`, and the fd is a
        // pty slave this function owns.
        unsafe { ioctl_set_winsize(slave.as_raw_fd(), size as *const Winsize) }
            .map_err(TtyError::from("ioctl(TIOCSWINSZ)"))?;
    }

    Ok((master, slave))
}

impl Pty {
    /// Take the slave side, to be wired into the child's stdio.
    ///
    /// Returns `None` on a second call. The parent must not keep a copy: see
    /// the struct documentation.
    pub fn take_slave(&mut self) -> Option<OwnedFd> {
        self.slave.take()
    }

    /// Duplicate the master side.
    ///
    /// Each relay thread gets its own duplicate rather than sharing one, so a
    /// reader and a writer never contend on a single file description's flags.
    pub fn dup_master(&self) -> Result<OwnedFd, TtyError> {
        self.master.try_clone().map_err(TtyError::from_io("dup"))
    }

    /// Copy the user's current terminal size onto the pty.
    ///
    /// Called once at start-up and again on every `SIGWINCH`, which is what
    /// makes a window resize mid-run reach the child: the kernel sends the
    /// child its own `SIGWINCH` as a result of this call.
    pub fn propagate_size(&self) -> Result<(), TtyError> {
        let size = parent_size()?;
        // SAFETY: `size` is a live, correctly typed `winsize`, and the fd is a
        // pty master this struct owns.
        unsafe { ioctl_set_winsize(self.master.as_raw_fd(), &raw const size) }
            .map_err(TtyError::from("ioctl(TIOCSWINSZ)"))?;
        Ok(())
    }
}

/// Make the slave side of a pty this process's controlling terminal.
///
/// # Safety
///
/// Only callable between `fork` and `exec`, where the only functions that may
/// be used are async-signal-safe ones. `setsid` and `ioctl` both are, and
/// neither allocates.
///
/// Expects the slave to already be on fd 0, which is true by the time
/// `Command`'s `pre_exec` hooks run: the standard library dups the configured
/// stdio into place first.
pub unsafe fn adopt_controlling_terminal() -> io::Result<()> {
    // A controlling terminal belongs to a session, so the child needs a session
    // of its own. This is also what makes the child's process group the pty's
    // foreground group, which is how a relayed Ctrl-C byte turns into a SIGINT
    // for the child rather than for keyless.
    nix::unistd::setsid().map_err(io::Error::from)?;
    // SAFETY: fd 0 is the pty slave, per the contract above.
    unsafe { ioctl_set_controlling_tty(0, 0) }.map_err(io::Error::from)?;
    Ok(())
}

/// The user's terminal, put in raw mode, and restored when this is dropped.
///
/// Raw mode is what lets Ctrl-C, arrow keys and paste reach the child
/// unmolested: the parent's line discipline stops interpreting them, and the
/// pty slave's line discipline — which the child controls — interprets them
/// instead.
///
/// # Restoration
///
/// Three exits are covered, and they need three different mechanisms:
///
/// - **Normal return and unwinding panic** — this type's `Drop`.
/// - **Aborting panic** — a panic hook, installed once. `[profile.release]` sets
///   `panic = "abort"`, so `Drop` does *not* run there; the hook still does,
///   before the abort.
/// - **A signal that would otherwise kill the process** — not handled here at
///   all. [`relay::Relay`] blocks those signals and forwards them to the child,
///   so the process leaves through the normal return path above.
///
/// `SIGKILL` and a hard `abort()` cannot be covered by anything. A terminal left
/// raw by either is repaired with `stty sane` or `reset`.
#[derive(Debug)]
pub struct RawMode {
    saved: Termios,
}

/// Put the user's terminal in raw mode.
pub fn enter_raw_mode() -> Result<RawMode, TtyError> {
    let saved = termios::tcgetattr(io::stdin()).map_err(TtyError::from("tcgetattr"))?;
    let mut raw = saved.clone();
    termios::cfmakeraw(&mut raw);
    // TCSAFLUSH: apply once the pending output has drained, and discard
    // unread input. Discarding is deliberate — keystrokes typed before the
    // child existed were meant for the shell, not for the child.
    termios::tcsetattr(io::stdin(), SetArg::TCSAFLUSH, &raw)
        .map_err(TtyError::from("tcsetattr"))?;
    remember_for_panic(&saved);
    Ok(RawMode { saved })
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // Nothing useful remains to be done if this fails, and a Drop that
        // panics while the terminal is raw would be the worst of both.
        let _ = termios::tcsetattr(io::stdin(), SetArg::TCSAFLUSH, &self.saved);
        forget_for_panic();
    }
}

/// The user's terminal with echo switched off, restored when this is dropped.
///
/// Narrower than [`RawMode`] on purpose. `keyless put` at a terminal needs one
/// thing — the typed value must not appear on screen or in the scrollback — and it
/// still wants the line discipline: backspace, Ctrl-C and Enter must behave the
/// way they do at every other password prompt the user has ever seen. Raw mode
/// would take all three away and make this prompt the odd one out.
///
/// It reuses the same panic-hook restoration as [`RawMode`], because the failure
/// it prevents is the same and worse: a process that dies with echo off leaves a
/// terminal that silently swallows everything typed into it afterwards.
#[derive(Debug)]
pub struct EchoOff {
    saved: Termios,
}

/// Switch terminal echo off.
///
/// # Errors
///
/// [`TtyError`] when stdin is not a terminal, or when the `termios` calls fail.
/// The caller must treat that as "do not prompt", never as "prompt anyway" — a
/// prompt whose echo could not be switched off would print the credential.
pub fn without_echo() -> Result<EchoOff, TtyError> {
    let saved = termios::tcgetattr(io::stdin()).map_err(TtyError::from("tcgetattr"))?;
    let mut quiet = saved.clone();
    quiet
        .local_flags
        .remove(termios::LocalFlags::ECHO | termios::LocalFlags::ECHONL);
    // TCSAFLUSH, as in raw mode: apply once pending output has drained and discard
    // input typed before the prompt existed. Discarding matters more here — those
    // keystrokes were echoed to the screen, so treating them as part of a secret
    // value would store something already visible.
    termios::tcsetattr(io::stdin(), SetArg::TCSAFLUSH, &quiet)
        .map_err(TtyError::from("tcsetattr"))?;
    remember_for_panic(&saved);
    Ok(EchoOff { saved })
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(io::stdin(), SetArg::TCSAFLUSH, &self.saved);
        forget_for_panic();
    }
}

/// The settings the panic hook restores. `None` when no terminal is raw.
fn saved_slot() -> &'static Mutex<Option<Termios>> {
    static SAVED: OnceLock<Mutex<Option<Termios>>> = OnceLock::new();
    SAVED.get_or_init(|| Mutex::new(None))
}

/// Take the lock, ignoring poisoning.
///
/// A poisoned lock means some other thread panicked while holding it. Refusing
/// to restore the terminal because of that would turn one bug into a wedged
/// terminal, which is the outcome this whole mechanism exists to prevent.
fn saved_lock() -> std::sync::MutexGuard<'static, Option<Termios>> {
    saved_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

fn remember_for_panic(saved: &Termios) {
    *saved_lock() = Some(saved.clone());
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_from_panic();
            previous(info);
        }));
    });
}

fn forget_for_panic() {
    *saved_lock() = None;
}

/// Restore the terminal from the panic hook.
///
/// Separate from `RawMode::drop` because the hook has no access to the guard,
/// and because the guard may be exactly what is being torn down.
fn restore_from_panic() {
    if let Some(saved) = saved_lock().take() {
        let _ = termios::tcsetattr(io::stdin(), SetArg::TCSAFLUSH, &saved);
    }
}

#[cfg(test)]
mod tests {
    use super::TtyError;
    use nix::errno::Errno;

    #[test]
    fn a_syscall_error_names_the_syscall() {
        let error = TtyError::Syscall {
            call: "posix_openpt",
            source: Errno::ENOENT,
        };
        let rendered = error.to_string();
        assert!(rendered.contains("posix_openpt"), "{rendered}");
    }

    #[test]
    fn the_error_type_never_carries_anything_but_a_name_and_an_errno() {
        // A pty error is produced on a path where secrets are already resolved.
        // Keeping the variants free of payload is what makes it impossible for
        // one to reach stderr.
        for error in [
            TtyError::NotATerminal,
            TtyError::Simulated,
            TtyError::Syscall {
                call: "ioctl(TIOCSWINSZ)",
                source: Errno::EBADF,
            },
        ] {
            let rendered = error.to_string();
            assert!(!rendered.is_empty());
            assert!(rendered.is_ascii(), "{rendered}");
        }
    }
}
