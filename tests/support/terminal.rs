//! A real pseudo-terminal, for a test that types an answer at a prompt.
//!
//! `tests/pty.rs` owns the general case — resizing, terminal ownership,
//! signals — because its own cases need all of that. Confirming a prompt
//! needs none of it: start the binary attached to one real terminal, wait for
//! a marker in its output, type a line, and collect the exit code plus
//! everything the terminal received. That is the whole shape of [`Terminal`].
//!
//! [`private_pty`] is the one construction of a pty pair in the suite, and
//! `tests/pty.rs` sizes the same pair for its own cases.
//!
//! Waiting for a marker rather than sleeping follows `tests/pty.rs`'s rule:
//! raw mode discards unread input on enable, so typing a moment too early
//! throws the keystrokes away and the child waits forever for a line that
//! already came and went. A fixed sleep does not fail there — it hangs.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Bound on waiting for one marker in the terminal's output.
const MARKER_PATIENCE: Duration = Duration::from_secs(30);

/// Guards `ptsname`, which answers out of a static buffer libc reuses. It is
/// held across the one call that reads that buffer and released the moment
/// the name has been copied — not a general "one pty at a time" lock.
static NAMING: Mutex<()> = Mutex::new(());

/// A pty pair whose two descriptors are close-on-exec from the instant they
/// exist, so no other test's child can inherit them.
///
/// # The defect, which is that these tests share one process
///
/// Case A's terminal is open while case B forks, so B's `keyless` — and the
/// shell and the backgrounded grandchild it starts — inherit it. A's master
/// then never reports end-of-file, because a process A has never heard of is
/// holding A's slave, and A blocks reading it until that stranger exits. This
/// file starts grandchildren that deliberately outlive their session by two
/// minutes, so "until that stranger exits" is longer than any deadline here.
///
/// # Why the descriptors are born with the flag rather than given it after
///
/// **`openpty` sets `FD_CLOEXEC` on neither descriptor, and a `fcntl` on the
/// far side of it is far too late.** `openpty` obtains the master first and
/// then spends the rest of its work — unlocking the pair, opening the slave,
/// configuring the line discipline — with an inheritable descriptor already
/// live. The window is not the nanosecond between two calls; it is the whole
/// body of `openpty`.
///
/// That is measured rather than argued: one thread allocating terminals this
/// way beside several threads spawning children, and **a large fraction of
/// those children come out holding a terminal they were never given** — at a
/// rate statistically indistinguishable from a control that never sets the
/// flag at all. Setting it afterwards buys nothing. Born with `O_CLOEXEC`, not
/// one child in any arm holds a stray terminal.
///
/// So the flag is part of each descriptor's creation. There is no ordering for
/// a future reader to preserve and no lock for one to forget, which is the
/// whole reason to spend five calls here — `posix_openpt`, `grantpt`,
/// `unlockpt`, `ptsname`, `open` — rather than one call to `openpty`. They are
/// named rather than counted so the next reader checks the list against the
/// body instead of trusting a number that drifts the moment a call moves.
///
/// The three descriptors `keyless` is *meant* to get are unaffected: they are
/// separate `try_clone`s handed to `Stdio`, and `dup2` onto 0, 1 and 2 clears
/// the flag on the descriptors it creates.
pub fn private_pty() -> (OwnedFd, OwnedFd) {
    // SAFETY: no arguments to get wrong, and the descriptor is owned the
    // instant it exists.
    let master = unsafe {
        nix::libc::posix_openpt(nix::libc::O_RDWR | nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC)
    };
    assert_ne!(
        master,
        -1,
        "this platform must provide a pty: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: a fresh descriptor from `posix_openpt` that nothing else owns.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    // SAFETY (both): a live master this function owns.
    let granted = unsafe { nix::libc::grantpt(master.as_raw_fd()) };
    assert_ne!(granted, -1, "grantpt: {}", std::io::Error::last_os_error());
    let unlocked = unsafe { nix::libc::unlockpt(master.as_raw_fd()) };
    assert_ne!(
        unlocked,
        -1,
        "unlockpt: {}",
        std::io::Error::last_os_error()
    );

    let opened = {
        let _naming = NAMING.lock().unwrap_or_else(|error| error.into_inner());
        // SAFETY: a live master, and `_naming` excludes the concurrent call
        // that would overwrite the buffer before it is copied below.
        let name = unsafe { nix::libc::ptsname(master.as_raw_fd()) };
        assert!(
            !name.is_null(),
            "ptsname: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: libc returned a NUL-terminated string valid until the next
        // call, which the guard still held here excludes.
        let path = unsafe { std::ffi::CStr::from_ptr(name) }.to_owned();
        // SAFETY: a NUL-terminated path, and the flags are a valid mode.
        unsafe {
            nix::libc::open(
                path.as_ptr(),
                nix::libc::O_RDWR | nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC,
            )
        }
    };
    assert_ne!(
        opened,
        -1,
        "open the pty slave: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: a fresh descriptor from `open` that nothing else owns.
    let slave = unsafe { OwnedFd::from_raw_fd(opened) };
    (master, slave)
}

/// One command, attached to a real terminal on all three of its streams.
pub struct Terminal {
    child: Child,
    slave: OwnedFd,
    master: OwnedFd,
    seen: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

/// Start `command` with stdin, stdout and stderr all attached to one fresh
/// pty, exactly as a shell would attach a foreground program to the terminal
/// it was typed into.
///
/// `command`'s own stdio settings are overwritten — nothing about how the
/// caller built it survives past this call except its program, arguments and
/// environment.
pub fn start(mut command: Command) -> Terminal {
    let (master, slave) = private_pty();

    let for_stdin = slave.try_clone().expect("dup slave for stdin");
    let for_stdout = slave.try_clone().expect("dup slave for stdout");
    let for_stderr = slave.try_clone().expect("dup slave for stderr");
    command
        .stdin(Stdio::from(for_stdin))
        .stdout(Stdio::from(for_stdout))
        .stderr(Stdio::from(for_stderr));

    let child = command.spawn().expect("the binary must run");

    // Read the master on a thread into a buffer the test can inspect as it
    // fills, the same way `tests/pty.rs`'s `UnderTerminal` does and for the
    // same reason: this test keeps its own copy of the slave open, so reading
    // to completion here would deadlock every case that wants to look before
    // the run ends.
    let reading = master.try_clone().expect("dup master for reading");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let filling = Arc::clone(&seen);
    let reader = thread::spawn(move || {
        let mut file = std::fs::File::from(reading);
        let mut buf = [0u8; 4096];
        while let Ok(count) = file.read(&mut buf) {
            if count == 0 {
                break;
            }
            filling
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .extend_from_slice(&buf[..count]);
        }
    });

    Terminal {
        child,
        slave,
        master,
        seen,
        reader: Some(reader),
    }
}

impl Terminal {
    fn text(&self) -> String {
        let seen = self.seen.lock().unwrap_or_else(|error| error.into_inner());
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// Block until `needle` appears in the terminal's output, or fail.
    pub fn await_output(&self, needle: &str) {
        let deadline = Instant::now() + MARKER_PATIENCE;
        while Instant::now() < deadline {
            if self.text().contains(needle) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "`{needle}` never reached the terminal; it received: {:?}",
            self.text()
        );
    }

    /// Type a line at the terminal, as if a person had, followed by Enter.
    pub fn type_line(&self, text: &str) {
        let mut keyboard =
            std::fs::File::from(self.master.try_clone().expect("dup master for writing"));
        keyboard.write_all(text.as_bytes()).expect("type");
        keyboard.write_all(b"\n").expect("type the newline");
    }

    /// Send the terminal's own end-of-file character (Ctrl-D), the way a
    /// person closing stdin at a prompt does — nothing is typed and nothing
    /// is closed, the same real signal a real terminal produces.
    pub fn type_eof(&self) {
        let mut keyboard =
            std::fs::File::from(self.master.try_clone().expect("dup master for writing"));
        keyboard.write_all(&[0x04]).expect("type EOF");
    }

    /// Wait for the run to end and return its exit code plus everything the
    /// terminal received.
    pub fn finish(self) -> (i32, String) {
        let Terminal {
            mut child,
            slave,
            master,
            seen,
            reader,
        } = self;
        let code = child.wait().expect("reap the child").code().unwrap_or(-1);
        // Closing this test's own copies of the slave and the master is what
        // lets the reader thread see end-of-file — it happens only after the
        // child has exited and holds no descriptors of its own any more.
        drop(slave);
        drop(master);
        if let Some(reader) = reader {
            let _ = reader.join();
        }
        let seen = seen.lock().unwrap_or_else(|error| error.into_inner());
        (code, String::from_utf8_lossy(&seen).into_owned())
    }
}
