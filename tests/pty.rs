//! The pty path, exercised through a terminal this test allocates itself.
//!
//! Nothing here stubs a terminal. Each test opens a real pty, gives the slave
//! side to the real `keyless` binary, and reads the master — so `keyless` is
//! genuinely attached to a terminal and takes the same branch a user's shell
//! would put it on. A test that faked the detection would prove only that the
//! fake works.
//!
//! The layout is two nested pseudo-terminals, and it is worth holding in mind
//! while reading:
//!
//! ```text
//!   this test  ──outer master──┐
//!                              │
//!              ┌──outer slave──┴─>  keyless  ──inner master──┐
//!              │                                            │
//!              └────────────────  the child  <──inner slave──┘
//! ```
//!
//! The outer pty is the test standing in for the user's terminal. The inner one
//! is the one `keyless` allocates. Everything the child writes crosses the
//! masker between the two.
//!
//! # Every case here is bounded, because a hang reports NOTHING
//!
//! A hanging test and a passing test are the same empty log, and this file is
//! the worked example: nine of its cases blocked forever on Linux and `cargo
//! test` never returned, so there was no red line for anyone to read. Every case
//! here runs through [`support::within`], which abandons a case that stalls and
//! reports it by name instead of stopping the suite.
//!
//! That bound stays whatever the code does. Everything below drives a real
//! child, a real terminal and descriptors another process can hold open, which
//! is the exact set of ingredients whose failure mode is silence.
//!
//! # No test here sleeps for a fixed period and then asserts
//!
//! Every one waits for a marker to appear in the output instead. That is not
//! tidiness. The first version of this file slept 400ms before typing at the
//! child, and it passed alone and hung under the parallel run: entering raw
//! mode uses `TCSAFLUSH`, which **discards unread input**, so keystrokes typed
//! a moment too early are thrown away and the child waits for a line that will
//! never arrive. A fixed sleep does not fail there — it hangs, which reports
//! nothing at all.

mod support;

use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::pty::Winsize;
use nix::sys::signal::{Signal, kill};
use nix::sys::termios::{self, LocalFlags, Termios};
use nix::unistd::Pid;

use support::{DECOY_VALUE, Stub, scratch, stub_security, within};

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// The bound on a whole case.
///
/// Deliberately larger than [`MARKER_PATIENCE`], which bounds one wait for one
/// marker. A case that stalls waiting for a specific marker should report THAT
/// marker and what the terminal received instead; only a stall with no more
/// specific owner should fall through to this one.
const CASE_PATIENCE: Duration = Duration::from_secs(60);

/// The bound on one wait for one thing the CHILD has to produce.
///
/// A wall clock, and it has to be: there is no watched body here to charge, and
/// the thing being waited for is another process's output rather than any work
/// this thread does. So it is a HANG bound and never a measurement — nothing
/// that uses it asserts anything about how long the marker took, and every case
/// that does assert on elapsed time says so at its own assertion. Its only job
/// is to name the marker that never arrived, which is the one thing
/// [`CASE_PATIENCE`] cannot say.
///
/// It is far above anything a terminal fixture in this file costs, deliberately:
/// these cases spend their time waiting rather than computing, so a machine with
/// no cpu to spare barely moves them.
const MARKER_PATIENCE: Duration = Duration::from_secs(30);

/// A distinctive terminal size, so "the child saw the size we set" cannot be
/// confused with "the child saw a plausible default". 24x80 would prove nothing.
const ROWS: u16 = 37;
const COLS: u16 = 113;

fn winsize(rows: u16, cols: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

nix::ioctl_write_ptr_bad!(set_winsize, nix::libc::TIOCSWINSZ, Winsize);

/// A config wired to a `security` stub, so no real keychain is ever consulted.
fn config_with_stub(dir: &std::path::Path, behaviour: &Stub) -> std::path::PathBuf {
    let stub = stub_security(dir, behaviour);
    let path = dir.join("config.json");
    let body = format!(
        r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{}"}}}},
            "secrets":{{"DECOY":{{}}}}}}"#,
        stub.display()
    );
    std::fs::write(&path, body).expect("write config");
    path
}

/// Who owns the terminal `keyless` is attached to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ownership {
    /// `keyless` inherits this test's session. The terminal outlives it, so its
    /// settings can still be read after it exits — which is the only way to
    /// check that it put them back.
    Inherited,
    /// `keyless` gets its own session and becomes the terminal's foreground
    /// process group, exactly as a shell would arrange it. Required to make the
    /// kernel deliver a real `SIGWINCH` on a resize.
    ///
    /// The cost is that the terminal is **revoked when `keyless` exits**: a
    /// session leader's death takes its controlling terminal with it, and
    /// `tcgetattr` on the slave then fails with `ENOTTY`. So this mode cannot
    /// observe anything after the run, which is why it is not the default.
    Owned,
}

/// `keyless`, running with its stdio attached to a terminal.
struct UnderTerminal {
    child: Child,
    /// The test's own handle on that terminal. Reading its `termios` is how raw
    /// mode and its restoration are observed.
    slave: OwnedFd,
    master: OwnedFd,
    seen: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
    /// The terminal as this test created it, read before anything was spawned.
    ///
    /// # A snapshot taken after the spawn is a race, not a baseline
    ///
    /// `keyless` puts this terminal in raw mode as part of the run, so "what it
    /// looked like beforehand" stops being readable the moment the child is
    /// alive. A case that spawns and *then* calls [`UnderTerminal::settings`]
    /// is racing the process it is testing for the answer, and under a loaded
    /// parallel run the process wins: the case then compares a correctly
    /// restored terminal against a raw one and reports the restore as broken —
    /// the exact inversion of what it is guarding.
    ///
    /// Reading it here removes the race rather than narrowing it. At this point
    /// the pty exists and nothing else does, so there is no ordering for a
    /// future reader to preserve.
    pristine: Termios,
}

/// Guards `ptsname`, which answers out of a static buffer libc reuses.
///
/// Nothing else in this file needs it, and it is deliberately not a general
/// "one pty at a time" lock: it is held across a single call that reads a
/// shared buffer, and released the moment the name has been copied.
static NAMING: Mutex<()> = Mutex::new(());

/// A terminal whose two descriptors are close-on-exec from the instant they
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
/// Measured on macOS: one thread allocating terminals this way, six threads
/// spawning children, and **3547 of 6244 children came out holding a terminal
/// they were never given** — statistically identical to the 3524 of 6267 from
/// a control that never set the flag at all. Setting it afterwards bought
/// nothing. Born with `O_CLOEXEC`: 0 of 6394.
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
fn terminal_that_stays_private(size: Winsize) -> (OwnedFd, OwnedFd) {
    // SAFETY: no arguments to get wrong, and the descriptor is owned below.
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

    // `openpty` took the size as an argument; without it, it is one ioctl on
    // the master, which is the same terminal.
    // SAFETY: a live winsize and a pty master this function owns.
    unsafe { set_winsize(master.as_raw_fd(), &raw const size) }.expect("size the pty");
    (master, slave)
}

fn start(args: &[&str], ownership: Ownership) -> UnderTerminal {
    let (master, slave) = terminal_that_stays_private(winsize(ROWS, COLS));

    let for_stdin = slave.try_clone().expect("dup slave");
    let for_stdout = slave.try_clone().expect("dup slave");
    let for_stderr = slave.try_clone().expect("dup slave");

    let mut command = Command::new(BIN);
    command
        .args(args)
        .stdin(Stdio::from(for_stdin))
        .stdout(Stdio::from(for_stdout))
        .stderr(Stdio::from(for_stderr));
    if ownership == Ownership::Owned {
        // SAFETY: fd 0 is the pty slave by the time pre_exec runs.
        let take_the_terminal = || unsafe { keyless::tty::adopt_controlling_terminal() };
        // SAFETY: calls only async-signal-safe functions and does not allocate.
        unsafe {
            command.pre_exec(take_the_terminal);
        }
    }
    // Before the spawn, deliberately: see `UnderTerminal::pristine`.
    let pristine = termios::tcgetattr(slave.as_fd()).expect("read the pristine terminal settings");

    let child = command.spawn().expect("the binary must run");

    // Read the master on a thread into a buffer the test can inspect as it
    // fills. The test keeps its own copy of the slave open — closing it is the
    // only way the master ever reports end-of-file — so reading to completion
    // here would deadlock every test that wants to look before the run ends.
    let reading = master.try_clone().expect("dup master");
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

    UnderTerminal {
        child,
        slave,
        master,
        seen,
        reader: Some(reader),
        pristine,
    }
}

fn start_under_terminal(args: &[&str]) -> UnderTerminal {
    start(args, Ownership::Inherited)
}

fn start_owning_terminal(args: &[&str]) -> UnderTerminal {
    start(args, Ownership::Owned)
}

impl UnderTerminal {
    /// Everything the terminal has received so far.
    fn text(&self) -> String {
        let seen = self.seen.lock().unwrap_or_else(|error| error.into_inner());
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// Block until `needle` appears in the output, or fail.
    ///
    /// This is the synchronisation primitive for every test that has to act
    /// mid-run. Waiting for the thing itself is the only way to be sure the
    /// child has got where it needs to be.
    fn await_output(&self, needle: &str) {
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

    /// The terminal as it was before `keyless` ran — the baseline a restore is
    /// judged against. See [`UnderTerminal::pristine`] for why it is not read
    /// on demand.
    fn as_created(&self) -> &Termios {
        &self.pristine
    }

    /// The current terminal settings, read through the test's own slave handle.
    fn settings(&self) -> Termios {
        termios::tcgetattr(self.slave.as_fd()).expect("read the terminal settings")
    }

    /// Resize the window, the way a window manager does.
    fn resize(&self, rows: u16, cols: u16) {
        let size = winsize(rows, cols);
        // SAFETY: a live winsize and a pty master this test owns.
        unsafe { set_winsize(self.master.as_raw_fd(), &raw const size) }.expect("resize the pty");
    }

    /// Send `keyless` itself a signal, the way `kill`, a supervisor or a
    /// closing terminal does.
    ///
    /// **Process-directed, never `killpg`.** This `keyless` shares the test
    /// runner's process group — see [`Ownership::Inherited`] — so a group signal
    /// from here would take the whole suite with it.
    fn signal(&self, signal: Signal) {
        kill(Pid::from_raw(self.child.id().cast_signed()), signal)
            .unwrap_or_else(|error| panic!("cannot send {signal:?} to keyless: {error}"));
    }

    /// Type at the terminal.
    fn type_at(&self, keys: &[u8]) {
        let mut keyboard =
            std::fs::File::from(self.master.try_clone().expect("dup master for writing"));
        keyboard.write_all(keys).expect("type at the terminal");
    }

    /// Reap `keyless` and return its exit code.
    ///
    /// Safe to call more than once — the standard library caches the status —
    /// so a test may reap, inspect the terminal, and then finish.
    fn wait_for_exit(&mut self) -> i32 {
        self.child
            .wait()
            .expect("reap keyless")
            .code()
            .unwrap_or(-1)
    }

    /// Wait for the run to end and return everything the terminal received.
    fn finish(mut self) -> (i32, String) {
        let code = self.wait_for_exit();
        // Closing this test's copy of the slave is what lets the reader see
        // end-of-file. It happens only after `keyless` has exited.
        drop(self.slave);
        drop(self.master);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let seen = self.seen.lock().unwrap_or_else(|error| error.into_inner());
        (code, String::from_utf8_lossy(&seen).into_owned())
    }
}

/// A terminal reports `\r\n`; comparing against `\n` everywhere else is noise.
fn lines(seen: &str) -> Vec<String> {
    seen.replace("\r\n", "\n")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Detection: the pty path is taken when, and only when, there is a terminal.
// ---------------------------------------------------------------------------

#[test]
fn a_masked_child_on_a_terminal_still_believes_it_is_on_a_terminal() {
    within(
        CASE_PATIENCE,
        "a_masked_child_on_a_terminal_still_believes_it_is_on_a_terminal",
        || {
            // The whole point. Before this, `keyless run -- npm install` lost its
            // progress bar, `git log` lost its pager, and every prompt changed shape —
            // a tax on every invocation, which is how a tool gets uninstalled.
            let dir = scratch("pty-child-sees-a-terminal");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

            let session = start_under_terminal(&[
                "--config",
                &config.display().to_string(),
                "--no-audit",
                "run",
                "-s",
                "DECOY",
                "--",
                "/bin/sh",
                "-c",
                "for fd in 0 1 2; do if [ -t $fd ]; then echo \"$fd TTY\"; else echo \"$fd PIPE\"; fi; done",
            ]);
            let (code, seen) = session.finish();

            assert_eq!(code, 0, "output was: {seen:?}");
            assert_eq!(
                lines(&seen),
                vec!["0 TTY", "1 TTY", "2 TTY"],
                "all three streams must be a terminal: {seen:?}"
            );
        },
    );
}

#[test]
fn piped_stdio_keeps_the_pipe_path_and_never_allocates() {
    within(
        CASE_PATIENCE,
        "piped_stdio_keeps_the_pipe_path_and_never_allocates",
        || {
            // The other half of "detect, don't assume". A CI job, an agent's shell call
            // or `keyless run ... | grep` must behave exactly as it did before any of
            // this existed. Writing terminal escapes into a pipe is not a nicety.
            let dir = scratch("pty-piped-stays-piped");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

            let output = Command::new(BIN)
                .args([
                    "--config",
                    &config.display().to_string(),
                    "--no-audit",
                    "run",
                    "-s",
                    "DECOY",
                    "--",
                    "/bin/sh",
                    "-c",
                    "if [ -t 1 ]; then echo TTY; else echo PIPE; fi",
                ])
                .output()
                .expect("the binary must run");

            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                "PIPE\n",
                "a pty was allocated with no terminal to preserve; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&output.stderr),
                "",
                "the ordinary non-interactive case must be silent"
            );
        },
    );
}

// ---------------------------------------------------------------------------
// Masking, through the pty.
// ---------------------------------------------------------------------------

#[test]
fn masking_survives_the_pty_path() {
    within(CASE_PATIENCE, "masking_survives_the_pty_path", || {
        let dir = scratch("pty-masking");
        let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

        let session = start_under_terminal(&[
            "--config",
            &config.display().to_string(),
            "--no-audit",
            "run",
            "-s",
            "DECOY",
            "--",
            "/bin/sh",
            "-c",
            "echo \"token=$DECOY\"",
        ]);
        let (code, seen) = session.finish();

        assert_eq!(code, 0);
        assert!(
            !seen.contains(DECOY_VALUE),
            "the value reached the terminal: {seen:?}"
        );
        assert_eq!(lines(&seen), vec!["token=[keyless:DECOY]"]);
    });
}

#[test]
fn the_split_write_property_holds_through_the_pty() {
    within(
        CASE_PATIENCE,
        "the_split_write_property_holds_through_the_pty",
        || {
            // The suffix-carry survives split-across-3-writes, split-every-character and
            // split-mid-rune at the unit level. Those properties are worth nothing if
            // the pty path bypasses the writer that provides them, so this drives the
            // hardest of the three — one byte per write — through two nested terminals
            // and the real binary.
            //
            // The sleep inside the child is what makes it a genuine split. Without it
            // the shell would hand the whole value over in one write and the test would
            // silently stop testing anything — the same shape of rot as a table test
            // that iterates the very list it is meant to check.
            let dir = scratch("pty-split-writes");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

            let session = start_under_terminal(&[
                "--config",
                &config.display().to_string(),
                "--no-audit",
                "run",
                "-s",
                "DECOY",
                "--",
                "/bin/sh",
                "-c",
                "i=1; while [ $i -le ${#DECOY} ]; do \
                   printf '%s' \"$(printf '%s' \"$DECOY\" | cut -c$i)\"; \
                   sleep 0.02; \
                   i=$((i+1)); \
                 done; echo",
            ]);
            let (code, seen) = session.finish();

            assert_eq!(code, 0, "output was: {seen:?}");
            assert!(
                !seen.contains(DECOY_VALUE),
                "one byte at a time leaked through the pty: {seen:?}"
            );
            assert_eq!(
                lines(&seen),
                vec!["[keyless:DECOY]"],
                "output was: {seen:?}"
            );
        },
    );
}

#[test]
fn a_prompt_with_no_trailing_newline_reaches_the_terminal_before_the_run_ends() {
    within(
        CASE_PATIENCE,
        "a_prompt_with_no_trailing_newline_reaches_the_terminal_before_the_run_ends",
        || {
            // The latency property the pty path lives on, end to end. The child prints a
            // prompt and then blocks forever; if the masker held back a flat needle's
            // worth of bytes, the user would see a truncated prompt and a session that
            // looks hung — and it would never resolve, because the next write never
            // comes. `await_output` returning is the assertion.
            let dir = scratch("pty-prompt-latency");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

            let session = start_under_terminal(&[
                "--config",
                &config.display().to_string(),
                "--no-audit",
                "run",
                "-s",
                "DECOY",
                "--",
                "/bin/sh",
                "-c",
                "printf 'Password: '; read ignored",
            ]);

            session.await_output("Password: ");

            // Let the child finish so the run can end.
            session.type_at(b"\r");
            let (code, seen) = session.finish();
            assert_eq!(code, 0, "output was: {seen:?}");
        },
    );
}

// ---------------------------------------------------------------------------
// Window size.
// ---------------------------------------------------------------------------

#[test]
fn the_initial_window_size_reaches_the_child() {
    within(
        CASE_PATIENCE,
        "the_initial_window_size_reaches_the_child",
        || {
            let dir = scratch("pty-initial-size");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

            let session = start_under_terminal(&[
                "--config",
                &config.display().to_string(),
                "--no-audit",
                "run",
                "-s",
                "DECOY",
                "--",
                "/bin/sh",
                "-c",
                "stty size",
            ]);
            let (code, seen) = session.finish();

            assert_eq!(code, 0, "output was: {seen:?}");
            assert_eq!(
                lines(&seen),
                vec![format!("{ROWS} {COLS}")],
                "the child must see the user's window, not a default: {seen:?}"
            );
        },
    );
}

#[test]
fn a_resize_mid_run_reaches_the_child() {
    within(CASE_PATIENCE, "a_resize_mid_run_reaches_the_child", || {
        // No signal is synthesised here. `keyless` owns the terminal's foreground
        // process group, so setting the window size makes the kernel deliver a real
        // SIGWINCH — the same event a window manager produces. Synthesising one
        // would have tested the handler while leaving the delivery path unproven,
        // and delivery is exactly where this broke: a blocked SIGWINCH left at its
        // default disposition is discarded by macOS before anything can wait on it.
        let dir = scratch("pty-resize");
        let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

        // The child synchronises on the resize itself rather than on a sleep: it
        // watches its own terminal until the size changes. The iteration cap is
        // what turns "the signal never arrived" into a failed assertion instead of
        // a suite that hangs.
        let watch_for_the_resize = format!(
            "stty size; i=0; \
             while [ \"$(stty size)\" = \"{ROWS} {COLS}\" ] && [ $i -lt 200 ]; do \
               sleep 0.05; i=$((i+1)); \
             done; stty size"
        );

        let session = start_owning_terminal(&[
            "--config",
            &config.display().to_string(),
            "--no-audit",
            "run",
            "-s",
            "DECOY",
            "--",
            "/bin/sh",
            "-c",
            &watch_for_the_resize,
        ]);

        // Only resize once the child has reported the size it started with.
        session.await_output(&format!("{ROWS} {COLS}"));
        session.resize(ROWS + 5, COLS - 7);

        let (code, seen) = session.finish();
        assert_eq!(code, 0, "output was: {seen:?}");
        assert_eq!(
            lines(&seen),
            vec![
                format!("{ROWS} {COLS}"),
                format!("{} {}", ROWS + 5, COLS - 7)
            ],
            "the resize did not reach the child: {seen:?}"
        );
    });
}

// ---------------------------------------------------------------------------
// Raw mode, and putting it back.
// ---------------------------------------------------------------------------

#[test]
fn the_terminal_is_put_in_raw_mode_and_restored_exactly() {
    within(
        CASE_PATIENCE,
        "the_terminal_is_put_in_raw_mode_and_restored_exactly",
        || {
            // Two assertions, and the first is what stops the second being vacuous: a
            // `keyless` that never touched the terminal would "restore" it perfectly.
            // So this proves the terminal really was raw *during* the run, and
            // byte-for-byte identical afterwards.
            let dir = scratch("pty-raw-restored");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

            let mut session = start_under_terminal(&[
                "--config",
                &config.display().to_string(),
                "--no-audit",
                "run",
                "-s",
                "DECOY",
                "--",
                "/bin/sh",
                "-c",
                "printf 'ready>'; read ignored",
            ]);
            let before = session.as_created().clone();
            assert!(
                before.local_flags.contains(LocalFlags::ICANON),
                "the fixture must start in canonical mode or it proves nothing"
            );

            session.await_output("ready>");
            let during = session.settings();
            assert!(
                !during.local_flags.contains(LocalFlags::ICANON)
                    && !during.local_flags.contains(LocalFlags::ECHO),
                "the terminal was never put in raw mode, so restoring it proves nothing"
            );

            session.type_at(b"\r");
            let code = session.wait_for_exit();
            let after = session.settings();
            let (_, seen) = session.finish();
            assert_eq!(code, 0, "output was: {seen:?}");

            assert_eq!(
                after.local_flags, before.local_flags,
                "local flags were not restored"
            );
            assert_eq!(
                after.input_flags, before.input_flags,
                "input flags were not restored"
            );
            assert_eq!(
                after.output_flags, before.output_flags,
                "output flags were not restored"
            );
            assert_eq!(
                after.control_flags, before.control_flags,
                "control flags were not restored"
            );
            assert_eq!(
                after.control_chars, before.control_chars,
                "control characters were not restored"
            );
        },
    );
}

#[test]
fn the_terminal_is_restored_when_the_child_dies_of_a_signal() {
    within(
        CASE_PATIENCE,
        "the_terminal_is_restored_when_the_child_dies_of_a_signal",
        || {
            // The exit path that skips a child's own teardown. The child kills itself
            // rather than returning, and the terminal must still come back.
            let dir = scratch("pty-restored-after-signal");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

            let mut session = start_under_terminal(&[
                "--config",
                &config.display().to_string(),
                "--no-audit",
                "run",
                "-s",
                "DECOY",
                "--",
                "/bin/sh",
                "-c",
                "printf 'ready>'; kill -TERM $$",
            ]);
            let before = session.as_created().clone();
            session.await_output("ready>");

            let code = session.wait_for_exit();
            let after = session.settings();
            let (_, seen) = session.finish();

            // 128 + SIGTERM(15); some shells trap and exit 143 themselves.
            assert_eq!(
                code, 143,
                "the exit code must survive the pty path: {seen:?}"
            );
            assert_eq!(
                after.local_flags, before.local_flags,
                "the terminal was left raw after a signalled child"
            );
            assert_eq!(
                after.control_chars, before.control_chars,
                "the terminal was left raw after a signalled child"
            );
        },
    );
}

// ---------------------------------------------------------------------------
// Signals arriving at `keyless` while a child owns the terminal.
//
// The relay blocks SIGINT, SIGTERM, SIGHUP and SIGQUIT for every one of its
// threads and consumes them with `sigwait`, so none of the four can kill this
// process while the user's terminal is raw. Consuming a signal is only half the
// contract: the other half is that the CHILD gets it, and until now nothing
// asserted that half. Deleting the forwarding call left the whole suite green,
// which is a never-block guarantee nothing was holding — `keyless` would eat a
// SIGTERM, keep the terminal, and leave the child running.
//
// **This is NOT the Ctrl-C path, and the difference matters for what these
// cases are worth.** A user pressing Ctrl-C sends no signal to `keyless` at all:
// the user's terminal is raw, so its driver generates nothing, the `0x03` byte
// travels down the input relay, and the pty slave's own line discipline raises
// SIGINT for the child's foreground group. What the forwarding covers is every
// signal that arrives at the `keyless` PROCESS — `kill`, a supervisor, a CI
// timeout, and SIGHUP when the terminal itself goes away.
//
// Each case bounds its own FAILURE rather than relying on the harness: the
// child sleeps 5 s and then exits normally, so forwarding that has stopped
// working ends as a wrong exit code within seconds. A child that waited forever
// would turn a regression into a hang, and a hang reports nothing at all.
//
// SIGQUIT is watched and forwarded like the other three and is deliberately not
// exercised: its default action writes a core dump, and a suite that litters
// cores on every run gets its guards deleted.
// ---------------------------------------------------------------------------

/// Interrupt a run with `signal` once its child is up, and report what came out.
fn run_interrupted_by(tag: &str, signal: Signal) -> (i32, String) {
    let dir = scratch(tag);
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

    let session = start_under_terminal(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "run",
        "-s",
        "DECOY",
        "--",
        "/bin/sh",
        "-c",
        "printf 'ready>'; sleep 5; printf 'outlived'",
    ]);
    // Never signal before the child is up: a signal forwarded to a child that
    // does not exist yet would prove nothing, and the marker is the only thing
    // that says it does.
    session.await_output("ready>");
    session.signal(signal);
    session.finish()
}

#[test]
fn a_signal_to_the_run_reaches_the_child() {
    within(
        CASE_PATIENCE,
        "a_signal_to_the_run_reaches_the_child",
        || {
            // `keyless` reports `128 + signal` for a child killed by one, so the
            // exit code is a statement about WHICH signal arrived — not merely that
            // the run ended.
            for (signal, expected, what) in [
                (Signal::SIGTERM, 143, "a termination request"),
                (Signal::SIGINT, 130, "an interrupt"),
                (
                    Signal::SIGHUP,
                    129,
                    "a hangup, which is what a closing terminal sends",
                ),
            ] {
                let (code, seen) = run_interrupted_by(&format!("pty-signal-{signal}"), signal);
                assert_eq!(
                    code, expected,
                    "{what} reached `keyless` and never reached the child: the run exited {code} \
                 rather than {expected}, so the child died of old age instead. The relay \
                 consumed the signal and did not forward it. Terminal saw: {seen:?}"
                );
                assert!(
                    !seen.contains("outlived"),
                    "the child ran to completion after {what} was sent to `keyless`: {seen:?}"
                );
            }
        },
    );
}

#[test]
fn a_forwarded_signal_reaches_the_childs_whole_process_group() {
    within(
        CASE_PATIENCE,
        "a_forwarded_signal_reaches_the_childs_whole_process_group",
        || {
            // The relay signals the process GROUP, and the child is a session
            // leader precisely so that group is its own. Signalling the child
            // alone would leave every process it started — a background job, a
            // `make` subprocess, the second half of a pipeline — alive and
            // holding the terminal, which is the shape of "I pressed Ctrl-C and
            // it is still running".
            //
            // The exit code cannot see that difference: the child dies either
            // way. Only something the GRANDCHILD would do afterwards can.
            //
            // ⚠️ `trap '' HUP` is the whole fixture, and the naive version of
            // this case PASSES against a relay that signals the child alone.
            // Measured 2026-08-09 on macOS with `killpg` replaced by `kill`: the
            // child is a session leader, so its death revokes the controlling
            // terminal and the kernel sends SIGHUP to that terminal's foreground
            // group — which kills the background subshell whatever the relay
            // did. Ignoring SIGHUP is what makes a grandchild outlive its
            // session, and it is also how `nohup` and every daemonising child
            // behave. An IGNORED disposition survives `exec`; a caught one would
            // not.
            //
            // ⚠️ And the marker is written on a CUE rather than on a timer.
            // A grandchild that slept a fixed period would be a race between
            // that period and how long this test takes to send its signal, and a
            // margin that holds on an idle machine is exactly the fixture that
            // passes twice in four runs under load.
            let dir = scratch("pty-signal-process-group");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
            let trapped = dir.join("trapped");
            let go = dir.join("go");
            let orphan = dir.join("orphan");

            // The background subshell inherits the child's process group,
            // because job control is off in `sh -c`. The child waits for it to
            // have trapped SIGHUP before announcing itself, so `ready>` means
            // the fixture is armed and not merely started.
            let body = format!(
                "(trap '' HUP; : > '{trapped}'; \
                  while [ ! -f '{go}' ]; do sleep 0.02; done; : > '{orphan}') & \
                 while [ ! -f '{trapped}' ]; do sleep 0.01; done; \
                 printf 'ready>'; sleep 5",
                trapped = trapped.display(),
                go = go.display(),
                orphan = orphan.display(),
            );

            let session = start_under_terminal(&[
                "--config",
                &config.display().to_string(),
                "--no-audit",
                "run",
                "-s",
                "DECOY",
                "--",
                "/bin/sh",
                "-c",
                &body,
            ]);
            session.await_output("ready>");
            session.signal(Signal::SIGTERM);
            let (code, seen) = session.finish();

            assert_eq!(code, 143, "the child outlived the signal: {seen:?}");

            // The fixture checks ITSELF. A subshell that never reached its trap
            // holds nothing and proves nothing, and this case would then pass
            // against a relay that signals only the child.
            assert!(
                trapped.exists(),
                "the background subshell never armed itself, so this case tested nothing"
            );

            // Now cue it. A subshell that is still alive writes within its 20 ms
            // poll; three seconds is 150 polls. The conclusion rests on having
            // TOLD it to write and waited, not on a margin against a timer.
            std::fs::write(&go, b"").expect("cue the background subshell");
            thread::sleep(Duration::from_secs(3));
            assert!(
                !orphan.exists(),
                "a process the child had started was still alive three seconds after the \
                 signal and answered its cue; the relay is signalling the child alone rather \
                 than its process group, so everything the child spawned keeps running"
            );
        },
    );
}

// ---------------------------------------------------------------------------
// Input.
// ---------------------------------------------------------------------------

#[test]
fn keystrokes_reach_the_child() {
    within(CASE_PATIENCE, "keystrokes_reach_the_child", || {
        // The input half of the relay. Without it the pty would be write-only and
        // every interactive program would hang at its first prompt — worse than the
        // piped stdio this replaces.
        let dir = scratch("pty-input");
        let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

        let session = start_under_terminal(&[
            "--config",
            &config.display().to_string(),
            "--no-audit",
            "run",
            "-s",
            "DECOY",
            "--",
            "/bin/sh",
            "-c",
            "printf 'ready>'; read answer; echo \"got:$answer\"",
        ]);

        // Never type before the child says it is reading: entering raw mode
        // discards unread input, so an early keystroke is silently destroyed.
        session.await_output("ready>");
        session.type_at(b"decoy-typed-answer\r");

        let (code, seen) = session.finish();
        assert_eq!(code, 0, "output was: {seen:?}");
        assert!(
            seen.contains("got:decoy-typed-answer"),
            "the keystrokes never arrived: {seen:?}"
        );
    });
}

// ---------------------------------------------------------------------------
// The never-block invariant, on the pty path.
// ---------------------------------------------------------------------------

#[test]
fn a_grandchild_holding_the_terminal_open_does_not_hang_the_run() {
    within(
        CASE_PATIENCE,
        "a_grandchild_holding_the_terminal_open_does_not_hang_the_run",
        || {
            // The pipe path has had a bounded drain for this since 2026-08-08: a
            // pty master, like a pipe, reports end-of-stream only when the LAST
            // holder lets go, and a backgrounded grandchild inherits the terminal
            // and outlives the child that started it. `keyless` must give up on
            // that output, not on the caller.
            //
            // ⚠️ This case is VACUOUS on macOS and the comment stays here so
            // nobody reads a green macOS run as proof. XNU revokes a controlling
            // terminal when its session ends, and the grandchild is in that same
            // session, so its descriptors are torn out from under it and the
            // master sees end-of-stream whatever `keyless` does. Linux performs no
            // such revoke: without a bound, this case never returns. The bound is
            // real on exactly one of the two platforms, and it is the platform CI
            // has to catch it on.
            //
            // ⚠️ Every line of the shell below is load-bearing, and the naive
            // version of it is a fixture that passes for the wrong reason.
            //
            // Linux sends `SIGHUP` to the foreground process group when the
            // child's session ends, so a plain `sleep 120 &` is KILLED and holds
            // nothing. Ignoring `SIGHUP` is what makes a grandchild outlive its
            // session, which is also how `nohup` and every daemonising child
            // behave. `trap '' HUP` survives the `exec` a shell may do for the
            // last command in a subshell, because POSIX keeps an IGNORED
            // disposition across `exec` — a caught one would not survive.
            //
            // And installing the trap is not enough: `(trap '' HUP; sleep 120) &`
            // RACES its own parent's exit, so whether the grandchild lives is
            // decided by which of the two wins. Measured 2026-08-09 against the
            // unbounded drain, on one binary, four invocations: it hung twice and
            // passed twice — a coin toss reported as a green test. So the parent
            // waits for a marker the grandchild writes AFTER trapping, and only
            // then exits.
            let dir = scratch("pty-grandchild-holds-the-terminal");
            let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
            let trapped = dir.join("trapped");
            let outlived = dir.join("outlived");

            let hold_the_terminal = format!(
                "(trap '' HUP; : > '{trapped}'; sleep 0.5; : > '{outlived}'; sleep 120) & \
                 while [ ! -f '{trapped}' ]; do sleep 0.01; done; \
                 echo ran",
                trapped = trapped.display(),
                outlived = outlived.display(),
            );

            let started = Instant::now();
            let session = start_under_terminal(&[
                "--config",
                &config.display().to_string(),
                "--no-audit",
                "run",
                "-s",
                "DECOY",
                "--",
                "/bin/sh",
                "-c",
                &hold_the_terminal,
            ]);
            let (code, seen) = session.finish();
            let took = started.elapsed();

            assert_eq!(code, 0, "output was: {seen:?}");
            assert!(
                seen.contains("ran"),
                "the child's own output must still arrive: {seen:?}"
            );
            // The holder lives for 120 s. Anything near that is the hang this
            // case exists to catch; the drain's own grace is 2 s.
            assert!(
                took < Duration::from_secs(20),
                "the run waited {took:?} on output a grandchild was holding open; \
                 it must give up on the output rather than on the caller"
            );

            // The fixture checks ITSELF. A grandchild that died with its session
            // holds nothing, and this case would then pass against completely
            // unbounded code — which is exactly what the naive version did.
            let deadline = Instant::now() + MARKER_PATIENCE;
            while !outlived.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                outlived.exists(),
                "the grandchild did not outlive the session, so it never held the \
                 terminal and this case proved nothing about the drain"
            );
        },
    );
}
