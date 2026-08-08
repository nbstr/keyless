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
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::pty::{OpenptyResult, Winsize, openpty};
use nix::sys::termios::{self, LocalFlags, Termios};

use support::{DECOY_VALUE, Stub, scratch, stub_security};

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// Long enough for a shell to start and print under a loaded parallel run,
/// short enough that a hang fails the test instead of the suite.
const PATIENCE: Duration = Duration::from_secs(30);

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
}

fn start(args: &[&str], ownership: Ownership) -> UnderTerminal {
    let OpenptyResult { master, slave } =
        openpty(Some(&winsize(ROWS, COLS)), None).expect("this platform must provide a pty");

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
        let deadline = Instant::now() + PATIENCE;
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
}

#[test]
fn piped_stdio_keeps_the_pipe_path_and_never_allocates() {
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
}

// ---------------------------------------------------------------------------
// Masking, through the pty.
// ---------------------------------------------------------------------------

#[test]
fn masking_survives_the_pty_path() {
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
}

#[test]
fn the_split_write_property_holds_through_the_pty() {
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
}

#[test]
fn a_prompt_with_no_trailing_newline_reaches_the_terminal_before_the_run_ends() {
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
}

// ---------------------------------------------------------------------------
// Window size.
// ---------------------------------------------------------------------------

#[test]
fn the_initial_window_size_reaches_the_child() {
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
}

#[test]
fn a_resize_mid_run_reaches_the_child() {
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
}

// ---------------------------------------------------------------------------
// Raw mode, and putting it back.
// ---------------------------------------------------------------------------

#[test]
fn the_terminal_is_put_in_raw_mode_and_restored_exactly() {
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
    let before = session.settings();
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
}

#[test]
fn the_terminal_is_restored_when_the_child_dies_of_a_signal() {
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
    let before = session.settings();
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
}

// ---------------------------------------------------------------------------
// Input.
// ---------------------------------------------------------------------------

#[test]
fn keystrokes_reach_the_child() {
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
}
