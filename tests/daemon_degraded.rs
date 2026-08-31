//! The never-block invariant, once per way the daemon can fail.
//!
//! A daemon is the easiest thing in this design to lose the invariant to.
//! Every other backend fails in one or two ways; a daemon fails in a dozen —
//! absent, stale, unreachable, wedged, half-answering, answering nonsense,
//! killed mid-sentence — and each of them is a separate opportunity for
//! `keyless run` to stop running somebody's command.
//!
//! So there is one test per failure mode, and each asserts the same three
//! things:
//!
//! 1. **The child ran.** Proved by a marker file the child writes, not by an
//!    exit code, which a process that never started can imitate.
//! 2. **The environment was not modified.** The marker holds `<unset>`.
//! 3. **The child's exit code survived.**
//!
//! Plus a fourth that matters as much: nothing the daemon does may cause a
//! value to appear anyway. A degraded run has no local fallback to reach for,
//! by construction — see `store::build`.

mod support;

// Twelve of the seventeen cases below stand up a FAKE daemon out of a plain
// `UnixListener` and misbehave on purpose, so they need no attestation and run
// on every platform — which is the half of this file worth the most, since the
// never-block invariant is what a session depends on when a daemon is missing.
//
// The five marked `#[cfg(target_os = "macos")]` bind a REAL `keylessd`. That
// needs the XNU attestation, so they exist on macOS only.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use keyless::State;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::store;
use keyless::store::Invocation;

use support::{DECOY_VALUE, client_config, scratch, short_socket_path, witness, witnessed};

/// How long a client waits before giving up on a wedged daemon. Short, so the
/// timeout tests do not dominate the suite.
const TIMEOUT_MS: u64 = 300;

/// Run one command against a daemon at `socket`, and report what the caller
/// would have seen.
fn run_against(socket: &Path, marker: &Path, code: i32) -> (keyless::cmd::run::Outcome, String) {
    let config = client_config(socket, TIMEOUT_MS);
    let built = store::build(&config, &Invocation::default());
    let binding = Binding::parse("DECOY").expect("valid binding");
    let argv = witness(marker, "DECOY", code);

    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &[binding],
            unusable: &[],
            argv: &argv,
            registry: &built.registry,
            audit: None,
            warnings: &built.warnings,
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run must never fail when the command exists");

    (outcome, String::from_utf8_lossy(&notes).into_owned())
}

/// Assert the invariant, whatever the daemon did.
fn assert_degraded_but_ran(tag: &str, socket: &Path, marker: &Path) {
    let (outcome, notes) = run_against(socket, marker, 7);

    assert_eq!(
        witnessed(marker),
        "<unset>",
        "{tag}: the child saw a modified environment"
    );
    assert_eq!(outcome.state, State::Degraded, "{tag}: state");
    assert_eq!(
        outcome.exit_code, 7,
        "{tag}: the child's exit code was lost"
    );
    assert!(outcome.injected.is_empty(), "{tag}: something was injected");
    assert_eq!(outcome.unresolved, ["DECOY"], "{tag}: unresolved names");
    assert!(
        notes.contains("DEGRADED"),
        "{tag}: the caller was not told; stderr was `{notes}`"
    );
    assert!(
        !notes.contains(DECOY_VALUE),
        "{tag}: a value reached stderr: {notes}"
    );
}

// ---------------------------------------------------------------------------
// A daemon that misbehaves in one specific way.
// ---------------------------------------------------------------------------

/// What the stand-in daemon does with a connection.
#[derive(Clone, Copy)]
enum Misbehaviour {
    /// Accept, then close without a word.
    CloseImmediately,
    /// Answer with something that is not JSON.
    Garbage,
    /// Answer with a valid frame from a protocol version this build does not
    /// speak.
    WrongVersion,
    /// Read the request and never answer.
    Hang,
    /// Send half a frame, then close. No newline ever arrives.
    HalfFrame,
    /// Answer with a frame far above the size cap and no newline.
    Flood,
    /// Claim success and send no value.
    OkWithNoValue,
}

/// A listener that misbehaves, stopped when this is dropped.
struct FakeDaemon {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FakeDaemon {
    fn start(dir: &Path, behaviour: Misbehaviour) -> Self {
        // NOT `dir.join(...)`: `dir` is under `TMPDIR`, and a socket named
        // there is a bet that `TMPDIR` is short. See `support::short_socket_path`.
        let socket = short_socket_path(dir);
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind the stand-in daemon");
        listener.set_nonblocking(true).expect("nonblocking");

        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => serve_badly(stream, behaviour, &flag),
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
        });

        FakeDaemon {
            socket,
            stop,
            thread: Some(thread),
        }
    }

    fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn serve_badly(mut stream: UnixStream, behaviour: Misbehaviour, stop: &AtomicBool) {
    // Read whatever the client sent, so the failure is about the reply rather
    // than about a refused write.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf);

    match behaviour {
        Misbehaviour::CloseImmediately => {}
        Misbehaviour::Garbage => {
            let _ = stream.write_all(b"this is not json at all\n");
        }
        Misbehaviour::WrongVersion => {
            let _ = stream.write_all(br#"{"v":9999,"status":"ok","value":"decoy"}"#);
            let _ = stream.write_all(b"\n");
        }
        Misbehaviour::Hang => {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(10));
            }
        }
        Misbehaviour::HalfFrame => {
            let _ = stream.write_all(br#"{"v":1,"status":"o"#);
        }
        Misbehaviour::Flood => {
            let blob = vec![b'x'; 128 * 1024];
            let _ = stream.write_all(&blob);
        }
        Misbehaviour::OkWithNoValue => {
            let _ = stream.write_all(br#"{"v":1,"status":"ok"}"#);
            let _ = stream.write_all(b"\n");
        }
    }
    let _ = stream.flush();
}

fn against_fake(tag: &str, behaviour: Misbehaviour) {
    let dir = scratch(tag);
    let fake = FakeDaemon::start(&dir, behaviour);
    let marker = dir.join("marker");
    assert_degraded_but_ran(tag, fake.socket(), &marker);
    drop(fake);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The failure modes
// ---------------------------------------------------------------------------

#[test]
fn an_absent_socket_degrades_and_the_child_still_runs() {
    let dir = scratch("daemon-absent");
    let marker = dir.join("marker");
    // Short even though nothing is bound here: `connect(2)` refuses an
    // over-long path with `InvalidInput` before it ever looks for the socket,
    // so under a long `TMPDIR` this would degrade for a reason that has nothing
    // to do with the socket being absent — and stay green while doing it.
    let absent = short_socket_path(&dir);
    let _ = std::fs::remove_file(&absent);
    assert_degraded_but_ran("absent", &absent, &marker);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_socket_path_that_is_a_regular_file_degrades() {
    let dir = scratch("daemon-regular-file");
    let path = dir.join("not-a-socket");
    std::fs::write(&path, b"a regular file").expect("write");
    let marker = dir.join("marker");
    assert_degraded_but_ran("regular file", &path, &marker);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_socket_path_that_is_a_directory_degrades() {
    let dir = scratch("daemon-directory");
    let path = dir.join("a-directory");
    std::fs::create_dir_all(&path).expect("mkdir");
    let marker = dir.join("marker");
    assert_degraded_but_ran("directory", &path, &marker);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stale_socket_with_nothing_listening_degrades() {
    // The inode outlives the process that made it, so connect fails with
    // ECONNREFUSED rather than ENOENT — a different code path from an absent
    // socket, and the one a crashed daemon actually leaves behind.
    let dir = scratch("daemon-stale");
    let path = short_socket_path(&dir);
    let _ = std::fs::remove_file(&path);
    {
        let listener = UnixListener::bind(&path).expect("bind");
        drop(listener);
    }
    assert!(path.exists(), "the socket inode must survive the listener");
    let marker = dir.join("marker");
    assert_degraded_but_ran("stale", &path, &marker);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_socket_we_may_not_connect_to_degrades() {
    let dir = scratch("daemon-forbidden");
    let path = short_socket_path(&dir);
    let _ = std::fs::remove_file(&path);
    let _listener = UnixListener::bind(&path).expect("bind");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    }
    let marker = dir.join("marker");
    // The owner of a mode-000 socket is still refused by the kernel's own
    // permission check on connect, which is exactly the case an install with
    // the wrong group produces.
    assert_degraded_but_ran("forbidden", &path, &marker);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_daemon_that_closes_without_answering_degrades() {
    against_fake("daemon-closes", Misbehaviour::CloseImmediately);
}

#[test]
fn a_daemon_that_answers_garbage_degrades() {
    against_fake("daemon-garbage", Misbehaviour::Garbage);
}

#[test]
fn a_daemon_speaking_another_protocol_version_degrades() {
    against_fake("daemon-version", Misbehaviour::WrongVersion);
}

#[test]
fn a_wedged_daemon_degrades_at_the_deadline() {
    against_fake("daemon-hang", Misbehaviour::Hang);
}

#[test]
fn a_daemon_that_stops_mid_frame_degrades() {
    against_fake("daemon-halfframe", Misbehaviour::HalfFrame);
}

#[test]
fn a_daemon_that_floods_past_the_frame_cap_degrades() {
    against_fake("daemon-flood", Misbehaviour::Flood);
}

#[test]
fn a_daemon_claiming_success_with_no_value_degrades() {
    // The nastiest of the malformed replies: `status` says the caller should
    // expect a value, so a decoder that trusted the status word would hand
    // `run` an empty string and report INJECTED.
    against_fake("daemon-okempty", Misbehaviour::OkWithNoValue);
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
#[test]
fn a_daemon_that_refuses_the_caller_degrades() {
    // A refused attestation must look exactly like every other failure from
    // `run`'s point of view: warn, and run the command anyway.
    let dir = scratch("daemon-denied");
    let config = support::daemon_config(&dir);
    support::write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = support::start_daemon(&config, support::policy_allowing_nobody());

    let marker = dir.join("marker");
    assert_degraded_but_ran("denied", running.socket(), &marker);

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
#[test]
fn a_daemon_whose_store_is_broken_degrades() {
    let dir = scratch("daemon-brokenstore");
    let config = support::daemon_config(&dir);
    // The store file is never created, so the daemon is healthy and its
    // backend is not.
    let running = support::start_daemon(&config, support::policy_allowing_self());

    let marker = dir.join("marker");
    assert_degraded_but_ran("broken store", running.socket(), &marker);

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
#[test]
fn a_daemon_that_does_not_have_the_name_degrades() {
    let dir = scratch("daemon-absentname");
    let config = support::daemon_config(&dir);
    support::write_secrets(&config.stores.file.path, &[("SOMETHING_ELSE", DECOY_VALUE)]);
    let running = support::start_daemon(&config, support::policy_allowing_self());

    let marker = dir.join("marker");
    assert_degraded_but_ran("absent name", running.socket(), &marker);

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
#[test]
fn a_daemon_that_dies_between_two_runs_degrades_the_second() {
    // The transition is what matters: the same config, the same command, and
    // the only difference is that the daemon stopped. The second run must lose
    // the secret and keep the command.
    let dir = scratch("daemon-dies");
    let config = support::daemon_config(&dir);
    support::write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = support::start_daemon(&config, support::policy_allowing_self());
    let socket = running.socket().to_path_buf();

    let first_marker = dir.join("marker-before");
    let (before, _) = run_against(&socket, &first_marker, 0);
    assert_eq!(
        before.state,
        State::Injected,
        "the daemon was meant to work"
    );
    assert_eq!(witnessed(&first_marker), DECOY_VALUE);

    drop(running);

    let second_marker = dir.join("marker-after");
    assert_degraded_but_ran("after the daemon died", &socket, &second_marker);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
#[test]
fn killing_the_daemon_never_widens_what_a_session_can_reach() {
    // Invariant 2, stated as a test. The config asks for the daemon AND all
    // four local backends; none of the four may be registered, because each
    // of them resolves through a credential the calling user already holds —
    // so any one left behind is a fallback that opens the instant the daemon
    // stops.
    let dir = scratch("daemon-nofallback");
    let config: keyless::config::Config = serde_json::from_str(
        r#"{"stores":{"keychain":{"enabled":true},
                      "infisical":{"enabled":true},
                      "onepassword":{"enabled":true},
                      "proton":{"enabled":true},
                      "daemon":{"enabled":true,
                      "socket":"/nonexistent/keyless/never.sock","timeout_ms":200}}}"#,
    )
    .expect("valid config");

    let built = store::build(&config, &Invocation::default());
    let ids: Vec<&str> = built.registry.stores().iter().map(|s| s.id()).collect();
    assert_eq!(
        ids,
        ["daemon"],
        "a local fallback would re-open the hole whenever the daemon stopped"
    );

    // Both channels: the three backends the user explicitly enabled are a
    // run-time warning, the keychain is a `doctor` note. What matters here is
    // that none of the four is dropped in silence.
    let said = built
        .warnings
        .iter()
        .chain(built.notes.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    for backend in ["keychain", "infisical", "onepassword", "proton"] {
        assert!(
            said.contains(backend),
            "dropping {backend} must be said out loud: {said}"
        );
    }
    assert!(
        built
            .warnings
            .iter()
            .any(|w| w.contains("infisical") && w.contains("proton")),
        "a backend the user explicitly enabled must warn on every run, not only in doctor: {:?}",
        built.warnings
    );

    let marker = dir.join("marker");
    let (outcome, _) = run_against(Path::new("/nonexistent/keyless/never.sock"), &marker, 5);
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(witnessed(&marker), "<unset>");
    let _ = std::fs::remove_dir_all(&dir);
}
