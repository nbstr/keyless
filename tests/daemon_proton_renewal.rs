#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::session_verbs::{
    LogoutAnswer, daemon_config_with_generations_loop, parse_verbs, stub_with_session_verbs,
};
use daemon_proton_support::{DECLARED, LISTING, session_dir};
use support::backend::Backend;
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::generations::current_generation;
use support::proton::{Listing, stub_pass_cli_listing};
use support::{PROTON_DECOY, install_executable, scratch};

#[test]
fn the_renewal_loop_establishes_each_session_in_a_fresh_generation_and_makes_it_current() {
    // CONTROL — the change that makes this fail: scope `establish`'s login
    // at `coordinates.session_dir` (the root) instead of the fresh
    // generation directory it just created. `info` still runs at the
    // generation, so `followed_by_info` below breaks — the login and the
    // info that verifies it are no longer at the same directory.
    let dir = scratch("daemon-proton-gen-establishes");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    // `login_after_minutes: 0` makes every tick due, so the loop renews on
    // every one-second probe interval rather than waiting out an age nobody
    // has time to reach in a short test run. `60_000` — this case is not
    // about the grace, so it gets the suite's generous ceiling rather than
    // the small one a loaded machine could turn red for the wrong reason.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    // Polled rather than a fixed sleep: this only waits on a subprocess spawn
    // this MACHINE'S load decides the speed of, not on anything the retirement
    // grace governs.
    let deadline = Instant::now() + Duration::from_secs(30);
    let current = loop {
        if let Some(name) = current_generation(&root) {
            break name;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published"
        );
        std::thread::sleep(Duration::from_millis(200));
    };

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    let first_login = lines
        .iter()
        .position(|line| line.verb == "login")
        .expect("the loop never logged in");
    let login_dir = lines[first_login].dir.clone();
    let followed_by_info = lines[first_login + 1..]
        .iter()
        .take_while(|line| line.verb != "login")
        .any(|line| line.verb == "info" && line.dir == login_dir);
    assert!(
        followed_by_info,
        "the first login was not followed by an info at the same directory"
    );

    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { .. } => {}
        other => panic!("a declared name must resolve: {}", other.reason()),
    }
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        root.join(current).display().to_string(),
        "a read was scoped somewhere other than the published current generation"
    );

    // The scope invariant over every line, not the single sample above: a
    // real vault read (`run`, `item`, `vault`) is never scoped at the root —
    // re-read fresh so the resolve just performed is included.
    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let root_str = root.display().to_string();
    for line in parse_verbs(&verbs) {
        if matches!(line.verb.as_str(), "run" | "item" | "vault") {
            assert_ne!(
                line.dir, root_str,
                "a `{}` was scoped at the root instead of a generation",
                line.verb
            );
        }
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `pass-cli` that hangs on its FIRST `login` and never returns, then
/// behaves normally on every later invocation.
///
/// On the first `login` it records its own pid in `<dir>/hung-login.pid`,
/// then execs `sleep 600`, which no test deadline waits out — so that login
/// never reaches `recovers` and appears in no verb log. Every other
/// invocation (a later `login`, any `info`, any `logout`) execs `recovers`,
/// the ordinary session-verbs stand-in, which logs it as usual.
fn stub_hangs_once_then_recovers(dir: &Path, recovers: &Path) -> PathBuf {
    let pidfile = dir.join("hung-login.pid");
    install_executable(
        &dir.join("pass-cli-hangs-once"),
        &format!(
            "#!/bin/sh\n\
             if [ \"$1\" = login ] && [ ! -e '{pidfile}' ]; then\n\
             \x20 echo $$ > '{pidfile}'\n\
             \x20 exec sleep 600\n\
             fi\n\
             exec '{recovers}' \"$@\"\n",
            pidfile = pidfile.display(),
            recovers = recovers.display(),
        ),
    )
}

#[test]
fn a_hung_login_is_killed_and_counted_as_a_failed_attempt_so_the_next_one_still_publishes() {
    // CONTROL — the change that makes this fail: reverting `login::run` to an
    // unbounded `Command::output()`. The loop then waits on `sleep 600`
    // forever, no generation is ever published, and this test times out
    // against its own 60 s poll deadline rather than seeing a second login.
    let dir = scratch("daemon-proton-hung-login");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let recovers = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    let verbs_log = dir.join("pass-cli.verbs");
    let vendor = stub_hangs_once_then_recovers(&dir, &recovers);

    // Small enough that the login deadline (2x this, per `login::login_deadline`)
    // is a few seconds — long enough for a real vendor spawn, short enough
    // that the sleeping stand-in is killed well inside this test's own poll
    // deadline.
    const TIMEOUT_MS: u64 = 1500;
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, TIMEOUT_MS);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if current_generation(&root).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published — a hung login stalled the loop instead of \
             being killed and counted as a failed attempt"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let verbs = std::fs::read_to_string(&verbs_log).unwrap_or_default();
    let login_lines = parse_verbs(&verbs)
        .iter()
        .filter(|line| line.verb == "login")
        .count();
    // The hung login never reaches the logging stand-in, so every `login`
    // line here is a later attempt — the one the loop made after the kill.
    assert!(
        login_lines >= 1,
        "no login followed the hung one, saw {login_lines}: {verbs}"
    );

    let hung_pid: i32 = std::fs::read_to_string(dir.join("hung-login.pid"))
        .expect("the hung child never recorded its own pid")
        .trim()
        .parse()
        .expect("a pid");
    assert!(
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(hung_pid),
            None::<nix::sys::signal::Signal>
        )
        .is_err(),
        "the hung pass-cli child (pid {hung_pid}) is still alive — it was never killed and reaped"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The daemon's uid is read off the audit log on every renewal attempt, never
/// once for the life of the loop.
///
/// A uid captured at start is right until the file it came from changes, and
/// then it is wrong for as long as the process lives: a daemon that started
/// against a misowned audit log spawned every vendor child as that owner and
/// failed every attempt until somebody restarted it, however promptly the
/// owner was put back.
///
/// Changing a file's owner to another uid needs privilege this suite does not
/// have, so the source is made wrong the one way an unprivileged test can:
/// the audit log is taken away. While it is gone no attempt may spawn a vendor
/// child — there is no uid to run one as, and reusing the last attempt's would
/// be the stale identity this case exists to rule out. Once it is back, the
/// next attempt publishes a generation with the same daemon still running.
///
/// CONTROL — the change that makes this fail: capture the owner once in
/// `session::spawn` and hand it to the loop. The loop then keeps logging in
/// with the uid it read at start while the audit log is absent, and the
/// "no vendor child while the source is gone" assertion goes red.
#[test]
fn the_renewal_loop_rereads_the_daemon_uid_so_a_restored_audit_log_needs_no_restart() {
    let dir = scratch("daemon-proton-uid-per-attempt");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    // Every one-second tick is due, so an attempt that is allowed to run does.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let audit = dir.join("audit.jsonl");
    let verbs_log = dir.join("pass-cli.verbs");
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let until = |what: &str, done: &dyn Fn() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !done() {
            assert!(Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(200));
        }
    };
    until("the loop never published a first generation", &|| {
        current_generation(&root).is_some()
    });

    std::fs::remove_file(&audit).expect("take the audit log away");
    // One tick already past its owner read may still finish its children;
    // what follows is measured after it has had the time to.
    std::thread::sleep(Duration::from_millis(2_500));
    let settled = std::fs::read_to_string(&verbs_log).unwrap_or_default();
    let during = current_generation(&root);
    std::thread::sleep(Duration::from_secs(4));
    let after = std::fs::read_to_string(&verbs_log).unwrap_or_default();
    let spawned: Vec<_> = parse_verbs(&after[settled.len()..])
        .into_iter()
        .map(|line| line.verb)
        .collect();
    assert!(
        spawned.is_empty(),
        "the loop ran vendor children with no audit log to read a uid off, so it reused an \
         earlier attempt's: {spawned:?}"
    );
    assert_eq!(
        current_generation(&root),
        during,
        "a generation was published while the daemon's uid could not be resolved"
    );

    std::fs::write(&audit, b"").expect("restore the audit log");
    until(
        "no generation was published after the audit log came back, so the loop needs a restart",
        &|| current_generation(&root) != during,
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
