//! The daemon working, end to end.
//!
//! Every refusal in `attestation.rs` and every degradation in
//! `daemon_degraded.rs` is only worth something if the thing they are refusing
//! and degrading actually works. This file is that control: a real daemon, a
//! real socket, a real child process, and the secret arriving in its
//! environment and nowhere else.

// The daemon is macOS-only (`src/lib.rs`), so this whole file is. On any other
// platform the crate below compiles to nothing and the binary reports 0 tests —
// ABSENT rather than ignored, which is why CI's `ignored == 15` assertion is
// unchanged and still means "the Proton live suite, and nothing else".
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::sync::Arc;
use std::sync::Barrier;
use std::time::Duration;

use keyless::State;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::store;
use keyless::store::Invocation;
use keyless::store::Store;
use keyless::store::daemon::DaemonStore;

use support::{
    DECOY_VALUE, client_config, daemon_config, echoes, policy_allowing_self, scratch, start_daemon,
    witness, witnessed, write_secrets,
};

#[test]
fn a_secret_reaches_the_child_through_the_daemon_and_nothing_else() {
    let dir = scratch("daemon-e2e");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let built = store::build(&client, &Invocation::default());
    let marker = dir.join("marker");
    let argv = witness(&marker, "DECOY", 0);

    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &[Binding::parse("DECOY").expect("valid")],
            unusable: &[],
            argv: &argv,
            registry: &built.registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run");

    assert_eq!(outcome.state, State::Injected);
    assert_eq!(outcome.injected, ["DECOY"]);
    assert_eq!(
        witnessed(&marker),
        DECOY_VALUE,
        "the child did not receive the value"
    );
    assert!(
        !String::from_utf8_lossy(&notes).contains(DECOY_VALUE),
        "the value reached stderr"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `YYYY-MM-DD` for `offset` days from now, the same way the daemon's own
/// `credential.rs` fixtures build one.
fn in_days(offset: i64) -> String {
    let millis = keyless::time::now_unix_millis() as i64 + offset * 86_400_000;
    keyless::time::rfc3339_utc(millis as u128)[..10].to_owned()
}

#[test]
fn keyless_run_warns_on_stderr_while_the_agent_token_is_inside_its_window() {
    let dir = scratch("daemon-token-expiry-inside");
    let mut config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    // Ten days out is inside the run warning's 14-day window and outside the
    // separate `keylessd check` one, which is the case this ticket is about:
    // a caller running commands, not an operator reading a log.
    let soon = in_days(10);
    config.stores.proton.token_expires = Some(soon.clone());
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let built = store::build(&client, &Invocation::default());
    let marker = dir.join("marker");
    let argv = witness(&marker, "DECOY", 0);

    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &[Binding::parse("DECOY").expect("valid")],
            unusable: &[],
            argv: &argv,
            registry: &built.registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run");

    assert_eq!(outcome.state, State::Injected);
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(witnessed(&marker), DECOY_VALUE);
    let said = String::from_utf8_lossy(&notes);
    assert!(said.contains(&soon), "{said}");
    assert!(said.contains("expires"), "{said}");
    assert!(
        !said.contains(DECOY_VALUE),
        "the advisory line carried the secret: {said}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keyless_run_says_nothing_outside_the_agent_tokens_window() {
    let dir = scratch("daemon-token-expiry-outside");
    let mut config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    // Comfortably past the 14-day run window (and the 30-day check one), so
    // this proves the run stays quiet rather than merely proving one date.
    config.stores.proton.token_expires = Some(in_days(90));
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let built = store::build(&client, &Invocation::default());
    let marker = dir.join("marker");
    let argv = witness(&marker, "DECOY", 0);

    let mut notes: Vec<u8> = Vec::new();
    run(
        RunRequest {
            bindings: &[Binding::parse("DECOY").expect("valid")],
            unusable: &[],
            argv: &argv,
            registry: &built.registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run");

    let said = String::from_utf8_lossy(&notes);
    assert!(!said.contains("expires"), "{said}");
    assert!(!said.contains("EXPIRED"), "{said}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn keyless_run_says_nothing_with_no_token_expires_configured() {
    // `daemon_config` declares no `token_expires` at all, which is the
    // ordinary state of an install that has never set one — every other test
    // in this file runs under exactly this condition and stays quiet.
    let dir = scratch("daemon-token-expiry-undeclared");
    let config = daemon_config(&dir);
    assert!(config.stores.proton.token_expires.is_none());
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let built = store::build(&client, &Invocation::default());
    let marker = dir.join("marker");
    let argv = witness(&marker, "DECOY", 0);

    let mut notes: Vec<u8> = Vec::new();
    run(
        RunRequest {
            bindings: &[Binding::parse("DECOY").expect("valid")],
            unusable: &[],
            argv: &argv,
            registry: &built.registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run");

    let said = String::from_utf8_lossy(&notes);
    assert!(!said.contains("expires"), "{said}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_value_from_the_daemon_is_masked_out_of_the_childs_output() {
    // The masker is compiled from whatever resolved, and a value that arrived
    // over a socket is no different from one that came out of a keychain.
    let dir = scratch("daemon-mask");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let built = store::build(&client, &Invocation::default());

    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &[Binding::parse("DECOY").expect("valid")],
            unusable: &[],
            argv: &echoes(DECOY_VALUE),
            registry: &built.registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run");

    assert_eq!(outcome.state, State::Injected);
    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn twenty_sessions_asking_at_once_make_one_upstream_call() {
    // Single-flight, over the socket rather than inside the resolver, so the
    // whole path is exercised: twenty connections, twenty attestations, twenty
    // audit rows — and one read of the store.
    //
    // The counter is the daemon's own, incremented where a store is actually
    // asked. Without it "they were coalesced" could only be asserted by
    // reading the implementation.
    let dir = scratch("daemon-singleflight");
    let mut config = daemon_config(&dir);
    // No caching, so anything the counter shows is coalescing and not a cache
    // hit. This is the distinction that makes the assertion mean something.
    config.cache_ttl_seconds = 0;
    // A store that takes 200ms, because coalescing can only coalesce requests
    // that actually overlap. Against the file store — microseconds — twenty
    // sequentially-arriving requests legitimately produce up to twenty calls,
    // and a test asserting one would be asserting that the machine is slow.
    // A slow backend makes the window real and the assertion exact.
    config.stores.file.enabled = false;
    config.stores.keychain.enabled = true;
    config.stores.keychain.binary = support::slow_store_stub(&dir, DECOY_VALUE, 200).into();
    let running = start_daemon(&config, policy_allowing_self());
    let socket = running.socket().to_path_buf();

    let gate = Arc::new(Barrier::new(20));
    std::thread::scope(|scope| {
        for _ in 0..20 {
            let socket = socket.clone();
            let gate = Arc::clone(&gate);
            scope.spawn(move || {
                let store = DaemonStore::new(socket, Duration::from_secs(10));
                gate.wait();
                let secret = store
                    .resolve("DECOY")
                    .expect("resolve")
                    .expect("a value must come back");
                assert_eq!(secret.expose(), DECOY_VALUE);
            });
        }
    });

    assert_eq!(
        running.upstream_calls(),
        1,
        "twenty simultaneous sessions must reach the store once, or a rate limit \
         degrades the whole fleet at the same instant"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn different_names_are_not_coalesced_into_one_call() {
    // The negative control for the test above.
    let dir = scratch("daemon-distinct");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(
        &config.stores.file.path,
        &[
            ("A", "decoy-a-0001"),
            ("B", "decoy-b-0002"),
            ("C", "decoy-c-0003"),
        ],
    );
    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(10));

    for name in ["A", "B", "C"] {
        assert!(store.resolve(name).expect("resolve").is_some());
    }
    assert_eq!(running.upstream_calls(), 3);

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_cache_serves_a_repeat_without_touching_the_store() {
    let dir = scratch("daemon-cache");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(10));

    for _ in 0..5 {
        assert!(store.resolve("DECOY").expect("resolve").is_some());
    }
    assert_eq!(running.upstream_calls(), 1);

    // And it is in memory only: nothing under the daemon's directory holds the
    // value, so stopping the daemon leaves nothing to decrypt.
    drop(running);
    for entry in std::fs::read_dir(&dir)
        .expect("read the daemon's directory")
        .flatten()
    {
        let path = entry.path();
        if path == config.stores.file.path.as_path() {
            continue;
        }
        let contents = std::fs::read(&path).unwrap_or_default();
        assert!(
            !String::from_utf8_lossy(&contents).contains(DECOY_VALUE),
            "{} holds the plaintext",
            path.display()
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
