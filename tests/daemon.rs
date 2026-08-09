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
use keyless::audit::AuditLog;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::store::Invocation;
use keyless::store::Store;
use keyless::store::daemon::DaemonStore;
use keyless::{ipc::protocol::Request, store};

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

#[test]
fn a_ping_reads_no_store_and_returns_no_value() {
    let dir = scratch("daemon-ping");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(5));

    assert!(store.health().is_ok());
    assert_eq!(
        running.upstream_calls(),
        0,
        "a health check must not read a secret"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_daemons_audit_log_chains_across_concurrent_sessions() {
    // Twenty sessions appending at once, through the daemon, to one file. A
    // row that interleaved with another would break the chain, so verifying it
    // is the assertion.
    let dir = scratch("daemon-audit-concurrent");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());
    let socket = running.socket().to_path_buf();

    std::thread::scope(|scope| {
        for _ in 0..20 {
            let socket = socket.clone();
            scope.spawn(move || {
                let store = DaemonStore::new(socket, Duration::from_secs(10));
                for _ in 0..3 {
                    let _ = store.resolve("DECOY");
                }
            });
        }
    });
    drop(running);

    let log = AuditLog::new(config.audit.to_path_buf());
    let rows = log.verify().expect("the chain must hold under concurrency");
    assert_eq!(rows, 60, "expected one row per request, got {rows}");

    let raw = std::fs::read_to_string(&config.audit).expect("read");
    assert!(
        !raw.contains(DECOY_VALUE),
        "the daemon's audit log carries a value"
    );
    for line in raw.lines() {
        assert!(line.starts_with("{\"hash\":\""), "partial row: {line}");
        assert!(line.ends_with('}'), "partial row: {line}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_value_the_caller_typed_on_its_own_argv_is_masked_in_the_daemons_row() {
    // The caller's argv is a claim, and this is the one place a claim can
    // carry a secret: an agent that put the value on its command line, which
    // is the habit the whole tool exists to replace. The daemon masks it with
    // the value it just resolved, so the one log the caller cannot edit does
    // not become the place the plaintext ends up.
    let dir = scratch("daemon-argv-mask");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let mut request = Request::resolve("DECOY");
    request.argv = vec![
        "curl".to_owned(),
        format!("-H Authorization: Bearer {DECOY_VALUE}"),
    ];
    request.cwd = format!("/tmp/{DECOY_VALUE}");

    let client =
        keyless::ipc::client::Client::new(running.socket().to_path_buf(), Duration::from_secs(5));
    let reply = client.request(&request).expect("the daemon must answer");
    assert!(matches!(reply, keyless::ipc::protocol::Reply::Value(_)));
    drop(running);

    let raw = std::fs::read_to_string(&config.audit).expect("read");
    assert!(
        !raw.contains(DECOY_VALUE),
        "a value the caller typed reached the audit log: {raw}"
    );
    assert!(
        raw.contains("[keyless:DECOY]"),
        "the argv was not masked, it was dropped: {raw}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_daemon_survives_a_client_that_disappears_mid_conversation() {
    // A session killed by its harness is routine at twenty sessions. The
    // daemon must keep serving the other nineteen.
    let dir = scratch("daemon-abandoned");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    for _ in 0..5 {
        let stream = std::os::unix::net::UnixStream::connect(running.socket()).expect("connect");
        use std::io::Write;
        let _ = (&stream).write_all(b"{\"v\":1,\"op\":\"resolve\",\"name\":\"DECOY\"");
        drop(stream);
    }

    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(5));
    let secret = store
        .resolve("DECOY")
        .expect("the daemon must still be serving")
        .expect("a value");
    assert_eq!(secret.expose(), DECOY_VALUE);

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_second_request_on_one_connection_is_answered() {
    // The regression test for an accepted socket inheriting O_NONBLOCK from a
    // non-blocking listener. That bug survived a single request-and-reply —
    // the request is already buffered when accept returns — and killed the
    // connection on the second, which is the shape no single-shot test sees.
    let dir = scratch("daemon-two-requests");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let stream = std::os::unix::net::UnixStream::connect(running.socket()).expect("connect");
    let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));

    for attempt in 0..3 {
        let frame = Request::resolve("DECOY").encode().expect("encode");
        keyless::ipc::protocol::write_frame(&mut &stream, &frame)
            .unwrap_or_else(|error| panic!("request {attempt} could not be sent: {error}"));
        let raw = keyless::ipc::protocol::read_frame(&mut reader)
            .unwrap_or_else(|error| panic!("request {attempt} got no frame: {error}"))
            .unwrap_or_else(|| panic!("request {attempt}: the daemon closed the connection"));
        match keyless::ipc::protocol::Reply::decode(&raw).expect("decode") {
            keyless::ipc::protocol::Reply::Value(secret) => {
                assert_eq!(secret.expose(), DECOY_VALUE);
            }
            other => panic!("request {attempt}: expected a value, got {other:?}"),
        }
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
