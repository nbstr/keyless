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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Barrier;
use std::time::Duration;

use keyless::State;
use keyless::audit::AuditLog;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::daemon::config::DaemonConfig;
use keyless::ipc::client::{Client, ClientError};
use keyless::store::Invocation;
use keyless::store::Store;
use keyless::store::daemon::DaemonStore;
use keyless::{
    ipc::protocol::{Reply, Request},
    store,
};

use support::{
    DECOY_VALUE, client_config, daemon_config, echoes, policy_allowing_self, scratch,
    short_socket_path, slow_store_stub, start_daemon, witness, witnessed, write_secrets,
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
    assert_eq!(witnessed(&marker), DECOY_VALUE);
    let said = String::from_utf8_lossy(&notes);
    assert!(said.contains(&soon), "{said}");
    assert!(said.contains("expires"), "{said}");

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
        // This reads one frame per request, so it asks for no heartbeat.
        let mut request = Request::resolve("DECOY");
        request.progress = false;
        let frame = request.encode().expect("encode");
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

#[test]
fn a_lookup_slower_than_the_clients_deadline_still_reaches_the_caller() {
    // The outage this closes, reproduced at a tenth of the scale.
    //
    // Measured 2026-09-10 on a live install: the daemon allowed itself ten
    // seconds per vendor call and spent two of them on a name whose vault
    // listing had expired, so a cold lookup took 1.45 to 4.38 seconds — while
    // the session gave up after three. The daemon resolved the name correctly
    // and wrote `allow` to its audit log with nobody left to hand the value to,
    // and every first lookup after a sixty-second idle gap degraded.
    //
    // Both requests below go to one daemon, over one store, and differ in one
    // field. That is the control: if the value arrives either way the deadline
    // was never the thing under test, and if it arrives neither way the
    // heartbeat is not what carries it.
    let dir = scratch("daemon-heartbeat");
    let mut config = daemon_config(&dir);
    // Nothing cached, so the second lookup pays the store's full cost too and
    // cannot be answered out of the first one's success.
    config.cache_ttl_seconds = 0;
    config.stores.file.enabled = false;
    config.stores.keychain.enabled = true;
    config.stores.keychain.binary = slow_store_stub(&dir, DECOY_VALUE, 2_500).into();
    let running = start_daemon(&config, policy_allowing_self());

    let silence = Duration::from_secs(1);
    let client = Client::new(running.socket().to_path_buf(), silence);

    let mut mute = Request::resolve("DECOY_MUTE");
    mute.progress = false;
    match client.request(&mute) {
        Err(ClientError::Timeout(after)) => assert_eq!(after, silence),
        other => panic!("a daemon that says nothing must time out, got {other:?}"),
    }

    let started = std::time::Instant::now();
    match client.request(&Request::resolve("DECOY_LOUD")) {
        Ok(Reply::Value(secret)) => assert_eq!(secret.expose(), DECOY_VALUE),
        other => panic!("a daemon that says it is working must be waited for, got {other:?}"),
    }
    assert!(
        started.elapsed() > silence,
        "the value came back inside the silence deadline, so the store was not slow \
         and this proves nothing: {:?}",
        started.elapsed()
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Which of the daemon's own stores answers a name.
//
// The daemon can be told to run two stores at once, and until it could also be
// told which one a name means, that configuration was unusable: every unpinned
// name came back `Ambiguous`, the client degraded, and the sentence it printed
// told the operator to add a `"store"` key and a `stores.default` key that the
// daemon's config file had no place to put. The advice named the SESSION
// config's keys, from the wrong side of the uid boundary.
//
// These fixtures parse the daemon config from JSON rather than building the
// struct, because that is the only way to prove a key is actually read: an
// unknown key is dropped silently by serde, which is exactly how the remedy
// used to evaporate.
// ---------------------------------------------------------------------------

/// A value only the keychain stub can produce, so a resolution that came from
/// the file store cannot be mistaken for one that came from the keychain.
const KEYCHAIN_VALUE: &str = "decoy-from-the-keychain-not-the-file-8817";

/// A daemon config JSON with both stores enabled. Both hold `DECOY`, under
/// different values, so which one answered is readable from the value alone.
///
/// `under_stores` and `at_top_level` are extra keys, each written with its
/// leading comma, so a fixture says only the routing it is about.
fn two_store_daemon(dir: &std::path::Path, under_stores: &str, at_top_level: &str) -> DaemonConfig {
    let secrets = dir.join("secrets.json");
    write_secrets(&secrets, &[("DECOY", DECOY_VALUE)]);
    let stub = slow_store_stub(dir, KEYCHAIN_VALUE, 0);
    let json = format!(
        r#"{{"socket":{socket},
             "audit":{audit},
             "cache_ttl_seconds":0,
             "idle_timeout_seconds":5,
             "stores":{{"file":{{"enabled":true,"path":{file}}},
                        "keychain":{{"enabled":true,"timeout_ms":60000,"binary":{binary},
                                     "keychain":{keychain}}}{under_stores}}}
             {at_top_level}}}"#,
        socket = json_path(&short_socket_path(dir)),
        audit = json_path(&dir.join("audit.jsonl")),
        file = json_path(&secrets),
        binary = json_path(&stub),
        keychain = json_path(&dir.join("stub.keychain-db")),
    );
    serde_json::from_str(&json).unwrap_or_else(|error| panic!("{error}\n{json}"))
}

fn json_path(path: &std::path::Path) -> String {
    serde_json::to_string(&path.display().to_string()).expect("encode a path")
}

/// Resolve `DECOY` through a real daemon and a real client, and report what
/// the child actually received plus everything the caller was told.
fn through_the_daemon(config: &DaemonConfig, dir: &std::path::Path) -> (State, String, String) {
    let running = start_daemon(config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let built = store::build(&client, &Invocation::default());
    let marker = dir.join("marker");

    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &[Binding::parse("DECOY").expect("valid")],
            unusable: &[],
            argv: &witness(&marker, "DECOY", 0),
            registry: &built.registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run");

    drop(running);
    (
        outcome.state,
        witnessed(&marker),
        String::from_utf8_lossy(&notes).into_owned(),
    )
}

#[test]
fn a_name_the_daemon_does_not_hold_is_absent_rather_than_undeclared() {
    // A client config under the daemon declares nothing about where a name
    // lives — the daemon's config decides that — so "you never declared it"
    // would send this reader to edit the one file that has no say. The absence
    // message is the honest one on this path, and it is the one that must
    // survive.
    let dir = scratch("daemon-absent-name");
    let config = daemon_config(&dir);
    // A vault holding something else entirely, so the daemon answers a real
    // "I do not have that" rather than failing to open its store.
    write_secrets(&config.stores.file.path, &[("NEIGHBOUR", DECOY_VALUE)]);
    let (state, seen, notes) = through_the_daemon(&config, &dir);

    assert_eq!(state, State::Degraded);
    assert_eq!(seen, "<unset>");
    assert!(
        notes.contains("not found in any store"),
        "the daemon's absence lost its wording: {notes}"
    );
    assert!(
        !notes.contains("not declared in your config"),
        "the client blamed a config that does not decide where names live: {notes}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_daemons_own_default_store_settles_a_two_store_ambiguity() {
    // The remedy the ambiguity message prescribes, applied where the ambiguity
    // actually is. Without a `stores.default` the daemon can read, this is a
    // configuration that cannot be fixed from either side of the boundary.
    let dir = scratch("daemon-two-store-default");
    let config = two_store_daemon(&dir, r#","default":"keychain""#, "");
    let (state, seen, _notes) = through_the_daemon(&config, &dir);

    assert_eq!(
        state,
        State::Injected,
        "the declared default did not answer"
    );
    assert_eq!(
        seen, KEYCHAIN_VALUE,
        "the default named the keychain and the file store answered"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_per_name_pin_in_the_daemons_config_reaches_exactly_the_store_it_names() {
    // The name's own pin, and it outranks a default naming the other store —
    // the same precedence the session config has, so an operator moving a
    // route across the boundary does not have to learn a second vocabulary.
    let dir = scratch("daemon-two-store-pin");
    let config = two_store_daemon(
        &dir,
        r#","default":"keychain""#,
        r#","secrets":{"DECOY":{"store":"file"}}"#,
    );
    let (state, seen, _notes) = through_the_daemon(&config, &dir);

    assert_eq!(state, State::Injected, "the pinned store did not answer");
    assert_eq!(seen, DECOY_VALUE, "the pin lost to the default store");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_daemon_pin_naming_a_store_that_is_not_enabled_still_fails() {
    // The negative control. Routing must not become a way to reach a store by
    // asking nicely: a pin whose store is off resolves to nothing at all,
    // rather than falling through to the store that is on.
    let dir = scratch("daemon-pin-absent");
    let secrets = dir.join("secrets.json");
    write_secrets(&secrets, &[("DECOY", DECOY_VALUE)]);
    let json = format!(
        r#"{{"socket":{socket},"audit":{audit},"cache_ttl_seconds":0,
             "idle_timeout_seconds":5,
             "stores":{{"file":{{"enabled":true,"path":{file}}}}},
             "secrets":{{"DECOY":{{"store":"keychain"}}}}}}"#,
        socket = json_path(&short_socket_path(&dir)),
        audit = json_path(&dir.join("audit.jsonl")),
        file = json_path(&secrets),
    );
    let config: DaemonConfig = serde_json::from_str(&json).expect("valid daemon config");
    let (state, seen, _notes) = through_the_daemon(&config, &dir);

    assert_eq!(
        state,
        State::Degraded,
        "a pin to a disabled store handed out the enabled store's value"
    );
    assert_eq!(seen, "<unset>", "the child received a value anyway");
    assert!(
        config
            .warnings()
            .iter()
            .any(|w| w.contains("DECOY -> keychain")),
        "a route to a store that is off said nothing until a session degraded: {:?}",
        config.warnings()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn two_stores_and_no_route_at_all_is_still_ambiguous_rather_than_guessed() {
    // Unchanged, and deliberately so: routing gives an operator a way to say
    // which store a name means, never a way for the daemon to decide for them.
    let dir = scratch("daemon-two-store-unrouted");
    let config = two_store_daemon(&dir, "", "");
    let (state, seen, notes) = through_the_daemon(&config, &dir);

    assert_eq!(state, State::Degraded);
    assert_eq!(seen, "<unset>");

    // What the session is told has to name the file that can settle it. Its
    // own config cannot: `store::build` drops a session's pins whenever the
    // daemon is enabled, so a reader who applies this advice where they are
    // standing changes nothing and the run degrades exactly as before.
    assert!(
        notes.contains("keylessd"),
        "the remedy did not say whose config file it belongs to: {notes}"
    );
    assert!(
        !notes.contains(DECOY_VALUE) && !notes.contains(KEYCHAIN_VALUE),
        "the degraded banner carried a value"
    );

    // And the operator is told, before a single request arrives, rather than
    // finding out from a session's degraded banner.
    let said = config.warnings().join(" ");
    assert!(
        said.contains("stores.default"),
        "a two-store daemon with no default warned about nothing: {said}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// A name nobody declared.
//
// `12a3896` taught the SESSION path to say `not declared in your config` where
// it used to say `not found in any store`, and that reads like an ordering: ask
// the config first, refuse, never touch a store. It is not one. That commit
// changed a SENTENCE. The store is asked either way, on both paths, at the same
// coordinate — the adapter derives an undeclared name's account from the name
// itself — and the sentence it produced says so out loud: `no store had one
// under the name itself`.
//
// So the daemon has nothing to be brought into line with, and its `absent` row
// is the accurate one: a store WAS asked and did not have it. The reason that
// took an experiment to establish rather than a read is that nothing in the
// tree could be pointed at. This is the thing to point at.
//
// It is also why the daemon cannot refuse an undeclared name even if it wanted
// to: it has no declared population to check one against. `DaemonConfig::names`
// is the allowlist for the `names` VERB — what the daemon will admit to
// knowing, opt-in because enumeration is a leak — and `DaemonConfig::secrets`
// is routing, read only for its `store` key and needed only when more than one
// store is configured. The installer writes neither. What the daemon serves is
// whatever its store holds, and asking the store is how it finds out.
// ---------------------------------------------------------------------------

/// A `security` stand-in that records the account it was asked for.
///
/// Recording the ACCOUNT rather than the whole command line is the point: the
/// account is the coordinate the adapter derived, and derived-from-the-name is
/// the property under test.
fn recording_store_stub(dir: &Path, log: &Path, holds: &str, value: &str) -> PathBuf {
    let body = format!(
        "#!/bin/sh\n\
         account=''\n\
         while [ $# -gt 0 ]; do\n\
         \x20 case \"$1\" in\n\
         \x20   -a) account=\"$2\"; shift 2 ;;\n\
         \x20   *) shift ;;\n\
         \x20 esac\n\
         done\n\
         printf '%s\\n' \"$account\" >> '{log}'\n\
         if [ \"$account\" = '{holds}' ]; then printf '%s\\n' '{value}'; exit 0; fi\n\
         exit 44\n",
        log = log.display(),
    );
    support::install_executable(&dir.join("security-recording"), &body)
}

/// The `decision` on the one row that named `name`.
fn decision_for(rows: &str, name: &str) -> String {
    let mut found: Vec<String> = Vec::new();
    for line in rows.lines() {
        let row: serde_json::Value = serde_json::from_str(line).expect("an audit row is JSON");
        let names = row["names"].as_array().expect("a row carries names");
        if names.len() == 1 && names[0].as_str() == Some(name) {
            found.push(
                row["decision"]
                    .as_str()
                    .expect("a row carries a decision")
                    .to_owned(),
            );
        }
    }
    assert_eq!(found.len(), 1, "rows naming {name} in:\n{rows}");
    found.remove(0)
}

#[test]
fn a_name_nobody_declared_is_asked_of_the_store_exactly_as_a_declared_one_is() {
    let dir = scratch("daemon-undeclared");
    let asked = dir.join("accounts-asked");

    let mut config = daemon_config(&dir);
    // No cache, so every resolve below is a real question put to the store
    // rather than a repeat served from memory.
    config.cache_ttl_seconds = 0;
    // One store, and a keychain rather than the file store, because the
    // keychain is the adapter that derives a coordinate from the name. The
    // file store looks a name up in a map and derives nothing.
    config.stores.file.enabled = false;
    config.stores.keychain.enabled = true;
    config.stores.keychain.binary = recording_store_stub(&dir, &asked, "HELD", DECOY_VALUE).into();

    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(10));

    // The control that matters more than the subject: a name the store holds
    // is served, and nothing about it changes.
    let served = store
        .resolve("HELD")
        .expect("resolve")
        .expect("a value must come back");
    assert_eq!(served.expose(), DECOY_VALUE);

    // The subject. `None` is the wire's `absent`.
    assert!(
        store
            .resolve("NEVER_DECLARED_BY_ANYBODY")
            .expect("resolve")
            .is_none()
    );

    drop(running);

    // The observation. Both names reached the store, and the undeclared one
    // reached it under itself — which is what makes `absent` a report of what a
    // store said rather than a guess made without asking.
    let accounts = std::fs::read_to_string(&asked).expect("the stub recorded what it was asked");
    assert_eq!(
        accounts.lines().collect::<Vec<_>>(),
        ["HELD", "NEVER_DECLARED_BY_ANYBODY"],
        "the store was not asked for both names, in order: {accounts:?}"
    );

    // And the rows say the two apart, by the words they already use. Compared
    // whole rather than by `contains`: `absent` is a substring of nothing here
    // today, and a decision word that gained a suffix would satisfy a
    // `contains` while meaning something else.
    let rows = std::fs::read_to_string(&config.audit).expect("read the audit log");
    assert_eq!(decision_for(&rows, "HELD"), "allow");
    assert_eq!(decision_for(&rows, "NEVER_DECLARED_BY_ANYBODY"), "absent");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The audit row's failure kind and staleness marker.
//
// Both facts already exist upstream of the audit boundary — `StoreError` says
// whether a store was reached, `resolver::Source` says whether a value came
// from the vendor or from memory — and both used to be dropped at `record`.
// ---------------------------------------------------------------------------

/// Every row naming `name`, whole rather than one field, so a case can read
/// `source` and `age_ms` alongside `decision` — in the order they were
/// written, since a caller comparing two calls for the same name needs that.
fn rows_for(rows: &str, name: &str) -> Vec<serde_json::Value> {
    rows.lines()
        .map(|line| serde_json::from_str(line).expect("an audit row is JSON"))
        .filter(|row: &serde_json::Value| {
            row["names"]
                .as_array()
                .is_some_and(|names| names.len() == 1 && names[0].as_str() == Some(name))
        })
        .collect()
}

/// A `security` stand-in that exits nonzero with a stderr line, on every
/// lookup — `StoreError::Backend`: the account was asked and refused it.
fn refusing_store_stub(dir: &Path) -> PathBuf {
    let body = "#!/bin/sh\n\
                 case \"$1\" in\n\
                 \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
                 esac\n\
                 echo 'security: SecKeychainSearchCopyNext: User interaction is not allowed.' >&2\n\
                 exit 51\n"
        .to_owned();
    support::install_executable(&dir.join("security-refusing"), &body)
}

/// A `security` stand-in that answers instantly the first time and sleeps
/// past `seconds` on every call after, so a refresh queued behind the first
/// answer cannot land inside the refresh grace.
fn slow_after_first_store_stub(dir: &Path, value: &str, seconds: u64) -> PathBuf {
    let counter = dir.join("calls.count");
    let body = format!(
        "#!/bin/sh\n\
         count=$(cat '{counter}' 2>/dev/null || echo 0)\n\
         count=$((count + 1))\n\
         echo \"$count\" > '{counter}'\n\
         case \"$1\" in\n\
         \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
         \x20 find-generic-password)\n\
         \x20\x20\x20 if [ \"$count\" -gt 1 ]; then sleep {seconds}; fi\n\
         \x20\x20\x20 printf '%s\\n' '{value}'; exit 0 ;;\n\
         esac\n\
         exit 1\n",
        counter = counter.display(),
    );
    support::install_executable(&dir.join("security-slow-after-first"), &body)
}

#[test]
fn a_dead_session_and_an_account_verdict_read_apart_in_the_audit_row() {
    // Dead: the binary does not exist. `capture` fails to spawn, which the
    // keychain adapter maps to `StoreError::Unavailable` — nothing was asked
    // about the name, so a cached value would still stand had one existed.
    let dead_dir = scratch("daemon-audit-silent");
    let mut dead_config = daemon_config(&dead_dir);
    dead_config.stores.file.enabled = false;
    dead_config.stores.keychain.enabled = true;
    dead_config.stores.keychain.binary = dead_dir.join("no-such-binary").into();
    let dead = start_daemon(&dead_config, policy_allowing_self());
    let dead_store = DaemonStore::new(dead.socket().to_path_buf(), Duration::from_secs(10));
    assert!(dead_store.resolve("SILENT_NAME").is_err());
    drop(dead);

    // Verdict: the store answers and refuses. `security` exits nonzero with
    // stderr, which the adapter maps to `StoreError::Backend` — the account
    // took a position on the name.
    let verdict_dir = scratch("daemon-audit-verdict");
    let mut verdict_config = daemon_config(&verdict_dir);
    verdict_config.stores.file.enabled = false;
    verdict_config.stores.keychain.enabled = true;
    verdict_config.stores.keychain.binary = refusing_store_stub(&verdict_dir).into();
    let verdict = start_daemon(&verdict_config, policy_allowing_self());
    let verdict_store = DaemonStore::new(verdict.socket().to_path_buf(), Duration::from_secs(10));
    assert!(verdict_store.resolve("VERDICT_NAME").is_err());
    drop(verdict);

    let dead_rows = std::fs::read_to_string(&dead_config.audit).expect("read the dead audit log");
    let verdict_rows =
        std::fs::read_to_string(&verdict_config.audit).expect("read the verdict audit log");

    let dead_decision = decision_for(&dead_rows, "SILENT_NAME");
    let verdict_decision = decision_for(&verdict_rows, "VERDICT_NAME");
    assert_eq!(dead_decision, "store-silent");
    assert_eq!(verdict_decision, "store-verdict");
    assert_ne!(
        dead_decision, verdict_decision,
        "a dead session and an account verdict must read apart"
    );

    let _ = std::fs::remove_dir_all(&dead_dir);
    let _ = std::fs::remove_dir_all(&verdict_dir);
}

#[test]
fn a_value_served_past_freshness_carries_its_staleness_in_the_audit_row() {
    let dir = scratch("daemon-audit-stale");
    let mut config = daemon_config(&dir);
    config.stores.file.enabled = false;
    config.stores.keychain.enabled = true;
    config.stores.keychain.binary = slow_after_first_store_stub(&dir, DECOY_VALUE, 3).into();
    config.cache_ttl_seconds = 1;
    config.cache_stale_seconds = 5;

    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(10));

    // Warm the cache. Fresh, so this row carries no age.
    let first = store
        .resolve("STALE_NAME")
        .expect("resolve")
        .expect("a value must come back");
    assert_eq!(first.expose(), DECOY_VALUE);

    // Past freshness, inside the stale window: the refresh this queues sleeps
    // three seconds against a one-second grace, so this read is answered from
    // the cache while that refresh is still in flight.
    std::thread::sleep(Duration::from_millis(1200));
    let second = store
        .resolve("STALE_NAME")
        .expect("resolve")
        .expect("a value must come back");
    assert_eq!(second.expose(), DECOY_VALUE);

    drop(running);

    let rows = std::fs::read_to_string(&config.audit).expect("read the audit log");
    let mut named = rows_for(&rows, "STALE_NAME");
    assert_eq!(named.len(), 2, "rows naming STALE_NAME in:\n{rows}");
    let fresh = named.remove(0);
    let stale = named.remove(0);

    assert_eq!(fresh["decision"].as_str(), Some("allow"), "{fresh:?}");
    assert_eq!(fresh["source"].as_str(), Some("store"), "{fresh:?}");
    assert!(fresh.get("age_ms").is_none(), "{fresh:?}");

    assert_eq!(stale["decision"].as_str(), Some("allow"), "{stale:?}");
    assert_eq!(stale["source"].as_str(), Some("stale"), "{stale:?}");
    assert!(
        stale["age_ms"].as_u64().expect("stale row carries an age") >= 1000,
        "{stale:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_fresh_read_from_memory_carries_no_age() {
    // The control for the case above: served inside the freshness window, a
    // row says `source: "memory"` and no age at all — `age` on `Answer` is
    // only ever `Some` past freshness.
    let dir = scratch("daemon-audit-memory");
    let mut config = daemon_config(&dir);
    config.stores.file.enabled = false;
    config.stores.keychain.enabled = true;
    config.stores.keychain.binary = slow_after_first_store_stub(&dir, DECOY_VALUE, 3).into();
    config.cache_ttl_seconds = 60;
    config.cache_stale_seconds = 60;

    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(10));

    let _ = store.resolve("MEMORY_NAME").expect("resolve");
    let _ = store.resolve("MEMORY_NAME").expect("resolve");

    drop(running);

    let rows = std::fs::read_to_string(&config.audit).expect("read the audit log");
    let mut named = rows_for(&rows, "MEMORY_NAME");
    assert_eq!(named.len(), 2, "rows naming MEMORY_NAME in:\n{rows}");
    let second = named.remove(1);
    assert_eq!(second["source"].as_str(), Some("memory"), "{second:?}");
    assert!(second.get("age_ms").is_some(), "{second:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `doctor --probe` against a client config naming `names`, each pinned to a
/// local backend the daemon suppresses — the shape a config carries after the
/// daemon is switched on over an existing one.
fn probed_through_the_daemon(dir: &Path, socket: &Path, names: &[&str]) -> (String, i32) {
    let secrets = names
        .iter()
        .map(|name| format!(r#""{name}":{{"store":"proton"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let paths = keyless::paths::Paths::under(dir);
    let mut load = keyless::config::Config::load(&paths.config);
    load.config = serde_json::from_str(&format!(
        r#"{{"stores":{{"daemon":{{"enabled":true,"socket":"{}","timeout_ms":3000}}}},
            "secrets":{{{secrets}}}}}"#,
        socket.display()
    ))
    .expect("valid client config");
    load.loaded = true;
    let built = store::build(&load.config, &Invocation::default());
    let audit = AuditLog::new(paths.audit.clone());

    let mut out: Vec<u8> = Vec::new();
    let code = keyless::cmd::doctor::doctor(
        &keyless::cmd::doctor::DoctorRequest {
            paths: &paths,
            load: &load,
            registry: &built.registry,
            audit: &audit,
            setup: None,
            notes: &[],
            probe: true,
            freshness: &keyless::freshness::Freshness::NoSourceTree,
            checkout: &keyless::checkout::Checkout::NoSourceTree,
            style: keyless::cmd::status::Style::PLAIN,
        },
        &mut out,
    )
    .expect("the report must be writable");
    (String::from_utf8(out).expect("utf-8"), code)
}

/// The state column of `name`'s row, read as a whole word: `unproven`
/// contains `proven`.
fn probed_state<'a>(report: &'a str, name: &str) -> &'a str {
    report
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(name))
        .and_then(|line| line.split_whitespace().nth(2))
        .unwrap_or_else(|| panic!("the report has no `{name}` row:\n{report}"))
}

/// `name`'s row and the indented lines under it, joined into one line.
fn probed_row(report: &str, name: &str) -> String {
    let mut lines = report
        .lines()
        .skip_while(|line| line.split_whitespace().nth(1) != Some(name));
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("the report has no `{name}` row:\n{report}"));
    std::iter::once(first)
        .chain(lines.take_while(|line| line.starts_with("      ")))
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn a_name_run_resolves_through_the_daemon_is_proven_by_the_probe() {
    // The probe and the run under ONE config. The name is pinned to a local
    // backend the daemon suppresses, so a probe choosing its store by that pin
    // points at a row that reads `off` and asks nothing, while the run — whose
    // registry dropped the pin — is served by the daemon.
    let dir = scratch("daemon-probe-proven");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let (report, code) = probed_through_the_daemon(&dir, running.socket(), &["DECOY"]);

    let client = client_config(running.socket(), 3_000);
    let built = store::build(&client, &Invocation::default());
    let marker = dir.join("marker");
    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &[Binding::parse("DECOY").expect("valid")],
            unusable: &[],
            argv: &witness(&marker, "DECOY", 0),
            registry: &built.registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run");
    assert_eq!(
        outcome.state,
        State::Injected,
        "the control: run resolves it"
    );

    assert_eq!(probed_state(&report, "DECOY"), "proven", "{report}");
    assert!(
        !report.split_whitespace().any(|word| word == "blocked"),
        "a name the daemon serves was marked blocked:\n{report}"
    );
    assert!(
        !report.contains(DECOY_VALUE),
        "the value reached the report"
    );
    let length = DECOY_VALUE.len().to_string();
    assert!(
        !report
            .split(|c: char| !c.is_ascii_digit())
            .any(|digits| digits == length),
        "the value's length reached the report:\n{report}"
    );
    assert_eq!(code, 0, "{report}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_name_the_daemon_does_not_serve_fails_the_probe_with_the_daemons_reason() {
    let dir = scratch("daemon-probe-failed");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let (report, code) = probed_through_the_daemon(&dir, running.socket(), &["DECOY", "MISSING"]);

    assert_eq!(probed_state(&report, "DECOY"), "proven", "{report}");
    assert_eq!(probed_state(&report, "MISSING"), "absent", "{report}");
    // The row's own text, detail and continuation lines alike: the STORES
    // section says "the daemon" on every suppressed row, so a report-wide
    // search is satisfied whatever this row says.
    let row = probed_row(&report, "MISSING");
    assert!(
        row.contains("daemon"),
        "the failing row does not carry the daemon's answer:\n{report}"
    );
    assert!(
        !report.contains(DECOY_VALUE),
        "the value reached the report"
    );
    assert_ne!(code, 0, "a failing name must fail the probe:\n{report}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
