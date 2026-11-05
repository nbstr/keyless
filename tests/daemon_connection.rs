//! The daemon's connections and its audit log under load: pings, concurrent
//! sessions, clients that vanish, slow lookups and a held audit lock.

// The daemon is macOS-only (`src/lib.rs`), so this whole file is. On any other
// platform the crate below compiles to nothing and the binary reports 0 tests —
// ABSENT rather than ignored, which is why CI's `ignored == 15` assertion is
// unchanged and still means "the Proton live suite, and nothing else".
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::sync::Barrier;
use std::time::Duration;

use keyless::audit::AuditLog;
use keyless::ipc::client::{Client, ClientError};
use keyless::ipc::protocol::{Reply, Request};
use keyless::store::Store;
use keyless::store::daemon::DaemonStore;

use support::audit_rows::rows_for;
use support::keychain::slow_after_first_store_stub;
use support::{
    DECOY_VALUE, daemon_config, policy_allowing_self, scratch, slow_store_stub, start_daemon,
    write_secrets,
};

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

#[test]
fn a_run_survives_the_audit_lock_being_held_past_the_silence_deadline() {
    // Five degrades in 36 hours on a live install, each followed by the
    // daemon's own `allow` row for the same name, stamped 0–14 seconds after
    // the client had already given up. The daemon heartbeats only while its
    // lookup thread runs; everything after the lookup — the audit append under
    // the log's exclusive lock, the anchor's full fsync — is silence, and a
    // silence longer than the client's deadline is what the client calls a
    // wedge. This holds that lock from outside for longer than the deadline,
    // which is what any other connection thread inside a slow append does.
    let dir = scratch("daemon-audit-lock-held");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let silence = Duration::from_secs(1);
    let client = Client::new(running.socket().to_path_buf(), silence);

    // The control: nothing holds the lock, and the value is back well inside
    // the deadline. A red below is then about the lock and nothing else.
    match client.request(&Request::resolve("DECOY")) {
        Ok(Reply::Value(secret)) => assert_eq!(secret.expose(), DECOY_VALUE),
        other => panic!("an unheld log must answer at once, got {other:?}"),
    }

    let hold = Duration::from_millis(2_500);
    let log = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(&config.audit)
        .expect("open the daemon's audit log");
    log.lock().expect("hold the audit log's lock");
    let holder = std::thread::spawn(move || {
        std::thread::sleep(hold);
        log.unlock().expect("release the audit log's lock");
    });

    let started = std::time::Instant::now();
    let reply = client.request(&Request::resolve("DECOY"));
    holder.join().expect("the lock holder");
    assert!(
        started.elapsed() >= hold - Duration::from_millis(100),
        "the reply came back before the lock was released, so the append was never \
         behind it and this proves nothing: {:?}",
        started.elapsed()
    );
    match reply {
        Ok(Reply::Value(secret)) => assert_eq!(secret.expose(), DECOY_VALUE),
        other => panic!(
            "a daemon that has the value and is waiting on its own log must keep the \
             client waiting with it, got {other:?}"
        ),
    }

    drop(running);
    let rows = std::fs::read_to_string(&config.audit).expect("read the audit log");
    let named = rows_for(&rows, "DECOY");
    assert_eq!(named.len(), 2, "rows naming DECOY in:\n{rows}");
    assert_eq!(
        named[1]["decision"].as_str(),
        Some("allow"),
        "{:?}",
        named[1]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn four_callers_polling_a_stale_served_name_never_degrade() {
    // The shape the live degrades had: several sessions asking for one name
    // the daemon already holds, each answered from its stale window while a
    // slow refresh runs behind them, each answer earning an audit row under
    // the log's one lock. Every reply here is a value the daemon has in
    // memory; a degrade can only be the daemon going silent on the way to
    // saying so.
    //
    // The arithmetic that bounds it: past freshness a read joins the refresh
    // in flight and waits its one-second grace before settling for the older
    // value — the stub sleeps three seconds, so a read that waits spends the
    // grace in full — and the four threads spend their graces concurrently,
    // so ten reads a thread is at most ten seconds, plus the warm-up and the
    // sleep that puts the entry past freshness. Measured at under five: each
    // landed refresh opens a one-second fresh window that answers from memory.
    let dir = scratch("daemon-stale-polling");
    let mut config = daemon_config(&dir);
    config.stores.file.enabled = false;
    config.stores.keychain.enabled = true;
    config.stores.keychain.binary = slow_after_first_store_stub(&dir, DECOY_VALUE, 3).into();
    config.cache_ttl_seconds = 1;
    config.cache_stale_seconds = 60;

    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(3));

    let warmed = store
        .resolve("POLLED")
        .expect("resolve")
        .expect("the first read warms the cache");
    assert_eq!(warmed.expose(), DECOY_VALUE);
    std::thread::sleep(Duration::from_millis(1200));

    const CALLERS: usize = 4;
    const READS_PER_CALLER: usize = 10;
    let gate = Barrier::new(CALLERS);
    std::thread::scope(|scope| {
        for caller in 0..CALLERS {
            let store = &store;
            let gate = &gate;
            scope.spawn(move || {
                gate.wait();
                for read in 0..READS_PER_CALLER {
                    match store.resolve("POLLED") {
                        Ok(Some(value)) => assert_eq!(value.expose(), DECOY_VALUE),
                        other => panic!(
                            "caller {caller}, read {read}: a name the daemon holds must \
                             never degrade, got {other:?}"
                        ),
                    }
                }
            });
        }
    });

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
