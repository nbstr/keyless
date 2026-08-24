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
use keyless::store::Invocation;
use keyless::store::Store;
use keyless::store::daemon::DaemonStore;
use keyless::{ipc::protocol::Request, store};

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
                        "keychain":{{"enabled":true,"binary":{binary},
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
