//! Which of the daemon's own stores answers a name, and what it does with a
//! name nobody declared.

// The daemon is macOS-only (`src/lib.rs`), so this whole file is. On any other
// platform the crate below compiles to nothing and the binary reports 0 tests —
// ABSENT rather than ignored, which is why CI's `ignored == 15` assertion is
// unchanged and still means "the Proton live suite, and nothing else".
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use keyless::State;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::daemon::config::DaemonConfig;
use keyless::store;
use keyless::store::Invocation;
use keyless::store::Store;
use keyless::store::daemon::DaemonStore;

use support::audit_rows::decision_for;
use support::{
    DECOY_VALUE, client_config, daemon_config, policy_allowing_self, scratch, short_socket_path,
    slow_store_stub, start_daemon, witness, witnessed, write_secrets,
};

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
/// What [`through_the_daemon`] reports as seen when the child never started.
const NEVER_STARTED: &str = "<never started>";

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
    let seen = if marker.exists() {
        witnessed(&marker)
    } else {
        NEVER_STARTED.to_owned()
    };
    (
        outcome.state,
        seen,
        String::from_utf8_lossy(&notes).into_owned(),
    )
}

#[test]
fn a_name_the_daemon_does_not_hold_is_refused_as_absent_rather_than_undeclared() {
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

    assert_eq!(state, State::Refused);
    assert_eq!(seen, NEVER_STARTED);
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
