//! What a session can learn about the names behind the daemon.
//!
//! # The defect this file is the control for
//!
//! `Op::Names` had a handler in the daemon and no sender anywhere in the crate,
//! so `keyless ls` on a machine whose secrets live behind the daemon printed
//! NOTHING — on exactly the installs where the session's own config is empty by
//! design and the listing is the only way to find out a name exists.
//!
//! Every assertion here is about NAMES. A client may learn what the daemon will
//! serve; it may never learn what a store HOLDS, which is why no test below
//! looks for a vault, a title, a field or a count.

#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod catalogue_daemon_support;
mod support;

use keyless::State;
use keyless::store::{Invocation, Registry, Resolution, build};

use catalogue_daemon_support::{
    DECOY, ONE_VAULT, arm, daemon_over, last_decision, listing, listing_of, run_named, settle,
    wait_until_served,
};
use support::backend::Backend;
use support::client::{client_config, write_secrets};
use support::daemon::{daemon_config, policy_allowing_self, start_daemon};
use support::proton::{pause_catalogue_listing, set_catalogue_listing, stub_pass_cli_catalogue};
use support::scratch;

#[test]
fn ls_over_an_empty_session_config_prints_what_the_daemon_serves() {
    let dir = scratch("ls-serves");
    let mut config = daemon_config(&dir);
    config.secrets.insert(
        "DECLARED_BEHIND_THE_DAEMON".to_owned(),
        serde_json::from_str(r#"{"store":"file"}"#).expect("valid"),
    );
    write_secrets(
        &config.stores.file.path,
        &[("DECLARED_BEHIND_THE_DAEMON", "unread-by-this-test")],
    );
    let running = start_daemon(&config, policy_allowing_self());

    // The session's own config declares no secret at all — the case that
    // printed an empty listing before `Request::names` existed.
    let session = client_config(running.socket(), 3_000);
    assert!(
        session.secrets.is_empty(),
        "the fixture must declare nothing"
    );

    let (listed, complaints) = listing(&session);
    assert!(complaints.is_empty(), "{complaints}");

    let row = listed
        .lines()
        .find(|line| line.starts_with("DECLARED_BEHIND_THE_DAEMON"))
        .unwrap_or_else(|| panic!("the daemon's name is not in the listing:\n{listed}"));
    let fields: Vec<&str> = row.split('\t').collect();
    // The four-field contract is load-bearing and unchanged: a daemon row says
    // `daemon` and then says nothing, because location and note would both be
    // things the client is not allowed to learn.
    assert_eq!(fields.len(), 4, "{row}");
    assert_eq!(fields[1], "daemon", "{row}");
    assert_eq!(fields[2], "-", "{row}");
    assert_eq!(fields[3], "-", "{row}");

    // The negative control for the whole file: the value the daemon holds for
    // that name is not in the listing, and neither is the store path.
    assert!(!listed.contains("unread-by-this-test"), "{listed}");
}

#[test]
fn a_daemon_that_cannot_answer_leaves_the_local_listing_standing() {
    // An absent daemon must not turn a listing into an error: a hard failure
    // here reads as an empty vault, which is the one wrong answer.
    let dir = scratch("ls-absent");
    let mut session = client_config(&dir.join("nothing-is-bound-here.sock"), 300);
    session.secrets.insert(
        "LOCAL".to_owned(),
        serde_json::from_str(r#"{"note":"still mine"}"#).expect("valid"),
    );

    let (listed, complaints) = listing(&session);
    assert!(listed.starts_with("LOCAL"), "{listed}");
    assert!(listed.contains("still mine"), "{listed}");
    assert!(
        complaints.contains("could not say what it serves"),
        "the degrade is said once, on stderr: {complaints:?}"
    );
}

#[test]
fn an_item_added_after_the_daemon_started_injects_on_its_first_run() {
    let dir = scratch("catalogue-new-item");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["decoy"]),
        "{}",
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = build(&client, &Invocation::default()).registry;

    wait_until_served(running.socket(), "DECOY");
    settle(&dir);
    assert_eq!(
        support::proton::vault_list_count(&dir),
        1,
        "priming the index cost more than one enumeration"
    );

    // Somebody adds an item to the vault. Nothing else happens: the daemon is
    // not signalled, not restarted, and its config is not touched.
    set_catalogue_listing(&dir, &listing_of(&["decoy", "decoy alpha"]));

    let (outcome, seen) = run_named(&registry, &dir, "DECOY_ALPHA");
    assert_eq!(seen, DECOY, "the child did not get the new item's value");
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(
        last_decision(&dir, "DECOY_ALPHA").as_deref(),
        Some("allow"),
        "the daemon's own row must say it served the name"
    );
}

/// A daemon whose index predates the item `decoy alpha`, which the vault now
/// holds behind a listing that takes `pause` seconds to answer.
fn stale_index(
    label: &str,
    timeout_ms: u64,
    pause: u64,
) -> (std::path::PathBuf, keyless::daemon::Running, Registry) {
    let dir = scratch(label);
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["decoy"]),
        "{}",
    );
    let mut config = daemon_over(&dir, &vendor);
    config.stores.proton.timeout_ms = timeout_ms;
    let running = start_daemon(&config, policy_allowing_self());
    let registry = build(
        &client_config(running.socket(), 3_000),
        &Invocation::default(),
    )
    .registry;
    wait_until_served(running.socket(), "DECOY");
    settle(&dir);
    set_catalogue_listing(&dir, &listing_of(&["decoy", "decoy alpha"]));
    pause_catalogue_listing(&dir, pause);
    (dir, running, registry)
}

#[test]
fn concurrent_misses_on_one_stale_index_cost_one_listing() {
    let (dir, _running, registry) = stale_index("catalogue-coalesce", 60_000, 1);
    let before = support::proton::vault_list_count(&dir);

    let runs = 6;
    let gate = std::sync::Barrier::new(runs);
    let seen: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..runs)
            .map(|nth| {
                let (registry, dir, gate) = (&registry, &dir, &gate);
                scope.spawn(move || {
                    let marker = dir.join(format!("concurrent-{nth}.marker"));
                    gate.wait();
                    support::run_with(
                        registry,
                        &["DECOY_ALPHA"],
                        &support::witness(&marker, "DECOY_ALPHA", 0),
                        &[],
                    );
                    support::witnessed(&marker)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("a run panicked"))
            .collect()
    });

    assert!(seen.iter().all(|value| value == DECOY), "{seen:?}");
    assert_eq!(
        support::proton::vault_list_count(&dir) - before,
        1,
        "{runs} concurrent misses must share one listing"
    );
}

#[test]
fn a_rebuild_with_no_verdict_in_time_is_silence_and_not_an_unknown_name() {
    let (dir, _running, registry) = stale_index("catalogue-rebuild-silent", 1_000, 10);

    let (outcome, seen) = run_named(&registry, &dir, "DECOY_ALPHA");
    assert_eq!(
        seen, "<unset>",
        "the child must still run, without the value"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(
        last_decision(&dir, "DECOY_ALPHA").as_deref(),
        Some("store-silent"),
        "a rebuild nobody answered must read as silence"
    );
}

#[test]
fn two_items_minting_one_name_are_refused_without_asking_any_store() {
    // C4. The assertion that matters is the ABSENCE of a vendor `run`: a
    // first-wins ambiguity would hand back a real credential that is the wrong
    // credential, and nothing downstream could tell.
    let dir = scratch("catalogue-ambiguous");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["my-key", "My Key", "other-key"]),
        "{}",
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = build(&client, &Invocation::default()).registry;

    // Enumerate first, so the miss below is a decision about a name the daemon
    // knows two items mint — not a name it has never heard of.
    let served = wait_until_served(running.socket(), "OTHER_KEY");
    assert!(
        !served.contains(&"MY_KEY".to_owned()),
        "a name the daemon refuses must not be listed: {served:?}"
    );

    let refused = registry.resolve("MY_KEY");
    assert!(
        !matches!(refused, Resolution::Found { .. }),
        "a colliding name must not resolve: {}",
        arm(&refused)
    );
    // No `run` was created. `pass-cli.argv` is written by the stub's run branch
    // and by nothing else, so its absence is the assertion — the same shape
    // `tests/daemon_proton.rs` argues for an undeclared name.
    // Nor is a title spelling that mints the colliding name: it is refused
    // under that name rather than guessed.
    let refused = registry.resolve("my-key");
    assert!(
        !matches!(refused, Resolution::Found { .. }),
        "a title spelling of a colliding name must not resolve: {}",
        arm(&refused)
    );
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a colliding name reached the vendor"
    );

    // The control: a non-colliding name from the same listing still resolves,
    // so the case above is about the collision and not about a broken fixture.
    match registry.resolve("OTHER_KEY") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), DECOY),
        other => panic!("the collision must not spread: {}", arm(&other)),
    }
    assert!(dir.join("pass-cli.argv").exists());
}
