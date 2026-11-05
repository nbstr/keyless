#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod catalogue_daemon_support;
mod support;

use keyless::State;
use keyless::daemon::config::DaemonConfig;
use keyless::store::{Invocation, Registry, Resolution, build};

use catalogue_daemon_support::{
    DECOY, ONE_VAULT, arm, daemon_over, listing_of, run_named, settle, wait_until_served,
};
use support::backend::Backend;
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::proton::stub_pass_cli_catalogue;
use support::scratch;

/// The string sitting in every value position of the view fixture below.
///
/// A field view is the one enumeration that reads an item's CONTENT, so it is
/// the only place a value could ride out into a name. Distinct and
/// recognisable, so its absence from the listing is an assertion rather than a
/// hope.
const VIEW_LEAK: &str = "decoy-Cat4-never-in-a-listing-0912";

/// One item's field view, carrying [`VIEW_LEAK`] in every value position.
fn demo_api_key_view() -> String {
    format!(
        r#"{{"item":{{"id":"It3mOne","share_id":"ShAr3","state":"Active","revision":2,
            "content":{{"item_uuid":"UU1D","title":"demo api key",
              "note":"{VIEW_LEAK}",
              "extra_fields":[{{"name":"Expiry Date","content":{{"Hidden":"{VIEW_LEAK}"}}}}]}}}}}}"#
    )
}

#[test]
fn a_field_nobody_could_guess_is_named_after_one_miss_and_carries_no_value() {
    // The case with no other route to it: a field whose label nobody would
    // guess from the item's name — on the live machine an accented French one —
    // serves a name no caller derives from anything they hold. Stage two is
    // fetched for THIS item only, and only because a miss inverted onto its
    // title. The label here is a decoy from the allowlist rather than the live
    // one: a coordinate naming anything in a real account must not be in this
    // repository, and the character classes that make the rule hard are pinned
    // in `tests/catalogue.rs` instead, where nothing is a coordinate.
    let dir = scratch("catalogue-field-view");
    let view = demo_api_key_view();
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["demo api key"]),
        &view,
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = build(&client, &Invocation::default()).registry;

    // Stage one. No field view has been fetched yet, and that is the point:
    // reading every item's fields on every rebuild would be one vendor call per
    // item, each a permanent off-machine audit entry.
    wait_until_served(running.socket(), "DEMO_API_KEY");
    assert_eq!(
        support::proton::view_count(&dir),
        0,
        "stage two ran before anything asked for it"
    );

    // A caller guesses the English name and misses. That miss inverts onto a
    // live title, so it is the one thing that buys a field view.
    let guess = registry.resolve("DEMO_API_KEY__EXPIRES");
    assert!(
        !matches!(guess, Resolution::Found { .. }),
        "the guess must miss: {}",
        arm(&guess)
    );

    let served = wait_until_served(running.socket(), "DEMO_API_KEY__EXPIRY_DATE");
    assert!(
        support::proton::view_count(&dir) >= 1,
        "no field view was fetched"
    );

    // C3 over the one enumeration that touches content: the view fixture holds
    // the marker in every value position, and neither it nor its length reaches
    // the listing.
    let rendered = served.join(",");
    assert!(!rendered.contains(VIEW_LEAK), "{rendered}");
    assert!(
        !rendered.contains(&VIEW_LEAK.len().to_string()),
        "the length of a value reached the listing: {rendered}"
    );

    match registry.resolve("DEMO_API_KEY__EXPIRY_DATE") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), DECOY),
        other => panic!("a derived field name must resolve: {}", arm(&other)),
    }
}

/// A daemon over one vault holding `titles`, and a session registry speaking to
/// it, once `ready` is listed.
fn serving(
    label: &str,
    titles: &[&str],
    view: &str,
    declare: impl FnOnce(&mut DaemonConfig),
    ready: &str,
) -> (std::path::PathBuf, keyless::daemon::Running, Registry) {
    let dir = scratch(label);
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(titles),
        view,
    );
    let mut config = daemon_over(&dir, &vendor);
    declare(&mut config);
    let running = start_daemon(&config, policy_allowing_self());
    let registry = build(
        &client_config(running.socket(), 3_000),
        &Invocation::default(),
    )
    .registry;
    wait_until_served(running.socket(), ready);
    (dir, running, registry)
}

fn assert_serves_decoy(registry: &Registry, name: &str) {
    match registry.resolve(name) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), DECOY, "{name}"),
        other => panic!("`{name}` must resolve: {}", arm(&other)),
    }
}

#[test]
fn an_item_asked_for_by_its_own_title_serves_what_its_minted_name_serves() {
    let (dir, _running, registry) = serving(
        "catalogue-title-spelled",
        &["decoy alpha"],
        "{}",
        |_| {},
        "DECOY_ALPHA",
    );

    assert_serves_decoy(&registry, "decoy-alpha");
    assert_serves_decoy(&registry, "DECOY_ALPHA");

    // The audit row carries the name as the caller sent it, not the minted
    // spelling it was looked up under.
    let audit = std::fs::read_to_string(dir.join("audit.jsonl")).expect("the daemon wrote a row");
    let row = audit
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("an audit row is JSON"))
        .find(|row| {
            row["names"]
                .as_array()
                .is_some_and(|names| names.len() == 1 && names[0].as_str() == Some("decoy-alpha"))
        })
        .unwrap_or_else(|| panic!("no audit row names `decoy-alpha` exactly as sent:\n{audit}"));
    assert_eq!(row["decision"].as_str(), Some("allow"), "{row}");
}

#[test]
fn a_declared_name_answers_to_its_items_title() {
    let (_dir, _running, registry) = serving(
        "catalogue-declared-title",
        &["demo login"],
        "{}",
        |config| {
            config.secrets.insert(
                "DEMO_LOGIN".to_owned(),
                serde_json::from_str(
                    r#"{"store":"proton","vault":"personal","item":"demo login","field":"password"}"#,
                )
                .expect("valid"),
            );
        },
        "DEMO_LOGIN",
    );
    assert_serves_decoy(&registry, "demo-login");
}

#[test]
fn a_title_spelled_field_name_resolves_on_its_first_ask() {
    let (_dir, _running, registry) = serving(
        "catalogue-title-field",
        &["demo api key"],
        &demo_api_key_view(),
        |_| {},
        "DEMO_API_KEY",
    );
    assert_serves_decoy(&registry, "demo-api-key__expiry-date");
}

#[test]
fn a_field_name_of_an_existing_item_injects_on_its_first_run() {
    let (dir, _running, registry) = serving(
        "catalogue-field-first-run",
        &["demo api key"],
        &demo_api_key_view(),
        |_| {},
        "DEMO_API_KEY",
    );
    settle(&dir);
    assert_eq!(
        support::proton::view_count(&dir),
        0,
        "no field view may be fetched before a miss"
    );

    let (outcome, seen) = run_named(&registry, &dir, "DEMO_API_KEY__EXPIRY_DATE");
    assert_eq!(seen, DECOY, "the child did not get the field's value");
    assert_eq!(outcome.state, State::Injected);
}

#[test]
fn the_first_request_to_a_daemon_that_never_listed_injects() {
    let dir = scratch("catalogue-never-listed");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["demo api key"]),
        &demo_api_key_view(),
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let registry = build(
        &client_config(running.socket(), 3_000),
        &Invocation::default(),
    )
    .registry;

    let (outcome, seen) = run_named(&registry, &dir, "DEMO_API_KEY__EXPIRY_DATE");
    assert_eq!(seen, DECOY, "the child did not get the value");
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(
        support::proton::vault_list_count(&dir),
        1,
        "one miss, one listing"
    );
}

#[test]
fn a_name_nothing_mints_is_refused_and_names_the_spelling_it_tried() {
    let (_dir, _running, registry) = serving(
        "catalogue-title-unknown",
        &["decoy-token"],
        "{}",
        |_| {},
        "DECOY_TOKEN",
    );

    let refused = registry.resolve("no-such-item");
    assert!(
        matches!(refused, Resolution::Refused { .. }),
        "an unrecognisable name must be refused with an explanation: {}",
        arm(&refused)
    );
    assert!(
        refused.reason().contains("tried `NO_SUCH_ITEM`"),
        "{}",
        refused.reason()
    );
}
