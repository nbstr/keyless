//! `items` and `fields` against a real account and the real `pass-cli`.
//!
//! Live, `#[ignore]`d and run by hand: how to run them, which fixtures they
//! need and what they must never do is the header of `tests/proton_live.rs`.

mod proton_live_support;

use keyless::config::Config;
use keyless::store::proton::Reason;

use proton_live_support::required;

// ---------------------------------------------------------------------------
// Discovery, against the real CLI.
//
// These are the reason `items` and `fields` exist. A stub proves the extraction
// handles a shape somebody wrote down; only the real CLI proves the shape is the
// CLI's — and it was NOT what `item create custom --get-template` describes,
// which is the only shape readable without printing a credential.
// ---------------------------------------------------------------------------

/// A config with a reader identity and no names declared at all.
///
/// `items` and `fields` ask the store, not the config, so a config that declares
/// nothing is the honest fixture: a caller reaches for these verbs precisely
/// because they do not yet know what to declare.
fn discovery_config(session_dir: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"session_dir":"{session_dir}","timeout_ms":30000}}}}}}"#
    )
}

fn live_discoverer(json: &str) -> Box<dyn keyless::store::discover::Discover> {
    let config: Config = serde_json::from_str(json).expect("the test config must be valid");
    keyless::store::discover::discoverer(&config, "proton", &Reason::for_verb("test"))
        .expect("proton must have a discoverer")
}

/// 11. `items` lists a live item and a trashed one, and marks which is which.
///
/// The trash rule from the other side: resolution refuses a trashed item, and
/// discovery must still SHOW it — somebody hunting a name that stopped resolving
/// has to be able to see that the item exists and is in the bin.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_listing_shows_a_trashed_item_and_marks_its_state() {
    let vault = required("KEYLESS_LIVE_VAULT");
    let discover = live_discoverer(&discovery_config(&required("KEYLESS_LIVE_SESSION_DIR")));
    let items = discover
        .items(Some(&vault))
        .expect("the scoped session must be able to list its own vault");

    assert!(
        !items.is_empty(),
        "vault `{vault}` is empty, so this test asserts nothing"
    );

    let trashed_title = required("KEYLESS_LIVE_TRASHED_TITLE");
    let trashed = items
        .iter()
        .find(|item| item.title == trashed_title)
        .unwrap_or_else(|| panic!("`{trashed_title}` is not in the listing"));
    assert!(
        !trashed.is_active(),
        "a trashed item was reported as active: state was `{}`",
        trashed.state
    );

    // The negative control: without a live item in the same listing, the
    // assertion above could pass on an implementation that calls everything
    // trashed.
    let live_title = required("KEYLESS_LIVE_CUSTOM_TITLE");
    let live = items
        .iter()
        .find(|item| item.title == live_title)
        .unwrap_or_else(|| panic!("`{live_title}` is not in the listing"));
    assert!(live.is_active(), "state was `{}`", live.state);
    assert_eq!(live.vault, vault);
    assert!(!live.kind.is_empty(), "the item type column was empty");
}

/// 12. `fields` reports a custom item's real field names, and no value.
///
/// **This is the assertion the whole discovery half exists for.** `keyless`
/// degraded once because a configured `field` did not match the item's real field
/// name, and the name could not be found: the only vendor verb that reveals it
/// also prints the value.
///
/// `KEYLESS_LIVE_CUSTOM_FIELD` is the name the operator expects, written out by
/// hand — an independent statement of what the item is, not something derived from
/// the command under test.
///
/// **This test does not carry the field's value, and deliberately so.** Requiring
/// the operator to export it would mean someone had to read it first, which is the
/// thing this verb exists to make unnecessary. The "a value never reaches the name
/// column" property is checked where it can be checked with a real needle: the
/// hand-written view fixture in `store::proton`, whose every value position holds
/// a marker string. What this test adds is the half a fixture cannot prove — that
/// the shape is the CLI's, and that the sibling keys of a value are reported as
/// structure rather than as fields.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_custom_items_field_names_are_reported_and_its_structure_is_not() {
    let vault = required("KEYLESS_LIVE_VAULT");
    let title = required("KEYLESS_LIVE_CUSTOM_TITLE");
    let expected = required("KEYLESS_LIVE_CUSTOM_FIELD");

    let discover = live_discoverer(&discovery_config(&required("KEYLESS_LIVE_SESSION_DIR")));
    let fields = discover
        .fields(Some(&vault), &title)
        .expect("a live custom item must report its fields");

    let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert!(
        names.contains(&expected.as_str()),
        "`{expected}` is not among the reported field names: {names:?}"
    );

    // The keys that sit beside a value on the real shape. Reporting one of these
    // as a field would mean the extraction recursed into a value container, which
    // is the step that stands between the credential and stdout.
    for structural in [
        "content",
        "Hidden",
        "Text",
        "Timestamp",
        "item_uuid",
        "name",
    ] {
        assert!(
            !names.contains(&structural),
            "`{structural}` is structure, not a field: {names:?}"
        );
    }

    // A custom field is reported as such and carries the vendor's own type word,
    // which is what makes a `Timestamp` field distinguishable from the credential.
    let found = fields
        .iter()
        .find(|field| field.name == expected)
        .expect("checked above");
    assert_eq!(found.kind.as_str(), "custom");
    assert!(
        found.value_type.is_some(),
        "the type column was empty for a custom field"
    );
}

/// 13. `fields` on a trashed item refuses and says why.
///
/// Reporting its fields would send the reader to write a config entry against a
/// title that can never resolve, because the resolver refuses a trashed item on
/// purpose.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_trashed_items_fields_are_refused_with_the_reason() {
    let discover = live_discoverer(&discovery_config(&required("KEYLESS_LIVE_SESSION_DIR")));
    let message = discover
        .fields(
            Some(&required("KEYLESS_LIVE_VAULT")),
            &required("KEYLESS_LIVE_TRASHED_TITLE"),
        )
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(message.contains("trash"), "{message}");
}
