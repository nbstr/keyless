//! Discovery reports structure, and only structure.

mod stores_support;
mod support;

use std::path::Path;

use keyless::store::proton::Reason;

use support::{SCOPED_SESSION_DIR, recorded, recorded_lines, scratch, stub_pass_cli_discovery};

use stores_support::{LIVE_AND_TRASHED, ONE_VAULT, mentions};

// ---------------------------------------------------------------------------
// Property: discovery reports structure, and only structure.
//
// Against a stub rather than a live account, so the trash column, the value
// exclusion and the failure paths are all exercised on every run rather than only
// where somebody has a vault configured. The live suite covers the half a stub
// cannot: that the shape is the CLI's.
// ---------------------------------------------------------------------------

/// The string that must never reach a listing. It sits in EVERY value position of
/// the view fixture below, so an extraction that reads one puts it in the output.
const VIEW_LEAK: &str = "decoy-St44-never-in-a-listing-0909";

/// `item view --output json` for a custom item, in the shape measured against
/// `pass-cli` 2.2.5 on 2026-08-08 — label under `name`, value inside a single-key
/// object whose key is the field's type.
fn view_with_values() -> String {
    format!(
        r#"{{"item":{{"id":"It3mL1v3","share_id":"ShAr3","state":"Active","revision":2,
            "content":{{"item_uuid":"UU1D","title":"demo api key","note":"{VIEW_LEAK}",
              "extra_fields":[
                {{"name":"API Key","content":{{"Hidden":"{VIEW_LEAK}"}}}},
                {{"name":"Expiry Date","content":{{"Timestamp":"1730000000"}}}}
              ]}}}}}}"#
    )
}

fn discoverer_for(stub: &Path) -> Box<dyn keyless::store::discover::Discover> {
    let config: keyless::config::Config = serde_json::from_str(&format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","session_dir":"{SCOPED_SESSION_DIR}",
                        "timeout_ms":60000}}}}}}"#,
        stub.display()
    ))
    .expect("valid config");
    keyless::store::discover::discoverer(&config, "proton", &Reason::for_verb("items"))
        .expect("proton must have a discoverer")
}

#[test]
fn a_listing_reports_a_trashed_items_state_verbatim() {
    // Both halves are the property. Hiding a trashed item leaves somebody hunting
    // for an item that is in the bin; showing it unmarked is worse, because they
    // write a config entry against a title that can never resolve.
    let dir = scratch("discover-trash");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let items = discoverer_for(&stub)
        .items(Some("personal"))
        .expect("the stub must answer");

    let trashed = items
        .iter()
        .find(|item| item.title == "keyless-decoy-alpha")
        .expect("a trashed item must still be listed");
    assert_eq!(trashed.state, "Trashed", "the state was not reported as-is");
    assert!(!trashed.is_active());

    // The negative control inside the same listing: without a live item here, the
    // assertion above could pass on an implementation that calls everything
    // trashed.
    let live = items
        .iter()
        .find(|item| item.title == "demo api key")
        .expect("the live item must be listed");
    assert_eq!(live.state, "Active");
    assert!(live.is_active());
    assert_eq!(live.kind, "custom");
    assert_eq!(live.vault, "personal");
}

#[test]
fn a_listing_with_no_vault_named_enumerates_every_vault_the_identity_sees() {
    let dir = scratch("discover-all-vaults");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let items = discoverer_for(&stub).items(None).expect("the stub answers");
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| item.vault == "personal"));
}

#[test]
fn field_names_are_reported_and_no_value_is() {
    // The security property of `fields`, against a fixture whose every value
    // position holds a marker. `item view` prints the values and there is no
    // vendor flag that stops it, so this extraction is the only thing between the
    // credential and stdout.
    let dir = scratch("discover-fields");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, &view_with_values());
    let fields = discoverer_for(&stub)
        .fields(Some("personal"), "demo api key")
        .expect("the stub must answer");

    let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert!(names.contains(&"API Key"), "{names:?}");
    assert!(names.contains(&"Expiry Date"), "{names:?}");

    for field in &fields {
        assert!(
            !field.name.contains(VIEW_LEAK),
            "a value was reported as a field name"
        );
        assert!(!field.path.contains(VIEW_LEAK));
        assert!(
            !field
                .value_type
                .as_deref()
                .is_some_and(|named| named.contains(VIEW_LEAK)),
            "a value reached the type column"
        );
    }

    // The type comes from the container's own key, which is how a `Timestamp`
    // field is distinguishable from the credential beside it.
    let expiry = fields
        .iter()
        .find(|field| field.name == "Expiry Date")
        .expect("checked above");
    assert_eq!(expiry.value_type.as_deref(), Some("Timestamp"));
}

#[test]
fn fields_on_a_trashed_item_is_refused_with_the_reason() {
    // Reporting them would send the reader to write a config entry against a
    // title the resolver refuses on purpose.
    let dir = scratch("discover-fields-trashed");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, &view_with_values());
    let message = discoverer_for(&stub)
        .fields(Some("personal"), "keyless-decoy-alpha")
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(message.contains("trash"), "{message}");
}

#[test]
fn discovery_never_reaches_the_verb_that_resolves_a_value() {
    // The stub answers `vault list`, `item list` and `item view` and fails
    // everything else — so if a discovery path ever reached `run`, these would
    // error rather than quietly resolving something. The recorded argv is the
    // second half of the check.
    let dir = scratch("discover-no-run");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, &view_with_values());
    let _ = discoverer_for(&stub)
        .fields(Some("personal"), "demo api key")
        .expect("the stub answers");

    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert_eq!(argv.first().map(String::as_str), Some("item"));
    for forbidden in ["run", "--env-file", "--no-masking", "--show-secrets"] {
        assert!(
            !mentions(&argv, forbidden),
            "`{forbidden}` appeared in a discovery invocation: {argv:?}"
        );
    }

    // And every discovery call carries the scoped session and a reason, exactly as
    // a read does — enumerating is a read of the vault's structure and is logged
    // off-machine like any other.
    assert_eq!(recorded(&dir.join("pass-cli.session")), SCOPED_SESSION_DIR);
    assert!(!recorded(&dir.join("pass-cli.reason")).trim().is_empty());
}

// ---------------------------------------------------------------------------
// A coordinate that begins with `-`.
//
// Proton ids are base64url, whose alphabet includes `-`, so about one id in 64
// begins with one. `pass-cli` parses with clap, which reads a standalone
// argument beginning with a single `-` as a cluster of short flags — whatever
// option preceded it — and refuses the command with exit 2. Found on a real
// item on 2026-08-08, not reasoned about: an id beginning `-` meant `keyless
// fields` could not inspect that item at all.
//
// Every coordinate below is invented. The property under test is the leading
// `-`, which any base64url-shaped decoy carries — see `no_real_vault_coordinates`
// in this file, which is what keeps it that way.
//
// The stub refuses exactly what the vendor refuses, so this is a test of the
// invocation reaching a parser, not of a copy of the adapter's flag list.
// ---------------------------------------------------------------------------

/// The same shape as `LIVE_AND_TRASHED`, with ids that begin with `-`.
const DASH_LEADING_IDS: &str = r#"{"items":[
    {"id":"-Kx7Qm2Za","share_id":"-Sh4r3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"demo.service","item_type":"custom"}]}"#;

fn dash_id_view() -> String {
    format!(
        r#"{{"item":{{"id":"-Kx7Qm2Za","share_id":"-Sh4r3","state":"Active","revision":2,
            "content":{{"item_uuid":"UU1D","title":"demo.service","note":"{VIEW_LEAK}",
              "extra_fields":[
                {{"name":"API Token","content":{{"Hidden":"{VIEW_LEAK}"}}}}
              ]}}}}}}"#
    )
}

#[test]
fn fields_inspects_an_item_whose_id_begins_with_a_dash() {
    let dir = scratch("discover-dash-id");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, DASH_LEADING_IDS, &dash_id_view());
    let fields = discoverer_for(&stub)
        .fields(Some("personal"), "demo.service")
        .expect("an item whose id begins with `-` must still be inspectable");

    let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert!(names.contains(&"API Token"), "{names:?}");

    // And the id reached the vendor joined to its flag, in one argument. The
    // assertion above cannot distinguish "addressed correctly" from "addressed
    // by title and got lucky", and addressing by title is the wrong fix here.
    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert!(
        argv.iter().any(|arg| arg == "--item-id=-Kx7Qm2Za"),
        "{argv:?}"
    );
    assert!(
        !argv.iter().any(|arg| arg == "--item-title"),
        "the item was addressed by title, which two items can share: {argv:?}"
    );
}

#[test]
fn a_vault_whose_name_begins_with_a_dash_is_still_enumerable() {
    // The same defect one verb earlier. `--vault-name` was already named rather
    // than positional, and that alone never fixed it: the vendor refuses the
    // value whichever option it followed.
    let dir = scratch("discover-dash-vault");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, DASH_LEADING_IDS, "{}");
    let items = discoverer_for(&stub)
        .items(Some("-dashvault"))
        .expect("a vault whose name begins with `-` must still be enumerable");
    assert_eq!(items.len(), 1);

    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert!(
        argv.iter().any(|arg| arg == "--vault-name=-dashvault"),
        "{argv:?}"
    );
}
