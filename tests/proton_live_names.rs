//! The Proton name form against a real account and the real `pass-cli`.
//!
//! Live, `#[ignore]`d and run by hand: how to run them, which fixtures they
//! need and what they must never do is the header of `tests/proton_live.rs`.

mod proton_live_support;
mod support;

use keyless::State;

use proton_live_support::{assert_is_expected, registry_from, required};
use support::{run_with, scratch, witness, witnessed};

const EX_USAGE: i32 = 64;

// ---------------------------------------------------------------------------
// The name form, against the real CLI.
//
// The whole reason it exists: a share id is minted per session. Measured
// 2026-08-08, vault `personal` answered with one share id to the agent session and a
// different one to the full account — so an address made of ids cannot survive
// a token renewal, and the volatile half has to be looked up every time.
// ---------------------------------------------------------------------------

/// A config that addresses one name by vault, title and field.
fn named_live_config(session_dir: &str, vault: &str, title: &str, field: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"session_dir":"{session_dir}","timeout_ms":20000}}}},
            "secrets":{{"DECOY":{{"vault":"{vault}","item":"{title}","field":"{field}"}}}}}}"#
    )
}

/// 6. The record shape the whole name form rests on.
///
/// Asserted against the vendor directly rather than through the adapter: the
/// adapter's parse would agree with itself whatever the CLI returned, so the
/// claim "the item id is under `id`" has to be checked here or nowhere. The
/// keys measured on 2026-08-08 were `id`, `share_id`, `vault_id`, `state`,
/// `flags`, `create_time`, `modify_time`, `title`, `item_type`.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn the_listing_carries_a_share_id_an_id_and_a_state_but_no_item_id() {
    let vault = required("KEYLESS_LIVE_VAULT");
    let output = std::process::Command::new("pass-cli")
        .args(["item", "list", "--vault-name", &vault, "--output", "json"])
        .env(
            "PROTON_PASS_SESSION_DIR",
            required("KEYLESS_LIVE_SESSION_DIR"),
        )
        .env(
            "PROTON_PASS_AGENT_REASON",
            "keyless test suite: checking the listing's record shape",
        )
        .output()
        .expect("`pass-cli` must be on PATH");
    assert!(
        output.status.success(),
        "the vendor CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("`item list --output json` must be JSON");
    let items = parsed["items"].as_array().expect("an `items` array");
    assert!(
        !items.is_empty(),
        "vault `{vault}` is empty, so this test asserts nothing"
    );

    for item in items {
        for key in ["id", "share_id", "state", "title"] {
            assert!(
                item[key].as_str().is_some_and(|value| !value.is_empty()),
                "`{key}` is absent or empty, and the name form cannot work without it"
            );
        }
        assert!(
            item["item_id"].is_null(),
            "an `item_id` key appeared; the adapter reads `id` and would now be reading \
             the wrong one of two"
        );
    }
}

/// 7. A title whose only match is trashed refuses the run, and says why.
///
/// The one rule this vault can prove for real today: `personal` holds exactly one
/// item and it is in the trash. Resolving it would hand a child a value its
/// owner believes they deleted, and a trashed item is still returned by
/// `item list`, so nothing about the listing itself refuses it. The vault
/// answered, so this is a name the store does not hold, not a store failure:
/// the command never starts.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_trashed_item_refuses_the_run_and_names_the_trash() {
    let dir = scratch("proton-live-trashed");
    let marker = dir.join("witness");
    let registry = registry_from(&named_live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_VAULT"),
        &required("KEYLESS_LIVE_TRASHED_TITLE"),
        "password",
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 41), &[]);

    assert!(!marker.exists(), "the child started: {notes}");
    assert_eq!(outcome.state, State::Refused, "{notes}");
    assert_eq!(outcome.exit_code, EX_USAGE, "{notes}");
    assert!(
        notes.contains("DECOY"),
        "the banner must name the secret: {notes}"
    );
    assert!(notes.contains("trash"), "the banner must say why: {notes}");
}

/// 8. A title nothing in the vault carries refuses the run rather than guessing.
///
/// The negative control for the two above: without it they could both pass on
/// an adapter that never resolves a named address at all. The title is one this
/// suite invents, so it cannot collide with anything a person created.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_title_that_exists_nowhere_refuses_the_run() {
    let dir = scratch("proton-live-no-title");
    let marker = dir.join("witness");
    let registry = registry_from(&named_live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_VAULT"),
        "keyless-there-is-no-item-with-this-title",
        "password",
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 43), &[]);

    assert!(!marker.exists(), "the child started: {notes}");
    assert_eq!(outcome.state, State::Refused, "{notes}");
    assert_eq!(outcome.exit_code, EX_USAGE, "{notes}");
    assert!(
        notes.contains("keyless-there-is-no-item-with-this-title"),
        "the banner must name the title it could not find: {notes}"
    );
    assert!(
        !notes.contains("trash"),
        "nothing was in the trash: {notes}"
    );
}

/// 9. A vault this session cannot list degrades rather than failing the run.
///
/// Stands in for a revoked grant or a renamed vault. Measured 2026-08-08: the
/// CLI exits 1 with `Could not find vault <name>`.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_vault_that_cannot_be_listed_degrades_and_still_runs() {
    let dir = scratch("proton-live-no-vault");
    let marker = dir.join("witness");
    let registry = registry_from(&named_live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        "keyless-no-such-vault-anywhere",
        "anything",
        "password",
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 47), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.exit_code, 47);
    assert!(
        notes.contains("keyless-no-such-vault-anywhere"),
        "the banner must name the vault: {notes}"
    );
}

/// 10. A name resolves end to end, with no id anywhere in the config.
///
/// **This is the positive path, and it is the one assertion the vault cannot
/// currently make.** `personal` holds a single item and it is trashed, and the agent
/// token is read-only — `item create` returns `NotAllowed` — so the item cannot
/// be made from inside this suite.
///
/// To make it run, create a **login** item in vault `personal` titled
/// `keyless-decoy-live`, with any disposable string in its `password` field,
/// then export:
///
/// ```text
/// export KEYLESS_LIVE_TITLE='keyless-decoy-live'
/// export KEYLESS_LIVE_FIELD='password'
/// export KEYLESS_LIVE_EXPECTED='that same disposable string'
/// ```
///
/// It panics naming the missing variable rather than skipping. A live test that
/// passes when its inputs are absent is a green result for work that never
/// happened, which is the failure this whole file is written to avoid.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_name_resolves_without_an_id_anywhere_in_the_config() {
    let expected = required("KEYLESS_LIVE_EXPECTED");
    let dir = scratch("proton-live-named");
    let marker = dir.join("witness");
    let registry = registry_from(&named_live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_VAULT"),
        &required("KEYLESS_LIVE_TITLE"),
        &required("KEYLESS_LIVE_FIELD"),
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_is_expected(&witnessed(&marker), &expected, "the injected value");
    assert_eq!(outcome.state, State::Injected, "{notes}");
    assert_eq!(notes, "", "a successful run says nothing at all");
}
