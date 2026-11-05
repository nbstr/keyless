//! How 1Password items resolve: absent, archived, ambiguous, out of vault.

mod stores_support;
mod support;

use keyless::State;
use keyless::store::proton::Reason;

use support::{
    Backend, ONEPASSWORD_DECOY, OnePasswordListing, op_listing_count, recorded, run_with, scratch,
    stub_op, stub_op_listing, witness, witness_env, witnessed, witnessed_env,
};

use stores_support::{ONEPASSWORD_DECOY_BY_TITLE, last_op_verb, onepassword_config, registry_from};

#[test]
fn a_title_absent_from_the_vault_is_refused_and_never_reaches_run() {
    // The listing says the item is not there, so there is nothing to resolve
    // and the vendor is not asked to try. `NotFound` rather than a vendor
    // error, so `doctor` sends the reader to the vault and not to the login.
    let dir = scratch("onepassword-absent-title");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    // `decoy` is not `DECOY`: the match is exact, so the listing's one item
    // does not answer for it.
    let registry = registry_from(
        &onepassword_config(&stub, r#"{"MISSING":{"item":"decoy"}}"#),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(
        &registry,
        &["MISSING"],
        &witness(&marker, "MISSING", 0),
        &[],
    );

    assert_eq!(outcome.state, State::Refused);
    assert!(!marker.exists(), "the child started: {notes}");
    assert!(notes.contains("not found in any store"), "{notes}");
    assert_eq!(
        last_op_verb(&dir),
        "item",
        "a run was attempted for an absent title"
    );
}

#[test]
fn an_archived_item_never_resolves_and_the_command_still_runs() {
    // The vendor resolves a reference to an archived item (documented), so
    // the listing is the only thing between a put-away credential and the
    // child. The state word is the vendor's own.
    let dir = scratch("onepassword-archived");
    let marker = dir.join("witness");
    let stub = stub_op_listing(
        &dir,
        &Backend::Injects(ONEPASSWORD_DECOY),
        &OnePasswordListing::Json(
            r#"[{"id":"It3mDead","title":"DECOY","category":"PASSWORD","state":"ARCHIVED"}]"#,
        ),
        "{}",
    );
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 3), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.exit_code, 3);
    assert_eq!(witnessed(&marker), "<unset>");
    assert!(notes.contains("archived"), "{notes}");
    assert_eq!(last_op_verb(&dir), "item", "an archived item reached `run`");
}

#[test]
fn two_live_items_with_one_title_degrade_and_name_the_ids() {
    let dir = scratch("onepassword-ambiguous-title");
    let marker = dir.join("witness");
    let stub = stub_op_listing(
        &dir,
        &Backend::Injects(ONEPASSWORD_DECOY),
        &OnePasswordListing::Json(
            r#"[{"id":"It3mOne","title":"DECOY","category":"PASSWORD"},
                {"id":"It3mTwo","title":"DECOY","category":"LOGIN"}]"#,
        ),
        "{}",
    );
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("It3mOne") && notes.contains("It3mTwo"),
        "{notes}"
    );
    assert!(notes.contains("\"item\""), "the fix must be named: {notes}");
    assert_eq!(last_op_verb(&dir), "item");

    // The escape hatch: the id in `item` picks one, and resolves.
    let marker = dir.join("witness-by-id");
    let registry = registry_from(
        &onepassword_config(&stub, r#"{"DECOY":{"item":"It3mTwo"}}"#),
        &Reason::default(),
    );
    let (outcome, _) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(
        recorded(&dir.join("op.probe")),
        "op://company/It3mTwo/password"
    );
}

#[test]
fn a_name_pinned_to_another_vault_never_spawns_op() {
    // The scoping rule at the one place a config entry could reach around
    // it. No listing, no run, no file written by the stub.
    let dir = scratch("onepassword-other-vault");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let registry = registry_from(
        &onepassword_config(&stub, r#"{"DECOY":{"vault":"personal","item":"DECOY"}}"#),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(witnessed(&marker), "<unset>");
    assert!(notes.contains("pinned to `company`"), "{notes}");
    assert!(notes.contains("personal"), "{notes}");
    assert!(
        !dir.join("op.argv").exists(),
        "a vendor process was spawned for a name pinned to another vault"
    );
}

#[test]
fn an_empty_vault_never_spawns_op_and_names_the_config_key() {
    // The refusal this whole backend rests on, against the one vault spelling
    // that parses and pins nothing. Unfiltered, `""` reaches the vendor as
    // `op item list --vault=` and builds `op:///<id>/<field>` — a listing and a
    // reference with a hole where the scoping is supposed to be.
    //
    // Asserted from the vendor's side: the stub writes `op.argv` on every
    // invocation, so its absence is the absence of a process.
    let dir = scratch("onepassword-empty-vault");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let registry = registry_from(
        &format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "onepassword":{{"enabled":true,"binary":"{}","vault":"","field":"password",
                                 "timeout_ms":60000}}}},
                "secrets":{ONEPASSWORD_DECOY_BY_TITLE}}}"#,
            stub.display()
        ),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(witnessed(&marker), "<unset>");
    assert!(notes.contains("stores.onepassword.vault"), "{notes}");
    assert!(
        !dir.join("op.argv").exists(),
        "a vendor process was spawned for a store pinned to no vault"
    );

    // The control: the same fixture with a real vault DOES spawn `op` and
    // injects, so the absence above is the empty string and not a stub that
    // never runs.
    let dir = scratch("onepassword-empty-vault-control");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );
    let (outcome, _) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(outcome.state, State::Injected);
    assert!(dir.join("op.argv").exists(), "the control spawned nothing");
}

#[test]
fn a_reference_handed_back_unresolved_is_refused_rather_than_injected() {
    // Measured: `op run` with nothing to resolve runs its child untouched. A
    // vendor that did that to the probe would hand `printenv` the literal
    // reference, and without the guard that string would be injected as the
    // credential.
    let dir = scratch("onepassword-unresolved");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Unset);
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "the reference was injected as a value"
    );
    assert!(notes.contains("resolving the reference"), "{notes}");
}

#[test]
fn a_concealed_onepassword_value_is_refused_rather_than_injected() {
    let dir = scratch("onepassword-concealed");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Concealed);
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "the mask token was injected as a value"
    );
    assert!(notes.contains("concealed"), "{notes}");
}

#[test]
fn several_onepassword_names_cost_exactly_one_listing() {
    // A run resolves its names concurrently, and the listing is what turns a
    // title into an id — so without the memoisation, N names would be N
    // listings racing each other. Counted from the stub's side.
    let dir = scratch("onepassword-one-listing");
    let marker = dir.join("witness");
    let stub = stub_op_listing(
        &dir,
        &Backend::Injects(ONEPASSWORD_DECOY),
        &OnePasswordListing::Json(
            r#"[{"id":"It3mOne","title":"DECOY","category":"PASSWORD"},
                {"id":"It3mTwo","title":"Router","category":"LOGIN"},
                {"id":"It3mL1v3","title":"decoy alpha","category":"API_CREDENTIAL"}]"#,
        ),
        "{}",
    );
    let registry = registry_from(
        &onepassword_config(
            &stub,
            r#"{"A":{"item":"DECOY"},"B":{"item":"Router"},"C":{"item":"decoy alpha"}}"#,
        ),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(
        &registry,
        &["A", "B", "C"],
        &witness_env(&marker, &["A", "B", "C"]),
        &[],
    );

    assert_eq!(outcome.state, State::Injected, "{notes}");
    let seen = witnessed_env(&marker);
    for name in ["A", "B", "C"] {
        assert_eq!(
            seen[name], ONEPASSWORD_DECOY,
            "{name} did not reach the child"
        );
    }
    assert_eq!(
        op_listing_count(&dir),
        1,
        "three names must cost one listing"
    );
}
