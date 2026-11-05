use super::parse;

// -----------------------------------------------------------------------
// The 1Password vault, and the login the daemon is handed.
// -----------------------------------------------------------------------

/// A 1Password daemon config with everything a lookup needs, so the
/// warnings can be asserted SILENT — the control every warning test here
/// needs, or a warning could fire on every config regardless.
///
/// The name carries its own `field` and the store sets no store-wide one,
/// which is the config that serves DECLARED names and nothing else. A
/// store-wide `field` is warned about — see the test below — because it is
/// the switch that turns the vault into the allowlist.
const ONEPASSWORD_WELL_FORMED: &str = r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"onepassword":{"enabled":true,"vault":"company",
                                         "credentials_file":"/tmp/keyless-test/onepassword.json",
                                         "credentials":{"OP_SERVICE_ACCOUNT_TOKEN":"SERVICE_ACCOUNT"}}},
                "secrets":{"DECOY":{"store":"onepassword","item":"Router","field":"password"}}}"#;

#[test]
fn a_well_formed_onepassword_config_registers_the_store_and_warns_about_nothing() {
    let config = parse(ONEPASSWORD_WELL_FORMED);
    let ids: Vec<String> = config
        .registry(None)
        .stores()
        .iter()
        .map(|store| store.id().to_owned())
        .collect();
    assert_eq!(ids, ["onepassword"]);
    assert!(config.warnings().is_empty(), "{:?}", config.warnings());
}

#[test]
fn a_names_onepassword_coordinates_are_read_from_the_daemons_own_config() {
    let config = parse(
        r#"{"stores":{"onepassword":{"vault":"company","field":"password"}},
                "secrets":{"A":{"store":"onepassword","item":"Router","section":"other",
                                "field":"api key"}}}"#,
    );
    let routing = config.onepassword_routing();
    assert_eq!(routing.vault().expect("pinned"), "company");
    let address = routing.address("A").expect("declared");
    assert_eq!(address.item, "Router");
    assert_eq!(address.section.as_deref(), Some("other"));
    assert_eq!(address.field, "api key");
    // An undeclared name is its own title at the store-wide field, in the
    // one vault — there is nowhere else it could point.
    assert_eq!(
        routing
            .address("A_NAME_NOBODY_EVER_DECLARED")
            .expect("addressable")
            .item,
        "A_NAME_NOBODY_EVER_DECLARED"
    );
}

#[test]
fn no_daemon_config_key_supplies_a_default_onepassword_vault() {
    // The same shape of assertion as the Infisical environment above: every
    // spelling somebody reaching for a default would try is dropped by
    // serde, and the routing built from the parsed config names no vault.
    let config = parse(
        r#"{"stores":{"onepassword":{"enabled":true,"default_vault":"personal"},
                          "vault":"personal"},
                "vault":"personal","onepassword_vault":"personal"}"#,
    );
    let rendered = serde_json::to_string(&config).expect("serialize");
    assert!(
        !rendered.contains("personal"),
        "a vault survived the parse: {rendered}"
    );
    assert!(config.onepassword_routing().vault().is_err());
    let said = config.warnings().join(" ");
    assert!(said.contains("stores.onepassword.vault"), "{said}");
}

#[test]
fn a_store_wide_field_is_told_that_it_makes_the_vault_the_allowlist() {
    // Behind the socket this is the property nobody can read off the
    // config. A store-wide `field` supplies the ONLY coordinate an
    // undeclared name lacks — the vault is the store's and the title is the
    // name itself — so every item in the pinned vault becomes reachable by
    // title to any attested client, `secrets` entry or not.
    //
    // The daemon has no declared-name population to check against (see
    // `crate::daemon::resolver`), and this adapter has no refusal of its
    // own, so nothing downstream would ever say it. It is said here, once,
    // where the operator is looking at the file they just wrote.
    let config = parse(
        r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"onepassword":{"enabled":true,"vault":"company","field":"password",
                                         "credentials_file":"/tmp/keyless-test/onepassword.json",
                                         "credentials":{"OP_SERVICE_ACCOUNT_TOKEN":"SA"}}},
                "secrets":{"DECOY":{"store":"onepassword","item":"Router"}}}"#,
    );
    let said = config.warnings().join(" ");
    assert!(said.contains("stores.onepassword.field"), "{said}");
    assert!(said.contains("allowlist"), "{said}");
    assert!(
        said.contains("company"),
        "the warning must name the vault: {said}"
    );
    // And the way out, or the warning is a fact with no action attached.
    assert!(said.contains("\"field\" on each name"), "{said}");

    // The behaviour the warning describes, asserted rather than assumed —
    // a warning about a property the code does not have is worse than none.
    let routing = config.onepassword_routing();
    let address = routing
        .address("A_NAME_NOBODY_EVER_DECLARED")
        .expect("a store-wide field makes an undeclared name addressable");
    assert_eq!(address.item, "A_NAME_NOBODY_EVER_DECLARED");

    // The control, which is also the remedy: with each name carrying its
    // own field and the store carrying none, the warning is silent AND an
    // undeclared name is refused before anything is spawned.
    let narrowed = parse(ONEPASSWORD_WELL_FORMED);
    assert!(narrowed.warnings().is_empty(), "{:?}", narrowed.warnings());
    assert!(
        narrowed
            .onepassword_routing()
            .address("A_NAME_NOBODY_EVER_DECLARED")
            .is_err(),
        "with no store-wide field an undeclared name must have nowhere to point"
    );
}

#[test]
fn an_empty_onepassword_vault_is_warned_about_exactly_as_a_missing_one_is() {
    // `""` parses, so it is the one spelling that reads as answered in the
    // file. Behind the daemon it must fail the same way `vault` absent does
    // — at startup, in the operator's own words — rather than reaching the
    // vendor as `--vault=` and a reference with a hole where the vault is.
    let config =
        parse(r#"{"stores":{"onepassword":{"enabled":true,"vault":"","field":"password"}}}"#);
    let said = config.warnings().join(" ");
    assert!(said.contains("stores.onepassword.vault"), "{said}");
    assert!(said.contains("names no vault"), "{said}");
    assert!(config.onepassword_routing().vault().is_err());

    // The control: a real vault silences exactly this warning, so the
    // assertion above is about the empty string and not about every config.
    let named =
        parse(r#"{"stores":{"onepassword":{"enabled":true,"vault":"company"}}}"#).warnings();
    assert!(
        !named
            .iter()
            .any(|warning| warning.contains("names no vault")),
        "{named:?}"
    );
}

#[test]
fn a_name_declaring_another_vault_is_refused_on_the_daemon_too() {
    // The whole point of hosting this adapter behind the boundary is that
    // a name cannot widen the vault. The daemon's config is the operator's,
    // but a wrong entry in it must still fail closed.
    let config = parse(
        r#"{"stores":{"onepassword":{"vault":"company","field":"password"}},
                "secrets":{"A":{"store":"onepassword","vault":"personal","item":"Router"}}}"#,
    );
    let said = config
        .onepassword_routing()
        .address("A")
        .expect_err("another vault is not this store's");
    assert!(said.contains("pinned to `company`"), "{said}");
}

#[test]
fn a_onepassword_store_with_no_credential_is_warned_about() {
    let said = parse(r#"{"stores":{"onepassword":{"enabled":true,"vault":"company"}}}"#)
        .warnings()
        .join(" ");
    assert!(said.contains("names no credential"), "{said}");
    assert!(said.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{said}");
    assert!(said.contains("credential --store onepassword"), "{said}");
}

#[test]
fn a_onepassword_credential_variable_outside_the_vendors_prefix_is_named_at_startup() {
    let said = parse(
        r#"{"stores":{"onepassword":{"enabled":true,"vault":"company",
                          "credentials":{"HOME":"X","OP_SERVICE_ACCOUNT_TOKEN":"Y"}}}}"#,
    )
    .warnings()
    .join(" ");
    assert!(said.contains("not `OP_*`"), "{said}");
    assert!(said.contains("HOME"), "{said}");
    assert!(
            !said.contains("refused because they are not `OP_*`, and every 1Password lookup will degrade while they are named: HOME, OP_"),
            "an accepted variable was reported as refused: {said}"
        );
}

#[test]
fn keeping_the_service_account_in_the_served_secrets_file_is_warned_about() {
    let said = parse(
            r#"{"stores":{"file":{"enabled":true,"path":"/tmp/keyless-test/secrets.json"},
                          "onepassword":{"enabled":true,"vault":"company",
                                         "credentials_file":"/tmp/keyless-test/secrets.json",
                                         "credentials":{"OP_SERVICE_ACCOUNT_TOKEN":"SERVICE_ACCOUNT"}},
                          "default":"file"}}"#,
        )
        .warnings()
        .join(" ");
    assert!(said.contains("same file the `file` store serves"), "{said}");
    assert!(said.contains("SERVICE_ACCOUNT"), "{said}");
    assert!(
        said.contains("stores.onepassword.credentials_file"),
        "{said}"
    );
}

#[test]
fn the_two_vendor_credential_files_default_to_different_paths() {
    // One file per store is what lets a rotation of one leave the other
    // alone, and what keeps `keylessd credential --store` meaningful.
    let config = parse("{}");
    assert_ne!(
        config.stores.onepassword.credentials_file.to_path_buf(),
        config.stores.infisical.credentials_file.to_path_buf()
    );
    assert_ne!(
        config.stores.onepassword.credentials_file.to_path_buf(),
        config.stores.file.path.to_path_buf()
    );
}
