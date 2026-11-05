use super::parse;

// -----------------------------------------------------------------------
// The Infisical coordinates, and the environment the daemon cannot have.
// -----------------------------------------------------------------------

#[test]
fn a_names_own_coordinates_are_read_from_the_daemons_own_config() {
    // `env`, `path` and `key` parsed into `SecretRoute` long before
    // anything read them. This is the projection that starts reading them,
    // and it must produce exactly what was written down.
    let config = parse(
        r#"{"secrets":{"DATABASE_URL":{"store":"infisical","env":"staging",
                                           "path":"/backend","key":"PG_URL"}}}"#,
    );
    let route = config.infisical_routing().route("DATABASE_URL");
    assert_eq!(route.env.as_deref(), Some("staging"));
    assert_eq!(route.path, "/backend");
    assert_eq!(route.key, "PG_URL");
}

#[test]
fn a_declared_name_that_states_no_environment_gets_none() {
    // Not an error here — it is a route with nothing to look up, and the
    // adapter turns that into a refusal that spawns nothing.
    let config = parse(r#"{"secrets":{"DATABASE_URL":{"store":"infisical"}}}"#);
    assert_eq!(config.infisical_routing().route("DATABASE_URL").env, None);
}

#[test]
fn no_daemon_config_key_supplies_a_default_infisical_environment() {
    // The rule this whole adapter's daemon port rests on, asserted the way
    // `there_is_no_config_key_that_permits_interpreted_callers` asserts
    // its own: a future key spelled any of these ways is dropped by serde,
    // so what matters is that the PARSED config cannot express one and the
    // routing built from it hands an undeclared name no environment.
    //
    // Every spelling below is one somebody reaching for a default would
    // try, including the session config's own dead `stores.infisical.env`.
    let config = parse(
        r#"{"stores":{"infisical":{"env":"prod"},"env":"prod","default_env":"prod"},
                "env":"prod","infisical_env":"prod",
                "secrets":{"DECLARED":{"store":"infisical","env":"staging"}}}"#,
    );
    let rendered = serde_json::to_string(&config).expect("serialize");
    for spelling in ["prod", "default_env", "infisical_env"] {
        assert!(
            !rendered.contains(spelling),
            "`{spelling}` survived the parse: {rendered}"
        );
    }

    let routing = config.infisical_routing();
    // The negative control, and it is not decoration: without it every
    // assertion here would be satisfied by a routing that resolves nothing
    // at all, which is not the property being claimed.
    assert_eq!(routing.route("DECLARED").env.as_deref(), Some("staging"));
    assert_eq!(
        routing.route("A_NAME_NOBODY_EVER_DECLARED").env,
        None,
        "a name the daemon's config never declared must have no environment, \
             or it becomes a key lookup against a real vault"
    );
}

#[test]
fn an_undeclared_name_takes_the_vendors_own_folder_and_its_own_key() {
    // The other two coordinates ARE defaulted, and the asymmetry is the
    // point: a wrong folder can only miss inside an environment somebody
    // named, and with no environment the lookup never happens anyway.
    let route = parse("{}")
        .infisical_routing()
        .route("A_NAME_NOBODY_EVER_DECLARED");
    assert_eq!(route.path, "/");
    assert_eq!(route.key, "A_NAME_NOBODY_EVER_DECLARED");
}

#[test]
fn enabling_infisical_registers_it_and_leaves_the_other_stores_alone() {
    let config = parse(
        r#"{"stores":{"infisical":{"enabled":true,
                                       "binary":"/nonexistent/keyless-test/infisical"}},
                "secrets":{"DATABASE_URL":{"env":"staging"}}}"#,
    );
    let registry = config.registry(None);
    let ids: Vec<&str> = registry.stores().iter().map(|store| store.id()).collect();
    assert_eq!(ids, ["infisical"]);

    // The negative control: with the branch removed the registry is empty,
    // and an empty registry answers `not found in any store` — which reads
    // as a working lookup that came back empty rather than as an absent
    // adapter. Asking for the store id is what tells them apart.
    assert_eq!(parse("{}").registry(None).stores().len(), 0);
}

#[test]
fn an_undeclared_name_reaches_no_vendor_because_it_has_no_environment() {
    // The whole safety argument, at the level this file can assert it: the
    // binary does not exist, so a lookup that SPAWNED would report the
    // store unavailable. A refusal that names the missing environment is a
    // lookup that never happened. `tests/daemon_infisical.rs` proves the
    // absence of the spawn itself, against a stand-in that records its argv.
    let config = parse(
        r#"{"stores":{"infisical":{"enabled":true,
                                       "binary":"/nonexistent/keyless-test/infisical"}},
                "secrets":{"DECLARED":{"env":"staging"}}}"#,
    );
    let registry = config.registry(None);

    let invented = registry.resolve("A_NAME_NOBODY_EVER_DECLARED").reason();
    assert!(invented.contains("was not asked"), "{invented}");
    assert!(
        !invented.contains("unavailable"),
        "the vendor was reached for a name nobody declared: {invented}"
    );

    // And the control that stops the above being satisfied by a store that
    // cannot look anything up: a DECLARED name does reach for the binary.
    let declared = registry.resolve("DECLARED").reason();
    assert!(
        declared.contains("unavailable"),
        "a declared name must actually be looked up: {declared}"
    );
}

#[test]
fn an_infisical_store_with_no_environment_anywhere_is_warned_about() {
    let said = parse(
        r#"{"stores":{"infisical":{"enabled":true}},
                             "secrets":{"DATABASE_URL":{}}}"#,
    )
    .warnings()
    .join(" ");
    assert!(said.contains("no name can resolve against it"), "{said}");

    // The negative control: one name with an environment silences it.
    let quiet = parse(
        r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"infisical":{"enabled":true}},
                "secrets":{"DATABASE_URL":{"env":"staging"}}}"#,
    )
    .warnings();
    assert!(quiet.is_empty(), "{quiet:?}");
}

#[test]
fn keeping_the_vendor_login_in_the_served_secrets_file_is_warned_about() {
    // The arrangement that quietly undoes the point of moving the
    // credential behind the boundary: everything in the file store is a
    // name an attested client can ask for, so a machine identity kept
    // there is handed to any session that guesses its label.
    let config = parse(
        r#"{"stores":{"file":{"enabled":true,"path":"/tmp/keyless-test/secrets.json"},
                          "infisical":{"enabled":true,
                                       "credentials_file":"/tmp/keyless-test/secrets.json",
                                       "credentials":{"INFISICAL_TOKEN":"MACHINE_IDENTITY"}}},
                "secrets":{"DATABASE_URL":{"env":"staging","store":"infisical"}}}"#,
    );
    let said = config.warnings().join(" ");
    assert!(said.contains("same file the `file` store serves"), "{said}");
    assert!(said.contains("MACHINE_IDENTITY"), "{said}");

    // The negative control: a file of its own — the default arrangement —
    // says nothing. Without it the warning could be firing on every config
    // that names a credential at all.
    //
    // A machine identity rather than the access token above, because a
    // token draws a warning of its own about expiring and this control has
    // to be able to assert SILENCE.
    let separate = parse(
        r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"file":{"enabled":true,"path":"/tmp/keyless-test/secrets.json"},
                          "infisical":{"enabled":true,"default":"file",
                                       "credentials_file":"/tmp/keyless-test/infisical.json",
                                       "credentials":{
                            "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":"MACHINE_IDENTITY_CLIENT_ID",
                            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET":"MACHINE_IDENTITY_SECRET"}},
                          "default":"file"},
                "secrets":{"DATABASE_URL":{"env":"staging","store":"infisical"}}}"#,
    )
    .warnings();
    assert!(separate.is_empty(), "{separate:?}");
}

#[test]
fn a_credential_variable_outside_the_vendors_own_prefix_is_named_at_startup() {
    let said = parse(
        r#"{"stores":{"infisical":{"enabled":true,
                                       "credentials":{"PATH":"X","INFISICAL_TOKEN":"Y"}}},
                "secrets":{"DATABASE_URL":{"env":"staging"}}}"#,
    )
    .warnings()
    .join(" ");
    assert!(said.contains("not `INFISICAL_*`"), "{said}");
    assert!(said.contains("PATH"), "{said}");
    // The negative control, in the same sentence: the variable that IS the
    // vendor's own must not be listed as refused, or the warning is just
    // "you named credentials" and says nothing.
    assert!(
        !said.contains("INFISICAL_TOKEN"),
        "an accepted variable was reported as refused: {said}"
    );
}
