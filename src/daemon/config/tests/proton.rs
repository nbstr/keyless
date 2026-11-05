use super::parse;
use crate::daemon::config::DaemonConfig;
use std::path::Path;

#[test]
fn the_daemon_config_builds_generations_only_where_proton_names_a_root() {
    assert!(
        parse("{}").generations().is_none(),
        "a config with no Proton store built a generation layout"
    );
    assert!(
        parse(r#"{"stores":{"proton":{"enabled":true}}}"#)
            .generations()
            .is_none(),
        "an enabled store with no session_dir built a generation layout"
    );
    assert!(
        parse(r#"{"stores":{"proton":{"session_dir":"/tmp/kl-gen"}}}"#)
            .generations()
            .is_none(),
        "a session_dir with the store not enabled built a generation layout"
    );

    let generations =
        parse(r#"{"stores":{"proton":{"enabled":true,"session_dir":"/tmp/kl-gen-root"}}}"#)
            .generations()
            .expect("enabled and session_dir together must build one");
    assert_eq!(generations.root(), Path::new("/tmp/kl-gen-root"));
}

#[test]
fn the_key_provider_that_forces_a_logout_cannot_be_written_into_a_config() {
    // `keyring` is the vendor's default and the one value a daemon must
    // never use: its uid has no login keychain, `pass-cli` answers a
    // missing local key beside an existing session store by reinitialising
    // that store, and a session store that is reinitialised on every
    // lookup is a store that never works and quietly destroys what it
    // replaces. So it is a parse error rather than a warning, which on a
    // daemon means the process refuses to start.
    let refused = serde_json::from_str::<DaemonConfig>(
        r#"{"stores":{"proton":{"enabled":true,"key_provider":"keyring"}}}"#,
    )
    .expect_err("`keyring` must not parse");
    let said = refused.to_string();
    assert!(
        said.contains("FORCING A LOGOUT"),
        "the refusal does not say what `keyring` does here: {said}"
    );

    // The control: both accepted values parse, so the assertion above is
    // about this one word and not about the field being unreadable.
    for word in ["fs", "env"] {
        let config = parse(&format!(
            r#"{{"stores":{{"proton":{{"enabled":true,"key_provider":"{word}"}}}}}}"#
        ));
        assert_eq!(config.stores.proton.key_provider.as_str(), word);
    }

    // And the default is `env`, so a config that says nothing is not
    // silently the vendor's `keyring` default — see `KeyProvider`'s own
    // doc for why `env` rather than `fs` is that default now.
    assert_eq!(parse("{}").stores.proton.key_provider.as_str(), "env");
}

#[test]
fn a_proton_name_is_routed_only_where_the_daemons_own_config_declares_it() {
    // A daemon-hosted Proton lookup reaches exactly the vault, item and
    // field an operator wrote in a file the calling user cannot write.
    // Nothing is defaulted, so a name that appears nowhere has no address
    // at all — which is what makes an invented name cost no vendor process.
    let config = parse(
        r#"{"stores":{"proton":{"enabled":true}},
                "secrets":{"DECLARED":{"store":"proton","vault":"company",
                                       "item":"decoy","field":"password"},
                           "ELSEWHERE":{"store":"keychain"}}}"#,
    );
    let routing = config.proton_routing();

    // Counted, not tested for emptiness: `ELSEWHERE` says nothing about
    // Proton and must not be projected, and a `> 0` check cannot see that.
    assert_eq!(routing.declared(), 1);
}

#[test]
fn the_daemon_has_no_second_proton_identity_for_writes() {
    // The session config carries a `manager` block — an editor-role token
    // the write verbs use. There is deliberately no counterpart here:
    // `store::manage` refuses every write under a daemon, so an editor
    // token in the daemon's file would be a larger prize with no way to be
    // used. A key added later would be dropped by serde in silence, so the
    // check is that the parsed config cannot express one.
    let config = parse(
        r#"{"stores":{"proton":{"enabled":true,
                                    "manager":{"session_dir":"/nonexistent/manager"}}}}"#,
    );
    let rendered = serde_json::to_string(&config).expect("serialize");
    assert!(!rendered.contains("manager"), "{rendered}");
}
