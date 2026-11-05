use super::KNOWN;
use super::body::render;

#[test]
fn a_written_config_parses_as_a_config() {
    // The one property that makes the whole verb worth having: what it
    // writes must be loadable by the thing that reads it. A hand-built JSON
    // string is exactly the kind of output that looks right and is not.
    for chosen in KNOWN {
        let body = render(chosen);
        let config: crate::config::Config =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("{chosen}: {e}\n{body}"));
        assert_eq!(
            config.stores.default_store.as_deref(),
            Some(chosen),
            "{body}"
        );
        assert!(config.secrets.is_empty(), "{body}");
    }
}

#[test]
fn the_written_config_enables_exactly_the_chosen_backend() {
    // Without this, the test above passes on a renderer that turns every
    // backend on — which would put an unpinned name back into the ambiguity
    // `stores.default` exists to remove.
    let config: crate::config::Config = serde_json::from_str(&render("keychain")).expect("valid");
    assert!(config.stores.keychain.enabled);
    assert!(!config.stores.infisical.enabled);
    assert!(!config.stores.onepassword.enabled);
    assert!(!config.stores.proton.enabled);
}

#[test]
fn nothing_init_writes_can_hold_a_value() {
    // The standing invariant, asserted against this verb's own output. The
    // config format has no field a value fits in, and this test exists so
    // that adding one is visibly a breaking change here.
    //
    // Matched as a JSON KEY rather than as a bare substring, because a
    // store section is not a value field: `"onepassword": {` names a
    // backend, and a substring check on `password` refused it. The key
    // form still catches the thing this exists for — a `"password":` or
    // `"value":` that a value could sit behind.
    for chosen in KNOWN {
        let body = render(chosen);
        for forbidden in ["\"value\":", "\"secret\":", "\"password\":", "\"token\":"] {
            assert!(
                !body.contains(forbidden),
                "`init` wrote a `{forbidden}` field:\n{body}"
            );
        }
    }
    // The control: the key form is still a check. A body that DID carry a
    // value field is refused by it.
    assert!(
        r#"{"secrets":{"A":{"password":"x"}}}"#.contains("\"password\":"),
        "the key-form check stopped matching a value field"
    );
}
