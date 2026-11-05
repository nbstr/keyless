use super::parse;
use crate::config::Policy as StorePolicy;

#[test]
fn two_stores_with_no_default_are_warned_about_before_a_request_arrives() {
    // Otherwise the first anyone hears of it is a session degrading, with
    // a message about config keys nobody has been told belong to this file.
    let config = parse(
        r#"{"stores":{"file":{"enabled":true},
                          "keychain":{"enabled":true,"keychain":"/tmp/k.keychain-db"}}}"#,
    );
    let said = config.warnings().join(" ");
    assert!(said.contains("stores.default"), "{said}");
    assert!(said.contains("file"), "{said}");
    assert!(said.contains("keychain"), "{said}");
}

#[test]
fn a_default_store_silences_the_two_store_warning() {
    // The negative control for the test above: without it, that warning
    // could be firing on every two-store config regardless of routing.
    let config = parse(
        r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"file":{"enabled":true},
                          "keychain":{"enabled":true,"keychain":"/tmp/k.keychain-db"},
                          "default":"file"}}"#,
    );
    assert!(config.warnings().is_empty(), "{:?}", config.warnings());
}

#[test]
fn a_route_naming_a_store_that_is_not_enabled_is_warned_about() {
    let config = parse(
        r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"file":{"enabled":true}},
                "secrets":{"DATABASE_URL":{"store":"keychain"}}}"#,
    );
    let said = config.warnings().join(" ");
    assert!(said.contains("DATABASE_URL -> keychain"), "{said}");
}

#[test]
fn a_names_own_pin_decides_which_of_the_daemons_stores_answers() {
    // Both keys are read off the same file, and the name's own pin
    // outranks the default — the precedence the session config has, so a
    // route moved across the boundary keeps meaning what it meant.
    let config = parse(
        r#"{"stores":{"file":{"enabled":true},
                          "keychain":{"enabled":true,"keychain":"/tmp/k.keychain-db"},
                          "default":"keychain"},
                "secrets":{"DATABASE_URL":{"store":"file"}}}"#,
    );
    let registry = config.registry(None);
    assert_eq!(registry.stores().len(), 2);
    // The file store's path does not exist, so this cannot be a value; the
    // question is only WHICH store was asked, and a route to a store that
    // is not registered says `routed store is not configured`.
    for name in ["DATABASE_URL", "ANYTHING_ELSE"] {
        assert!(
            !registry
                .resolve(name)
                .reason()
                .contains("stores could answer"),
            "`{name}` was ambiguous despite a route covering it"
        );
    }
}

#[test]
fn the_store_policy_is_read_from_the_file_like_a_sessions_is() {
    let config = parse(
        r#"{"stores":{"file":{"enabled":true},
                          "keychain":{"enabled":true,"keychain":"/tmp/k.keychain-db"},
                          "policy":"ordered"}}"#,
    );
    assert_eq!(config.stores.policy, StorePolicy::Ordered);
    // Ordering never refuses to choose, so it is never ambiguous — and the
    // two-store warning is about ambiguity, so it does not fire.
    let said = config.warnings().join(" ");
    assert!(!said.contains("stores.default"), "{said}");
}
