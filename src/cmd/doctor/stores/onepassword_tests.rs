use super::failing::remedy;
use super::points_at;
use super::remedy_tests::unavailable;
use crate::cmd::doctor::tests::loaded;

#[test]
fn a_proven_onepassword_row_names_the_vault_it_is_confined_to() {
    // The vault is the whole point of this backend, so a green row that
    // did not name it would certify the wrong thing: "1Password answered"
    // is true of every vault the login can see, and this store reads one.
    let load = loaded(
        r#"{"stores":{"onepassword":{"enabled":true,"vault":"company","account":"demo"}},
            "secrets":{}}"#,
    );
    let detail = points_at(&load.config, "onepassword");
    assert!(detail.contains("vault \"company\""), "{detail}");
    assert!(detail.contains("account demo"), "{detail}");

    // An empty vault is not a coordinate. The store refuses it as no vault
    // at all, so a row printing `vault ""` would be the report contradicting
    // the store it describes — and it reads as a vault whose name is blank
    // rather than as the config key nobody filled in.
    let load = loaded(r#"{"stores":{"onepassword":{"enabled":true,"vault":""}}}"#);
    let detail = points_at(&load.config, "onepassword");
    assert!(detail.contains("vault unset"), "{detail}");
    assert!(!detail.contains("vault \"\""), "{detail}");

    // With no account named, the row must not invent one: the CLI chose,
    // and which one it chose is a fact this report never read.
    let load = loaded(r#"{"stores":{"onepassword":{"enabled":true,"vault":"company"}}}"#);
    let detail = points_at(&load.config, "onepassword");
    assert!(detail.contains("chosen by the CLI"), "{detail}");

    let action = remedy(&load.config, "onepassword", &unavailable("onepassword"));
    assert!(action.contains("op signin"), "{action}");
    assert!(action.contains("stores.onepassword.vault"), "{action}");
    assert!(action.contains("stores.onepassword.account"), "{action}");
}
