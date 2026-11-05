use super::{SCOPED, SHARED_SECRETS, store_from};
use crate::config::Config;
use crate::store::Store;
use crate::store::proton::reason::Reason;
use crate::store::proton::routing::{Address, ItemAddress, Routing};
use crate::store::proton::store::ProtonStore;

#[test]
fn a_daemon_projects_a_name_onto_the_address_a_session_projects_it_onto() {
    // The two hosts of this adapter read two different config types. What
    // must not differ is which name has an address and which address it is:
    // a daemon that resolved a name the session refuses, or refused one it
    // resolves, would be a second answer to a question with one answer.
    //
    // Each side is compared against a WRITTEN-OUT address rather than
    // against the other. Comparing the two projections to each other is
    // satisfied by any change that moves both — including deleting the
    // rule that decides what an address is.
    let config: Config = serde_json::from_str(&format!(
        r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}"}}}},"secrets":{SHARED_SECRETS}}}"#
    ))
    .expect("valid config");
    let secrets: std::collections::BTreeMap<String, crate::config::SecretRoute> =
        serde_json::from_str(SHARED_SECRETS).expect("valid secrets");

    let session = Routing::from_config(&config);
    let daemon = Routing::from_secrets(&secrets);

    let expected: [(&str, Option<Address>); 4] = [
        (
            "BY_REFERENCE",
            Some(Address::Reference("pass://share/item/password".to_owned())),
        ),
        (
            "BY_NAME",
            Some(Address::Named(ItemAddress {
                vault: "company".to_owned(),
                item: "decoy".to_owned(),
                field: "password".to_owned(),
            })),
        ),
        // An entry that says nothing about Proton is ABSENT, not unusable:
        // the two have different remedies and a lookup reports different
        // sentences for them.
        ("NOT_PROTON", None),
        ("A_NAME_NOBODY_EVER_DECLARED", None),
    ];

    for (name, want) in &expected {
        assert_eq!(
            session.route(name).as_deref(),
            want.as_ref(),
            "session, `{name}`"
        );
        assert_eq!(
            daemon.route(name).as_deref(),
            want.as_ref(),
            "daemon, `{name}`"
        );
    }

    // The half-written one carries a sentence rather than a coordinate, so
    // the variant is what is pinned — on each side separately.
    assert!(matches!(
        session.route("HALF_WRITTEN").as_deref(),
        Some(Address::Unusable(_))
    ));
    assert!(matches!(
        daemon.route("HALF_WRITTEN").as_deref(),
        Some(Address::Unusable(_))
    ));
    assert_eq!(session.declared(), 3);
    assert_eq!(daemon.declared(), 3);
}

#[test]
fn a_store_built_from_parts_carries_no_session_directory_until_it_is_given_one() {
    // `new` is the daemon's constructor, and the one default it must not
    // have is a session directory: inheriting the ambient one resolves
    // every name against an identity nobody chose, which is the failure
    // mode that looks exactly like success. See `session_dir`.
    let secrets: std::collections::BTreeMap<String, crate::config::SecretRoute> =
        serde_json::from_str(SHARED_SECRETS).expect("valid secrets");
    let store = ProtonStore::new(
        std::path::PathBuf::from("/nonexistent/pass-cli"),
        std::path::PathBuf::from("/usr/bin/printenv"),
        Routing::from_secrets(&secrets),
        Reason::default(),
    );

    let error = store
        .resolve("BY_NAME")
        .expect_err("a store with no session directory must degrade");
    assert!(
        error.to_string().contains("session_dir"),
        "the fault named is not the missing session directory: {error}"
    );

    // And once it is given one, the same store reaches the address rather
    // than the precondition above — the control that keeps the assertion
    // from passing for any reason at all.
    let pointed = store.in_session_dir(Some(std::path::PathBuf::from(SCOPED)));
    assert!(matches!(
        pointed.resolve("A_NAME_NOBODY_EVER_DECLARED"),
        Ok(None)
    ));
}

// -----------------------------------------------------------------------
// The name form: what the config may say, and what it may not.
// -----------------------------------------------------------------------

/// A store whose config declares `X` with `extra`, scoped and un-runnable.
///
/// The binary does not exist, so any test below that reaches a spawn fails
/// loudly instead of quietly asserting on the wrong error.
fn store_with_route(extra: &str) -> ProtonStore {
    store_from(&format!(
        r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}",
                                   "binary":"/nonexistent/keyless-test/pass-cli"}}}},
            "secrets":{{"X":{{{extra}}}}}}}"#
    ))
}

#[test]
fn declaring_both_an_address_and_a_reference_is_refused_rather_than_ranked() {
    // Two answers to one question. Picking whichever this build happens to
    // prefer is how the wrong item gets read with nothing said — the same
    // failure `Policy::Explicit` refuses for two backends and one name.
    let store = store_with_route(
        r#""reference":"pass://S/I/password","vault":"personal","item":"decoy","field":"password""#,
    );
    let message = store
        .resolve("X")
        .expect_err("a doubly-declared address must not resolve")
        .to_string();
    assert!(message.contains("reference"), "{message}");
    assert!(message.contains("vault"), "{message}");
}

#[test]
fn a_half_written_name_form_names_every_part_that_is_missing() {
    // None of the three is inferable, so a partial entry is a refusal with
    // a list rather than a guess. An empty string counts as missing.
    let store = store_with_route(r#""vault":"personal","field":"""#);
    let message = store
        .resolve("X")
        .expect_err("an incomplete address must not resolve")
        .to_string();
    assert!(message.contains("item"), "{message}");
    assert!(message.contains("field"), "{message}");
    assert!(
        !message.contains("vault,"),
        "the part that WAS given was reported missing: {message}"
    );
}

#[test]
fn a_field_containing_a_slash_is_refused_before_it_becomes_an_address() {
    // `pass://SHARE/ITEM/a/b` moves the boundary: the CLI would be handed a
    // different address than the one written down, and it would look fine.
    let store = store_with_route(r#""vault":"personal","item":"decoy","field":"a/b""#);
    let message = store
        .resolve("X")
        .expect_err("a field with a separator in it must not resolve")
        .to_string();
    assert!(message.contains('/'), "{message}");
    assert!(message.contains("field"), "{message}");
}

#[test]
fn a_complete_name_form_is_an_address_and_a_reference_is_taken_verbatim() {
    // The negative control for the three refusals above: without it they
    // could all pass on a parser that accepts nothing at all.
    let named: crate::config::SecretRoute =
        serde_json::from_str(r#"{"vault":"personal","item":"decoy alpha","field":"password"}"#)
            .expect("valid route");
    let Some(Address::Named(address)) = Address::from_route(&named) else {
        panic!("a complete name form is not an address");
    };
    assert_eq!(
        (
            address.vault.as_str(),
            address.item.as_str(),
            address.field.as_str()
        ),
        ("personal", "decoy alpha", "password")
    );

    let referenced: crate::config::SecretRoute =
        serde_json::from_str(r#"{"reference":"pass://S/I/password"}"#).expect("valid route");
    assert!(matches!(
        Address::from_route(&referenced),
        Some(Address::Reference(reference)) if reference == "pass://S/I/password"
    ));

    let silent: crate::config::SecretRoute =
        serde_json::from_str(r#"{"account":"demo-token"}"#).expect("valid route");
    assert_eq!(Address::from_route(&silent), None);
}

// -----------------------------------------------------------------------
// The listing that turns a name into this session's ids.
// -----------------------------------------------------------------------
