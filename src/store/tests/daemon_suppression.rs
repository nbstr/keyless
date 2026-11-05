//! The daemon suppresses every local backend, not just the keychain.

use crate::store::{Invocation, build};

fn config_from(json: &str) -> crate::config::Config {
    serde_json::from_str(json).expect("valid config")
}

/// The registered backend ids, and everything the build had to say —
/// both channels joined, because these tests are about *whether it was
/// said*, not about which stream it went to.
fn registered(config: &crate::config::Config) -> (Vec<String>, Vec<String>) {
    let built = build(config, &Invocation::default());
    let ids = built
        .registry
        .stores()
        .iter()
        .map(|store| store.id().to_owned())
        .collect();
    let mut said = built.warnings;
    said.extend(built.notes);
    (ids, said)
}

#[test]
fn enabling_the_daemon_suppresses_every_local_backend() {
    // Invariant: killing the daemon must yield fewer secrets, never more.
    // Each of these three resolves through a credential the calling user
    // already holds, so any one of them left registered is a local
    // fallback that opens the moment the daemon stops.
    let (ids, warnings) = registered(&config_from(
        r#"{"stores":{"keychain":{"enabled":true},
                      "infisical":{"enabled":true},
                      "onepassword":{"enabled":true},
                      "proton":{"enabled":true},
                      "daemon":{"enabled":true}}}"#,
    ));
    assert_eq!(ids, ["daemon"]);
    let said = warnings.join(" ");
    for backend in ["keychain", "infisical", "onepassword", "proton"] {
        assert!(
            said.contains(backend),
            "dropping {backend} must be said out loud: {said}"
        );
    }
}

#[test]
fn the_suppression_warning_says_where_a_suppressed_backends_names_can_go() {
    // A suppression is only actionable if the sentence says what to do
    // next, and the three backends have DIFFERENT next steps: an Infisical
    // name needs an "env" beside it, a 1Password name needs the vault and a
    // service account scoped to it, and a Proton name needs a session
    // directory the daemon owns. One sentence covering all three would have
    // to be wrong about two of them.
    let infisical_only = registered(&config_from(
        r#"{"stores":{"infisical":{"enabled":true},"daemon":{"enabled":true}}}"#,
    ))
    .1
    .join(" ");
    assert!(
        infisical_only.contains("keylessd.json"),
        "an Infisical name has somewhere to go and the warning must name it: {infisical_only}"
    );
    assert!(
        !infisical_only.contains("does not carry"),
        "the adapter exists, so this must not say it does not: {infisical_only}"
    );

    let proton_only = registered(&config_from(
        r#"{"stores":{"proton":{"enabled":true},"daemon":{"enabled":true}}}"#,
    ))
    .1
    .join(" ");
    assert!(
        proton_only.contains("keylessd.json"),
        "a Proton name has somewhere to go and the warning must name it: {proton_only}"
    );
    assert!(
        proton_only.contains("session_dir"),
        "a daemon has no ambient Proton login, so the sentence must say where its \
         own one lives: {proton_only}"
    );
    assert!(
        !proton_only.contains("does not carry"),
        "the adapter exists, so this must not say it does not: {proton_only}"
    );

    // A 1Password name moves too, and the sentence has to say the two
    // things a daemon needs that a session did not: the same vault, and a
    // login of its own.
    let onepassword_only = registered(&config_from(
        r#"{"stores":{"onepassword":{"enabled":true},"daemon":{"enabled":true}}}"#,
    ))
    .1
    .join(" ");
    assert!(
        onepassword_only.contains("keylessd.json"),
        "{onepassword_only}"
    );
    assert!(
        onepassword_only.contains("service account"),
        "{onepassword_only}"
    );
    assert!(onepassword_only.contains("\"vault\""), "{onepassword_only}");
    assert!(
        !onepassword_only.contains("does not carry"),
        "{onepassword_only}"
    );

    // All at once: each keeps its own instruction rather than one being
    // flattened into another's.
    let all = registered(&config_from(
        r#"{"stores":{"infisical":{"enabled":true},"onepassword":{"enabled":true},
                      "proton":{"enabled":true},"daemon":{"enabled":true}}}"#,
    ))
    .1
    .join(" ");
    assert!(all.contains("keylessd.json"), "{all}");
    assert!(all.contains("the Infisical ones"), "{all}");
    assert!(all.contains("the 1Password ones"), "{all}");
    assert!(all.contains("the Proton ones"), "{all}");
    assert!(!all.contains("does not carry"), "{all}");
}

#[test]
fn without_the_daemon_every_configured_backend_is_registered() {
    // The negative control. Without it the test above could pass because
    // these backends are never registered under any configuration.
    let (ids, warnings) = registered(&config_from(
        r#"{"stores":{"keychain":{"enabled":true},
                      "infisical":{"enabled":true},
                      "onepassword":{"enabled":true},
                      "proton":{"enabled":true}}}"#,
    ));
    assert_eq!(ids, ["keychain", "infisical", "onepassword", "proton"]);
    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn the_daemon_drops_per_name_store_pins_and_names_them() {
    // A pin left in place would name a backend that is no longer
    // registered, so the name would degrade with `routed store is not
    // configured` — pointing the reader at a store their config plainly
    // enables. Routing is the daemon's decision now.
    let config = config_from(
        r#"{"stores":{"infisical":{"enabled":true},"daemon":{"enabled":true}},
            "secrets":{"DATABASE_URL":{"store":"infisical"}}}"#,
    );
    let built = build(&config, &Invocation::default());
    assert!(
        built
            .warnings
            .iter()
            .any(|w| w.contains("DATABASE_URL -> infisical")),
        "{:?}",
        built.warnings
    );

    // And the name reaches the daemon rather than dying on the stale pin.
    // The socket does not exist, so this fails — but it must fail as an
    // unreachable daemon, never as an unconfigured route.
    let reason = built.registry.resolve("DATABASE_URL").reason();
    assert!(
        !reason.contains("routed store is not configured"),
        "the stale pin survived: {reason}"
    );
}

#[test]
fn a_pin_that_names_the_daemon_survives() {
    let config = config_from(
        r#"{"stores":{"daemon":{"enabled":true}},
            "secrets":{"DATABASE_URL":{"store":"daemon"}}}"#,
    );
    let built = build(&config, &Invocation::default());
    // No WARNING: nothing the user asked for was dropped. The keychain
    // note is a `doctor` line and does not belong on every run.
    assert!(built.warnings.is_empty(), "{:?}", built.warnings);
    assert!(
        !built
            .registry
            .resolve("DATABASE_URL")
            .reason()
            .contains("routed store is not configured")
    );
}

#[test]
fn a_default_store_the_daemon_suppresses_is_dropped_and_named() {
    let config = config_from(
        r#"{"stores":{"keychain":{"enabled":true},"daemon":{"enabled":true},
                      "default":"keychain"}}"#,
    );
    let built = build(&config, &Invocation::default());
    assert!(
        built.warnings.iter().any(|w| w.contains("stores.default")),
        "{:?}",
        built.warnings
    );
    // One store is registered, so an unpinned name reaches it rather than
    // failing on a default that names something suppressed.
    assert!(
        !built
            .registry
            .resolve("ANY")
            .reason()
            .contains("routed store is not configured")
    );
}
