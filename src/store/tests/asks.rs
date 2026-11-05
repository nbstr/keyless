//! `asks` — what `doctor` reads before a name is looked up.

use super::{Fixed, two_tenants};
use crate::store::{Registry, build, daemon};

#[test]
fn asks_answers_a_names_own_pin() {
    let registry = Registry::new(two_tenants()).with_routes(
        [("DATABASE_URL".to_owned(), "personal".to_owned())]
            .into_iter()
            .collect(),
    );
    assert_eq!(registry.asks("DATABASE_URL"), Some("personal"));
}

#[test]
fn asks_answers_the_default_store_when_unpinned() {
    let registry = Registry::new(two_tenants()).with_default_store(Some("personal".to_owned()));
    assert_eq!(registry.asks("DATABASE_URL"), Some("personal"));
}

#[test]
fn asks_answers_the_single_configured_backend() {
    let registry = Registry::new(vec![Box::new(Fixed {
        id: "a",
        value: Some("decoy"),
    })]);
    assert_eq!(registry.asks("X"), Some("a"));
}

#[test]
fn asks_answers_none_for_an_unpinned_name_with_several_backends() {
    // The shape `resolve` reports as `Ambiguous`: there is no single
    // backend to name, so `doctor` must not invent one either.
    let registry = Registry::new(two_tenants());
    assert_eq!(registry.asks("DATABASE_URL"), None);
}

#[test]
fn asks_answers_the_daemon_for_a_name_configs_own_pin_names_elsewhere() {
    // The defect this method exists to close: the config pins the name to
    // `proton`, but `build` suppresses every local backend and every
    // per-name pin the moment the daemon is enabled, so the lookup this
    // registry actually performs reaches the daemon. `asks` must read
    // that choice off the registry `resolve` will use, not off the
    // config's own pin.
    let config: crate::config::Config = serde_json::from_str(
        r#"{"stores":{"proton":{"enabled":true},"daemon":{"enabled":true}},
            "secrets":{"DATABASE_URL":{"store":"proton"}}}"#,
    )
    .expect("valid config");
    let built = build(&config, &crate::store::Invocation::default());
    assert_eq!(
        built.registry.asks("DATABASE_URL"),
        Some(daemon::DAEMON_STORE_ID)
    );
}
