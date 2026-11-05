//! Explicit — the default.

use super::{Broken, Fixed, two_tenants};
use crate::store::{Registry, Resolution};

#[test]
fn an_unpinned_name_with_two_backends_is_ambiguous_rather_than_guessed() {
    // The whole reason this policy exists. Whichever value came back here
    // would be right half the time and silent the other half.
    let registry = Registry::new(two_tenants());
    match registry.resolve("DATABASE_URL") {
        Resolution::Ambiguous { candidates } => {
            assert_eq!(candidates, ["company", "personal"]);
        }
        Resolution::Found { .. } => panic!("a wrong store's value was returned silently"),
        _ => panic!("expected Ambiguous"),
    }
}

#[test]
fn the_ambiguous_reason_names_the_candidates_and_carries_no_value() {
    let registry = Registry::new(two_tenants());
    let reason = registry.resolve("DATABASE_URL").reason();
    assert!(reason.contains("company"));
    assert!(reason.contains("personal"));
    assert!(!reason.contains("decoy-"), "the reason leaked a value");
}

#[test]
fn a_pinned_name_reaches_exactly_the_store_it_names() {
    let registry = Registry::new(two_tenants()).with_routes(
        [("DATABASE_URL".to_owned(), "personal".to_owned())]
            .into_iter()
            .collect(),
    );
    match registry.resolve("DATABASE_URL") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), "decoy-personal-value"),
        _ => panic!("a pinned name must resolve"),
    }
}

#[test]
fn a_pinned_name_does_not_fall_back_when_its_store_lacks_it() {
    // Falling through to the other backend here would produce exactly the
    // cross-tenant value the pin was written to prevent.
    let registry = Registry::new(vec![
        Box::new(Fixed {
            id: "company",
            value: None,
        }),
        Box::new(Fixed {
            id: "personal",
            value: Some("decoy-personal-value"),
        }),
    ])
    .with_routes(
        [("DATABASE_URL".to_owned(), "company".to_owned())]
            .into_iter()
            .collect(),
    );
    assert!(matches!(
        registry.resolve("DATABASE_URL"),
        Resolution::NotFound { .. }
    ));
}

#[test]
fn a_pinned_name_does_not_fall_back_when_its_store_is_broken() {
    let registry = Registry::new(vec![
        Box::new(Broken("company")),
        Box::new(Fixed {
            id: "personal",
            value: Some("decoy-personal-value"),
        }),
    ])
    .with_routes(
        [("DATABASE_URL".to_owned(), "company".to_owned())]
            .into_iter()
            .collect(),
    );
    match registry.resolve("DATABASE_URL") {
        Resolution::Failed(errors) => assert_eq!(errors.len(), 1),
        Resolution::Found { .. } => panic!("a broken pin fell through to another tenant"),
        _ => panic!("expected Failed"),
    }
}

#[test]
fn the_default_store_answers_unpinned_names() {
    let registry = Registry::new(two_tenants()).with_default_store(Some("personal".to_owned()));
    match registry.resolve("DATABASE_URL") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), "decoy-personal-value"),
        _ => panic!("the declared default must answer"),
    }
}

#[test]
fn a_names_own_pin_outranks_the_default_store() {
    let registry = Registry::new(two_tenants())
        .with_default_store(Some("personal".to_owned()))
        .with_routes(
            [("DATABASE_URL".to_owned(), "company".to_owned())]
                .into_iter()
                .collect(),
        );
    match registry.resolve("DATABASE_URL") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), "decoy-company-value"),
        _ => panic!("the name's own pin must win"),
    }
}

#[test]
fn a_single_backend_needs_no_pin() {
    // The one-store setup — every existing user — is unchanged.
    let registry = Registry::new(vec![Box::new(Fixed {
        id: "a",
        value: Some("decoy-only-store"),
    })]);
    assert!(registry.resolve("X").is_found());
}

#[test]
fn a_route_to_an_absent_backend_fails_loudly() {
    let registry = Registry::new(vec![Box::new(Fixed {
        id: "a",
        value: Some("decoy"),
    })])
    .with_routes(
        [("X".to_owned(), "nowhere".to_owned())]
            .into_iter()
            .collect(),
    );
    match registry.resolve("X") {
        Resolution::Failed(errors) => assert_eq!(errors.len(), 1),
        _ => panic!("a route to a missing backend must not silently fall through"),
    }
}

#[test]
fn a_default_store_that_is_not_configured_fails_loudly() {
    let registry = Registry::new(vec![Box::new(Fixed {
        id: "a",
        value: Some("decoy"),
    })])
    .with_default_store(Some("nowhere".to_owned()));
    assert!(matches!(registry.resolve("X"), Resolution::Failed(_)));
}

#[test]
fn every_backend_healthy_and_empty_reports_notfound() {
    let registry = Registry::new(vec![Box::new(Fixed {
        id: "a",
        value: None,
    })]);
    assert!(matches!(registry.resolve("X"), Resolution::NotFound { .. }));
}

#[test]
fn an_empty_registry_reports_no_store_enabled_rather_than_an_absence() {
    let registry = Registry::new(Vec::new());
    assert!(matches!(
        registry.resolve("X"),
        Resolution::Failed(errors) if errors[0].to_string().contains("no store is enabled")
    ));
    assert!(registry.is_empty());
}
