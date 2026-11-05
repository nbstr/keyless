//! Ordered — opt-in, and only safe when every backend is one tenant.

use super::{Broken, Fixed, two_tenants};
use crate::config::Policy;
use crate::store::{Registry, Resolution};

#[test]
fn the_first_backend_with_a_value_wins_when_ordering_is_asked_for() {
    let registry = Registry::new(vec![
        Box::new(Fixed {
            id: "a",
            value: None,
        }),
        Box::new(Fixed {
            id: "b",
            value: Some("decoy-from-b"),
        }),
    ])
    .with_policy(Policy::Ordered);
    match registry.resolve("X") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), "decoy-from-b"),
        _ => panic!("expected a value"),
    }
}

#[test]
fn a_failing_backend_does_not_hide_a_later_hit_when_ordering_is_asked_for() {
    let registry = Registry::new(vec![
        Box::new(Broken("down")),
        Box::new(Fixed {
            id: "b",
            value: Some("decoy-still-found"),
        }),
    ])
    .with_policy(Policy::Ordered);
    assert!(registry.resolve("X").is_found());
}

#[test]
fn all_backends_erroring_reports_failed_not_notfound() {
    let registry = Registry::new(vec![Box::new(Broken("one")), Box::new(Broken("two"))])
        .with_policy(Policy::Ordered);
    match registry.resolve("X") {
        Resolution::Failed(errors) => assert_eq!(errors.len(), 2),
        _ => panic!("expected Failed"),
    }
}

#[test]
fn ordering_never_reports_ambiguity_because_it_never_refuses_to_choose() {
    let registry = Registry::new(two_tenants()).with_policy(Policy::Ordered);
    assert!(registry.resolve("DATABASE_URL").is_found());
}
