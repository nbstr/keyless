use super::route;
use crate::store::proton_manager::ProtonManager;

#[test]
fn a_half_written_config_entry_names_every_part_that_is_missing() {
    let error = ProtonManager::address("X", &route(r#"{"vault":"personal"}"#))
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(error.contains("item"), "{error}");
    assert!(error.contains("field"), "{error}");
}

#[test]
fn a_reference_only_entry_is_refused_because_it_addresses_something_that_exists() {
    let error = ProtonManager::address("X", &route(r#"{"reference":"pass://S/I/password"}"#))
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(error.contains("already exists"), "{error}");
}

#[test]
fn a_complete_entry_is_an_address() {
    // The negative control for the two refusals above: without it, both could
    // pass on an `address` that accepts nothing at all.
    let address = ProtonManager::address(
        "X",
        &route(r#"{"vault":"personal","item":"d","field":"password"}"#),
    )
    .expect("a complete entry");
    assert_eq!(address.vault, "personal");
    assert_eq!(address.field, "password");
}

#[test]
fn a_field_with_a_separator_is_refused_before_anything_is_created() {
    let error = ProtonManager::address("X", &route(r#"{"vault":"c","item":"d","field":"a/b"}"#))
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(error.contains('/'), "{error}");
}
