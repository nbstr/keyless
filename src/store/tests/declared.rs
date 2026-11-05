//! "In a store" and "resolvable" are different states.

use super::Fixed;
use crate::store::Registry;

/// One healthy backend that holds nothing, told which names the config
/// declares.
fn empty_store_declaring(declared: &[&str]) -> Registry {
    Registry::new(vec![Box::new(Fixed {
        id: "a",
        value: None,
    })])
    .with_declared_names(declared.iter().map(|name| (*name).to_owned()).collect())
}

#[test]
fn a_name_the_config_never_declared_says_so_rather_than_reading_as_absent() {
    // The incident: a credential really was in the vault, under the right
    // item and the right field, and nothing had ever declared its name. The
    // absence message sent its reader to the store to look for something
    // the store was never asked about.
    let reason = empty_store_declaring(&["DECLARED"])
        .resolve("NEVER_DECLARED")
        .reason();
    assert!(
        reason.contains("not declared in your config"),
        "an undeclared name must say which file is missing the line: {reason}"
    );
    assert!(
        reason.contains("Declare it under \"secrets\""),
        "a diagnosis with no next action is the shape this report used to have: {reason}"
    );
    // The one thing it cannot know. Nothing was asked of any store on this
    // name's behalf beyond the name itself, so a store holding it under
    // some other coordinate is not a fact in evidence.
    assert!(
        !reason.contains("is in your store"),
        "the message claimed a store holds it: {reason}"
    );
}

#[test]
fn a_declared_name_that_no_store_holds_still_reads_as_a_plain_absence() {
    // The negative control for the test above. This name HAS a declaration,
    // so its coordinate was asked and came back empty — the store is the
    // right place to look, and this message is the one that says so. If
    // both cases start naming the config, the distinction is gone in the
    // other direction and this test is what notices.
    let reason = empty_store_declaring(&["DECLARED"])
        .resolve("DECLARED")
        .reason();
    assert_eq!(reason, "not found in any store");
}

#[test]
fn a_registry_given_no_declarations_claims_nothing_about_them() {
    // A registry built without the config's names — the daemon client, and
    // every caller that constructs one directly — cannot tell the two
    // states apart, and says the older, weaker thing rather than inventing
    // the stronger one.
    let reason = Registry::new(vec![Box::new(Fixed {
        id: "a",
        value: None,
    })])
    .resolve("NEVER_DECLARED")
    .reason();
    assert_eq!(reason, "not found in any store");
}
