//! What a miss is told: the names it might have meant, never a coordinate.

use super::fixtures::{advice, field, indexed, item, key_of};
use keyless::store::catalogue::{ProtonMint, Route};
use std::collections::BTreeMap;

#[test]
fn a_miss_on_a_known_item_names_every_name_that_item_serves() {
    // The case that has no other route: an accented field label mints a name no
    // caller derives from anything they hold — on the live machine, a French
    // one. Naming the item's whole minted set is the answer, and it is names
    // only, never the field's own spelling.
    let summary = item("decoy-db-alpha");
    let catalogue = indexed(&BTreeMap::new(), std::slice::from_ref(&summary));
    let key = key_of(&summary);
    catalogue.install_view(
        &key,
        &ProtonMint,
        &summary,
        &[field("Réf décoy"), field("password")],
    );

    let said = advice(&catalogue, "DECOY_DB_ALPHA__REF");
    assert!(said.contains("DECOY_DB_ALPHA__R_F_D_COY"), "{said}");
    assert!(said.contains("DECOY_DB_ALPHA"), "{said}");
    // Names only: not the field's own spelling, and not the vault.
    assert!(!said.contains("Réf décoy"), "{said}");
    assert!(!said.contains("personal"), "{said}");
}

#[test]
fn a_miss_on_nothing_recognisable_offers_the_nearest_names_and_an_age() {
    let catalogue = indexed(
        &BTreeMap::new(),
        &[
            item("decoy-token"),
            item("decoy-pat"),
            item("other-token"),
            item("unrelated"),
        ],
    );

    let said = advice(&catalogue, "DECOY_TOKE");
    assert!(said.contains("DECOY_TOKEN"), "{said}");
    assert!(
        said.contains("ago"),
        "the index's age is part of the answer: {said}"
    );
    assert!(
        !said.contains("UNRELATED"),
        "a name sharing nothing is noise: {said}"
    );
}

#[test]
fn a_name_that_normalises_to_nothing_served_degrades_and_names_the_form_it_tried() {
    let catalogue = indexed(&BTreeMap::new(), &[item("decoy-token")]);

    assert!(matches!(
        catalogue.route("no-such-item"),
        Route::Unknown { .. }
    ));
    let said = advice(&catalogue, "no-such-item");
    assert!(said.contains("tried `NO_SUCH_ITEM`"), "{said}");

    // A name looked up as sent gets the sentence it always got.
    let unchanged = advice(&catalogue, "NO_SUCH_ITEM");
    assert!(!unchanged.contains("tried"), "{unchanged}");
}
