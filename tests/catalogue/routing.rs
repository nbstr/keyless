//! Where a name routes: declared, minted, ambiguous, or unknown.

use super::fixtures::{advice, field, indexed, item, item_at, key_of};
use keyless::config::SecretRoute;
use keyless::store::catalogue::naming::{mint, mint_bare};
use keyless::store::catalogue::{Catalogue, ProtonMint, Provenance, Route};
use std::collections::BTreeMap;

#[test]
fn a_normalised_title_containing_the_joiner_is_still_inverted_correctly() {
    // `foo (bar)` mints `FOO__BAR_`, which CONTAINS the joiner. Splitting a
    // missed name on `__` would read this as item `FOO` with field `BAR_`, and
    // would do it silently on exactly the titles a caller cannot guess.
    assert_eq!(mint_bare("foo (bar)").as_deref(), Some("FOO__BAR_"));

    let catalogue = indexed(&BTreeMap::new(), &[item("foo (bar)"), item("foo")]);

    let inverted = catalogue
        .invert("FOO__BAR___USERNAME")
        .expect("the longest matching bare name");
    assert_eq!(inverted.title, "foo (bar)");

    // And the shorter title still claims its own fields.
    let shorter = catalogue.invert("FOO__USERNAME").expect("an inversion");
    assert_eq!(shorter.title, "foo");
}

#[test]
fn two_items_that_mint_one_name_leave_it_ambiguous_on_both_sides() {
    let catalogue = indexed(
        &BTreeMap::new(),
        &[item("my-key"), item("My Key"), item("other-key")],
    );

    match catalogue.route("MY_KEY") {
        Route::Ambiguous { stores, items } => {
            assert_eq!(items, 2);
            assert_eq!(stores, ["proton"]);
        }
        other => panic!("a name two items mint must not route anywhere: {other:?}"),
    }

    // Reported as store ids and a count. The colliding TITLES are coordinates
    // and stay on the daemon's side; `keylessd check` is where they may appear.
    let said = advice(&catalogue, "MY_KEY");
    assert!(!said.contains("my-key"), "{said}");
    assert!(!said.contains("My Key"), "{said}");

    // A title spelling that mints the colliding name is refused the same way,
    // never guessed, and says which name it was refused under.
    match catalogue.route("my-key") {
        Route::Ambiguous { items, .. } => assert_eq!(items, 2),
        other => panic!("a title spelling of a colliding name must not route: {other:?}"),
    }
    let said = advice(&catalogue, "my-key");
    assert!(
        said.contains("tried `MY_KEY`") && said.contains("is minted by"),
        "{said}"
    );

    // A non-colliding name from the same listing is unaffected — without this
    // the test would pass on an index that refused everything.
    assert!(
        matches!(catalogue.route("OTHER_KEY"), Route::Known(_)),
        "the collision must not spread"
    );

    // And an ambiguous name is not offered in the listing: the daemon refuses
    // it, so a listing that promised it would disagree with the resolver.
    assert!(!catalogue.names().contains(&"MY_KEY".to_owned()));
    assert!(catalogue.names().contains(&"OTHER_KEY".to_owned()));
}

#[test]
fn a_declaration_answers_before_anything_the_vault_mints() {
    let mut secrets = BTreeMap::new();
    secrets.insert(
        "DEMO_API_KEY".to_owned(),
        serde_json::from_str(r#"{"store":"keychain","account":"acct-name"}"#).expect("valid"),
    );
    let catalogue = indexed(&secrets, &[item("demo api key")]);

    match catalogue.route("DEMO_API_KEY") {
        Route::Known(entry) => assert_eq!(entry.store, "keychain"),
        other => panic!("the declaration must win: {other:?}"),
    }
}

#[test]
fn a_trashed_item_mints_no_name() {
    // A trashed item resolves through a `pass://` reference and is refused by
    // title, so a name minted for one would list and never resolve.
    let mut binned = item("gone");
    binned.state = "Trashed".to_owned();
    let catalogue = indexed(&BTreeMap::new(), &[binned]);
    assert!(catalogue.names().is_empty(), "{:?}", catalogue.names());
}

#[test]
fn an_empty_index_serves_exactly_the_declared_set() {
    let mut secrets = BTreeMap::new();
    secrets.insert(
        "DECLARED".to_owned(),
        serde_json::from_str("{}").expect("valid"),
    );
    let catalogue = Catalogue::new(&secrets);
    assert_eq!(catalogue.names(), ["DECLARED"]);
    assert_eq!(catalogue.indexed_at(), None);
}

#[test]
fn two_live_items_sharing_one_title_clash_rather_than_one_of_them_vanishing() {
    // The collision an `ItemKey` cannot tell apart: it is `(store, vault,
    // title)` and carries no item id, so two live items with one title in one
    // vault arrive with EQUAL keys. Folded as "the same item again" they mint a
    // `Sole` name — which `ProtonStore::reference_for` then refuses by name,
    // reporting "N live items in vault X are titled Y". A listing that promised
    // it would be a listing that disagrees with the resolver.
    let catalogue = indexed(
        &BTreeMap::new(),
        &[
            item_at("It3mOne", "decoy"),
            item_at("It3mTwo", "decoy"),
            item("demo login"),
        ],
    );

    match catalogue.route("DECOY") {
        Route::Ambiguous { stores, items } => {
            // Two, and they are two because `ItemKey` carries the backend's
            // own id. Keyed on the title alone they would be one key, and the
            // second would vanish into the first.
            assert_eq!(items, 2);
            assert_eq!(stores, ["proton"]);
        }
        other => panic!("two items sharing a title must not route: {other:?}"),
    }
    assert!(!catalogue.names().contains(&"DECOY".to_owned()));
    // The control: a title held by one item is unaffected.
    assert!(catalogue.names().contains(&"DEMO_LOGIN".to_owned()));
}

#[test]
fn a_title_spelled_name_routes_to_what_its_minted_form_serves() {
    // A caller who passed the item's own title, not the name it mints.
    let catalogue = indexed(&BTreeMap::new(), &[item("nexus-linear")]);

    match (
        catalogue.route("nexus-linear"),
        catalogue.route("NEXUS_LINEAR"),
    ) {
        (Route::Known(by_title), Route::Known(by_minted)) => {
            assert_eq!(by_title.route.item, by_minted.route.item);
            assert_eq!(by_title.route.vault, by_minted.route.vault);
            assert_eq!(by_title.route.field, by_minted.route.field);
        }
        other => panic!("both spellings must route to the same entry: {other:?}"),
    }
}

#[test]
fn a_declaration_answers_to_its_title_spelling_and_the_spelling_as_sent_wins() {
    let mut secrets = BTreeMap::new();
    for (name, item) in [("DEMO_LOGIN", "demo login"), ("demo-token", "demo token")] {
        secrets.insert(
            name.to_owned(),
            serde_json::from_str::<SecretRoute>(&format!(
                r#"{{"store":"proton","vault":"personal","item":"{item}","field":"password"}}"#
            ))
            .expect("valid"),
        );
    }
    // `DEMO_TOKEN` is also minted by the vault, so an operator's own spelling
    // has to be asked before the one it normalises to.
    let catalogue = indexed(&secrets, &[item("demo-token")]);

    match catalogue.route("demo-login") {
        Route::Known(entry) => {
            assert_eq!(entry.provenance, Provenance::Declared);
            assert_eq!(entry.route.item.as_deref(), Some("demo login"));
        }
        other => panic!("a declaration must answer to its title spelling: {other:?}"),
    }
    match catalogue.route("demo-token") {
        Route::Known(entry) => assert_eq!(entry.provenance, Provenance::Declared),
        other => panic!("the spelling as sent must win: {other:?}"),
    }
}

#[test]
fn a_field_qualified_title_spelling_inverts_onto_the_same_item_as_its_minted_form() {
    let plain = item("demo api key");
    let catalogue = indexed(&BTreeMap::new(), std::slice::from_ref(&plain));
    let key = key_of(&plain);
    catalogue.install_view(
        &key,
        &ProtonMint,
        &plain,
        &[field("Expiry Date"), field("password")],
    );

    let by_minted = catalogue
        .invert("DEMO_API_KEY__EXPIRY_DATE")
        .expect("the minted spelling inverts");
    let by_title = catalogue
        .invert("demo-api-key__expiry-date")
        .expect("the title spelling must invert onto the same item");
    assert_eq!(by_minted, by_title);

    assert!(matches!(
        catalogue.route("demo-api-key__expiry-date"),
        Route::Known(_)
    ));
}

#[test]
fn a_title_and_a_field_that_mint_one_name_clash_across_the_two_stages() {
    // The `__`-inside-a-title hazard from the other side. An item titled
    // `decoy (alpha` mints `DECOY__ALPHA` from the item listing, and item
    // `decoy` with a field `alpha` mints the same name from its field view.
    // Answering out of the index the moment it holds an entry would resolve
    // this to whichever item stage one saw, with the clash invisible.
    assert_eq!(mint_bare("decoy (alpha").as_deref(), Some("DECOY__ALPHA"));
    assert_eq!(mint("decoy", "alpha").as_deref(), Some("DECOY__ALPHA"));

    let plain = item("decoy");
    let catalogue = indexed(&BTreeMap::new(), &[item("decoy (alpha"), plain.clone()]);

    // Before the field view lands the index knows one minting, and that is the
    // honest answer — this is what makes the assertion below about the clash
    // and not about a name that never resolved.
    assert!(matches!(catalogue.route("DECOY__ALPHA"), Route::Known(_)));

    catalogue.install_view(
        &key_of(&plain),
        &ProtonMint,
        &plain,
        &[field("alpha"), field("password")],
    );

    match catalogue.route("DECOY__ALPHA") {
        Route::Ambiguous { items, .. } => assert_eq!(items, 2),
        other => panic!("a name two stages mint must not route: {other:?}"),
    }
    assert!(!catalogue.names().contains(&"DECOY__ALPHA".to_owned()));
    // The bare name of the item whose view landed is minted by that one item
    // twice — once by the listing, once by its own `password` field — and that
    // is agreement, not a clash.
    assert!(matches!(catalogue.route("DECOY"), Route::Known(_)));
    assert!(catalogue.names().contains(&"DECOY".to_owned()));
}
