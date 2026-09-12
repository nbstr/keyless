//! The naming rule, and what a derived index refuses to carry.
//!
//! # Why a fixture stands in for the 50 live names, and why it is invented
//!
//! The rule in `src/store/catalogue.rs` was derived from the names the live
//! daemon already serves, and reproduces all 50 of them exactly with zero
//! collisions — measured against the live `keylessd.json` on 2026-09-12 and
//! re-verified there by a third independent reader. That file is root-owned and
//! holds the coordinates of every credential on the machine, so this suite must
//! not read it and no CI runner could.
//!
//! The fixture below therefore stands in for it, and it is INVENTED rather than
//! transcribed. `tests/publication.rs` refuses a real item title, vault name or
//! field label anywhere in this repository, and it is right to: a scrub that
//! replaced an item's title once already left two of its field labels behind.
//!
//! What the fixture reproduces is the CHARACTER CLASSES that make the rule hard,
//! which is the whole of what the awkward live names have in common — a
//! non-ASCII letter inside a word, a leading digit, spaces beside hyphens, a
//! multi-word custom field label, and the bare-password case. A rule that gets
//! these right gets the plain ones right by construction; a rule that gets one
//! of them wrong is wrong on the live machine.

use keyless::config::SecretRoute;
use keyless::store::catalogue::{
    Catalogue, IndexBuilder, ItemKey, Mint, ProtonMint, Route, mint, mint_bare,
};
use keyless::store::discover::{FieldKind, FieldSummary, ItemSummary};
use std::collections::BTreeMap;

/// A live item, with an id derived from its title.
///
/// Distinct titles therefore get distinct ids, which is the ordinary case. Two
/// items that SHARE a title need `item_at` to say so: the id is what holds them
/// apart, and deriving it from the title would fold them back into one.
fn item(title: &str) -> ItemSummary {
    item_at(&format!("It3m{}", title.len()), title)
}

fn item_at(id: &str, title: &str) -> ItemSummary {
    ItemSummary {
        id: id.to_owned(),
        vault: "personal".to_owned(),
        title: title.to_owned(),
        state: "Active".to_owned(),
        kind: "login".to_owned(),
    }
}

/// Where one item sits, as the catalogue keys it.
fn key_of(summary: &ItemSummary) -> ItemKey {
    ItemKey {
        store: ProtonMint.store().to_owned(),
        vault: summary.vault.clone(),
        id: summary.id.clone(),
        title: summary.title.clone(),
    }
}

/// The advice a name gets, over the verdict the catalogue holds for it.
///
/// `advice` takes the route rather than computing one, so the miss path can
/// hand over the verdict it already has. Every caller here wants that same
/// pairing, so it is made once.
fn advice(catalogue: &Catalogue, name: &str) -> String {
    catalogue.advice(name, &catalogue.route(name))
}

/// A catalogue over `secrets`, holding an index minted from `items`.
fn indexed(secrets: &BTreeMap<String, SecretRoute>, items: &[ItemSummary]) -> Catalogue {
    let catalogue = Catalogue::new(secrets);
    let mut building = IndexBuilder::new();
    for item in items {
        building.item(&ProtonMint, item);
    }
    catalogue.install(building.finish());
    catalogue
}

fn field(name: &str) -> FieldSummary {
    FieldSummary {
        name: name.to_owned(),
        kind: FieldKind::Custom,
        value_type: None,
        path: "sections[0].fields[0]".to_owned(),
    }
}

#[test]
fn the_minter_reproduces_every_awkward_name_the_daemon_already_serves() {
    // (item title, field name, the name the live daemon serves it under).
    let declared = [
        // A non-ASCII letter is ONE underscore, not one per UTF-8 byte. This is
        // the case a byte-wise walk gets wrong while looking right everywhere
        // else: `D_COY` with two underscores would be a name nobody has ever
        // asked for. Two live names carry this shape.
        ("decoy-db-alpha", "Réf décoy", "DECOY_DB_ALPHA__R_F_D_COY"),
        (
            "decoy-db-alpha",
            "Type de bàse de décoys",
            "DECOY_DB_ALPHA__TYPE_DE_B_SE_DE_D_COYS",
        ),
        // A title that starts with a digit is not a legal variable name, so it
        // is prefixed rather than trimmed — trimming would collide `9decoy`
        // with an item titled `decoy`.
        ("9decoy", "password", "_9DECOY"),
        // Spaces beside hyphens, which mint the same character either way.
        (
            "decoy PAT alpha-beta-gamma",
            "password",
            "DECOY_PAT_ALPHA_BETA_GAMMA",
        ),
        // A multi-word custom field label, which is where a caller's guess is
        // least likely to be right.
        ("decoy-agent", "Token decoy", "DECOY_AGENT__TOKEN_DECOY"),
        // The bare case: one item, one password, one name with no suffix.
        ("demo api key", "password", "DEMO_API_KEY"),
    ];

    for (title, field_name, expected) in declared {
        assert_eq!(
            mint(title, field_name).as_deref(),
            Some(expected),
            "`{title}` / `{field_name}`"
        );
    }
}

#[test]
fn a_title_that_mints_nothing_addressable_mints_no_name_at_all() {
    // An empty result is not a name, it is a collision waiting: every untitled
    // item would answer to it.
    assert_eq!(mint_bare(""), None);
    assert_eq!(mint("", "password"), None);
    // And a field whose name normalises to nothing cannot suffix anything.
    assert_eq!(mint("real", ""), None);
}

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
fn nothing_a_field_summary_carries_but_its_name_reaches_a_route() {
    // C3, at the seam a value could only ever arrive through. `Discover` is
    // shaped so a value cannot be returned at all; what it CAN return besides a
    // field's name is its value type and its structural path, and this asserts
    // the catalogue keeps neither. Each marker is a distinct recognisable
    // string, and each marker's LENGTH is asserted absent too — a length plus a
    // password policy is a materially smaller search space, which is why
    // `src/store/discover.rs` treats one as a value.
    let markers = [
        "MARKERVALUETYPEAAAA",
        "MARKERPATHBBBBBBBBBBBBBBB",
        "MARKERKINDCCCCCCCCCCCCCCCCCCCCC",
    ];
    let leaky = FieldSummary {
        name: "API Token".to_owned(),
        kind: FieldKind::Custom,
        value_type: Some(markers[0].to_owned()),
        path: markers[1].to_owned(),
    };
    let summary = item("decoy-agent");
    let catalogue = indexed(&BTreeMap::new(), std::slice::from_ref(&summary));
    let key = key_of(&summary);
    catalogue.install_view(
        &key,
        &ProtonMint,
        &summary,
        &[leaky.clone(), field("password")],
    );

    let rendered = format!(
        "{:?}|{}|{}|{}|{:?}",
        catalogue.route("DECOY_AGENT__API_TOKEN"),
        catalogue.names().join(","),
        advice(&catalogue, "DECOY_AGENT__NOPE"),
        catalogue.item_names(&key).join(","),
        catalogue.route("DECOY_AGENT"),
    );

    for marker in markers {
        assert!(
            !rendered.contains(marker),
            "{marker} reached a route: {rendered}"
        );
        let length = marker.len().to_string();
        assert!(
            !rendered.contains(&length),
            "the length {length} of {marker} reached a route: {rendered}"
        );
    }
    // The negative control: without this the assertions above would pass on a
    // catalogue that had recorded nothing whatever.
    assert!(
        catalogue
            .names()
            .contains(&"DECOY_AGENT__API_TOKEN".to_owned()),
        "{:?}",
        catalogue.names()
    );
}

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
fn the_derived_index_has_no_way_to_reach_a_disk() {
    // C7, asserted the way this suite asserts every other structural promise:
    // by reading the source. A `Serialize` derive is the one edit that would
    // make the index writable by accident, and it would read as harmless.
    let source = include_str!("../src/store/catalogue.rs");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "Serialize",
        "to_vec",
        "write_all",
        "File::create",
        "fs::write",
    ] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` in the catalogue: the derived index lives in the daemon's heap and \
             dies with the daemon, and a durable copy is a `get` verb with extra steps"
        );
    }
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
