//! Live items, fields and catalogues the catalogue suite builds its cases from.

use keyless::config::SecretRoute;
use keyless::store::catalogue::{Catalogue, IndexBuilder, ItemKey, ProtonMint, naming::Mint};
use keyless::store::discover::{FieldKind, FieldSummary, ItemSummary};
use std::collections::BTreeMap;

/// A live item, with an id derived from its title.
///
/// Distinct titles therefore get distinct ids, which is the ordinary case. Two
/// items that SHARE a title need `item_at` to say so: the id is what holds them
/// apart, and deriving it from the title would fold them back into one.
pub fn item(title: &str) -> ItemSummary {
    item_at(&format!("It3m{}", title.len()), title)
}

pub fn item_at(id: &str, title: &str) -> ItemSummary {
    ItemSummary {
        id: id.to_owned(),
        vault: "personal".to_owned(),
        title: title.to_owned(),
        state: "Active".to_owned(),
        kind: "login".to_owned(),
    }
}

/// Where one item sits, as the catalogue keys it.
pub fn key_of(summary: &ItemSummary) -> ItemKey {
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
pub fn advice(catalogue: &Catalogue, name: &str) -> String {
    catalogue.advice(name, &catalogue.route(name))
}

/// A catalogue over `secrets`, holding an index minted from `items`.
pub fn indexed(secrets: &BTreeMap<String, SecretRoute>, items: &[ItemSummary]) -> Catalogue {
    let catalogue = Catalogue::new(secrets);
    let mut building = IndexBuilder::new();
    for item in items {
        building.item(&ProtonMint, item);
    }
    catalogue.install(building.finish());
    catalogue
}

pub fn field(name: &str) -> FieldSummary {
    FieldSummary {
        name: name.to_owned(),
        kind: FieldKind::Custom,
        value_type: None,
        path: "sections[0].fields[0]".to_owned(),
    }
}
