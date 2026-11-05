//! The derived snapshot: what one item contributes, and how two items minting
//! one name fold into a clash.

use std::collections::BTreeSet;
use std::time::Instant;

use super::naming::{BARE_FIELD, Mint};
use super::{Entry, Index, IndexBuilder, ItemKey, Provenance};
use crate::store::discover::ItemSummary;

/// What one item contributes to the index.
#[derive(Debug, Clone)]
pub(super) struct Minted {
    pub(super) entry: Entry,
    /// The item this name came from, so a second one minting it is a collision
    /// and a second FIELD of the same item is not.
    pub(super) item: ItemKey,
}

/// One name and everything that mints it.
#[derive(Debug, Clone)]
pub(super) enum Slot {
    /// One item mints it.
    ///
    /// Boxed for the reason [`Route::Known`] is: a clash is a small set and a
    /// count, and an index is mostly `Sole`.
    Sole(Box<Minted>),
    /// Several do. Nothing is asked; see [`Route::Ambiguous`].
    Clash {
        stores: BTreeSet<String>,
        /// The items that minted it. Its length IS the count, because
        /// [`ItemKey`] carries the backend's own identifier and two live items
        /// sharing one title are therefore two keys.
        keys: BTreeSet<ItemKey>,
    },
}

impl Slot {
    /// Fold another minting of the same name in.
    ///
    /// # Why there is no "same item, mint it again" arm
    ///
    /// There was one, and it was a hole. [`IndexBuilder::item`] is the only
    /// caller and runs once per item, so every minting that arrives here is a
    /// different item — including two live items sharing one title, which
    /// `ProtonStore::reference_for` refuses by name. An arm that folded them
    /// minted a `Sole` name the resolve would not serve, which is precisely the
    /// disagreement [`Catalogue::names`] exists to prevent.
    fn add(&mut self, minted: Minted) {
        match self {
            Slot::Sole(held) => {
                let stores = [held.entry.store.clone(), minted.entry.store.clone()]
                    .into_iter()
                    .collect();
                let keys = [held.item.clone(), minted.item].into_iter().collect();
                *self = Slot::Clash { stores, keys };
            }
            Slot::Clash { stores, keys } => {
                stores.insert(minted.entry.store.clone());
                keys.insert(minted.item);
            }
        }
    }
}

/// One live title, kept so a missed name can be inverted onto it.
#[derive(Debug, Clone)]
pub(super) struct Title {
    pub(super) bare: String,
    /// The two fields of an [`ItemSummary`] its [`ItemKey`] does not already
    /// carry, so a lazily fetched field view can be minted without
    /// re-enumerating the vault and without a second copy of the coordinates.
    pub(super) state: String,
    pub(super) kind: String,
}

impl IndexBuilder {
    /// An empty builder.
    #[must_use]
    pub fn new() -> Self {
        IndexBuilder::default()
    }

    /// Add one item's bare name, if the store's vocabulary mints one.
    ///
    /// Trashed items are skipped. A trashed item still resolves through a
    /// `pass://` reference and is refused by title, so minting a name for one
    /// would produce a name that lists and never resolves.
    pub fn item(&mut self, minter: &dyn Mint, item: &ItemSummary) {
        if !item.is_active() {
            return;
        }
        let Some(name) = minter.bare_name(item) else {
            return;
        };
        let key = ItemKey {
            store: minter.store().to_owned(),
            vault: item.vault.clone(),
            id: item.id.clone(),
            title: item.title.clone(),
        };
        self.index.titles.insert(
            key.clone(),
            Title {
                bare: name.clone(),
                state: item.state.clone(),
                kind: item.kind.clone(),
            },
        );
        self.insert(
            name,
            Minted {
                entry: Entry {
                    store: minter.store().to_owned(),
                    route: minter.route(item, BARE_FIELD),
                    provenance: Provenance::Derived,
                },
                item: key,
            },
        );
    }

    fn insert(&mut self, name: String, minted: Minted) {
        self.index
            .minted
            .entry(name)
            .and_modify(|slot| slot.add(minted.clone()))
            .or_insert_with(|| Slot::Sole(Box::new(minted)));
    }

    /// The finished snapshot, stamped with the moment it completed.
    #[must_use]
    pub fn finish(mut self) -> Index {
        self.index.at = Some(Instant::now());
        self.index
    }
}

impl Index {
    /// Every name it mints, with the items that mint each one.
    ///
    /// Coordinates, so daemon-side only — `keylessd check` is the one reader,
    /// and it runs root-side against the daemon's own config, where the
    /// socket's rule about coordinates does not apply. A row with more than one
    /// item is a collision, and naming the colliding titles is the only way an
    /// operator can act on one.
    #[must_use]
    pub fn minted(&self) -> Vec<(String, Vec<ItemKey>)> {
        self.minted
            .iter()
            .map(|(name, slot)| {
                let items = match slot {
                    Slot::Sole(held) => vec![held.item.clone()],
                    Slot::Clash { keys, .. } => keys.iter().cloned().collect(),
                };
                (name.clone(), items)
            })
            .collect()
    }

    /// Every item it holds, as coordinates. Daemon-side only.
    #[must_use]
    pub fn items(&self) -> Vec<ItemKey> {
        self.titles.keys().cloned().collect()
    }
}
