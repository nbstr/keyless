//! How many items mint one name, read across the snapshot and its fresh field
//! views together.

use std::collections::BTreeSet;

use super::index::Slot;
use super::{Entry, Inner, ItemKey, VIEW_LIFETIME};

/// What the derived half of the catalogue says about one name.
///
/// An enum rather than a count beside an optional entry, because that pairing
/// can spell a state with no meaning — one minting and no entry to serve it —
/// and every reader then has to decide what to do about it. [`names_in`] read
/// the count alone and would have listed such a name while [`Catalogue::route`]
/// refused it, which is the listing-versus-resolver disagreement
/// [`Catalogue::names`] exists to prevent.
pub(super) enum Mintings {
    /// Nothing derived mints it.
    None,
    /// Exactly one item does.
    ///
    /// Boxed for [`Route::Known`]'s reason: an [`Entry`] carries a whole
    /// [`SecretRoute`], and the other two variants are a set and a count.
    Sole(Box<Entry>),
    /// Several do.
    Clash {
        stores: BTreeSet<String>,
        items: usize,
    },
}

/// Read BOTH derived sources before either answers.
///
/// # Why the index alone is not enough
///
/// A normalised title can contain the joiner, so one name has two ways of being
/// minted: an item titled `bar (baz` mints `BAR__BAZ` from stage one, and item
/// `bar` with a field `baz` mints the same name from stage two. Answering out of
/// the index the moment it holds an entry resolves that to the first item with
/// the clash invisible — the same `__`-inside-a-title hazard that made the miss
/// path invert the minter rather than split on a literal `__`, arriving from the
/// other side.
///
/// # Why items are counted by KEY and not by hit
///
/// The same item minting one name twice is not a clash and must not read as
/// one: a field view mints the bare name for the `password` field, so an item's
/// own view and the index agree about that name by construction.
pub(super) fn mintings(inner: &Inner, name: &str) -> Mintings {
    let (counted, mut stores, indexed, mut sole) = match inner.index.minted.get(name) {
        Some(Slot::Sole(held)) => (
            [held.item.clone()].into_iter().collect(),
            [held.entry.store.clone()].into_iter().collect(),
            1,
            Some(held.entry.clone()),
        ),
        Some(Slot::Clash { stores, keys }) => (keys.clone(), stores.clone(), keys.len(), None),
        None => (BTreeSet::<ItemKey>::new(), BTreeSet::new(), 0, None),
    };

    let mut extra = 0usize;
    for (key, view) in &inner.views {
        if view.at.elapsed() >= VIEW_LIFETIME || counted.contains(key) {
            continue;
        }
        let Some(entry) = view.minted.get(name) else {
            continue;
        };
        extra += 1;
        stores.insert(entry.store.clone());
        if indexed == 0 && extra == 1 {
            sole = Some(entry.clone());
        }
    }

    match (indexed + extra, sole) {
        (0, _) => Mintings::None,
        (1, Some(entry)) => Mintings::Sole(Box::new(entry)),
        (items, _) => Mintings::Clash { stores, items },
    }
}

/// Every derived name exactly one item mints, from the snapshot and its fresh
/// views together.
///
/// An ambiguous name is left out wherever the ambiguity comes from, so the
/// listing cannot promise a name the resolver refuses.
pub(super) fn names_in(inner: &Inner) -> BTreeSet<String> {
    let mut candidates: BTreeSet<&String> = inner.index.minted.keys().collect();
    for view in inner.views.values() {
        if view.at.elapsed() < VIEW_LIFETIME {
            candidates.extend(view.minted.keys());
        }
    }
    candidates
        .into_iter()
        .filter(|name| is_sole(inner, name))
        .cloned()
        .collect()
}

/// Whether exactly one item mints `name`, without building the answer.
///
/// The same walk [`mintings`] makes and none of its allocations: that function
/// clones an [`ItemKey`] into a fresh set, a store name into a second, and a
/// whole [`Entry`] with its [`SecretRoute`] into a `Box` — all of which every
/// caller asking only "is this one item's?" discards. There is one such caller
/// per candidate name, so the cost is paid once per name in the index on every
/// listing.
fn is_sole(inner: &Inner, name: &str) -> bool {
    let (counted, indexed): (Option<&ItemKey>, usize) = match inner.index.minted.get(name) {
        Some(Slot::Sole(held)) => (Some(&held.item), 1),
        // Two or more already, so nothing a view adds can bring it back to one.
        Some(Slot::Clash { .. }) => return false,
        None => (None, 0),
    };
    let mut items = indexed;
    for (key, view) in &inner.views {
        if view.at.elapsed() >= VIEW_LIFETIME || counted == Some(key) {
            continue;
        }
        if view.minted.contains_key(name) {
            items += 1;
            if items > 1 {
                return false;
            }
        }
    }
    items == 1
}
