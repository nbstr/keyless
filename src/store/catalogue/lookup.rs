//! Reading a catalogue: which route a name takes, which names are served, and
//! what a miss is told.

use std::borrow::Cow;
use std::collections::BTreeSet;

use super::index::Title;
use super::mintings::{Mintings, mintings, names_in};
use super::naming::{FIELD_JOIN, declared_under, spelling};
use super::{Catalogue, ItemKey, Route, VIEW_LIFETIME};
use crate::store::discover::ItemSummary;

/// How many alternatives a miss offers.
const NEAREST: usize = 5;

impl Catalogue {
    /// What this catalogue says about one name.
    ///
    /// Declared first, derived second — see [`Catalogue::declared`]. Reads only;
    /// it starts no rebuild and asks no store, which is what lets the miss path
    /// call it while holding nothing.
    ///
    /// The derived half is asked under the name's [`spelling`], so an item's own
    /// title reaches what it mints. The resolver above keys its cache on the
    /// name as sent, so `nexus-linear` and `NEXUS_LINEAR` are two cache entries
    /// for one value.
    #[must_use]
    pub fn route(&self, name: &str) -> Route {
        let spelt = spelling(name);
        if let Some(entry) = declared_under(&self.declared, name, &spelt) {
            return Route::Known(Box::new(entry.clone()));
        }
        let inner = self.inner();
        match mintings(&inner, &spelt) {
            Mintings::None => Route::Unknown {
                nearest: nearest_to(&spelt, &names_in(&inner)),
                indexed_at: inner.index.at.map(|at| at.elapsed()),
            },
            Mintings::Sole(entry) => Route::Known(entry),
            Mintings::Clash { stores, items } => Route::Ambiguous {
                stores: stores.into_iter().collect(),
                items,
            },
        }
    }

    /// Every name the daemon will serve. Names only, no coordinates.
    ///
    /// An ambiguous name is left out: it is a name the daemon refuses, and a
    /// listing that promised it would be a listing that disagrees with the
    /// resolver. With no derived snapshot this is exactly the declared set,
    /// which is what `keyless ls` printed before the catalogue existed.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let inner = self.inner();
        let mut names: BTreeSet<String> = self.declared.keys().cloned().collect();
        names.extend(names_in(&inner));
        names.into_iter().collect()
    }

    /// Which item a missed name belongs to, by inverting the minter.
    ///
    /// The LONGEST matching bare name wins, so a title that is a prefix of
    /// another cannot claim the other's fields. Returns a coordinate and is
    /// daemon-side only.
    #[must_use]
    pub fn invert(&self, name: &str) -> Option<ItemKey> {
        let name = spelling(name);
        let name = name.as_ref();
        let inner = self.inner();
        let mut best: Option<(&ItemKey, &Title)> = None;
        for (item, title) in &inner.index.titles {
            let matches = name == title.bare
                || name
                    .strip_prefix(title.bare.as_str())
                    .is_some_and(|rest| rest.starts_with(FIELD_JOIN));
            if !matches {
                continue;
            }
            if best.is_none_or(|(_, held)| title.bare.len() > held.bare.len()) {
                best = Some((item, title));
            }
        }
        Some(best?.0.clone())
    }

    /// Every name one item mints, once its field view has been fetched.
    ///
    /// Names only. This is what a miss on an item whose fields nobody could
    /// guess has to say: a French-fielded item serving
    /// `MISSION_MANAGER_SUPABASE__H_TE` is not derivable from anything the
    /// caller holds, so listing the item's whole minted set is the only route to
    /// that value that does not involve reading the vault by hand.
    #[must_use]
    pub fn item_names(&self, item: &ItemKey) -> Vec<String> {
        let inner = self.inner();
        let mut names: BTreeSet<String> = inner
            .views
            .get(item)
            .filter(|view| view.at.elapsed() < VIEW_LIFETIME)
            .map(|view| view.minted.keys().cloned().collect())
            .unwrap_or_default();
        names.extend(inner.index.titles.get(item).map(|title| title.bare.clone()));
        // Offered names are served names. A bare name two items mint is
        // refused, and advertising it in a miss message would send the caller
        // to a second refusal.
        //
        // Tested one name at a time rather than against `names_in`, which walks
        // every candidate in the index to answer a question about the handful
        // an item mints.
        names.retain(|name| matches!(mintings(&inner, name), Mintings::Sole(_)));
        names.into_iter().collect()
    }

    /// The item summary behind one key, for a caller about to fetch its fields.
    ///
    /// A coordinate, so daemon-side only.
    #[must_use]
    pub fn summary(&self, item: &ItemKey) -> Option<ItemSummary> {
        self.inner()
            .index
            .titles
            .get(item)
            .map(|title| ItemSummary {
                id: item.id.clone(),
                vault: item.vault.clone(),
                title: item.title.clone(),
                state: title.state.clone(),
                kind: title.kind.clone(),
            })
    }

    /// The sentence a missed name gets.
    ///
    /// Names and an age, and nothing else — no title, no vault, no field, no
    /// count of what the store holds. See boundary 2 in the module docs.
    ///
    /// Takes the `route` its caller already computed rather than computing one.
    /// The miss path already holds that verdict, so a [`Catalogue::route`]
    /// here walks the index a second time for an answer already in the
    /// caller's hand.
    ///
    /// A name looked up under a different [`spelling`] is shown with it, so a
    /// caller who typed an item's own title sees which minted form was tried.
    #[must_use]
    pub fn advice(&self, name: &str, route: &Route) -> String {
        self.suggestion(name, route)
            .unwrap_or_else(|| self.unbound(name))
    }

    /// The advice, when it points somewhere: the names of the item behind
    /// `name`, the stores minting it, the nearest served names, or the
    /// spelling it was looked up under.
    #[must_use]
    pub fn suggestion(&self, name: &str, route: &Route) -> Option<String> {
        let age = self.age();
        let shown = shown(name);
        if let Some(item) = self.invert(name) {
            let names = self.item_names(&item);
            if !names.is_empty() {
                return Some(format!(
                    "nothing is bound to {shown}; the item behind that name serves: {} ({age})",
                    names.join(", ")
                ));
            }
        }
        match route {
            Route::Ambiguous { stores, items } => Some(format!(
                "{shown} is minted by {items} items across {} ({age}); declare it to say which",
                stores.join(", ")
            )),
            Route::Unknown { nearest, .. } if !nearest.is_empty() => Some(format!(
                "nothing is bound to {shown}; nearest served names: {} ({age})",
                nearest.join(", ")
            )),
            _ if matches!(spelling(name), Cow::Owned(_)) => Some(self.unbound(name)),
            _ => None,
        }
    }

    fn unbound(&self, name: &str) -> String {
        format!("nothing is bound to {} ({})", shown(name), self.age())
    }

    fn age(&self) -> String {
        // `checkout::ago` rather than a ladder of this module's own: it is the
        // one every other age in this tool is rendered through, its tiers are
        // pinned by tests, and it has a DAY tier — a second ladder that stopped
        // at hours would report a two-day-old index as `51h` beside a `2d`
        // everywhere else.
        self.indexed_at().map_or_else(
            || "no index yet".to_owned(),
            |age| format!("indexed {}", crate::checkout::ago(age)),
        )
    }
}

fn shown(name: &str) -> String {
    match spelling(name) {
        Cow::Owned(spelt) => format!("`{name}` (tried `{spelt}`)"),
        Cow::Borrowed(_) => format!("`{name}`"),
    }
}

/// Up to [`NEAREST`] names sharing the longest prefix with `name`.
///
/// Case-insensitive, because a caller who typed the name in lower case has made
/// exactly the mistake this is for. A candidate sharing nothing is not offered:
/// an unrelated name presented as "nearest" reads as a suggestion and is noise.
fn nearest_to(name: &str, candidates: &BTreeSet<String>) -> Vec<String> {
    let target = name.to_ascii_uppercase();
    let mut scored: Vec<(usize, &String)> = candidates
        .iter()
        .map(|candidate| {
            (
                shared_prefix(&target, &candidate.to_ascii_uppercase()),
                candidate,
            )
        })
        .filter(|(shared, _)| *shared > 0)
        .collect();
    scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
    scored
        .into_iter()
        .take(NEAREST)
        .map(|(_, candidate)| candidate.clone())
        .collect()
}

fn shared_prefix(left: &str, right: &str) -> usize {
    left.chars()
        .zip(right.chars())
        .take_while(|(a, b)| a == b)
        .count()
}
