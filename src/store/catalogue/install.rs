//! Building a catalogue and writing into it: the declared map at construction,
//! then derived snapshots and field views as the rebuilder installs them.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::naming::Mint;
use super::{Catalogue, Entry, Index, Inner, ItemKey, Provenance, VIEW_LIFETIME, View};
use crate::config::SecretRoute;
use crate::store::discover::{FieldSummary, ItemSummary};

impl Catalogue {
    /// A catalogue over one declared map, with no derived snapshot yet.
    #[must_use]
    pub fn new(secrets: &BTreeMap<String, SecretRoute>) -> Self {
        Catalogue {
            declared: secrets
                .iter()
                .map(|(name, route)| {
                    (
                        name.clone(),
                        Entry {
                            store: route.store.clone().unwrap_or_default(),
                            route: route.clone(),
                            provenance: Provenance::Declared,
                        },
                    )
                })
                .collect(),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The lock, surviving a poisoned one.
    ///
    /// Same reasoning as the Proton listing cache: this map holds what a store
    /// said about itself, with no invariant spanning two entries, so refusing to
    /// read it after an unrelated panic would degrade every lookup for no gain.
    pub(super) fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replace the derived snapshot.
    ///
    /// Field views are kept: they are keyed by item, they carry their own
    /// lifetime, and an item that has gone away is unreachable through the new
    /// snapshot's titles anyway.
    pub fn install(&self, index: Index) {
        self.inner().index = index;
    }

    /// Record one item's fields — stage two, fetched because a miss asked for it.
    pub fn install_view(
        &self,
        item: &ItemKey,
        minter: &dyn Mint,
        summary: &ItemSummary,
        fields: &[FieldSummary],
    ) {
        let minted = fields
            .iter()
            .filter_map(|field| {
                minter.name(summary, field).map(|name| {
                    (
                        name,
                        Entry {
                            store: minter.store().to_owned(),
                            route: minter.route(summary, &field.name),
                            provenance: Provenance::Derived,
                        },
                    )
                })
            })
            .collect();
        self.inner().views.insert(
            item.clone(),
            View {
                minted,
                at: Instant::now(),
            },
        );
    }

    /// Whether this item's field view is present and inside [`VIEW_LIFETIME`].
    #[must_use]
    pub fn view_is_fresh(&self, item: &ItemKey) -> bool {
        self.inner()
            .views
            .get(item)
            .is_some_and(|view| view.at.elapsed() < VIEW_LIFETIME)
    }

    /// How old the derived snapshot is, or `None` when none has landed.
    #[must_use]
    pub fn indexed_at(&self) -> Option<Duration> {
        self.inner().index.at.map(|at| at.elapsed())
    }
}
