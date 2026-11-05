use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::error::StoreError;
use crate::store::exec::{capture, summarise};
use crate::store::proton_session::{self, GenerationName};

use super::store::ProtonStore;

/// One record of `pass-cli item list --output json`.
///
/// Only the four keys this adapter acts on are named. That is forward
/// compatibility and a safety property at once: a key added by a later CLI
/// cannot fail the parse, and — since `--show-secrets` is never passed and is
/// refused for agent sessions anyway — content this adapter did not ask for is
/// not merely unused, it is never held. Every field here is a coordinate, which
/// is why naming one in an error message is safe.
///
/// **`id`, not `item_id`** — there is no `item_id` key, and asking for one
/// yields nothing.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ItemRecord {
    pub(crate) id: String,
    pub(crate) share_id: String,
    pub(crate) state: String,
    pub(crate) title: String,
    /// `login`, `custom`, `note`, … Defaulted rather than required so a listing
    /// from a CLI that stops sending it degrades one column of `items` instead of
    /// failing every lookup in `run`.
    #[serde(default)]
    pub(crate) item_type: String,
}

impl ItemRecord {
    /// Whether this item is live, as an allowlist rather than a denylist.
    ///
    /// A trashed item is still listed, and resolving one would hand a child a
    /// value its owner believes they deleted. Anything that is not plainly
    /// `Active` — a state added by a later CLI, a spelling this build has never
    /// seen — is therefore treated as not resolvable, which degrades the name
    /// instead of reading something unexpected.
    pub(crate) fn is_active(&self) -> bool {
        self.state.eq_ignore_ascii_case("active")
    }
}

/// What `pass-cli item list --output json` prints.
#[derive(Debug, Deserialize)]
pub(crate) struct ItemListing {
    pub(crate) items: Vec<ItemRecord>,
}

/// One record of `pass-cli vault list --output json`.
///
/// Only the name is read. A vault's share id is minted per session — see this
/// module's header — so storing one would be storing something that expires, and
/// every command below addresses a vault by `--vault-name` anyway.
#[derive(Debug, Clone, Deserialize)]
struct VaultRecord {
    name: String,
}

/// What `pass-cli vault list --output json` prints.
#[derive(Debug, Deserialize)]
struct VaultListing {
    vaults: Vec<VaultRecord>,
}

/// Which title matched, in the three shapes a caller has to be told apart.
pub(crate) enum Matched<'a> {
    /// Exactly one live item carries the title.
    One(&'a ItemRecord),
    /// Nothing carries it at all.
    None,
    /// Only trashed items carry it. Resolving one would hand out a value its
    /// owner believes is deleted, so this is never silently promoted to `One`.
    OnlyTrashed,
    /// Several live items carry it. Refused, never ranked: guessing here is a
    /// wrong credential delivered with nothing said.
    Several(Vec<&'a ItemRecord>),
}

/// Find the one live item with `title`, or say which of the other three it is.
///
/// Shared by the resolver and by `fields` so the two cannot disagree about which
/// item a title names. Each caller writes its own message, because the fix
/// differs: a resolver points at the `reference` escape hatch, `fields` points at
/// the trash.
pub(crate) fn match_title<'a>(items: &'a [ItemRecord], title: &str) -> Matched<'a> {
    // Exact and case-sensitive: a looser match is a second way to reach an item
    // nobody named.
    let (live, dead): (Vec<&ItemRecord>, Vec<&ItemRecord>) = items
        .iter()
        .filter(|record| record.title == title)
        .partition(|record| record.is_active());

    match live.as_slice() {
        [only] => Matched::One(only),
        [] if dead.is_empty() => Matched::None,
        [] => Matched::OnlyTrashed,
        _ => Matched::Several(live),
    }
}

/// One vault's cache entry, and the gate that makes it fill exactly once.
///
/// The inner `Mutex` is the whole point: it is held across the vendor CLI spawn,
/// so several names resolving from one vault at the same time produce one
/// listing rather than one each. See [`ProtonStore::cached_items`].
pub(super) type VaultSlot = Arc<Mutex<Option<Listed>>>;

/// One vault's items, and when they were fetched.
///
/// The timestamp is what makes the cache expire. Without it the entry is a
/// statement about the vault that was true once and is never checked again —
/// and the check it silently drops is the trash rule, since a trashed item is
/// still listed and is refused only because a listing says `Trashed`.
pub(super) struct Listed {
    pub(super) items: Arc<Vec<ItemRecord>>,
    pub(super) at: Instant,
    /// The generation this listing was fetched under. `None` on the session
    /// side, which has no generations and so nothing to compare against.
    ///
    /// A renewal replaces the identity a session directory serves without
    /// changing its path, so the directory alone cannot tell a stale listing
    /// from a fresh one — the generation is what changed. A slot filled under
    /// one generation and read under the next is exactly as stale as one read
    /// past its TTL, so it is refetched the same way rather than handed out as
    /// though the vault behind it had not changed.
    pub(super) generation: Option<GenerationName>,
}

/// The longest a listing may be reused, whatever the config asks for.
///
/// A config is not a trusted input — it can arrive by `--config` or
/// `KEYLESS_CONFIG` from whatever wrote the file — so `listing_ttl_ms` is
/// clamped for the same reason `timeout_ms` is: without a ceiling it is the
/// knob that turns the expiry off again, and an expiry that a number can
/// disable is not a bound. Fifteen minutes is far above the default and far
/// below "until somebody restarts it".
pub const MAX_LISTING_TTL_MS: u64 = 900_000;

/// A configured `listing_ttl_ms` as a duration, clamped to
/// [`MAX_LISTING_TTL_MS`].
#[must_use]
pub const fn bounded_listing_ttl(milliseconds: u64) -> Duration {
    let bounded = if milliseconds > MAX_LISTING_TTL_MS {
        MAX_LISTING_TTL_MS
    } else {
        milliseconds
    };
    Duration::from_millis(bounded)
}

impl ProtonStore {
    /// How old a listing this store will reuse.
    ///
    /// Zero when this store is the rebuilder's: an enumeration that accepted a
    /// listing older than the question that queued it cannot answer that
    /// question. See [`ProtonStore::always_relisting`].
    pub(super) fn reusable_for(&self) -> Duration {
        if self.relist {
            Duration::ZERO
        } else {
            self.listing_ttl
        }
    }

    /// One vault's items, from the cache or from the CLI.
    ///
    /// # Two locks, and why neither one is the other
    ///
    /// A run resolves its names CONCURRENTLY — see [`crate::cmd::run`], where
    /// doing it in turn made N unresolvable names cost N deadlines. So "check,
    /// then fetch, then insert" is a race that costs one vendor CLI spawn per
    /// racing name, which is precisely the cost this cache exists to remove.
    ///
    /// The **map** lock is therefore held only long enough to hand out a vault's
    /// slot, so a lookup in a different vault is never serialised behind this
    /// one. The **slot** lock is held across the spawn on purpose: it is the
    /// thing that makes "one listing per vault per run" true rather than
    /// probable, and every thread waiting on it wants the answer that spawn is
    /// about to produce.
    ///
    /// A failed fetch leaves the slot empty, so a later name retries rather than
    /// inheriting a failure it did not cause.
    ///
    /// # Why the entry expires
    ///
    /// An entry is only reused while it is younger than
    /// [`crate::config::ProtonConfig::listing_ttl_ms`]. A cache with no expiry
    /// is a cache that can only be right about the moment it was filled, and
    /// what it is asked about later includes **whether an item is in the trash**
    /// — a question this adapter can answer only from a listing, because the
    /// vendor resolves a trashed item's reference without complaint. Kept
    /// forever, the entry does not merely go stale: it silently switches off the
    /// one rule standing between a deleted credential and a child's environment,
    /// for as long as whatever holds this adapter stays alive.
    ///
    /// A `keyless run` cannot reach the expiry — it resolves its names in one
    /// burst and exits — so the memoisation this cache exists for is untouched;
    /// see `several_names_from_one_vault_cost_exactly_one_listing`.
    ///
    /// An expired entry is replaced only by a fetch that succeeded. A refresh
    /// that fails returns the failure, which degrades the lookup, rather than
    /// falling back to the stale answer it was sent to replace.
    pub(super) fn cached_items(
        &self,
        pass: &proton_session::Pass<'_>,
        vault: &str,
        name: &str,
    ) -> Result<Arc<Vec<ItemRecord>>, StoreError> {
        self.listed_items(pass, vault, name, self.listing_ttl)
    }

    /// The same, with the caller saying how old a reusable entry may be.
    ///
    /// `reusable_for` of zero forces a fetch. Only the freshness test moves:
    /// the map lock, the slot lock and the single-flight across the spawn are
    /// exactly as above, so a forced listing still coalesces with every other
    /// reader of that vault and still fills the shared slot for them.
    pub(super) fn listed_items(
        &self,
        pass: &proton_session::Pass<'_>,
        vault: &str,
        name: &str,
        reusable_for: Duration,
    ) -> Result<Arc<Vec<ItemRecord>>, StoreError> {
        let generation = pass.generation().cloned();
        let slot = Arc::clone(self.cache().entry(vault.to_owned()).or_default());
        let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cached) = slot.as_ref()
            && cached.at.elapsed() < reusable_for
            && cached.generation == generation
        {
            return Ok(Arc::clone(&cached.items));
        }
        let fetched = Arc::new(self.fetch_items(pass, vault, name)?);
        *slot = Some(Listed {
            items: Arc::clone(&fetched),
            at: Instant::now(),
            generation,
        });
        Ok(fetched)
    }

    /// The listing cache, surviving a poisoned lock.
    ///
    /// A panic elsewhere cannot corrupt this map's meaning — it holds what the
    /// vendor said about a vault, with no invariant spanning two entries — so
    /// refusing to serve from it after an unrelated panic would degrade a run
    /// for no safety gain.
    pub(super) fn cache(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, VaultSlot>> {
        self.listings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run the listing and parse it.
    fn fetch_items(
        &self,
        pass: &proton_session::Pass<'_>,
        vault: &str,
        name: &str,
    ) -> Result<Vec<ItemRecord>, StoreError> {
        let captured = capture(
            self.list_command(
                pass.dir(),
                vault,
                name,
                &self.vendor_login()?,
                std::env::vars_os(),
            ),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            // The vendor names the vault it could not find, which is a name
            // rather than a credential, so quoting its first line is safe and is
            // the only way "I typed the vault wrong" is distinguishable from "my
            // token expired".
            let said = summarise(&captured.stderr);
            return Err(self.vendor_failed(
                pass,
                format!("cannot list vault `{vault}`: {said}"),
                &said,
            ));
        }

        serde_json::from_slice::<ItemListing>(&captured.stdout)
            .map(|listing| listing.items)
            .map_err(|error| {
                self.backend(format!(
                    "`item list` for vault `{vault}` did not parse: {error}"
                ))
            })
    }

    /// Every vault this identity can see.
    pub(super) fn vaults(
        &self,
        pass: &proton_session::Pass<'_>,
    ) -> Result<Vec<String>, StoreError> {
        let captured = capture(
            self.vault_list_command(pass.dir(), &self.vendor_login()?, std::env::vars_os()),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            let said = summarise(&captured.stderr);
            return Err(self.vendor_failed(pass, format!("cannot list vaults: {said}"), &said));
        }

        serde_json::from_slice::<VaultListing>(&captured.stdout)
            .map(|listing| listing.vaults.into_iter().map(|v| v.name).collect())
            .map_err(|error| self.backend(format!("`vault list` did not parse: {error}")))
    }
}
