//! What the daemon can serve, derived from what the stores already hold.
//!
//! # The hole this closes
//!
//! Before this module a name was serveable only because somebody had written it
//! into `keylessd.json`'s `secrets` map — a root-owned file. Adding one item to
//! a vault therefore cost a privileged edit and a daemon restart, and every name
//! that nobody had transcribed was simply absent however plainly the store held
//! it. The transcription is also the one part of the arrangement nothing checks:
//! a renamed item leaves a declaration pointing at nothing, and the declaration
//! goes on reading as correct.
//!
//! So the daemon mints the names itself, from the coordinates a store already
//! enumerates through [`crate::store::discover::Discover`]. A declaration
//! remains the way to say something the vocabulary cannot mint — a different
//! variable name, a reference form, a note — and it still wins, by being looked
//! up first.
//!
//! # Four boundaries, and none of them is a convention
//!
//! 1. **This index never touches disk.** No file, no serialisation, no
//!    `Serialize` derive on any type in this module. The argument is
//!    [`crate::daemon::resolver`]'s, unchanged: a durable copy of what the vault
//!    holds is decryptable without the daemon, which puts the answer back on the
//!    calling user's side of the uid boundary — a `get` verb with extra steps.
//!    It lives in the daemon's heap and dies with the daemon, so killing
//!    `keylessd` strictly reduces what is obtainable.
//! 2. **No coordinate leaves the daemon.** [`Entry`] carries a
//!    [`SecretRoute`] — vault name, item title, field — because the resolver
//!    needs it, and it is read only on the daemon's side. Everything this module
//!    renders for a client is NAMES: [`Catalogue::names`], and
//!    [`Catalogue::advice`] on a miss. An ambiguity is reported as store ids and
//!    a COUNT, never as the titles that collided, for the same reason
//!    [`crate::store::discover::discoverer`] refuses to enumerate the `daemon`
//!    store at all.
//! 3. **Nothing heavy on the happy request path.** A declared name that resolves
//!    costs a map lookup, and a derived one a lookup under the lock; neither
//!    allocates a spelling it did not need. The scan behind a suggestion and
//!    the rebuild behind a stale index are paid on a miss, which is why a miss
//!    may cost a lock and a scan and a hit costs neither.
//! 4. **No value, and no value's LENGTH, can cross.** The catalogue reads only
//!    through `Discover`, whose shape makes a value structurally unavailable —
//!    see that module for why a length is treated as a value here: "22
//!    characters" plus a password policy is a materially smaller search space.
//!
//! # Which stores mint, and which honestly do not
//!
//! Proton mints. Its addressing is a vault name, an item title and a field
//! name, which is exactly the vocabulary the rule below is written in.
//!
//! The other three do not, and each refusal is a fact about the backend rather
//! than work left undone — the same honesty
//! [`crate::store::discover::discoverer`] already practises:
//!
//! - **1Password** enumerates safely and still mints nothing, because its
//!   addressing already defaults an undeclared name to its own spelling as the
//!   item title in the pinned vault. A minted `MY_ITEM` would therefore be
//!   looked up as an item TITLED `MY_ITEM`, never as the item `my-item` it was
//!   minted from — a name that lists and cannot resolve, which is worse than a
//!   name that is absent.
//! - **The keychain** has no verb that lists items for one service without
//!   dumping the whole keychain file.
//! - **Infisical** under the daemon has no environment by construction, so
//!   there is no coordinate to enumerate against — see
//!   `DaemonConfig::infisical_routing`.
//!
//! # Why the catalogue owns no store
//!
//! It is an index holder and nothing else. A daemon-side rebuilder holds the
//! discoverers AND an `Arc<Catalogue>`, and pushes fresh snapshots in; the store
//! adapters hold an `Arc<Catalogue>` to read their derived addresses out of. The
//! arrows point one way, so there is no cycle to keep alive. A catalogue that
//! held the adapters would close that loop and the whole graph would leak.
//!
//! # Why the miss path inverts the minter rather than splitting on `__`
//!
//! A normalised title can itself contain `__`: `foo (bar)` mints `FOO__BAR_`.
//! Splitting a missed name at its last `__` is therefore ambiguous on exactly
//! the titles a caller is least able to guess. Instead every live title is
//! minted, the missed name is minted too, the two are compared, and the LONGEST
//! matching bare name wins — which is deterministic and cannot disagree with the
//! minter, because it IS the minter.

mod index;
mod install;
mod lookup;
mod mintings;
pub mod naming;
mod rebuild;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::config::SecretRoute;
use crate::store::discover::{Discover, FieldSummary, ItemSummary};
use index::{Slot, Title};
use naming::{Mint, declared_under, mint, mint_bare, spelling};
use rebuild::{Engine, Never};

/// How long a fetched field view is trusted.
///
/// Long enough that a burst of misses against one item costs one vendor call;
/// short enough that a renamed field surfaces within a quarter of an hour. The
/// alternative — a polling clock — was refused deliberately: a fifteen-minute
/// poll is roughly 2,700 vendor calls a day, and every one of them is a
/// permanent off-machine audit entry in the vault. So staleness is bounded by a
/// lifetime and refreshed by DEMAND, never by a timer nobody asked for.
pub const VIEW_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// Where a name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Written into the daemon's own config by an operator.
    Declared,
    /// Minted from what a store enumerates.
    Derived,
}

/// One name the daemon can serve, and where its value lives.
///
/// The route is a coordinate and never leaves the daemon: see boundary 2 in the
/// module docs. There is no field here that could hold a value or a length, and
/// [`SecretRoute`] has none either — which is the structural half of the
/// promise, the assertion in `tests/catalogue.rs` being the other half.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Which store answers it.
    pub store: String,
    /// Where inside that store.
    pub route: SecretRoute,
    /// Declared or minted.
    pub provenance: Provenance,
}

/// What the catalogue says about one name.
#[derive(Debug, Clone)]
pub enum Route {
    /// Exactly one thing mints or declares it.
    ///
    /// Boxed because the other two variants are a handful of words and an
    /// [`Entry`] carries a whole [`SecretRoute`]; unboxed, every `Route` an
    /// ambiguity or a miss produced would still be the size of the largest one.
    Known(Box<Entry>),
    /// Two or more items mint it, so nothing is asked.
    ///
    /// # Why an ambiguity is a refusal rather than a first-wins
    ///
    /// Reading one of two items that mint one name is a coin toss decided by
    /// map iteration order, and it is silent: the caller gets a real credential
    /// that is the wrong credential. The declared map is the escape hatch — an
    /// operator who means one of them says so, and a declaration outranks
    /// everything here.
    ///
    /// Store ids and a count, never the colliding titles. `keylessd check` runs
    /// root-side and is where those may be named.
    Ambiguous {
        /// Which stores mint it, sorted and deduplicated.
        stores: Vec<String>,
        /// How many items do.
        items: usize,
    },
    /// Nothing serves it.
    Unknown {
        /// Names the index does hold that look closest. Names only.
        nearest: Vec<String>,
        /// How old the derived snapshot is, or `None` when none has landed.
        ///
        /// Whether a rebuild was queued off the back of this miss is not
        /// recorded here: [`Catalogue::route`] owns no queue and starts
        /// nothing, and the caller that does the queueing already knows. A
        /// catalogue that could queue its own rebuild would hold the
        /// rebuilder, and the rebuilder holds the catalogue — see the module
        /// docs.
        indexed_at: Option<Duration>,
    },
}

/// Which item a missed name inverts onto.
///
/// A coordinate, so it stays daemon-side: it exists to tell a rebuilder which
/// one item to fetch a field view for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ItemKey {
    /// The store that holds it.
    pub store: String,
    /// The vault within that store, empty where the store has no vaults.
    pub vault: String,
    /// The backend's own identifier.
    ///
    /// Here rather than a title alone, because a title is not unique: two live
    /// items in one vault may share one, and without the id they arrive as one
    /// key. Everything keyed by an item then treats the pair as a single item —
    /// the derived index folds their names together, the view map holds one
    /// entry for both, and a field fetch answers about whichever of them it
    /// finds. Each of those was held straight by a comment before the type
    /// could hold it.
    pub id: String,
    /// The item's title.
    pub title: String,
}

/// A derived snapshot: stage one, the item listing.
///
/// Immutable once built. Installing a new one replaces it whole rather than
/// patching it, so a rebuild that saw a smaller vault cannot leave names behind
/// that the vault no longer holds.
#[derive(Debug, Default)]
pub struct Index {
    minted: BTreeMap<String, Slot>,
    /// One entry per item that mints a bare name.
    ///
    /// Keyed rather than listed: [`Catalogue::summary`] and
    /// [`Catalogue::item_names`] ask about ONE item, and a list answers that by
    /// walking every item in the vault. [`Catalogue::invert`] still scans, and
    /// has to — it is asking which title is a prefix of a name, which no
    /// ordering by key answers.
    titles: BTreeMap<ItemKey, Title>,
    at: Option<Instant>,
}

/// Accumulates a snapshot from what the discoverers enumerated.
#[derive(Default)]
pub struct IndexBuilder {
    index: Index,
}

/// One item's fields, fetched on demand.
struct View {
    minted: BTreeMap<String, Entry>,
    at: Instant,
}

#[derive(Default)]
struct Inner {
    index: Index,
    views: BTreeMap<ItemKey, View>,
}

/// The names the daemon can serve, declared and derived.
///
/// Shared: the rebuilder installs into it, the store adapters read out of it,
/// and the request path consults it only after a resolve failed.
pub struct Catalogue {
    /// Written once, at construction, from the daemon's own config.
    ///
    /// # Why declared outranks derived by LOOKUP ORDER
    ///
    /// A precedence rule somebody has to remember is a rule that gets applied
    /// inconsistently at the third call site. This map is simply consulted
    /// first, so there is no rule and no second call site: an operator's
    /// declaration is what answers, whatever the vault happens to mint.
    declared: BTreeMap<String, Entry>,
    inner: Mutex<Inner>,
}

/// One store the catalogue can be rebuilt from: how to enumerate it, and how to
/// name what it holds.
pub struct Source {
    /// Reads structure and never content. See [`crate::store::discover`].
    pub discover: Box<dyn Discover + Send + Sync>,
    /// The naming rule for that store's vocabulary.
    pub mint: Box<dyn Mint + Send + Sync>,
}

/// What a miss's rebuild came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rebuilt {
    /// The catalogue now holds what the store says about this name.
    Current,
    /// The store gave no verdict in time, or failed a moment ago: nothing is
    /// known about whether the name exists.
    Silent,
}

/// Keeps the catalogue's derived index up to date, for the miss that waits on
/// it.
///
/// # Why a miss drives this and a clock does not
///
/// Every enumeration is a vendor process and a permanent off-machine audit
/// entry in the vault. A fifteen-minute poll is roughly 2,700 of those a day,
/// bought to notice a change nobody is waiting on. A miss, by contrast, is
/// somebody waiting: it is the one moment where a stale index has a cost, and
/// it is bounded by [`REBUILD_RETRY_FLOOR`](rebuild::REBUILD_RETRY_FLOOR) so a loop of unknown names cannot
/// turn into a spawn per iteration.
///
/// Dropping it stops the worker.
pub struct Rebuilder {
    engine: Arc<Engine>,
    /// Disconnects when the worker returns — a timed join, which `std` does not
    /// offer. Same shape as the resolver's.
    ///
    /// Behind a `Mutex` because a `Receiver` is `Send` and not `Sync`, and this
    /// handle is shared with every connection thread so a miss can ask from
    /// where a miss happens. Only [`Drop`] ever touches it.
    done: Mutex<std::sync::mpsc::Receiver<Never>>,
    handle: Option<JoinHandle<()>>,
}

/// What a declared map holds for `name`: under the name as sent, then under the
/// name it mints.
///
/// The one place that order is written. Declared names are the only ones an
/// operator may spell any way they like, so the caller's own spelling is asked
/// first and always wins; the minted spelling is asked only on a miss.
#[must_use]
pub fn find_declared<'a, V>(map: &'a BTreeMap<String, V>, name: &str) -> Option<&'a V> {
    declared_under(map, name, &spelling(name))
}

/// Proton Pass's naming vocabulary.
///
/// The rule was not invented here. It was DERIVED from the 50 names the live
/// daemon already served, and reproduces every one of them exactly with zero
/// collisions — re-verified against the live config on 2026-09-12 by a third
/// independent reader. `tests/catalogue.rs` holds the awkward cases verbatim as
/// a fixture, because the live declarations are in a root-owned file the suite
/// must not read.
pub struct ProtonMint;

impl Mint for ProtonMint {
    fn store(&self) -> &str {
        crate::store::proton::STORE_ID
    }

    fn name(&self, item: &ItemSummary, field: &FieldSummary) -> Option<String> {
        mint(&item.title, &field.name)
    }

    fn bare_name(&self, item: &ItemSummary) -> Option<String> {
        mint_bare(&item.title)
    }

    fn route(&self, item: &ItemSummary, field: &str) -> SecretRoute {
        SecretRoute {
            store: Some(self.store().to_owned()),
            vault: Some(item.vault.clone()),
            item: Some(item.title.clone()),
            field: Some(field.to_owned()),
            ..SecretRoute::default()
        }
    }
}
