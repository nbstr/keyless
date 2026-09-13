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

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::config::SecretRoute;
use crate::store::discover::{Discover, FieldSummary, ItemSummary};

/// The field whose minted name carries no suffix.
///
/// One field per item has to be the item's own name, or every credential would
/// be addressed by a two-part name and the common case — an item holding one
/// password — would read worst. `password` is the choice because it is the
/// built-in every vault backend has and the one a login item always carries.
pub const BARE_FIELD: &str = "password";

/// What separates an item's minted name from a field's.
///
/// Two underscores rather than one, so a field name cannot be confused with the
/// continuation of a title: `A_B` with field `C` and `A` with field `B_C` mint
/// `A_B__C` and `A__B_C`, which are different names. It is not a parseable
/// boundary — see the module docs — it is a joiner.
const FIELD_JOIN: &str = "__";

/// How long a fetched field view is trusted.
///
/// Long enough that a burst of misses against one item costs one vendor call;
/// short enough that a renamed field surfaces within a quarter of an hour. The
/// alternative — a polling clock — was refused deliberately: a fifteen-minute
/// poll is roughly 2,700 vendor calls a day, and every one of them is a
/// permanent off-machine audit entry in the vault. So staleness is bounded by a
/// lifetime and refreshed by DEMAND, never by a timer nobody asked for.
pub const VIEW_LIFETIME: Duration = Duration::from_secs(15 * 60);

/// How many alternatives a miss offers.
const NEAREST: usize = 5;

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

/// A store whose vocabulary can mint names.
///
/// Pure by contract: an implementation spawns nothing and reads nothing. It is a
/// naming rule, so a test can hold it against a fixture of real titles without a
/// vault anywhere in sight — which is how the 50-name reproduction is asserted.
pub trait Mint {
    /// The store id these names belong to.
    fn store(&self) -> &str;

    /// The name one field of one item mints, or `None` where the store's
    /// vocabulary cannot mint one.
    fn name(&self, item: &ItemSummary, field: &FieldSummary) -> Option<String>;

    /// The bare name of an item — the one its [`BARE_FIELD`] answers to.
    fn bare_name(&self, item: &ItemSummary) -> Option<String>;

    /// Where one minted name lives, as a route the resolver can take.
    fn route(&self, item: &ItemSummary, field: &str) -> SecretRoute;
}

/// Every character that is not ASCII-alphanumeric becomes one `_`.
///
/// # Why per CHARACTER, and why not `str::to_uppercase` first
///
/// Both halves are load-bearing and both were measured against the live
/// declarations on 2026-09-12.
///
/// Per character, because a title carrying `é` must produce ONE underscore:
/// `Type de base de données` is declared as `TYPE_DE_BASE_DE_DONN_ES`, and a
/// byte-wise walk of its UTF-8 would emit two for that one letter.
///
/// ASCII uppercase, because Unicode uppercasing is not length-preserving:
/// `ß`.to_uppercase() is `SS`, so uppercasing before the mapping would turn one
/// unmappable character into two underscores. Every character this rule keeps is
/// ASCII by construction, so there is nothing an ASCII fold can get wrong.
#[must_use]
pub fn normalise(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    // A leading digit makes the result an illegal environment variable name in
    // every shell, so `1up` is `_1UP`. Prefixed rather than dropped: dropping
    // would collide `1up` with `up`.
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// The name an item title and a field name mint together.
///
/// `password` mints the bare name, everything else appends [`FIELD_JOIN`] and
/// the normalised field. An empty title mints nothing: a name of `""`, or of
/// nothing but underscores, is not addressable and would collide with every
/// other untitled item.
#[must_use]
pub fn mint(title: &str, field: &str) -> Option<String> {
    let bare = mint_bare(title)?;
    if field.eq_ignore_ascii_case(BARE_FIELD) {
        return Some(bare);
    }
    let suffix = normalise(field);
    if suffix.is_empty() {
        return None;
    }
    Some(format!("{bare}{FIELD_JOIN}{suffix}"))
}

/// The bare name of a title, or `None` where the title mints nothing.
#[must_use]
pub fn mint_bare(title: &str) -> Option<String> {
    let bare = normalise(title);
    if bare.is_empty() {
        return None;
    }
    Some(bare)
}

/// The name a request is looked up under: what its own text mints.
///
/// A caller who addresses an item by its title — `nexus-linear`,
/// `nexus-mission__SECRET_KEY` — is asking for what that title mints, and
/// running the request through [`normalise`] reproduces the minted form exactly
/// because it IS the minting rule. Nothing is guessed: a spelling that two
/// items mint is ambiguous under either spelling alike.
///
/// Borrowed when the name is already a fixed point of [`normalise`], which
/// every minted name is, so a lookup that hits gains no allocation.
fn spelling(name: &str) -> Cow<'_, str> {
    let minted = !name.starts_with(|c: char| c.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if minted {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(normalise(name))
    }
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

fn declared_under<'a, V>(map: &'a BTreeMap<String, V>, name: &str, spelt: &str) -> Option<&'a V> {
    map.get(name)
        .or_else(|| (spelt != name).then(|| map.get(spelt)).flatten())
}

/// What one item contributes to the index.
#[derive(Debug, Clone)]
struct Minted {
    entry: Entry,
    /// The item this name came from, so a second one minting it is a collision
    /// and a second FIELD of the same item is not.
    item: ItemKey,
}

/// One name and everything that mints it.
#[derive(Debug, Clone)]
enum Slot {
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
struct Title {
    bare: String,
    /// The two fields of an [`ItemSummary`] its [`ItemKey`] does not already
    /// carry, so a lazily fetched field view can be minted without
    /// re-enumerating the vault and without a second copy of the coordinates.
    state: String,
    kind: String,
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
    fn inner(&self) -> MutexGuard<'_, Inner> {
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
    /// The miss path decides whether to queue a rebuild off that same verdict,
    /// so a [`Catalogue::route`] here walks the index a second time for an
    /// answer already in the caller's hand.
    ///
    /// A name looked up under a different [`spelling`] is shown with it, so a
    /// caller who typed an item's own title sees which minted form was tried.
    #[must_use]
    pub fn advice(&self, name: &str, route: &Route) -> String {
        // `checkout::ago` rather than a ladder of this module's own: it is the
        // one every other age in this tool is rendered through, its tiers are
        // pinned by tests, and it has a DAY tier — a second ladder that stopped
        // at hours would report a two-day-old index as `51h` beside a `2d`
        // everywhere else.
        let age = self.indexed_at().map_or_else(
            || "no index yet".to_owned(),
            |age| format!("indexed {}", crate::checkout::ago(age)),
        );
        let shown = match spelling(name) {
            Cow::Owned(spelt) => format!("`{name}` (tried `{spelt}`)"),
            Cow::Borrowed(_) => format!("`{name}`"),
        };
        if let Some(item) = self.invert(name) {
            let names = self.item_names(&item);
            if !names.is_empty() {
                return format!(
                    "nothing is bound to {shown}; the item behind that name serves: {} ({age})",
                    names.join(", ")
                );
            }
        }
        match route {
            Route::Ambiguous { stores, items } => format!(
                "{shown} is minted by {items} items across {} ({age}); declare it to say which",
                stores.join(", ")
            ),
            Route::Unknown { nearest, .. } if !nearest.is_empty() => format!(
                "nothing is bound to {shown}; nearest served names: {} ({age})",
                nearest.join(", ")
            ),
            _ => format!("nothing is bound to {shown} ({age})"),
        }
    }
}

/// What the derived half of the catalogue says about one name.
///
/// An enum rather than a count beside an optional entry, because that pairing
/// can spell a state with no meaning — one minting and no entry to serve it —
/// and every reader then has to decide what to do about it. [`names_in`] read
/// the count alone and would have listed such a name while [`Catalogue::route`]
/// refused it, which is the listing-versus-resolver disagreement
/// [`Catalogue::names`] exists to prevent.
enum Mintings {
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
fn mintings(inner: &Inner, name: &str) -> Mintings {
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
fn names_in(inner: &Inner) -> BTreeSet<String> {
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

/// How long a failed rebuild waits before another is started.
///
/// Mirrors [`crate::daemon::resolver`]'s refresh floor, and for the same
/// reason: a store that is down must not be asked once per miss. Without it a
/// script looping over unknown names turns one outage into a spawn per
/// iteration, each one a permanent off-machine audit entry.
const REBUILD_RETRY_FLOOR: Duration = Duration::from_secs(5);

/// How long shutdown waits for the rebuild worker before it stops waiting.
///
/// The same bound and the same reasoning as the resolver's: a worker parked
/// inside a vendor call cannot see the stop flag, and holding the process open
/// for it is worse than leaving it to finish.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// One store the catalogue can be rebuilt from: how to enumerate it, and how to
/// name what it holds.
pub struct Source {
    /// Reads structure and never content. See [`crate::store::discover`].
    pub discover: Box<dyn Discover + Send + Sync>,
    /// The naming rule for that store's vocabulary.
    pub mint: Box<dyn Mint + Send + Sync>,
}

/// What the worker has been asked to do.
#[derive(Default)]
struct Work {
    /// A full re-enumeration is wanted.
    full: bool,
    /// One is running right now.
    ///
    /// # Why "wanted" is not enough on its own
    ///
    /// The worker clears `full` when it TAKES the task, not when it finishes
    /// it, so every request arriving during the enumeration re-arms the flag
    /// and buys a second whole enumeration the moment the first lands. The
    /// window is the length of a vault walk — one `vault list` plus one `item
    /// list` per vault — and the requests arriving inside it are not rare: a
    /// daemon that has never enumerated queues one on every `Op::Names`, so a
    /// caller polling `keyless ls` while the first rebuild runs costs one
    /// enumeration per poll, each a permanent off-machine audit entry.
    ///
    /// A request that arrives while one is running wants what that one is
    /// already fetching, so it is dropped rather than queued.
    running: bool,
    /// Items whose field view a miss asked for.
    items: VecDeque<ItemKey>,
    /// When the last attempt failed without producing a snapshot.
    failed_at: Option<Instant>,
}

struct Engine {
    catalogue: Arc<Catalogue>,
    sources: Vec<Source>,
    work: Mutex<Work>,
    wake: Condvar,
    stop: AtomicBool,
}

/// Keeps the catalogue's derived index up to date, off the request path.
///
/// # Why a miss drives this and a clock does not
///
/// Every enumeration is a vendor process and a permanent off-machine audit
/// entry in the vault. A fifteen-minute poll is roughly 2,700 of those a day,
/// bought to notice a change nobody is waiting on. A miss, by contrast, is
/// somebody waiting: it is the one moment where a stale index has a cost, and
/// it is bounded by [`REBUILD_RETRY_FLOOR`] so a loop of unknown names cannot
/// turn into a spawn per iteration.
///
/// Dropping it stops the worker.
pub struct Rebuilder {
    engine: Arc<Engine>,
    /// Disconnects when the worker returns — a timed join, which `std` does not
    /// offer. Same shape as the resolver's.
    ///
    /// Behind a `Mutex` because a `Receiver` is `Send` and not `Sync`, and this
    /// handle is shared with every connection thread so a miss can queue from
    /// where a miss happens. Only [`Drop`] ever touches it.
    done: Mutex<std::sync::mpsc::Receiver<Never>>,
    handle: Option<JoinHandle<()>>,
}

/// Carried by a channel that only ever closes, never sends.
enum Never {}

impl Drop for Rebuilder {
    fn drop(&mut self) {
        // Under the work lock, which is what makes the wait below safe to be
        // unbounded. The worker holds that lock across "is stop set?" and
        // "wait", so a flag set while it holds the lock cannot land between the
        // two and leave a notification with nobody to receive it. Set outside
        // it, the worker could read `false`, this could notify, and the worker
        // could then wait forever on a daemon that is shutting down.
        {
            let _work = self.engine.lock();
            self.engine.stop.store(true, Ordering::Relaxed);
        }
        self.engine.wake.notify_all();
        let done = self.done.lock().unwrap_or_else(PoisonError::into_inner);
        match done.recv_timeout(SHUTDOWN_GRACE) {
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                drop(done);
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
            }
            // Parked inside a vendor call. Left detached, exactly as the
            // resolver leaves its own: it holds no lock this process needs, and
            // the alternative is not exiting.
            _ => {
                let _ = writeln!(
                    std::io::stderr(),
                    "{}d: a catalogue rebuild is still waiting on its store; shutting down \
                     without it",
                    crate::NAME
                );
            }
        }
    }
}

impl Rebuilder {
    /// Start the worker. Dropping the returned handle stops it.
    ///
    /// One worker, not two: a rebuild is a whole-vault enumeration and there is
    /// never useful parallelism between two of them, where the resolver's two
    /// workers exist so one slow NAME cannot hold the queue.
    #[must_use]
    pub fn start(catalogue: &Arc<Catalogue>, sources: Vec<Source>) -> Self {
        let engine = Arc::new(Engine {
            catalogue: Arc::clone(catalogue),
            sources,
            work: Mutex::new(Work::default()),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
        });
        let (alive, done) = std::sync::mpsc::channel::<Never>();
        let worker = Arc::clone(&engine);
        let handle = std::thread::Builder::new()
            .name(format!("{}d-catalogue", crate::NAME))
            .spawn(move || {
                worker.run();
                drop(alive);
            })
            .ok();
        Rebuilder {
            engine,
            done: Mutex::new(done),
            handle,
        }
    }

    /// Ask for whatever this missed name needs, and say whether anything was
    /// queued.
    ///
    /// A name that inverts onto a live title needs that ONE item's fields —
    /// stage two, one vendor call. A name that inverts onto nothing needs a
    /// fresh listing, which is stage one. A name that inverts onto an item
    /// whose view is already fresh needs nothing at all: the answer is that the
    /// item does not serve it, and asking again would not change that.
    pub fn queue(&self, name: &str) -> bool {
        let catalogue = &self.engine.catalogue;
        let mut work = self.engine.lock();
        if work
            .failed_at
            .is_some_and(|at| at.elapsed() < REBUILD_RETRY_FLOOR)
        {
            return false;
        }
        let queued = match catalogue.invert(name) {
            Some(item) if !catalogue.view_is_fresh(&item) => {
                if work.items.contains(&item) {
                    false
                } else {
                    work.items.push_back(item);
                    true
                }
            }
            Some(_) => false,
            None => {
                let fresh = !work.full && !work.running;
                work.full = fresh;
                fresh
            }
        };
        drop(work);
        if queued {
            self.engine.wake.notify_one();
        }
        queued
    }

    /// Ask for a full enumeration, whatever the floor says.
    ///
    /// The startup call. A daemon that has just bound has no index at all, and
    /// the floor exists to bound RETRIES rather than to delay the first one.
    pub fn queue_full(&self) {
        let mut work = self.engine.lock();
        // Floored on the same terms as `queue`, and for a reason the `running`
        // guard does not cover: a rebuild that FAILED installs nothing, so
        // `indexed_at()` stays `None` and the daemon asks again on every
        // listing. Against a store that is down, N `keyless ls` invocations
        // would buy N whole vault walks — and each of those is a permanent
        // off-machine audit entry. The FIRST attempt is unfloored, because
        // `failed_at` is only set once one has already been made.
        let floored = work
            .failed_at
            .is_some_and(|at| at.elapsed() < REBUILD_RETRY_FLOOR);
        if work.running || floored {
            return;
        }
        work.full = true;
        drop(work);
        self.engine.wake.notify_one();
    }
}

impl Engine {
    fn lock(&self) -> MutexGuard<'_, Work> {
        self.work.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn run(&self) {
        loop {
            let taken = {
                let mut work = self.lock();
                loop {
                    if self.stop.load(Ordering::Relaxed) {
                        return;
                    }
                    if work.full {
                        work.full = false;
                        work.running = true;
                        break Task::Full;
                    }
                    if let Some(item) = work.items.pop_front() {
                        break Task::Fields(item);
                    }
                    // Unbounded, with no timeout to re-check the stop flag on:
                    // `Drop` sets that flag and then calls `notify_all`, and
                    // nothing else ever writes it, so there is no state this
                    // wait could miss. A timed wait here would be 345,600
                    // wakeups a day on a daemon nobody queries.
                    //
                    // The resolver's own worker, which this otherwise mirrors,
                    // does need one: it sweeps expired cache entries on a
                    // timer, so its idle ticks are work. This one has no sweep,
                    // because the index is replaced whole rather than expired
                    // entry by entry.
                    work = self.wake.wait(work).unwrap_or_else(PoisonError::into_inner);
                }
            };
            match taken {
                Task::Full => {
                    self.rebuild();
                    self.lock().running = false;
                }
                Task::Fields(item) => self.fetch_fields(&item),
            }
        }
    }

    /// Re-enumerate every source and install the result.
    ///
    /// # Why a partial enumeration installs nothing
    ///
    /// An index built from the sources that answered is not a smaller truth, it
    /// is a wrong one: every name the unreachable store mints would vanish from
    /// `names()` and from every route, so a store being briefly down would read
    /// exactly like its items having been deleted. The previous snapshot is
    /// older and correct, so it stands, and the failure is floored so the next
    /// miss does not spawn again immediately.
    fn rebuild(&self) {
        let mut building = IndexBuilder::new();
        for source in &self.sources {
            let Ok(items) = source.discover.items(None) else {
                self.lock().failed_at = Some(Instant::now());
                return;
            };
            for item in &items {
                building.item(source.mint.as_ref(), item);
            }
        }
        self.lock().failed_at = None;
        self.catalogue.install(building.finish());
    }

    /// Fetch one item's fields — stage two.
    fn fetch_fields(&self, item: &ItemKey) {
        let Some(source) = self
            .sources
            .iter()
            .find(|source| source.mint.store() == item.store)
        else {
            return;
        };
        let Some(summary) = self.catalogue.summary(item) else {
            return;
        };
        let vault = (!item.vault.is_empty()).then_some(item.vault.as_str());
        match source.discover.fields(vault, &item.title) {
            Ok(fields) => {
                self.lock().failed_at = None;
                self.catalogue
                    .install_view(item, source.mint.as_ref(), &summary, &fields);
            }
            Err(_) => self.lock().failed_at = Some(Instant::now()),
        }
    }
}

enum Task {
    Full,
    Fields(ItemKey),
}

#[cfg(test)]
mod tests {
    use super::{normalise, spelling};
    use std::borrow::Cow;

    #[test]
    fn a_borrowed_spelling_is_exactly_what_normalise_would_have_returned() {
        // The borrow is a shortcut past `normalise`, so it is only sound where
        // `normalise` is the identity. Each side of that boundary is here.
        for name in [
            "NEXUS_LINEAR",
            "NEXUS_MISSION__SECRET_KEY",
            "_1UP",
            "",
            "nexus-linear",
            "Nexus_Linear",
            "1UP",
            "A B",
            "données",
        ] {
            let spelt = spelling(name);
            assert_eq!(spelt, normalise(name), "{name}");
            assert_eq!(
                matches!(spelt, Cow::Borrowed(_)),
                normalise(name) == name,
                "{name}"
            );
        }
    }
}
