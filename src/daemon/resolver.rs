//! One upstream call per name, however many sessions ask at once.
//!
//! # Why single-flight is a security property here, not a performance tweak
//!
//! Twenty agent sessions start within a second of each other and every one of
//! them wants `GITHUB_TOKEN`. Without coalescing that is twenty keychain
//! prompts, or twenty requests against a vault's rate limit. The rate limit
//! answers 429, every session degrades, and the fleet loses its secrets **at
//! the same moment** — which is indistinguishable from the daemon being down
//! and is exactly the shape of failure that gets a tool uninstalled.
//!
//! So the first caller for a name does the work and every caller that arrives
//! while it is in flight waits for that one answer.
//!
//! # The cache, and why it is not the cache invariant 2 forbids
//!
//! There is an in-memory TTL cache in this struct. The forbidden thing is an
//! **offline** cache: a file on disk that lets a client obtain a value while
//! the daemon is not running. Such a file has to be decryptable without the
//! daemon, which puts its key back on the calling user's side of the boundary,
//! which is a `get` verb with extra steps.
//!
//! This cache is the opposite in both properties that matter:
//!
//! - **It never touches disk.** No file, no `mmap`, no swap-backed temp. It is
//!   heap in the daemon's address space, and the daemon's memory is not
//!   readable by the calling user.
//! - **It dies with the daemon.** Killing `keylessd` empties it. There is no
//!   state left behind that anything could decrypt, so killing the daemon
//!   strictly reduces what is obtainable — never increases it.
//!
//! The distinction is written down here because it is the easiest thing in this
//! file to get wrong: "add persistence to the cache so restarts are cheap" is a
//! natural-sounding change that would void the entire design.
//!
//! Failures and absences are **not** cached. A store that is briefly down must
//! not pin every session into degraded mode for the whole TTL; the in-flight
//! coalescing already stops a failure storm from becoming a request storm.

mod fetch;
mod refresh;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::secret::Secret;
use crate::store::Registry;

use self::fetch::wait_for_timeout;

/// How long the first read past freshness waits for its own refresh before it
/// is handed the older value.
///
/// A store that answers inside this keeps a rotated value's served age at
/// roughly the freshness window, which is the bound this daemon had before
/// stale serving existed. Past it the caller gets the older value rather than
/// a vendor process's latency.
const REFRESH_GRACE: Duration = Duration::from_secs(1);

/// What resolving a name produced.
///
/// `Clone` so one upstream answer can be handed to every waiter. The value is
/// behind an `Arc` rather than copied, so N waiters share one plaintext buffer
/// and that buffer is zeroized once, when the last of them drops it.
#[derive(Clone)]
pub enum Outcome {
    /// A store answered with a value.
    Found(Arc<Secret>),
    /// Every store was healthy and none had it.
    Absent,
    /// At least one store could not answer as asked.
    Failed {
        /// Comes from a store's error text and therefore never contains a
        /// value.
        reason: String,
        /// Whether anything was actually decided about the name.
        kind: FailureKind,
    },
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Found(_) => f.write_str("Found(<redacted>)"),
            Outcome::Absent => f.write_str("Absent"),
            Outcome::Failed { reason, kind } => write!(f, "Failed({kind:?}, {reason})"),
        }
    }
}

/// Whether a failed lookup means a store took a position on the name, or
/// nothing was decided about it at all.
///
/// This is the split [`Fetched::is_silent`] already drew to decide eviction —
/// a silent failure leaves a cached value standing, a verdict evicts it —
/// carried onto [`Outcome`] itself so the audit boundary can tell the two
/// apart too. Before this type existed `record` in
/// [`crate::daemon`] flattened every failure to the same word, which is what
/// made a dead session and a store's own refusal indistinguishable after the
/// fact: distinguishing them required correlating every other row in the log
/// against the daemon's stderr, to reconstruct a fact the daemon already held
/// here and discarded at the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// Every store asked was unreachable — no network, the binary missing,
    /// the daemon's own Proton session dead — or none could be asked at all.
    /// The name's standing is exactly what it was before this call.
    Silent,
    /// A store was reached and took a position: refused the item, revoked or
    /// renamed it, or declined to be asked because the request itself is
    /// underspecified. Whatever was cached is now known wrong.
    Verdict,
    /// No store was asked, because this daemon's own config lets several of
    /// them answer the name and pins none. A fault in the daemon, not a
    /// position on the name, so a run degrades on it rather than refusing.
    Unrouted,
}

impl FailureKind {
    /// The word an audit row carries for a failed lookup.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            FailureKind::Silent => "store-silent",
            FailureKind::Verdict => "store-verdict",
            FailureKind::Unrouted => "unrouted",
        }
    }
}

/// Where the value a caller received came from.
///
/// Recorded rather than inferred, because "the daemon answered" and "a store
/// answered" are different facts about the same reply, and only the daemon can
/// tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A store was asked during this request.
    Store,
    /// Served from memory, inside the freshness window.
    Memory,
    /// Served from memory past freshness, while a refresh was running or after
    /// one could not reach the store.
    Stale,
}

impl Source {
    /// The word an audit row carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Source::Store => "store",
            Source::Memory => "memory",
            Source::Stale => "stale",
        }
    }
}

/// One resolution, and where it came from.
pub struct Answer {
    /// What resolving produced.
    pub outcome: Outcome,
    /// Which of the three routes produced it.
    pub source: Source,
    /// How long ago the store answered, on a `Memory` or `Stale` answer.
    pub age: Option<Duration>,
}

/// What one upstream call produced, and whether a failure was the store's
/// verdict or its silence.
///
/// The distinction decides eviction: a store that ANSWERED — no such item, the
/// token is refused — has told this daemon its cached value is worthless, and
/// keeping it would serve a credential the vendor has disowned. A store that
/// could not answer has said nothing about the value, and dropping it would
/// turn a slow vendor back into the outage this cache exists to prevent.
#[derive(Clone)]
struct Fetched {
    outcome: Outcome,
}

impl Fetched {
    /// Whether the store said nothing about the name at all.
    ///
    /// Derived from the outcome rather than stored beside it, so there is
    /// exactly one place this call's classification lives — [`FailureKind`]
    /// on [`Outcome::Failed`] — rather than a second copy computed
    /// independently in [`Resolver::ask_upstream`] and left to agree with it
    /// by convention.
    fn is_silent(&self) -> bool {
        matches!(
            self.outcome,
            Outcome::Failed {
                kind: FailureKind::Silent,
                ..
            }
        )
    }
}

struct Cached {
    outcome: Outcome,
    at: Instant,
}

/// One resolution in progress, and the waiters on it.
struct Flight {
    done: Mutex<Option<Fetched>>,
    ready: Condvar,
}

#[derive(Default)]
struct Shared {
    cache: HashMap<String, Cached>,
    inflight: HashMap<String, Arc<Flight>>,
    /// Names waiting for a refresh worker, and the set that says which are
    /// already waiting — the queue is a list, and a list cannot answer
    /// "already queued?" without a scan.
    queue: VecDeque<String>,
    queued: HashSet<String>,
    /// When a name's refresh last failed without reaching its store.
    silent_since: HashMap<String, Instant>,
    /// Bumped by every clear. A fetch that started before one lands after it
    /// and must not refill the cache the clear emptied — the reload that
    /// cleared it would otherwise get the old value back from a call already
    /// in the air.
    generation: u64,
}

/// Resolves names against the configured stores, once each.
pub struct Resolver {
    registry: Registry,
    ttl: Duration,
    /// How long past freshness a value may still be served while its refresh
    /// runs, or after a refresh could not reach the store. Zero disables stale
    /// serving, and a zero `ttl` disables it whatever this holds.
    stale: Duration,
    /// How old a value may be and still be served once a store asked for it
    /// gave no verdict within its timeout. Zero disables it.
    silent: Duration,
    shared: Mutex<Shared>,
    /// Wakes a refresh worker when a name is queued, and on shutdown.
    work: Condvar,
    stop: AtomicBool,
    /// Counts calls that actually reached a store. The single-flight test reads
    /// it; without an independent counter, "twenty requests made one call"
    /// could only be asserted by looking at the implementation, which is not
    /// evidence.
    upstream_calls: AtomicU64,
}

/// Running refresh workers. Dropping it stops them.
pub struct Refresher {
    resolver: Arc<Resolver>,
    /// Disconnects when the last worker returns — a timed join, which `std`
    /// does not offer. Same shape as the renewal loop's.
    done: std::sync::mpsc::Receiver<Never>,
    handles: Vec<JoinHandle<()>>,
}

/// Carried by a channel that only ever closes, never sends.
enum Never {}

impl Resolver {
    /// Wrap a registry with coalescing and a cache TTL.
    ///
    /// A zero TTL disables caching without disabling coalescing, which is the
    /// right setting for a store whose values rotate.
    #[must_use]
    pub fn new(registry: Registry, ttl: Duration) -> Self {
        Resolver {
            registry,
            ttl,
            stale: Duration::ZERO,
            silent: Duration::ZERO,
            shared: Mutex::new(Shared::default()),
            work: Condvar::new(),
            stop: AtomicBool::new(false),
            upstream_calls: AtomicU64::new(0),
        }
    }

    /// How long past freshness a value may still be served.
    ///
    /// The window only ever covers a store that could not answer: a store that
    /// answers replaces the value, and an answer that disowns it — no such
    /// item, a refused token — evicts it on the spot.
    #[must_use]
    pub fn with_stale_window(mut self, stale: Duration) -> Self {
        self.stale = stale;
        self
    }

    /// How old a value may be and still be served while its store is silent.
    ///
    /// Opens only after a fetch for the name ends in silence. A store that
    /// answers wins over it, and a name the store disowned has already been
    /// evicted, so it is never served from here.
    #[must_use]
    pub fn with_silent_window(mut self, silent: Duration) -> Self {
        self.silent = silent;
        self
    }

    /// How many times a store has actually been asked.
    #[must_use]
    pub fn upstream_calls(&self) -> u64 {
        self.upstream_calls.load(Ordering::Relaxed)
    }

    /// Resolve one name, coalescing with any concurrent request for it.
    ///
    /// Three routes, and the answer says which one it took: inside the
    /// freshness window the value comes from memory and no store is asked;
    /// past it, within the stale window, a refresh is queued and this call
    /// waits [`REFRESH_GRACE`] for it before falling back to the older value;
    /// with no entry, or one past both windows, a store is asked here — and
    /// if it is silent, a value inside the silent window is served instead.
    pub fn resolve(&self, name: &str) -> Answer {
        if let Some(answer) = self.cached_answer(name) {
            return answer;
        }
        let fetched = self.fetch(name);
        if fetched.is_silent()
            && let Some(answer) = self.silent_answer(name)
        {
            return answer;
        }
        Answer {
            outcome: fetched.outcome,
            source: Source::Store,
            age: None,
        }
    }

    /// The value held for `name`, when it is younger than the silent window.
    fn silent_answer(&self, name: &str) -> Option<Answer> {
        if self.ttl.is_zero() {
            return None;
        }
        let shared = self.lock();
        let cached = shared.cache.get(name)?;
        let age = cached.at.elapsed();
        (age < self.silent).then(|| Answer {
            outcome: cached.outcome.clone(),
            source: Source::Stale,
            age: Some(age),
        })
    }

    /// How long an entry stays in memory: until it is past every window that
    /// could still serve it.
    fn retention(&self) -> Duration {
        (self.ttl + self.stale).max(self.silent)
    }

    /// The cached routes, or `None` when a store has to be asked here.
    fn cached_answer(&self, name: &str) -> Option<Answer> {
        if self.ttl.is_zero() {
            return None;
        }
        let (outcome, age) = {
            let shared = self.lock();
            let cached = shared.cache.get(name)?;
            let age = cached.at.elapsed();
            if age >= self.ttl + self.stale {
                return None;
            }
            (cached.outcome.clone(), age)
        };

        if age < self.ttl {
            return Some(Answer {
                outcome,
                source: Source::Memory,
                age: Some(age),
            });
        }

        // Past freshness, inside the stale window. Ask for a refresh, then wait
        // briefly for it: a store that answers quickly keeps the served age at
        // the freshness window, and one that does not costs this caller a
        // second rather than a vendor process's whole latency.
        let flight = self.queue_refresh(name);
        if let Some(fetched) = flight.and_then(|flight| wait_for_timeout(&flight, REFRESH_GRACE)) {
            // The store answered. Its answer replaced or evicted the entry in
            // the worker; either way it is what this caller gets. A silent
            // failure says nothing about the value, and falls through to the
            // stale answer below instead.
            if !fetched.is_silent() {
                return Some(Answer {
                    outcome: fetched.outcome,
                    source: Source::Store,
                    age: None,
                });
            }
        }
        Some(Answer {
            outcome,
            source: Source::Stale,
            age: Some(age),
        })
    }

    /// Drop every cached value.
    ///
    /// Used on a reload, and by tests that need the next call to be a real one.
    /// A refresh already in flight lands after this and finds its own entry
    /// gone, so the cache stays empty rather than refilling behind the caller.
    pub fn clear_cache(&self) {
        let mut shared = self.lock();
        shared.cache.clear();
        shared.queue.clear();
        shared.queued.clear();
        shared.silent_since.clear();
        shared.generation = shared.generation.wrapping_add(1);
    }

    /// How many values are cached right now.
    #[must_use]
    pub fn cached_len(&self) -> usize {
        self.lock().cache.len()
    }

    /// A poisoned mutex means some other thread panicked while holding it. The
    /// data behind it is a cache and a map of in-flight markers — nothing whose
    /// invariants a panic could have broken in a way that matters — so recovery
    /// is correct, and it is certainly better than a daemon that stops
    /// answering because one connection thread panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
