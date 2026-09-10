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

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::{Registry, Resolution};

/// Upper bound on cached names.
///
/// A client can ask for any name it likes, and every miss would otherwise be a
/// permanent entry. Bounded so a hostile or careless caller cannot grow the
/// daemon's heap by naming secrets that do not exist — though only successes
/// are cached, which already makes that hard.
const MAX_CACHE_ENTRIES: usize = 256;

/// How many refreshes may be in flight at once.
///
/// Two rather than one, so a single slow name does not hold the queue, and not
/// more, because every refresh is a vendor process and the point of this whole
/// mechanism is to ask the vendor no more often than expiry already did.
const REFRESH_WORKERS: usize = 2;

/// How long the first read past freshness waits for its own refresh before it
/// is handed the older value.
///
/// A store that answers inside this keeps a rotated value's served age at
/// roughly the freshness window, which is the bound this daemon had before
/// stale serving existed. Past it the caller gets the older value rather than
/// a vendor process's latency.
const REFRESH_GRACE: Duration = Duration::from_secs(1);

/// How long a name whose refresh failed transiently waits before another is
/// started.
///
/// Mirrors the renewal loop's own floor: a store that is down must not be
/// asked once per read while every reader is being served from memory anyway.
const REFRESH_RETRY_FLOOR: Duration = Duration::from_secs(5);

/// How often the workers drop entries nobody has read since they went stale.
///
/// Without it a value stays resident until something asks for it again, and
/// residency is the one cost of holding plaintext in memory at all.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How long a worker's idle wait runs before it re-checks the stop flag.
const WORKER_POLL: Duration = Duration::from_millis(250);

/// How long shutdown waits for the refresh workers before it stops waiting.
///
/// The same bound and the same reasoning as the renewal loop's: a worker
/// parked inside a vendor call cannot see the stop flag, and holding the
/// process open for it is worse than leaving it to finish.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

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
    /// At least one store could not answer. Carries the reason, which comes
    /// from a store's error text and therefore never contains a value.
    Failed(String),
}

impl std::fmt::Debug for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Found(_) => f.write_str("Found(<redacted>)"),
            Outcome::Absent => f.write_str("Absent"),
            Outcome::Failed(reason) => write!(f, "Failed({reason})"),
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
    /// Every error was a store that could not answer.
    silent: bool,
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

impl Drop for Refresher {
    fn drop(&mut self) {
        self.resolver.stop.store(true, Ordering::Relaxed);
        self.resolver.work.notify_all();
        match self.done.recv_timeout(SHUTDOWN_GRACE) {
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                for handle in self.handles.drain(..) {
                    let _ = handle.join();
                }
            }
            // A worker is still inside a vendor call. Left detached, exactly
            // as the renewal loop leaves its own: it holds no lock this
            // process needs, and the alternative is not exiting.
            _ => {
                let _ = writeln!(
                    std::io::stderr(),
                    "{}d: a refresh is still waiting on its store; shutting down without it",
                    crate::NAME
                );
            }
        }
    }
}

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

    /// Start the refresh workers. Dropping the returned handle stops them.
    ///
    /// Separate from construction so a caller that never serves — a check, a
    /// test reading the cache directly — starts no threads at all.
    #[must_use]
    pub fn start(resolver: &Arc<Self>) -> Refresher {
        let (alive, done) = std::sync::mpsc::channel::<Never>();
        let mut handles = Vec::with_capacity(REFRESH_WORKERS);
        for worker in 0..REFRESH_WORKERS {
            let resolver = Arc::clone(resolver);
            let alive = alive.clone();
            if let Ok(handle) = std::thread::Builder::new()
                .name(format!("{}d-refresh-{worker}", crate::NAME))
                .spawn(move || {
                    resolver.refresh_loop();
                    drop(alive);
                })
            {
                handles.push(handle);
            }
        }
        drop(alive);
        Refresher {
            resolver: Arc::clone(resolver),
            done,
            handles,
        }
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
    /// with no entry, or one past both windows, a store is asked here.
    pub fn resolve(&self, name: &str) -> Answer {
        if let Some(answer) = self.cached_answer(name) {
            return answer;
        }
        let fetched = self.fetch(name);
        Answer {
            outcome: fetched.outcome,
            source: Source::Store,
            age: None,
        }
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
            match fetched {
                // The store answered. Its answer replaced or evicted the entry
                // in the worker; either way it is what this caller gets.
                Fetched { outcome, silent } if !silent => {
                    return Some(Answer {
                        outcome,
                        source: Source::Store,
                        age: None,
                    });
                }
                // It could not answer, which says nothing about the value.
                _ => {}
            }
        }
        Some(Answer {
            outcome,
            source: Source::Stale,
            age: Some(age),
        })
    }

    /// Queue a refresh for `name`, unless one is already queued, already
    /// running, or its last attempt failed inside [`REFRESH_RETRY_FLOOR`].
    ///
    /// Returns the flight to wait on — the one already running, or the one
    /// this call just created for the worker to fulfil.
    ///
    /// The flight is created HERE rather than in the worker, so the reader that
    /// asked for the refresh has something to wait its grace on. Created in the
    /// worker instead, the reader would find nothing to wait for and would fall
    /// straight through to the older value, and the grace would never apply to
    /// the case it exists for.
    fn queue_refresh(&self, name: &str) -> Option<Arc<Flight>> {
        let mut shared = self.lock();
        if let Some(flight) = shared.inflight.get(name) {
            return Some(Arc::clone(flight));
        }
        if let Some(since) = shared.silent_since.get(name)
            && since.elapsed() < REFRESH_RETRY_FLOOR
        {
            return None;
        }
        if shared.queued.contains(name) {
            return None;
        }
        let flight = Arc::new(Flight {
            done: Mutex::new(None),
            ready: Condvar::new(),
        });
        shared.inflight.insert(name.to_owned(), Arc::clone(&flight));
        shared.queued.insert(name.to_owned());
        shared.queue.push_back(name.to_owned());
        drop(shared);
        self.work.notify_one();
        Some(flight)
    }

    /// One refresh worker: take a name, refresh it, and sweep between names.
    fn refresh_loop(&self) {
        let mut last_sweep = Instant::now();
        while !self.stop.load(Ordering::Relaxed) {
            let next = {
                let mut shared = self.lock();
                loop {
                    if self.stop.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(name) = shared.queue.pop_front() {
                        break Some(name);
                    }
                    let (guard, timeout) = self
                        .work
                        .wait_timeout(shared, WORKER_POLL)
                        .unwrap_or_else(PoisonError::into_inner);
                    shared = guard;
                    if timeout.timed_out() {
                        break None;
                    }
                }
            };

            match next {
                Some(name) => {
                    // The flight was created when the name was queued, and the
                    // reader that queued it may be waiting on that one — so
                    // this fulfils it rather than opening a second.
                    let queued = self.lock().inflight.get(&name).map(Arc::clone);
                    match queued {
                        Some(flight) => {
                            self.run_fetch(&name, &flight);
                        }
                        None => {
                            self.fetch(&name);
                        }
                    }
                    self.lock().queued.remove(&name);
                }
                None => {
                    if last_sweep.elapsed() >= SWEEP_INTERVAL {
                        self.sweep();
                        last_sweep = Instant::now();
                    }
                }
            }
        }
    }

    /// Drop every entry past both windows, so a value nobody reads again does
    /// not sit in memory until something else evicts it.
    fn sweep(&self) {
        let horizon = self.ttl + self.stale;
        let mut shared = self.lock();
        shared
            .cache
            .retain(|_, cached| cached.at.elapsed() < horizon);
        shared
            .silent_since
            .retain(|_, since| since.elapsed() < REFRESH_RETRY_FLOOR);
    }

    /// Ask a store, coalescing with any concurrent fetch for the same name,
    /// and put what comes back into the cache.
    fn fetch(&self, name: &str) -> Fetched {
        // Either this call becomes the leader for `name`, or it joins the
        // flight already under way. The lock is held only long enough to decide
        // which; the upstream call happens with nothing locked, or twenty
        // sessions would serialise behind one slow keychain.
        let flight = {
            let mut shared = self.lock();
            match shared.inflight.get(name) {
                Some(existing) => {
                    let existing = Arc::clone(existing);
                    drop(shared);
                    return wait_for(&existing);
                }
                None => {
                    let flight = Arc::new(Flight {
                        done: Mutex::new(None),
                        ready: Condvar::new(),
                    });
                    shared.inflight.insert(name.to_owned(), Arc::clone(&flight));
                    flight
                }
            }
        };
        self.run_fetch(name, &flight)
    }

    /// Ask a store for `name` and publish the answer to `flight`, which is
    /// already registered as this name's in-flight resolution.
    fn run_fetch(&self, name: &str, flight: &Arc<Flight>) -> Fetched {
        let generation = self.lock().generation;
        let fetched = self.ask_upstream(name);

        {
            let mut shared = self.lock();
            shared.inflight.remove(name);
            if shared.generation != generation {
                // Cleared while this was in the air. Publishing to the waiters
                // still happens — they asked, and the store answered them — but
                // nothing of it is kept.
                shared.silent_since.remove(name);
                drop(shared);
                let mut done = flight.done.lock().unwrap_or_else(PoisonError::into_inner);
                *done = Some(fetched.clone());
                drop(done);
                flight.ready.notify_all();
                return fetched;
            }
            match &fetched {
                // A value: it replaces whatever was there, and its clock starts
                // again.
                Fetched {
                    outcome: outcome @ Outcome::Found(_),
                    ..
                } if !self.ttl.is_zero() => {
                    shared.silent_since.remove(name);
                    evict_if_full(&mut shared.cache);
                    shared.cache.insert(
                        name.to_owned(),
                        Cached {
                            outcome: outcome.clone(),
                            at: Instant::now(),
                        },
                    );
                }
                // The store could not answer. The entry stands, and the floor
                // stops the next reader asking again immediately.
                Fetched { silent: true, .. } => {
                    shared.silent_since.insert(name.to_owned(), Instant::now());
                }
                // The store answered about this name and had nothing, or
                // refused. Whatever is held is disowned by the only party that
                // could say so.
                _ => {
                    shared.cache.remove(name);
                    shared.silent_since.remove(name);
                }
            }
        }

        // Publish to the waiters after the shared state is consistent, so a
        // woken waiter that re-enters `resolve` sees the cache already filled.
        {
            let mut done = flight.done.lock().unwrap_or_else(PoisonError::into_inner);
            *done = Some(fetched.clone());
        }
        flight.ready.notify_all();

        fetched
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

    fn ask_upstream(&self, name: &str) -> Fetched {
        self.upstream_calls.fetch_add(1, Ordering::Relaxed);
        let silent = |errors: &[StoreError]| {
            !errors.is_empty()
                && errors
                    .iter()
                    .all(|error| matches!(error, StoreError::Unavailable { .. }))
        };
        let outcome = match self.registry.resolve(name) {
            Resolution::Found { secret, .. } => Outcome::Found(Arc::new(secret)),
            // One shape of absence arrives here, not two, and the wildcard is
            // what records that rather than a collapse of two live cases:
            // [`crate::daemon::config::DaemonConfig::registry`] never calls
            // [`Registry::with_declared_names`], so `undeclared` is false on
            // this side always.
            //
            // That is not an omission. The daemon has no declared population to
            // check a name against — `names` is the allowlist for the `names`
            // verb, `secrets` is routing read only for its `store` key — so what
            // the daemon serves is whatever its store holds, and asking the
            // store is how it finds out.
            //
            // Which makes `Absent` the accurate word here: a store was asked,
            // under the coordinate its adapter derived from the name, and did
            // not have it. A session resolving the same undeclared name does
            // exactly the same thing and differs only in the sentence printed
            // afterwards — `12a3896` changed that sentence, never the ordering,
            // which is why there is no refusal on the session side for this one
            // to be missing. `tests/daemon.rs` holds that down by watching the
            // store be asked, because it is not readable from here.
            Resolution::NotFound { .. } => Outcome::Absent,
            Resolution::Failed(errors) => {
                // Read before the errors are flattened into one sentence: the
                // variants are what say whether a store answered, and a string
                // cannot be asked that afterwards.
                let could_not_answer = silent(&errors);
                let reason = errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                return Fetched {
                    outcome: Outcome::Failed(reason),
                    silent: could_not_answer,
                };
            }
            // Several of the daemon's own backends could have meant this name
            // and none is pinned. Nothing was asked, so nothing is known about
            // whether the name exists — and guessing is the cross-tenant leak
            // that policy exists to prevent.
            //
            // It reaches the caller as a failure naming the candidates, which
            // degrades the run. That is the right side of the boundary for this
            // decision: the client cannot fix it and must not be able to,
            // because the client is the untrusted party. The daemon's operator
            // fixes it in the daemon's config.
            //
            // Which is why the sentence says WHOSE config. The registry's own
            // wording names `"store"` and `stores.default` without saying which
            // file they belong in, and the reader of a degraded run is holding
            // the wrong one: their session's pins were dropped on purpose by
            // `store::build`, so editing them changes nothing at all.
            ambiguous @ Resolution::Ambiguous { .. } => Outcome::Failed(format!(
                "{} — in keylessd's own config file, not this session's; \
                 a session cannot settle which of the daemon's stores a name means",
                ambiguous.reason()
            )),
        };
        // Everything that reaches here is the store's own answer about the
        // name, including an ambiguity, which is this daemon's config saying
        // no store may be asked at all.
        Fetched {
            outcome,
            silent: false,
        }
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

fn wait_for(flight: &Arc<Flight>) -> Fetched {
    let mut done = flight.done.lock().unwrap_or_else(PoisonError::into_inner);
    while done.is_none() {
        done = flight
            .ready
            .wait(done)
            .unwrap_or_else(PoisonError::into_inner);
    }
    done.clone().unwrap_or(Fetched {
        outcome: Outcome::Failed("the resolution finished without a result".to_owned()),
        silent: true,
    })
}

/// The flight's answer, or `None` when it has not landed inside `grace`.
///
/// A reader past freshness holds a value already, so waiting longer buys a
/// fresher answer at the cost of the latency this whole mechanism exists to
/// take off the request path.
fn wait_for_timeout(flight: &Arc<Flight>, grace: Duration) -> Option<Fetched> {
    let deadline = Instant::now() + grace;
    let mut done = flight.done.lock().unwrap_or_else(PoisonError::into_inner);
    while done.is_none() {
        let left = deadline.checked_duration_since(Instant::now())?;
        let (guard, timeout) = flight
            .ready
            .wait_timeout(done, left)
            .unwrap_or_else(PoisonError::into_inner);
        done = guard;
        if timeout.timed_out() {
            return done.clone();
        }
    }
    done.clone()
}

fn evict_if_full(cache: &mut HashMap<String, Cached>) {
    if cache.len() < MAX_CACHE_ENTRIES {
        return;
    }
    // Oldest first. A cache this small does not justify a heap or an LRU list.
    if let Some(oldest) = cache
        .iter()
        .min_by_key(|(_, cached)| cached.at)
        .map(|(name, _)| name.clone())
    {
        cache.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_CACHE_ENTRIES, Outcome, Resolver};
    use crate::error::StoreError;
    use crate::secret::Secret;
    use crate::store::{Registry, Store};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    /// A store that counts its calls and can be made slow, so a race is
    /// reproducible rather than hoped for.
    struct Counting {
        calls: Arc<AtomicU64>,
        delay: Duration,
        value: Option<&'static str>,
    }

    impl Store for Counting {
        fn id(&self) -> &str {
            "counting"
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            Ok(self.value.map(|v| Secret::new(v.to_owned())))
        }
        fn health(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    /// A second store, so ambiguity has two candidates to name.
    struct Named(&'static str);

    impl Store for Named {
        fn id(&self) -> &str {
            self.0
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            Ok(Some(Secret::new("decoy-two".to_owned())))
        }
        fn health(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    fn resolver(
        calls: &Arc<AtomicU64>,
        delay: Duration,
        value: Option<&'static str>,
        ttl: Duration,
    ) -> Resolver {
        Resolver::new(
            Registry::new(vec![Box::new(Counting {
                calls: Arc::clone(calls),
                delay,
                value,
            })]),
            ttl,
        )
    }

    #[test]
    fn twenty_concurrent_requests_make_one_upstream_call() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = Arc::new(resolver(
            &calls,
            Duration::from_millis(80),
            Some("decoy-single-flight"),
            Duration::ZERO,
        ));
        // TTL is zero, so nothing is cached: a second call would show up in the
        // counter. Any coalescing seen here is coalescing, not caching.
        let gate = Arc::new(Barrier::new(20));
        std::thread::scope(|scope| {
            for _ in 0..20 {
                let resolver = Arc::clone(&resolver);
                let gate = Arc::clone(&gate);
                scope.spawn(move || {
                    gate.wait();
                    match resolver.resolve("SHARED").outcome {
                        Outcome::Found(secret) => {
                            assert_eq!(secret.expose(), "decoy-single-flight");
                        }
                        other => panic!("expected a value, got {other:?}"),
                    }
                });
            }
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "twenty simultaneous requests for one name must reach the store once"
        );
        assert_eq!(resolver.upstream_calls(), 1);
    }

    #[test]
    fn different_names_are_not_coalesced_with_each_other() {
        // The negative control for the test above: if `resolve` coalesced
        // everything rather than per name, this would also report one call.
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = Arc::new(resolver(
            &calls,
            Duration::from_millis(40),
            Some("decoy"),
            Duration::ZERO,
        ));
        std::thread::scope(|scope| {
            for i in 0..6 {
                let resolver = Arc::clone(&resolver);
                scope.spawn(move || {
                    let _ = resolver.resolve(&format!("NAME_{i}"));
                });
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn a_cached_value_is_served_without_touching_the_store() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = resolver(
            &calls,
            Duration::ZERO,
            Some("decoy-cached"),
            Duration::from_secs(60),
        );
        for _ in 0..5 {
            assert!(matches!(resolver.resolve("X").outcome, Outcome::Found(_)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resolver.cached_len(), 1);
    }

    #[test]
    fn an_expired_entry_is_fetched_again() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = resolver(
            &calls,
            Duration::ZERO,
            Some("decoy-expiring"),
            Duration::from_millis(30),
        );
        assert!(matches!(resolver.resolve("X").outcome, Outcome::Found(_)));
        std::thread::sleep(Duration::from_millis(60));
        assert!(matches!(resolver.resolve("X").outcome, Outcome::Found(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_failure_is_never_cached() {
        // A store that is briefly down must not pin every session into
        // degraded mode for the whole TTL.
        struct Broken;
        impl Store for Broken {
            fn id(&self) -> &str {
                "broken"
            }
            fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
                Err(StoreError::Unavailable {
                    store: "broken".to_owned(),
                    detail: "down".to_owned(),
                })
            }
            fn health(&self) -> Result<(), StoreError> {
                Err(StoreError::Unavailable {
                    store: "broken".to_owned(),
                    detail: "down".to_owned(),
                })
            }
        }
        let resolver = Resolver::new(
            Registry::new(vec![Box::new(Broken)]),
            Duration::from_secs(600),
        );
        assert!(matches!(resolver.resolve("X").outcome, Outcome::Failed(_)));
        assert!(matches!(resolver.resolve("X").outcome, Outcome::Failed(_)));
        assert_eq!(resolver.cached_len(), 0);
        assert_eq!(resolver.upstream_calls(), 2);
    }

    #[test]
    fn an_absence_is_never_cached_either() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = resolver(&calls, Duration::ZERO, None, Duration::from_secs(600));
        assert!(matches!(resolver.resolve("X").outcome, Outcome::Absent));
        assert!(matches!(resolver.resolve("X").outcome, Outcome::Absent));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resolver.cached_len(), 0);
    }

    #[test]
    fn the_cache_is_bounded() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = resolver(
            &calls,
            Duration::ZERO,
            Some("decoy"),
            Duration::from_secs(600),
        );
        for i in 0..(MAX_CACHE_ENTRIES + 40) {
            let _ = resolver.resolve(&format!("N{i}"));
        }
        assert!(resolver.cached_len() <= MAX_CACHE_ENTRIES);
    }

    #[test]
    fn clearing_the_cache_makes_the_next_call_real() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = resolver(
            &calls,
            Duration::ZERO,
            Some("decoy"),
            Duration::from_secs(600),
        );
        let _ = resolver.resolve("X");
        resolver.clear_cache();
        let _ = resolver.resolve("X");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn an_ambiguous_name_says_which_config_file_can_settle_it() {
        // The remedy has to name the daemon's file. A reader who applies it to
        // the session's config changes nothing — `store::build` drops a
        // session's pins whenever the daemon is enabled — and then has a
        // config that looks correct and a run that still degrades.
        let registry = Registry::new(vec![
            Box::new(Counting {
                calls: Arc::new(AtomicU64::new(0)),
                delay: Duration::ZERO,
                value: Some("decoy-one"),
            }),
            Box::new(Named("other")),
        ]);
        match Resolver::new(registry, Duration::ZERO)
            .resolve("DATABASE_URL")
            .outcome
        {
            Outcome::Failed(reason) => {
                assert!(reason.contains("keylessd"), "{reason}");
                assert!(reason.contains("stores.default"), "{reason}");
                assert!(!reason.contains("decoy-"), "the reason leaked a value");
            }
            other => panic!("expected a failure naming the candidates, got {other:?}"),
        }
    }

    /// What a scripted store answers on one call.
    #[derive(Clone, Copy)]
    enum Reply {
        Value(&'static str),
        /// The store was asked and had nothing.
        Absent,
        /// The store could not be reached — the one shape that keeps a cached
        /// value alive.
        Silent,
        /// The store answered and disowned the value.
        Verdict,
    }

    /// A store whose answer changes per call, so a refresh can answer
    /// differently from the read that filled the cache. The last reply repeats.
    struct Scripted {
        calls: Arc<AtomicU64>,
        delay: Duration,
        replies: Vec<Reply>,
    }

    impl Store for Scripted {
        fn id(&self) -> &str {
            "scripted"
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) as usize;
            std::thread::sleep(self.delay);
            let reply = self
                .replies
                .get(call)
                .or_else(|| self.replies.last())
                .copied()
                .unwrap_or(Reply::Absent);
            match reply {
                Reply::Value(value) => Ok(Some(Secret::new(value.to_owned()))),
                Reply::Absent => Ok(None),
                Reply::Silent => Err(StoreError::Unavailable {
                    store: "scripted".to_owned(),
                    detail: "no answer".to_owned(),
                }),
                Reply::Verdict => Err(StoreError::Backend {
                    store: "scripted".to_owned(),
                    detail: "the item is in the trash".to_owned(),
                }),
            }
        }
        fn health(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    fn scripted(
        calls: &Arc<AtomicU64>,
        delay: Duration,
        replies: Vec<Reply>,
        ttl: Duration,
        stale: Duration,
    ) -> Arc<Resolver> {
        Arc::new(
            Resolver::new(
                Registry::new(vec![Box::new(Scripted {
                    calls: Arc::clone(calls),
                    delay,
                    replies,
                })]),
                ttl,
            )
            .with_stale_window(stale),
        )
    }

    fn value_of(answer: &super::Answer) -> String {
        match &answer.outcome {
            Outcome::Found(secret) => secret.expose().to_owned(),
            other => panic!("expected a value, got {other:?}"),
        }
    }

    #[test]
    fn a_fresh_value_is_served_from_memory_and_says_where_it_came_from() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::ZERO,
            vec![Reply::Value("decoy-warm")],
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        assert_eq!(resolver.resolve("X").source, super::Source::Store);
        let second = resolver.resolve("X");
        assert_eq!(second.source, super::Source::Memory);
        assert_eq!(value_of(&second), "decoy-warm");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_store_slower_than_the_grace_is_answered_from_memory_meanwhile() {
        // The property the whole mechanism exists for: past freshness, with a
        // store that takes longer than a caller should wait, the caller gets
        // the value it had rather than the vendor's latency.
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::from_secs(2),
            vec![Reply::Value("decoy-first"), Reply::Value("decoy-second")],
            Duration::from_millis(50),
            Duration::from_secs(60),
        );
        let refresher = Resolver::start(&resolver);

        let cold = resolver.resolve("X");
        assert_eq!(cold.source, super::Source::Store);
        assert_eq!(value_of(&cold), "decoy-first");

        std::thread::sleep(Duration::from_millis(120));
        let stale = resolver.resolve("X");
        assert_eq!(stale.source, super::Source::Stale, "{:?}", stale.outcome);
        assert_eq!(value_of(&stale), "decoy-first");

        // The refresh lands on its own, off this caller's request.
        std::thread::sleep(Duration::from_secs(3));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "the store was asked more than once for the one refresh"
        );
        // What it fetched is what the next reader gets. That reader is past the
        // 50 ms window too, so it is served the new value and starts its own
        // refresh — the source it carries is not what this case is about.
        assert_eq!(value_of(&resolver.resolve("X")), "decoy-second");
        drop(refresher);
    }

    #[test]
    fn a_stale_read_starts_one_refresh_however_many_readers() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::from_millis(400),
            vec![Reply::Value("decoy")],
            Duration::from_millis(50),
            Duration::from_secs(60),
        );
        let refresher = Resolver::start(&resolver);
        let _ = resolver.resolve("X");
        std::thread::sleep(Duration::from_millis(120));

        std::thread::scope(|scope| {
            for _ in 0..10 {
                let resolver = Arc::clone(&resolver);
                scope.spawn(move || {
                    let _ = resolver.resolve("X");
                });
            }
        });
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "ten readers past freshness must start one refresh between them"
        );
        drop(refresher);
    }

    #[test]
    fn a_store_that_could_not_answer_keeps_the_value_and_is_not_asked_again_at_once() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::ZERO,
            vec![Reply::Value("decoy-held"), Reply::Silent],
            Duration::from_millis(50),
            Duration::from_secs(60),
        );
        let refresher = Resolver::start(&resolver);
        let _ = resolver.resolve("X");
        std::thread::sleep(Duration::from_millis(120));

        let served = resolver.resolve("X");
        assert_eq!(served.source, super::Source::Stale);
        assert_eq!(value_of(&served), "decoy-held");

        // The floor holds the next reads off the store while the value is
        // being served from memory anyway.
        for _ in 0..5 {
            let again = resolver.resolve("X");
            assert_eq!(value_of(&again), "decoy-held");
        }
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(refresher);
    }

    #[test]
    fn a_store_that_disowns_the_value_evicts_it_rather_than_serving_it_stale() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::ZERO,
            vec![Reply::Value("decoy-gone"), Reply::Verdict],
            Duration::from_millis(50),
            Duration::from_secs(60),
        );
        let refresher = Resolver::start(&resolver);
        let _ = resolver.resolve("X");
        std::thread::sleep(Duration::from_millis(120));

        let answered = resolver.resolve("X");
        assert_eq!(answered.source, super::Source::Store);
        assert!(
            matches!(answered.outcome, Outcome::Failed(ref reason) if reason.contains("trash")),
            "{:?}",
            answered.outcome
        );
        assert_eq!(resolver.cached_len(), 0, "a disowned value stayed cached");
        drop(refresher);
    }

    #[test]
    fn an_absence_from_a_refresh_evicts_the_value_too() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::ZERO,
            vec![Reply::Value("decoy-removed"), Reply::Absent],
            Duration::from_millis(50),
            Duration::from_secs(60),
        );
        let refresher = Resolver::start(&resolver);
        let _ = resolver.resolve("X");
        std::thread::sleep(Duration::from_millis(120));

        let answered = resolver.resolve("X");
        assert!(
            matches!(answered.outcome, Outcome::Absent),
            "expected the store's own absence, got {:?} from {:?}",
            answered.outcome,
            answered.source
        );
        assert_eq!(resolver.cached_len(), 0);
        drop(refresher);
    }

    #[test]
    fn a_zero_ttl_disables_stale_serving_too() {
        // One key turns the whole mechanism off. A daemon told to cache
        // nothing must not acquire a five-minute window through a second key.
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::ZERO,
            vec![Reply::Value("decoy")],
            Duration::ZERO,
            Duration::from_secs(60),
        );
        for _ in 0..3 {
            assert_eq!(resolver.resolve("X").source, super::Source::Store);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(resolver.cached_len(), 0);
    }

    #[test]
    fn a_value_past_both_windows_is_fetched_on_the_request_itself() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::ZERO,
            vec![Reply::Value("decoy-old"), Reply::Value("decoy-new")],
            Duration::from_millis(40),
            Duration::from_millis(40),
        );
        let _ = resolver.resolve("X");
        std::thread::sleep(Duration::from_millis(150));
        let answered = resolver.resolve("X");
        assert_eq!(answered.source, super::Source::Store);
        assert_eq!(value_of(&answered), "decoy-new");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn stale_serving_asks_no_more_often_than_expiry_alone_did() {
        // The volume claim, measured rather than argued: the same read
        // schedule against a resolver with a stale window and one without.
        fn calls_under(stale: Duration) -> u64 {
            let calls = Arc::new(AtomicU64::new(0));
            let resolver = scripted(
                &calls,
                Duration::ZERO,
                vec![Reply::Value("decoy")],
                Duration::from_millis(40),
                stale,
            );
            let refresher = Resolver::start(&resolver);
            for _ in 0..4 {
                let _ = resolver.resolve("X");
                let _ = resolver.resolve("X");
                std::thread::sleep(Duration::from_millis(60));
            }
            std::thread::sleep(Duration::from_millis(300));
            drop(refresher);
            calls.load(Ordering::SeqCst)
        }
        let without = calls_under(Duration::ZERO);
        let with = calls_under(Duration::from_secs(60));
        assert!(
            with <= without,
            "stale serving asked the store more often: {with} against {without}"
        );
    }

    #[test]
    fn clearing_the_cache_during_a_refresh_leaves_it_empty() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::from_millis(500),
            vec![Reply::Value("decoy-one"), Reply::Value("decoy-two")],
            Duration::from_millis(40),
            Duration::from_secs(60),
        );
        let refresher = Resolver::start(&resolver);
        let _ = resolver.resolve("X");
        std::thread::sleep(Duration::from_millis(80));
        let _ = resolver.resolve("X"); // starts a refresh, serves the old value
        resolver.clear_cache();
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(
            resolver.cached_len(),
            0,
            "a refresh in flight refilled a cache that had been cleared"
        );
        drop(refresher);
    }

    #[test]
    fn an_outcome_debug_never_prints_the_value() {
        let outcome = Outcome::Found(std::sync::Arc::new(Secret::new(
            "decoy-must-not-appear-7742".to_owned(),
        )));
        assert!(!format!("{outcome:?}").contains("7742"));
    }
}
