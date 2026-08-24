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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::secret::Secret;
use crate::store::{Registry, Resolution};

/// Upper bound on cached names.
///
/// A client can ask for any name it likes, and every miss would otherwise be a
/// permanent entry. Bounded so a hostile or careless caller cannot grow the
/// daemon's heap by naming secrets that do not exist — though only successes
/// are cached, which already makes that hard.
const MAX_CACHE_ENTRIES: usize = 256;

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

struct Cached {
    outcome: Outcome,
    at: Instant,
}

/// One resolution in progress, and the waiters on it.
struct Flight {
    done: Mutex<Option<Outcome>>,
    ready: Condvar,
}

#[derive(Default)]
struct Shared {
    cache: HashMap<String, Cached>,
    inflight: HashMap<String, Arc<Flight>>,
}

/// Resolves names against the configured stores, once each.
pub struct Resolver {
    registry: Registry,
    ttl: Duration,
    shared: Mutex<Shared>,
    /// Counts calls that actually reached a store. The single-flight test reads
    /// it; without an independent counter, "twenty requests made one call"
    /// could only be asserted by looking at the implementation, which is not
    /// evidence.
    upstream_calls: AtomicU64,
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
            shared: Mutex::new(Shared::default()),
            upstream_calls: AtomicU64::new(0),
        }
    }

    /// How many times a store has actually been asked.
    #[must_use]
    pub fn upstream_calls(&self) -> u64 {
        self.upstream_calls.load(Ordering::Relaxed)
    }

    /// Resolve one name, coalescing with any concurrent request for it.
    pub fn resolve(&self, name: &str) -> Outcome {
        // Either this call becomes the leader for `name`, or it joins the
        // flight already under way. The lock is held only long enough to decide
        // which; the upstream call happens with nothing locked, or twenty
        // sessions would serialise behind one slow keychain.
        let flight = {
            let mut shared = self.lock();

            if let Some(cached) = shared.cache.get(name) {
                if cached.at.elapsed() < self.ttl {
                    return cached.outcome.clone();
                }
                shared.cache.remove(name);
            }

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

        let outcome = self.ask_upstream(name);

        {
            let mut shared = self.lock();
            shared.inflight.remove(name);
            if matches!(outcome, Outcome::Found(_)) && !self.ttl.is_zero() {
                evict_if_full(&mut shared.cache);
                shared.cache.insert(
                    name.to_owned(),
                    Cached {
                        outcome: outcome.clone(),
                        at: Instant::now(),
                    },
                );
            }
        }

        // Publish to the waiters after the shared state is consistent, so a
        // woken waiter that re-enters `resolve` sees the cache already filled.
        {
            let mut done = flight.done.lock().unwrap_or_else(PoisonError::into_inner);
            *done = Some(outcome.clone());
        }
        flight.ready.notify_all();

        outcome
    }

    /// Drop every cached value.
    ///
    /// Used on a reload, and by tests that need the next call to be a real one.
    pub fn clear_cache(&self) {
        self.lock().cache.clear();
    }

    /// How many values are cached right now.
    #[must_use]
    pub fn cached_len(&self) -> usize {
        self.lock().cache.len()
    }

    fn ask_upstream(&self, name: &str) -> Outcome {
        self.upstream_calls.fetch_add(1, Ordering::Relaxed);
        match self.registry.resolve(name) {
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
            Resolution::Failed(errors) => Outcome::Failed(
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
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

fn wait_for(flight: &Arc<Flight>) -> Outcome {
    let mut done = flight.done.lock().unwrap_or_else(PoisonError::into_inner);
    while done.is_none() {
        done = flight
            .ready
            .wait(done)
            .unwrap_or_else(PoisonError::into_inner);
    }
    done.clone().unwrap_or(Outcome::Failed(
        "the resolution finished without a result".to_owned(),
    ))
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
                    match resolver.resolve("SHARED") {
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
            assert!(matches!(resolver.resolve("X"), Outcome::Found(_)));
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
        assert!(matches!(resolver.resolve("X"), Outcome::Found(_)));
        std::thread::sleep(Duration::from_millis(60));
        assert!(matches!(resolver.resolve("X"), Outcome::Found(_)));
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
        assert!(matches!(resolver.resolve("X"), Outcome::Failed(_)));
        assert!(matches!(resolver.resolve("X"), Outcome::Failed(_)));
        assert_eq!(resolver.cached_len(), 0);
        assert_eq!(resolver.upstream_calls(), 2);
    }

    #[test]
    fn an_absence_is_never_cached_either() {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = resolver(&calls, Duration::ZERO, None, Duration::from_secs(600));
        assert!(matches!(resolver.resolve("X"), Outcome::Absent));
        assert!(matches!(resolver.resolve("X"), Outcome::Absent));
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
        match Resolver::new(registry, Duration::ZERO).resolve("DATABASE_URL") {
            Outcome::Failed(reason) => {
                assert!(reason.contains("keylessd"), "{reason}");
                assert!(reason.contains("stores.default"), "{reason}");
                assert!(!reason.contains("decoy-"), "the reason leaked a value");
            }
            other => panic!("expected a failure naming the candidates, got {other:?}"),
        }
    }

    #[test]
    fn an_outcome_debug_never_prints_the_value() {
        let outcome = Outcome::Found(std::sync::Arc::new(Secret::new(
            "decoy-must-not-appear-7742".to_owned(),
        )));
        assert!(!format!("{outcome:?}").contains("7742"));
    }
}
