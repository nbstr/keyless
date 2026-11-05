use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::error::StoreError;
use crate::store::Resolution;

use super::{Cached, FailureKind, Fetched, Flight, Outcome, Resolver};

/// Upper bound on cached names.
///
/// A client can ask for any name it likes, and every miss would otherwise be a
/// permanent entry. Bounded so a hostile or careless caller cannot grow the
/// daemon's heap by naming secrets that do not exist — though only successes
/// are cached, which already makes that hard.
pub(super) const MAX_CACHE_ENTRIES: usize = 256;

impl Resolver {
    /// Ask a store, coalescing with any concurrent fetch for the same name,
    /// and put what comes back into the cache.
    pub(super) fn fetch(&self, name: &str) -> Fetched {
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
    pub(super) fn run_fetch(&self, name: &str, flight: &Arc<Flight>) -> Fetched {
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
            match &fetched.outcome {
                // A value: it replaces whatever was there, and its clock starts
                // again.
                Outcome::Found(_) if !self.ttl.is_zero() => {
                    shared.silent_since.remove(name);
                    evict_if_full(&mut shared.cache);
                    shared.cache.insert(
                        name.to_owned(),
                        Cached {
                            outcome: fetched.outcome.clone(),
                            at: Instant::now(),
                        },
                    );
                }
                // The store could not answer. The entry stands, and the floor
                // stops the next reader asking again immediately.
                _ if fetched.is_silent() => {
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

    fn ask_upstream(&self, name: &str) -> Fetched {
        self.upstream_calls.fetch_add(1, Ordering::Relaxed);
        // Every error unavailable means no store took a position: each one
        // was never reached, so nothing here disagrees with a cached value.
        // Any other error mix means at least one store WAS reached and had
        // something to say, which is what makes the value worth evicting.
        let kind_of = |errors: &[StoreError]| {
            if !errors.is_empty()
                && errors
                    .iter()
                    .all(|error| matches!(error, StoreError::Unavailable { .. }))
            {
                FailureKind::Silent
            } else {
                FailureKind::Verdict
            }
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
            // to be missing. `tests/daemon_routing.rs` holds that down by watching the
            // store be asked, because it is not readable from here.
            Resolution::NotFound { .. } | Resolution::Refused { .. } => Outcome::Absent,
            Resolution::Failed(errors) => {
                // Read before the errors are flattened into one sentence: the
                // variants are what say whether a store answered, and a string
                // cannot be asked that afterwards.
                let kind = kind_of(&errors);
                let reason = errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                return Fetched {
                    outcome: Outcome::Failed { reason, kind },
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
            ambiguous @ Resolution::Ambiguous { .. } => Outcome::Failed {
                reason: format!(
                    "{} — in keylessd's own config file, not this session's; \
                     a session cannot settle which of the daemon's stores a name means",
                    ambiguous.reason()
                ),
                kind: FailureKind::Unrouted,
            },
        };
        // Everything that reaches here is the store's own answer about the
        // name, including an ambiguity, which is this daemon's config saying
        // no store may be asked at all.
        Fetched { outcome }
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
        outcome: Outcome::Failed {
            reason: "the resolution finished without a result".to_owned(),
            kind: FailureKind::Silent,
        },
    })
}

/// The flight's answer, or `None` when it has not landed inside `grace`.
///
/// A reader past freshness holds a value already, so waiting longer buys a
/// fresher answer at the cost of the latency this whole mechanism exists to
/// take off the request path.
pub(super) fn wait_for_timeout(flight: &Arc<Flight>, grace: Duration) -> Option<Fetched> {
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
