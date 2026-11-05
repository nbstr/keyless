mod caching;
mod coalescing;
mod failures;
mod stale;

use super::{Outcome, Resolver};
use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::{Registry, Store};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
