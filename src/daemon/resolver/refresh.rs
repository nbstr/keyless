use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::{Flight, Never, Refresher, Resolver};

/// How many refreshes may be in flight at once.
///
/// Two rather than one, so a single slow name does not hold the queue, and not
/// more, because every refresh is a vendor process and the point of this whole
/// mechanism is to ask the vendor no more often than expiry already did.
const REFRESH_WORKERS: usize = 2;

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
    pub(super) fn queue_refresh(&self, name: &str) -> Option<Arc<Flight>> {
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

    /// Drop every entry past every window, so a value nobody reads again does
    /// not sit in memory until something else evicts it.
    fn sweep(&self) {
        let horizon = self.retention();
        let mut shared = self.lock();
        shared
            .cache
            .retain(|_, cached| cached.at.elapsed() < horizon);
        shared
            .silent_since
            .retain(|_, since| since.elapsed() < REFRESH_RETRY_FLOOR);
    }
}
