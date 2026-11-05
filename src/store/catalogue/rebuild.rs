//! The worker that keeps the derived index fresh, for the misses that wait on it.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::{Catalogue, IndexBuilder, ItemKey, Rebuilder, Rebuilt, Route, Source};

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
    /// How many full enumerations the worker has taken, and how many it has
    /// finished. A miss waits for the one that covers it by number, so misses
    /// arriving during one enumeration all wait on that one.
    taken: u64,
    finished: u64,
    /// Whether the last finished enumeration installed a snapshot.
    installed: bool,
    /// Items whose field view a miss asked for.
    items: VecDeque<ItemKey>,
    /// The item whose field view is being fetched right now.
    fetching: Option<ItemKey>,
    /// When the last attempt failed without producing a snapshot.
    failed_at: Option<Instant>,
}

pub(super) struct Engine {
    catalogue: Arc<Catalogue>,
    sources: Vec<Source>,
    work: Mutex<Work>,
    wake: Condvar,
    /// Signalled whenever a task finishes, for the misses waiting on one.
    settled: Condvar,
    stop: AtomicBool,
}

/// Carried by a channel that only ever closes, never sends.
pub(super) enum Never {}

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
            settled: Condvar::new(),
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

    /// Bring the catalogue up to date for a name the store did not serve, and
    /// wait for it, for at most `within`.
    ///
    /// A name that inverts onto nothing needs a fresh listing; one that then
    /// inverts onto a live title whose field view is stale needs that one
    /// item's fields. A name that inverts onto an item whose view is fresh
    /// needs nothing: that item does not serve it.
    ///
    /// Misses arriving while a listing or a field fetch is in flight wait on
    /// that one rather than starting their own, so a burst of runs against one
    /// stale index costs one vendor listing.
    ///
    /// Anything short of a verdict is [`Rebuilt::Silent`]: the wait running
    /// out, a store that could not be enumerated, or one that failed within
    /// [`REBUILD_RETRY_FLOOR`]. A store's silence must never read as a name it
    /// does not hold.
    pub fn rebuild_for(&self, name: &str, within: Duration) -> Rebuilt {
        let deadline = Instant::now() + within;
        let catalogue = &self.engine.catalogue;
        let mut listed = false;
        let mut work = self.engine.lock();
        loop {
            if work
                .failed_at
                .is_some_and(|at| at.elapsed() < REBUILD_RETRY_FLOOR)
            {
                return Rebuilt::Silent;
            }
            if !matches!(catalogue.route(name), Route::Unknown { .. }) {
                return Rebuilt::Current;
            }
            match catalogue.invert(name) {
                Some(item) if !catalogue.view_is_fresh(&item) => {
                    let pending = |work: &Work| {
                        work.items.contains(&item) || work.fetching.as_ref() == Some(&item)
                    };
                    if !pending(&work) {
                        work.items.push_back(item.clone());
                        self.engine.wake.notify_one();
                    }
                    let Some(settled) = self.settle(work, deadline, |work| !pending(work)) else {
                        return Rebuilt::Silent;
                    };
                    drop(settled);
                    return if catalogue.view_is_fresh(&item) {
                        Rebuilt::Current
                    } else {
                        Rebuilt::Silent
                    };
                }
                Some(_) => return Rebuilt::Current,
                None if listed => return Rebuilt::Current,
                None => {
                    let covering = if work.running {
                        work.taken
                    } else {
                        work.full = true;
                        self.engine.wake.notify_one();
                        work.taken + 1
                    };
                    let Some(settled) =
                        self.settle(work, deadline, |work| work.finished >= covering)
                    else {
                        return Rebuilt::Silent;
                    };
                    if !settled.installed {
                        return Rebuilt::Silent;
                    }
                    work = settled;
                    listed = true;
                }
            }
        }
    }

    /// Wait until `done` holds, or `None` once `deadline` passes first.
    fn settle<'a>(
        &self,
        mut work: MutexGuard<'a, Work>,
        deadline: Instant,
        done: impl Fn(&Work) -> bool,
    ) -> Option<MutexGuard<'a, Work>> {
        while !done(&work) {
            let left = deadline.checked_duration_since(Instant::now())?;
            work = self
                .engine
                .settled
                .wait_timeout(work, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        Some(work)
    }

    /// Ask for a full enumeration, whatever the floor says.
    ///
    /// The startup call. A daemon that has just bound has no index at all, and
    /// the floor exists to bound RETRIES rather than to delay the first one.
    pub fn queue_full(&self) {
        let mut work = self.engine.lock();
        // Floored on the same terms as `rebuild_for`, and for a reason the `running`
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
                        work.taken += 1;
                        break Task::Full;
                    }
                    if let Some(item) = work.items.pop_front() {
                        work.fetching = Some(item.clone());
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
                    let installed = self.rebuild();
                    let mut work = self.lock();
                    work.running = false;
                    work.finished += 1;
                    work.installed = installed;
                }
                Task::Fields(item) => {
                    self.fetch_fields(&item);
                    self.lock().fetching = None;
                }
            }
            self.settled.notify_all();
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
    fn rebuild(&self) -> bool {
        let mut building = IndexBuilder::new();
        for source in &self.sources {
            let Ok(items) = source.discover.items(None) else {
                self.lock().failed_at = Some(Instant::now());
                return false;
            };
            for item in &items {
                building.item(source.mint.as_ref(), item);
            }
        }
        self.lock().failed_at = None;
        self.catalogue.install(building.finish());
        true
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
