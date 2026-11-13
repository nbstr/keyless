use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::Config;
use crate::store::proton_session::Generations;

use super::auto_login::AutoLogin;
use super::environment::KeyProvider;
use super::listing::{VaultSlot, bounded_listing_ttl};
use super::reason::Reason;
use super::routing::Routing;
use super::token::AgentToken;

/// Reads one Proton Pass item at a time through `pass-cli run`.
pub struct ProtonStore {
    pub(super) binary: PathBuf,
    pub(super) probe_binary: PathBuf,
    /// Value of `PROTON_PASS_SESSION_DIR` for every child. See
    /// [`ProtonStore::session_dir`].
    pub(super) session_dir: Option<PathBuf>,
    /// Where the local key encrypting that session lives, or `None` to leave
    /// the choice to the vendor. See [`ProtonStore::key_provider`].
    pub(super) key_provider: Option<KeyProvider>,
    /// The daemon's own login, or `None` on a session, which inherits one.
    /// See [`AgentToken`].
    pub(super) credentials: Option<AgentToken>,
    /// How a session gets back in once Proton has ended it, or `None` to
    /// leave that to a person. See [`AutoLogin`].
    pub(super) auto_login: Option<AutoLogin>,
    /// Whom to spawn the vendor as. See [`ProtonStore::with_run_as`].
    pub(super) run_as: Option<(u32, u32)>,
    pub(super) timeout: Duration,
    pub(super) reason: Reason,
    /// name -> where its value lives.
    pub(super) routing: Routing,
    /// How long a listing may be reused. See [`ProtonStore::cached_items`].
    pub(super) listing_ttl: Duration,
    /// The daemon's layout of generation directories, shared with the renewal
    /// loop that creates and retires them. `None` wherever nothing replaces the
    /// session — a `keyless` session inherits whatever is already logged in and
    /// has no generations of its own. See [`ProtonStore::enter`].
    pub(super) generations: Option<Arc<Generations>>,
    /// vault name -> that vault's items, until they expire.
    ///
    /// In memory and nowhere else. A cache on disk that the client can read is
    /// a `get` verb with extra steps, which is the one thing this tool does not
    /// offer.
    /// vault name -> that vault's items, until they expire.
    ///
    /// Behind an `Arc` so two stores over one identity can share it. The daemon
    /// builds two: the one that RESOLVES, and the one the rebuilder enumerates
    /// through. Given separate caches they would each spend a `pass-cli item
    /// list` per vault — and the cost argument for deriving names at all is
    /// that stage one is already fetched on every cold resolve. Sharing is what
    /// makes that true rather than nearly true.
    ///
    /// `VaultSlot` is itself an `Arc<Mutex<..>>`, so the per-vault single-flight
    /// is unaffected: two stores contending for one vault still produce one
    /// listing, which is the property this sharing exists to extend.
    pub(super) listings: Arc<Mutex<BTreeMap<String, VaultSlot>>>,
    /// Whether [`Discover::items`] refuses a cached listing. See
    /// [`ProtonStore::always_relisting`].
    pub(super) relist: bool,
}

/// Find `binary` as an executable file, following `PATH` for a bare name.
///
/// Written here rather than taken as a dependency: it is a dozen lines, and the
/// alternative is a crate in the trusted path of a secrets tool.
pub(crate) fn resolve_executable(binary: &Path) -> Option<PathBuf> {
    if binary.components().count() > 1 {
        return is_executable(binary).then(|| binary.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

impl ProtonStore {
    /// Construct from a parsed config and the reason reads will be recorded under.
    #[must_use]
    pub fn from_config(config: &Config, reason: Reason) -> Self {
        let settings = &config.stores.proton;
        Self::new(
            settings.binary.to_path_buf(),
            settings.probe_binary.to_path_buf(),
            Routing::from_config(config),
            reason,
        )
        .in_session_dir(
            settings
                .session_dir
                .as_deref()
                .map(|path| path.to_path_buf()),
        )
        .with_timeout(settings.timeout_ms)
        .with_listing_ttl(settings.listing_ttl_ms)
        // A config asking for something unusable runs without it; the
        // registry is what warns, once, with the reason.
        .with_auto_login(AutoLogin::from_config(config).ok().flatten())
    }

    /// Construct from the parts, with no session config anywhere behind it.
    ///
    /// The constructor a daemon uses. It takes a [`Routing`] rather than a
    /// `Config` for the reason [`Routing`] exists: the daemon's `secrets` block
    /// is not a [`crate::config::Config`] and must not have to become one for
    /// this adapter to be hosted behind the socket.
    ///
    /// The session directory is deliberately **not** a parameter here and is
    /// set by [`ProtonStore::in_session_dir`] instead, so that a store built
    /// and never pointed at one degrades every lookup rather than inheriting
    /// the ambient session. See [`ProtonStore::session_dir`] for why that is
    /// the only acceptable default.
    #[must_use]
    pub fn new(binary: PathBuf, probe_binary: PathBuf, routing: Routing, reason: Reason) -> Self {
        ProtonStore {
            binary,
            probe_binary,
            session_dir: None,
            key_provider: None,
            credentials: None,
            auto_login: None,
            run_as: None,
            timeout: crate::config::bounded_timeout(crate::config::DEFAULT_TIMEOUT_MS),
            reason,
            routing,
            listing_ttl: bounded_listing_ttl(crate::config::default_listing_ttl_ms()),
            listings: Arc::new(Mutex::new(BTreeMap::new())),
            relist: false,
            generations: None,
        }
    }

    /// Refuse to reuse a cached listing, however fresh it is — in BOTH
    /// enumeration verbs.
    ///
    /// `items` and `fields` each read a listing, and both readings are the
    /// rebuild's. `fields` resolves a title to an id through it, so a store
    /// that relisted for `items` and not for `fields` would enumerate a fresh
    /// vault and then address an item out of a stale one.
    ///
    /// # Why exactly one caller wants this, and why the shared cache survives it
    ///
    ///
    /// The catalogue's rebuilder enumerates through the SAME listing cache a
    /// resolve fills — that sharing is what makes stage one of a rebuild free.
    /// But a rebuild is queued BY a miss, and the listing it would reuse was
    /// fetched before the item that caused the miss existed. So the one reader
    /// that cannot accept a cached listing is the one this sharing was built
    /// for: at the default `listing_ttl_ms` of 60000 it would spend a minute
    /// unable to learn the thing it was started to learn, and would report the
    /// vault unchanged the whole time.
    ///
    /// It does not throw the sharing away, because the direction that pays is
    /// the other one: the fresh listing this store fetches lands in the shared
    /// slot, so the next cold resolve reuses it. And the cost is bounded by the
    /// rebuilder's own retry floor, the same shape the resolver's refresh queue
    /// uses — a caller naming garbage spends at most one listing per floor.
    #[must_use]
    pub fn always_relisting(mut self) -> Self {
        self.relist = true;
        self
    }

    /// Share another store's listing cache.
    ///
    /// Only ever called between two stores built over the SAME session
    /// directory and the same identity: a listing is what one identity can see,
    /// and the generation stamped on each entry is what keeps a renewal from
    /// being served out of it. See the field's own docs for why the daemon
    /// wants this.
    #[must_use]
    pub fn sharing_listings_with(mut self, other: &ProtonStore) -> Self {
        self.listings = Arc::clone(&other.listings);
        self
    }

    /// Which logged-in identity answers every child this store spawns.
    #[must_use]
    pub fn in_session_dir(mut self, session_dir: Option<PathBuf>) -> Self {
        self.session_dir = session_dir;
        self
    }

    /// The login this daemon presents, read out of its own file at lookup time.
    ///
    /// `None` on a session, which inherits one by spawning the vendor. See
    /// [`AgentToken`] for why a daemon cannot.
    #[must_use]
    pub fn with_agent_token(mut self, credentials: Option<AgentToken>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Where the local key encrypting that session is kept.
    ///
    /// # Why a session sets none and a daemon must
    ///
    /// `None` leaves [`KEY_PROVIDER_VAR`] off the child entirely, so the vendor
    /// uses whatever the caller's own environment says — which for a person at
    /// a terminal is the keyring their `pass-cli login` already put the key in.
    /// Setting one there would be this adapter deciding, on a user's behalf,
    /// where a key it did not create should be looked for, and getting it wrong
    /// costs that user their login. So the session side stays out of it.
    ///
    /// A daemon has no such inheritance and no such default worth keeping: its
    /// uid's keyring is empty, and [`KeyProvider`] documents what `pass-cli`
    /// does about an empty one. So the daemon always names a provider, and it
    /// is a config field there rather than a constant here.
    /// Which uid and gid the vendor runs as, when this store is used from a
    /// process that is not already the daemon.
    ///
    /// # Why a read needs this at all
    ///
    /// `pass-cli` WRITES to the session directory on invocations that only
    /// read: against a directory with no identity in it, it creates
    /// `.session/pass-cli.db` and `.session/local.key`, owned by whoever ran
    /// it. Inside the daemon that is the daemon, and this is a no-op.
    ///
    /// `keylessd check` is the case that is not. It runs under `sudo`,
    /// resolves every store to fill in its rows, and so spawned the vendor AS
    /// ROOT into the daemon's own session directory. Every later access by the
    /// daemon then answered `Error creating local key file: Permission denied`
    /// — which reads like a broken token, and is a directory the diagnostic
    /// broke while reporting on it.
    ///
    /// Measured on a real install: a session cleared for repair, one
    /// `sudo keylessd check`, and the store was unrecoverable by the renewal
    /// loop until the directory was given back by hand.
    ///
    /// Set unconditionally by the config, exactly as
    /// [`crate::daemon::login`] sets it for the login verbs: from root it is
    /// the privilege drop, and from the daemon's own uid it is a call that
    /// changes nothing and still succeeds — so there is no branch here that
    /// could be right on one machine and wrong on another.
    #[must_use]
    pub fn with_run_as(mut self, run_as: Option<(u32, u32)>) -> Self {
        self.run_as = run_as;
        self
    }

    #[must_use]
    pub fn with_key_provider(mut self, key_provider: Option<KeyProvider>) -> Self {
        self.key_provider = key_provider;
        self
    }

    /// Bound one lookup, in milliseconds. Clamped by
    /// [`crate::config::bounded_timeout`], so a config cannot switch the
    /// deadline off by naming a large enough number.
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout = crate::config::bounded_timeout(timeout_ms);
        self
    }

    /// How long one vault listing may be reused, in milliseconds. Clamped by
    /// [`bounded_listing_ttl`], for the reason that function documents.
    #[must_use]
    pub fn with_listing_ttl(mut self, listing_ttl_ms: u64) -> Self {
        self.listing_ttl = bounded_listing_ttl(listing_ttl_ms);
        self
    }

    /// Share a [`Generations`] with whatever renews this session.
    ///
    /// The layout is the caller's to build and to hand to every side that
    /// reads through it, because the side that creates and retires generations
    /// is the daemon and this adapter must not depend on it.
    #[must_use]
    pub fn with_generations(mut self, generations: Option<Arc<Generations>>) -> Self {
        self.generations = generations;
        self
    }
}
