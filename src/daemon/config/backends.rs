use std::collections::BTreeMap;
use std::sync::Arc;

use super::{Backends, DaemonConfig};
use crate::store::catalogue::{Catalogue, ProtonMint, Source};
use crate::store::file::FileStore;
use crate::store::infisical::InfisicalStore;
use crate::store::keychain::KeychainStore;
use crate::store::onepassword::OnePasswordStore;
use crate::store::proton::{ProtonStore, Reason as ProtonReason};
use crate::store::proton_session::Generations;
use crate::store::{Registry, Store};

impl DaemonConfig {
    /// Which name is pinned to which store, by store id.
    ///
    /// Only [`SecretRoute::store`] is read here: the coordinate fields beside
    /// it say where a name lives *inside* a backend, which is
    /// [`DaemonConfig::infisical_routing`]'s question rather than this one's.
    pub(super) fn routes(&self) -> BTreeMap<String, String> {
        self.secrets
            .iter()
            .filter_map(|(name, route)| route.store.clone().map(|store| (name.clone(), store)))
            .collect()
    }

    /// The generation layout this config names, or `None` when there is
    /// nothing to build one over.
    ///
    /// `Some` exactly when Proton is enabled and `session_dir` is set — the
    /// same precondition [`crate::store::proton::ProtonStore::session_dir`]
    /// and [`super::login::coordinates`] already enforce, so a caller that
    /// gets `Some` here knows every other Proton-reading call in this crate
    /// will too. Fresh on every call rather than cached: this method builds
    /// the type, and *which instance* is shared across the daemon is decided
    /// once, by [`Daemon::bind`](super::Daemon::bind) — every other caller
    /// that wants the SAME running layout takes it from there rather than
    /// calling this again.
    #[must_use]
    pub fn generations(&self) -> Option<Arc<Generations>> {
        if !self.stores.proton.enabled {
            return None;
        }
        let root = self.stores.proton.session_dir.as_deref()?;
        // The same guard `ProtonStore::session_dir` applies on the session
        // side, restated here because a `Some` from this function is what
        // makes `ProtonStore::enter`'s daemon-side arm skip that call
        // entirely. Returning `None` for a relative root — rather than
        // building a `Generations` over it — is what sends the daemon read
        // path back through `session_dir()`'s own check and its
        // named-config-line message, instead of degrading later as
        // `CurrentFault::Absent`, a sentence that points an operator at "no
        // session established" when the real fault is one config line.
        if !root.is_absolute() {
            return None;
        }
        Some(Arc::new(Generations::at(root.to_path_buf())))
    }

    /// The Proton adapter this daemon reads through.
    ///
    /// Factored out because the daemon builds TWO of them over one identity —
    /// the one that resolves, and the one the catalogue rebuilder enumerates
    /// through — and two constructions of the same fifteen settings would be
    /// free to disagree about which vault, which timeout, which key provider.
    /// The disagreement would be invisible: the rebuilder would simply mint
    /// names for a vault the resolver cannot read.
    ///
    /// `catalogue` is `None` for the discovering twin: enumeration takes no
    /// route, so an index that fed itself would only be a way for a stale
    /// snapshot to keep itself alive.
    fn proton_store(
        &self,
        generations: Option<&Arc<Generations>>,
        catalogue: Option<Arc<Catalogue>>,
    ) -> ProtonStore {
        let settings = &self.stores.proton;
        ProtonStore::new(
            settings.binary.to_path_buf(),
            settings.probe_binary.to_path_buf(),
            self.proton_routing().with_catalogue(catalogue),
            // Not `Reason::for_run(argv)`. The reason is written into
            // Proton's own remote audit trail, permanently, and a
            // daemon's `argv` arrives from a client — `crate::audit`
            // records it as a CLAIM, never a fact. A registry is built
            // once at startup anyway, so there is no per-request reason
            // to be had here even if one were wanted.
            ProtonReason::for_verb(crate::DAEMON_NAME),
        )
        .in_session_dir(
            settings
                .session_dir
                .as_deref()
                .map(|path| path.to_path_buf()),
        )
        // Always named here, never left to the vendor's default. See
        // `KeyProvider`: the default is a keyring, a daemon uid has
        // none, and `pass-cli` answers that by reinitialising the
        // session store it was asked to read.
        .with_key_provider(Some(settings.key_provider))
        // Whoever runs the vendor owns what it writes, and it writes on
        // invocations that only read. Read off the audit log, which is
        // the same source the login verbs use.
        .with_run_as(
            crate::daemon::credential::daemon_owner(&self.audit)
                .map(|owner| (owner.uid, owner.gid)),
        )
        .with_timeout(settings.timeout_ms)
        .with_listing_ttl(settings.listing_ttl_ms)
        .with_generations(generations.cloned())
        .with_agent_token(self.agent_token())
    }

    /// Build the store registry, with the routing that decides which store
    /// answers a name.
    ///
    /// Order is search order, and the file store comes first because it is the
    /// one whose permissions this crate can actually enforce. Order is **not**
    /// how a name picks a store, though: under the default
    /// [`StorePolicy::Explicit`] a name resolves against its own pin, else
    /// `stores.default`, else the single configured store — and two stores with
    /// neither is reported as ambiguous rather than guessed at.
    ///
    /// The routing has to live here, on the daemon's side, because the daemon
    /// is the side that knows what its stores hold. A session cannot settle it:
    /// [`crate::store::build`] drops every per-name pin when the daemon is
    /// enabled, precisely so a client cannot steer which vault answers.
    ///
    /// `shared` is the [`Generations`] the renewal loop creates and retires
    /// generations through, when one is already built — the running daemon's
    /// own case. `None` builds a fresh, PRIVATE `Generations` from this same
    /// config instead of leaving the registry with none at all: `keylessd
    /// check` resolves in its own process and renews nothing, but it still has
    /// to read `<root>/current` to report on the store honestly.
    #[must_use]
    pub fn registry(&self, shared: Option<&Arc<Generations>>) -> Registry {
        self.backends(shared, None).registry
    }

    /// The registry, and the sources a catalogue rebuild enumerates through.
    ///
    /// Both at once because the discovering twin has to be built over the
    /// resolving store's own listing cache, and the sharing pays in ONE
    /// direction: the twin refuses a cached listing — see
    /// [`ProtonStore::always_relisting`], which exists because a rebuild queued
    /// by a miss cannot answer that miss out of a listing fetched before the
    /// item existed — so it never reuses anything. What it does is WRITE: the
    /// fresh listing it fetches lands in the shared slot, and the next cold
    /// resolve is served from it instead of spawning a `pass-cli item list` of
    /// its own. Built over separate caches, every rebuild would be a listing
    /// nobody else could use.
    ///
    /// `catalogue` decides only what the RESOLVING adapters read their
    /// undeclared addresses out of. The sources are built either way, so a
    /// caller that wants to enumerate — `keylessd check` — does not have to
    /// construct a catalogue it will not read. The cost is one `ProtonStore`
    /// built and dropped by [`DaemonConfig::registry`], which is a struct and
    /// no vendor call.
    #[must_use]
    pub fn backends(
        &self,
        shared: Option<&Arc<Generations>>,
        catalogue: Option<&Arc<Catalogue>>,
    ) -> Backends {
        let generations = shared.cloned().or_else(|| self.generations());
        let mut stores: Vec<Box<dyn Store>> = Vec::new();
        if self.stores.file.enabled {
            stores.push(Box::new(FileStore::new(
                self.stores.file.path.to_path_buf(),
            )));
        }
        if self.stores.keychain.enabled {
            stores.push(Box::new(
                KeychainStore::new(
                    self.stores.keychain.binary.to_path_buf(),
                    self.stores.keychain.service.clone(),
                )
                .in_keychain(
                    self.stores
                        .keychain
                        .keychain
                        .as_deref()
                        .map(|path| path.to_path_buf()),
                ),
            ));
        }
        if self.stores.infisical.enabled {
            let settings = &self.stores.infisical;
            stores.push(Box::new(
                InfisicalStore::new(
                    settings.binary.to_path_buf(),
                    settings.probe_binary.to_path_buf(),
                    // The environment-free routing, and the only one this side
                    // ever builds. See `infisical_routing` for why the absence
                    // is what makes hosting this adapter here safe.
                    self.infisical_routing(),
                )
                .with_timeout(settings.timeout_ms)
                .in_project(
                    settings.project_id.clone(),
                    settings
                        .config_dir
                        .as_deref()
                        .map(|path| path.to_path_buf()),
                )
                .at_domain(settings.domain.clone())
                .with_vendor_credentials(self.vendor_credentials()),
            ));
        }
        if self.stores.onepassword.enabled {
            let settings = &self.stores.onepassword;
            stores.push(Box::new(
                OnePasswordStore::new(
                    settings.binary.to_path_buf(),
                    settings.probe_binary.to_path_buf(),
                    self.onepassword_routing(),
                )
                .with_timeout(settings.timeout_ms)
                .with_listing_ttl(settings.listing_ttl_ms)
                .for_account(settings.account.clone())
                .in_config_dir(
                    settings
                        .config_dir
                        .as_deref()
                        .map(|path| path.to_path_buf()),
                )
                .with_vendor_credentials(self.service_account()),
            ));
        }
        let mut sources: Vec<Source> = Vec::new();
        if self.stores.proton.enabled {
            let resolving = self.proton_store(generations.as_ref(), catalogue.cloned());
            sources.push(Source {
                discover: Box::new(
                    self.proton_store(generations.as_ref(), None)
                        .sharing_listings_with(&resolving)
                        .always_relisting(),
                ),
                mint: Box::new(ProtonMint),
            });
            stores.push(Box::new(resolving));
        }
        Backends {
            registry: Registry::new(stores)
                .with_routes(self.routes())
                .with_policy(self.stores.policy)
                .with_default_store(self.stores.default_store.clone()),
            sources,
        }
    }
}
