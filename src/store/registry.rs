//! How a [`Registry`] answers one name: a pin, the default, the only backend,
//! or a refusal to guess.

use std::collections::{BTreeMap, BTreeSet};

use super::{Registry, Resolution, Store};
use crate::config::Policy;
use crate::error::StoreError;

/// Why an empty name is refused, in the words the refused banner prints.
const EMPTY_NAME: &str = "the name is empty, so it names nothing to look up";

impl Resolution {
    /// Whether a value came back.
    #[must_use]
    pub fn is_found(&self) -> bool {
        matches!(self, Resolution::Found { .. })
    }

    /// Which backend answered, when one did.
    #[must_use]
    pub fn store(&self) -> Option<&str> {
        match self {
            Resolution::Found { store, .. } => Some(store),
            _ => None,
        }
    }

    /// A short reason for the degraded banner. Never contains a value.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Resolution::Found { .. } => "resolved".to_owned(),
            // Two states, two sentences, and the difference is which file the
            // reader should open. The declared name is absent from the place
            // its declaration points at; the undeclared one points at nothing,
            // so nothing was ever asked on its behalf beyond its own name.
            // Neither sentence says a store HOLDS it — that is a fact no
            // lookup for an undeclared name can have established.
            Resolution::NotFound { undeclared: false } => "not found in any store".to_owned(),
            Resolution::NotFound { undeclared: true } => "not declared in your config, so nothing \
                 says where its value lives; no store had one under the name itself. Declare it \
                 under \"secrets\", or write it there with `keyless put`"
                .to_owned(),
            Resolution::Failed(errors) => errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
            Resolution::Refused { reason } => reason.clone(),
            Resolution::Ambiguous { candidates } => format!(
                "{} stores could answer ({}) and none is pinned; \
                 add \"store\" to this name, or set \"stores.default\"",
                candidates.len(),
                candidates.join(", ")
            ),
        }
    }
}

impl Registry {
    /// Build from a backend list, under the default [`Policy::Explicit`].
    #[must_use]
    pub fn new(stores: Vec<Box<dyn Store>>) -> Self {
        Registry {
            stores,
            routes: BTreeMap::new(),
            policy: Policy::default(),
            default_store: None,
            declared: None,
        }
    }

    /// Pin specific names to specific backends by id.
    #[must_use]
    pub fn with_routes(mut self, routes: BTreeMap<String, String>) -> Self {
        self.routes = routes;
        self
    }

    /// Choose how an unpinned name picks a backend.
    #[must_use]
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Set the backend an unpinned name resolves against.
    #[must_use]
    pub fn with_default_store(mut self, store: Option<String>) -> Self {
        self.default_store = store;
        self
    }

    /// Every name the config behind this registry declares.
    ///
    /// A backend cannot supply this fact and must not be asked to invent it:
    /// asked for a name it has no coordinate for, a store either says "I do not
    /// have that" or spawns a lookup for the name itself. Both are indistinguishable
    /// from a declared name that is genuinely absent, which is how a credential
    /// sitting in the right vault gets reported as one the vault does not hold.
    /// See [`Resolution::NotFound`].
    ///
    /// **Supplied only by a caller whose config decides where names live.** A
    /// registry left without it reports [`Resolution::NotFound`] exactly as it
    /// always did, because "you never declared this" said to somebody whose
    /// declarations live elsewhere is a fresh wrong answer, not a fix.
    #[must_use]
    pub fn with_declared_names(mut self, declared: BTreeSet<String>) -> Self {
        self.declared = Some(declared);
        self
    }

    /// Whether the config is known to declare nothing for `name`.
    ///
    /// False when it declares one, and false when there is no config to ask.
    fn undeclared(&self, name: &str) -> bool {
        self.declared
            .as_ref()
            .is_some_and(|declared| !declared.contains(name))
    }

    /// Whether any backend is configured at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stores.is_empty()
    }

    /// The configured backends, for `doctor`.
    #[must_use]
    pub fn stores(&self) -> &[Box<dyn Store>] {
        &self.stores
    }

    /// Ask for `name`, under the configured policy.
    ///
    /// An empty name is refused whatever the backends say: it can only come
    /// from a substitution that expanded to nothing, and a child started
    /// without the credential it named fails somewhere harder to read. A
    /// backend that [judges names](Store::judges_names) is still asked, so
    /// the refusal reaches its log too.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Resolution {
        if name.is_empty() && !self.stores.iter().any(|store| store.judges_names()) {
            return Resolution::Refused {
                reason: EMPTY_NAME.to_owned(),
            };
        }
        let resolution = match self.policy {
            Policy::Explicit => self.resolve_explicit(name),
            Policy::Ordered => self.resolve_ordered(name),
        };
        match resolution {
            Resolution::Refused { .. } => resolution,
            _ if name.is_empty() => Resolution::Refused {
                reason: EMPTY_NAME.to_owned(),
            },
            _ => resolution,
        }
    }

    /// The one backend a lookup of `name` will ask, or `None` when it would
    /// ask several backends or none.
    ///
    /// For a caller that must know where a lookup goes before making it —
    /// `doctor` skips a name whose backend is already down. It reads the
    /// registry rather than the config because [`build`](super::build) can drop a name's
    /// own pin (the daemon does), and the resolvers below take their choice
    /// from the same helpers, so the answer cannot drift from the lookup.
    #[must_use]
    pub fn asks(&self, name: &str) -> Option<&str> {
        match self.policy {
            Policy::Explicit => self.chosen_explicit(name),
            Policy::Ordered => self.pinned(name).or_else(|| self.single_store()),
        }
    }

    fn pinned(&self, name: &str) -> Option<&str> {
        self.routes.get(name).map(String::as_str)
    }

    fn single_store(&self) -> Option<&str> {
        match self.stores.as_slice() {
            [only] => Some(only.id()),
            _ => None,
        }
    }

    /// The pin, else the default, else the only backend. `None` with several
    /// backends is exactly the case [`Resolution::Ambiguous`] reports.
    fn chosen_explicit(&self, name: &str) -> Option<&str> {
        self.pinned(name)
            .or(self.default_store.as_deref())
            .or_else(|| self.single_store())
    }

    /// Exactly one backend is eligible, and it is never chosen by ordering.
    fn resolve_explicit(&self, name: &str) -> Resolution {
        let undeclared = self.undeclared(name);
        let Some(chosen) = self.chosen_explicit(name) else {
            return if self.stores.is_empty() {
                Resolution::Failed(vec![no_store_enabled()])
            } else {
                Resolution::Ambiguous {
                    candidates: self
                        .stores
                        .iter()
                        .map(|store| store.id().to_owned())
                        .collect(),
                }
            };
        };

        match self.stores.iter().find(|store| store.id() == chosen) {
            Some(store) => Self::ask(store.as_ref(), name, undeclared),
            // A name pinned to a backend that is absent or disabled must not
            // quietly fall through to a different one — that is the same leak
            // the policy exists to prevent, reached by a different route.
            None => Resolution::Failed(vec![StoreError::Unavailable {
                store: chosen.to_owned(),
                detail: "routed store is not configured".to_owned(),
            }]),
        }
    }

    /// Every backend in order, first hit wins. Opt-in; see [`Policy::Ordered`].
    fn resolve_ordered(&self, name: &str) -> Resolution {
        let pinned = self.pinned(name);
        let mut errors = Vec::new();
        let mut asked_any = false;

        for store in &self.stores {
            if let Some(pinned) = pinned
                && store.id() != pinned
            {
                continue;
            }
            asked_any = true;
            match store.resolve(name) {
                Ok(Some(secret)) => {
                    return Resolution::Found {
                        store: store.id().to_owned(),
                        secret,
                    };
                }
                Ok(None) => {}
                Err(error @ StoreError::Refused { .. }) => {
                    return Resolution::Refused {
                        reason: error.to_string(),
                    };
                }
                Err(error) => errors.push(error),
            }
        }

        if !asked_any && let Some(pinned) = pinned {
            errors.push(StoreError::Unavailable {
                store: pinned.to_owned(),
                detail: "routed store is not configured".to_owned(),
            });
        }

        if !asked_any && pinned.is_none() {
            errors.push(no_store_enabled());
        }

        if errors.is_empty() {
            Resolution::NotFound {
                undeclared: self.undeclared(name),
            }
        } else {
            Resolution::Failed(errors)
        }
    }

    /// One backend, one question.
    fn ask(store: &dyn Store, name: &str, undeclared: bool) -> Resolution {
        match store.resolve(name) {
            Ok(Some(secret)) => Resolution::Found {
                store: store.id().to_owned(),
                secret,
            },
            Ok(None) => Resolution::NotFound { undeclared },
            Err(error @ StoreError::Refused { .. }) => Resolution::Refused {
                reason: error.to_string(),
            },
            Err(error) => Resolution::Failed(vec![error]),
        }
    }
}

/// What a lookup reports when no store is enabled to ask. A gap in this
/// machine's setup rather than a store's answer about the name, so it degrades
/// a run where an absence refuses it.
fn no_store_enabled() -> StoreError {
    StoreError::Unavailable {
        store: "keyless".to_owned(),
        detail: "no store is enabled; enable one under `stores` in the config file".to_owned(),
    }
}
