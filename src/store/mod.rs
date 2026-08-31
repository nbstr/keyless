//! The backend seam, and the rule that decides which backend answers.
//!
//! A store answers one question: "do you have a value for this name?" It
//! deliberately cannot enumerate values, cannot write, and cannot be asked for
//! anything but a single named lookup. Adding a backend means implementing
//! [`Store`] and pushing it into [`build`]. Nothing in `run` changes, and
//! nothing in `run` knows which backend answered.
//!
//! Trait objects rather than an enum: the set of backends is open, and an enum
//! would make every new adapter a change to a shared type that `run` matches on.
//!
//! # One name, several stores
//!
//! With a company vault and a personal vault both configured, `DATABASE_URL`
//! could mean either. "Ask each backend in turn and take the first hit" answers
//! that question with configuration order — silently, invisibly, and wrongly
//! half the time. A personal database URL handed to a deploy script is not a
//! convenience feature misfiring; it is one tenant's credential crossing into
//! another's work, and nothing in the output would say so.
//!
//! So the default is [`Policy::Explicit`]: exactly one backend is eligible for
//! a name, and which one is never inferred from ordering.
//!
//! | The name declares | Backends configured | Outcome |
//! |---|---|---|
//! | `"store": "infisical"` | any | that backend, and only it |
//! | nothing, `stores.default` set | any | the default backend, and only it |
//! | nothing | exactly one | that one |
//! | nothing | two or more | [`Resolution::Ambiguous`] — the run degrades and names the candidates |
//!
//! Ambiguity is resolved by **refusing to guess**, not by picking. The run still
//! happens — the never-block invariant has no exception for this either — with
//! the name listed as unresolved and a message saying which backends could have
//! meant it and how to pin one.
//!
//! Note what the ambiguous case deliberately does *not* do: it does not query
//! the candidates to see which of them happens to have the name. That would
//! read a value out of a store the user never intended to touch, and against
//! Proton Pass it would write an audit entry for a read that was only ever a
//! guess. Asking is not free, so it is not done.
//!
//! [`Policy::Ordered`] restores the first-hit behaviour for anyone whose
//! backends all hold secrets of the same trust level. It is opt-in because the
//! failure it enables is silent.

pub mod daemon;
pub mod discover;
pub mod envnames;
pub mod exec;
pub mod file;
pub mod infisical;
pub mod keychain;
pub mod manage;
pub mod onepassword;
pub mod proton;
pub mod proton_manager;

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{Config, Policy};
use crate::error::StoreError;
use crate::secret::Secret;

/// A credential backend.
///
/// `Send + Sync` because the resolver may one day fan out across backends; it
/// costs nothing today and avoids a breaking change later.
pub trait Store: Send + Sync {
    /// Stable identifier, used in config routes and in error messages.
    fn id(&self) -> &str;

    /// Look up one name.
    ///
    /// `Ok(None)` means "I am healthy and I do not have it", which is a
    /// different fact from `Err(..)` — "I could not tell you". `doctor` shows
    /// the difference; `run` degrades identically on both, because from the
    /// child's point of view they are the same outcome.
    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError>;

    /// Cheap reachability check that reads no secret.
    fn health(&self) -> Result<(), StoreError>;
}

/// What the registry concluded about one name.
pub enum Resolution {
    /// A backend answered with a value.
    ///
    /// The backend's own id travels with it, so an audit row can say **which
    /// identity resolved the name**. That matters now that a second, write-capable
    /// identity exists: `proton` in a row is a statement that the reader answered,
    /// and a row saying `proton (manager)` can only have come from a write verb.
    /// Recorded rather than assumed — a constant string asserted by a test would
    /// prove nothing about which code path ran.
    Found {
        /// Which backend answered.
        store: String,
        /// The value.
        secret: Secret,
    },
    /// Every backend that was asked was healthy and none had it.
    NotFound {
        /// The config behind this registry was consulted and declares no such
        /// name.
        ///
        /// **"In a store" and "resolvable" are different states, and the plain
        /// absence message is true of both.** A name the config never declared
        /// has no coordinate — no vault, no item, no field, no account — so the
        /// only thing a backend could be asked for is the name itself. Reported
        /// as a plain absence, that sends the reader to the vault to look for
        /// something that may well be sitting there, when the line that fixes
        /// it is in the config file.
        ///
        /// `false` means EITHER declared OR not knowable — see
        /// [`Registry::with_declared_names`]. A registry built without the
        /// declared set claims nothing, because a wrong "you never declared it"
        /// is the same class of misdirection in the other direction.
        undeclared: bool,
    },
    /// At least one backend could not answer. Carries every error, so `doctor`
    /// and the degraded banner can say which backend failed and why.
    Failed(Vec<StoreError>),
    /// Several backends could have meant this name and none was chosen.
    ///
    /// No backend was asked. See the module documentation for why guessing here
    /// is a cross-tenant leak rather than a convenience.
    Ambiguous {
        /// The ids of the backends that could have answered.
        candidates: Vec<String>,
    },
}

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
            Resolution::Ambiguous { candidates } => format!(
                "{} stores could answer ({}) and none is pinned; \
                 add \"store\" to this name, or set \"stores.default\"",
                candidates.len(),
                candidates.join(", ")
            ),
        }
    }
}

/// The configured backends, the per-name routing, and the rule that picks one.
#[derive(Default)]
pub struct Registry {
    stores: Vec<Box<dyn Store>>,
    routes: BTreeMap<String, String>,
    policy: Policy,
    default_store: Option<String>,
    declared: Option<BTreeSet<String>>,
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
    #[must_use]
    pub fn resolve(&self, name: &str) -> Resolution {
        match self.policy {
            Policy::Explicit => self.resolve_explicit(name),
            Policy::Ordered => self.resolve_ordered(name),
        }
    }

    /// Exactly one backend is eligible, and it is never chosen by ordering.
    fn resolve_explicit(&self, name: &str) -> Resolution {
        let chosen = self
            .routes
            .get(name)
            .or(self.default_store.as_ref())
            .map(String::as_str);

        let undeclared = self.undeclared(name);
        let Some(chosen) = chosen else {
            return match self.stores.as_slice() {
                [] => Resolution::NotFound { undeclared },
                [only] => Self::ask(only.as_ref(), name, undeclared),
                several => Resolution::Ambiguous {
                    candidates: several.iter().map(|store| store.id().to_owned()).collect(),
                },
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
        let pinned = self.routes.get(name).map(String::as_str);
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
                Err(error) => errors.push(error),
            }
        }

        if !asked_any && let Some(pinned) = pinned {
            errors.push(StoreError::Unavailable {
                store: pinned.to_owned(),
                detail: "routed store is not configured".to_owned(),
            });
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
            Err(error) => Resolution::Failed(vec![error]),
        }
    }
}

/// The backends a config turns on, in search order.
///
/// The daemon suppresses every local backend — see [`build`] — so this reports
/// exactly one entry when it is enabled, rather than listing backends that will
/// never be consulted.
#[must_use]
pub fn enabled_stores(config: &Config) -> Vec<&'static str> {
    if config.stores.daemon.enabled {
        return vec![daemon::DAEMON_STORE_ID];
    }
    [
        ("keychain", config.stores.keychain.enabled),
        (infisical::STORE_ID, config.stores.infisical.enabled),
        (onepassword::STORE_ID, config.stores.onepassword.enabled),
        ("proton", config.stores.proton.enabled),
    ]
    .into_iter()
    .filter_map(|(id, on)| on.then_some(id))
    .collect()
}

/// Which backend a verb other than `run` should talk to.
///
/// Deliberately the same rule [`Registry::resolve`] applies under
/// [`Policy::Explicit`], and for the same reason: with a company vault and a
/// personal vault both configured, picking by configuration order picks wrong
/// half the time and says nothing. So an explicit `--store` wins, then the name's
/// own pin, then `stores.default`, then a single configured backend — and two or
/// more is reported as ambiguous rather than guessed.
///
/// # Errors
///
/// A sentence naming the candidates and how to pin one.
pub fn choose_store(
    config: &Config,
    name: Option<&str>,
    requested: Option<&str>,
) -> Result<String, String> {
    if let Some(requested) = requested {
        return Ok(requested.to_owned());
    }
    if let Some(pinned) = name.and_then(|name| config.secrets.get(name)?.store.clone()) {
        return Ok(pinned);
    }
    if let Some(default) = config.stores.default_store.clone() {
        return Ok(default);
    }
    match enabled_stores(config).as_slice() {
        [only] => Ok((*only).to_owned()),
        [] => {
            Err("no store is configured; enable one under `stores` in the config file".to_owned())
        }
        several => Err(format!(
            "{} stores are configured ({}) and none is pinned; pass --store, \
             or set \"stores.default\"",
            several.len(),
            several.join(", ")
        )),
    }
}

/// What one invocation knows and the config file cannot.
///
/// Two facts today, and they are the same kind of thing: each describes **this
/// command**, not this machine. A struct rather than two positional arguments,
/// for the reason [`crate::cmd::run::RunRequest`] is one — a third fact added by
/// widening a call signature is a change nobody reads, and both of these decide
/// which real value a name resolves to.
#[derive(Debug, Clone, Default)]
pub struct Invocation {
    /// The justification Proton Pass records against every read it serves.
    ///
    /// See [`proton::Reason`] for what may and may not go in it. Every other
    /// backend ignores it.
    pub reason: proton::Reason,
    /// `keyless run --env <slug>`: the Infisical environment for every name in
    /// this run that declares none.
    ///
    /// Deliberately weaker than a name's own `env`, and deliberately absent by
    /// default. Infisical has no default environment and neither does `keyless`;
    /// see [`infisical`] for what a config-level default cost when it existed.
    pub infisical_env: Option<String>,
}

impl Invocation {
    /// For a `keyless run` of `argv`.
    #[must_use]
    pub fn for_run(argv: &[std::ffi::OsString]) -> Self {
        Invocation {
            reason: proton::Reason::for_run(argv),
            infisical_env: None,
        }
    }

    /// For a verb that has no child, such as `doctor --probe`.
    #[must_use]
    pub fn for_verb(verb: &str) -> Self {
        Invocation {
            reason: proton::Reason::for_verb(verb),
            infisical_env: None,
        }
    }

    /// Attach the environment `--env` named, if it named one.
    #[must_use]
    pub fn with_infisical_env(mut self, env: Option<String>) -> Self {
        self.infisical_env = env;
        self
    }
}

/// A registry, plus anything an operator should be told about how it was built.
///
/// Two channels, because they have different audiences and different costs.
/// `run` prints [`Built::warnings`] on **every invocation**, so a line that
/// belongs to every user of a working configuration does not belong there: this
/// crate already learned that announcing an ordinary condition on every run
/// trains the reader to ignore its stderr, and the reader who stops reading
/// stderr is the reader who misses a real degrade.
pub struct Built {
    /// The backends, in search order.
    pub registry: Registry,
    /// Something the caller asked for was dropped, and they will notice.
    ///
    /// Printed by `run` and by `doctor`. Never a value.
    pub warnings: Vec<String>,
    /// How the registry was assembled, for someone who came to ask.
    ///
    /// Printed by `doctor` only. This is where the ordinary consequences of a
    /// correct configuration go — true, worth knowing once, and not worth a
    /// line on every command.
    pub notes: Vec<String>,
}

/// Assemble the registry a config describes.
///
/// This function is the extension point for another backend: add its
/// construction here, gated on its own config section. Nothing else needs to
/// know it exists.
///
/// `invocation` carries what the config cannot know: why this read is happening,
/// and which Infisical environment this command named. See [`Invocation`].
///
/// # The rule enforced here rather than documented
///
/// **When the daemon is enabled, every local backend is suppressed — keychain,
/// Infisical, 1Password and Proton alike — whatever their own `enabled` flags
/// say.**
///
/// The point of the daemon is that killing it must get you *fewer* secrets,
/// never more. Leave any local backend registered beside it, and the moment the
/// daemon stops answering `run` reaches for that backend instead — with the
/// session's own uid, and every login that uid already holds.
/// That is not a fallback. It is the hole the daemon exists to close, re-opening
/// itself automatically whenever the thing closing it goes away, and anyone able
/// to stop a process could choose it.
///
/// All four are the same class of thing, which is why the rule is not specific
/// to the keychain: each resolves through a credential the calling user already
/// holds. Infisical inherits the CLI's login, 1Password inherits `op`'s, Proton
/// inherits `pass-cli`'s. A session that can run `keyless` can run any of those
/// CLIs directly, so registering them under the daemon would leave it guarding
/// one door of four.
///
/// ## Per-name pins are dropped too, and that is the safer direction
///
/// A `"store": "infisical"` pin exists to stop an unpinned name resolving
/// against the wrong tenant — see the module documentation. Under the daemon
/// there is exactly one local backend, so there is no local ambiguity left for a
/// pin to resolve, and which vault a name means becomes the **daemon's**
/// question to answer from its own config.
///
/// That is a relocation, not a removal. The daemon's registry runs this same
/// [`crate::config::Policy::Explicit`] rule, so an ambiguous name still degrades
/// rather than resolving to a guess. Moving the decision to the privileged side
/// is strictly better, because the client is the untrusted party.
///
/// Leaving the pins would be worse than useless: they would name backends that
/// are no longer registered, so every pinned name would degrade with
/// `routed store is not configured` — a message pointing at a store the user can
/// plainly see enabled in their own config.
///
/// A pin naming `daemon` is kept, and so is a `stores.default` that does.
#[must_use]
pub fn build(config: &Config, invocation: &Invocation) -> Built {
    let mut stores: Vec<Box<dyn Store>> = Vec::new();
    let mut warnings = Vec::new();
    let mut notes = Vec::new();

    let mut routes: BTreeMap<String, String> = config
        .secrets
        .iter()
        .filter_map(|(name, route)| route.store.clone().map(|store| (name.clone(), store)))
        .collect();
    let mut default_store = config.stores.default_store.clone();

    if config.stores.daemon.enabled {
        stores.push(Box::new(daemon::DaemonStore::new(
            config.stores.daemon.socket_path(),
            config.stores.daemon.timeout(),
        )));

        // Which suppressions the user will actually miss, and which are
        // routine, is a question the config can answer — but only for three of
        // the four.
        //
        // `infisical`, `onepassword` and `proton` default to disabled, so
        // finding one enabled means somebody typed it, and suppressing it takes
        // away names they are resolving today. That earns a warning on every
        // run.
        //
        // `keychain` defaults to ENABLED, so its flag says nothing about
        // intent: a config that has never mentioned a keychain reports one.
        // Warning on that would put a line on every single command for every
        // daemon user, forever, which is how stderr stops being read. It goes
        // to `doctor`, which is where somebody has come to ask.
        let explicit: Vec<&str> = [
            ("infisical", config.stores.infisical.enabled),
            (onepassword::STORE_ID, config.stores.onepassword.enabled),
            ("proton", config.stores.proton.enabled),
        ]
        .into_iter()
        .filter_map(|(id, enabled)| enabled.then_some(id))
        .collect();

        let suppressed: Vec<&str> = [
            ("keychain", config.stores.keychain.enabled),
            ("infisical", config.stores.infisical.enabled),
            (onepassword::STORE_ID, config.stores.onepassword.enabled),
            ("proton", config.stores.proton.enabled),
        ]
        .into_iter()
        .filter_map(|(id, enabled)| enabled.then_some(id))
        .collect();

        if !explicit.is_empty() {
            // The halves are not the same story, and saying they are would be
            // a wrong fact in the one place a user reads on every command.
            // `keylessd` carries the Infisical and 1Password adapters: those
            // names are moved, not lost, and the sentence has to say where to.
            // It carries no Proton adapter: those names have nowhere to go
            // yet, and that is a different instruction.
            let mut remedies: Vec<String> = Vec::new();
            if config.stores.infisical.enabled {
                remedies.push(if explicit.len() == 1 {
                    "declare them under `secrets` in `keylessd.json`, with an \"env\", and \
                     enable `stores.infisical` there"
                        .to_owned()
                } else {
                    "declare the Infisical ones under `secrets` in `keylessd.json`, with an \
                     \"env\", and enable `stores.infisical` there"
                        .to_owned()
                });
            }
            if config.stores.onepassword.enabled {
                remedies.push(if explicit.len() == 1 {
                    "declare them under `secrets` in `keylessd.json`, enable \
                     `stores.onepassword` there with the same \"vault\", and give the daemon \
                     a service account scoped to that vault"
                        .to_owned()
                } else {
                    "declare the 1Password ones under `secrets` in `keylessd.json`, enable \
                     `stores.onepassword` there with the same \"vault\", and give the daemon \
                     a service account scoped to that vault"
                        .to_owned()
                });
            }
            if config.stores.proton.enabled {
                remedies.push(if explicit.len() == 1 {
                    "`keylessd` does not carry that adapter yet".to_owned()
                } else {
                    "`keylessd` does not carry the Proton adapter yet".to_owned()
                });
            }
            warnings.push(format!(
                "the daemon is enabled, so {} {} not used locally: a local fallback would hand \
                 out more secrets when the daemon stops, not fewer. Names that live there must \
                 be served by the daemon's own config — {}",
                explicit.join(" and "),
                if explicit.len() == 1 { "is" } else { "are" },
                remedies.join("; ")
            ));
        }

        if !suppressed.is_empty() {
            notes.push(format!(
                "the daemon resolves every name, so the local {} backend{} {} not consulted",
                suppressed.join(", "),
                if suppressed.len() == 1 { "" } else { "s" },
                if suppressed.len() == 1 { "is" } else { "are" }
            ));
        }

        let mut dropped: Vec<String> = Vec::new();
        routes.retain(|name, store| {
            let keep = store == daemon::DAEMON_STORE_ID;
            if !keep {
                dropped.push(format!("{name} -> {store}"));
            }
            keep
        });
        if !dropped.is_empty() {
            dropped.sort();
            warnings.push(format!(
                "the daemon resolves every name, so these per-name store pins are ignored: {}",
                dropped.join(", ")
            ));
        }

        if let Some(named) = default_store.as_deref()
            && named != daemon::DAEMON_STORE_ID
        {
            warnings.push(format!(
                "`stores.default` names `{named}`, which the daemon suppresses; the daemon \
                 decides which vault a name means"
            ));
            default_store = None;
        }
    } else {
        if config.stores.keychain.enabled {
            stores.push(Box::new(keychain::KeychainStore::from_config(config)));
        }
        if config.stores.infisical.enabled {
            // A config that still sets the environment `keyless` used to default
            // is TOLD, rather than silently ignored. Unknown keys are dropped by
            // design, so without this the reader would see names stop resolving
            // and nothing connecting that to the line that caused it.
            if let Some(stale) = &config.stores.infisical.env {
                warnings.push(format!(
                    "`stores.infisical.env` is set to `{stale}` and is IGNORED. A machine-wide \
                     default environment resolved names nobody declared, against whichever \
                     environment this file happened to name. Put \"env\" on each name under \
                     `secrets`, or pass `keyless run --env {stale}` per command; then delete \
                     the key to silence this"
                ));
            }
            stores.push(Box::new(infisical::InfisicalStore::from_config(
                config,
                invocation.infisical_env.as_deref(),
            )));
        }
        if config.stores.onepassword.enabled {
            stores.push(Box::new(onepassword::OnePasswordStore::from_config(config)));
        }
        if config.stores.proton.enabled {
            stores.push(Box::new(proton::ProtonStore::from_config(
                config,
                invocation.reason.clone(),
            )));
        }
    }

    let mut registry = Registry::new(stores)
        .with_routes(routes)
        .with_policy(config.stores.policy)
        .with_default_store(default_store);

    // Withheld under the daemon, and only there. This config still lists names
    // — `ls` and `doctor` read them from here — but it is the DAEMON's config
    // that says where a name's value lives, so a name missing from this one is
    // not evidence that nobody declared it. Telling a daemon user to declare it
    // here would send them to edit a file that does not decide the question,
    // which is the same fault as the message this distinction exists to fix.
    if !config.stores.daemon.enabled {
        registry = registry.with_declared_names(config.secrets.keys().cloned().collect());
    }

    Built {
        registry,
        warnings,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::{Registry, Resolution, Store};
    use crate::config::Policy;
    use crate::error::StoreError;
    use crate::secret::Secret;

    struct Fixed {
        id: &'static str,
        value: Option<&'static str>,
    }

    impl Store for Fixed {
        fn id(&self) -> &str {
            self.id
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            Ok(self.value.map(|v| Secret::new(v.to_owned())))
        }
        fn health(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    struct Broken(&'static str);

    impl Store for Broken {
        fn id(&self) -> &str {
            self.0
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            Err(StoreError::Unavailable {
                store: self.0.to_owned(),
                detail: "stub is always down".to_owned(),
            })
        }
        fn health(&self) -> Result<(), StoreError> {
            Err(StoreError::Unavailable {
                store: self.0.to_owned(),
                detail: "stub is always down".to_owned(),
            })
        }
    }

    /// Two backends that both hold the name, which is the shape the policy is
    /// about: a company vault and a personal one, each with a `DATABASE_URL`.
    fn two_tenants() -> Vec<Box<dyn Store>> {
        vec![
            Box::new(Fixed {
                id: "company",
                value: Some("decoy-company-value"),
            }),
            Box::new(Fixed {
                id: "personal",
                value: Some("decoy-personal-value"),
            }),
        ]
    }

    // -----------------------------------------------------------------------
    // Explicit — the default.
    // -----------------------------------------------------------------------

    #[test]
    fn an_unpinned_name_with_two_backends_is_ambiguous_rather_than_guessed() {
        // The whole reason this policy exists. Whichever value came back here
        // would be right half the time and silent the other half.
        let registry = Registry::new(two_tenants());
        match registry.resolve("DATABASE_URL") {
            Resolution::Ambiguous { candidates } => {
                assert_eq!(candidates, ["company", "personal"]);
            }
            Resolution::Found { .. } => panic!("a wrong store's value was returned silently"),
            _ => panic!("expected Ambiguous"),
        }
    }

    #[test]
    fn the_ambiguous_reason_names_the_candidates_and_carries_no_value() {
        let registry = Registry::new(two_tenants());
        let reason = registry.resolve("DATABASE_URL").reason();
        assert!(reason.contains("company"));
        assert!(reason.contains("personal"));
        assert!(!reason.contains("decoy-"), "the reason leaked a value");
    }

    #[test]
    fn a_pinned_name_reaches_exactly_the_store_it_names() {
        let registry = Registry::new(two_tenants()).with_routes(
            [("DATABASE_URL".to_owned(), "personal".to_owned())]
                .into_iter()
                .collect(),
        );
        match registry.resolve("DATABASE_URL") {
            Resolution::Found { secret, .. } => assert_eq!(secret.expose(), "decoy-personal-value"),
            _ => panic!("a pinned name must resolve"),
        }
    }

    #[test]
    fn a_pinned_name_does_not_fall_back_when_its_store_lacks_it() {
        // Falling through to the other backend here would produce exactly the
        // cross-tenant value the pin was written to prevent.
        let registry = Registry::new(vec![
            Box::new(Fixed {
                id: "company",
                value: None,
            }),
            Box::new(Fixed {
                id: "personal",
                value: Some("decoy-personal-value"),
            }),
        ])
        .with_routes(
            [("DATABASE_URL".to_owned(), "company".to_owned())]
                .into_iter()
                .collect(),
        );
        assert!(matches!(
            registry.resolve("DATABASE_URL"),
            Resolution::NotFound { .. }
        ));
    }

    #[test]
    fn a_pinned_name_does_not_fall_back_when_its_store_is_broken() {
        let registry = Registry::new(vec![
            Box::new(Broken("company")),
            Box::new(Fixed {
                id: "personal",
                value: Some("decoy-personal-value"),
            }),
        ])
        .with_routes(
            [("DATABASE_URL".to_owned(), "company".to_owned())]
                .into_iter()
                .collect(),
        );
        match registry.resolve("DATABASE_URL") {
            Resolution::Failed(errors) => assert_eq!(errors.len(), 1),
            Resolution::Found { .. } => panic!("a broken pin fell through to another tenant"),
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn the_default_store_answers_unpinned_names() {
        let registry = Registry::new(two_tenants()).with_default_store(Some("personal".to_owned()));
        match registry.resolve("DATABASE_URL") {
            Resolution::Found { secret, .. } => assert_eq!(secret.expose(), "decoy-personal-value"),
            _ => panic!("the declared default must answer"),
        }
    }

    #[test]
    fn a_names_own_pin_outranks_the_default_store() {
        let registry = Registry::new(two_tenants())
            .with_default_store(Some("personal".to_owned()))
            .with_routes(
                [("DATABASE_URL".to_owned(), "company".to_owned())]
                    .into_iter()
                    .collect(),
            );
        match registry.resolve("DATABASE_URL") {
            Resolution::Found { secret, .. } => assert_eq!(secret.expose(), "decoy-company-value"),
            _ => panic!("the name's own pin must win"),
        }
    }

    #[test]
    fn a_single_backend_needs_no_pin() {
        // The one-store setup — every existing user — is unchanged.
        let registry = Registry::new(vec![Box::new(Fixed {
            id: "a",
            value: Some("decoy-only-store"),
        })]);
        assert!(registry.resolve("X").is_found());
    }

    #[test]
    fn a_route_to_an_absent_backend_fails_loudly() {
        let registry = Registry::new(vec![Box::new(Fixed {
            id: "a",
            value: Some("decoy"),
        })])
        .with_routes(
            [("X".to_owned(), "nowhere".to_owned())]
                .into_iter()
                .collect(),
        );
        match registry.resolve("X") {
            Resolution::Failed(errors) => assert_eq!(errors.len(), 1),
            _ => panic!("a route to a missing backend must not silently fall through"),
        }
    }

    #[test]
    fn a_default_store_that_is_not_configured_fails_loudly() {
        let registry = Registry::new(vec![Box::new(Fixed {
            id: "a",
            value: Some("decoy"),
        })])
        .with_default_store(Some("nowhere".to_owned()));
        assert!(matches!(registry.resolve("X"), Resolution::Failed(_)));
    }

    #[test]
    fn every_backend_healthy_and_empty_reports_notfound() {
        let registry = Registry::new(vec![Box::new(Fixed {
            id: "a",
            value: None,
        })]);
        assert!(matches!(registry.resolve("X"), Resolution::NotFound { .. }));
    }

    // -----------------------------------------------------------------------
    // "In a store" and "resolvable" are different states.
    // -----------------------------------------------------------------------

    /// One healthy backend that holds nothing, told which names the config
    /// declares.
    fn empty_store_declaring(declared: &[&str]) -> Registry {
        Registry::new(vec![Box::new(Fixed {
            id: "a",
            value: None,
        })])
        .with_declared_names(declared.iter().map(|name| (*name).to_owned()).collect())
    }

    #[test]
    fn a_name_the_config_never_declared_says_so_rather_than_reading_as_absent() {
        // The incident: a credential really was in the vault, under the right
        // item and the right field, and nothing had ever declared its name. The
        // absence message sent its reader to the store to look for something
        // the store was never asked about.
        let reason = empty_store_declaring(&["DECLARED"])
            .resolve("NEVER_DECLARED")
            .reason();
        assert!(
            reason.contains("not declared in your config"),
            "an undeclared name must say which file is missing the line: {reason}"
        );
        assert!(
            reason.contains("Declare it under \"secrets\""),
            "a diagnosis with no next action is the shape this report used to have: {reason}"
        );
        // The one thing it cannot know. Nothing was asked of any store on this
        // name's behalf beyond the name itself, so a store holding it under
        // some other coordinate is not a fact in evidence.
        assert!(
            !reason.contains("is in your store"),
            "the message claimed a store holds it: {reason}"
        );
    }

    #[test]
    fn a_declared_name_that_no_store_holds_still_reads_as_a_plain_absence() {
        // The negative control for the test above. This name HAS a declaration,
        // so its coordinate was asked and came back empty — the store is the
        // right place to look, and this message is the one that says so. If
        // both cases start naming the config, the distinction is gone in the
        // other direction and this test is what notices.
        let reason = empty_store_declaring(&["DECLARED"])
            .resolve("DECLARED")
            .reason();
        assert_eq!(reason, "not found in any store");
    }

    #[test]
    fn a_registry_given_no_declarations_claims_nothing_about_them() {
        // A registry built without the config's names — the daemon client, and
        // every caller that constructs one directly — cannot tell the two
        // states apart, and says the older, weaker thing rather than inventing
        // the stronger one.
        let reason = Registry::new(vec![Box::new(Fixed {
            id: "a",
            value: None,
        })])
        .resolve("NEVER_DECLARED")
        .reason();
        assert_eq!(reason, "not found in any store");
    }

    // -----------------------------------------------------------------------
    // The daemon suppresses every local backend, not just the keychain.
    // -----------------------------------------------------------------------

    fn config_from(json: &str) -> crate::config::Config {
        serde_json::from_str(json).expect("valid config")
    }

    /// The registered backend ids, and everything the build had to say —
    /// both channels joined, because these tests are about *whether it was
    /// said*, not about which stream it went to.
    fn registered(config: &crate::config::Config) -> (Vec<String>, Vec<String>) {
        let built = super::build(config, &super::Invocation::default());
        let ids = built
            .registry
            .stores()
            .iter()
            .map(|store| store.id().to_owned())
            .collect();
        let mut said = built.warnings;
        said.extend(built.notes);
        (ids, said)
    }

    #[test]
    fn enabling_the_daemon_suppresses_every_local_backend() {
        // Invariant: killing the daemon must yield fewer secrets, never more.
        // Each of these three resolves through a credential the calling user
        // already holds, so any one of them left registered is a local
        // fallback that opens the moment the daemon stops.
        let (ids, warnings) = registered(&config_from(
            r#"{"stores":{"keychain":{"enabled":true},
                          "infisical":{"enabled":true},
                          "onepassword":{"enabled":true},
                          "proton":{"enabled":true},
                          "daemon":{"enabled":true}}}"#,
        ));
        assert_eq!(ids, ["daemon"]);
        let said = warnings.join(" ");
        for backend in ["keychain", "infisical", "onepassword", "proton"] {
            assert!(
                said.contains(backend),
                "dropping {backend} must be said out loud: {said}"
            );
        }
    }

    #[test]
    fn the_suppression_warning_says_where_a_suppressed_backends_names_can_go() {
        // A suppression is only actionable if the sentence says what to do
        // next, and the two backends now have DIFFERENT next steps: `keylessd`
        // carries the Infisical adapter, so those names move into its config;
        // it carries no Proton adapter, so those names have nowhere to go yet.
        // One sentence covering both would have to be wrong about one of them.
        let infisical_only = registered(&config_from(
            r#"{"stores":{"infisical":{"enabled":true},"daemon":{"enabled":true}}}"#,
        ))
        .1
        .join(" ");
        assert!(
            infisical_only.contains("keylessd.json"),
            "an Infisical name has somewhere to go and the warning must name it: {infisical_only}"
        );
        assert!(
            !infisical_only.contains("does not carry"),
            "the adapter exists, so this must not say it does not: {infisical_only}"
        );

        let proton_only = registered(&config_from(
            r#"{"stores":{"proton":{"enabled":true},"daemon":{"enabled":true}}}"#,
        ))
        .1
        .join(" ");
        assert!(
            proton_only.contains("does not carry that adapter yet"),
            "a Proton name has nowhere to go and the warning must say so: {proton_only}"
        );

        // A 1Password name moves too, and the sentence has to say the two
        // things a daemon needs that a session did not: the same vault, and a
        // login of its own.
        let onepassword_only = registered(&config_from(
            r#"{"stores":{"onepassword":{"enabled":true},"daemon":{"enabled":true}}}"#,
        ))
        .1
        .join(" ");
        assert!(
            onepassword_only.contains("keylessd.json"),
            "{onepassword_only}"
        );
        assert!(
            onepassword_only.contains("service account"),
            "{onepassword_only}"
        );
        assert!(onepassword_only.contains("\"vault\""), "{onepassword_only}");
        assert!(
            !onepassword_only.contains("does not carry"),
            "{onepassword_only}"
        );

        // All at once: each keeps its own instruction rather than one being
        // flattened into another's.
        let all = registered(&config_from(
            r#"{"stores":{"infisical":{"enabled":true},"onepassword":{"enabled":true},
                          "proton":{"enabled":true},"daemon":{"enabled":true}}}"#,
        ))
        .1
        .join(" ");
        assert!(all.contains("keylessd.json"), "{all}");
        assert!(all.contains("the Infisical ones"), "{all}");
        assert!(all.contains("the 1Password ones"), "{all}");
        assert!(
            all.contains("does not carry the Proton adapter yet"),
            "{all}"
        );
    }

    #[test]
    fn without_the_daemon_every_configured_backend_is_registered() {
        // The negative control. Without it the test above could pass because
        // these backends are never registered under any configuration.
        let (ids, warnings) = registered(&config_from(
            r#"{"stores":{"keychain":{"enabled":true},
                          "infisical":{"enabled":true},
                          "onepassword":{"enabled":true},
                          "proton":{"enabled":true}}}"#,
        ));
        assert_eq!(ids, ["keychain", "infisical", "onepassword", "proton"]);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn the_daemon_drops_per_name_store_pins_and_names_them() {
        // A pin left in place would name a backend that is no longer
        // registered, so the name would degrade with `routed store is not
        // configured` — pointing the reader at a store their config plainly
        // enables. Routing is the daemon's decision now.
        let config = config_from(
            r#"{"stores":{"infisical":{"enabled":true},"daemon":{"enabled":true}},
                "secrets":{"DATABASE_URL":{"store":"infisical"}}}"#,
        );
        let built = super::build(&config, &super::Invocation::default());
        assert!(
            built
                .warnings
                .iter()
                .any(|w| w.contains("DATABASE_URL -> infisical")),
            "{:?}",
            built.warnings
        );

        // And the name reaches the daemon rather than dying on the stale pin.
        // The socket does not exist, so this fails — but it must fail as an
        // unreachable daemon, never as an unconfigured route.
        let reason = built.registry.resolve("DATABASE_URL").reason();
        assert!(
            !reason.contains("routed store is not configured"),
            "the stale pin survived: {reason}"
        );
    }

    #[test]
    fn a_pin_that_names_the_daemon_survives() {
        let config = config_from(
            r#"{"stores":{"daemon":{"enabled":true}},
                "secrets":{"DATABASE_URL":{"store":"daemon"}}}"#,
        );
        let built = super::build(&config, &super::Invocation::default());
        // No WARNING: nothing the user asked for was dropped. The keychain
        // note is a `doctor` line and does not belong on every run.
        assert!(built.warnings.is_empty(), "{:?}", built.warnings);
        assert!(
            !built
                .registry
                .resolve("DATABASE_URL")
                .reason()
                .contains("routed store is not configured")
        );
    }

    #[test]
    fn a_default_store_the_daemon_suppresses_is_dropped_and_named() {
        let config = config_from(
            r#"{"stores":{"keychain":{"enabled":true},"daemon":{"enabled":true},
                          "default":"keychain"}}"#,
        );
        let built = super::build(&config, &super::Invocation::default());
        assert!(
            built.warnings.iter().any(|w| w.contains("stores.default")),
            "{:?}",
            built.warnings
        );
        // One store is registered, so an unpinned name reaches it rather than
        // failing on a default that names something suppressed.
        assert!(
            !built
                .registry
                .resolve("ANY")
                .reason()
                .contains("routed store is not configured")
        );
    }

    #[test]
    fn an_empty_registry_reports_notfound_rather_than_panicking() {
        let registry = Registry::new(Vec::new());
        assert!(matches!(registry.resolve("X"), Resolution::NotFound { .. }));
        assert!(registry.is_empty());
    }

    // -----------------------------------------------------------------------
    // Ordered — opt-in, and only safe when every backend is one tenant.
    // -----------------------------------------------------------------------

    #[test]
    fn the_first_backend_with_a_value_wins_when_ordering_is_asked_for() {
        let registry = Registry::new(vec![
            Box::new(Fixed {
                id: "a",
                value: None,
            }),
            Box::new(Fixed {
                id: "b",
                value: Some("decoy-from-b"),
            }),
        ])
        .with_policy(Policy::Ordered);
        match registry.resolve("X") {
            Resolution::Found { secret, .. } => assert_eq!(secret.expose(), "decoy-from-b"),
            _ => panic!("expected a value"),
        }
    }

    #[test]
    fn a_failing_backend_does_not_hide_a_later_hit_when_ordering_is_asked_for() {
        let registry = Registry::new(vec![
            Box::new(Broken("down")),
            Box::new(Fixed {
                id: "b",
                value: Some("decoy-still-found"),
            }),
        ])
        .with_policy(Policy::Ordered);
        assert!(registry.resolve("X").is_found());
    }

    #[test]
    fn all_backends_erroring_reports_failed_not_notfound() {
        let registry = Registry::new(vec![Box::new(Broken("one")), Box::new(Broken("two"))])
            .with_policy(Policy::Ordered);
        match registry.resolve("X") {
            Resolution::Failed(errors) => assert_eq!(errors.len(), 2),
            _ => panic!("expected Failed"),
        }
    }

    #[test]
    fn ordering_never_reports_ambiguity_because_it_never_refuses_to_choose() {
        let registry = Registry::new(two_tenants()).with_policy(Policy::Ordered);
        assert!(registry.resolve("DATABASE_URL").is_found());
    }
}
