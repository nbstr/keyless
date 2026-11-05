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
//!
//! # What a backend does about its vendor's telemetry and update checks
//!
//! Each of the four adapters that spawn a vendor binary states this itself,
//! in its own module doc, because the answer is vendor-specific and the
//! property is not: [`infisical`] passes a flag on every invocation,
//! [`proton`] sets two environment variables on every command it spawns, and
//! [`onepassword`] and [`keychain`] switch nothing off, each because its
//! vendor offers nothing to switch. Not a [`Store`] method: the vendors
//! disagree on the SHAPE of the answer, not merely its value, so a method
//! here would either default to a no-op the two of them never override, or
//! force every adapter to implement a property half of them do not have.

pub mod catalogue;
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
pub mod proton_session;

mod registration;
mod registry;

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

    /// An operational notice this backend wants surfaced on stderr once, from
    /// its most recent lookup — never a secret, and never tied to the name
    /// that was asked for. `None` for every backend but [`daemon::DaemonStore`],
    /// which relays whatever the daemon's own reply carried; a local backend
    /// has no daemon reply to relay one from.
    fn advisory(&self) -> Option<String> {
        None
    }

    /// Whether this backend decides for itself which names are malformed,
    /// and records the refusal where its owner reads it.
    ///
    /// `false` for every local backend: a registry never hands one an empty
    /// name, because what a vendor CLI makes of an empty argument is anyone's
    /// guess. `true` for [`daemon::DaemonStore`], whose daemon refuses an
    /// empty or over-long name and writes that refusal to its own audit log —
    /// a log the caller cannot edit, which is why the registry still asks.
    fn judges_names(&self) -> bool {
        false
    }
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
    /// A backend declined the request itself: the name names nothing any
    /// lookup could find, or the caller is not one it will serve. Carries why,
    /// for the refused banner. Never contains a value.
    Refused {
        /// The rule the request broke, and who applied it.
        reason: String,
    },
    /// Several backends could have meant this name and none was chosen.
    ///
    /// No backend was asked. See the module documentation for why guessing here
    /// is a cross-tenant leak rather than a convenience.
    Ambiguous {
        /// The ids of the backends that could have answered.
        candidates: Vec<String>,
    },
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
        registration::register_the_daemon_alone(
            config,
            &mut stores,
            &mut routes,
            &mut default_store,
            &mut warnings,
            &mut notes,
        );
    } else {
        registration::register_local_backends(config, invocation, &mut stores, &mut warnings);
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
mod tests;
