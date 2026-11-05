//! Putting a value INTO a store, under a second identity.
//!
//! # Two identities, and which verbs may reach which
//!
//! Everything that reads — `run`, `doctor --probe`, `items`, `fields` — uses the
//! **reader**: for Proton Pass, a viewer-role agent token in its own session
//! directory. That is what ~20 concurrent sessions are given, and it cannot
//! create, move or trash anything.
//!
//! Everything that writes — `new`, `put` — uses the **manager**: a second,
//! editor-role token in a second session directory, named explicitly in the
//! config. Nothing in this module is reachable from a [`crate::store::Registry`],
//! and [`crate::store::proton::ProtonStore`] does not read the manager block at
//! all, so there is no path by which a `run` can act as the manager. That is a
//! property of the types rather than a rule someone has to remember.
//!
//! # Where the split is enforced, and where it is only advisory
//!
//! **Say this part plainly or it becomes a false claim.** Two session
//! directories are two tokens, two audit trails at the vendor and two expiries.
//! They are not a boundary: any process running as this uid can set
//! `PROTON_PASS_SESSION_DIR` to the manager's directory and act as the manager.
//! A file mode does not help, because the reader that must work in every session
//! is readable by every session.
//!
//! The only thing on this machine that can hold a credential this uid cannot
//! reach is [`crate::daemon`], behind a second uid. So the enforced version of
//! this split is "the manager token lives on the daemon's side", and it is not
//! built yet: `keylessd` carries a file store and a keychain store, no Proton
//! adapter, and the protocol has no write operation.
//!
//! Given that, [`manager`] does the one thing that cannot be wrong — **it
//! refuses to write locally whenever the daemon is enabled.** Reaching around a
//! configured daemon would break the rule the whole daemon design rests on
//! ([`crate::store::build`]): killing the daemon must yield *fewer* powers, never
//! more. A local write path that opens whenever the daemon is off is exactly that
//! hole, one verb over.
//!
//! # Why a write refuses on failure when a read does not
//!
//! `keyless run` never refuses over a store's failure, because that blocks
//! somebody's actual work and a tool that blocks work gets removed — after
//! which the plaintext comes back. That argument does not transfer to `new` and
//! `put`. They are setup steps, run once, with a person watching the output;
//! nothing downstream is waiting on them. And the failure modes are asymmetric:
//! a `run` that degrades still runs the command, where a write that "degraded"
//! would report success with nothing stored, and the next `run` would refuse a
//! name its owner just watched being stored. So the write verbs exit non-zero
//! and say what is missing.

use crate::config::{Config, SecretRoute};
use crate::secret::Secret;
use crate::store::keychain::KeychainManager;
use crate::store::proton::Reason;
use crate::store::proton_manager::ProtonManager;

/// Where a value was put. Coordinates only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// A human-readable description of the destination — a vault and item title,
    /// or a keychain service and account. Never a value.
    pub location: String,
}

/// A store that can be written to, as the manager identity.
pub trait Manage {
    /// Stable identifier, matching the [`crate::store::Store`] of the same backend.
    fn id(&self) -> &str;

    /// Which identity this writer acts as, for the audit row and for `doctor`.
    ///
    /// Rendered rather than derived from the store id so a row says
    /// `proton (manager)` and can never be confused with a read.
    fn identity(&self) -> String {
        format!("{} (manager)", self.id())
    }

    /// Store `value` under `name`, at the coordinates `route` declares.
    ///
    /// # Errors
    ///
    /// [`ManageError`] for every failure. Implementations must build their
    /// message from the backend's **stderr** only, exactly as the read adapters
    /// do — a write's stdout can echo what was written.
    fn store(&self, name: &str, route: &SecretRoute, value: &Secret)
    -> Result<Stored, ManageError>;
}

/// Why a write did not happen.
#[derive(Debug)]
pub enum ManageError {
    /// No identity is configured that is allowed to write to this backend.
    NoIdentity {
        /// Store identifier.
        store: String,
        /// What to configure, and what to mint.
        detail: String,
    },
    /// The daemon holds the manager identity, so a local write is refused.
    DaemonHoldsIt(String),
    /// The config does not say where in the backend the value should go.
    Address {
        /// Store identifier.
        store: String,
        /// Which fields are missing.
        detail: String,
    },
    /// The value itself cannot be stored by this backend. Never contains it.
    Value {
        /// Store identifier.
        store: String,
        /// What about its shape is unusable.
        detail: String,
    },
    /// The backend was reached and refused or errored.
    Backend {
        /// Store identifier.
        store: String,
        /// Cause, from the backend's stderr only.
        detail: String,
    },
    /// The backend could not be reached.
    Unavailable {
        /// Store identifier.
        store: String,
        /// Cause.
        detail: String,
    },
}

impl ManageError {
    /// The process exit code to report.
    ///
    /// Split so a caller can tell "fix your config" from "fix your data" from
    /// "the vault said no" without parsing a sentence. The values follow
    /// `sysexits.h`, which is what a shell script already knows.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            // EX_CONFIG: nothing was attempted; a file needs editing.
            ManageError::NoIdentity { .. }
            | ManageError::DaemonHoldsIt(_)
            | ManageError::Address { .. } => 78,
            // EX_DATAERR: the value cannot be represented.
            ManageError::Value { .. } => 65,
            ManageError::Backend { .. } | ManageError::Unavailable { .. } => 1,
        }
    }
}

impl std::fmt::Display for ManageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManageError::NoIdentity { store, detail } => {
                write!(f, "store `{store}` has no manager identity: {detail}")
            }
            ManageError::DaemonHoldsIt(detail) => write!(f, "{detail}"),
            ManageError::Address { store, detail } => {
                write!(f, "store `{store}` does not know where to put it: {detail}")
            }
            ManageError::Value { store, detail } => {
                write!(f, "store `{store}` cannot store this value: {detail}")
            }
            ManageError::Backend { store, detail } => {
                write!(f, "store `{store}` refused the write: {detail}")
            }
            ManageError::Unavailable { store, detail } => {
                write!(f, "store `{store}` is unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for ManageError {}

/// What an operator must mint before Proton can be written to.
///
/// Spelled out to the flag because the fix is several steps in somebody else's
/// product and a generic "permission denied" sends the reader to the wrong one —
/// vault permissions, usually, which are not the problem.
///
/// Measured 2026-08-08 against a live account and `pass-cli` 2.2.5, and again
/// 2026-08-21 against 2.3.2:
///
/// - `agent access grant` takes `--role`, whose values are `viewer`, `editor`
///   and `manager`, and whose **default is `viewer`**. So a token minted without
///   thinking about the role is read-only, which is why this failure is the
///   normal one rather than an unusual one.
/// - A viewer-role token returns `NotAllowed` from `item create` and from
///   `item trash`.
/// - **`agent create --vault <V>` fixes the agent's access set permanently.**
///   A later `agent access grant` on that agent answers `NotAllowed` for every
///   role — including the one it already holds — and `agent access revoke`
///   answers `NotExists` for the very vault the agent can read. So the editor
///   agent is created with NO `--vault` and granted afterwards, and only the
///   viewer agent is created with one.
///
/// That last point inverts the order this recipe used to give, which paired
/// `agent create --vault <V>` with a following `access grant --role editor`.
/// Both commands report success-shaped failures for the wrong reason: the grant
/// blames permission, so the reader goes and checks the vault's sharing settings
/// and the account's plan, and neither is what is wrong.
///
/// # Which session each of the three commands runs in, which is the whole recipe
///
/// The recipe this replaces named two commands and no session, and it was
/// unfollowable twice over.
///
/// - `agent create` and `agent access grant` act as the **account**. They mint a
///   token for an agent; they are not run by one. So they belong in whichever
///   session directory holds your own login — the default one unless you keep it
///   elsewhere — and NOT in the manager's directory, which has no identity in it
///   until the third command puts one there.
/// - The third command is the one that was missing altogether. `agent create`
///   prints a token and writes to no session directory, so a recipe that stops
///   after `access grant` leaves a token in the scrollback, a config pointing at
///   an empty directory, and a store that fails authentication for a reason
///   nothing on the machine explains.
pub fn mint_a_manager_token(session_dir: Option<&std::path::Path>) -> String {
    format!(
        "add \"manager\": {{\"session_dir\": \"~/.keyless-pass-manager\"}} to stores.proton — a \
         leading `~` is expanded against your home directory, and the path must not be relative \
         — then put a SECOND agent token in that directory with the editor role. In the session \
         where you are logged in as the ACCOUNT (the default one, unless you keep your own login \
         in a named {session_var}), run `pass-cli agent create <name> --expiration 3m` with NO \
         `--vault`, and then `pass-cli agent access grant <name> --vault-name <VAULT> --role \
         editor` — `--role` defaults to `viewer`, which is exactly why a write fails with \
         NotAllowed. The `--vault` is omitted from the create deliberately: an agent minted with \
         one has a FIXED access set, and every later `access grant` on it answers NotAllowed for \
         every role while `access revoke` answers NotExists — so a create that names the vault \
         cannot be given the editor role afterwards at all. Then log the token it printed into \
         the manager's own directory, which is \
         the step that actually creates that session: `{login}`. The token goes in the \
         environment rather than in `--pat`, so it is not readable from the process table; it is \
         still in your shell history. Keep the reader token viewer-only: it is the one every \
         session gets",
        session_var = crate::store::proton::SESSION_DIR_VAR,
        login = crate::store::proton::login_with_token(session_dir),
    )
}

/// Why Infisical has no manager identity here.
const INFISICAL_HAS_NO_WRITER: &str = "this build writes through no Infisical verb. `infisical secrets set` takes the value as a \
     command-line argument, which is the leak this tool exists to remove — an argument is readable \
     from the process table for as long as the process lives — and the CLI offers no way to pass \
     one on stdin. Set it in the Infisical UI";

/// Why 1Password has no manager identity here yet.
///
/// Unlike Infisical this is a gap rather than a refusal: measured against `op`
/// 2.39.0, `op item create -` reads a JSON item template from stdin, which is
/// exactly the shape a writer needs. It is listed under *Not built yet* in the
/// README; until then the sentence names the vendor's own stdin form so nobody
/// reaches for the assignment form, which puts the value in argv.
const ONEPASSWORD_HAS_NO_WRITER: &str = "this build writes through no 1Password verb yet. Create the item in the 1Password app, \
     or with `op item create --vault <VAULT> -` fed a JSON template on stdin — never with an \
     assignment argument such as `password=<value>`, which is readable from the process table";

/// The [`Manage`] implementation for a store id, or the reason there is none.
///
/// # Errors
///
/// [`ManageError::DaemonHoldsIt`] when a daemon is configured, and
/// [`ManageError::NoIdentity`] when this backend has no writer or none is
/// configured.
pub fn manager(
    config: &Config,
    store: &str,
    reason: &Reason,
) -> Result<Box<dyn Manage>, ManageError> {
    // First, and before any backend is considered. Under a daemon the local
    // backends are deliberately not registered for reads; a write path that
    // stayed open would be the same hole reached by a different verb.
    if config.stores.daemon.enabled {
        return Err(ManageError::DaemonHoldsIt(format!(
            "`stores.daemon.enabled` is set, so the manager identity belongs on the daemon's side \
             of the uid boundary and a local write would reach around it. `keylessd` carries no \
             write operation in this build, so store `{store}` cannot be written from here. Do the \
             write on the machine that holds the vault, or turn the daemon off for it and \
             understand that the reader/manager split is then advisory"
        )));
    }

    match store {
        "proton" => ProtonManager::from_config(config, reason.clone()).map(|m| {
            let boxed: Box<dyn Manage> = Box::new(m);
            boxed
        }),
        "keychain" => Ok(Box::new(KeychainManager::from_config(config))),
        "infisical" => Err(ManageError::NoIdentity {
            store: store.to_owned(),
            detail: INFISICAL_HAS_NO_WRITER.to_owned(),
        }),
        "onepassword" => Err(ManageError::NoIdentity {
            store: store.to_owned(),
            detail: ONEPASSWORD_HAS_NO_WRITER.to_owned(),
        }),
        other => Err(ManageError::NoIdentity {
            store: other.to_owned(),
            detail: "no such store".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests;
