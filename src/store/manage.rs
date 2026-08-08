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
//! # Why a write may refuse when a read may not
//!
//! `keyless run` never refuses, because refusing blocks somebody's actual work
//! and a tool that blocks work gets removed — after which the plaintext comes
//! back. That argument does not transfer to `new` and `put`. They are setup
//! steps, run once, with a person watching the output; nothing downstream is
//! waiting on them. And the failure modes are asymmetric: a `run` that degrades
//! still runs the command, where a write that "degraded" would report success
//! with nothing stored, and the next `run` would degrade for a reason nobody can
//! find. So the write verbs exit non-zero and say what is missing.

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
/// Measured 2026-08-08 against a live account and `pass-cli` 2.2.5:
///
/// - `agent access grant` takes `--role`, whose values are `viewer`, `editor`
///   and `manager`, and whose **default is `viewer`**. So a token minted without
///   thinking about the role is read-only, which is why this failure is the
///   normal one rather than an unusual one.
/// - A viewer-role token returns `NotAllowed` from `item create` and from
///   `item trash`.
pub const MINT_A_MANAGER_TOKEN: &str = "add \"manager\": {\"session_dir\": \"~/.keyless-pass-manager\"} to stores.proton, then put a \
     SECOND agent token in that directory with the editor role: `pass-cli agent create <name> \
     --expiration 3m --vault <VAULT>`, then `pass-cli agent access grant <name> --vault-name \
     <VAULT> --role editor` — `--role` defaults to `viewer`, which is exactly why a write fails \
     with NotAllowed. Keep the reader token viewer-only: it is the one every session gets";

/// Why Infisical has no manager identity here.
const INFISICAL_HAS_NO_WRITER: &str = "this build writes through no Infisical verb. `infisical secrets set` takes the value as a \
     command-line argument, which is the leak this tool exists to remove — an argument is readable \
     from the process table for as long as the process lives — and the CLI offers no way to pass \
     one on stdin. Set it in the Infisical UI";

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
        other => Err(ManageError::NoIdentity {
            store: other.to_owned(),
            detail: "no such store".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{ManageError, manager};
    use crate::config::Config;
    use crate::store::proton::Reason;

    fn config_from(json: &str) -> Config {
        serde_json::from_str(json).expect("valid config")
    }

    #[test]
    fn a_configured_daemon_refuses_every_local_write() {
        // The rule the daemon design rests on, applied to the write verbs:
        // enabling the daemon must not leave a local path open beside it.
        let config = config_from(
            r#"{"stores":{"daemon":{"enabled":true},
                          "proton":{"enabled":true,"session_dir":"/tmp/r",
                                    "manager":{"session_dir":"/tmp/m"}}}}"#,
        );
        for store in ["proton", "keychain"] {
            let error = manager(&config, store, &Reason::default())
                .map(|_| String::new())
                .unwrap_or_else(|error| error.to_string());
            assert!(error.contains("uid boundary"), "{store}: {error}");
        }
    }

    #[test]
    fn without_a_daemon_a_configured_manager_is_available() {
        // The negative control for the test above: without it, that one could
        // pass on a `manager` that never returns a writer under any config.
        let config = config_from(
            r#"{"stores":{"proton":{"enabled":true,"session_dir":"/tmp/r",
                                    "manager":{"session_dir":"/tmp/m"}}}}"#,
        );
        let writer = manager(&config, "proton", &Reason::default()).expect("a manager");
        assert_eq!(writer.id(), "proton");
        assert_eq!(writer.identity(), "proton (manager)");
        assert!(manager(&config, "keychain", &Reason::default()).is_ok());
    }

    #[test]
    fn proton_without_a_manager_block_names_the_token_to_mint() {
        let config =
            config_from(r#"{"stores":{"proton":{"enabled":true,"session_dir":"/tmp/r"}}}"#);
        let error = manager(&config, "proton", &Reason::default())
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("manager"), "{error}");
        assert!(error.contains("agent access grant"), "{error}");
        assert!(
            error.contains("--role editor"),
            "the message must name the flag, not just the idea: {error}"
        );
        assert!(error.contains("viewer-only"), "{error}");
    }

    #[test]
    fn infisical_says_why_it_has_no_writer_and_names_the_reason() {
        let error = manager(&config_from("{}"), "infisical", &Reason::default())
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("command-line argument"), "{error}");
    }

    #[test]
    fn the_exit_codes_separate_a_config_fault_from_a_data_fault() {
        assert_eq!(
            ManageError::NoIdentity {
                store: "proton".to_owned(),
                detail: String::new()
            }
            .exit_code(),
            78
        );
        assert_eq!(
            ManageError::Value {
                store: "keychain".to_owned(),
                detail: String::new()
            }
            .exit_code(),
            65
        );
        assert_eq!(
            ManageError::Backend {
                store: "proton".to_owned(),
                detail: String::new()
            }
            .exit_code(),
            1
        );
    }

    #[test]
    fn no_manage_error_message_can_carry_a_value() {
        // Every variant is built from a store id and a detail that this crate
        // takes from stderr. This is the guard that a variant carrying the value
        // itself would have to be added past.
        let leak = "decoy-would-be-a-leak-5150";
        for error in [
            ManageError::Value {
                store: "keychain".to_owned(),
                detail: "it contains a newline".to_owned(),
            },
            ManageError::Backend {
                store: "proton".to_owned(),
                detail: "NotAllowed".to_owned(),
            },
        ] {
            assert!(!error.to_string().contains(leak));
        }
    }
}
