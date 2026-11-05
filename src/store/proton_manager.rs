//! Writing to Proton Pass, as the editor-role identity.
//!
//! A separate type from [`ProtonStore`](crate::store::proton::ProtonStore), in a
//! separate file, holding a separate session directory. That separation is the
//! mechanism, not decoration: nothing constructs this type except
//! [`crate::store::manage::manager`], a
//! [`crate::store::Registry`] cannot hold it, and `ProtonStore` never reads the
//! `manager` block — so there is no expression in this crate by which a `run`
//! acts as the editor.
//!
//! # The value never touches a command line
//!
//! `pass-cli item create login --password <VALUE>` exists and is not used.
//! `item create <type> --from-template -` reads a JSON template **from stdin**,
//! which is the whole reason a write verb is buildable here at all: an argument
//! is readable from the process table for as long as the child lives, which is
//! the CLI-flag shape this tool exists to remove.
//!
//! Two consequences of that choice, both stated rather than left to be found:
//!
//! - **`item update` is not used, so this creates and never overwrites.**
//!   `item update` takes `--field name=value` and offers no template on stdin, so
//!   updating an existing item would mean putting the value in argv. A name whose
//!   item already exists is therefore refused, with the reason. Rotation through
//!   this verb is not available until the vendor accepts an update on stdin.
//! - **A duplicate title would break reads, so it is checked first.** Two live
//!   items with one title make the name form ambiguous, and the resolver refuses
//!   an ambiguous title rather than guessing. Creating one is how a write verb
//!   silently breaks a working `run`, so the pre-flight listing is load-bearing
//!   and not politeness.
//!
//! # What the vendor's templates actually look like
//!
//! Measured 2026-08-08 against `pass-cli` 2.2.5, via `--get-template`, which
//! prints a shape and no values:
//!
//! ```text
//! login:  {"title":"","username":null,"email":null,"password":null,"totp_uri":null,"urls":[]}
//! custom: {"title":"","note":"","sections":[{"section_name":"…",
//!           "fields":[{"field_name":"…","field_type":"text|hidden|totp|timestamp","value":""}]}]}
//! ```
//!
//! So a name whose `field` is one of the login item's own fields becomes a login
//! item, and anything else becomes a custom item with one hidden field of that
//! name. `hidden` rather than `text` because the field holds a credential, and
//! Proton's own UI conceals a hidden field.

mod address;
mod command;
mod refusal;
mod template;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::time::Duration;

use crate::config::{Config, SecretRoute};
use crate::secret::Secret;
use crate::store::exec::capture_with_input;
use crate::store::manage::{Manage, ManageError, Stored, mint_a_manager_token};
use crate::store::proton::{REFERENCE_SCHEME, Reason, relative_session_dir, resolve_executable};
use template::{Kind, Template};

/// Writes items to Proton Pass through `pass-cli item create`.
pub struct ProtonManager {
    binary: PathBuf,
    /// `PROTON_PASS_SESSION_DIR` for every child. The **manager's**, never the
    /// reader's.
    session_dir: PathBuf,
    timeout: Duration,
    reason: Reason,
}

impl ProtonManager {
    /// Build from a parsed config, or say what has to be minted.
    ///
    /// # Errors
    ///
    /// [`ManageError::NoIdentity`] when `stores.proton.manager.session_dir` is
    /// absent. There is deliberately no fallback to the reader's session
    /// directory: a viewer token cannot write, so falling back would turn a
    /// legible "mint an editor token" into the vendor's `NotAllowed` — and if the
    /// reader token were ever granted write access, the fallback would silently
    /// undo the whole split.
    ///
    /// The same variant when that directory is RELATIVE. A read degrades on this
    /// and still runs the command; a write refuses, which is the asymmetry
    /// [`crate::store::manage`] documents — a write that "degraded" would report
    /// success with nothing stored, and here it would store into a session
    /// directory that depends on where the operator was standing.
    pub fn from_config(config: &Config, reason: Reason) -> Result<Self, ManageError> {
        let settings = &config.stores.proton;
        let manager = settings.manager.as_ref().and_then(|manager| {
            manager
                .session_dir
                .as_deref()
                .map(|dir| (manager, dir.to_path_buf()))
        });

        let Some((manager, session_dir)) = manager else {
            return Err(ManageError::NoIdentity {
                store: "proton".to_owned(),
                detail: mint_a_manager_token(None),
            });
        };

        if !session_dir.is_absolute() {
            return Err(ManageError::NoIdentity {
                store: "proton".to_owned(),
                detail: relative_session_dir(
                    "stores.proton.manager.session_dir",
                    session_dir.as_path(),
                ),
            });
        }

        Ok(ProtonManager {
            binary: settings.binary.to_path_buf(),
            session_dir,
            timeout: crate::config::bounded_timeout(manager.timeout_ms),
            reason,
        })
    }
}

impl Manage for ProtonManager {
    fn id(&self) -> &str {
        "proton"
    }

    fn store(
        &self,
        name: &str,
        route: &SecretRoute,
        value: &Secret,
    ) -> Result<Stored, ManageError> {
        let address = Self::address(name, route)?;

        if value.is_empty() {
            return Err(ManageError::Value {
                store: self.id().to_owned(),
                detail: "the value is empty; the resolver treats an empty item as a \
                         misconfiguration rather than a credential, so this would never resolve"
                    .to_owned(),
            });
        }

        if resolve_executable(&self.binary).is_none() {
            return Err(ManageError::Unavailable {
                store: self.id().to_owned(),
                detail: format!(
                    "`{}` is not on PATH or is not executable",
                    self.binary.display()
                ),
            });
        }

        self.refuse_a_duplicate_title(&address)?;

        let kind = Kind::for_field(&address.field);
        let template = Template::build(kind, &address, value)?;
        let captured = capture_with_input(
            self.create_command(kind.as_str(), &address, std::env::vars_os()),
            self.timeout,
            &template.0,
        )
        .map_err(|error| self.unavailable(&error))?;

        if !captured.status.success() {
            return Err(self.refused(
                &captured.stderr,
                &format!(
                    "cannot create `{}` in vault `{}`",
                    address.item, address.vault
                ),
                true,
            ));
        }

        // Deliberately not read: `item create` echoes the item it made, and this
        // build does not need any of it. The reference a config entry resolves is
        // rebuilt from a fresh listing on every lookup anyway, because a share id
        // belongs to one session.
        Ok(Stored {
            location: format!(
                "{REFERENCE_SCHEME}{}/{}/{} ({} item)",
                address.vault,
                address.item,
                address.field,
                kind.as_str()
            ),
        })
    }
}
