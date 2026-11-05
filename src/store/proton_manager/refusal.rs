//! What a failed write says, and when the token's role is named as the cause.

use super::ProtonManager;
use crate::store::exec::{self, CaptureError, summarise};
use crate::store::manage::{Manage, ManageError, mint_a_manager_token};

/// Substrings the vendor uses when the token's role is the problem.
///
/// Measured 2026-08-08 against a live account and `pass-cli` 2.2.5. A viewer-role
/// token answers:
///
/// ```text
/// Error: Error creating login item
///
/// Caused by:
///     Could not perform operation. Reason: NotAllowed
/// ```
///
/// **`NotAllowed` is on the `Caused by:` line, not the first one**, which is why
/// this adapter reads the vendor's whole stderr through
/// [`crate::store::exec::summarise`]. Quoting only the first line reported the
/// refusal as `Error creating login item` — a sentence that names no cause — and
/// the guidance below never fired. That was a live failure, not a hypothetical.
///
/// Matched case-insensitively and in several spellings, because the point is to
/// attach the fix to the failure.
const ROLE_REFUSALS: &[&str] = &["notallowed", "not allowed", "permission", "forbidden"];

/// Whether a create failure the vendor did not explain is worth blaming on the role.
///
/// Yes, and it has to be said as a likelihood rather than a fact. `--role` on
/// `pass-cli agent access grant` defaults to `viewer`, so an unexplained create
/// failure is far more often a read-only token than anything else — but asserting
/// it would be wrong the day the vault is full or the network drops, and a
/// confidently wrong diagnosis costs more than an honest guess.
///
/// It names the FLAG and not a command line. The command that sets the role is
/// part of the recipe appended right after this sentence, where it is spelled
/// once, in full, with the session it runs in — see
/// [`crate::store::manage::mint_a_manager_token`]. Half a command here would be
/// a second thing to keep correct, and the half that gets dropped is always the
/// session.
const UNEXPLAINED_CREATE_HINT: &str = "the vendor did not say why. By far the most common cause is the token's ROLE: `--role` \
     defaults to `viewer` when an agent is granted access to a vault, and a viewer cannot create \
     an item";

impl ProtonManager {
    pub(super) fn unavailable(&self, error: &CaptureError) -> ManageError {
        match exec::unavailable(self.id(), &self.binary, error) {
            // Every variant collapses to the same write-side error: whether the
            // binary was missing, the vendor refused, or the request was
            // underspecified, the caller's fact is that nothing was written and
            // here is why. Matched exhaustively rather than with `_` so a new
            // variant is a compile error to be considered, not a silent join.
            crate::error::StoreError::Unavailable { store, detail }
            | crate::error::StoreError::Backend { store, detail }
            | crate::error::StoreError::Misconfigured { store, detail }
            | crate::error::StoreError::Refused { store, detail } => {
                ManageError::Unavailable { store, detail }
            }
        }
    }

    /// A refusal, with the role fix attached.
    ///
    /// `create_failed` says whether this was the create itself, rather than the
    /// listing before it. On a create the role guidance is always attached — as a
    /// stated fact when the vendor named `NotAllowed`, and as the likely cause when
    /// it named nothing. On a listing failure it is not: a viewer can list, so a
    /// listing that failed is a different fault and blaming the role would send the
    /// reader somewhere useless.
    pub(super) fn refused(&self, stderr: &[u8], context: &str, create_failed: bool) -> ManageError {
        let vendor = summarise(stderr);
        let lowered = vendor.to_ascii_lowercase();
        let named_the_role = ROLE_REFUSALS.iter().any(|marker| lowered.contains(marker));

        let detail = if named_the_role {
            format!(
                "{context}: {vendor}. That is the token's ROLE, not the request: an agent token \
                 with viewer access cannot create or trash an item. {}",
                mint_a_manager_token(Some(&self.session_dir))
            )
        } else if create_failed {
            format!(
                "{context}: {vendor}. {UNEXPLAINED_CREATE_HINT}. {}",
                mint_a_manager_token(Some(&self.session_dir))
            )
        } else {
            format!("{context}: {vendor}")
        };
        ManageError::Backend {
            store: self.id().to_owned(),
            detail,
        }
    }
}
