//! The `pass-cli` invocations a write makes, each scoped to the manager's
//! session.

use std::process::Command;

use super::ProtonManager;
use super::address::Address;
use crate::store::proton::{
    REASON_VAR, SESSION_DIR_VAR, flag_value, remove_ambient_references, set_vendor_switch_offs,
};

impl ProtonManager {
    /// Put the things every child of this manager needs on one command.
    ///
    /// This manager's own analogue of `ProtonStore::scope` and
    /// `daemon::login::scope`: a builder that quietly lacked one of these
    /// would fail as a missing item, or a duplicate title, rather than as a
    /// missing variable.
    ///
    /// - **The ambient filter** runs first, so a caller who exported a
    ///   `pass://` reference cannot have it removed again once the variables
    ///   below are set.
    /// - **The session directory** is the MANAGER's, never the reader's — see
    ///   [`ProtonManager::from_config`].
    /// - **The reason** is required by the vendor and is what the remote audit
    ///   entry is filed under.
    /// - **The two vendor switch-offs**, so a listing or a create writes no
    ///   telemetry row, and asks about no update even if a later release
    ///   stops skipping that check for a child whose stderr is a pipe. See
    ///   [`set_vendor_switch_offs`].
    fn scope<I>(&self, command: &mut Command, ambient: I, reason: String)
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        remove_ambient_references(command, ambient);
        command.env(SESSION_DIR_VAR, &self.session_dir);
        command.env(REASON_VAR, reason);
        set_vendor_switch_offs(command);
    }

    /// Build one `pass-cli item list --vault-name … --output json` invocation.
    ///
    /// Under the MANAGER's session, deliberately: the pre-flight check has to see
    /// what the writer will see. Read as the reader it could miss an item the
    /// editor can see, and then the create would produce the duplicate this check
    /// exists to prevent.
    /// `ambient` is a parameter rather than a call to [`std::env::vars_os`] here
    /// so a test can prove the filtering is **wired in**, not merely that the
    /// filter works when called directly. On the read adapter, testing the filter
    /// on its own left the suite green after its call site was deleted.
    pub(super) fn list_command<I>(&self, vault: &str, ambient: I) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("item");
        command.arg("list");
        // Joined with `=`: a vault whose name starts with `-` is read as a
        // short-flag cluster when it arrives as its own argument. See
        // [`flag_value`].
        flag_value(&mut command, "--vault-name", vault);
        command.arg("--output");
        command.arg("json");
        self.scope(
            &mut command,
            ambient,
            self.reason.for_action("listing", vault),
        );
        command
    }

    /// Build one `pass-cli item create <kind> --vault-name … --from-template -`.
    ///
    /// The template arrives on stdin. `-` is the vendor's own spelling for that,
    /// so this is the documented path rather than a trick.
    pub(super) fn create_command<I>(&self, kind: &str, address: &Address, ambient: I) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("item");
        command.arg("create");
        command.arg(kind);
        flag_value(&mut command, "--vault-name", &address.vault);
        command.arg("--from-template");
        command.arg("-");
        self.scope(
            &mut command,
            ambient,
            self.reason.for_action("creating", &address.item),
        );
        command
    }
}
