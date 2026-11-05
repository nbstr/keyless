//! The row for a live store that could not answer, and what to type next.

use super::StoreRow;
use crate::cmd::status::Mark;
use crate::config::Config;
use crate::error::StoreError;

/// A live store that could not answer.
///
/// The three [`StoreError`] variants already separate the three places a reader
/// has to be sent — the install, their own config file, and the store itself —
/// so the mark and the action are read off the variant rather than sniffed out
/// of a message.
pub(super) fn failing_row(config: &Config, id: &str, error: &StoreError) -> StoreRow {
    let (mark, state) = match error {
        // Not there yet: no binary, no login, no network. A step nobody took,
        // which is amber rather than red — but still a problem, because a store
        // that was ENABLED and cannot answer is a store that cannot serve.
        StoreError::Unavailable { .. } => (Mark::NotSetUp, "absent"),
        // One line of the config file, and nothing was contacted.
        StoreError::Misconfigured { .. } => (Mark::NotSetUp, "config"),
        // Installed, reached, and saying no.
        StoreError::Backend { .. } | StoreError::Refused { .. } => (Mark::Broken, "broken"),
    };
    StoreRow {
        id: id.to_owned(),
        mark,
        state,
        // The vendor's own words, so a reader knows which of the many ways this
        // backend fails they are looking at. Never its stdout; see
        // `crate::error`.
        detail: error.detail().to_owned(),
        action: Some(remedy(config, id, error)),
    }
}

/// What to type next, per backend and per kind of failure.
///
/// Written here rather than inside each adapter because it is advice about this
/// MACHINE, not about the lookup that failed — and because a `Misconfigured`
/// error already carries the config fix in its own detail, so repeating it would
/// give a reader two sentences to reconcile.
pub(super) fn remedy(config: &Config, id: &str, error: &StoreError) -> String {
    if matches!(error, StoreError::Misconfigured { .. }) {
        return format!(
            "the fix is one line of {}'s config file, not anything in the store",
            crate::NAME
        );
    }
    match id {
        "keychain" => "unlock the login keychain in Keychain Access, \
                       or check `stores.keychain.binary`"
            .to_owned(),
        "infisical" => "`infisical login`, then check `stores.infisical.project_id` \
                        and the `env` on each name"
            .to_owned(),
        // The command with THIS machine's session directory already in it. The
        // sentence it replaces — "`pass-cli login` into
        // `stores.proton.session_dir`" — is followable only by someone who
        // already knows that the directory travels in an environment variable;
        // typed literally it logs into the DEFAULT session, which on a machine
        // with a full-account login answers `Already authenticated` and leaves
        // the broken session untouched. That answer cost a day.
        "proton" => match &config.stores.proton.session_dir {
            Some(dir) => format!(
                "`{}`, or re-issue the agent token — the variable is not optional, \
                 a bare `pass-cli login` logs into the DEFAULT session",
                crate::store::proton::login_into(dir.as_path())
            ),
            None => format!(
                "set `stores.proton.session_dir`, then log in with `{}`",
                crate::store::proton::scoped_command_template("login")
            ),
        },
        "daemon" => "start `keylessd`, or set `stores.daemon.enabled` to false so \
                     this machine reads its own stores"
            .to_owned(),
        // `op signin` is the vendor's own bootstrap and is idempotent; the
        // account is the half that goes wrong on a machine with two of them.
        "onepassword" => "`op signin`, then check `stores.onepassword.vault` names a vault \
                          that login can see, and `stores.onepassword.account` when this \
                          machine has more than one account"
            .to_owned(),
        other => format!("check the settings for `stores.{other}`"),
    }
}
