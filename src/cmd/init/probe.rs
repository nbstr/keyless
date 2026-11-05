//! Probing one backend at a time against the config this machine reads.

use super::Finding;
use crate::cmd::status::Mark;
use crate::config::Config;
use crate::store::{self, Invocation};

pub(super) fn probe_one(base: &Config, id: &'static str) -> Finding {
    let config = sole_store(base, id);
    let built = store::build(&config, &Invocation::for_verb("init"));
    let Some(store) = built.registry.stores().first() else {
        return Finding {
            store: id,
            mark: Mark::Off,
            state: "off",
            detail: "this build did not construct the backend".to_owned(),
            next: None,
        };
    };

    match store.health() {
        Ok(()) => Finding {
            store: id,
            mark: Mark::Proven,
            state: "proven",
            detail: proven_detail(id),
            next: None,
        },
        Err(error) => {
            let (mark, state) = match error {
                // Not installed, not logged in, nothing to reach.
                crate::error::StoreError::Unavailable { .. } => (Mark::NotSetUp, "absent"),
                // Reachable in principle, and missing a coordinate only its
                // owner can supply. This is the normal answer for Infisical and
                // Proton on a fresh machine, and it is not a fault.
                crate::error::StoreError::Misconfigured { .. } => (Mark::NotSetUp, "config"),
                crate::error::StoreError::Backend { .. }
                | crate::error::StoreError::Refused { .. } => (Mark::Broken, "broken"),
            };
            Finding {
                store: id,
                mark,
                state,
                detail: error.detail().to_owned(),
                next: Some(setup_step(id)),
            }
        }
    }
}

/// `base` with exactly one backend switched on, and everything else kept.
///
/// The `enabled` flags are the only thing this touches. `secrets`, `policy` and
/// each backend's own settings are the coordinates a health check needs, and a
/// probe that drops them reports on a machine nobody has.
///
/// The daemon is forced off, and that one IS a discard rather than an
/// isolation: an enabled daemon suppresses every local backend whatever their
/// flags say (see [`crate::store::build`]), and this verb's product is which
/// LOCAL backend an unpinned name should use. Leaving it on would make all
/// three rows describe the daemon.
pub(super) fn sole_store(base: &Config, id: &str) -> Config {
    let mut config = base.clone();
    config.stores.daemon.enabled = false;
    config.stores.keychain.enabled = id == "keychain";
    config.stores.infisical.enabled = id == "infisical";
    config.stores.onepassword.enabled = id == "onepassword";
    config.stores.proton.enabled = id == "proton";
    config
}

fn proven_detail(id: &str) -> String {
    match id {
        "keychain" => "the login keychain answered a search".to_owned(),
        "infisical" => "the CLI fetched a non-credential key".to_owned(),
        "onepassword" => "the login can see the pinned vault".to_owned(),
        _ => "the session listed its vaults".to_owned(),
    }
}

/// The one step that moves a backend from "not yet" to usable.
fn setup_step(id: &str) -> String {
    match id {
        "keychain" => "the login keychain must be present and unlocked; \
                       open Keychain Access"
            .to_owned(),
        "infisical" => "`infisical login`, then add \"project_id\" under \
                        `stores.infisical` and an \"env\" on each name"
            .to_owned(),
        // The vault is the coordinate nobody can guess for you, and the
        // account is the one that bites on a machine with two of them.
        "onepassword" => "`op signin`, then set `stores.onepassword.vault` to the ONE vault \
                          this machine may read, and `stores.onepassword.account` if you \
                          have more than one account"
            .to_owned(),
        // The variable is the whole of the instruction. "Log in into a session
        // directory" is followable only by somebody who already knows the
        // directory travels in an environment variable — and every spelling
        // reached for instead is a documented dead end. See
        // `crate::store::proton::scoped_command_template`.
        _ => format!(
            "`{}`, then set `stores.proton.session_dir` to that same directory — \
             the variable is not optional, a bare `pass-cli login` logs into the \
             DEFAULT session and reports success",
            crate::store::proton::scoped_command_template("login")
        ),
    }
}
