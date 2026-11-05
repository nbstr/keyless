//! Which backends a config registers, and what an operator is told about the
//! ones it does not. Both halves of the rule [`build`](super::build) documents.

use std::collections::BTreeMap;

use super::{Invocation, Store, daemon, infisical, keychain, onepassword, proton};
use crate::config::Config;

/// The daemon, and nothing local beside it: drops every per-name pin and any
/// `stores.default` that names a suppressed backend, and says so.
pub(super) fn register_the_daemon_alone(
    config: &Config,
    stores: &mut Vec<Box<dyn Store>>,
    routes: &mut BTreeMap<String, String>,
    default_store: &mut Option<String>,
    warnings: &mut Vec<String>,
    notes: &mut Vec<String>,
) {
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
        // `keylessd` carries all three adapters, so every one of these
        // names is moved rather than lost — but they are moved to three
        // different places and the remedies do not collapse into one: an
        // Infisical name needs an "env" the daemon has no other way to
        // learn, a 1Password name needs the vault and a service account
        // scoped to it, and a Proton name needs a session directory the
        // daemon owns, because there is no ambient login for it to inherit.
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
                "declare them under `secrets` in `keylessd.json` with their \"vault\", \
                 \"item\" and \"field\", enable `stores.proton` there with a \
                 `session_dir` the daemon owns, and log that session in with a \
                 viewer-role agent token"
                    .to_owned()
            } else {
                "declare the Proton ones under `secrets` in `keylessd.json` with their \
                 \"vault\", \"item\" and \"field\", enable `stores.proton` there with a \
                 `session_dir` the daemon owns, and log that session in with a \
                 viewer-role agent token"
                    .to_owned()
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
        *default_store = None;
    }
}

/// Every local backend the config enables, in search order.
pub(super) fn register_local_backends(
    config: &Config,
    invocation: &Invocation,
    stores: &mut Vec<Box<dyn Store>>,
    warnings: &mut Vec<String>,
) {
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
