use super::ProtonManager;
use super::address::Address;
use crate::config::{Config, SecretRoute};
use crate::store::proton::Reason;

mod address;
mod command;
mod preconditions;
mod refusal;
mod template;

/// The reader's session directory, and the manager's. Two literals, written
/// out by hand: a test that compares the adapter's export against the
/// adapter's own field proves nothing.
const READER: &str = "/tmp/keyless-tests-reader-session";
const MANAGER: &str = "/tmp/keyless-tests-manager-session";

fn config() -> Config {
    serde_json::from_str(&format!(
        r#"{{"stores":{{"proton":{{"enabled":true,"session_dir":"{READER}",
             "manager":{{"session_dir":"{MANAGER}"}},
             "binary":"/nonexistent/keyless-test/pass-cli"}}}}}}"#
    ))
    .expect("valid config")
}

fn manager() -> ProtonManager {
    ProtonManager::from_config(&config(), Reason::for_verb("new")).expect("a manager")
}

fn route(json: &str) -> SecretRoute {
    serde_json::from_str(json).expect("valid route")
}

fn address() -> Address {
    Address {
        vault: "personal".to_owned(),
        item: "decoy".to_owned(),
        field: "api key".to_owned(),
    }
}

/// An ambient environment written out by hand, independent of this process's.
fn ambient() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    [
        ("PLAIN", "not-a-reference"),
        ("A_REFERENCE", "pass://share/item/password"),
        ("EMBEDDED", "prefix pass://share/item/password suffix"),
        ("LOOKALIKE", "passx://share/item/password"),
    ]
    .into_iter()
    .map(|(key, value)| {
        (
            std::ffi::OsString::from(key),
            std::ffi::OsString::from(value),
        )
    })
    .collect()
}
