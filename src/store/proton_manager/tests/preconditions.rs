use super::{manager, route};
use crate::config::Config;
use crate::secret::Secret;
use crate::store::manage::Manage;
use crate::store::proton::Reason;
use crate::store::proton_manager::ProtonManager;

#[test]
fn an_empty_value_is_refused_rather_than_stored() {
    // The resolver treats an empty item as a misconfiguration, so storing one
    // creates a name that can never resolve and says nothing about why.
    let error = manager()
        .store(
            "X",
            &route(r#"{"vault":"personal","item":"d","field":"password"}"#),
            &Secret::new(String::new()),
        )
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(error.contains("empty"), "{error}");
}

#[test]
fn a_missing_binary_fails_before_anything_is_spawned() {
    let error = manager()
        .store(
            "X",
            &route(r#"{"vault":"personal","item":"d","field":"password"}"#),
            &Secret::new("decoy-value-0001".to_owned()),
        )
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(error.contains("not on PATH"), "{error}");
}

#[test]
fn a_config_with_no_manager_block_yields_no_writer_at_all() {
    let bare: Config =
        serde_json::from_str(r#"{"stores":{"proton":{"session_dir":"/tmp/r"}}}"#).expect("valid");
    assert!(ProtonManager::from_config(&bare, Reason::default()).is_err());

    // And a manager block with no session directory is the same fault, not a
    // silent fallback to the reader's.
    let half: Config =
        serde_json::from_str(r#"{"stores":{"proton":{"session_dir":"/tmp/r","manager":{}}}}"#)
            .expect("valid");
    assert!(ProtonManager::from_config(&half, Reason::default()).is_err());
}
