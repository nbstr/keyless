use super::failing::remedy;
use crate::cmd::doctor::tests::loaded;
use crate::error::StoreError;

/// A `Unavailable` from a store, for the rows that are about the ACTION.
pub(super) fn unavailable(store: &str) -> StoreError {
    StoreError::Unavailable {
        store: store.to_owned(),
        detail: "the session cannot be used".to_owned(),
    }
}

#[test]
fn the_proton_next_action_names_the_variable_that_selects_the_session() {
    // The action column is a separate sentence from the adapter's detail,
    // and it is the one a reader copies. `pass-cli login` on its own logs
    // into the DEFAULT session — on macOS `~/Library/Application
    // Support/proton-pass-cli/.session` — which on a machine with a
    // full-account login answers `Already authenticated` and leaves the
    // configured session exactly as broken as it was. That answer is true,
    // it is about a different session, and it cost a day on 2026-08-10.
    let load = loaded(
        r#"{"stores":{"proton":{"enabled":true,"session_dir":"/tmp/keyless-doctor-agent"}}}"#,
    );
    let action = remedy(&load.config, "proton", &unavailable("proton"));
    assert!(
        action.contains("PROTON_PASS_SESSION_DIR=/tmp/keyless-doctor-agent pass-cli login"),
        "the next action did not name this machine's session directory: {action}"
    );
}

#[test]
fn the_proton_next_action_with_no_session_directory_asks_for_one_first() {
    // There is no directory to name, so the advice must not invent one. It
    // still says how the directory travels, because that is the half nobody
    // guesses.
    let load = loaded(r#"{"stores":{"proton":{"enabled":true}}}"#);
    let action = remedy(&load.config, "proton", &unavailable("proton"));
    assert!(action.contains("stores.proton.session_dir"), "{action}");
    assert!(action.contains("PROTON_PASS_SESSION_DIR"), "{action}");
}
