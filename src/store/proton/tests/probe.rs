use super::{Fixed, SCOPED, ambient, argv_of, store_from};
use crate::store::Store;
use crate::store::proton::environment::{
    ENCRYPTION_KEY_VAR, KeyProvider, REASON_VAR, SESSION_DIR_VAR, assert_vendor_switch_offs,
    env_value,
};
use crate::store::proton::reason::{REASON_MAX, Reason};
use crate::store::proton::resolve::looks_concealed;
use crate::store::proton::store::ProtonStore;
use crate::store::proton::token::{AgentToken, TOKEN_VAR};
use std::ffi::OsString;
use std::path::Path;

fn command_for(store: &ProtonStore, name: &str) -> std::process::Command {
    store.probe_command(
        Path::new(SCOPED),
        Path::new("/tmp/probe.env"),
        name,
        &[],
        ambient(),
    )
}

fn argv(store: &ProtonStore, name: &str) -> Vec<String> {
    argv_of(&command_for(store, name))
}

/// The variables a built command SETS, as a sorted list of names. A
/// removal — which `get_envs` reports as a `None` value — is not a set.
fn set_variables(command: &std::process::Command) -> Vec<String> {
    let mut names: Vec<String> = command
        .get_envs()
        .filter(|(_, value)| value.is_some())
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn the_session_probe_carries_every_credential_the_read_beside_it_carries() {
    // The probe asks nothing about an item, so carrying the account token
    // reads as unnecessary — and under `KeyProvider::Env` the same login
    // also carries `ENCRYPTION_KEY_VAR`, which is what lets the vendor
    // OPEN the local session store at all. A probe built without it names
    // the `env` provider with nothing for it to read, fails for that
    // reason on every call, and latches every vendor verdict into a
    // session fault for as long as the install runs — while the daemon
    // keeps serving values the account may already have revoked.
    //
    // CONTROL — the change that makes this fail: passing `&[]` as the
    // login, which is what this builder did when it was written. The
    // probe's variable list then loses both credential variables and the
    // assertion below names them.
    let credentials = AgentToken::new(
        Box::new(Fixed),
        [
            (TOKEN_VAR.to_owned(), "AGENT_TOKEN".to_owned()),
            (ENCRYPTION_KEY_VAR.to_owned(), "LOCAL_KEY".to_owned()),
        ]
        .into_iter()
        .collect(),
    );
    let store = store_from("{}")
        .with_agent_token(Some(credentials))
        .with_key_provider(Some(KeyProvider::Env));

    let probe = set_variables(&store.info_probe_command(Path::new(SCOPED), ambient()));
    let read = set_variables(&store.list_command(
        Path::new(SCOPED),
        "personal",
        "DECOY",
        &store.vendor_login().expect("the decoy login resolves"),
        ambient(),
    ));

    for variable in [TOKEN_VAR, ENCRYPTION_KEY_VAR] {
        assert!(
            read.contains(&variable.to_owned()),
            "the read this case compares against does not carry {variable}, so the \
             comparison proves nothing: {read:?}"
        );
        assert!(
            probe.contains(&variable.to_owned()),
            "the session probe runs without {variable}, so under the `env` key provider \
             it cannot open the session it is asking about: {probe:?}"
        );
    }
}

/// The value the child would see for `key`, as the adapter set it.
fn child_env(store: &ProtonStore, name: &str, key: &str) -> Option<String> {
    env_value(&command_for(store, name), key)
}

#[test]
fn the_invocation_uses_run_and_never_the_verb_that_prints_a_value() {
    // `pass-cli item view --field` writes plaintext to stdout. Same rule as
    // Infisical's denied verbs: this adapter must not become the way there.
    //
    // The exact argv, rather than a check per forbidden word: a full match
    // implies every one of them is absent, and it is the same command this
    // adapter has always built — see `set_vendor_switch_offs`, asserted
    // below on the same built command rather than a second one.
    let store = store_from(r#"{"secrets":{"X":{"reference":"pass://V/I/F"}}}"#);
    let command = command_for(&store, "X");
    assert_eq!(
        argv_of(&command),
        vec![
            "pass-cli",
            "run",
            "--env-file=/tmp/probe.env",
            "--no-masking",
            "--",
            "/usr/bin/printenv",
            "KEYLESS_PROBE",
        ]
    );
    assert_vendor_switch_offs(&command);
}

#[test]
fn masking_is_disabled_for_the_probe_only() {
    // Without this the probe reads `<concealed by Proton Pass>` and injects
    // it as though it were the credential.
    let store = store_from("{}");
    assert!(argv(&store, "X").iter().any(|arg| arg == "--no-masking"));
}

#[test]
fn a_concealed_value_is_refused_rather_than_injected() {
    assert!(looks_concealed(b"<concealed by Proton Pass>"));
    assert!(looks_concealed(b"<CONCEALED BY PROTON PASS>"));
    assert!(!looks_concealed(b"decoy-a-perfectly-ordinary-value"));
}

#[test]
fn a_reason_is_set_on_every_read() {
    let store = store_from("{}");
    let reason = child_env(&store, "DECOY", REASON_VAR).expect("every read must carry a reason");
    assert!(!reason.is_empty(), "an empty reason is refused by the API");
    assert!(reason.contains("DECOY"));
}

#[test]
fn every_read_names_the_session_directory_it_runs_under() {
    // The bug this replaces: with nothing exported, `pass-cli` falls back
    // to its shared per-user session. Measured 2026-08-08, that session was
    // the full account and saw two vaults where the scoped agent saw one —
    // so the scoping was bypassed while every name still resolved.
    let store = store_from("{}");
    assert_eq!(
        child_env(&store, "X", SESSION_DIR_VAR).as_deref(),
        Some(SCOPED),
        "the child would inherit whichever identity `pass-cli` was last logged into"
    );
}

#[test]
fn an_ambient_reference_is_taken_out_of_the_probes_environment() {
    // Measured 2026-08-08: `pass-cli run` resolves every `pass://` in the
    // inherited environment, so one unrelated variable made the probe read
    // a second item from the vault — recorded off-machine, permanently —
    // and failed the whole lookup when that item did not resolve.
    //
    // Built through `probe_command`, not by calling the filter directly.
    // The direct call was the first version of this test, and deleting the
    // call site left it green — a test of a function nothing has to use.
    let store = store_from("{}");
    // `get_envs` yields `None` as the value for a removal.
    let removed: Vec<String> = command_for(&store, "X")
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();

    assert!(removed.contains(&"A_REFERENCE".to_owned()), "{removed:?}");
    assert!(
        removed.contains(&"EMBEDDED".to_owned()),
        "a reference inside a longer value is still resolved by the CLI: {removed:?}"
    );
    for kept in ["PLAIN", "LOOKALIKE", "EMPTY"] {
        assert!(
            !removed.contains(&kept.to_owned()),
            "`{kept}` was dropped from the probe's environment: {removed:?}"
        );
    }
}

#[test]
fn a_store_with_no_session_directory_degrades_and_says_how_to_fix_it() {
    // Not a refusal to run: `resolve` returning `Unavailable` is exactly
    // what an unreachable backend returns, and `run` spawns the child on
    // both. See `never_block.rs` for the property itself.
    let store = store_from(r#"{"secrets":{"X":{"reference":"pass://S/I/F"}}}"#);
    let error = store
        .resolve("X")
        .expect_err("an unscoped lookup must not reach the ambient session");
    let message = error.to_string();
    assert!(message.contains("session_dir"), "{message}");
    assert!(
        store.health().is_err(),
        "`doctor` must say it before a run does"
    );
}

#[test]
fn a_configured_session_directory_is_taken_verbatim_and_stops_the_complaint() {
    // The negative control for the two tests above: without it, both could
    // pass on a store that can never be configured at all.
    //
    // The binary is deliberately absent, so the remaining health failure is
    // about the binary. That is what proves the session complaint stopped
    // rather than merely being outranked by it.
    let store = store_from(
        r#"{"stores":{"proton":{"session_dir":"/tmp/kl-agent",
                                "binary":"/nonexistent/keyless-test/pass-cli"}}}"#,
    );
    assert_eq!(
        store.session_dir().expect("configured"),
        Path::new("/tmp/kl-agent")
    );
    let message = store
        .health()
        .expect_err("the binary is absent")
        .to_string();
    assert!(
        !message.contains("session_dir"),
        "a configured session was still reported as missing: {message}"
    );
}

#[test]
fn a_read_never_uses_the_manager_identity_even_when_one_is_configured() {
    // The reader/manager split, from the reader's side. `ProtonStore` must not
    // read the `manager` block at all: the tempting mistake is a "helpful"
    // fallback that prefers the manager when one is present, or falls back to
    // it when the reader's directory is missing. Either turns every one of ~20
    // sessions into an editor, silently, because a session that can write also
    // resolves every name successfully.
    let store = store_from(
        r#"{"stores":{"proton":{"session_dir":"/tmp/keyless-reader",
                                "manager":{"session_dir":"/tmp/keyless-manager"}}}}"#,
    );
    assert_eq!(
        store.session_dir().expect("the reader is configured"),
        Path::new("/tmp/keyless-reader"),
        "a read resolved as the manager identity"
    );

    // And with no reader configured, the manager is NOT borrowed to stand in
    // for it: the lookup degrades and says to set `session_dir`.
    let manager_only: crate::config::Config = serde_json::from_str(
        r#"{"stores":{"proton":{"manager":{"session_dir":"/tmp/keyless-manager"}}}}"#,
    )
    .expect("valid config");
    let store = ProtonStore::from_config(&manager_only, Reason::default());
    let message = store
        .session_dir()
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(message.contains("session_dir"), "{message}");
    assert!(
        !message.contains("keyless-manager"),
        "the manager's directory was used as a reader fallback: {message}"
    );
}

#[test]
fn the_reason_names_the_command_but_carries_no_argument_value() {
    // An argument vector is where every shape this tool exists to remove
    // ends up. The reason is assembled before anything has resolved, so
    // there is nothing to redact it with, and it is then sent to a vendor
    // and kept. An argument value must never be in it — this is the test
    // that says so.
    let leaked = "decoy-Zx91-would-be-a-leak-0042";
    let argv: Vec<OsString> = ["/usr/local/bin/psql", "--dbname", leaked]
        .iter()
        .map(OsString::from)
        .collect();
    let reason = Reason::for_run(&argv).for_name("DATABASE_URL");

    assert!(!reason.contains(leaked), "the reason leaked an argument");
    assert!(!reason.contains("--dbname"));
    assert!(reason.contains("psql"), "the reason must still be useful");
    assert!(reason.contains("2 args"));
    assert!(reason.contains("DATABASE_URL"));
}

#[test]
fn a_reason_is_never_empty_and_never_over_the_cap() {
    // The cap is the vendor's; an over-long reason is rejected, and a
    // rejected read is a degraded run for a reason that is entirely ours.
    let long_name = "N".repeat(REASON_MAX * 2);
    let reason = Reason::default().for_name(&long_name);
    assert!(reason.len() <= REASON_MAX, "length was {}", reason.len());
    assert!(!reason.trim().is_empty());

    // A multi-byte name must not be cut mid-character.
    let wide = "é".repeat(REASON_MAX);
    let reason = Reason::default().for_name(&wide);
    assert!(reason.len() <= REASON_MAX);
    assert!(std::str::from_utf8(reason.as_bytes()).is_ok());

    // An empty argv still produces something.
    assert!(!Reason::for_run(&[]).for_name("X").trim().is_empty());
}
