//! A network store that is absent, broken or hung still lets the command run.

mod stores_support;
mod support;

use std::time::{Duration, Instant};

use keyless::State;
use keyless::store::proton::Reason;

use support::{
    Backend, PROTON_DECOY, SCOPED_SESSION_DIR, run_with, scratch, stub_infisical, stub_pass_cli,
    witness, witnessed,
};

use stores_support::{PROTON_REFERENCE, infisical_config, proton_config, registry_from};

// ---------------------------------------------------------------------------
// Property: Infisical cannot stop the command.
// ---------------------------------------------------------------------------

#[test]
fn an_absent_infisical_binary_still_spawns_the_child() {
    // A machine where the CLI was never installed, or is not on this process's
    // PATH — which is not the same PATH an interactive shell has.
    let dir = scratch("infisical-absent");
    let marker = dir.join("witness");
    let registry = registry_from(
        &infisical_config(&dir.join("there-is-no-infisical-here")),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 42), &[]);

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "the environment was modified"
    );
    assert_eq!(
        outcome.exit_code, 42,
        "the child's exit code must come back"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("DEGRADED"), "no banner was printed: {notes}");
    assert!(notes.contains("DECOY"), "the banner must name the secret");
}

#[test]
fn an_infisical_that_never_answers_still_spawns_the_child() {
    // The failure a local store cannot have: a connection accepted and then
    // left open forever. Without a deadline this test does not fail, it hangs
    // — so the elapsed assertion is what turns a lost timeout into a clean red.
    let dir = scratch("infisical-hangs");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Hangs);
    // Its own config, not the shared builder: here the deadline is the SUBJECT
    // — the assertion below quotes it — and a deadline under test is a
    // different thing from a bound on a test.
    let registry = registry_from(
        &format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "infisical":{{"enabled":true,"binary":"{}","timeout_ms":300}}}},
                "secrets":{{"DECOY":{{"env":"dev"}}}}}}"#,
            stub.display()
        ),
        &Reason::default(),
    );

    let started = Instant::now();
    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 17), &[]);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "the lookup was not bounded: waited {elapsed:?}"
    );
    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 17);
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("no answer within 300 ms"),
        "the caller must be told it timed out: {notes}"
    );
}

#[test]
fn an_infisical_that_fails_its_own_lookup_still_spawns_the_child() {
    let dir = scratch("infisical-own-failure");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::OwnFailure);
    let registry = registry_from(&infisical_config(&stub), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 9), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 9);
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("infisical init"),
        "the backend's own diagnosis must reach the caller: {notes}"
    );
}

// ---------------------------------------------------------------------------
// Property: Proton Pass cannot stop the command.
// ---------------------------------------------------------------------------

#[test]
fn an_unset_session_directory_degrades_the_name_and_still_spawns_the_child() {
    // The scoping control has no safe default, so an unset `session_dir` stops
    // the LOOKUP. It must not stop the COMMAND: refusing to resolve a name and
    // refusing to run are different things, and only the first is ever
    // allowed. Without this, a correct-looking safety improvement would have
    // broken the one invariant the whole tool rests on.
    let dir = scratch("proton-unscoped");
    let marker = dir.join("witness");
    let stub = stub_pass_cli(&dir, &Backend::Injects(PROTON_DECOY));
    let registry = registry_from(
        &format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "proton":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}},
                "secrets":{{"DECOY":{{"reference":"{PROTON_REFERENCE}"}}}}}}"#,
            stub.display()
        ),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 17), &[]);

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "an unscoped value was injected"
    );
    assert_eq!(
        outcome.exit_code, 17,
        "the child's exit code must come back"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("session_dir"),
        "the fix must be named: {notes}"
    );

    // And nothing was spawned at all, so no remote audit entry was written for
    // a read whose identity nobody chose.
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "an unscoped lookup reached the vendor CLI anyway"
    );
}

#[test]
fn an_absent_pass_cli_binary_still_spawns_the_child() {
    // A user who declares a Proton-backed name before installing the CLI — or
    // whose PATH here is not the PATH an interactive shell has — must still be
    // able to work.
    let dir = scratch("proton-absent");
    let marker = dir.join("witness");
    let registry = registry_from(
        &proton_config(&dir.join("there-is-no-pass-cli-here")),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 31), &[]);

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "the environment was modified"
    );
    assert_eq!(
        outcome.exit_code, 31,
        "the child's exit code must come back"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("DEGRADED"));
    assert!(notes.contains("DECOY"));
}

#[test]
fn a_pass_cli_that_never_answers_still_spawns_the_child() {
    let dir = scratch("proton-hangs");
    let marker = dir.join("witness");
    let stub = stub_pass_cli(&dir, &Backend::Hangs);
    // Its own config, for the same reason as the Infisical hang above: the
    // deadline is the subject here, not a bound.
    let registry = registry_from(
        &format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "proton":{{"enabled":true,"binary":"{}",
                            "session_dir":"{SCOPED_SESSION_DIR}","timeout_ms":300}}}},
                "secrets":{{"DECOY":{{"reference":"{PROTON_REFERENCE}"}}}}}}"#,
            stub.display()
        ),
        &Reason::default(),
    );

    let started = Instant::now();
    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 23), &[]);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "the lookup was not bounded: waited {elapsed:?}"
    );
    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 23);
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("no answer within 300 ms"), "{notes}");
}
