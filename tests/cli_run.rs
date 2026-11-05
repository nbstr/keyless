mod cli_support;
mod support;

use cli_support::{config_with_stub, keyless, line_for, stderr_of, stdout_of};
use support::{Backend, DECOY_VALUE, INFISICAL_DECOY, Stub, scratch, stub_infisical};

// ---------------------------------------------------------------------------
// The happy path, end to end.
// ---------------------------------------------------------------------------

#[test]
fn a_child_that_echoes_the_secret_prints_the_mask_instead() {
    let dir = scratch("e2e-masked");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let audit = dir.join("audit.jsonl");

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &audit.display().to_string(),
        "run",
        "-s",
        "DECOY",
        "--",
        "/bin/sh",
        "-c",
        "echo \"$DECOY\"",
    ]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(stdout_of(&output), "[keyless:DECOY]\n");
    assert!(!stdout_of(&output).contains(DECOY_VALUE));
    assert_eq!(stderr_of(&output), "", "a successful run is silent");
}

#[test]
fn a_value_from_a_network_store_is_masked_exactly_like_a_local_one() {
    // The single property that decided the Infisical design. Nesting `keyless
    // run` inside `infisical run` would have kept the plaintext out of this
    // process — and with it, out of the masker. Neither vendor CLI redacts
    // anything here, so the value would have reached the terminal whole.
    //
    // This is the end-to-end proof that it does not: the child echoes what it
    // was given, and the real binary's real stdout carries the mask.
    let dir = scratch("e2e-infisical-masked");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "infisical":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}},
                "secrets":{{"DECOY":{{"env":"dev"}}}}}}"#,
            stub.display()
        ),
    )
    .expect("write config");

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "run",
        "-s",
        "DECOY",
        "--",
        "/bin/sh",
        "-c",
        "echo \"$DECOY\"",
    ]);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert_eq!(stdout_of(&output), "[keyless:DECOY]\n");
    assert!(
        !stdout_of(&output).contains(INFISICAL_DECOY),
        "a vault value reached the terminal unmasked"
    );
}

#[test]
fn the_child_really_receives_the_value() {
    // The mask must not be hiding a failure to inject: the child sees the real
    // value, it is only the *output* that is filtered.
    let dir = scratch("e2e-received");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "run",
        "-s",
        "DECOY",
        "--",
        "/bin/sh",
        "-c",
        "test \"$DECOY\" = \"$1\" && echo MATCH || echo MISMATCH",
        "sh",
        DECOY_VALUE,
    ]);

    // The comparison happens inside the child, so only the verdict is printed.
    assert_eq!(
        stdout_of(&output),
        "MATCH\n",
        "stderr: {}",
        stderr_of(&output)
    );
}

#[test]
fn the_exit_code_is_forwarded() {
    let dir = scratch("e2e-exit");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "run",
        "-s",
        "DECOY",
        "--",
        "/bin/sh",
        "-c",
        "exit 33",
    ]);
    assert_eq!(output.status.code(), Some(33));
}

// ---------------------------------------------------------------------------
// Degrading, end to end.
// ---------------------------------------------------------------------------

#[test]
fn a_missing_name_degrades_and_still_runs_the_command() {
    let dir = scratch("e2e-degraded");
    let config = config_with_stub(&dir, &Stub::NotFound);

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "run",
        "-s",
        "DECOY",
        "-s",
        "OTHER",
        "--",
        "/bin/sh",
        "-c",
        "printf '%s' \"${DECOY-<unset>}\"; exit 21",
    ]);

    assert_eq!(output.status.code(), Some(21), "the exit code must survive");
    assert_eq!(
        stdout_of(&output),
        "<unset>",
        "the environment must be unmodified"
    );
    assert!(
        stderr_of(&output).contains("keyless: DEGRADED — 2 names unresolved: DECOY, OTHER"),
        "stderr was: {}",
        stderr_of(&output)
    );
}

#[test]
fn a_name_the_config_never_declared_says_so_and_a_declared_one_does_not() {
    // Hit live: a credential really was in the store, under the right item and
    // the right field, and its name had never been declared. Nothing said where
    // to look, so nothing looked there — and the run reported it exactly as it
    // reports a declared name the store was asked for and does not hold. Two
    // states, one sentence, and the sentence sent its reader to the store.
    //
    // Both names go through one invocation, so the two messages are produced by
    // the same binary, the same config and the same store on the same run:
    // `DECOY` is declared by `config_with_stub`, `NOT_DECLARED_ANYWHERE` is not,
    // and the keychain stub answers `errSecItemNotFound` to both.
    let dir = scratch("e2e-undeclared");
    let config = config_with_stub(&dir, &Stub::NotFound);

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "run",
        "-s",
        "DECOY",
        "-s",
        "NOT_DECLARED_ANYWHERE",
        "--",
        "/bin/sh",
        "-c",
        "exit 7",
    ]);

    assert_eq!(output.status.code(), Some(7), "the command must still run");
    let stderr = stderr_of(&output);

    let undeclared = line_for(&stderr, "NOT_DECLARED_ANYWHERE");
    assert!(
        undeclared.contains("not declared in your config"),
        "the undeclared name did not name the file that is missing the line: {stderr}"
    );
    assert!(
        undeclared.contains("Declare it under \"secrets\""),
        "the diagnosis carried no next action: {stderr}"
    );

    // The negative control, and the direction that matters: a name that IS
    // declared must keep pointing at the store. If both lines start naming the
    // config, one conflation has been traded for another and every reader is
    // sent to the wrong file instead of the wrong store.
    let declared = line_for(&stderr, "DECOY");
    assert_eq!(
        declared, "keyless:   DECOY: not found in any store",
        "the declared-and-absent message changed: {stderr}"
    );
}

#[test]
fn an_absent_config_still_runs_the_command() {
    let dir = scratch("e2e-no-config");
    let output = keyless(&[
        "--config",
        &dir.join("nothing-here.json").display().to_string(),
        "--no-audit",
        "run",
        "--",
        "/bin/echo",
        "ran",
    ]);
    assert!(output.status.success());
    assert_eq!(stdout_of(&output), "ran\n");
}

#[test]
fn a_run_audit_row_names_the_reader_identity_and_never_the_manager() {
    // The row is what makes "did a session ever act as the editor?" answerable
    // from the log rather than from trust. A `Registry` cannot hold a writer, so
    // this must be `(reader)` for every backend that answers a `run`.
    let dir = scratch("audit-identity");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let audit = dir.join("audit.jsonl");

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &audit.display().to_string(),
        "run",
        "-s",
        "DECOY",
        "--",
        "/bin/echo",
        "ran",
    ]);
    assert!(output.status.success(), "{}", stderr_of(&output));

    let rows = std::fs::read_to_string(&audit).expect("the log must exist");
    assert!(
        rows.contains("\"identities\":[\"keychain (reader)\"]"),
        "the row must name which identity resolved it:\n{rows}"
    );
    assert!(
        !rows.contains("manager"),
        "a run row mentioned the manager identity:\n{rows}"
    );
}

// ---------------------------------------------------------------------------
// The audit log.
// ---------------------------------------------------------------------------

#[test]
fn the_audit_row_records_the_name_and_masks_a_value_typed_on_the_command_line() {
    let dir = scratch("e2e-audit");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let audit = dir.join("audit.jsonl");

    // The habit this tool replaces: the value typed as a literal flag. Even
    // then it must not reach the log.
    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &audit.display().to_string(),
        "run",
        "-s",
        "DECOY",
        "--",
        "/bin/echo",
        &format!("--token={DECOY_VALUE}"),
    ]);
    assert!(output.status.success());

    let rows = std::fs::read_to_string(&audit).expect("the log must exist");
    assert!(
        !rows.contains(DECOY_VALUE),
        "the audit log leaked a value:\n{rows}"
    );
    assert!(rows.contains("[keyless:DECOY]"));
    assert!(rows.contains("\"state\":\"INJECTED\""));
    assert!(rows.contains("\"names\":[\"DECOY\"]"));
    assert!(rows.contains("\"exit_code\":0"));
    assert!(rows.contains("\"verb\":\"run\""));
    assert_eq!(rows.lines().count(), 1);
}

#[test]
fn a_degraded_run_records_which_names_were_missing() {
    let dir = scratch("e2e-audit-degraded");
    let config = config_with_stub(&dir, &Stub::NotFound);
    let audit = dir.join("audit.jsonl");

    let _ = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &audit.display().to_string(),
        "run",
        "-s",
        "DECOY",
        "--",
        "/bin/echo",
        "x",
    ]);

    let rows = std::fs::read_to_string(&audit).expect("the log must exist");
    assert!(rows.contains("\"state\":\"DEGRADED\""));
    assert!(rows.contains("\"unresolved\":[\"DECOY\"]"));
    assert!(rows.contains("\"names\":[]"));
}

#[test]
fn no_audit_writes_nothing() {
    let dir = scratch("e2e-no-audit");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let audit = dir.join("audit.jsonl");
    let _ = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &audit.display().to_string(),
        "--no-audit",
        "run",
        "--",
        "/bin/echo",
        "x",
    ]);
    assert!(!audit.exists(), "--no-audit must create no file");
}
