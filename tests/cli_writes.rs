mod cli_support;
mod support;

use cli_support::{config_with_stub, keyless, stderr_of, stdout_of};
use support::{DECOY_VALUE, Stub, scratch, stub_security};

#[test]
fn there_is_no_way_to_pass_a_value_to_put_as_an_argument() {
    // An argument is readable from the process table for as long as the process
    // lives. A flag that exists gets used, so none of these may.
    let dir = scratch("put-no-value-flag");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let config = config.display().to_string();
    let leak = "decoy-would-be-on-argv-6161";

    // Asserted on clap's PARSE-error code, not merely on "it failed". Under
    // `Command::output()` stdin is empty, so a `put` that accepted the flag and
    // ignored it would fail anyway for want of a value — and a test that only
    // checked for failure would stay green while the flag existed. Exit 2 is the
    // argument parser refusing to accept the word at all, which is the property.
    for flag in [
        "--value",
        "--secret",
        "--password",
        "--from",
        "--plaintext",
        "--stdin-value",
    ] {
        let output = keyless(&[
            "--config",
            &config,
            "--no-audit",
            "put",
            "DECOY",
            flag,
            leak,
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "`put {flag}` was not refused by the argument parser; a value must never be an \
             argument. stderr: {}",
            stderr_of(&output)
        );
    }

    // And a bare positional value is not a value either — `put` takes exactly one
    // argument, the NAME.
    let output = keyless(&["--config", &config, "--no-audit", "put", "DECOY", leak]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "`put NAME VALUE` was accepted as a positional value. stderr: {}",
        stderr_of(&output)
    );
}

#[test]
fn neither_new_nor_put_has_a_flag_that_prints_what_it_stored() {
    let dir = scratch("write-no-reveal");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let config = config.display().to_string();

    for verb in ["new", "put"] {
        for flag in ["--show", "--print", "--reveal", "--echo", "--no-mask"] {
            let output = keyless(&["--config", &config, "--no-audit", verb, "DECOY", flag]);
            assert!(
                !output.status.success(),
                "`{verb} {flag}` was accepted; a write must not be able to display the value"
            );
        }
    }
}

#[test]
fn new_prints_where_it_stored_the_value_and_never_the_value() {
    // Against the `security` stub, so no real keychain is touched. The stub
    // accepts the write and records nothing back, which is exactly the shape a
    // successful write has: one line naming the destination and the identity.
    let dir = scratch("new-prints-nothing");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"stores":{{"keychain":{{"service":"svc","binary":"{}","timeout_ms":60000}}}},
                "secrets":{{"DECOY":{{}}}}}}"#,
            stub.display()
        ),
    )
    .expect("write config");

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "new",
        "DECOY",
        "--length",
        "32",
    ]);
    let printed = stdout_of(&output);
    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert!(printed.starts_with("stored\tDECOY"), "{printed}");
    assert!(printed.contains("svc/DECOY"), "{printed}");
    // One line, and every field on it is a coordinate. A generated 32-character
    // value cannot hide in it.
    assert_eq!(printed.lines().count(), 1, "{printed}");
    assert_eq!(stderr_of(&output), "", "a successful write is silent");

    // The value reached the child's stdin, twice, and is nowhere in this output —
    // which is the pair of facts that makes the line above meaningful rather than
    // just short.
    let arrived = std::fs::read_to_string(dir.join("security.stdin"))
        .expect("the stub must have been given a value on stdin");
    let lines: Vec<&str> = arrived.lines().collect();
    assert_eq!(lines.len(), 2, "`security` is asked twice: {lines:?}");
    assert_eq!(lines[0], lines[1]);
    assert_eq!(lines[0].len(), 32, "--length was not honoured");
    assert!(
        !printed.contains(lines[0]),
        "`new` printed the value it generated"
    );
}

#[test]
fn a_write_verb_refuses_rather_than_degrading_and_says_what_is_missing() {
    // The asymmetry with `run`, at the CLI boundary. `run` never refuses; a write
    // that "degraded" would report success with nothing stored.
    let dir = scratch("write-refuses");
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        r#"{"stores":{"keychain":{"enabled":false},
             "proton":{"enabled":true,"session_dir":"/tmp/keyless-no-such-session"}},
            "secrets":{"DECOY":{"vault":"personal","item":"d","field":"password"}}}"#,
    )
    .expect("write config");

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "new",
        "DECOY",
    ]);
    // EX_CONFIG: nothing was attempted and a file needs editing.
    assert_eq!(output.status.code(), Some(78), "{}", stderr_of(&output));
    assert!(stdout_of(&output).is_empty(), "a refusal printed a result");
    let complaint = stderr_of(&output);
    assert!(complaint.contains("manager"), "{complaint}");
    assert!(complaint.contains("--role editor"), "{complaint}");
}

#[test]
fn a_configured_daemon_refuses_a_local_write_and_names_the_boundary() {
    // Killing the daemon must yield FEWER powers, never more. A local write path
    // that opens whenever the daemon is off is that hole, one verb over.
    let dir = scratch("write-under-daemon");
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        r#"{"stores":{"daemon":{"enabled":true,"socket":"/tmp/keyless-no-socket.sock"},
             "proton":{"enabled":true,"session_dir":"/tmp/r",
                       "manager":{"session_dir":"/tmp/m"}}},
            "secrets":{"DECOY":{"vault":"personal","item":"d","field":"password"}}}"#,
    )
    .expect("write config");

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--no-audit",
        "new",
        "DECOY",
        "--store",
        "proton",
    ]);
    assert_eq!(output.status.code(), Some(78));
    assert!(
        stderr_of(&output).contains("uid boundary"),
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn items_and_fields_say_why_a_backend_cannot_enumerate() {
    // A verb that works in one backend and leaks in another is worse than one
    // that is plainly absent in the second: a caller learns to trust it from the
    // backend where it is safe.
    let dir = scratch("no-enumeration");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let config = config.display().to_string();

    let output = keyless(&["--config", &config, "items", "--store", "keychain"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_of(&output).contains("whole keychain file"),
        "{}",
        stderr_of(&output)
    );
    assert!(stdout_of(&output).is_empty());

    // Infisical enumerates ITEMS and has no FIELDS, which is a different kind of
    // absence and says so: a secret there is one value, so the coordinate is
    // complete without one and the message names the verb that does answer.
    let output = keyless(&[
        "--config",
        &config,
        "fields",
        "--store",
        "infisical",
        "--item",
        "anything",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_of(&output).contains("single value"),
        "{}",
        stderr_of(&output)
    );
    assert!(
        stderr_of(&output).contains("items infisical"),
        "{}",
        stderr_of(&output)
    );
}

#[test]
fn a_store_is_nameable_as_a_word_and_not_only_as_a_flag() {
    // `keyless items proton` is what a person types. It used to die on clap's
    // `unexpected argument 'proton'`, whose Usage line names `--store` nowhere —
    // so the message was true and taught nothing, which is the same defect
    // `keyless get` had.
    let dir = scratch("positional-store");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let config = config.display().to_string();

    // Each side is asserted against a LITERAL rather than against the other.
    // Comparing the two outputs would take both sides of the equality from the
    // code under test, so it would hold whatever that code did — including if
    // both spellings broke identically. `tests/oracle_independence.rs` fails a
    // build written the other way, and it caught this test.
    for output in [
        keyless(&["--config", &config, "items", "keychain"]),
        keyless(&["--config", &config, "items", "--store", "keychain"]),
    ] {
        assert_eq!(output.status.code(), Some(1));
        assert!(
            stderr_of(&output).contains("whole keychain file"),
            "this spelling must reach the backend, not clap: {}",
            stderr_of(&output)
        );
        assert!(stdout_of(&output).is_empty());
    }

    // Both at once is refused rather than ranked. Two spellings that disagree
    // is a question, and answering it by picking one is how a caller ends up
    // reading a store they did not ask about.
    let both = keyless(&[
        "--config", &config, "items", "keychain", "--store", "proton",
    ]);
    assert_eq!(both.status.code(), Some(2));
    assert!(
        stderr_of(&both).contains("cannot be used with"),
        "{}",
        stderr_of(&both)
    );
}
