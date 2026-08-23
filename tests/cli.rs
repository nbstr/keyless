//! End-to-end tests against the built binary.
//!
//! These exist for the properties that only hold at the CLI boundary — above
//! all, that **no verb prints a value**. That is a claim about the shape of the
//! command surface, so it has to be tested by asking the real binary for those
//! verbs and watching it refuse.

mod support;

use std::path::Path;
use std::process::{Command, Output};

use support::{
    Backend, DECOY_VALUE, INFISICAL_DECOY, Stub, scratch, stub_infisical, stub_security,
};

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// Write a config wired to a `security` stub, so no real keychain is touched.
fn config_with_stub(dir: &Path, behaviour: &Stub) -> std::path::PathBuf {
    let stub = stub_security(dir, behaviour);
    let path = dir.join("config.json");
    let body = format!(
        r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{}"}}}},
            "secrets":{{"DECOY":{{"note":"a decoy"}},"OTHER":{{}}}}}}"#,
        stub.display()
    );
    std::fs::write(&path, body).expect("write config");
    path
}

fn keyless(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("the binary must run")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// The verb that must not exist.
// ---------------------------------------------------------------------------

#[test]
fn there_is_no_verb_that_prints_a_value() {
    // Every name a caller might reach for. If any of these ever succeeds, the
    // architecture is void: an agent takes the shortest path, and a verb that
    // prints a value is always the shortest path.
    for verb in [
        "get", "read", "show", "cat", "export", "print", "reveal", "dump", "value", "fetch",
        "copy", "env", "eval", "shell", "exec",
    ] {
        let output = keyless(&[verb, "DECOY"]);
        assert!(
            !output.status.success(),
            "`keyless {verb}` succeeded; there must be no verb that yields a value"
        );
    }
}

/// Refusing is half the job; the other half is that the refusal TEACHES.
///
/// `error: unrecognized subcommand 'get'` is what a CLI says about a typo and
/// about a feature nobody has written yet, so it reads as a broken install
/// rather than as the design. A person who concludes the tool is unfinished
/// goes back to the plaintext path, which is the outcome this whole crate
/// exists to prevent — so the message is a security property, not a courtesy.
#[test]
fn every_refused_word_explains_itself_and_points_at_run() {
    for verb in keyless::cmd::refuse::REFUSED {
        let output = keyless(&[verb, "DECOY"]);
        assert!(
            !output.status.success(),
            "`keyless {verb}` must not succeed"
        );

        // Explanations go to stderr: this verb yields no result, and a message
        // on stdout would land in whatever the caller piped it into.
        let text = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            text.contains(&format!("there is no `{verb}`")),
            "`{verb}` must be named back to the person who typed it: {text}"
        );
        assert!(
            text.contains("will not be one"),
            "`{verb}` must read as a decision, not as an unfinished feature: {text}"
        );
        assert!(
            text.contains("run -s NAME"),
            "`{verb}` must show the shape that does work: {text}"
        );
        assert!(
            stdout_of(&output).is_empty(),
            "`{verb}` must write nothing to stdout: {}",
            stdout_of(&output)
        );
    }
}

/// The refusals are hidden, and the verb list is the reason.
///
/// `Cargo.toml` records that the verb set is a security property a reader must
/// be able to check at a glance. A `get` printed in `--help` would undo that:
/// somebody skimming for "does anything here print a value" would find one.
#[test]
fn the_help_verb_list_does_not_grow_a_reading_verb() {
    let output = keyless(&["--help"]);
    let text = stdout_of(&output);
    let commands = text
        .split_once("Commands:")
        .expect("help must list commands")
        .1;
    // `skip(1)` drops what is left of the `Commands:` line itself, which is
    // empty and would otherwise end the `take_while` before it read a row.
    let listed = commands
        .lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .collect::<Vec<_>>();
    assert!(!listed.is_empty(), "the parser read no rows: {commands}");

    // The four setup-family verbs are the justification this gate asks for.
    // None of them reads a store: `setup` writes a config and registers a hook
    // pack, `disable`/`enable` flip one boolean in the pack's own config, and
    // `uninstall` deletes what a receipt says was created. Not one of them can
    // reach a credential, so none of them can print one.
    assert_eq!(
        listed,
        [
            "run",
            "ls",
            "items",
            "fields",
            "new",
            "put",
            "doctor",
            "init",
            "setup",
            "disable",
            "enable",
            "uninstall"
        ],
        "the visible verb set changed; every addition has to be justified against \
         `no verb prints a value`"
    );
}

/// The way out is listed where a person in a hurry will look.
///
/// A guard that cannot be turned off gets destroyed instead: somebody who
/// cannot find the switch guts their settings file by hand, and then the
/// protection is gone silently and for good. So `--help` has to name it — and
/// this is the surface a PERSON reads, which is why the block message an agent
/// reads deliberately does not.
#[test]
fn the_help_names_the_off_switch_and_the_way_back() {
    let text = stdout_of(&keyless(&["--help"]));
    for expected in ["disable", "enable", "uninstall"] {
        assert!(
            text.contains(expected),
            "`--help` does not mention `{expected}`:\n{text}"
        );
    }
}

#[test]
fn there_is_no_flag_that_disables_masking() {
    let dir = scratch("no-reveal-flags");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let config = config.display().to_string();

    for flag in [
        "--reveal",
        "--no-mask",
        "--no-masking",
        "--print",
        "--plaintext",
        "--unsafe",
        "--show-secrets",
    ] {
        let output = keyless(&[
            "--config",
            &config,
            "run",
            flag,
            "-s",
            "DECOY",
            "--",
            "/bin/echo",
        ]);
        assert!(
            !output.status.success(),
            "`{flag}` was accepted; masking must not be switchable"
        );
    }
}

#[test]
fn help_advertises_the_whole_verb_set_and_the_constraint() {
    let output = keyless(&["--help"]);
    assert!(output.status.success());
    let help = stdout_of(&output);
    for verb in [
        "run", "ls", "items", "fields", "new", "put", "doctor", "init",
    ] {
        assert!(help.contains(verb), "help must mention `{verb}`:\n{help}");
    }
    assert!(
        help.contains("no verb that prints a value"),
        "help must say the constraint out loud:\n{help}"
    );
}

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
            r#"{{"stores":{{"keychain":{{"service":"svc","binary":"{}"}}}},
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

// ---------------------------------------------------------------------------
// ls and doctor.
// ---------------------------------------------------------------------------

#[test]
fn ls_prints_names_and_never_a_value() {
    let dir = scratch("e2e-ls");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let output = keyless(&["--config", &config.display().to_string(), "ls"]);

    assert!(output.status.success());
    let listing = stdout_of(&output);
    assert!(listing.contains("DECOY"));
    assert!(listing.contains("OTHER"));
    assert!(
        !listing.contains(DECOY_VALUE),
        "ls leaked a value: {listing}"
    );
}

#[test]
fn ls_says_which_environment_an_infisical_name_points_at() {
    // An environment decides which real value comes back, so a name whose
    // environment is invisible in the listing is the same hazard as one that
    // resolves against an invisible default. `no-env` is the set of names that
    // will degrade until somebody gives them one.
    let dir = scratch("e2e-ls-env");
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        r#"{"stores":{"keychain":{"enabled":false},
             "infisical":{"enabled":true,"path":"/backend"}},
            "secrets":{"PINNED":{"env":"prod"},"LOOSE":{}}}"#,
    )
    .expect("write config");

    let output = keyless(&["--config", &config.display().to_string(), "ls"]);
    let listing = stdout_of(&output);

    assert!(output.status.success(), "stderr: {}", stderr_of(&output));
    assert!(listing.contains("prod:/backend"), "listing: {listing}");
    assert!(listing.contains("no-env:/backend"), "listing: {listing}");
}

#[test]
fn run_env_covers_a_name_that_declares_none_and_never_outranks_one_that_does() {
    // Both halves of the precedence rule, through the real binary: the flag
    // rescues the name that says nothing, and leaves the name that says `prod`
    // exactly where it is. The stub echoes the environment it was called with,
    // so this reads the vendor call rather than the adapter's own idea of it.
    let dir = scratch("e2e-run-env");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "infisical":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}},
                "secrets":{{"LOOSE":{{}},"PINNED":{{"env":"prod"}}}}}}"#,
            stub.display()
        ),
    )
    .expect("write config");

    for (name, expected) in [("LOOSE", "--env=staging"), ("PINNED", "--env=prod")] {
        let output = keyless(&[
            "--config",
            &config.display().to_string(),
            "--no-audit",
            "run",
            "--env",
            "staging",
            "-s",
            name,
            "--",
            "/bin/echo",
            "ran",
        ]);
        assert!(output.status.success(), "stderr: {}", stderr_of(&output));
        let argv = std::fs::read_to_string(dir.join("infisical.argv")).expect("the stub recorded");
        assert!(
            argv.lines().any(|line| line == expected),
            "{name} was looked up with: {argv}"
        );
    }
}

#[test]
fn a_name_with_no_environment_degrades_and_says_both_ways_to_fix_it() {
    // What a config that still sets a store-level `env` produces the first time
    // it is run after this rule lands. The message has to be actionable with
    // nobody there to explain it, and the command has to run regardless.
    let dir = scratch("e2e-no-env");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "infisical":{{"enabled":true,"binary":"{}","env":"prod",
                               "timeout_ms":60000}}}},
                "secrets":{{"DATABASE_URL":{{}}}}}}"#,
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
        "DATABASE_URL",
        "--",
        "/bin/echo",
        "ran",
    ]);
    let notes = stderr_of(&output);

    assert_eq!(stdout_of(&output), "ran\n", "the command must still run");
    assert!(output.status.success(), "the exit code must be the child's");
    assert!(notes.contains("DEGRADED"), "notes: {notes}");
    assert!(notes.contains("DATABASE_URL"), "notes: {notes}");
    assert!(notes.contains("\"env\""), "the per-name fix: {notes}");
    assert!(notes.contains("--env"), "the per-run fix: {notes}");
    assert!(
        notes.contains("stores.infisical.env") && notes.contains("IGNORED"),
        "the stale key must be named: {notes}"
    );
    assert!(
        !notes.contains(INFISICAL_DECOY),
        "a value reached stderr: {notes}"
    );
    assert!(
        !dir.join("infisical.argv").exists(),
        "the backend was invoked with no environment"
    );
}

#[test]
fn doctor_reports_a_healthy_setup_and_leaks_nothing() {
    let dir = scratch("e2e-doctor");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let audit = dir.join("audit.jsonl");

    // Produce a row first so the chain has something to verify.
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
        "hello",
    ]);

    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &audit.display().to_string(),
        "doctor",
        "--probe",
    ]);

    let report = stdout_of(&output);
    assert!(report.contains("chain intact"), "report: {report}");
    assert_eq!(
        state_of(row_for(&report, "keychain")),
        "proven",
        "report: {report}"
    );
    assert_eq!(
        state_of(row_for(&report, "DECOY")),
        "proven",
        "report: {report}"
    );
    // `ok` is the word this report no longer has anywhere. It was a verdict on
    // the credential, printed after a check that measured a binary.
    assert!(!report.contains(" ok "), "report: {report}");
    // The boundary line rides with every report, so no reader takes a resolving
    // name for a credential whose scope somebody checked.
    assert!(
        report.contains("not checked, and never will be"),
        "report: {report}"
    );
    assert!(
        !report.contains(DECOY_VALUE),
        "doctor leaked a value: {report}"
    );
    assert_eq!(output.status.code(), Some(0), "report: {report}");
}

#[test]
fn doctor_reports_a_broken_store_without_blocking_anything() {
    let dir = scratch("e2e-doctor-broken");
    let config = config_with_stub(&dir, &Stub::Dead);
    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &dir.join("audit.jsonl").display().to_string(),
        "doctor",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let report = stdout_of(&output);
    assert!(report.contains("problem(s)"), "{report}");
    assert!(!report.contains("\n0 problem(s)"), "{report}");
    // The row that failed must say what to do about it. A diagnosis with no
    // next action is the shape this report used to have.
    assert!(report.contains("→"), "{report}");
}

/// The one report row whose subject is `subject`.
/// The state column of a rendered row: `<mark> <subject> <state> <detail>`.
///
/// Read as a whole column, because `unproven` CONTAINS `proven` — so
/// `contains("proven")` passes on the one state it exists to exclude. Measured
/// over this tree: every `proven` in the crate can be rewritten to `unproven`,
/// leaving a green mark beside the word that denies it, and the suite stays
/// green.
fn state_of(row: &str) -> &str {
    row.split_whitespace().nth(2).unwrap_or_default()
}

fn row_for<'a>(report: &'a str, subject: &str) -> &'a str {
    report
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(subject))
        .unwrap_or_else(|| panic!("the report has no `{subject}` row:\n{report}"))
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

// ---------------------------------------------------------------------------
// Nothing leaves the machine.
// ---------------------------------------------------------------------------

/// Every offset in `haystack` at which `needle` appears, case-insensitively.
fn occurrences(haystack: &[u8], needle: &str) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| window.eq_ignore_ascii_case(needle.as_bytes()))
        .map(|(at, _)| at)
        .collect()
}

#[test]
fn the_binary_contains_no_network_endpoint() {
    // The reference implementation posted the user's email to a hard-coded
    // endpoint with no opt-out, while its docs claimed it collected nothing.
    // This test reads the built binary and fails if a URL scheme appears in it
    // outside of the strings this project deliberately ships.
    scan_for_endpoints(BIN);
}

#[test]
fn the_daemon_binary_contains_no_network_endpoint_either() {
    // The daemon is the process that holds every credential and runs
    // unattended for weeks. It is the last thing that should be able to reach
    // the network, and it is the one a reader is least likely to check.
    let daemon = std::path::Path::new(BIN)
        .parent()
        .map(|dir| dir.join("keylessd"))
        .expect("the test binary has a parent directory");
    assert!(
        daemon.is_file(),
        "keylessd was not built; expected it at {}",
        daemon.display()
    );
    scan_for_endpoints(&daemon.display().to_string());
}

fn scan_for_endpoints(path: &str) {
    let binary = std::fs::read(path).expect("read the built binary");
    for needle in [
        "https://api.",
        "http://",
        "vercel.app",
        "analytics",
        "sentry.io",
        "amplitude",
        "posthog",
    ] {
        assert!(
            occurrences(&binary, needle).is_empty(),
            "{path} contains `{needle}`"
        );
    }
}

#[test]
fn the_only_telemetry_string_in_the_binary_is_the_one_that_switches_it_off() {
    // The Infisical CLI's telemetry defaults to ON, so the adapter passes
    // `--telemetry=false` on every invocation it makes — otherwise `keyless`
    // would be the reason a report left the machine, which is exactly what the
    // blanket ban above exists to prevent.
    //
    // So the word is allowed, and only in that one shape. Written out here
    // rather than imported from the crate: a test that reads the same constant
    // the implementation uses would keep passing if that constant were edited
    // to `--telemetry=true`.
    const ONLY_ALLOWED: &str = "--telemetry=false";

    let binary = std::fs::read(BIN).expect("read the built binary");
    let allowed: Vec<usize> = occurrences(&binary, ONLY_ALLOWED)
        .into_iter()
        // The offset of the word within the allowed string.
        .map(|at| at + "--".len())
        .collect();

    for at in occurrences(&binary, "telemetry") {
        assert!(
            allowed.contains(&at),
            "the binary contains a `telemetry` string that is not `{ONLY_ALLOWED}`"
        );
    }
    assert!(
        !allowed.is_empty(),
        "`{ONLY_ALLOWED}` is absent; the vendor CLI's telemetry is no longer being disabled"
    );
}

#[test]
fn the_daemon_carries_no_telemetry_string_of_its_own() {
    // `scan_for_endpoints` deliberately stopped banning the word outright, so
    // without this the daemon is the one binary nothing checks for it. It links
    // the same library, so `--telemetry=false` may legitimately appear; what
    // must not appear is any OTHER telemetry string.
    //
    // Presence is not asserted here, unlike for the client: the daemon does not
    // construct the Infisical adapter, so whether the literal survives is a
    // linker decision and not a property worth pinning.
    const ONLY_ALLOWED: &str = "--telemetry=false";
    let daemon = std::path::Path::new(BIN)
        .parent()
        .map(|dir| dir.join("keylessd"))
        .expect("the test binary has a parent directory");
    let binary = std::fs::read(&daemon).expect("read the built daemon");

    let allowed: Vec<usize> = occurrences(&binary, ONLY_ALLOWED)
        .into_iter()
        .map(|at| at + "--".len())
        .collect();
    for at in occurrences(&binary, "telemetry") {
        assert!(
            allowed.contains(&at),
            "keylessd contains a `telemetry` string that is not `{ONLY_ALLOWED}`"
        );
    }
}

// ---------------------------------------------------------------------------
// The status display: what a person sees, and what a pipe gets.
//
// These are at the binary boundary on purpose. `Style` is unit-tested as a pure
// function of five variables, and that proves the DECISION. It cannot prove the
// binary wires the decision to the stream it is writing to — which is the half
// that was wrong in `ls` once already, and the half a reader is actually exposed
// to.
// ---------------------------------------------------------------------------

/// Run the binary with extra environment, and with stdout captured (never a tty).
fn keyless_env(env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut command = Command::new(BIN);
    for (key, value) in env {
        command.env(key, value);
    }
    command.args(args).output().expect("the binary must run")
}

#[test]
fn a_redirected_doctor_is_clean_text() {
    let dir = scratch("e2e-doctor-piped");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &dir.join("audit.jsonl").display().to_string(),
        "doctor",
    ]);
    let report = stdout_of(&output);
    assert!(
        !report.contains('\x1b'),
        "a redirected report carried an escape sequence: {report:?}"
    );
    // The control. Without it this passes on a build that has no colour at all,
    // which would make the assertion above a statement about nothing.
    let forced = keyless_env(
        &[("CLICOLOR_FORCE", "1")],
        &[
            "--config",
            &config.display().to_string(),
            "--audit",
            &dir.join("audit.jsonl").display().to_string(),
            "doctor",
        ],
    );
    assert!(
        stdout_of(&forced).contains('\x1b'),
        "the binary emits no colour on any path, so the piped assertion proves nothing"
    );
}

#[test]
fn a_reader_who_refused_colour_is_never_overruled() {
    // `NO_COLOR` is a refusal and `CLICOLOR_FORCE` is a request. The first
    // spelling of this decision let the request win, which makes `NO_COLOR` a
    // preference rather than the guarantee it is meant to be.
    let dir = scratch("e2e-doctor-no-color");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let output = keyless_env(
        &[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")],
        &[
            "--config",
            &config.display().to_string(),
            "--audit",
            &dir.join("audit.jsonl").display().to_string(),
            "doctor",
        ],
    );
    assert!(
        !stdout_of(&output).contains('\x1b'),
        "NO_COLOR was overruled: {:?}",
        stdout_of(&output)
    );
}

#[test]
fn the_marks_degrade_to_ascii_on_a_terminal_that_cannot_render_them() {
    let dir = scratch("e2e-doctor-ascii");
    let config = config_with_stub(&dir, &Stub::Returns(DECOY_VALUE));
    let args = [
        "--config",
        &config.display().to_string(),
        "--audit",
        &dir.join("audit.jsonl").display().to_string(),
        "doctor",
    ];
    let ascii = stdout_of(&keyless_env(&[("KEYLESS_ASCII", "1")], &args));
    // Total, because every string this crate writes is ASCII already and the
    // fixture's store contributes no message of its own. The one thing the
    // fallback cannot cover is text `keyless` did not author — a vendor's
    // stderr, a note somebody typed — and rewriting that would be editing
    // evidence rather than degrading a glyph.
    assert!(
        ascii.is_ascii(),
        "the fallback rendering is not ASCII:\n{ascii}"
    );
    // Still a report, not a blank one: the degrade must lose the glyphs and
    // nothing else.
    assert!(ascii.contains("STORES"), "{ascii}");
    assert!(ascii.contains("keychain"), "{ascii}");
    // The control, so this is a statement about the degrade rather than about a
    // build that never emitted a glyph.
    let utf8 = stdout_of(&keyless_env(&[("LC_ALL", "en_US.UTF-8")], &args));
    assert!(
        !utf8.is_ascii(),
        "no build ever renders the Unicode marks:\n{utf8}"
    );
}

// ---------------------------------------------------------------------------
// `init`.
// ---------------------------------------------------------------------------

#[test]
fn init_never_waits_for_input_it_cannot_get() {
    // The hazard this verb introduces and the one it is allowed to have exactly
    // one of. A setup command that blocks on a prompt in a pipeline reads as a
    // hang, and a watchdog kills it with no evidence of what it wanted.
    let dir = scratch("e2e-init-no-tty");
    let config = dir.join("config.json");
    let output = keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &dir.join("audit.jsonl").display().to_string(),
        "init",
    ]);
    // Whatever it decided, it decided. `Command::output` would never return
    // from a process sitting on a read of an inherited stdin.
    assert!(
        output.status.code().is_some(),
        "init did not exit: {output:?}"
    );
}

#[test]
fn init_writes_a_config_that_the_tool_can_then_read() {
    let dir = scratch("e2e-init-writes");
    let config = dir.join("config.json");
    let path = config.display().to_string();
    let audit = dir.join("audit.jsonl").display().to_string();

    let written = keyless(&[
        "--config", &path, "--audit", &audit, "init", "--store", "keychain",
    ]);
    assert_eq!(written.status.code(), Some(0), "{written:?}");
    assert!(config.exists(), "init reported success and wrote nothing");

    // The property that makes the verb worth having: `doctor` reads what `init`
    // wrote. A hand-built JSON string is exactly the kind of output that looks
    // right and does not parse.
    let report = stdout_of(&keyless(&["--config", &path, "--audit", &audit, "doctor"]));
    assert!(
        !report.contains("broken") && !report.contains("cannot parse"),
        "doctor could not read the config init wrote:\n{report}"
    );
    assert!(report.contains("keychain"), "{report}");
}

#[test]
fn a_second_init_leaves_the_first_config_alone() {
    let dir = scratch("e2e-init-twice");
    let config = dir.join("config.json");
    let path = config.display().to_string();
    let audit = dir.join("audit.jsonl").display().to_string();
    std::fs::write(&config, "{\"secrets\":{\"MINE\":{}}}").expect("write");

    let output = keyless(&["--config", &path, "--audit", &audit, "init"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(&config).expect("read"),
        "{\"secrets\":{\"MINE\":{}}}",
        "a second init overwrote a config it was not asked to touch"
    );
    assert!(stdout_of(&output).contains("--force"), "{output:?}");
}

#[test]
fn init_has_no_way_to_be_handed_a_value() {
    // The standing constraint, aimed at the newest verb. `init` writes a file,
    // and the moment it accepts a credential it becomes the shortest path to
    // putting one in a shell history.
    for flag in ["--value", "--secret", "--password", "--token", "--set"] {
        let output = keyless(&["init", flag, "anything"]);
        assert!(
            !output.status.success(),
            "`init {flag}` was accepted; nothing in this verb may take a value"
        );
    }
}

#[test]
fn a_home_with_no_keychain_is_reported_without_spawning_security() {
    // The guard against a MODAL WINDOW, not against an error. With `HOME`
    // pointed at a directory holding no keychain, macOS answers a missing
    // default keychain with a dialog whose buttons include Reset To Defaults —
    // from a command nobody thought could do anything but print. A `stat` cannot
    // open a window, so the check is one and it runs before any process exists.
    let dir = scratch("e2e-home-no-keychain");
    let home = dir.join("empty-home");
    std::fs::create_dir_all(&home).expect("home");
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        r#"{"stores":{"keychain":{"enabled":true,"service":"keyless"}}}"#,
    )
    .expect("write config");

    let mut command = Command::new(BIN);
    command.env("HOME", &home);
    let output = command
        .args([
            "--config",
            &config.display().to_string(),
            "--audit",
            &dir.join("audit.jsonl").display().to_string(),
            "doctor",
        ])
        .output()
        .expect("the binary must run");

    let report = stdout_of(&output);
    let flat = report.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("has no login keychain"),
        "the guard did not fire:\n{report}"
    );
    assert!(
        flat.contains("modal dialog"),
        "the row must say WHY it refused to spawn, or somebody removes it:\n{report}"
    );
    // Amber, not red: this HOME has no keychain, which is a state rather than a
    // fault in the store.
    assert_eq!(state_of(row_for(&report, "keychain")), "absent", "{report}");
}

#[test]
fn doctor_says_which_variables_a_name_actually_delivers() {
    // A bare `-s NAME` lands in `$NAME` and in the variables the declaration
    // says it answers to. That is otherwise undiscoverable: `ls` may not grow a
    // fifth field, and a run that works prints nothing.
    let dir = scratch("e2e-doctor-aliases");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{}"}}}},
                "secrets":{{"STAGING_URL":{{"var":"DATABASE_URL"}},"PLAIN":{{}}}}}}"#,
            stub.display()
        ),
    )
    .expect("write config");

    let report = stdout_of(&keyless(&[
        "--config",
        &config.display().to_string(),
        "--audit",
        &dir.join("audit.jsonl").display().to_string(),
        "doctor",
    ]));
    let flat = report.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("-s STAGING_URL sets $STAGING_URL and $DATABASE_URL"),
        "the report did not say which variables arrive:\n{report}"
    );
    // And it says nothing about a name that delivers only itself, or the line
    // becomes furniture on every row and stops being read.
    assert!(!flat.contains("-s PLAIN sets"), "{report}");
}

#[test]
fn init_reports_the_guards_without_installing_them() {
    // The settings file belongs to another program. `init` reports; `--hooks`
    // writes. A secrets broker that edits a neighbour's configuration
    // unasked is doing the thing this tool argues against.
    let dir = scratch("e2e-init-guards");
    let home = dir.join("home");
    std::fs::create_dir_all(home.join(".claude")).expect("home");
    let settings = home.join(".claude").join("settings.json");
    std::fs::write(&settings, "{}").expect("write settings");

    let mut command = Command::new(BIN);
    command.env("HOME", &home);
    let output = command
        .args([
            "--config",
            &dir.join("config.json").display().to_string(),
            "--audit",
            &dir.join("audit.jsonl").display().to_string(),
            "init",
            "--store",
            "keychain",
        ])
        .output()
        .expect("the binary must run");

    let report = stdout_of(&output);
    assert!(report.contains("GUARDS"), "{report}");
    assert_eq!(
        std::fs::read_to_string(&settings).expect("read"),
        "{}",
        "init wrote to a settings file it was not asked to touch"
    );
    assert!(report.contains("--hooks"), "{report}");
}
