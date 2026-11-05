mod cli_support;
mod support;

use std::process::Command;

use cli_support::{BIN, keyless, row_for, state_of, stdout_of};
use support::keychain::{Stub, stub_security};
use support::{DECOY_VALUE, scratch};

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
            r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{}","timeout_ms":60000}}}},
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
