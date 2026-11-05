mod cli_support;
mod support;

use cli_support::{
    config_with_stub, keyless, keyless_env, row_for, state_of, stderr_of, stdout_of,
};
use support::{Backend, DECOY_VALUE, INFISICAL_DECOY, Stub, scratch, stub_infisical};

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

// ---------------------------------------------------------------------------
// The status display: what a person sees, and what a pipe gets.
//
// These are at the binary boundary on purpose. `Style` is unit-tested as a pure
// function of five variables, and that proves the DECISION. It cannot prove the
// binary wires the decision to the stream it is writing to — which is the half
// that was wrong in `ls` once already, and the half a reader is actually exposed
// to.
// ---------------------------------------------------------------------------

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
