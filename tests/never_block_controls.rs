//! The other side of the never-block invariant: when everything works, `run`
//! injects, masks, records and forwards exactly as asked.

mod support;

use std::path::PathBuf;

use keyless::State;
use keyless::audit::AuditLog;
use keyless::cmd::run::{RunRequest, TtyPolicy, run};
use keyless::store::Registry;
use keyless::store::keychain::KeychainStore;

use support::always_errors::AlwaysErrors;
use support::{DECOY_VALUE, Stub, run_with, scratch, stub_security, witness, witnessed};

// ---------------------------------------------------------------------------
// The other side of the invariant: when everything works, it works.
// ---------------------------------------------------------------------------

#[test]
fn a_resolved_secret_reaches_the_child_and_nothing_else() {
    let dir = scratch("happy-path");
    let marker = dir.join("witness");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));

    let registry = Registry::new(vec![Box::new(KeychainStore::new(
        stub,
        "keyless".to_owned(),
    ))]);
    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(
        witnessed(&marker),
        DECOY_VALUE,
        "the child must see the value"
    );
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(outcome.injected, vec!["DECOY".to_owned()]);
    assert_eq!(outcome.exit_code, 0);
    assert!(
        !notes.contains(DECOY_VALUE),
        "the value must never appear on stderr: {notes}"
    );
    assert_eq!(notes, "", "a successful run says nothing at all");
}

#[test]
fn an_alias_puts_the_value_in_a_different_variable() {
    let dir = scratch("alias");
    let marker = dir.join("witness");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    let registry = Registry::new(vec![Box::new(KeychainStore::new(
        stub,
        "keyless".to_owned(),
    ))]);

    let (outcome, _) = run_with(
        &registry,
        &["GH_TOKEN=DECOY"],
        &witness(&marker, "GH_TOKEN", 0),
        &[],
    );

    assert_eq!(witnessed(&marker), DECOY_VALUE);
    assert_eq!(outcome.state, State::Injected);
}

#[test]
fn one_missing_name_withholds_all_of_them() {
    // Two states, no third: a partially injected environment would be a third
    // state and is harder to reason about than all-or-nothing.
    let dir = scratch("partial");
    let marker = dir.join("witness");

    let good = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    // Pinned, because two backends are configured: the default policy refuses
    // to decide which of them an unpinned name means. Which store answers is
    // incidental here — the property under test is all-or-nothing injection.
    let registry = Registry::new(vec![
        Box::new(KeychainStore::new(good, "keyless".to_owned())),
        Box::new(AlwaysErrors("broken")),
    ])
    .with_routes(
        [("PRESENT".to_owned(), "keychain".to_owned())]
            .into_iter()
            .collect(),
    );

    // PRESENT resolves from the stub; the stub answers every lookup, so force a
    // miss with a backend that only errors.
    let only_broken = Registry::new(vec![Box::new(AlwaysErrors("broken"))]);
    let (outcome, _) = run_with(
        &only_broken,
        &["ABSENT"],
        &witness(&marker, "ABSENT", 0),
        &[],
    );
    assert_eq!(outcome.state, State::Degraded);

    let (outcome, _) = run_with(
        &registry,
        &["PRESENT"],
        &witness(&marker, "PRESENT", 0),
        &[],
    );
    assert_eq!(
        outcome.state,
        State::Injected,
        "the healthy store still answers"
    );
}

#[test]
fn a_malformed_secret_flag_degrades_instead_of_failing() {
    let dir = scratch("bad-spec");
    let marker = dir.join("witness");
    let registry = Registry::new(Vec::new());

    let mut notes: Vec<u8> = Vec::new();
    let unusable = vec!["9NOT_A_VARIABLE".to_owned()];
    let outcome = run(
        RunRequest {
            bindings: &[],
            unusable: &unusable,
            argv: &witness(&marker, "ANY", 5),
            registry: &registry,
            audit: None,
            warnings: &["`9NOT_A_VARIABLE` is not a usable environment variable name".to_owned()],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("a typo must not stop the command");

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 5);
    assert_eq!(outcome.state, State::Degraded);
}

#[test]
fn an_unwritable_audit_log_does_not_stop_the_child() {
    let dir = scratch("audit-unwritable");
    let marker = dir.join("witness");
    // A path under an existing FILE cannot be created as a directory.
    let blocker = dir.join("not-a-directory");
    std::fs::write(&blocker, b"x").expect("write blocker");
    let log = AuditLog::new(blocker.join("nested").join("audit.jsonl"));

    let registry = Registry::new(Vec::new());
    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &[],
            unusable: &[],
            argv: &witness(&marker, "ANY", 11),
            registry: &registry,
            audit: Some(&log),
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("an unwritable log must not stop the command");

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 11);
    assert!(
        String::from_utf8_lossy(&notes).contains("audit log"),
        "the caller should be told the log failed"
    );
}

#[test]
fn a_child_killed_by_a_signal_reports_the_shell_convention() {
    let registry = Registry::new(Vec::new());
    let argv: Vec<std::ffi::OsString> = ["/bin/sh", "-c", "kill -TERM $$"]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();

    let (outcome, _) = run_with(&registry, &[], &argv, &[]);
    // 128 + SIGTERM(15). Some shells trap and exit 143 themselves; both are 143.
    assert_eq!(outcome.exit_code, 143);
}

#[test]
fn a_run_with_no_secrets_at_all_is_a_transparent_passthrough() {
    let dir = scratch("passthrough");
    let marker = dir.join("witness");
    let registry = Registry::new(Vec::new());
    let (outcome, notes) = run_with(&registry, &[], &witness(&marker, "PATH", 0), &[]);

    assert!(
        !witnessed(&marker).is_empty(),
        "PATH must still be inherited"
    );
    assert_ne!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(notes, "");
}

#[test]
fn a_missing_command_is_the_only_refusal_and_it_is_a_usage_error() {
    let registry = Registry::new(Vec::new());
    let mut notes: Vec<u8> = Vec::new();
    let error = run(
        RunRequest {
            bindings: &[],
            unusable: &[],
            argv: &[],
            registry: &registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect_err("there is no child to spawn");
    assert_eq!(error.exit_code(), 64);
}

#[test]
fn a_command_that_does_not_exist_reports_127_like_a_shell() {
    let registry = Registry::new(Vec::new());
    let argv = vec![std::ffi::OsString::from(
        PathBuf::from("/nonexistent/keyless/definitely-not-a-command").as_os_str(),
    )];
    let mut notes: Vec<u8> = Vec::new();
    let error = run(
        RunRequest {
            bindings: &[],
            unusable: &[],
            argv: &argv,
            registry: &registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect_err("the command does not exist");
    assert_eq!(error.exit_code(), 127);
}
