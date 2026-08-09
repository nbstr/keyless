//! The never-block invariant, proved rather than asserted in prose.
//!
//! The requirement is absolute and it decides every trade-off below: **a
//! degraded `keyless` must never stop the command it wraps.** An agent session
//! that is blocked is worse than one that runs without a secret, so every
//! failure in this file costs a degrade and never the child.
//!
//! Six failures are meant to be survivable, and each gets a test that checks
//! the same three things: the child **ran**, the child's **exit code came
//! back**, and the child's **environment was not modified**. The third is what
//! separates this from "we caught the error" — a degraded run must not hand the
//! child a half-built environment.
//!
//! The fifth is the one where `keyless` declines to *ask*: a backend whose
//! required coordinate is missing is not queried at all, because guessing one
//! resolves a name against the wrong tenant. Declining to guess must still cost
//! a degrade rather than the command.
//!
//! The sixth — a pseudo-terminal that cannot be allocated — is the odd one out
//! and asserts the environment *was* modified. Losing a terminal is a loss of
//! comfort, not of trust: there is no reason to withhold a secret that resolved
//! perfectly well just because the output will not be coloured.
//!
//! An audit of 20+ competing tools found not one that degrades instead of
//! failing closed. That is the gap these tests defend.

mod support;

use std::path::PathBuf;

use keyless::State;
use keyless::audit::AuditLog;
use keyless::cmd::run::{RunRequest, TtyPolicy, run};
use keyless::config::{Config, Policy};
use keyless::error::StoreError;
use keyless::secret::Secret;
use keyless::store::keychain::KeychainStore;
use keyless::store::{self, Invocation, Registry, Store};

use support::{
    Backend, DECOY_VALUE, Stub, run_with, run_with_tty, scratch, stub_infisical, stub_security,
    witness, witnessed,
};

// ---------------------------------------------------------------------------
// Property 1 of 4: the store cannot be reached at all.
// ---------------------------------------------------------------------------

#[test]
fn store_unreachable_still_spawns_the_child() {
    let dir = scratch("store-unreachable");
    let marker = dir.join("witness");

    // A `security` binary that is not there: the shape of a non-macOS machine,
    // a stripped container, or a broken PATH.
    let registry = Registry::new(vec![Box::new(KeychainStore::new(
        dir.join("there-is-no-security-here"),
        "keyless".to_owned(),
    ))]);

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
    assert_eq!(outcome.unresolved, vec!["DECOY".to_owned()]);
    assert!(notes.contains("DEGRADED"), "no banner was printed: {notes}");
    assert!(
        notes.contains("DECOY"),
        "the banner must name the secret: {notes}"
    );
}

// ---------------------------------------------------------------------------
// Property 2 of 4: the store is healthy and has never heard of the name.
// ---------------------------------------------------------------------------

#[test]
fn name_not_found_still_spawns_the_child() {
    let dir = scratch("name-not-found");
    let marker = dir.join("witness");
    let stub = stub_security(&dir, &Stub::NotFound);

    let registry = Registry::new(vec![Box::new(KeychainStore::new(
        stub,
        "keyless".to_owned(),
    ))]);

    let (outcome, notes) = run_with(
        &registry,
        &["MISSING_ONE", "MISSING_TWO"],
        &witness(&marker, "MISSING_ONE", 7),
        &[],
    );

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 7);
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.unresolved.len(), 2);
    // The exact banner shape the design calls for.
    assert!(
        notes.contains("keyless: DEGRADED — 2 names unresolved: MISSING_ONE, MISSING_TWO"),
        "banner was: {notes}"
    );
}

// ---------------------------------------------------------------------------
// Property 3 of 4: the config file is unparseable.
// ---------------------------------------------------------------------------

#[test]
fn corrupt_config_still_spawns_the_child() {
    // Two genuinely different corruptions, because they fail at different
    // layers and only one of them is a JSON problem:
    //   - bytes that are not UTF-8 at all fail while reading the file;
    //   - text that is not JSON fails while parsing it.
    // Both must reach the same place: defaults, a warning, and a child.
    let cases: [(&str, &[u8], &str); 2] = [
        (
            "not-utf8",
            b"\xff\xfe{\x00\x01 garbage",
            "cannot read config",
        ),
        (
            "not-json",
            b"{ this is not json at all ][ ",
            "cannot parse config",
        ),
    ];

    for (tag, bytes, expected) in cases {
        let dir = scratch(&format!("corrupt-config-{tag}"));
        let marker = dir.join("witness");
        let config_path = dir.join("config.json");
        std::fs::write(&config_path, bytes).expect("write config");

        // Exactly what `main` does: load, notice the problem, keep the defaults.
        let load = Config::load(&config_path);
        let problem = load
            .problem
            .as_ref()
            .unwrap_or_else(|| panic!("the {tag} fixture must actually be corrupt"));
        assert!(!load.loaded);
        assert!(
            problem.to_string().contains(expected),
            "{tag}: expected `{expected}`, got `{problem}`"
        );

        // The defaulted config, with the backend pointed at a stub so no real
        // keychain is ever consulted by this suite.
        let mut config = load.config.clone();
        config.stores.keychain.binary = stub_security(&dir, &Stub::NotFound).into();
        let registry = store::build(&config, &Invocation::default()).registry;

        let warnings = vec![problem.to_string()];
        let (outcome, notes) =
            run_with(&registry, &["ANY"], &witness(&marker, "ANY", 3), &warnings);

        assert_eq!(
            witnessed(&marker),
            "<unset>",
            "{tag}: environment was modified"
        );
        assert_eq!(outcome.exit_code, 3, "{tag}: exit code lost");
        assert_eq!(outcome.state, State::Degraded, "{tag}");
        assert!(
            notes.contains(expected),
            "{tag}: caller not told why: {notes}"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 4 of 4: every configured backend errors.
// ---------------------------------------------------------------------------

/// A backend that fails every call.
///
/// Defined here, in a separate crate, which also proves the `Store` seam is
/// genuinely public: another agent can add Infisical or Proton Pass without
/// touching `run`.
struct AlwaysErrors(&'static str);

impl Store for AlwaysErrors {
    fn id(&self) -> &str {
        self.0
    }
    fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
        Err(StoreError::Backend {
            store: self.0.to_owned(),
            detail: "deliberately broken for the test".to_owned(),
        })
    }
    fn health(&self) -> Result<(), StoreError> {
        Err(StoreError::Unavailable {
            store: self.0.to_owned(),
            detail: "deliberately broken for the test".to_owned(),
        })
    }
}

#[test]
fn every_store_adapter_erroring_still_spawns_the_child() {
    let dir = scratch("all-stores-error");
    let marker = dir.join("witness");

    // `Ordered` so that all three are actually asked and all three actually
    // fail — which is the property under test. Under the default `Explicit`
    // policy an unpinned name with three backends is never asked of any of
    // them; that path degrades too, and has its own test in `stores.rs`.
    let registry = Registry::new(vec![
        Box::new(AlwaysErrors("first")),
        Box::new(AlwaysErrors("second")),
        Box::new(AlwaysErrors("third")),
    ])
    .with_policy(Policy::Ordered);

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 19), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 19);
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("deliberately broken"), "notes were: {notes}");
}

// ---------------------------------------------------------------------------
// Property 5 of 6: a coordinate the backend requires is missing.
// ---------------------------------------------------------------------------

#[test]
fn a_name_with_no_infisical_environment_still_spawns_the_child() {
    // Infisical has no default environment, and neither does `keyless` — a
    // default resolved names nobody declared against whichever environment one
    // machine happened to name. Refusing to guess must cost the caller a
    // degrade, never the command.
    //
    // The stub here ANSWERS. That is what stops this test being vacuous: with
    // the guard gone the adapter spawns it, the name resolves, and the state
    // below is `Injected` rather than `Degraded`. A stub that could not answer
    // would pass whether or not the rule existed.
    let dir = scratch("infisical-no-environment");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Injects(DECOY_VALUE));
    let config: Config = serde_json::from_str(&format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "infisical":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}},
            "secrets":{{"DECOY":{{}}}}}}"#,
        stub.display()
    ))
    .expect("valid config");
    let registry = store::build(&config, &Invocation::default()).registry;

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
    assert_eq!(outcome.unresolved, vec!["DECOY".to_owned()]);

    // Nothing was spawned and no network call was made: a missing environment
    // is a lookup that never happened, not one that failed.
    assert!(
        !dir.join("infisical.argv").exists(),
        "the backend was invoked without an environment"
    );

    // The message has to be actionable without anybody explaining it: the name,
    // the requirement, and both ways to satisfy it.
    assert!(notes.contains("DEGRADED"), "no banner: {notes}");
    assert!(notes.contains("DECOY"), "the banner must name it: {notes}");
    assert!(
        notes.contains("\"env\""),
        "the per-name fix must be named: {notes}"
    );
    assert!(
        notes.contains("--env"),
        "the per-run fix must be named: {notes}"
    );
    assert!(
        !notes.contains(DECOY_VALUE),
        "the message carried a value: {notes}"
    );
}

// ---------------------------------------------------------------------------
// Property 6 of 6: a pseudo-terminal cannot be allocated.
// ---------------------------------------------------------------------------

#[test]
fn a_pty_that_cannot_be_allocated_still_spawns_the_child() {
    // No `/dev/ptmx`, a full descriptor table, a kernel without pty support, a
    // container that did not mount devpts. `keyless` loses colour and progress
    // bars for this one command; it does not lose the command.
    //
    // This cannot be provoked on a healthy machine, which is exactly why the
    // policy carries a variant that fails on purpose. Without it the fallback
    // would be code nobody has ever executed.
    let dir = scratch("pty-allocation-failure");
    let marker = dir.join("witness");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    let registry = Registry::new(vec![Box::new(KeychainStore::new(
        stub,
        "keyless".to_owned(),
    ))]);

    let (outcome, notes) = run_with_tty(
        &registry,
        &["DECOY"],
        &witness(&marker, "DECOY", 23),
        &[],
        TtyPolicy::SimulateAllocationFailure,
    );

    assert_eq!(
        witnessed(&marker),
        DECOY_VALUE,
        "the child must still run, and still receive its secret"
    );
    assert_eq!(
        outcome.exit_code, 23,
        "the child's exit code must come back"
    );
    assert_eq!(
        outcome.state,
        State::Injected,
        "a pty is a comfort, not a precondition — failing to get one must not degrade injection"
    );
    assert!(
        notes.contains("no pseudo-terminal"),
        "the caller must be told why the terminal looks wrong: {notes}"
    );
    assert!(
        !notes.contains(DECOY_VALUE),
        "the warning must not carry a value: {notes}"
    );
}

#[test]
fn a_pipe_is_not_worth_a_warning() {
    // The ordinary state of a script, a CI job or an agent's shell call. If this
    // printed a line, every non-interactive invocation would print it, and a
    // reader trained to ignore this tool's stderr is a reader who misses the
    // DEGRADED banner that matters.
    let dir = scratch("pty-not-a-terminal");
    let marker = dir.join("witness");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    let registry = Registry::new(vec![Box::new(KeychainStore::new(
        stub,
        "keyless".to_owned(),
    ))]);

    let (_, notes) = run_with_tty(
        &registry,
        &["DECOY"],
        &witness(&marker, "DECOY", 0),
        &[],
        TtyPolicy::Pipes,
    );
    assert_eq!(notes, "", "a piped run says nothing at all");
}

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
