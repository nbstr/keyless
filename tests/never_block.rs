//! The never-block invariant, proved rather than asserted in prose.
//!
//! The requirement is absolute and it decides every trade-off below: **a
//! degraded `keyless` must never stop the command it wraps.** An agent session
//! that is blocked is worse than one that runs without a secret, so every
//! failure in this file costs a degrade and never the child.
//!
//! Five failures are meant to be survivable, and each gets a test that checks
//! the same three things: the child **ran**, the child's **exit code came
//! back**, and the child's **environment was not modified**. The third is what
//! separates this from "we caught the error" — a degraded run must not hand the
//! child a half-built environment.
//!
//! The fourth is the one where `keyless` declines to *ask*: a backend whose
//! required coordinate is missing is not queried at all, because guessing one
//! resolves a name against the wrong tenant. Declining to guess must still cost
//! a degrade rather than the command.
//!
//! The fifth — a pseudo-terminal that cannot be allocated — is the odd one out
//! and asserts the environment *was* modified. Losing a terminal is a loss of
//! comfort, not of trust: there is no reason to withhold a secret that resolved
//! perfectly well just because the output will not be coloured.
//!
//! One answer marks the boundary and is not a failure at all: a healthy store
//! that has never heard of the name. That run is refused — the child never
//! starts — because running it would hide a wrong name inside the child.
//!
//! An audit of 20+ competing tools found not one that degrades instead of
//! failing closed. That is the gap these tests defend.

mod support;

use keyless::State;
use keyless::cmd::run::TtyPolicy;
use keyless::config::{Config, Policy};
use keyless::store::keychain::KeychainStore;
use keyless::store::{self, Invocation, Registry};

use support::always_errors::AlwaysErrors;
use support::{
    Backend, DECOY_VALUE, Stub, run_with, run_with_tty, scratch, stub_infisical, stub_security,
    witness, witnessed,
};

// ---------------------------------------------------------------------------
// Property 1 of 5: the store cannot be reached at all.
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
// The boundary: the store is healthy and has never heard of the name.
// ---------------------------------------------------------------------------

#[test]
fn name_not_found_refuses_the_run_and_never_spawns_the_child() {
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

    assert!(!marker.exists(), "the child started: {notes}");
    assert_eq!(outcome.exit_code, 64);
    assert_eq!(outcome.state, State::Refused);
    assert_eq!(outcome.unresolved.len(), 2);
    // The exact banner shape the design calls for.
    assert!(
        notes.contains("keyless: REFUSED — 2 of 2 names refused; the command was not run"),
        "banner was: {notes}"
    );
}

// ---------------------------------------------------------------------------
// Property 2 of 5: the config file is unparseable.
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
        config.stores.keychain.binary = stub_security(&dir, &Stub::Errors).into();
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
// Property 3 of 5: every configured backend errors.
// ---------------------------------------------------------------------------

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
// Property 4 of 5: a coordinate the backend requires is missing.
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
// Property 5 of 5: a pseudo-terminal cannot be allocated.
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
