//! The network-backed backends, and the rule that picks between them.
//!
//! Three properties, each of which the rest of the tool's design depends on:
//!
//! 1. **A backend that is absent, broken, or hung still lets the command run.**
//!    This is the never-block invariant, extended to a store that can fail in
//!    ways a local one cannot — no network, an expired token, a connection that
//!    is accepted and then never answered. An audit of 20+ competing tools
//!    found not one that degrades instead of failing closed, and a network
//!    store is exactly where that property is easiest to lose.
//! 2. **A name never silently resolves to the wrong store's value.**
//! 3. **The invocation uses only the vendor verb that prints nothing**, carries
//!    a reason that contains no argument value, and switches off telemetry the
//!    user did not ask for.
//!
//! # What is faked, and what that is worth
//!
//! Both CLIs are exercised against stubs written in `support`, and both stubs
//! now encode behaviour that was **measured** rather than read: Infisical
//! against 0.43.114 — the flags it accepts, that its stdout is byte-for-byte
//! the child's, and the exact stderr wording that distinguishes an unset
//! variable from a failure of its own — and Proton Pass against `pass-cli`
//! 2.2.5 on 2026-08-08, including the `run --env-file … --no-masking --`
//! spelling, the `pass://SHARE_ID/ITEM_ID/FIELD` reference format, and that
//! `PROTON_PASS_SESSION_DIR` selects which logged-in identity answers.
//!
//! A stub is still a stub: it proves the adapter builds the invocation the CLI
//! accepts, not that the account behind it answers. The live path is covered by
//! `proton_live.rs`, which is opt-in because it needs a real account.

mod support;

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use keyless::State;
use keyless::config::Config;
use keyless::store::proton::Reason;
use keyless::store::{self, Invocation, Registry};

use support::{
    Backend, CONCEALED, INFISICAL_DECOY, Listing, NEIGHBOUR_KEY, PROTON_DECOY, SCOPED_SESSION_DIR,
    listing_count, recorded, recorded_lines, run_with, scratch, stub_infisical, stub_pass_cli,
    stub_pass_cli_discovery, stub_pass_cli_listing, witness, witness_env, witnessed, witnessed_env,
};

/// Whether `argv` carries `flag`, in either of the two spellings clap accepts.
///
/// Written once because the adapter now joins every option to its value with
/// `=`. A check for the bare string would silently stop biting on the joined
/// form — a forbidden flag would slip through a test that still reads as a
/// guard, which is the exact failure shape these tests exist to catch.
fn mentions(argv: &[String], flag: &str) -> bool {
    argv.iter()
        .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
}

/// Build a registry from a JSON config, as `main` does.
fn registry_from(json: &str, reason: &Reason) -> Registry {
    let config: Config = serde_json::from_str(json).expect("the test config must be valid");
    store::build(
        &config,
        &Invocation {
            reason: reason.clone(),
            infisical_env: None,
        },
    )
    .registry
}

/// A config with only Infisical enabled, pointed at a stub.
///
/// `DECOY` declares its own environment, because there is no config-level
/// default and a name without one is never looked up. Leaving it off would make
/// every property below pass against a store that never spawned anything —
/// which is exactly the vacuous green this file exists to avoid. The tests that
/// are *about* a missing environment build their own config.
fn infisical_config(binary: &Path) -> String {
    infisical_config_for(binary, r#""DECOY":{"env":"dev"}"#)
}

/// The same, with the `secrets` block written out by the caller.
///
/// # The ceiling is spelled here, and it used to be spelled nowhere
///
/// Every fixture built from this one wants an ANSWER, so each needs a deadline
/// the stub can finish inside. Naming none does not mean "no deadline": it
/// means the crate's own `DEFAULT_TIMEOUT_MS`, which is 10 000 — HALF the floor
/// `tests/suite_hygiene.rs` sets for a ceiling on a stub that must answer.
///
/// That gate reads `"timeout_ms":<digits>` out of these config strings, so a
/// number nobody wrote is a number it cannot scan: the eleven fixtures built
/// from here sat under an unwritten 10 000 while the gate reported green. The
/// identical remediation had already reached `tests/cli.rs`,
/// `tests/never_block.rs` and this file's own Proton call sites, beside the
/// identical stub — and missed this builder. That is the drift the gate exists
/// to prevent, arriving through the one spelling it cannot read.
///
/// It is a CEILING and never a measurement — no fixture here asserts anything
/// about elapsed time. A test whose SUBJECT is the deadline writes its own
/// config rather than taking this one, because two `timeout_ms` keys in one
/// object are a serde error and because a deadline under test is not a bound on
/// a test.
fn infisical_config_for(binary: &Path, secrets: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "infisical":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}},
            "secrets":{{{secrets}}}}}"#,
        binary.display()
    )
}

/// A config with only Proton enabled, pointed at a stub.
///
/// `session_dir` is set in every one of these, because without it the adapter
/// degrades before it spawns anything and every property below would be
/// exercised against a store that never ran. The tests that are *about* an
/// unset session directory build their own config.
///
/// # The ceiling, and why it moved from the call sites into here
///
/// `"timeout_ms":60000` is a ceiling, never a measurement: a fixture asserting
/// a SUCCESS has no opinion about how long the stub took. So the only thing the
/// number decides is how loaded this machine has to be before a passing test
/// reports a failure.
///
/// It was 5000, which encoded "no fork of `/bin/sh` is ever slower than five
/// seconds". Measured 2026-08-09: with a `cargo mutants` campaign running
/// beside the suite at `--jobs 2`, six fixtures failed with `no answer within
/// 5000 ms`, and all of them passed the moment the suite ran alone. That is a
/// false RED, and mutation testing turns a false red into a wrong baseline — a
/// mutant a flake killed is recorded as caught, and the next clean run reports
/// it as a new survivor.
///
/// The repair then left the number at seven call sites for each caller to
/// remember. It is written once, here, for the same reason
/// `tests/suite_hygiene.rs` exists at all: a number that has to be remembered
/// is a number that drifts back.
fn proton_config(binary: &Path) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","session_dir":"{SCOPED_SESSION_DIR}","timeout_ms":60000}}}},
            "secrets":{{"DECOY":{{"reference":"{PROTON_REFERENCE}"}}}}}}"#,
        binary.display()
    )
}

/// A reference in the format the real CLI accepts: `pass://SHARE_ID/ITEM_ID/FIELD`.
///
/// Shortened here — the live ids are 88-character base64 — but the *shape* is
/// the vendor's, and it is opaque ids rather than human vault and item names.
const PROTON_REFERENCE: &str = "pass://ShAr3Id0decoy==/It3mId0decoy==/password";

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

// ---------------------------------------------------------------------------
// The happy paths.
// ---------------------------------------------------------------------------

#[test]
fn an_infisical_value_reaches_the_child_and_nothing_else() {
    let dir = scratch("infisical-happy");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let registry = registry_from(&infisical_config(&stub), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(witnessed(&marker), INFISICAL_DECOY, "the child must see it");
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(outcome.injected, vec!["DECOY".to_owned()]);
    assert_eq!(notes, "", "a successful run says nothing at all");
}

#[test]
fn a_proton_value_reaches_the_child_and_nothing_else() {
    let dir = scratch("proton-happy");
    let marker = dir.join("witness");
    let stub = stub_pass_cli(&dir, &Backend::Injects(PROTON_DECOY));
    let registry = registry_from(&proton_config(&stub), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(notes, "");

    // The reference reached the CLI through the env file, and the env file is
    // gone. Checked from the stub's side, so it is the interface being tested
    // rather than the adapter's own bookkeeping.
    assert_eq!(
        recorded(&dir.join("pass-cli.reference")).trim(),
        PROTON_REFERENCE
    );

    // And it ran as the identity the config named, not as whatever the machine
    // was last logged into. Read from the stub's own environment, so an adapter
    // that exported nothing records `<unset>` and fails here.
    assert_eq!(
        recorded(&dir.join("pass-cli.session")),
        SCOPED_SESSION_DIR,
        "the lookup inherited the ambient Proton session"
    );

    // `--env-file=<path>`, one argument. Every value this adapter passes is
    // joined to its flag, because the vendor's parser reads a value that begins
    // with `-` as a cluster of short flags, and `TMPDIR` decides this one.
    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    let env_file = argv
        .iter()
        .find_map(|arg| arg.strip_prefix("--env-file="))
        .expect("the reference must travel in an env file");
    assert!(
        !Path::new(env_file).exists(),
        "the probe env file outlived the lookup: {env_file}"
    );
}

#[test]
fn an_unset_name_is_reported_as_missing_rather_than_as_a_broken_store() {
    // Measured: the CLI reports a non-zero child as `failed to wait for command
    // termination: exit status N`, and its own failures carry different
    // wording. Getting this backwards sends a user hunting a broken login when
    // the secret is simply at another path.
    let dir = scratch("infisical-unset");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Unset);
    let registry = registry_from(&infisical_config(&stub), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 4), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.exit_code, 4);
    assert!(
        notes.contains("not found in any store"),
        "an unset name must read as absent, not as a failure: {notes}"
    );
    assert!(
        !notes.contains("exit status"),
        "vendor noise reached the user"
    );
}

#[test]
fn an_empty_value_is_a_problem_rather_than_a_silent_blank() {
    // Injecting an empty string is worse than degrading: the command runs, the
    // credential is blank, and the failure surfaces somewhere else entirely.
    let dir = scratch("infisical-empty");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Empty);
    let registry = registry_from(&infisical_config(&stub), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(witnessed(&marker), "<unset>");
    assert!(notes.contains("empty"), "{notes}");
}

// ---------------------------------------------------------------------------
// The invocation itself.
// ---------------------------------------------------------------------------

#[test]
fn the_infisical_invocation_uses_only_the_verb_that_prints_nothing() {
    // Read off the stub's own record of what it was called with, not off the
    // adapter's list of flags. `infisical secrets`, `infisical secrets get` and
    // `infisical export` all write plaintext to stdout and are denied at the
    // harness level; an adapter that reached for one would be the way around
    // that denial.
    let dir = scratch("infisical-argv");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let registry = registry_from(
        &infisical_config_for(&stub, r#""DECOY":{"env":"staging","path":"/backend"}"#),
        &Reason::default(),
    );
    let _ = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    let argv = recorded_lines(&dir.join("infisical.argv"));
    assert_eq!(argv.first().map(String::as_str), Some("run"));
    for forbidden in ["secrets", "export", "get", "reveal", "--command", "-c"] {
        assert!(
            !argv.iter().any(|arg| arg == forbidden),
            "`{forbidden}` was passed: {argv:?}"
        );
    }

    // The coordinates the config asked for, and the probe after the separator.
    assert!(argv.iter().any(|arg| arg == "--env=staging"));
    assert!(argv.iter().any(|arg| arg == "--path=/backend"));
    let separator = argv
        .iter()
        .position(|arg| arg == "--")
        .expect("the child command must be separated");
    assert!(argv[separator + 1].ends_with("printenv"));
    assert_eq!(argv.get(separator + 2).map(String::as_str), Some("DECOY"));
}

/// The same registry, plus the environment `keyless run --env <slug>` supplied.
fn registry_from_with_env(json: &str, env: &str) -> Registry {
    let config: Config = serde_json::from_str(json).expect("the test config must be valid");
    store::build(
        &config,
        &Invocation::default().with_infisical_env(Some(env.to_owned())),
    )
    .registry
}

#[test]
fn the_invocation_environment_reaches_the_vendor_call() {
    // `--env` is the second of the two places an environment may come from, and
    // it has to arrive as the vendor's own mandatory flag rather than as
    // anything this crate invented. Read off the stub's record of its argv.
    let dir = scratch("infisical-invocation-env");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let registry = registry_from_with_env(&infisical_config_for(&stub, r#""DECOY":{}"#), "staging");

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(outcome.state, State::Injected, "notes: {notes}");
    assert_eq!(witnessed(&marker), INFISICAL_DECOY);
    let argv = recorded_lines(&dir.join("infisical.argv"));
    assert!(
        argv.iter().any(|arg| arg == "--env=staging"),
        "the invocation environment did not reach the CLI: {argv:?}"
    );
}

#[test]
fn a_names_own_environment_beats_the_invocation_environment() {
    // Precedence, proved on the wire. A blanket `--env` exists for the names
    // that say nothing; a name that states where it lives must not be repainted
    // by it, or `--env staging` on a run that also touches a production-pinned
    // name would quietly move that name too.
    let dir = scratch("infisical-env-precedence");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let registry = registry_from_with_env(
        &infisical_config_for(&stub, r#""DECOY":{"env":"prod"}"#),
        "staging",
    );

    let _ = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    let argv = recorded_lines(&dir.join("infisical.argv"));
    assert!(
        argv.iter().any(|arg| arg == "--env=prod"),
        "the name's own environment was lost: {argv:?}"
    );
    assert!(
        !argv.iter().any(|arg| arg == "--env=staging"),
        "the flag overrode a name that declared its own environment: {argv:?}"
    );
}

#[test]
fn a_stale_config_level_environment_is_ignored_and_named() {
    // `stores.infisical.env` used to be a machine-wide default. It is read by
    // nothing now, and a config that still carries it is told which line to
    // delete — unknown keys are dropped silently by design, so without this the
    // reader would see names stop resolving and nothing connecting the two.
    let dir = scratch("infisical-stale-env");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    // Its own config: the stale `stores.infisical.env` key is the SUBJECT, and
    // the shared builder deliberately does not carry a key it exists to warn
    // about. The ceiling is spelled here for the same reason it is spelled
    // there — the lookup below must get an answer.
    let config: Config = serde_json::from_str(&format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "infisical":{{"enabled":true,"binary":"{}","env":"prod","timeout_ms":60000}}}},
            "secrets":{{"DECOY":{{}}}}}}"#,
        stub.display()
    ))
    .expect("valid config");
    let built = store::build(&config, &Invocation::default());

    assert!(
        built
            .warnings
            .iter()
            .any(|w| w.contains("stores.infisical.env") && w.contains("IGNORED")),
        "the stale key was not reported: {:?}",
        built.warnings
    );

    let (outcome, _) = run_with(
        &built.registry,
        &["DECOY"],
        &witness(&marker, "DECOY", 5),
        &built.warnings,
    );

    // Ignored means ignored: the name does not resolve, and the backend is not
    // spawned to find out.
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(witnessed(&marker), "<unset>");
    assert!(
        !dir.join("infisical.argv").exists(),
        "the stale key supplied an environment after all"
    );
}

#[test]
fn the_infisical_invocation_switches_off_telemetry_and_pins_the_log_stream() {
    // `keyless` promises it makes no network call the user did not ask for.
    // The vendor CLI's telemetry defaults to ON, so shelling out with default
    // flags would break that promise through a subprocess.
    //
    // The log destination is pinned for a different reason: the CLI also reads
    // it from LOG_DESTINATION, and a value of `stdout` there would interleave
    // log lines with the value being read.
    let dir = scratch("infisical-flags");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let registry = registry_from(&infisical_config(&stub), &Reason::default());
    let _ = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    let argv = recorded_lines(&dir.join("infisical.argv"));
    assert!(
        argv.iter().any(|arg| arg == "--telemetry=false"),
        "telemetry was left on: {argv:?}"
    );
    assert!(argv.iter().any(|arg| arg == "--log-destination=stderr"));
    assert!(argv.iter().any(|arg| arg == "--silent"));
}

#[test]
fn every_proton_read_carries_a_reason_that_names_the_command() {
    let dir = scratch("proton-reason");
    let marker = dir.join("witness");
    let stub = stub_pass_cli(&dir, &Backend::Injects(PROTON_DECOY));
    let registry = registry_from(
        &proton_config(&stub),
        &Reason::for_run(&witness(&marker, "DECOY", 0)),
    );
    let _ = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    let reason = recorded(&dir.join("pass-cli.reason"));
    assert!(!reason.trim().is_empty(), "an empty reason is refused");
    assert!(reason.len() <= 300, "the vendor caps it at 300 characters");
    assert!(
        reason.contains("DECOY"),
        "the reason must say what it wanted"
    );
    assert!(reason.contains("sh"), "the reason must say who wanted it");
}

#[test]
fn the_proton_reason_never_carries_an_argument_value() {
    // An argument vector is where every shape this tool exists to remove ends
    // up. A reason is assembled before
    // anything has resolved — so there is nothing to redact it with — and is
    // then sent to a vendor and stored. Putting argv in it would forward the
    // exact leak this tool exists to prevent, under a field labelled "reason".
    let leaked = "decoy-Zx91-typed-on-the-command-line-0042";
    let dir = scratch("proton-reason-argv");
    let stub = stub_pass_cli(&dir, &Backend::Injects(PROTON_DECOY));

    let argv: Vec<OsString> = ["/bin/echo", "--token", leaked]
        .iter()
        .map(OsString::from)
        .collect();
    let registry = registry_from(&proton_config(&stub), &Reason::for_run(&argv));
    let _ = run_with(&registry, &["DECOY"], &argv, &[]);

    let reason = recorded(&dir.join("pass-cli.reason"));
    assert!(
        !reason.contains(leaked),
        "the reason sent an argument value to the vendor: {reason}"
    );
    assert!(!reason.contains("--token"), "reason: {reason}");
    assert!(reason.contains("echo"), "reason: {reason}");
}

#[test]
fn a_concealed_value_is_refused_rather_than_injected() {
    // The vendor masks its own child's output by default, substituting
    // `<concealed by Proton Pass>`. The probe reads that child's output, so if
    // `--no-masking` were ever dropped or ignored the adapter would inject the
    // placeholder as though it were the credential — and the command would fail
    // later, somewhere else, with an authentication error nobody could explain.
    let dir = scratch("proton-concealed");
    let marker = dir.join("witness");
    let stub = stub_pass_cli(&dir, &Backend::Concealed);
    let registry = registry_from(&proton_config(&stub), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 6), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert_ne!(
        witnessed(&marker),
        CONCEALED,
        "the placeholder was injected as though it were a credential"
    );
    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 6);
    assert!(notes.contains("concealed"), "{notes}");
}

// ---------------------------------------------------------------------------
// The name form: a stable address, resolved to this session's ids at lookup.
//
// A share id is minted per session — measured 2026-08-08, one vault answered
// with two different ids to two live sessions of one account — so an address
// made of ids cannot survive a token renewal. These cover the address that can:
// vault name, item title, field. Every one runs through `run`, so the
// never-block invariant is asserted alongside the rule, and a rule that
// "refuses" is checked by the CLI's `run` verb never being spawned at all.
// ---------------------------------------------------------------------------

/// A vault listing in the vendor's shape, measured 2026-08-08.
///
/// Written out by hand rather than generated: a fixture built from the
/// adapter's own idea of the record would agree with it whatever that became.
/// The item id is under `id`; there is no `item_id` key.
const ONE_LIVE_ITEM: &str = r#"{"items":[
    {"id":"It3mL1v3","share_id":"ShAr3L1v3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"}]}"#;

/// The same vault, with the only matching item in the trash.
const ONE_TRASHED_ITEM: &str = r#"{"items":[
    {"id":"It3mDead","share_id":"ShAr3L1v3","vault_id":"V","state":"Trashed","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"}]}"#;

/// Two live items sharing one title, plus a trashed third that must not count.
const TWO_LIVE_ITEMS: &str = r#"{"items":[
    {"id":"It3mOne","share_id":"ShAr3L1v3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"},
    {"id":"It3mTwo","share_id":"ShAr3L1v3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-02T00:00:00","modify_time":"2000-01-02T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"},
    {"id":"It3mDead","share_id":"ShAr3L1v3","vault_id":"V","state":"Trashed","flags":[],
     "create_time":"2000-01-03T00:00:00","modify_time":"2000-01-03T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"}]}"#;

/// A config whose names are addressed by vault, title and field.
fn named_config(binary: &Path, secrets: &str) -> String {
    named_config_extra(binary, secrets, "")
}

/// The same, with `proton_extra` spliced into the `stores.proton` block.
///
/// Written as raw JSON rather than as a typed builder so the tests below state
/// the file an operator writes, which is the only form this crate promises.
fn named_config_extra(binary: &Path, secrets: &str, proton_extra: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","session_dir":"{SCOPED_SESSION_DIR}",
                        "timeout_ms":60000{proton_extra}}}}},
            "secrets":{secrets}}}"#,
        binary.display()
    )
}

/// The one name most fixtures below declare, addressed by name.
const DECOY_BY_NAME: &str =
    r#"{"DECOY":{"vault":"personal","item":"keyless-decoy-alpha","field":"password"}}"#;

#[test]
fn a_named_item_is_addressed_by_the_ids_this_session_minted() {
    // The whole point: nothing in the config holds an id, and the reference the
    // CLI receives holds the ones the listing just reported.
    let dir = scratch("proton-named");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_LIVE_ITEM),
    );
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(notes, "", "a successful run says nothing at all");
    assert_eq!(
        recorded(&dir.join("pass-cli.reference")).trim(),
        "pass://ShAr3L1v3/It3mL1v3/password",
        "the reference was not built from the listing this session returned"
    );

    // The listing asked for the vault the config named, and asked for nothing
    // that could print content.
    let list_argv = recorded_lines(&dir.join("pass-cli.list.argv"));
    assert!(
        list_argv.iter().any(|arg| arg == "--vault-name=personal"),
        "{list_argv:?}"
    );
    assert!(
        !list_argv.iter().any(|arg| arg == "--show-secrets"),
        "{list_argv:?}"
    );
}

#[test]
fn a_trashed_item_never_resolves_and_the_command_still_runs() {
    // Resolving one would hand the child a value its owner believes they
    // deleted — and silently, since a trashed item is still listed. The `run`
    // verb must never be reached.
    let dir = scratch("proton-trashed");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_TRASHED_ITEM),
    );
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 17), &[]);

    assert_eq!(witnessed(&marker), "<unset>", "a trashed item was injected");
    assert_eq!(
        outcome.exit_code, 17,
        "the child's exit code must come back"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("DECOY"), "{notes}");
    assert!(notes.contains("trash"), "the banner must say why: {notes}");
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "the value of a trashed item was read before it was refused"
    );
}

#[test]
fn two_live_items_with_one_title_degrade_and_name_the_candidates() {
    // The house rule for ambiguity: refuse and name the candidates, exactly as
    // `Policy::Explicit` does for two backends answering one name. Picking the
    // first would be right half the time and silent the other half.
    let dir = scratch("proton-ambiguous");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(TWO_LIVE_ITEMS),
    );
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 23), &[]);

    assert_eq!(witnessed(&marker), "<unset>", "an ambiguous title resolved");
    assert_eq!(outcome.exit_code, 23);
    assert_eq!(outcome.state, State::Degraded);
    for candidate in ["It3mOne", "It3mTwo"] {
        assert!(notes.contains(candidate), "{candidate} unnamed: {notes}");
    }
    assert!(
        !notes.contains("It3mDead"),
        "a trashed twin was counted as a candidate: {notes}"
    );
    assert!(
        notes.contains("reference"),
        "the banner must say how to pin one: {notes}"
    );
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "an ambiguous name was read from anyway"
    );
}

#[test]
fn a_title_that_is_in_no_vault_degrades_and_still_runs() {
    // The negative control for the three above: with an empty listing they
    // could all pass on an adapter that never resolves anything at all.
    let dir = scratch("proton-no-such-item");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(&dir, &Backend::Injects(PROTON_DECOY), &Listing::EMPTY);
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 11), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 11);
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("keyless-decoy-alpha"), "{notes}");
    assert!(
        !notes.contains("trash"),
        "nothing was in the trash: {notes}"
    );
}

#[test]
fn a_vault_the_session_cannot_list_degrades_and_still_runs() {
    // An expired token, a renamed vault, a grant that was revoked. Measured
    // 2026-08-08: the CLI exits 1 and says `Could not find vault <name>`.
    let dir = scratch("proton-no-such-vault");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(&dir, &Backend::Injects(PROTON_DECOY), &Listing::NoSuchVault);
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 13), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 13);
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("personal"),
        "the banner must name the vault: {notes}"
    );
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a value was read out of a vault that could not even be listed"
    );
}

#[test]
fn declaring_both_an_address_and_a_reference_degrades_without_spawning_anything() {
    // Two answers to one question. Refused before anything runs, so the
    // ambiguity costs no vault read and leaves no audit entry.
    let dir = scratch("proton-both-forms");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_LIVE_ITEM),
    );
    let secrets = format!(
        r#"{{"DECOY":{{"vault":"personal","item":"keyless-decoy-alpha","field":"password",
                       "reference":"{PROTON_REFERENCE}"}}}}"#
    );
    let registry = registry_from(&named_config(&stub, &secrets), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 31), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 31);
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("reference") && notes.contains("vault"),
        "the banner must name both forms so one can be deleted: {notes}"
    );
    assert_eq!(listing_count(&dir), 0, "a vault was enumerated anyway");
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a doubly-declared address was read from anyway"
    );
}

#[test]
fn several_names_from_one_vault_cost_exactly_one_listing() {
    // One `keyless run` routinely asks for several names, and the listing is
    // memoised for the life of the process — in memory, never on disk. Counted
    // from the stub's side, so an adapter that spawned twice fails here.
    let dir = scratch("proton-one-listing");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_LIVE_ITEM),
    );
    let secrets = r#"{"DECOY":{"vault":"personal","item":"keyless-decoy-alpha","field":"password"},
                      "SECOND":{"vault":"personal","item":"keyless-decoy-alpha","field":"username"}}"#;
    let registry = registry_from(&named_config(&stub, secrets), &Reason::default());

    let (outcome, notes) = run_with(
        &registry,
        &["DECOY", "SECOND"],
        &witness(&marker, "SECOND", 0),
        &[],
    );

    assert_eq!(outcome.state, State::Injected, "{notes}");
    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(
        listing_count(&dir),
        1,
        "one vault was enumerated once per name instead of once per run"
    );
}

/// A `pass-cli` stand-in whose vault CHANGES after its first listing: the item
/// is `Active` the first time it is listed and `Trashed` every time after.
///
/// That is somebody emptying an item into the trash while a process that has
/// already listed the vault is still alive — the one event a memoised listing
/// cannot see, and the one the trash rule exists to catch.
///
/// Only `item list` is answered here. Everything else is handed to the ordinary
/// stub in the same directory, so a lookup that gets as far as a value still
/// records its argv, its reason and its reference where the tests above read
/// them. The tally goes to the same `pass-cli.list.count` [`listing_count`]
/// reads, so "was the vault listed again" is counted from the vendor's side.
fn stub_pass_cli_trashed_after_first_listing(dir: &Path) -> PathBuf {
    let delegate = stub_pass_cli_listing(dir, &Backend::Injects(PROTON_DECOY), &Listing::EMPTY);
    let listed_once = dir.join("pass-cli.listed-once");
    let path = dir.join("pass-cli-trashing-stub");
    let body = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'list' ]; then\n\
         \x20 echo one >> '{count}'\n\
         \x20 if [ -e '{flag}' ]; then\n\
         \x20   printf '%s' '{trashed}'\n\
         \x20 else\n\
         \x20   : > '{flag}'\n\
         \x20   printf '%s' '{live}'\n\
         \x20 fi\n\
         \x20 exit 0\n\
         fi\n\
         exec '{delegate}' \"$@\"\n",
        count = dir.join("pass-cli.list.count").display(),
        flag = listed_once.display(),
        trashed = ONE_TRASHED_ITEM,
        live = ONE_LIVE_ITEM,
        delegate = delegate.display(),
    );
    std::fs::write(&path, body).expect("cannot write the trashing stub");
    let mut mode = std::fs::metadata(&path)
        .expect("cannot stat the trashing stub")
        .permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(&path, mode).expect("cannot chmod the trashing stub");
    path
}

#[test]
fn a_listing_older_than_its_ttl_is_fetched_again_before_it_is_trusted() {
    // The trash rule lives in the LISTING: the reference form has none, and
    // `pass-cli run` resolves a trashed item happily — measured 2026-08-08, see
    // `keyless::config::SecretRoute::reference`. So a listing that is memoised
    // and never re-fetched is that rule switched off, silently, for as long as
    // whatever holds this adapter stays alive: the item is in the trash and the
    // cached record still says `Active`.
    let dir = scratch("proton-listing-expiry");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_trashed_after_first_listing(&dir);
    let registry = registry_from(
        &named_config_extra(&stub, DECOY_BY_NAME, r#","listing_ttl_ms":20"#),
        &Reason::default(),
    );

    let (first, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(first.state, State::Injected, "{notes}");
    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(listing_count(&dir), 1);

    // Past the TTL by a wide margin, so the assertion below is about expiry and
    // not about how long a machine took to get here.
    std::thread::sleep(Duration::from_millis(250));

    let (second, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 19), &[]);

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "a trashed item was injected out of a listing that predates the trashing"
    );
    assert_eq!(
        listing_count(&dir),
        2,
        "the vault was never listed again, so nothing in this process can ever \
         learn that an item was trashed"
    );
    assert_eq!(second.exit_code, 19, "the child's exit code must come back");
    assert_eq!(second.state, State::Degraded);
    assert!(notes.contains("trash"), "the banner must say why: {notes}");
}

#[test]
fn a_lookup_inside_the_ttl_serves_the_cache_and_lists_nothing() {
    // The other direction, and the control that keeps the test above honest: a
    // TTL that expired instantly would satisfy it and would also undo the
    // memoisation, turning N names into N vendor spawns and N audit entries.
    //
    // The stub answers a DIFFERENT vault on its second listing, so serving the
    // first answer is positive evidence the cache was read — not the absence of
    // evidence that it was not.
    let dir = scratch("proton-listing-within-ttl");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_trashed_after_first_listing(&dir);
    // The default TTL, spelled by leaving it out: a default too short to
    // survive two lookups in a row would fail here.
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (first, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(first.state, State::Injected, "{notes}");
    assert_eq!(witnessed(&marker), PROTON_DECOY);

    let (second, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(second.state, State::Injected, "{notes}");
    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(
        listing_count(&dir),
        1,
        "a second lookup inside the TTL listed the vault again, so the cache \
         this adapter is built around is doing nothing"
    );
}

// ---------------------------------------------------------------------------
// The resolution policy.
// ---------------------------------------------------------------------------

/// Both backends enabled and both able to answer — a company vault and a
/// personal one, which is the situation the policy exists for.
fn two_stores_config(infisical: &Path, proton: &Path, secrets: &str, stores_extra: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "infisical":{{"enabled":true,"binary":"{}","timeout_ms":60000}},
             "proton":{{"enabled":true,"binary":"{}","timeout_ms":60000,
                        "session_dir":"{SCOPED_SESSION_DIR}"}}{stores_extra}}},
            "secrets":{secrets}}}"#,
        infisical.display(),
        proton.display()
    )
}

#[test]
fn an_unpinned_name_with_two_stores_degrades_rather_than_guessing() {
    let dir = scratch("policy-ambiguous");
    let marker = dir.join("witness");
    let infisical = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let proton = stub_pass_cli(&dir, &Backend::Injects(PROTON_DECOY));
    let registry = registry_from(
        &two_stores_config(
            &infisical,
            &proton,
            r#"{"DECOY":{"reference":"pass://ShAr3Id0decoy==/It3mId0decoy==/password"}}"#,
            "",
        ),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 12), &[]);

    let seen = witnessed(&marker);
    assert_ne!(seen, INFISICAL_DECOY, "a store was guessed");
    assert_ne!(seen, PROTON_DECOY, "a store was guessed");
    assert_eq!(seen, "<unset>");
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.exit_code, 12, "the child still runs");
    assert!(notes.contains("infisical"), "{notes}");
    assert!(notes.contains("proton"), "{notes}");
}

#[test]
fn a_pinned_name_reaches_the_store_it_names_and_not_the_other() {
    // The negative control for the policy: both stubs answer, and they answer
    // with different strings, so resolving against the wrong one is visible in
    // what the child received rather than only in an internal state.
    let dir = scratch("policy-pinned");
    let infisical = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let proton = stub_pass_cli(&dir, &Backend::Injects(PROTON_DECOY));
    let secrets = r#"{"COMPANY":{"store":"infisical","env":"dev"},
                      "PERSONAL":{"store":"proton","reference":"pass://ShAr3Id0decoy==/It3mId0decoy==/password"}}"#;

    for (name, expected, wrong) in [
        ("COMPANY", INFISICAL_DECOY, PROTON_DECOY),
        ("PERSONAL", PROTON_DECOY, INFISICAL_DECOY),
    ] {
        let marker = dir.join(format!("witness-{name}"));
        let registry = registry_from(
            &two_stores_config(&infisical, &proton, secrets, ""),
            &Reason::default(),
        );
        let (outcome, _) = run_with(&registry, &[name], &witness(&marker, name, 0), &[]);

        assert_eq!(outcome.state, State::Injected, "{name} did not resolve");
        assert_ne!(witnessed(&marker), wrong, "{name} reached the wrong store");
        assert_eq!(witnessed(&marker), expected, "{name} got the wrong value");
    }
}

#[test]
fn a_declared_default_store_answers_unpinned_names() {
    let dir = scratch("policy-default");
    let marker = dir.join("witness");
    let infisical = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let proton = stub_pass_cli(&dir, &Backend::Injects(PROTON_DECOY));
    let registry = registry_from(
        &two_stores_config(
            &infisical,
            &proton,
            r#"{"DECOY":{"reference":"pass://ShAr3Id0decoy==/It3mId0decoy==/password"}}"#,
            r#","default":"proton""#,
        ),
        &Reason::default(),
    );

    let (outcome, _) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(witnessed(&marker), PROTON_DECOY);
}

#[test]
fn a_name_pinned_to_a_disabled_store_degrades_rather_than_falling_through() {
    // Disabling a backend must not quietly re-route its names to whatever else
    // is configured. That is the same cross-tenant resolution the policy
    // prevents, reached by editing one boolean.
    let dir = scratch("policy-disabled-pin");
    let marker = dir.join("witness");
    let infisical = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let config = format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "infisical":{{"enabled":true,"binary":"{}","timeout_ms":60000}},
             "proton":{{"enabled":false}}}},
            "secrets":{{"DECOY":{{"store":"proton","reference":"pass://P/I/f"}}}}}}"#,
        infisical.display()
    );
    let registry = registry_from(&config, &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 8), &[]);

    assert_ne!(
        witnessed(&marker),
        INFISICAL_DECOY,
        "a disabled pin fell through to another store"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.exit_code, 8);
    assert!(notes.contains("not configured"), "{notes}");
}

#[test]
fn a_backend_nobody_enabled_is_never_spawned() {
    // The default is off for both new backends. A user with a keychain-only
    // setup must not start paying a process spawn and a network round trip per
    // lookup because a newer build knows how to talk to a vault.
    let dir = scratch("policy-not-enabled");
    let marker = dir.join("witness");
    let infisical = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let config = format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "infisical":{{"binary":"{}"}}}},
            "secrets":{{"DECOY":{{}}}}}}"#,
        infisical.display()
    );
    let registry = registry_from(&config, &Reason::default());

    let (outcome, _) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(outcome.state, State::Degraded);
    assert!(
        !dir.join("infisical.argv").exists(),
        "a backend that was not enabled was spawned anyway"
    );
}

#[test]
fn only_the_names_that_were_asked_for_reach_the_child() {
    // The narrowing that nesting could not have done. `infisical run` injects
    // every secret at the path; this vault really does hold a second one, and
    // the child never sees it, because `keyless` spawns the command itself and
    // sets exactly what was requested.
    //
    // # Why the fixture holds a name nobody asks for
    //
    // This case used to witness `SOMETHING_ELSE`, a name that appeared NOWHERE
    // — not in the stub, not in the config, not in this process's environment.
    // Nothing the tool can do sets a name it was never given, so the assertion
    // held with the whole Infisical adapter deleted: measured by replacing the
    // registry with an empty one and the bindings with none, it still passed,
    // in 0.00 s. It was a case named for an invariant it did not exercise.
    // [`NEIGHBOUR_KEY`] is in the vault, so the absence asserted below is an
    // absence the fixture could have supplied.
    //
    // # Two halves, and only one of them owns a clock
    //
    // The VALUE half needs the stub to answer, so it is bounded by the
    // fixture's deadline — a stub that misses it turns this red for a reason
    // that has nothing to do with narrowing, which is why the message names the
    // degrade. The INVOCATION half is not bounded by anything: the stub records
    // its argv on its first line, and what was ASKED FOR is settled there
    // whatever happens next.
    let dir = scratch("infisical-narrow");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::InjectsWholeVault);
    let registry = registry_from(&infisical_config(&stub), &Reason::default());

    let (outcome, notes) = run_with(
        &registry,
        &["DECOY"],
        &witness_env(&marker, &["DECOY", NEIGHBOUR_KEY]),
        &[],
    );

    // Read from the other side of the interface: what the adapter actually
    // asked the vendor for. One name, and no trace of the command the user
    // gave — a tool that ran that command UNDER `infisical run` would have to
    // put it right here.
    let argv = recorded_lines(&dir.join("infisical.argv"));
    let probe = argv
        .iter()
        .position(|arg| arg == "--")
        .map(|at| &argv[at + 1..])
        .expect("the invocation must hand the probe over after `--`");
    assert_eq!(
        probe.len(),
        2,
        "the vendor was handed something other than a one-name probe: {probe:?}"
    );
    assert_eq!(
        probe[1], "DECOY",
        "the probe asked for a name other than the one requested"
    );
    assert!(
        !argv.iter().any(|arg| arg.contains(NEIGHBOUR_KEY)),
        "a name nobody asked for was named to the vendor: {argv:?}"
    );

    assert_eq!(
        outcome.state,
        State::Injected,
        "the lookup did not answer, so nothing was narrowed: {notes}"
    );
    let seen = witnessed_env(&marker);
    // A value carrying variables of its own shows up here as names the witness
    // never asked about — which is what a probe printing the whole environment
    // instead of one variable produces.
    let extra: Vec<&String> = seen
        .keys()
        .filter(|name| *name != "DECOY" && *name != NEIGHBOUR_KEY)
        .collect();
    assert!(
        extra.is_empty(),
        "an injected value carried variables of its own: {extra:?}"
    );
    // Exactly the value, never merely present and never merely non-empty.
    assert_eq!(
        seen.get("DECOY").map(String::as_str),
        Some(INFISICAL_DECOY),
        "the requested name did not arrive intact"
    );
    assert_eq!(
        seen.get(NEIGHBOUR_KEY).map(String::as_str),
        Some("<unset>"),
        "a name nobody asked for reached the child's environment"
    );
}

// ---------------------------------------------------------------------------
// Property: discovery reports structure, and only structure.
//
// Against a stub rather than a live account, so the trash column, the value
// exclusion and the failure paths are all exercised on every run rather than only
// where somebody has a vault configured. The live suite covers the half a stub
// cannot: that the shape is the CLI's.
// ---------------------------------------------------------------------------

/// One vault, so `items` with no `--vault` has something to enumerate.
const ONE_VAULT: &str = r#"{"vaults":[{"name":"personal","id":"V1"}]}"#;

/// A live custom item and a trashed login, which is exactly the shape of the
/// decoy vault this was written against.
const LIVE_AND_TRASHED: &str = r#"{"items":[
    {"id":"It3mL1v3","share_id":"ShAr3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"demo api key","item_type":"custom"},
    {"id":"It3mDead","share_id":"ShAr3","vault_id":"V","state":"Trashed","flags":[],
     "create_time":"2000-01-03T00:00:00","modify_time":"2000-01-03T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"}]}"#;

/// The string that must never reach a listing. It sits in EVERY value position of
/// the view fixture below, so an extraction that reads one puts it in the output.
const VIEW_LEAK: &str = "decoy-St44-never-in-a-listing-0909";

/// `item view --output json` for a custom item, in the shape measured against
/// `pass-cli` 2.2.5 on 2026-08-08 — label under `name`, value inside a single-key
/// object whose key is the field's type.
fn view_with_values() -> String {
    format!(
        r#"{{"item":{{"id":"It3mL1v3","share_id":"ShAr3","state":"Active","revision":2,
            "content":{{"item_uuid":"UU1D","title":"demo api key","note":"{VIEW_LEAK}",
              "extra_fields":[
                {{"name":"API Key","content":{{"Hidden":"{VIEW_LEAK}"}}}},
                {{"name":"Expiry Date","content":{{"Timestamp":"1730000000"}}}}
              ]}}}}}}"#
    )
}

fn discoverer_for(stub: &Path) -> Box<dyn keyless::store::discover::Discover> {
    let config: keyless::config::Config = serde_json::from_str(&format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","session_dir":"{SCOPED_SESSION_DIR}",
                        "timeout_ms":60000}}}}}}"#,
        stub.display()
    ))
    .expect("valid config");
    keyless::store::discover::discoverer(&config, "proton", &Reason::for_verb("items"))
        .expect("proton must have a discoverer")
}

#[test]
fn a_listing_reports_a_trashed_items_state_verbatim() {
    // Both halves are the property. Hiding a trashed item leaves somebody hunting
    // for an item that is in the bin; showing it unmarked is worse, because they
    // write a config entry against a title that can never resolve.
    let dir = scratch("discover-trash");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let items = discoverer_for(&stub)
        .items(Some("personal"))
        .expect("the stub must answer");

    let trashed = items
        .iter()
        .find(|item| item.title == "keyless-decoy-alpha")
        .expect("a trashed item must still be listed");
    assert_eq!(trashed.state, "Trashed", "the state was not reported as-is");
    assert!(!trashed.is_active());

    // The negative control inside the same listing: without a live item here, the
    // assertion above could pass on an implementation that calls everything
    // trashed.
    let live = items
        .iter()
        .find(|item| item.title == "demo api key")
        .expect("the live item must be listed");
    assert_eq!(live.state, "Active");
    assert!(live.is_active());
    assert_eq!(live.kind, "custom");
    assert_eq!(live.vault, "personal");
}

#[test]
fn a_listing_with_no_vault_named_enumerates_every_vault_the_identity_sees() {
    let dir = scratch("discover-all-vaults");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let items = discoverer_for(&stub).items(None).expect("the stub answers");
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|item| item.vault == "personal"));
}

#[test]
fn field_names_are_reported_and_no_value_is() {
    // The security property of `fields`, against a fixture whose every value
    // position holds a marker. `item view` prints the values and there is no
    // vendor flag that stops it, so this extraction is the only thing between the
    // credential and stdout.
    let dir = scratch("discover-fields");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, &view_with_values());
    let fields = discoverer_for(&stub)
        .fields(Some("personal"), "demo api key")
        .expect("the stub must answer");

    let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert!(names.contains(&"API Key"), "{names:?}");
    assert!(names.contains(&"Expiry Date"), "{names:?}");

    for field in &fields {
        assert!(
            !field.name.contains(VIEW_LEAK),
            "a value was reported as a field name"
        );
        assert!(!field.path.contains(VIEW_LEAK));
        assert!(
            !field
                .value_type
                .as_deref()
                .is_some_and(|named| named.contains(VIEW_LEAK)),
            "a value reached the type column"
        );
    }

    // The type comes from the container's own key, which is how a `Timestamp`
    // field is distinguishable from the credential beside it.
    let expiry = fields
        .iter()
        .find(|field| field.name == "Expiry Date")
        .expect("checked above");
    assert_eq!(expiry.value_type.as_deref(), Some("Timestamp"));
}

#[test]
fn fields_on_a_trashed_item_is_refused_with_the_reason() {
    // Reporting them would send the reader to write a config entry against a
    // title the resolver refuses on purpose.
    let dir = scratch("discover-fields-trashed");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, &view_with_values());
    let message = discoverer_for(&stub)
        .fields(Some("personal"), "keyless-decoy-alpha")
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(message.contains("trash"), "{message}");
}

#[test]
fn discovery_never_reaches_the_verb_that_resolves_a_value() {
    // The stub answers `vault list`, `item list` and `item view` and fails
    // everything else — so if a discovery path ever reached `run`, these would
    // error rather than quietly resolving something. The recorded argv is the
    // second half of the check.
    let dir = scratch("discover-no-run");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, &view_with_values());
    let _ = discoverer_for(&stub)
        .fields(Some("personal"), "demo api key")
        .expect("the stub answers");

    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert_eq!(argv.first().map(String::as_str), Some("item"));
    for forbidden in ["run", "--env-file", "--no-masking", "--show-secrets"] {
        assert!(
            !mentions(&argv, forbidden),
            "`{forbidden}` appeared in a discovery invocation: {argv:?}"
        );
    }

    // And every discovery call carries the scoped session and a reason, exactly as
    // a read does — enumerating is a read of the vault's structure and is logged
    // off-machine like any other.
    assert_eq!(recorded(&dir.join("pass-cli.session")), SCOPED_SESSION_DIR);
    assert!(!recorded(&dir.join("pass-cli.reason")).trim().is_empty());
}

// ---------------------------------------------------------------------------
// A coordinate that begins with `-`.
//
// Proton ids are base64url, whose alphabet includes `-`, so about one id in 64
// begins with one. `pass-cli` parses with clap, which reads a standalone
// argument beginning with a single `-` as a cluster of short flags — whatever
// option preceded it — and refuses the command with exit 2. Found on a real
// item on 2026-08-08, not reasoned about: an id beginning `-` meant `keyless
// fields` could not inspect that item at all.
//
// Every coordinate below is invented. The property under test is the leading
// `-`, which any base64url-shaped decoy carries — see `no_real_vault_coordinates`
// in this file, which is what keeps it that way.
//
// The stub refuses exactly what the vendor refuses, so this is a test of the
// invocation reaching a parser, not of a copy of the adapter's flag list.
// ---------------------------------------------------------------------------

/// The same shape as `LIVE_AND_TRASHED`, with ids that begin with `-`.
const DASH_LEADING_IDS: &str = r#"{"items":[
    {"id":"-Kx7Qm2Za","share_id":"-Sh4r3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"demo.service","item_type":"custom"}]}"#;

fn dash_id_view() -> String {
    format!(
        r#"{{"item":{{"id":"-Kx7Qm2Za","share_id":"-Sh4r3","state":"Active","revision":2,
            "content":{{"item_uuid":"UU1D","title":"demo.service","note":"{VIEW_LEAK}",
              "extra_fields":[
                {{"name":"API Token","content":{{"Hidden":"{VIEW_LEAK}"}}}}
              ]}}}}}}"#
    )
}

#[test]
fn fields_inspects_an_item_whose_id_begins_with_a_dash() {
    let dir = scratch("discover-dash-id");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, DASH_LEADING_IDS, &dash_id_view());
    let fields = discoverer_for(&stub)
        .fields(Some("personal"), "demo.service")
        .expect("an item whose id begins with `-` must still be inspectable");

    let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert!(names.contains(&"API Token"), "{names:?}");

    // And the id reached the vendor joined to its flag, in one argument. The
    // assertion above cannot distinguish "addressed correctly" from "addressed
    // by title and got lucky", and addressing by title is the wrong fix here.
    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert!(
        argv.iter().any(|arg| arg == "--item-id=-Kx7Qm2Za"),
        "{argv:?}"
    );
    assert!(
        !argv.iter().any(|arg| arg == "--item-title"),
        "the item was addressed by title, which two items can share: {argv:?}"
    );
}

#[test]
fn a_vault_whose_name_begins_with_a_dash_is_still_enumerable() {
    // The same defect one verb earlier. `--vault-name` was already named rather
    // than positional, and that alone never fixed it: the vendor refuses the
    // value whichever option it followed.
    let dir = scratch("discover-dash-vault");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, DASH_LEADING_IDS, "{}");
    let items = discoverer_for(&stub)
        .items(Some("-dashvault"))
        .expect("a vault whose name begins with `-` must still be enumerable");
    assert_eq!(items.len(), 1);

    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert!(
        argv.iter().any(|arg| arg == "--vault-name=-dashvault"),
        "{argv:?}"
    );
}

// ---------------------------------------------------------------------------
// `doctor` and a dead session.
//
// Measured on 2026-08-08: with the agent session expired, `keyless doctor`
// printed `store proton ok` and `0 problem(s)` while every Proton name was
// degrading — the child ran with an empty bearer and the resulting HTTP 400
// came back at exit 0. `doctor` is the command a session is told to run to find
// that out, and `keyless run` never refuses, so nothing else on the machine
// could have said it.
// ---------------------------------------------------------------------------

/// The one report line about the Proton store.
///
/// By subject rather than by an exact prefix: the row carries a mark, a state
/// word and a detail, and pinning the whole spelling here would make every
/// assertion below a test of the layout rather than of the finding.
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

fn proton_row(report: &str) -> &str {
    report
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some("proton"))
        .unwrap_or_else(|| panic!("the report has no `proton` row:\n{report}"))
}

/// `doctor`'s report and its exit code, against a registry built from `config`.
fn doctor_report(dir: &Path, config: &str) -> (String, i32) {
    let paths = keyless::paths::Paths::under(dir);
    let mut load = keyless::config::Config::load(&paths.config);
    load.config = serde_json::from_str(config).expect("the test config must be valid");
    load.loaded = true;
    let registry = store::build(
        &load.config,
        &Invocation {
            reason: Reason::for_verb("doctor"),
            infisical_env: None,
        },
    )
    .registry;
    let audit = keyless::audit::AuditLog::new(paths.audit.clone());

    let mut out: Vec<u8> = Vec::new();
    // `Style::PLAIN` on purpose: these assertions are about WORDS, and a
    // coloured render would wrap every one of them in escape sequences that a
    // `contains` cannot see through.
    let code = keyless::cmd::doctor::doctor(
        &keyless::cmd::doctor::DoctorRequest {
            paths: &paths,
            load: &load,
            registry: &registry,
            audit: &audit,
            setup: None,
            notes: &[],
            probe: false,
            // Fixed, not probed: these cases are about STORES, and a real
            // checkout reading would make them fail whenever the developer's
            // branch happened to be ahead of its remote.
            freshness: &keyless::freshness::Freshness::NoSourceTree,
            checkout: &keyless::checkout::Checkout::NoSourceTree,
            style: keyless::cmd::status::Style::PLAIN,
        },
        &mut out,
    )
    .expect("the report must be writable");
    (String::from_utf8(out).expect("utf-8"), code)
}

#[test]
fn doctor_reports_an_expired_proton_session_as_a_problem() {
    let dir = scratch("doctor-dead-session");
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config(&stub));

    // Not proven, and the row says which kind of not-proven it is. A dead
    // session is `absent` rather than `broken`: the store is installed and
    // reachable, and the identity it needs has expired — so the reader is sent
    // to a login, not to the vault.
    assert!(
        !proton_row(&report).contains("proven"),
        "a dead session was reported as proven:\n{report}"
    );
    assert_eq!(state_of(proton_row(&report)), "absent", "{report}");
    // The vendor's own words, so the reader knows which of the many ways this
    // backend fails they are looking at.
    //
    // Read against a whitespace-collapsed copy: the report wraps a long detail
    // across lines for a person to read, so a phrase can straddle a newline.
    // `doctor` is the human surface and `ls` is the parseable one — see
    // `crate::cmd::ls` for the four tab-separated fields a program should read
    // instead of this.
    let flat = report.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("authenticated client"),
        "the report did not say what the vendor said:\n{report}"
    );
    // And the fix, because "requires an authenticated client" does not tell
    // anybody which session directory to re-mint.
    // As ONE string. Asserting the command and the directory separately passes
    // on a report that names both and joins neither, which is the report that
    // cost the hours: `pass-cli login` typed without the variable in front of it
    // reaches the DEFAULT session and answers `Already authenticated`.
    assert!(
        flat.contains(&format!(
            "PROTON_PASS_SESSION_DIR={SCOPED_SESSION_DIR} pass-cli login"
        )),
        "{report}"
    );
    assert_eq!(code, 1, "{report}");
    assert!(!report.contains("0 problem(s)"), "{report}");

    // The check reached the vendor rather than concluding from the config, and
    // it asked for the one verb that reads no item content.
    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert_eq!(argv.first().map(String::as_str), Some("vault"));
    assert_eq!(argv.get(1).map(String::as_str), Some("list"));
    for forbidden in ["run", "view", "--show-secrets", "--env-file"] {
        assert!(
            !mentions(&argv, forbidden),
            "a health check asked for `{forbidden}`: {argv:?}"
        );
    }
}

#[test]
fn doctor_reports_a_live_proton_session_as_ok() {
    // The negative control for the test above. Without it, that one passes on an
    // implementation that reports every Proton store as broken, which would be a
    // false RED — the same defect wearing the other colour, and the one that
    // gets a health check deleted.
    let dir = scratch("doctor-live-session");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let (report, code) = doctor_report(&dir, &proton_config(&stub));

    assert_eq!(state_of(proton_row(&report)), "proven", "{report}");
    // And never the word that was false. `ok` said "the binary answered" while
    // reading as "your secrets are reachable"; a row is green here only because
    // a read path came back.
    assert!(!proton_row(&report).contains(" ok"), "{report}");
    assert_eq!(code, 0, "{report}");
    assert!(report.contains("0 problem(s)"), "{report}");

    // `ok` here is a claim about a live session, and the default report is
    // still allowed to make it because it MEASURED it — for the price of one
    // spawn that reads no item content. The last thing the vendor was asked
    // is the proof: `vault list`, never `run`.
    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert_eq!(argv.first().map(String::as_str), Some("vault"));
    assert!(!mentions(&argv, "run"), "{argv:?}");

    // And the report says which question it did NOT ask. `--probe` resolves
    // every name, which READS every credential; that is why it is opt-in, and
    // why the report has to name it rather than leave the reader believing
    // `store proton ok` covers their names too.
    assert!(report.contains("not probed"), "{report}");
    assert!(report.contains("--probe"), "{report}");
}

#[test]
fn a_proton_store_with_no_session_directory_is_unhealthy_without_spawning_anything() {
    // The local preconditions still come first, and they still short-circuit.
    // A health check that spawned the vendor before noticing there is no
    // identity to ask as would report the wrong cause, and — measured
    // 2026-08-08 — `pass-cli` REINITIALISES the session database at whatever
    // path it is pointed at, so "spawn first, ask later" is not a cosmetic
    // mistake here.
    let dir = scratch("doctor-no-session");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let config = format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}}}}"#,
        stub.display()
    );
    let (report, code) = doctor_report(&dir, &config);

    let state = state_of(proton_row(&report));
    assert!(
        state == "config" || state == "absent",
        "the row's state is `{state}`, and an unset session directory is either \
         a config fault or an unreachable store:\n{report}"
    );
    assert!(report.contains("session_dir"), "{report}");
    assert_eq!(code, 1, "{report}");
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "the vendor was spawned with no session directory configured"
    );
}

// ---------------------------------------------------------------------------
// Property: an interrupted session write is NAMED, never called plain absent.
//
// The incident, 2026-08-10: a fleet of agents was killed by session limits, and
// one of them was a `keyless run` whose `pass-cli` child was mid-write. It left
// `/Users/nab/.keyless-pass-session/.session/session.json` (118 bytes, where a
// healthy sibling directory's is 393) beside a zero-byte
// `session.tmp.28182.0`, same second. One killed process stranded the whole
// store, and `doctor` reported `absent` — true, and it sends a reader to
// `pass-cli login`, which hits the DEFAULT session, answers `Already
// authenticated`, and changes nothing.
//
// `pass-cli` owns that write: `session.tmp.` and `session.json` are both string
// literals in the vendor binary (2.2.5), and `keyless` writes its only temp file
// — `keyless-probe-<pid>-<n>.env` — into `std::env::temp_dir()`. So keyless
// cannot make the rename atomic. What it CAN do is recognise the shape and say
// which command actually reaches this directory.
// ---------------------------------------------------------------------------

/// A session directory with `.session/session.json` and one unfinished write.
///
/// `temp_idle` is how long ago the unfinished write last moved — the whole
/// discriminator between "abandoned by a killed process" and "a sibling is
/// writing this right now". `session_idle` is how long ago the session file
/// itself last moved, which decides whether the temp file is the LAST thing
/// that happened here or a scar from an attempt that a later login superseded.
/// Both sides of both lines need a fixture, so both are parameters.
fn session_dir_with_an_interrupted_write(
    root: &Path,
    temp: &str,
    temp_idle: Duration,
    session_idle: Duration,
) -> std::path::PathBuf {
    let session = root.join("agent-session").join(".session");
    std::fs::create_dir_all(&session).expect("create the session directory");
    // Bytes that are deliberately not JSON: the real file is an encrypted blob,
    // and a fixture holding parseable JSON would invite an implementation that
    // reads it. Nothing in this crate may open a session file.
    std::fs::write(session.join("session.json"), [0x9c, 0x01, 0x02]).expect("write session.json");
    std::fs::write(session.join(temp), b"").expect("write the temp file");

    backdate(&session.join("session.json"), session_idle);
    backdate(&session.join(temp), temp_idle);

    session
        .parent()
        .expect("the session directory has a parent")
        .to_path_buf()
}

/// Set one file's modification time to `idle` ago.
///
/// Through `std::fs::FileTimes` rather than a `touch` subprocess: the ages under
/// test here are hours and days, and a fixture that had to WAIT for them would
/// be a suite nobody runs.
fn backdate(path: &Path, idle: Duration) {
    let times = std::fs::FileTimes::new().set_modified(std::time::SystemTime::now() - idle);
    std::fs::File::options()
        .write(true)
        .open(path)
        .expect("reopen the file to backdate it")
        .set_times(times)
        .expect("backdate the file");
}

/// A Proton-only config pointed at `binary`, with an explicit session directory.
fn proton_config_at(binary: &Path, session_dir: &Path) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","session_dir":"{}","timeout_ms":60000}}}},
            "secrets":{{"DECOY":{{"reference":"{PROTON_REFERENCE}"}}}}}}"#,
        binary.display(),
        session_dir.display()
    )
}

/// The report with its wrapping removed, so a phrase may straddle a line.
fn flattened(report: &str) -> String {
    report.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn doctor_names_an_interrupted_session_write_rather_than_reporting_a_plain_absence() {
    let dir = scratch("doctor-torn-session");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.28182.0",
        Duration::from_secs(3600),
        Duration::from_secs(7200),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));
    let flat = flattened(&report);

    // The state, in words. `absent` alone was true and sent a reader to the
    // wrong command; the row now says WHICH kind of unusable this is.
    assert!(flat.contains("HALF-WRITTEN"), "{report}");
    // Named, so the reader can look at the file the report is talking about.
    assert!(flat.contains("session.tmp.28182.0"), "{report}");
    // And whose write it is, because that decides who can fix it.
    assert!(flat.contains("keyless writes NOTHING"), "{report}");
    // The vendor still speaks for itself.
    assert!(flat.contains("authenticated client"), "{report}");
    assert_eq!(code, 1, "{report}");
}

#[test]
fn the_interrupted_session_remedy_names_this_session_directory_and_the_variable() {
    // The half of the incident that cost the time. `pass-cli login` typed
    // literally logs into the default session and answers `Already
    // authenticated`; the directory travels in `PROTON_PASS_SESSION_DIR`, which
    // is the same variable this adapter puts on every child it spawns.
    let dir = scratch("doctor-torn-remedy");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.31337.0",
        Duration::from_secs(3600),
        Duration::from_secs(7200),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, _) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));
    let flat = flattened(&report);

    let expected = format!(
        "PROTON_PASS_SESSION_DIR={} pass-cli login",
        session_dir.display()
    );
    assert!(
        flat.contains(&expected),
        "the report never printed the command that reaches this session:\n{report}"
    );
}

#[test]
fn a_proton_failure_with_no_interrupted_write_still_names_the_variable() {
    // The generic path, which is every other way a session dies — an expired
    // agent token, a revoked one. The old advice was `pass-cli login` into
    // `stores.proton.session_dir`, which is followable only by someone who
    // already knows the answer. There is no torn write here, so this is the
    // remedy alone.
    let dir = scratch("doctor-dead-session-remedy");
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config(&stub));
    let flat = flattened(&report);

    assert!(!flat.contains("HALF-WRITTEN"), "{report}");
    assert!(
        flat.contains(&format!(
            "PROTON_PASS_SESSION_DIR={SCOPED_SESSION_DIR} pass-cli login"
        )),
        "{report}"
    );
    assert_eq!(code, 1, "{report}");
}

#[test]
fn a_write_from_moments_ago_is_never_called_an_interrupted_one() {
    // The safety property. A zero-byte temp file held by a LIVE `pass-cli` and
    // one abandoned by a killed one are the same file; the only thing that
    // separates them without inspecting open descriptors is that one stops
    // moving. So a fresh one is reported as undecided, and the reader is asked
    // to look again rather than told a session is damaged.
    let dir = scratch("doctor-fresh-write");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.4242.0",
        Duration::from_secs(0),
        Duration::from_secs(7200),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));
    let flat = flattened(&report);

    assert!(
        !flat.contains("HALF-WRITTEN"),
        "a write from this second was reported as damage:\n{report}"
    );
    assert!(
        flat.contains("may be writing this session right now"),
        "{report}"
    );
    assert!(flat.contains("session.tmp.4242.0"), "{report}");
    assert_eq!(code, 1, "{report}");
}

#[test]
fn a_session_that_answers_is_never_reported_as_half_written() {
    // The false-positive control, and the reason the forensics run only after
    // the round trip has already failed. An orphan temp file beside a session
    // that ANSWERS is debris; a health check that calls a working store broken
    // is a health check that gets ignored.
    let dir = scratch("doctor-live-with-orphan-temp");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.11111.0",
        Duration::from_secs(86_400),
        Duration::from_secs(172_800),
    );
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let (report, code) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));

    assert_eq!(state_of(proton_row(&report)), "proven", "{report}");
    assert!(!report.contains("HALF-WRITTEN"), "{report}");
    assert_eq!(code, 0, "{report}");
}

#[test]
fn doctor_leaves_an_interrupted_write_exactly_where_it_found_it() {
    // A broker that eats a live session is far worse than one that reports a
    // torn one. There is no expression in this crate that removes a file from a
    // session directory, and this is the fixture that would notice one arriving.
    let dir = scratch("doctor-torn-untouched");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.55555.0",
        Duration::from_secs(3600),
        Duration::from_secs(7200),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, _) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));

    let session = session_dir.join(".session");
    assert!(
        session.join("session.tmp.55555.0").exists(),
        "doctor removed an unfinished write:\n{report}"
    );
    assert!(
        session.join("session.json").exists(),
        "doctor removed a session file:\n{report}"
    );
}

#[test]
fn a_leftover_older_than_the_session_file_is_a_scar_and_not_a_cause() {
    // The state this check would otherwise get wrong FOREVER, and it is not
    // hypothetical: measured on the incident's own directory on 2026-08-11, the
    // abandoned `session.tmp.28182.0` from 17:47:30 the previous day was still
    // sitting beside a `session.json` rewritten at 06:35:14 that morning. The
    // session had recovered; nothing removed the temp file.
    //
    // `rename` carries the source's modification time, so a `session.json`
    // NEWER than a temp file proves a later write landed. Without that
    // comparison, every unrelated Proton failure from that day on — an expired
    // token, a revoked one — would be reported as a half-written session on the
    // strength of a file that stopped mattering months earlier. That is a
    // permanent false diagnosis, which is worse than the bare `absent` this
    // whole change replaces.
    let dir = scratch("doctor-recovered-leftover");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.28182.0",
        Duration::from_secs(86_400),
        Duration::from_secs(600),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));
    let flat = flattened(&report);

    assert!(
        !flat.contains("HALF-WRITTEN"),
        "a leftover from before the last successful write was reported as damage:\n{report}"
    );
    assert!(
        !flat.contains("session.tmp.28182.0"),
        "a superseded temp file was named as the cause:\n{report}"
    );
    // The generic failure is still reported, and still names the command that
    // reaches this directory rather than the default one.
    assert!(flat.contains("authenticated client"), "{report}");
    assert!(
        flat.contains(&format!(
            "PROTON_PASS_SESSION_DIR={} pass-cli login",
            session_dir.display()
        )),
        "{report}"
    );
    assert_eq!(code, 1, "{report}");
}
