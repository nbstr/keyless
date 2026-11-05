//! What reaches the child, and how each vendor is invoked to get it there.

mod stores_support;
mod support;

use std::ffi::OsString;
use std::path::Path;

use keyless::State;
use keyless::config::Config;
use keyless::store::proton::Reason;
use keyless::store::{self, Invocation, Registry};

use support::{
    Backend, CONCEALED, INFISICAL_DECOY, PROTON_DECOY, SCOPED_SESSION_DIR, recorded,
    recorded_lines, run_with, scratch, stub_infisical, stub_pass_cli, witness, witnessed,
};

use stores_support::{
    PROTON_REFERENCE, infisical_config, infisical_config_for, proton_config, registry_from,
};

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
fn an_unset_name_is_refused_as_missing_rather_than_degraded_as_a_broken_store() {
    // Measured: the CLI reports a non-zero child as `failed to wait for command
    // termination: exit status N`, and its own failures carry different
    // wording. Getting this backwards sends a user hunting a broken login when
    // the secret is simply at another path.
    let dir = scratch("infisical-unset");
    let marker = dir.join("witness");
    let stub = stub_infisical(&dir, &Backend::Unset);
    let registry = registry_from(&infisical_config(&stub), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 4), &[]);

    assert_eq!(outcome.state, State::Refused);
    assert_eq!(outcome.exit_code, 64);
    assert!(!marker.exists(), "the child started: {notes}");
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
