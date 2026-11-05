//! The resolution policy: which store a name reaches when several could answer.

mod stores_support;
mod support;

use std::path::Path;

use keyless::State;
use keyless::store::proton::Reason;

use support::{
    Backend, INFISICAL_DECOY, NEIGHBOUR_KEY, PROTON_DECOY, SCOPED_SESSION_DIR, recorded_lines,
    run_with, scratch, stub_infisical, stub_pass_cli, witness, witness_env, witnessed,
    witnessed_env,
};

use stores_support::{infisical_config, registry_from};

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
             "infisical":{{"binary":"{}","timeout_ms":60000}}}},
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
