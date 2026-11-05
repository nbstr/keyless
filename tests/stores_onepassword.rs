//! 1Password cannot stop the command, and is invoked without a verb that prints a value.

mod stores_support;
mod support;

use std::time::{Duration, Instant};

use keyless::State;
use keyless::store::proton::Reason;

use support::{
    Backend, ONEPASSWORD_DECOY, OnePasswordListing, recorded, recorded_lines, run_with, scratch,
    stub_op, stub_op_listing, witness, witness_env, witnessed, witnessed_env,
};

use stores_support::{
    ONEPASSWORD_DECOY_BY_TITLE, last_op_verb, mentions, onepassword_config, registry_from,
};

// ---------------------------------------------------------------------------
// Property: 1Password cannot stop the command, and reads exactly one vault.
//
// The stub encodes the vendor's DOCUMENTED shapes and two MEASURED refusals;
// see `src/store/onepassword.rs` for which is which. What these cases prove is
// what `keyless` does with each answer, from the vendor's side of the
// interface: the argv it was spawned with, the environment it was handed, and
// the reference it was asked to resolve.
// ---------------------------------------------------------------------------

#[test]
fn an_absent_op_binary_still_spawns_the_child() {
    let dir = scratch("onepassword-absent");
    let marker = dir.join("witness");
    let registry = registry_from(
        &onepassword_config(&dir.join("there-is-no-op-here"), ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 42), &[]);

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "the environment was modified"
    );
    assert_eq!(outcome.exit_code, 42);
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("DEGRADED"), "{notes}");
    assert!(notes.contains("DECOY"), "the banner must name the secret");
}

#[test]
fn an_op_that_never_answers_still_spawns_the_child() {
    let dir = scratch("onepassword-hangs");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Hangs);
    // The listing answers and the RUN hangs, so the deadline being tested is
    // the lookup's. Its own config: here the deadline is the SUBJECT.
    let registry = registry_from(
        &format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "onepassword":{{"enabled":true,"binary":"{}","vault":"company",
                                 "field":"password","timeout_ms":300}}}},
                "secrets":{ONEPASSWORD_DECOY_BY_TITLE}}}"#,
            stub.display()
        ),
        &Reason::default(),
    );

    let started = Instant::now();
    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 17), &[]);
    let elapsed = started.elapsed();

    assert!(elapsed < Duration::from_secs(10), "waited {elapsed:?}");
    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 17);
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("no answer within 300 ms"), "{notes}");
}

#[test]
fn an_op_that_is_not_signed_in_degrades_and_names_the_login_rather_than_the_name() {
    // The measured refusal. It must reach the caller as a LOGIN problem with
    // the vendor's own bootstrap named, never as a name that is absent — those
    // send a reader to two different places.
    let dir = scratch("onepassword-not-signed-in");
    let marker = dir.join("witness");
    let stub = stub_op_listing(
        &dir,
        &Backend::Injects(ONEPASSWORD_DECOY),
        &OnePasswordListing::NotSignedIn,
        "{}",
    );
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 9), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 9);
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("op signin"), "{notes}");
    assert!(notes.contains("not a missing name"), "{notes}");
    assert!(
        notes.contains("not signed in"),
        "the vendor's own words must reach the caller: {notes}"
    );
    // The log prefix the vendor wraps its errors in is not part of the diagnosis.
    assert!(!notes.contains("[ERROR]"), "{notes}");
    // And the refusal stopped at the listing: no `run` was attempted.
    assert_eq!(last_op_verb(&dir), "item");
}

#[test]
fn a_onepassword_value_reaches_the_child_and_nothing_else() {
    let dir = scratch("onepassword-happy");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );

    let (outcome, notes) = run_with(
        &registry,
        &["DECOY"],
        &witness_env(&marker, &["DECOY", "KEYLESS_PROBE"]),
        &[],
    );

    assert_eq!(outcome.state, State::Injected, "{notes}");
    assert_eq!(notes, "", "a successful run says nothing at all");
    let seen = witnessed_env(&marker);
    assert_eq!(seen["DECOY"], ONEPASSWORD_DECOY, "the child must see it");
    // The probe variable is the adapter's, for one process that lives for one
    // lookup. The user's command must never inherit it.
    assert_eq!(
        seen["KEYLESS_PROBE"], "<unset>",
        "the probe leaked into the child"
    );

    // What the vendor was asked to resolve: the PINNED vault, the item's id
    // out of the listing, and the store-wide field — as a reference in the
    // environment, never in argv.
    assert_eq!(
        recorded(&dir.join("op.probe")),
        "op://company/It3mL1v3/password"
    );
    let argv = recorded_lines(&dir.join("op.argv"));
    assert!(!argv.iter().any(|arg| arg.contains("op://")), "{argv:?}");
}

#[test]
fn the_onepassword_invocation_uses_run_and_no_verb_that_prints_a_value() {
    // Asserted on what the stub RECORDED, not on the adapter's own list. `read`,
    // `item get` and `inject` print plaintext and the hook pack refuses them;
    // if one appears here, this adapter has become the way around that.
    let dir = scratch("onepassword-argv");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );
    let (outcome, _) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(outcome.state, State::Injected);

    let run = recorded_lines(&dir.join("op.argv"));
    assert_eq!(run.first().map(String::as_str), Some("run"), "{run:?}");
    assert!(run.iter().any(|arg| arg == "--no-masking"), "{run:?}");
    let separator = run.iter().position(|arg| arg == "--").expect("a separator");
    assert_eq!(
        run[separator + 1..],
        ["/usr/bin/printenv", "KEYLESS_PROBE"],
        "{run:?}"
    );

    let list = recorded_lines(&dir.join("op.list.argv"));
    assert_eq!(&list[..2], ["item", "list"], "{list:?}");
    assert!(mentions(&list, "--vault"), "{list:?}");
    assert!(list.iter().any(|arg| arg == "--vault=company"), "{list:?}");
    assert!(
        list.iter().any(|arg| arg == "--include-archive"),
        "{list:?}"
    );

    for argv in [&run, &list] {
        for forbidden in ["read", "get", "inject", "--reveal"] {
            assert!(
                !argv.iter().any(|arg| arg == forbidden),
                "`{forbidden}` appeared in {argv:?}"
            );
        }
    }
}

#[test]
fn the_vendor_is_handed_a_cleared_environment_and_the_probe() {
    // The clearing is what makes `printenv` exact: nothing this process
    // carries can come back as a value, and no ambient `op://` can cost a read
    // nobody asked for. Read off the environment the stub actually received.
    let dir = scratch("onepassword-env");
    let marker = dir.join("witness");
    let stub = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let registry = registry_from(
        &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE),
        &Reason::default(),
    );
    let (outcome, _) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(outcome.state, State::Injected);

    let handed = recorded(&dir.join("op.env"));
    let names: Vec<&str> = handed.lines().collect();
    assert!(names.contains(&"KEYLESS_PROBE"), "{names:?}");
    assert!(names.contains(&"PATH"), "{names:?}");
    // The adapter's forwarded set, plus what `/bin/sh` adds to its own
    // environment on the way to `env`. Anything else is a variable this
    // process carried that reached the vendor.
    let forwarded = [
        "HOME",
        "PATH",
        "TMPDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "no_proxy",
        "XDG_CONFIG_HOME",
        "KEYLESS_PROBE",
    ];
    let shell_adds = ["PWD", "OLDPWD", "SHLVL", "_"];
    for name in &names {
        assert!(
            forwarded.contains(name) || shell_adds.contains(name) || name.starts_with("OP_"),
            "`{name}` was handed to the vendor: {names:?}"
        );
    }
}
