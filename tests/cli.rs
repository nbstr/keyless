//! End-to-end tests against the built binary.
//!
//! These exist for the properties that only hold at the CLI boundary — above
//! all, that **no verb prints a value**. That is a claim about the shape of the
//! command surface, so it has to be tested by asking the real binary for those
//! verbs and watching it refuse.

mod cli_support;
mod support;

use cli_support::{config_with_stub, keyless, keyless_env, stdout_of};
use support::backend::Backend;
use support::keychain::Stub;
use support::{DECOY_VALUE, scratch};

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

// ---------------------------------------------------------------------------
// The 1Password probe's environment, at the binary boundary.
//
// Here rather than in the adapter's own tests because the thing under test is
// the WIRING. The filter is a pure function and is unit-tested as one, but a
// unit test cannot see the call being deleted — the Proton adapter records
// exactly that: with its filter tested on its own, removing the call left the
// suite green. Only a child process with an environment of its own can prove
// the rule is applied on the path a real lookup takes.
// ---------------------------------------------------------------------------

#[test]
fn an_ambient_op_reference_never_reaches_the_vendor() {
    // `OP_*` is forwarded BY NAME, because `OP_SESSION_<account>` cannot be
    // spelled in advance. So a caller who exported `OP_ANYTHING=op://…` walked
    // straight through `env_clear()` — and `op run` resolves every reference it
    // finds in the whole environment, which buys a read nobody asked for and
    // fails the probe with a message naming a variable unrelated to the lookup.
    let dir = support::scratch("e2e-op-ambient-reference");
    let stub = support::onepassword::stub_op(&dir, &Backend::Injects(support::ONEPASSWORD_DECOY));
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "onepassword":{{"enabled":true,"binary":"{}","vault":"company",
                                 "field":"password","timeout_ms":60000}}}},
                "secrets":{{"DECOY":{{"item":"DECOY"}}}}}}"#,
            stub.display()
        ),
    )
    .expect("write config");

    let output = keyless_env(
        &[
            // The stray reference, and a login variable beside it that MUST
            // survive — the control that stops this passing on a build which
            // simply forwards no `OP_*` at all.
            ("OP_KEYLESS_REVIEW", "op://company/Router/password"),
            ("OP_ACCOUNT", "demo"),
        ],
        &[
            "--config",
            &config.display().to_string(),
            "--audit",
            &dir.join("audit.jsonl").display().to_string(),
            "run",
            "-s",
            "DECOY",
            "--",
            "/usr/bin/true",
        ],
    );
    assert!(output.status.success(), "{output:?}");

    // Read from the vendor's side: the stub records the NAMES of the
    // environment it was handed, and never their values.
    let handed = support::recorded_lines(&dir.join("op.env"));
    assert!(
        !handed.iter().any(|name| name == "OP_KEYLESS_REVIEW"),
        "an ambient op:// reference reached the vendor: {handed:?}"
    );
    assert!(
        handed.iter().any(|name| name == "OP_ACCOUNT"),
        "the login half of the prefix stopped being forwarded: {handed:?}"
    );
}
