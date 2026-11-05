//! The Proton Pass path against a real account and the real `pass-cli`.
//!
//! Every other Proton test in this suite runs against a shell stub. A stub
//! proves the adapter builds an invocation that matches a contract someone
//! wrote down; it cannot prove the contract is the CLI's. These tests close
//! that gap, and they are the reason `proton.rs` may say "observed" rather than
//! "documented".
//!
//! The suite is split by what each part proves; this file holds the reference
//! path and carries the header every sibling points back to:
//!
//! | File | Proves |
//! |---|---|
//! | `proton_live.rs` | a reference resolves, the session is scoped, a failed session degrades, the probe file is removed |
//! | `proton_live_masking.rs` | the vendor masks the probe's output unless told not to |
//! | `proton_live_names.rs` | the name form: listing shape, trash, a missing title, a missing vault, the positive path |
//! | `proton_live_discovery.rs` | `items` and `fields` |
//! | `proton_live_write.rs` | a viewer-role token cannot write |
//!
//! # Why they are `#[ignore]` and not feature-gated
//!
//! They need a Proton account, a Pass Plus subscription, a minted agent token
//! and a vault with a decoy item in it. None of that exists on a fresh checkout
//! or in CI, so running them by default would make the suite fail for everyone
//! who is not the author.
//!
//! `#[ignore]` rather than "read an env var and return early": a test that
//! silently passes when its inputs are absent is a **green result for work that
//! never happened**, which is the exact failure this crate's test suite is
//! written to avoid. Ignored tests are reported as ignored, by name, in the
//! summary. Missing configuration below is a `panic`, never a skip.
//!
//! # Running them
//!
//! ```text
//! export KEYLESS_LIVE_SESSION_DIR=~/.keyless-pass-session
//! export KEYLESS_LIVE_REFERENCE='pass://SHARE_ID/ITEM_ID/password'
//! export KEYLESS_LIVE_EXPECTED='the decoy value that reference holds'
//! export KEYLESS_LIVE_FOREIGN='pass://OTHER_SHARE_ID/OTHER_ITEM_ID/password'
//! export KEYLESS_LIVE_VAULT='personal'
//! export KEYLESS_LIVE_TRASHED_TITLE='keyless-decoy-alpha'
//! export KEYLESS_LIVE_TITLE='the title of a LIVE decoy item in that vault'
//! export KEYLESS_LIVE_FIELD='password'
//! export KEYLESS_LIVE_CUSTOM_TITLE='demo api key'
//! export KEYLESS_LIVE_CUSTOM_FIELD='API Key'
//! cargo test --test 'proton_live*' -- --ignored --test-threads=1
//! ```
//!
//! `KEYLESS_LIVE_CUSTOM_*` describe a LIVE item of type `custom`, and the field
//! variable is written out by hand on purpose: it is an independent statement of
//! what the item's field is called, not something derived from the command under
//! test. **No variable here holds that field's value**, because exporting one would
//! mean somebody had to read it first — which is exactly what `fields` exists to
//! make unnecessary.
//!
//! `KEYLESS_LIVE_FOREIGN` must name an item in a vault the agent token was
//! **not** granted — that is the whole point of the scoping test, and without
//! it that test would assert nothing.
//!
//! **A share id is not stable.** Re-establishing a session mints a new one for
//! the same vault, so `KEYLESS_LIVE_REFERENCE` is read from the session that
//! will resolve it, at the time of the run — never copied from an earlier one.
//! That instability is why the name form exists at all; see `store::proton`.
//!
//! # Which of these have actually been observed, and with what
//!
//! Fifteen tests, and they split by which fixtures the runner had.
//!
//! **Nine were observed green on 2026-08-08** against `pass-cli` 2.2.5 and a real
//! account, with only the coordinates above exported — a session directory, a
//! vault name, two item titles and a field name. None of those is a credential,
//! so anyone with the account can reproduce them:
//! the two vault-scoping tests, the four name-form tests, the two discovery tests
//! and the viewer-role write refusal.
//! Two of those name-form tests, the trashed title and the missing one, asserted
//! a degraded run then and assert a refused one now; the refusal has not yet
//! been observed live.
//!
//! **Six need a fixture that is a VALUE or a foreign share, and were not run in
//! that session.** They panic naming the variable, which is the correct outcome —
//! a live test that passes without its inputs is a green result for work that
//! never happened:
//!
//! | Needs | Why it was not supplied |
//! |---|---|
//! | `KEYLESS_LIVE_EXPECTED` | it is the decoy item's value, and exporting it means reading a credential first |
//! | `KEYLESS_LIVE_REFERENCE` | derivable from a listing, but the tests that use it also want `EXPECTED` |
//! | `KEYLESS_LIVE_FOREIGN` | a share id in a vault the token was NOT granted, which needs a second vault |
//! | `KEYLESS_LIVE_TITLE` | a LIVE decoy item; the vault holds one live custom item and one trashed login |
//!
//! `a_live_name_resolves_without_an_id_anywhere_in_the_config`'s own doc comment,
//! in `proton_live_names.rs`, says exactly what to create for it.
//!
//! **Export `KEYLESS_LIVE_FOREIGN` only AFTER deriving the other fixtures.**
//! `pass-cli run` resolves every `pass://` in the environment it inherits, so a
//! deliberately-unresolvable reference exported first fails any `pass-cli run`
//! used to read a decoy value — and hands back an empty string rather than an
//! error. That happened while building this suite's own fixtures.
//!
//! # What these tests must never do
//!
//! Use a disposable decoy item, in a vault that holds nothing real. Every read
//! is logged off-machine, permanently, and no assertion here prints a value:
//! a mismatch reports lengths, never contents.

mod proton_live_support;
mod support;

use std::path::Path;

use keyless::State;

use proton_live_support::{assert_is_expected, registry_from, required};
use support::{run_with, scratch, witness, witnessed};

fn live_config(session_dir: &str, reference: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"session_dir":"{session_dir}","timeout_ms":20000}}}},
            "secrets":{{"DECOY":{{"reference":"{reference}"}}}}}}"#
    )
}

/// 1. A reference resolves end to end through `pass-cli run --env-file`.
///
/// This test also carries the wiring check for `remove_ambient_references`:
/// the runner exports `KEYLESS_LIVE_FOREIGN`, which holds a `pass://` reference
/// the scoped session cannot resolve. Before the filter existed, `pass-cli run`
/// found that variable in the inherited environment, tried to resolve it, and
/// failed the whole lookup — so this test injected nothing and the child saw
/// `<unset>`. That is how the behaviour was found.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_reference_resolves_into_the_child_and_nowhere_else() {
    let expected = required("KEYLESS_LIVE_EXPECTED");
    assert!(
        required("KEYLESS_LIVE_FOREIGN").contains("pass://"),
        "this test needs an unresolvable ambient reference to be meaningful"
    );
    let dir = scratch("proton-live-resolve");
    let marker = dir.join("witness");
    let registry = registry_from(&live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_REFERENCE"),
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_is_expected(&witnessed(&marker), &expected, "the injected value");
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(notes, "", "a successful run says nothing at all");
}

/// 2a. The configured session sees exactly the vaults it was granted.
///
/// The scoping stated as a set rather than as a failed read, which is the
/// stronger claim and the cheaper one: it needs no reason, reads no value, and
/// aims at nothing. `KEYLESS_LIVE_VAULTS` is a comma-separated list the
/// operator writes out by hand — an independent statement of what the token was
/// minted for, not something derived from the same command being checked.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn the_configured_session_sees_exactly_the_vaults_it_was_granted() {
    let expected: Vec<String> = {
        let mut names: Vec<String> = required("KEYLESS_LIVE_VAULTS")
            .split(',')
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .collect();
        names.sort();
        names
    };

    let output = std::process::Command::new("pass-cli")
        .args(["vault", "list", "--output", "json"])
        .env(
            "PROTON_PASS_SESSION_DIR",
            required("KEYLESS_LIVE_SESSION_DIR"),
        )
        .output()
        .expect("`pass-cli` must be on PATH");
    assert!(
        output.status.success(),
        "the vendor CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("`vault list --output json` must be JSON");
    let mut seen: Vec<String> = parsed["vaults"]
        .as_array()
        .expect("a `vaults` array")
        .iter()
        .filter_map(|vault| vault["name"].as_str().map(str::to_owned))
        .collect();
    seen.sort();

    // Vault NAMES are not credentials, so naming them in a failure is safe and
    // is the only way this failure is diagnosable.
    assert_eq!(
        seen, expected,
        "the configured session is not the scoped one"
    );
}

/// 2b. A share the token was not granted does not resolve.
///
/// The same property from the other side, exercised through the adapter. It
/// must fail as a backend error, not as a value from somewhere else.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn the_scoped_session_cannot_reach_a_vault_it_was_not_granted() {
    let dir = scratch("proton-live-foreign");
    let marker = dir.join("witness");
    let registry = registry_from(&live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_FOREIGN"),
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 5), &[]);

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "the scoped session read a vault it was never granted"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.exit_code, 5, "the child's exit code must come back");
    assert!(notes.contains("DECOY"), "the banner must name the secret");
}

/// 4. A session directory with no session degrades, and the child still runs.
///
/// Stands in for an expired token: `pass-cli` finds no session under the
/// directory and fails to authenticate. That must cost the *name*, never the
/// *command*.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn an_absent_session_degrades_the_name_and_still_runs_the_command() {
    let dir = scratch("proton-live-nosession");
    let marker = dir.join("witness");
    let empty = dir.join("no-session-here");
    std::fs::create_dir_all(&empty).expect("create an empty session directory");

    let registry = registry_from(&live_config(
        &empty.to_string_lossy(),
        &required("KEYLESS_LIVE_REFERENCE"),
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 29), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(
        outcome.exit_code, 29,
        "an unauthenticated store must not swallow the child's exit code"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("DEGRADED"), "{notes}");
}

/// 5. The probe env file is gone even when the child fails.
///
/// `Drop` is what deletes it, so the interesting path is the one that returns
/// early. A child that exits non-zero exercises it without needing a panic.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn the_probe_env_file_does_not_outlive_a_failing_child() {
    let dir = scratch("proton-live-cleanup");
    let marker = dir.join("witness");
    let registry = registry_from(&live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_REFERENCE"),
    ));

    let before = probe_files();
    let (outcome, _) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 3), &[]);
    let after = probe_files();

    assert_eq!(outcome.exit_code, 3);
    assert_eq!(
        after, before,
        "a probe env file outlived its lookup: {after:?}"
    );
}

/// Every `keyless-probe-*.env` currently in the platform temp directory.
///
/// Compared before and after rather than asserted empty: another `keyless` on
/// this machine may legitimately have one open, and a test that fails because a
/// sibling process exists is a test nobody trusts.
fn probe_files() -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(std::env::temp_dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("keyless-probe-") && Path::new(name).extension().is_some())
        .collect();
    found.sort();
    found
}
