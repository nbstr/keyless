//! The Proton Pass path against a real account and the real `pass-cli`.
//!
//! Every other Proton test in this suite runs against a shell stub. A stub
//! proves the adapter builds an invocation that matches a contract someone
//! wrote down; it cannot prove the contract is the CLI's. These tests close
//! that gap, and they are the reason `proton.rs` may say "observed" rather than
//! "documented".
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
//! cargo test --test proton_live -- --ignored --test-threads=1
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
//! [`a_live_name_resolves_without_an_id_anywhere_in_the_config`]'s own doc comment
//! says exactly what to create for it.
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

mod support;

use std::path::Path;

use keyless::State;
use keyless::config::Config;
use keyless::store::proton::Reason;
use keyless::store::{self, Invocation, Registry};

use support::{run_with, scratch, witness, witnessed};

/// A required input, or a panic naming it.
///
/// Never a default and never a skip: a live test that invents its own inputs
/// verifies the invention.
fn required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        panic!("{key} must be set to run the live Proton tests; see this file's header")
    })
}

fn live_config(session_dir: &str, reference: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"session_dir":"{session_dir}","timeout_ms":20000}}}},
            "secrets":{{"DECOY":{{"reference":"{reference}"}}}}}}"#
    )
}

fn registry_from(json: &str) -> Registry {
    let config: Config = serde_json::from_str(json).expect("the test config must be valid");
    store::build(&config, &Invocation::default()).registry
}

/// Assert equality without ever putting either side in the failure message.
fn assert_is_expected(got: &str, expected: &str, what: &str) {
    assert_eq!(
        got.len(),
        expected.len(),
        "{what}: got {} bytes, expected {}",
        got.len(),
        expected.len()
    );
    assert!(got == expected, "{what}: same length, different bytes");
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

/// 3. The two maskers do not collide, because only one is ever in the pipe.
///
/// `keyless` spawns the user's command **itself** — `pass-cli` is in the pipe
/// for the probe and nowhere else — so the vendor's masking never sees the real
/// child's output and this crate's masker never sees the vendor's placeholder.
/// The one place they could collide is the probe, which reads its child's
/// stdout: leave the vendor's masking on there and the adapter injects the
/// placeholder as though it were the credential.
///
/// So this measures the vendor directly, in both settings, and proves
/// `--no-masking` is load-bearing rather than decorative. Nothing here goes
/// through `keyless`, on purpose: the adapter always passes the flag, so the
/// unflagged behaviour is unreachable from inside it.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn the_vendor_conceals_the_probes_own_output_unless_masking_is_switched_off() {
    let dir = scratch("proton-live-masking");
    let reference = required("KEYLESS_LIVE_REFERENCE");
    let env_file = dir.join("probe.dotenv");
    std::fs::write(&env_file, format!("KEYLESS_PROBE={reference}\n")).expect("write the env file");

    let unmasked = probe_directly(&env_file, true);
    let masked = probe_directly(&env_file, false);

    assert!(
        !unmasked.contains("concealed"),
        "`--no-masking` did not switch the vendor's masking off"
    );
    assert!(
        masked.to_ascii_lowercase().contains("concealed"),
        "the vendor did not conceal without the flag, so the guard in `proton.rs` \
         is protecting against nothing — re-read what it substitutes now"
    );
    assert_ne!(
        masked.len(),
        unmasked.len(),
        "both settings produced the same number of bytes"
    );
}

/// Run the vendor's `run` verb directly and return its child's stdout.
///
/// Returns the raw bytes as a string — which for `no_masking` is the decoy
/// value — so every caller must assert on it without printing it.
fn probe_directly(env_file: &Path, no_masking: bool) -> String {
    let mut command = std::process::Command::new("pass-cli");
    command.arg("run").arg("--env-file").arg(env_file);
    if no_masking {
        command.arg("--no-masking");
    }
    // This test drives the vendor directly, so it does not get the adapter's
    // ambient-reference filter for free. The runner's own inputs hold `pass://`
    // strings, and `pass-cli run` resolves every one it finds in the inherited
    // environment — which would fail this probe for a reason that has nothing
    // to do with masking.
    for key in ["KEYLESS_LIVE_REFERENCE", "KEYLESS_LIVE_FOREIGN"] {
        command.env_remove(key);
    }
    command
        .arg("--")
        .arg("/usr/bin/printenv")
        .arg("KEYLESS_PROBE")
        .env(
            "PROTON_PASS_SESSION_DIR",
            required("KEYLESS_LIVE_SESSION_DIR"),
        )
        .env(
            "PROTON_PASS_AGENT_REASON",
            "keyless test suite: measuring the vendor's masking default",
        );
    let output = command.output().expect("`pass-cli` must be on PATH");
    assert!(
        output.status.success(),
        "the vendor CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned()
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

// ---------------------------------------------------------------------------
// The name form, against the real CLI.
//
// The whole reason it exists: a share id is minted per session. Measured
// 2026-08-08, vault `personal` answered with one share id to the agent session and a
// different one to the full account — so an address made of ids cannot survive
// a token renewal, and the volatile half has to be looked up every time.
// ---------------------------------------------------------------------------

/// A config that addresses one name by vault, title and field.
fn named_live_config(session_dir: &str, vault: &str, title: &str, field: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"session_dir":"{session_dir}","timeout_ms":20000}}}},
            "secrets":{{"DECOY":{{"vault":"{vault}","item":"{title}","field":"{field}"}}}}}}"#
    )
}

/// 6. The record shape the whole name form rests on.
///
/// Asserted against the vendor directly rather than through the adapter: the
/// adapter's parse would agree with itself whatever the CLI returned, so the
/// claim "the item id is under `id`" has to be checked here or nowhere. The
/// keys measured on 2026-08-08 were `id`, `share_id`, `vault_id`, `state`,
/// `flags`, `create_time`, `modify_time`, `title`, `item_type`.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn the_listing_carries_a_share_id_an_id_and_a_state_but_no_item_id() {
    let vault = required("KEYLESS_LIVE_VAULT");
    let output = std::process::Command::new("pass-cli")
        .args(["item", "list", "--vault-name", &vault, "--output", "json"])
        .env(
            "PROTON_PASS_SESSION_DIR",
            required("KEYLESS_LIVE_SESSION_DIR"),
        )
        .env(
            "PROTON_PASS_AGENT_REASON",
            "keyless test suite: checking the listing's record shape",
        )
        .output()
        .expect("`pass-cli` must be on PATH");
    assert!(
        output.status.success(),
        "the vendor CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("`item list --output json` must be JSON");
    let items = parsed["items"].as_array().expect("an `items` array");
    assert!(
        !items.is_empty(),
        "vault `{vault}` is empty, so this test asserts nothing"
    );

    for item in items {
        for key in ["id", "share_id", "state", "title"] {
            assert!(
                item[key].as_str().is_some_and(|value| !value.is_empty()),
                "`{key}` is absent or empty, and the name form cannot work without it"
            );
        }
        assert!(
            item["item_id"].is_null(),
            "an `item_id` key appeared; the adapter reads `id` and would now be reading \
             the wrong one of two"
        );
    }
}

/// 7. A trashed item does not resolve, and the command still runs.
///
/// The one rule this vault can prove for real today: `personal` holds exactly one
/// item and it is in the trash. Resolving it would hand a child a value its
/// owner believes they deleted, and a trashed item is still returned by
/// `item list`, so nothing about the listing itself refuses it.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_trashed_item_degrades_the_name_and_still_runs_the_command() {
    let dir = scratch("proton-live-trashed");
    let marker = dir.join("witness");
    let registry = registry_from(&named_live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_VAULT"),
        &required("KEYLESS_LIVE_TRASHED_TITLE"),
        "password",
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 41), &[]);

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "a trashed item was resolved and injected"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(
        outcome.exit_code, 41,
        "the child's exit code must come back"
    );
    assert!(notes.contains("trash"), "the banner must say why: {notes}");
}

/// 8. A title nothing in the vault carries degrades rather than guessing.
///
/// The negative control for the two above: without it they could both pass on
/// an adapter that never resolves a named address at all. The title is one this
/// suite invents, so it cannot collide with anything a person created.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_title_that_exists_nowhere_degrades_and_still_runs() {
    let dir = scratch("proton-live-no-title");
    let marker = dir.join("witness");
    let registry = registry_from(&named_live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_VAULT"),
        "keyless-there-is-no-item-with-this-title",
        "password",
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 43), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.exit_code, 43);
    assert!(
        notes.contains("keyless-there-is-no-item-with-this-title"),
        "the banner must name the title it could not find: {notes}"
    );
    assert!(
        !notes.contains("trash"),
        "nothing was in the trash: {notes}"
    );
}

/// 9. A vault this session cannot list degrades rather than failing the run.
///
/// Stands in for a revoked grant or a renamed vault. Measured 2026-08-08: the
/// CLI exits 1 with `Could not find vault <name>`.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_vault_that_cannot_be_listed_degrades_and_still_runs() {
    let dir = scratch("proton-live-no-vault");
    let marker = dir.join("witness");
    let registry = registry_from(&named_live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        "keyless-no-such-vault-anywhere",
        "anything",
        "password",
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 47), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.state, State::Degraded);
    assert_eq!(outcome.exit_code, 47);
    assert!(
        notes.contains("keyless-no-such-vault-anywhere"),
        "the banner must name the vault: {notes}"
    );
}

/// 10. A name resolves end to end, with no id anywhere in the config.
///
/// **This is the positive path, and it is the one assertion the vault cannot
/// currently make.** `personal` holds a single item and it is trashed, and the agent
/// token is read-only — `item create` returns `NotAllowed` — so the item cannot
/// be made from inside this suite.
///
/// To make it run, create a **login** item in vault `personal` titled
/// `keyless-decoy-live`, with any disposable string in its `password` field,
/// then export:
///
/// ```text
/// export KEYLESS_LIVE_TITLE='keyless-decoy-live'
/// export KEYLESS_LIVE_FIELD='password'
/// export KEYLESS_LIVE_EXPECTED='that same disposable string'
/// ```
///
/// It panics naming the missing variable rather than skipping. A live test that
/// passes when its inputs are absent is a green result for work that never
/// happened, which is the failure this whole file is written to avoid.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_name_resolves_without_an_id_anywhere_in_the_config() {
    let expected = required("KEYLESS_LIVE_EXPECTED");
    let dir = scratch("proton-live-named");
    let marker = dir.join("witness");
    let registry = registry_from(&named_live_config(
        &required("KEYLESS_LIVE_SESSION_DIR"),
        &required("KEYLESS_LIVE_VAULT"),
        &required("KEYLESS_LIVE_TITLE"),
        &required("KEYLESS_LIVE_FIELD"),
    ));

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_is_expected(&witnessed(&marker), &expected, "the injected value");
    assert_eq!(outcome.state, State::Injected, "{notes}");
    assert_eq!(notes, "", "a successful run says nothing at all");
}

// ---------------------------------------------------------------------------
// Discovery, against the real CLI.
//
// These are the reason `items` and `fields` exist. A stub proves the extraction
// handles a shape somebody wrote down; only the real CLI proves the shape is the
// CLI's — and it was NOT what `item create custom --get-template` describes,
// which is the only shape readable without printing a credential.
// ---------------------------------------------------------------------------

/// A config with a reader identity and no names declared at all.
///
/// `items` and `fields` ask the store, not the config, so a config that declares
/// nothing is the honest fixture: a caller reaches for these verbs precisely
/// because they do not yet know what to declare.
fn discovery_config(session_dir: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"session_dir":"{session_dir}","timeout_ms":30000}}}}}}"#
    )
}

fn live_discoverer(json: &str) -> Box<dyn keyless::store::discover::Discover> {
    let config: Config = serde_json::from_str(json).expect("the test config must be valid");
    keyless::store::discover::discoverer(&config, "proton", &Reason::for_verb("test"))
        .expect("proton must have a discoverer")
}

/// 11. `items` lists a live item and a trashed one, and marks which is which.
///
/// The trash rule from the other side: resolution refuses a trashed item, and
/// discovery must still SHOW it — somebody hunting a name that stopped resolving
/// has to be able to see that the item exists and is in the bin.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_listing_shows_a_trashed_item_and_marks_its_state() {
    let vault = required("KEYLESS_LIVE_VAULT");
    let discover = live_discoverer(&discovery_config(&required("KEYLESS_LIVE_SESSION_DIR")));
    let items = discover
        .items(Some(&vault))
        .expect("the scoped session must be able to list its own vault");

    assert!(
        !items.is_empty(),
        "vault `{vault}` is empty, so this test asserts nothing"
    );

    let trashed_title = required("KEYLESS_LIVE_TRASHED_TITLE");
    let trashed = items
        .iter()
        .find(|item| item.title == trashed_title)
        .unwrap_or_else(|| panic!("`{trashed_title}` is not in the listing"));
    assert!(
        !trashed.is_active(),
        "a trashed item was reported as active: state was `{}`",
        trashed.state
    );

    // The negative control: without a live item in the same listing, the
    // assertion above could pass on an implementation that calls everything
    // trashed.
    let live_title = required("KEYLESS_LIVE_CUSTOM_TITLE");
    let live = items
        .iter()
        .find(|item| item.title == live_title)
        .unwrap_or_else(|| panic!("`{live_title}` is not in the listing"));
    assert!(live.is_active(), "state was `{}`", live.state);
    assert_eq!(live.vault, vault);
    assert!(!live.kind.is_empty(), "the item type column was empty");
}

/// 12. `fields` reports a custom item's real field names, and no value.
///
/// **This is the assertion the whole discovery half exists for.** `keyless`
/// degraded once because a configured `field` did not match the item's real field
/// name, and the name could not be found: the only vendor verb that reveals it
/// also prints the value.
///
/// `KEYLESS_LIVE_CUSTOM_FIELD` is the name the operator expects, written out by
/// hand — an independent statement of what the item is, not something derived from
/// the command under test.
///
/// **This test does not carry the field's value, and deliberately so.** Requiring
/// the operator to export it would mean someone had to read it first, which is the
/// thing this verb exists to make unnecessary. The "a value never reaches the name
/// column" property is checked where it can be checked with a real needle: the
/// hand-written view fixture in `store::proton`, whose every value position holds
/// a marker string. What this test adds is the half a fixture cannot prove — that
/// the shape is the CLI's, and that the sibling keys of a value are reported as
/// structure rather than as fields.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_custom_items_field_names_are_reported_and_its_structure_is_not() {
    let vault = required("KEYLESS_LIVE_VAULT");
    let title = required("KEYLESS_LIVE_CUSTOM_TITLE");
    let expected = required("KEYLESS_LIVE_CUSTOM_FIELD");

    let discover = live_discoverer(&discovery_config(&required("KEYLESS_LIVE_SESSION_DIR")));
    let fields = discover
        .fields(Some(&vault), &title)
        .expect("a live custom item must report its fields");

    let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();
    assert!(
        names.contains(&expected.as_str()),
        "`{expected}` is not among the reported field names: {names:?}"
    );

    // The keys that sit beside a value on the real shape. Reporting one of these
    // as a field would mean the extraction recursed into a value container, which
    // is the step that stands between the credential and stdout.
    for structural in [
        "content",
        "Hidden",
        "Text",
        "Timestamp",
        "item_uuid",
        "name",
    ] {
        assert!(
            !names.contains(&structural),
            "`{structural}` is structure, not a field: {names:?}"
        );
    }

    // A custom field is reported as such and carries the vendor's own type word,
    // which is what makes a `Timestamp` field distinguishable from the credential.
    let found = fields
        .iter()
        .find(|field| field.name == expected)
        .expect("checked above");
    assert_eq!(found.kind.as_str(), "custom");
    assert!(
        found.value_type.is_some(),
        "the type column was empty for a custom field"
    );
}

/// 13. `fields` on a trashed item refuses and says why.
///
/// Reporting its fields would send the reader to write a config entry against a
/// title that can never resolve, because the resolver refuses a trashed item on
/// purpose.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_trashed_items_fields_are_refused_with_the_reason() {
    let discover = live_discoverer(&discovery_config(&required("KEYLESS_LIVE_SESSION_DIR")));
    let message = discover
        .fields(
            Some(&required("KEYLESS_LIVE_VAULT")),
            &required("KEYLESS_LIVE_TRASHED_TITLE"),
        )
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(message.contains("trash"), "{message}");
}

/// 14. A viewer-role token cannot write, and the failure names the role.
///
/// **This is the one write assertion this account can make.** Measured
/// 2026-08-08: `--role` on `pass-cli agent access grant` defaults to `viewer`, so
/// a token minted without thinking about the role is read-only and `item create`
/// answers `NotAllowed`. A bare `NotAllowed` sends the reader hunting through
/// vault permissions, which are not the problem.
///
/// It deliberately points the MANAGER session at the reader's session directory:
/// that is the only editor-shaped configuration this account can express, and the
/// point is that even so the vendor refuses. **Nothing is created by this test**
/// — the refusal is the assertion. Once a real editor token exists, this test
/// needs `KEYLESS_LIVE_MANAGER_SESSION_DIR` pointed at it and inverting.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_viewer_role_token_cannot_create_and_the_failure_names_the_role() {
    let session = required("KEYLESS_LIVE_SESSION_DIR");
    let vault = required("KEYLESS_LIVE_VAULT");
    let config: Config = serde_json::from_str(&format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"session_dir":"{session}","timeout_ms":30000,
                        "manager":{{"session_dir":"{session}","timeout_ms":30000}}}}}},
            "secrets":{{"DECOY":{{"vault":"{vault}",
                                  "item":"keyless-live-write-probe-do-not-create",
                                  "field":"password"}}}}}}"#
    ))
    .expect("valid config");

    let manager = keyless::store::manage::manager(&config, "proton", &Reason::for_verb("new"))
        .expect(
            "a manager block is configured, so a writer must be constructible even if it cannot \
             write",
        );
    assert_eq!(manager.identity(), "proton (manager)");

    let message = manager
        .store(
            "DECOY",
            &config.route("DECOY"),
            &keyless::secret::Secret::new("decoy-live-write-probe-value".to_owned()),
        )
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());

    assert!(
        message.contains("ROLE") || message.contains("role"),
        "the refusal must attach the fix to the failure: {message}"
    );
    assert!(
        message.contains("--role editor"),
        "the refusal must name the flag: {message}"
    );
    assert!(
        !message.contains("decoy-live-write-probe-value"),
        "the refusal carried the value"
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
