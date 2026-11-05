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

#![allow(dead_code)]

use std::path::Path;

use keyless::config::Config;
use keyless::store::proton::Reason;
use keyless::store::{self, Invocation, Registry};

use crate::support::{SCOPED_SESSION_DIR, recorded_lines};

/// Whether `argv` carries `flag`, in either of the two spellings clap accepts.
///
/// Written once because the adapter now joins every option to its value with
/// `=`. A check for the bare string would silently stop biting on the joined
/// form — a forbidden flag would slip through a test that still reads as a
/// guard, which is the exact failure shape these tests exist to catch.
pub fn mentions(argv: &[String], flag: &str) -> bool {
    argv.iter()
        .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
}

/// Build a registry from a JSON config, as `main` does.
pub fn registry_from(json: &str, reason: &Reason) -> Registry {
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
pub fn infisical_config(binary: &Path) -> String {
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
pub fn infisical_config_for(binary: &Path, secrets: &str) -> String {
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
pub fn proton_config(binary: &Path) -> String {
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
pub const PROTON_REFERENCE: &str = "pass://ShAr3Id0decoy==/It3mId0decoy==/password";

/// One vault, so `items` with no `--vault` has something to enumerate.
pub const ONE_VAULT: &str = r#"{"vaults":[{"name":"personal","id":"V1"}]}"#;

/// A live custom item and a trashed login, which is exactly the shape of the
/// decoy vault this was written against.
pub const LIVE_AND_TRASHED: &str = r#"{"items":[
    {"id":"It3mL1v3","share_id":"ShAr3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"demo api key","item_type":"custom"},
    {"id":"It3mDead","share_id":"ShAr3","vault_id":"V","state":"Trashed","flags":[],
     "create_time":"2000-01-03T00:00:00","modify_time":"2000-01-03T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"}]}"#;

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
pub fn state_of(row: &str) -> &str {
    row.split_whitespace().nth(2).unwrap_or_default()
}

pub fn proton_row(report: &str) -> &str {
    report
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some("proton"))
        .unwrap_or_else(|| panic!("the report has no `proton` row:\n{report}"))
}

/// `doctor`'s report and its exit code, against a registry built from `config`.
pub fn doctor_report(dir: &Path, config: &str) -> (String, i32) {
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

/// The report with its wrapping removed, so a phrase may straddle a line.
pub fn flattened(report: &str) -> String {
    report.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A config with only 1Password enabled, pinned to one vault, with a store-wide
/// field, pointed at a stub. `timeout_ms` is the same ceiling every other
/// builder in this file names, for the reason `proton_config` gives.
pub fn onepassword_config(binary: &Path, secrets: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "onepassword":{{"enabled":true,"binary":"{}","vault":"company","field":"password",
                             "timeout_ms":60000}}}},
            "secrets":{secrets}}}"#,
        binary.display()
    )
}

/// The one name most 1Password fixtures declare: the stub's live item, by title.
pub const ONEPASSWORD_DECOY_BY_TITLE: &str = r#"{"DECOY":{"item":"DECOY"}}"#;

/// The verb the LAST `op` invocation ran, read off what the stub recorded.
///
/// `op.argv` is overwritten by every invocation, so after a lookup it holds the
/// `run`; after a lookup that stopped at the listing it holds the `item list`.
pub fn last_op_verb(dir: &Path) -> String {
    recorded_lines(&dir.join("op.argv"))
        .first()
        .cloned()
        .unwrap_or_default()
}
