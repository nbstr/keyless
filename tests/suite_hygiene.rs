//! Properties of the SUITE, asserted by the suite.
//!
//! Everything else in `tests/` checks the tool. This file checks the fixtures,
//! because a fixture can be wrong in a way that no amount of green will show.
//!
//! # The defect this exists for
//!
//! Every store adapter runs its vendor CLI under a deadline, and every fixture
//! that wants a SUCCESS therefore has to name one. That number is a CEILING and
//! never a measurement: a test asserting "the value reached the child" has no
//! opinion about how long the stub took. So the only thing the number decides is
//! **how loaded this machine has to be before a passing test reports a
//! failure.**
//!
//! It was `5000` almost everywhere, which encodes "no fork of `/bin/sh` is ever
//! slower than five seconds". Measured 2026-08-09 on macOS, with a `cargo
//! mutants` campaign running beside the suite at `--jobs 2`: six fixtures in
//! `tests/stores.rs` failed with `no answer within 5000 ms`, and all of them
//! passed the moment the suite ran alone.
//!
//! Both shapes that produces are worse than a plain failure:
//!
//! * A FALSE RED. `the_proton_reason_never_carries_an_argument_value` panics
//!   with `pass-cli.reason was never written` — the stub was killed before its
//!   first line ran, so a runtime artefact is absent and the panic reads like a
//!   missing fixture file. It sent one reader looking for a file to commit; the
//!   file is written by a shell stub into a per-test scratch directory and must
//!   never be in the repository.
//! * A FALSE GREEN, which is the expensive one.
//!   `a_name_with_no_infisical_environment_still_spawns_the_child` says in its
//!   own comment that the answering stub is what stops it being vacuous. A stub
//!   that times out cannot answer, so under load that test asserts a degrade
//!   that would happen anyway — it goes green while measuring nothing.
//!
//! # Why a gate rather than a sweep
//!
//! The sweep was done twice and missed three call sites both times, in two files
//! nobody thought to look at (`tests/cli.rs`, `tests/never_block.rs`). A number
//! that has to be remembered is a number that drifts back.
//!
//! # What this CANNOT see, which is most of the reason to read it
//!
//! * **Only the JSON spelling.** It reads `"timeout_ms":<digits>` out of the
//!   config strings. Deadlines passed as Rust values —
//!   `DaemonStore::new(path, Duration::from_secs(10))`, `client_config(sock,
//!   3_000)` — are invisible here. Those bound a unix-socket round trip to an
//!   in-process daemon rather than a `fork` + `exec` of a shell, so their margin
//!   is far wider, but the gap is real and it is not closed.
//! * **It cannot tell a ceiling from a measurement.** That is why the table
//!   below is a table and not a threshold: only a human knows whether a number
//!   is the subject of a test or merely a bound on it. A threshold would have
//!   had to call `750` (a value under test in `tests/hostile.rs`) and `5000` (a
//!   ceiling that broke) the same thing.
//! * It scans SOURCE. A fixture that computes a timeout at runtime is not seen.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every `"timeout_ms"` a config string in `tests/` is allowed to name, and why.
///
/// Add a row rather than a value: the reason is the whole point of the table.
/// A number with no row turns this test red with the file that introduced it.
const CLASSIFIED: &[(u64, &str)] = &[
    (
        200,
        "tests/daemon_degraded.rs — the deadline IS the subject: the test asserts \
         the message a client prints when a daemon does not answer.",
    ),
    (
        300,
        "tests/stores.rs — the deadline IS the subject: two fixtures assert the \
         wording of `no answer within 300 ms` against a stub that sleeps.",
    ),
    (
        750,
        "tests/hostile.rs — not a deadline at all. It is the negative control for \
         timeout clamping, and the test asserts the parsed value comes back \
         unchanged. Nothing is spawned.",
    ),
    (
        20_000,
        "tests/proton_live.rs — a ceiling on the REAL `pass-cli` against a real \
         Proton account over the network. Every test using it is `#[ignore]`d and \
         needs credentials, so it never runs in CI.",
    ),
    (
        30_000,
        "tests/proton_live.rs — the same, for the discovery and write probes, \
         which make more round trips than a single read.",
    ),
    (
        60_000,
        "The generous ceiling for a stub that MUST answer. Not a measurement: no \
         fixture using it asserts anything about elapsed time. It is set far above \
         any plausible `fork` + `exec` so that a loaded machine cannot turn a \
         passing test red.",
    ),
    (
        86_400_000,
        "tests/hostile.rs — a day, named deliberately by a hostile config to prove \
         `stores.daemon.timeout_ms` is clamped. The number is the attack.",
    ),
];

/// The floor a ceiling has to clear. Below this, a number must be a deliberate
/// measurement with its own row above, or it is the defect this file exists for.
const CEILING_FLOOR_MS: u64 = 20_000;

#[test]
fn every_fixture_deadline_is_classified() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = Vec::new();
    collect_rust_sources(&root, &mut sources);
    assert!(
        sources.len() >= 10,
        "only {} source files were found under {} — the scan collapsed, and a \
         scan that reads nothing passes everything",
        sources.len(),
        root.display()
    );

    let mut found: BTreeSet<(u64, String)> = BTreeSet::new();
    for path in &sources {
        // This file's own prose names every value in the table, so scanning it
        // would just read the table back and prove nothing.
        if path
            .file_name()
            .is_some_and(|name| name == "suite_hygiene.rs")
        {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let name = relative(&root, path);
        for value in timeouts_in(&text) {
            found.insert((value, name.clone()));
        }
    }

    assert!(
        !found.is_empty(),
        "no `\"timeout_ms\":<digits>` was found anywhere under {}. Either every \
         fixture stopped naming a deadline, or the scan below stopped matching \
         the spelling they use — and the second reads exactly like a pass.",
        root.display()
    );

    let known: BTreeSet<u64> = CLASSIFIED.iter().map(|(value, _)| *value).collect();
    let unclassified: Vec<&(u64, String)> = found
        .iter()
        .filter(|(value, _)| !known.contains(value))
        .collect();

    assert!(
        unclassified.is_empty(),
        "unclassified fixture deadline(s): {}\n\n\
         Add a row to CLASSIFIED in tests/suite_hygiene.rs saying which kind of \
         number this is.\n\
         * Is the deadline the SUBJECT of the test — does it assert the timeout \
         message? Then say so, and keep it small.\n\
         * Is it a CEILING on a stub that must answer? Then it belongs at {} or \
         above, and {} is what the rest of the suite uses. A ceiling below {} ms \
         does not measure the tool; it measures how busy this machine is.",
        unclassified
            .iter()
            .map(|(value, file)| format!("{value} in {file}"))
            .collect::<Vec<_>>()
            .join(", "),
        CEILING_FLOOR_MS,
        60_000,
        CEILING_FLOOR_MS
    );
}

/// Every `"timeout_ms":<digits>` in `text`.
///
/// A format placeholder (`"timeout_ms":{timeout_ms}` in the daemon helper) has
/// no digits after the colon and is skipped, which is correct: the value comes
/// from the caller and is a Rust expression this scan cannot see.
fn timeouts_in(text: &str) -> Vec<u64> {
    const KEY: &str = "\"timeout_ms\"";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(KEY) {
        rest = &rest[at + KEY.len()..];
        let after = rest.trim_start();
        let Some(after) = after.strip_prefix(':') else {
            continue;
        };
        let digits: String = after
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(value) = digits.parse::<u64>() {
            out.push(value);
        }
    }
    out
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
