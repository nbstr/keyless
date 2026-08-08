//! What may appear in a fixture coordinate, and what may not.
//!
//! # Why this file exists
//!
//! One commit replaced the maintainer's own vault and item names with neutral
//! placeholders. The very next commit put real coordinates back — in a test
//! written to reproduce a real bug, against the real item that exhibited it.
//! Nothing noticed, because a fixture holding a real vault coordinate compiles,
//! runs and passes exactly like one holding a decoy. The reviewer found it, and
//! a review that has to run twice is not a control.
//!
//! # Why an allowlist and not a denylist
//!
//! A denylist would catch the two strings that already came back and nothing
//! else — and it would only do that by carrying those two real names in the
//! published repository in order to forbid them, which is the disclosure it is
//! supposed to prevent.
//!
//! An allowlist catches the NEXT one, whatever it is called, and it names only
//! decoys. Adding a coordinate to a fixture means adding it here, which is the
//! moment somebody has to answer "is this one mine?" out loud.
//!
//! # What this does not cover
//!
//! `src/` and `tests/` only — the crate's own sources. `hooks/` and `site/`
//! are published from this repository too and are NOT scanned; they have
//! separate owners and are not Rust. Extending the scan is one entry in
//! [`SCANNED_ROOTS`] plus a file-extension change, and nothing here pretends
//! that work is done.

use std::path::{Path, PathBuf};

/// Every vault, item, share and title literal a fixture is allowed to use.
///
/// All invented. None addresses anything in any real account, and no test in
/// this crate reaches a real vault — see the `Development` section of the
/// README for the full statement of that.
const DECOY_COORDINATES: &[&str] = &[
    // Proton item ids and share ids.
    "-Kx7Qm2Za",
    "-Sh4r3",
    "ITEM1",
    "SHARE1",
    // Vault names.
    "-dashvault",
    "personal",
    // Item titles.
    "",
    "Router",
    "decoy",
    "demo api key",
    "demo.service",
    "keyless-decoy-alpha",
    "t",
];

/// A decoy item id has to keep this property, because a test depends on it.
///
/// `pass-cli` parses with clap, which reads a standalone argument beginning
/// with a single `-` as a cluster of short flags and refuses the command. That
/// is the bug the dash-leading fixtures exist to reproduce, so "tidying" the
/// decoy id into something that does not begin with `-` would leave every one
/// of those tests green and testing nothing.
///
/// This is the cheap half of the lesson: the property is what the test needs,
/// and a real coordinate was never required to carry it.
const BASE64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Where a coordinate can appear, spelled as the literal that precedes it.
///
/// Both the flag form the adapter builds and the quoted form a fixture holds.
/// The flag says `false`: it is one shell word, so a space ends it. The quoted
/// forms say `true`, because an item title legitimately contains spaces and
/// ending on the first one truncates the value into something that matches
/// nothing — an allowlist compared against a truncation reports every entry as
/// an offender, which is a loud failure but the wrong one.
const MARKERS: &[(&str, bool)] = &[
    ("--item-id=", false),
    ("--share-id=", false),
    ("--vault-name=", false),
    ("--item-title=", false),
    ("\"title\":\"", true),
    ("\"title\": \"", true),
    ("title: \"", true),
];

const SCANNED_ROOTS: &[&str] = &["src", "tests"];

/// Every coordinate-position value in `source`, with the marker that found it.
fn coordinates(source: &str) -> Vec<(&'static str, String)> {
    let mut found = Vec::new();
    for (marker, quoted) in MARKERS {
        let mut rest = source;
        while let Some(at) = rest.find(marker) {
            let after = &rest[at + marker.len()..];
            // A value ends at the closing quote or an escape in either
            // spelling, and additionally at a word break when it is a bare
            // shell argument rather than a quoted string.
            let end = after
                .find(|c: char| {
                    c == '"' || c == '\\' || c == '\'' || (!quoted && c.is_whitespace())
                })
                .unwrap_or(after.len());
            let value = &after[..end];
            // A documentation metavariable is not a coordinate. `<vault>` in a
            // doc comment names the shape of an argument, not an account.
            if !value.starts_with('<') {
                found.push((*marker, value.to_owned()));
            }
            rest = &after[end..];
        }
    }
    found
}

fn rust_sources() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for scanned in SCANNED_ROOTS {
        walk(&root.join(scanned), &mut sources);
    }
    sources.sort();
    sources
}

#[test]
fn every_fixture_coordinate_is_an_allowlisted_decoy() {
    let mut seen = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    // This file is excluded from its own scan: it holds the allowlist, and
    // `the_scanner_can_actually_fail` deliberately plants a value that is not on
    // it. Spelled with `file!()` rather than a literal name so a rename cannot
    // quietly re-include it and turn the control into an offender.
    let guard = Path::new(env!("CARGO_MANIFEST_DIR")).join(file!());

    for path in rust_sources() {
        if path == guard {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("a readable source file");
        for (marker, value) in coordinates(&source) {
            seen += 1;
            if !DECOY_COORDINATES.contains(&value.as_str()) {
                offenders.push(format!("{}: `{marker}{value}`", path.display()));
            }
        }
    }

    // The negative control, and it is the point of the whole file. A marker
    // that stops matching — a fixture rewritten, a flag renamed — would leave
    // this test scanning nothing and reporting a pass, which is exactly how the
    // coordinates got back in unnoticed the first time. So the scan has to
    // prove it read something before its silence means anything.
    assert!(
        seen >= 20,
        "the scan found only {seen} coordinates, so it is not reading the fixtures any more \
         and its silence proves nothing: check MARKERS against the fixtures"
    );

    assert!(
        offenders.is_empty(),
        "a coordinate outside the decoy allowlist reached a fixture.\n\
         If it is invented, add it to DECOY_COORDINATES. If it names anything in a real \
         account, it must not be in this repository at all.\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_scanner_can_actually_fail() {
    // Without this the test above could be vacuous in the other direction: an
    // extractor that finds values but never rejects one reads exactly like a
    // clean repository.
    let planted = "let argv = \"--item-id=NOT-ON-THE-ALLOWLIST\";";
    let found = coordinates(planted);

    assert_eq!(found.len(), 1, "the extractor missed a planted coordinate");
    assert_eq!(found[0].1, "NOT-ON-THE-ALLOWLIST");
    assert!(
        !DECOY_COORDINATES.contains(&found[0].1.as_str()),
        "the planted value must not be allowlisted, or this control proves nothing"
    );
}

#[test]
fn a_documentation_metavariable_is_not_read_as_a_coordinate() {
    // `--vault-name=<vault>` appears in a doc comment describing the shape of
    // the argument. Reading it as a coordinate would make the allowlist grow to
    // hold prose, and an allowlist nobody can keep accurate gets deleted.
    assert!(coordinates("`pass-cli item list --vault-name=<vault>`").is_empty());
}

#[test]
fn a_decoy_item_id_still_begins_with_a_dash() {
    let dash_leading: Vec<&&str> = DECOY_COORDINATES
        .iter()
        .filter(|value| value.starts_with('-') && value.len() > 1)
        .collect();

    assert!(
        !dash_leading.is_empty(),
        "no decoy coordinate begins with `-` any more, so every test of the \
         dash-leading-id refusal is now green against a value that cannot trigger it"
    );

    for value in dash_leading {
        assert!(
            value.chars().all(|c| BASE64URL.contains(c)),
            "`{value}` is not base64url, so it is not the shape a real Proton id has \
             and the fixture no longer reproduces the vendor's parser"
        );
    }
}
