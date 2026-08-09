//! What may appear in a published file, and what may not.
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
//! # The rule the three scanners below share
//!
//! IDENTITY is kept and must never be touched here: who built this, under what
//! name, with what judgement, and what they got wrong. The MIT copyright, the
//! author, the repository URL and the reasoning in every comment all stay.
//!
//! INVENTORY is what is inside one person's machine and accounts, and it may
//! not be published at all. The test that separates them is one question:
//! **would this fact still be true if somebody else had built the tool?**
//! "Built by nab" — no, and that is an attribution, so it stays. "The default
//! session saw two vaults" — no, and that is an inventory, so it goes.
//!
//! Three scanners, because inventory reaches source in three different shapes:
//!
//! | scanner | shape | control |
//! |---|---|---|
//! | [`every_coordinate_is_an_allowlisted_decoy`] | a vault, item, share, account or service name | [`the_coordinate_scanner_can_actually_fail`] |
//! | [`no_source_file_speaks_about_the_authors_own_machine`] | prose that makes a claim about the machine it was written on | [`the_deixis_scanner_can_actually_fail`] |
//! | [`every_record_timestamp_is_an_allowlisted_fixture`] | a wall-clock instant transcribed out of a real record | [`the_timestamp_scanner_can_actually_fail`] |
//!
//! …and one corpus, because all three of them read the WORKING TREE, and a
//! published repository is not its working tree. The same three grammars run a
//! second time over every blob any ref can reach — see the section headed *The
//! history* at the foot of this file, and
//! [`the_history_walk_sees_a_leak_that_is_only_in_history`] for the control that
//! proves it catches what a tree scanner structurally cannot.
//!
//! # Why an allowlist and not a denylist
//!
//! A denylist would catch the two strings that already came back and nothing
//! else — and it would only do that by carrying those two real names in the
//! published repository in order to forbid them, which is the disclosure it is
//! supposed to prevent.
//!
//! An allowlist catches the NEXT one, whatever it is called. Adding a
//! coordinate to a fixture means adding it here, which is the moment somebody
//! has to answer "is this one mine?" out loud.
//!
//! **The lists that govern the WORKING TREE name only decoys, and that is the
//! rule.** Two small lists beside them do not, and they are the exception, not a
//! softening of it: [`HISTORICAL_COORDINATES`] and [`HISTORICAL_INSTANTS`] hold
//! what the published HISTORY already carries and no edit can take back. A walk
//! over the history has to say what it forgives; the alternative is not looking.
//! Each entry is asserted absent from the tree and present in the history, so
//! neither list can licence a new fixture nor outlive the rewrite that would
//! empty it.
//!
//! # What this does NOT cover, stated so nobody reads silence as coverage
//!
//! - **Commit messages.** This file reads git OBJECTS and never a commit
//!   message, and five of this repository's own messages carry a census figure
//!   while every check here is green. That gate is `publication`'s
//!   commit-message direction in `hooks/tests/test_publication.py`, which owns
//!   the prose grammar; putting a second copy of that grammar here would give
//!   the repository two graders that drift apart. The split is by GRAMMAR, not
//!   by surface: this file owns the coordinate, instant and deixis grammars and
//!   runs each over both the tree and the history; that file owns the census
//!   grammar and runs it over `hooks/` and over every commit body.
//! - **A number that is a measurement of one machine.** That is a grammar over
//!   prose, and it was measured over this crate: 26 hits on `src/` + `tests/` +
//!   `README.md`, and every one of them a false positive — `Property 1 of 4`,
//!   `6 of 13 encodings`, `~20 concurrent sessions`, `64 hex`. It also missed
//!   the real leak here, which was spelled `saw two vaults` in words. A gate
//!   that refuses correct work gets deleted, so this file does not carry one;
//!   the same grammar stays where it measured clean, over `hooks/` prose.
//! - **What is already in the history.** The walk NAMES it and stops it growing;
//!   it cannot remove it. Three lists carry that residue —
//!   [`HISTORICAL_COORDINATES`], [`HISTORICAL_INSTANTS`] and
//!   [`HISTORY_DEIXIS_RATCHET`], the last of which holds 25 blobs across 8 paths
//!   whose prose describes one machine. Every one of them empties only when the
//!   history is rewritten a third time. Reading this file as "the repository is
//!   clean" would be reading a green ratchet as an empty one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ───────────────────────────────────────────────────────────────────────────
// The corpus
// ───────────────────────────────────────────────────────────────────────────

/// Every directory this repository publishes.
///
/// `hooks/` and `site/` are here because they are published from this
/// repository too, and for a long time they were not scanned at all. Adding a
/// root is not enough on its own: the walk used to filter on `ext == "rs"`, so
/// a new root contributed zero files and the scan reported clean. Both halves
/// have to move together, which is what [`TEXT_EXTENSIONS`] and
/// [`no_published_file_type_is_left_unscanned`] exist to force.
const SCANNED_ROOTS: &[&str] = &[
    ".cargo", ".github", "examples", "hooks", "install", "site", "src", "tests",
];

/// Published files that sit at the repository root rather than under one.
///
/// `LICENSE` is named here because it carries no extension, so the walk above
/// cannot reach it. It was in [`DEIXIS_EXEMPT`] before it was in this list,
/// which made that exemption vacuous — the file it excused was never scanned,
/// so removing the excuse would have changed nothing and nobody would have
/// found out. An exemption that excuses a file nobody reads is indistinguishable
/// from a working one.
const SCANNED_FILES: &[&str] = &["Cargo.lock", "Cargo.toml", "LICENSE", "README.md"];

/// Every text file type the published tree contains.
///
/// Asserted against what the tree ACTUALLY holds, so a `.toml` or a `.txt`
/// appearing for the first time fails loudly instead of being silently exempt.
const TEXT_EXTENSIONS: &[&str] = &[
    "html", "json", "md", "plist", "py", "rs", "sh", "toml", "txt", "yml",
];

/// Directories that hold build output or version-control state.
const SKIPPED_DIRS: &[&str] = &[".git", "__pycache__", "target"];

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// This file, spelled with `file!()` so a rename cannot quietly re-include it.
///
/// It is excluded from its own scans because it holds the allowlists and the
/// planted controls. The exclusion is not taken on trust:
/// [`the_guards_own_exemption_is_a_real_exemption`] proves that scanning this
/// file DOES produce offenders, so an extractor that has stopped reading cannot
/// hide behind the exemption.
fn guard_path() -> PathBuf {
    manifest_dir().join(file!())
}

fn is_text(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| TEXT_EXTENSIONS.contains(&ext))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            if !SKIPPED_DIRS.contains(&name) {
                walk(&path, out);
            }
        } else if is_text(&path) {
            out.push(path);
        }
    }
}

/// Every published text file, this guard excluded.
fn published_files() -> Vec<PathBuf> {
    let root = manifest_dir();
    let mut files = Vec::new();
    for scanned in SCANNED_ROOTS {
        walk(&root.join(scanned), &mut files);
    }
    for scanned in SCANNED_FILES {
        files.push(root.join(scanned));
    }
    let guard = guard_path();
    files.retain(|path| *path != guard);
    files.sort();
    files
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn shown(path: &Path) -> String {
    path.strip_prefix(manifest_dir())
        .unwrap_or(path)
        .display()
        .to_string()
}

// ───────────────────────────────────────────────────────────────────────────
// Scanner 1 — store coordinates
// ───────────────────────────────────────────────────────────────────────────

/// Every vault, item, share, account, service, field and title literal a
/// published file is allowed to use.
///
/// All invented. None addresses anything in any real account, and no test in
/// this crate reaches a real vault — see the `Development` section of the
/// README for the full statement of that.
///
/// It is longer than it was because the scan is wider than it was: 260
/// coordinate positions across ten file types, where the previous version read
/// seven markers in `.rs` files only. Every entry here is a decoy, a
/// single-letter stub, a documentation metavariable or a generic field label.
const DECOY_COORDINATES: &[&str] = &[
    // Proton item ids, share ids and vault ids.
    "-Kx7Qm2Za",
    "-Sh4r3",
    "I",
    "ITEM1",
    "It3mDead",
    "It3mL1v3",
    "It3mOne",
    "It3mTwo",
    "SHARE1",
    "ShAr3",
    "ShAr3L1v3",
    "V",
    "V1",
    "X",
    "a",
    "b",
    "c",
    "d",
    "id",
    "share",
    "t",
    // Vault names.
    "-dashvault",
    "Personal",
    "company",
    "personal",
    // Item titles.
    "",
    "DECOY",
    "DECOY_TOKEN",
    "GITHUB_TOKEN",
    "Router",
    "decoy",
    "decoy alpha",
    "demo api key",
    "demo.service",
    "example-api-key",
    "keyless-decoy-alpha",
    "keyless-live-write-probe-do-not-create",
    "looks like a label",
    // Keychain services and accounts.
    "acct",
    "acct-name",
    "base",
    "demo",
    "demo-token",
    "keyless",
    "kv",
    "other",
    "svc",
    // Field labels. Generic by construction: a label copied out of a real item
    // is exactly how `my api key` and `second secret` survived a scrub that had
    // already replaced the item's title.
    "API Key",
    "API Token",
    "Expiry Date",
    "api key",
    "comment",
    "expires",
    "first hidden field",
    "password",
    "second hidden field",
    "username",
    // `pass://` references, and the documentation forms of one.
    "OTHER_SHARE_ID/OTHER_ITEM_ID/password",
    "P/I/f",
    "Personal/Router/password",
    "S/I/F",
    "S/I/password",
    "SHARE/ITEM/FIELD",
    "SHARE/ITEM/a/b",
    "SHARE_ID/ITEM_ID/FIELD",
    "SHARE_ID/ITEM_ID/password",
    "ShAr3Id0decoy==/It3mId0decoy==/password",
    "ShAr3L1v3/It3mL1v3/password",
    "V/I/F",
    "a/b",
    "bogus/bogus/password",
    "personal/demo",
    "share/item/password",
    // Prose fragments that land in a coordinate position in the README.
    "name=value",
    "…",
];

/// Coordinates that only the HISTORY carries, and that no edit can remove.
///
/// The sibling of [`HISTORICAL_INSTANTS`], and it exists for the same reason:
/// the history is append-only from here, so a walk that greened without naming
/// these would be a walk that was not looking. Both directions are held by
/// [`the_historical_coordinates_are_historical_only`] — absent from every
/// published file, present in the history — so the list can neither license a
/// new fixture nor outlive the rewrite that would empty it.
///
/// **Both entries are field LABELS, and they are already written out in the
/// docstring above**, which quotes them as the worked example of a label copied
/// from a real item surviving a scrub that had already replaced the item's
/// title. Naming them here discloses nothing that the tree does not already
/// disclose; what it adds is that they are now forbidden in a fixture rather
/// than merely absent from one.
///
/// They are NOT in [`DECOY_COORDINATES`], and that is the whole point of a
/// second list: a decoy is invented, and these were not.
const HISTORICAL_COORDINATES: &[&str] = &["my api key", "second secret"];

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
/// Every entry is a store coordinate by NAME, so it means the same thing in a
/// `.rs` fixture, a `.json` config, a README code block and a doc comment. The
/// old marker list held seven entries, all of which required a `=` or an
/// embedded quote; that is why `"vaults":[{"name":"…"}]` — the exact shape the
/// leaked vault name was written in — was invisible to it, and why a coordinate
/// written `--vault personal` in a doc comment was too.
const STORE_MARKERS: &[&str] = &[
    "\"field\":",
    "\"field_name\":",
    "\"item\":",
    "\"item_id\":",
    "\"section_name\":",
    "\"service\":",
    "\"share_id\":",
    "\"title\":",
    "\"vault\":",
    "\"vault_id\":",
    "\"account\":",
    "--field ",
    "--field=",
    "--item ",
    "--item-id ",
    "--item-id=",
    "--item-title ",
    "--item-title=",
    "--item=",
    "--share-id ",
    "--share-id=",
    "--vault ",
    "--vault-name ",
    "--vault-name=",
    "--vault=",
    "account:",
    "field:",
    "item:",
    "service:",
    "share_id:",
    "title:",
    "vault:",
    "vault_id:",
];

/// Markers read in Rust sources only, and the restriction is measured.
///
/// `"name"` and `"id"` are store coordinates in the Proton fixtures — an
/// `extra_fields` label and an item id — and they are ALSO the two most generic
/// keys in JSON. Scanned across every file type they pull in the eighty-odd
/// mutation names in `hooks/tests/mutations.json`, which would put eighty
/// entries that are not coordinates into the allowlist above and make it
/// unmaintainable. An allowlist nobody can keep accurate gets deleted, and then
/// the real coordinates flow. Restricting them to `.rs` keeps the Proton
/// fixtures covered at a cost of nothing: no store coordinate reaches `hooks/`
/// or `site/` under either key.
const RUST_ONLY_MARKERS: &[&str] = &["\"id\":", "\"name\":", "id:", "name:"];

/// Characters a `pass://` reference is made of.
const REFERENCE_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=./";

/// Every coordinate-position value in `source`, with the marker that found it.
fn coordinates(source: &str, rust: bool) -> Vec<(&'static str, String)> {
    let bytes = source.as_bytes();
    let mut found = Vec::new();

    let markers = STORE_MARKERS
        .iter()
        .chain(if rust { RUST_ONLY_MARKERS } else { &[] }.iter());

    for marker in markers {
        let mut at = 0usize;
        while let Some(hit) = source[at..].find(*marker) {
            let start_of_marker = at + hit;
            let mut i = start_of_marker + marker.len();
            at = i;

            // A string literal whose ENTIRE content is the marker is a marker
            // DEFINITION, not a use of one: the quote after it closes the
            // literal rather than opening a value. `"--vault=",` in the list
            // above reads as a coordinate position otherwise, and the "value"
            // extracted is the comma and whatever came next.
            //
            // This file is the only one that writes markers rather than using
            // them, so the tree scan — which excludes this file — never met the
            // shape. The history walk reads every blob this file has ever been,
            // and it cannot exclude a file without going blind to the rest of
            // it, so the discrimination belongs here. Measured over this
            // repository's own history: 25 such reads, all artifacts, no
            // coordinates.
            if start_of_marker > 0 {
                let opener = bytes[start_of_marker - 1];
                if (opener == b'"' || opener == b'\'') && i < bytes.len() && bytes[i] == opener {
                    continue;
                }
            }

            // A key may be followed by whitespace before its value.
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
            if i >= bytes.len() {
                continue;
            }
            let value = if bytes[i] == b'"' || bytes[i] == b'\'' {
                // Quoted. Ends at the closing quote, an escape, or a newline —
                // an item title legitimately contains spaces, so ending on the
                // first one would truncate the value into something that
                // matches nothing and report every entry as an offender.
                let quote = bytes[i];
                let start = i + 1;
                let mut end = start;
                while end < bytes.len()
                    && bytes[end] != quote
                    && bytes[end] != b'\\'
                    && bytes[end] != b'\n'
                {
                    end += 1;
                }
                // Nothing closed it before the line ended, so it was never a
                // quoted value at all. Reporting the fragment would put a
                // string nobody wrote in front of the allowlist.
                //
                // This one catches NOTHING in this repository — the
                // marker-literal rule above reaches every one of the 25 reads
                // that were artifacts, and it reaches them earlier. It is here
                // because it is true independently: a value has a closing quote
                // on its own line, and the extractor should not invent one.
                if end >= bytes.len() || bytes[end] == b'\n' {
                    continue;
                }
                &source[start..end]
            } else if marker.ends_with(':') {
                // Unquoted after a key is a Rust type annotation (`title:
                // String`), not a value.
                continue;
            } else {
                // A bare shell argument: one word, so a space ends it. A
                // backslash ends it too — a long `&str` in this crate wraps
                // with Rust's line continuation, so `--vault-name \` followed
                // by a newline would otherwise yield a value of `\` and report
                // a backslash as an undeclared coordinate.
                let start = i;
                let mut end = start;
                while end < bytes.len()
                    && !(bytes[end] as char).is_whitespace()
                    && bytes[end] != b'"'
                    && bytes[end] != b'\''
                    && bytes[end] != b'`'
                    && bytes[end] != b'\\'
                {
                    end += 1;
                }
                let word = &source[start..end];
                // A flag with no value after it is not a coordinate. The QUOTED
                // branch above deliberately keeps an empty value, because
                // `"title":""` is a real fixture and the empty title is on the
                // allowlist on purpose.
                if word.is_empty() {
                    continue;
                }
                word
            };
            if !is_metavariable(value) {
                found.push((*marker, value.to_owned()));
            }
        }
    }

    // `pass://` references. Read as reference characters rather than as a
    // quoted value, because the form that matters most appears unquoted in
    // prose — `pass://<share>/<item>/<field>` in a doc comment, and
    // `pass://personal/demo api key/API Key` in the README.
    let mut at = 0usize;
    while let Some(hit) = source[at..].find("pass://") {
        let start = at + hit + "pass://".len();
        let mut end = start;
        while end < bytes.len() && REFERENCE_CHARS.contains(bytes[end] as char) {
            end += 1;
        }
        at = start.max(end);
        let value = &source[start..end];
        if !value.is_empty() && !is_metavariable(value) {
            found.push(("pass://", value.to_owned()));
        }
    }

    found
}

/// A metavariable names the SHAPE of an argument, not an account.
///
/// `<vault>` in a doc comment and `{vault}` in a `format!` template are both
/// placeholders. Reading them as coordinates would make the allowlist grow to
/// hold prose and template syntax, which is how an allowlist stops being read.
fn is_metavariable(value: &str) -> bool {
    value.starts_with('<') || value.starts_with('{')
}

#[test]
fn every_coordinate_is_an_allowlisted_decoy() {
    let mut seen = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for path in published_files() {
        let source = read(&path);
        let rust = path.extension().is_some_and(|ext| ext == "rs");
        for (marker, value) in coordinates(&source, rust) {
            seen += 1;
            if !DECOY_COORDINATES.contains(&value.as_str()) {
                offenders.push(format!("{}: `{marker}` -> `{value}`", shown(&path)));
            }
        }
    }

    // The negative control, and it is the point of the whole file. A marker
    // that stops matching — a fixture rewritten, a flag renamed — would leave
    // this test scanning nothing and reporting a pass, which is exactly how the
    // coordinates got back in unnoticed the first time. So the scan has to
    // prove it read something before its silence means anything.
    //
    // The floor is well under the 260 positions measured when this was written:
    // it is there to catch an extractor that has stopped working, not to freeze
    // the fixtures.
    assert!(
        seen >= 200,
        "the scan found only {seen} coordinates, so it is not reading the fixtures any more \
         and its silence proves nothing: check STORE_MARKERS against the fixtures"
    );

    assert!(
        offenders.is_empty(),
        "a coordinate outside the decoy allowlist reached a published file.\n\
         If it is invented, add it to DECOY_COORDINATES. If it names anything in a real \
         account, it must not be in this repository at all.\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_coordinate_scanner_can_actually_fail() {
    // Without this the test above could be vacuous in the other direction: an
    // extractor that finds values but never rejects one reads exactly like a
    // clean repository.
    let planted = "let argv = \"--item-id=NOT-ON-THE-ALLOWLIST\";";
    let found = coordinates(planted, true);

    assert_eq!(found.len(), 1, "the extractor missed a planted coordinate");
    assert_eq!(found[0].1, "NOT-ON-THE-ALLOWLIST");
    assert!(
        !DECOY_COORDINATES.contains(&found[0].1.as_str()),
        "the planted value must not be allowlisted, or this control proves nothing"
    );
}

#[test]
fn the_scanner_reads_the_shape_the_leaked_vault_name_was_written_in() {
    // The measured hole in the previous version, asserted rather than described.
    // Against the real leak that guard flagged 5 of 14 lines, and this is the
    // shape it could not see: a value under a generic `name` key, inside a JSON
    // array, with no `--vault-name=` marker anywhere near it.
    let planted =
        r##"const ONE_VAULT: &str = r#"{"vaults":[{"name":"NOT-A-DECOY","id":"V1"}]}"#;"##;
    let found = coordinates(planted, true);

    assert!(
        found.iter().any(|(_, value)| value == "NOT-A-DECOY"),
        "the vaults-name-array shape is invisible again: {found:?}"
    );
}

#[test]
fn the_scanner_reads_a_coordinate_written_in_a_doc_comment() {
    // The other measured hole: the old markers all required a `=` or an
    // embedded quote, so a coordinate in prose — which is where a maintainer
    // most naturally writes one — was never in a marker position at all.
    let planted = "/// Run `pass-cli item list --vault NOT-A-DECOY` to see the ids.";
    let found = coordinates(planted, true);

    assert!(
        found.iter().any(|(_, value)| value == "NOT-A-DECOY"),
        "a space-separated flag in a doc comment is invisible: {found:?}"
    );

    // And a `pass://` reference spelled out in prose.
    let reference = "//! A reference looks like `pass://NOT-A-DECOY/item/password`.";
    assert!(
        coordinates(reference, true)
            .iter()
            .any(|(_, value)| value == "NOT-A-DECOY/item/password"),
        "a `pass://` reference in prose is invisible"
    );
}

#[test]
fn a_documentation_metavariable_is_not_read_as_a_coordinate() {
    // `--vault-name=<vault>` appears in a doc comment describing the shape of
    // the argument, and `{vault}` appears inside a `format!` template. Reading
    // either as a coordinate would make the allowlist grow to hold prose, and
    // an allowlist nobody can keep accurate gets deleted.
    assert!(coordinates("`pass-cli item list --vault-name=<vault>`", true).is_empty());
    assert!(coordinates(r#"format!("--vault={vault}")"#, true).is_empty());

    // A Rust type annotation is not a value, and `.rs` is full of them.
    assert!(coordinates("pub struct Route { vault: Option<String> }", true).is_empty());
}

#[test]
fn a_marker_literal_is_not_read_as_a_coordinate_position() {
    // The list of markers is itself a run of quoted strings, so every entry in
    // it ends with a marker followed immediately by a quote — the shape a
    // coordinate position has, spelled by the closing quote instead of an
    // opening one. Read naively it yields the comma and the newline after it.
    //
    // The tree scan never met this, because it excludes this file. The history
    // walk reads every blob this file has ever been, so the discrimination has
    // to be in the extractor rather than in an exemption.
    assert!(
        coordinates("    \"--vault=\",\n    \"--vault \",\n", true).is_empty(),
        "a marker literal is being read as a coordinate position again"
    );
    assert!(
        coordinates("const M: &[&str] = &[\"item:\", \"title:\"];\n", true).is_empty(),
        "a key-shaped marker literal is being read as a coordinate position"
    );

    // And the discrimination is narrow: a value that IS closed on its own line
    // is still read, including the empty title, which is a real fixture.
    assert!(
        coordinates("{\"vault\":\"personal\"}\n", true)
            .iter()
            .any(|(_, value)| value == "personal"),
        "the fix swallowed an ordinary quoted value"
    );
    assert!(
        coordinates("{\"title\":\"\"}\n", true)
            .iter()
            .any(|(_, value)| value.is_empty()),
        "the fix swallowed the empty title, which is an allowlisted fixture"
    );
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

// ───────────────────────────────────────────────────────────────────────────
// Scanner 2 — prose about the author's own machine
// ───────────────────────────────────────────────────────────────────────────

/// Phrases that attach a claim to the machine this repository was built on.
///
/// This is a grammar over DEIXIS, not over numbers, and that is what makes it
/// shippable where a census grammar is not. Each phrase below binds a statement
/// to one particular machine — the one the author used — so there is no
/// legitimate use of any of them in a tool other people run. Measured over the
/// whole published tree: six hits, six of them real, zero false positives.
///
/// `this machine` on its own is deliberately NOT here, and the omission is the
/// difference between a gate that survives and one that gets deleted. The
/// crate says "~20 agent sessions on this machine can append at once" and "how
/// loaded this machine has to be before a passing test reports a failure" —
/// both about whatever machine is running the tool, both correct, and a rule
/// that refused them would be switched off within a week.
///
/// `their author's machine` is not caught either, and that is also deliberate:
/// `hooks/install.py` uses it to describe shipped hook configs in general. The
/// definite article is the discrimination, and it has to be read.
const MACHINE_DEIXIS: &[&str] = &[
    "machine this was built",
    "machine this was written",
    "machine this was developed",
    "machine i built",
    "machine i wrote",
    "my machine",
    "my own machine",
    "on my laptop",
    "the author's machine",
    "the author's own machine",
    "the maintainer's machine",
    "the maintainer's own machine",
    "nab's",
    "on nab's",
];

/// Files allowed to contain the phrases above.
///
/// One entry, and `LICENSE` is deliberately NOT a second one. The copyright
/// reads `Copyright (c) 2026 nab` — a bare attribution, which is IDENTITY and
/// which no phrase above matches. `nab's` is here and `nab` is not, and that
/// gap IS the identity/inventory line: "built by nab" is an attribution and
/// stays, "nab's own config produces this" is a statement about one person's
/// machine and goes. Exempting `LICENSE` would have excused a file that commits
/// no offence, which is an exemption that can never be observed to work.
///
/// `hooks/tests/test_publication.py` is the sibling guard and does commit the
/// offence, because it names the class in order to forbid it — the same reason
/// this file exempts itself.
const DEIXIS_EXEMPT: &[&str] = &["hooks/tests/test_publication.py"];

fn deixis_in(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    MACHINE_DEIXIS
        .iter()
        .filter(|phrase| lower.contains(**phrase))
        .copied()
        .collect()
}

#[test]
fn no_source_file_speaks_about_the_authors_own_machine() {
    let mut offenders: Vec<String> = Vec::new();

    for path in published_files() {
        let relative = shown(&path);
        if DEIXIS_EXEMPT
            .iter()
            .any(|exempt| relative.ends_with(exempt))
        {
            continue;
        }
        for phrase in deixis_in(&read(&path)) {
            offenders.push(format!("{relative}: `{phrase}`"));
        }
    }

    assert!(
        offenders.is_empty(),
        "a published file makes a claim about the machine it was written on.\n\
         Keep the reasoning and drop the machine: state the mechanism as a rule that is \
         true wherever the tool runs.\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_deixis_scanner_can_actually_fail() {
    // Every phrase has to be reachable, or an entry can be quietly misspelled
    // and the list shrinks without anybody noticing.
    for phrase in MACHINE_DEIXIS {
        let planted = format!("//! Measured on {phrase} at the time, this held.");
        assert!(
            !deixis_in(&planted).is_empty(),
            "`{phrase}` does not match its own planted sentence"
        );
    }

    // Case-insensitive, because a comment starts sentences with a capital.
    assert!(!deixis_in("On The Machine This Was Built For, it returns 0.").is_empty());

    // And the two measured non-offenders stay non-offenders. Without these the
    // list could be widened into something that refuses correct writing, which
    // is the failure that ends with the gate deleted.
    assert!(
        deixis_in("~20 agent sessions on this machine can append at once").is_empty(),
        "`this machine` alone must not be an offence"
    );
    assert!(
        deixis_in("most shipped hook configs only work on their author's machine").is_empty(),
        "`their author's machine` is a statement about other people's configs"
    );
}

#[test]
fn the_guards_own_exemption_is_a_real_exemption() {
    // The sibling guard is exempt because it names the class in order to forbid
    // it. If scanning it found NOTHING, the extractor would be broken and every
    // clean verdict above would be worthless — an exemption nobody tests is a
    // blind spot, and a blind spot here reports the whole tree clean.
    let sibling = manifest_dir().join("hooks/tests/test_publication.py");
    assert!(
        !deixis_in(&read(&sibling)).is_empty(),
        "the sibling guard no longer contains the phrases it exists to forbid, \
         so the deixis matcher has stopped matching"
    );

    // This file too: it quotes the leaked sentence in its own header.
    assert!(
        !deixis_in(&read(&guard_path())).is_empty(),
        "this guard no longer contains the phrase it exempts itself for"
    );

    // `LICENSE` is scanned and NOT exempt, which is only safe because the
    // attribution it carries is not an offence. Both halves are asserted, since
    // either one failing silently would be a scrub that ate the copyright.
    let license = manifest_dir().join("LICENSE");
    assert!(
        published_files().contains(&license),
        "LICENSE is published and must be scanned for coordinates like any other file"
    );
    let text = read(&license);
    assert!(
        text.contains("Copyright") && text.contains("nab"),
        "LICENSE no longer carries the author's name. The copyright is IDENTITY, \
         not inventory, and no scrub this file drives may remove it."
    );
    assert!(
        deixis_in(&text).is_empty(),
        "the deixis list has grown far enough to refuse a bare copyright line, \
         which would make this guard delete the attribution it exists to protect"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Scanner 3 — transcribed record timestamps
// ───────────────────────────────────────────────────────────────────────────

/// Every wall-clock instant a published file is allowed to carry.
///
/// A `create_time` copied out of a real vault view is the moment somebody
/// created that item, and it reads exactly like a made-up one. Six fixture
/// records in this crate carried a real pair, transcribed with the rest of the
/// record, and survived a scrub that had already replaced the item's title —
/// because nobody looks at a timestamp.
///
/// **Every entry below is legal for a reason a reader can check, and there are
/// exactly two of those reasons.** That is the property, not the list:
///
/// - **Synthetic by construction.** Midnight on the first three days of 2000
///   cannot be mistaken for an observation. Nobody has to decide whether it is
///   one.
/// - **Arithmetic.** The `src/time.rs` vectors are epoch conversions — leap
///   days, the 2100 non-leap year, the `1_000_000_000` epoch second. Each is
///   derivable from the integer written beside it, so the entry states no fact
///   about any machine, and [`the_readme_audit_row_is_derivable_arithmetic`]
///   holds the README's row to the same standard rather than to an assertion.
///
/// **An entry legal for neither reason has no place here, however innocent it
/// looks — and one used to be here.** The README's audit row carried
/// `2026-08-06T…`, allowlisted with the note that it was illustrative. It was
/// legal by ASSERTION: a reader could not tell it from a row copied out of the
/// author's own log, and neither could the person maintaining this list. It is
/// gone from the tree, replaced by an instant that satisfies both reasons at
/// once. [`HISTORICAL_INSTANTS`] is where it went and why it could not simply
/// be deleted.
const FIXTURE_INSTANTS: &[&str] = &[
    // Proton record fixtures, and the README's audit row, which now uses the
    // first of them.
    "2000-01-01T00:00:00",
    "2000-01-01T00:00:01",
    "2000-01-02T00:00:00",
    "2000-01-02T00:00:01",
    "2000-01-03T00:00:00",
    "2000-01-03T00:00:01",
    // Epoch-conversion vectors in `src/time.rs`.
    "1970-01-01T00:00:00",
    "2000-02-29T00:00:00",
    "2001-09-09T01:46:40",
    "2024-02-29T00:00:00",
    "2025-08-06T00:00:00",
    "2025-12-31T23:59:59",
    "2026-01-01T00:00:00",
    "2100-02-28T00:00:00",
    "2100-03-01T00:00:00",
];

/// Instants that only the HISTORY carries, and that no rewrite is going to
/// remove.
///
/// **This list names an instant in order to forgive it, which is the thing the
/// scanners here otherwise refuse to do — so read why it is the only honest
/// spelling available.** The value below is in this repository's published
/// history, in blobs of `README.md` that predate the tree fix. History is
/// append-only from here: the only way to unpublish it is a third rewrite of
/// every sha, and until that happens a history walk that greened without naming
/// it would be a walk that was not looking.
///
/// So the choice is not "name it or not". It is "name it in a list that is
/// scoped, asserted and shrinking, or do not scan the history at all". This is
/// the first.
///
/// Both directions are held by [`the_historical_instants_are_historical_only`]:
///
/// - every entry must be ABSENT from the working tree, so the list can never
///   become a licence for a new fixture to reuse the value; and
/// - every entry must still be PRESENT in the history, so it cannot rot into a
///   permanent exemption after a rewrite finally removes it.
///
/// A value that satisfies neither is a value somebody forgot to delete.
const HISTORICAL_INSTANTS: &[&str] = &["2026-08-06T14:22:01"];

/// `YYYY-MM-DDTHH:MM:SS`, found without a regex dependency.
///
/// A DATE on its own is not in scope: `Measured 2026-08-08` describes when a
/// vendor's output was read, which is provenance for a claim about the vendor
/// and not an inventory. A date with a TIME OF DAY is a different object — it
/// is an instant, and an instant in a fixture was transcribed from something.
fn instants(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let digits = |window: &[u8]| window.iter().all(u8::is_ascii_digit);

    for start in 0..bytes.len().saturating_sub(18) {
        let window = &bytes[start..start + 19];
        let shaped = digits(&window[0..4])
            && window[4] == b'-'
            && digits(&window[5..7])
            && window[7] == b'-'
            && digits(&window[8..10])
            && window[10] == b'T'
            && digits(&window[11..13])
            && window[13] == b':'
            && digits(&window[14..16])
            && window[16] == b':'
            && digits(&window[17..19]);
        if shaped {
            found.push(String::from_utf8_lossy(window).into_owned());
        }
    }
    found
}

#[test]
fn every_record_timestamp_is_an_allowlisted_fixture() {
    let mut seen = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for path in published_files() {
        for instant in instants(&read(&path)) {
            seen += 1;
            if !FIXTURE_INSTANTS.contains(&instant.as_str()) {
                offenders.push(format!("{}: `{instant}`", shown(&path)));
            }
        }
    }

    assert!(
        seen >= 20,
        "the scan found only {seen} timestamps, so it has stopped reading the fixtures"
    );

    assert!(
        offenders.is_empty(),
        "a wall-clock instant outside the fixture allowlist reached a published file.\n\
         If it was transcribed from a real record it is the moment somebody created that \
         record, and it must not be in this repository. Use an obvious fixture instant.\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_timestamp_scanner_can_actually_fail() {
    let found = instants("\"create_time\":\"2026-08-08T09:09:01\",");
    assert_eq!(found, vec!["2026-08-08T09:09:01".to_owned()]);
    assert!(
        !FIXTURE_INSTANTS.contains(&found[0].as_str()),
        "the planted instant must not be allowlisted, or this control proves nothing"
    );

    // A bare date is deliberately out of scope.
    assert!(instants("Measured 2026-08-08 against pass-cli 2.2.5").is_empty());
}

#[test]
fn the_readme_audit_row_is_derivable_arithmetic() {
    // The README prints one audit row, and a row carries BOTH the instant and
    // the epoch millisecond it was rendered from. `audit::render` builds the
    // first from the second and from nothing else, so in real output the two
    // agree by construction — which makes the pair checkable, and makes an
    // instant in this document a derivable number rather than a transcription.
    //
    // It was neither, and that is why this test exists rather than a note. The
    // row that stood here paired an instant with an epoch millisecond that
    // renders two hours away from it: a gap this tool cannot produce, and
    // exactly the local-time offset of the machine the README was written on.
    // So the row was wrong as documentation AND was carrying an observation,
    // and the allowlist entry that permitted it could only ever have been a
    // judgement call. This is the mechanical form of that judgement.
    let readme = read(&manifest_dir().join("README.md"));
    let mut pairs = 0usize;

    let mut at = 0usize;
    while let Some(hit) = readme[at..].find("\"ts\":\"") {
        let start = at + hit + "\"ts\":\"".len();
        let end = start + readme[start..].find('"').expect("a closing quote");
        let rendered = &readme[start..end];
        at = end;

        let key = readme[end..]
            .find("\"ts_ms\":")
            .map(|offset| end + offset + "\"ts_ms\":".len())
            .expect("an audit row carries `ts_ms` beside `ts`");
        let digits: String = readme[key..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let millis: u128 = digits.parse().expect("`ts_ms` is an integer");

        assert_eq!(
            keyless::time::rfc3339_utc(millis),
            rendered,
            "the README's audit row prints an instant this tool would never \
             render from the `ts_ms` printed beside it. Either the row was \
             transcribed from somewhere and edited, or the number was. Render \
             it: `keyless::time::rfc3339_utc({millis})`."
        );
        pairs += 1;
    }

    assert!(
        pairs > 0,
        "the README no longer shows an audit row, so this check read nothing. \
         Either restore the example or delete this test — a scan of zero rows \
         passes exactly like a scan of correct ones."
    );
}

#[test]
fn the_historical_coordinates_are_historical_only() {
    // The same ratchet as the one below, over the other class. Written as two
    // tests rather than one loop because the two lists are read by different
    // extractors, and a shared helper would have to take a closure to say so.
    let history = history();

    for coordinate in HISTORICAL_COORDINATES {
        assert!(
            !DECOY_COORDINATES.contains(coordinate),
            "`{coordinate}` is on both lists, so a fixture may use it after all \
             and the split means nothing"
        );

        let in_tree: Vec<String> = published_files()
            .into_iter()
            .filter(|path| {
                let rust = path.extension().is_some_and(|ext| ext == "rs");
                coordinates(&read(path), rust)
                    .iter()
                    .any(|(_, value)| value == coordinate)
            })
            .map(|path| shown(&path))
            .collect();
        assert!(
            in_tree.is_empty(),
            "`{coordinate}` is forgiven in the history because the history \
             cannot be changed. It is back in a published file, which can be: \
             {in_tree:?}"
        );

        assert!(
            history.coordinates_seen_values.contains(*coordinate),
            "`{coordinate}` is no longer anywhere in the history, so the \
             rewrite that removed it has landed. Delete this entry — a \
             forgiveness for something that is gone is how a ratchet becomes a \
             permanent hole."
        );
    }
}

#[test]
fn the_historical_instants_are_historical_only() {
    // Both directions of the ratchet described on `HISTORICAL_INSTANTS`. Either
    // one alone is worthless: without the first the list licenses a new leak in
    // the tree, and without the second it survives the rewrite that made it
    // unnecessary and quietly forgives the next thing that matches.
    for instant in HISTORICAL_INSTANTS {
        assert!(
            !FIXTURE_INSTANTS.contains(instant),
            "`{instant}` is on both lists, so the tree allows it after all and \
             the split means nothing"
        );

        let in_tree: Vec<String> = published_files()
            .into_iter()
            .filter(|path| instants(&read(path)).iter().any(|found| found == instant))
            .map(|path| shown(&path))
            .collect();
        assert!(
            in_tree.is_empty(),
            "`{instant}` is forgiven in the history because the history cannot \
             be changed. It is back in the working tree, which can: {in_tree:?}"
        );

        let in_history = history().instants_seen_values.contains(*instant);
        assert!(
            in_history,
            "`{instant}` is no longer anywhere in the history, so the rewrite \
             that removed it has landed. Delete this entry — a forgiveness for \
             something that is gone is how a ratchet becomes a permanent hole."
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// The corpus itself
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn no_published_file_type_is_left_unscanned() {
    // Adding a root is not one line, and this is the half that is easy to
    // forget: the walk filters on extension, so a root full of `.py` and
    // `.html` contributed nothing while `TEXT_EXTENSIONS` held only `rs`, and
    // the scan reported clean. This fails when a file type appears for the
    // first time, rather than letting it be silently exempt.
    let mut present: BTreeSet<String> = BTreeSet::new();

    fn collect(dir: &Path, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).expect("a readable directory") {
            let path = entry.expect("a directory entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if path.is_dir() {
                if !SKIPPED_DIRS.contains(&name) {
                    collect(&path, out);
                }
            } else if !name.starts_with('.')
                && let Some(ext) = path.extension().and_then(|e| e.to_str())
                && ext != "pyc"
            {
                out.insert(ext.to_owned());
            }
        }
    }

    for scanned in SCANNED_ROOTS {
        collect(&manifest_dir().join(scanned), &mut present);
    }

    let unscanned: Vec<&String> = present
        .iter()
        .filter(|ext| !TEXT_EXTENSIONS.contains(&ext.as_str()))
        .collect();

    assert!(
        unscanned.is_empty(),
        "a published file type is scanned by nothing: {unscanned:?}.\n\
         Add it to TEXT_EXTENSIONS, or say in SKIPPED_DIRS why the tree it lives in \
         is not published."
    );
}

#[test]
fn the_walk_reaches_every_published_root() {
    // A root that contributes zero files is a root that is not scanned, however
    // it is spelled in SCANNED_ROOTS. This is the assertion that would have
    // failed the day `hooks` was added to the roots and the walk still filtered
    // on `.rs`.
    let files = published_files();
    assert!(
        files.len() >= 90,
        "the walk found only {} published files",
        files.len()
    );

    for scanned in SCANNED_ROOTS {
        let root = manifest_dir().join(scanned);
        assert!(
            files.iter().any(|path| path.starts_with(&root)),
            "`{scanned}` is in SCANNED_ROOTS and contributed no file: \
             its file types are missing from TEXT_EXTENSIONS"
        );
    }

    for scanned in SCANNED_FILES {
        let path = manifest_dir().join(scanned);
        assert!(files.contains(&path), "`{scanned}` was not scanned");
    }
}

#[test]
fn every_file_at_the_repository_root_is_accounted_for() {
    // `SCANNED_FILES` is a hand-written list, and a hand-written list of files
    // is the one thing in here that cannot fail loudly on its own: a new file
    // at the root is simply absent from it, and absence is silence.
    // `no_published_file_type_is_left_unscanned` does not help — it walks
    // SCANNED_ROOTS, and the root itself is not one of them.
    //
    // Directories are covered by SCANNED_ROOTS and are asserted there.
    // Dot-files are configuration for tools rather than published prose, and
    // `target` is build output.
    let root = manifest_dir();
    let mut unaccounted: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(root).expect("a readable repository root") {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if path.is_dir() || name.starts_with('.') {
            continue;
        }
        if !SCANNED_FILES.contains(&name.as_str()) {
            unaccounted.push(name);
        }
    }

    assert!(
        unaccounted.is_empty(),
        "a file at the repository root is scanned by nothing: {unaccounted:?}.\n\
         Add it to SCANNED_FILES. Every file here is published."
    );

    // And every directory at the root is either scanned or deliberately not.
    let mut unscanned_dirs: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(root).expect("a readable repository root") {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if !path.is_dir() || SKIPPED_DIRS.contains(&name.as_str()) {
            continue;
        }
        if !SCANNED_ROOTS.contains(&name.as_str()) {
            unscanned_dirs.push(name);
        }
    }

    assert!(
        unscanned_dirs.is_empty(),
        "a directory at the repository root is scanned by nothing: {unscanned_dirs:?}.\n\
         Add it to SCANNED_ROOTS, or to SKIPPED_DIRS with a reason."
    );
}

// ───────────────────────────────────────────────────────────────────────────
// The history — the same three grammars, over every blob a ref can reach
// ───────────────────────────────────────────────────────────────────────────
//
// # The defect this closes, which is a defect in the GATES and not in the tree
//
// Every scanner above reads the WORKING TREE. Twice now a class has been clean
// at `HEAD` and dirty behind it, and both times for the same mechanical reason:
// the scrub commit landed AFTER the commits that introduced the class, so the
// tree went green while the blobs those commits still point at stayed exactly
// as they were written. A tree scanner cannot see that and never will — it is
// reading the one revision the leak is not in. Round one missed a keychain
// coordinate class; round two missed transcribed wall-clock instants. Neither
// was a failure of care, and a third sweep by hand would not be either.
//
// A published repository is not its working tree. It is every object a clone
// receives, and `git log -p` on a rewritten history is the only place the two
// differ.
//
// # Why OBJECTS, and not `git log --all -p`
//
// Four reasons, in the order they would bite.
//
// 1. **A patch is not the content.** `-p` emits a diff: every line carries a
//    `+`, `-` or space in column one, and a value can straddle a hunk boundary.
//    `coordinates` reads a value up to the next quote or space, so a removal
//    marker lands INSIDE the value it extracts and the allowlist comparison is
//    against a string nobody wrote. The object walk reads each file exactly as
//    it was committed.
// 2. **`log -p` shows no diff for a merge**, by default and on purpose. Content
//    introduced by a merge RESOLUTION appears in no patch at all. This history
//    has no merges today and will have one the week after it is published.
// 3. **Cost.** A patch walk pays for a blob once per commit that touched it —
//    `O(commits × changed bytes)`. The object walk pays once per DISTINCT blob,
//    whatever its history, and git already stores them deduplicated by content.
// 4. **Reachability is the definition of published.** `git push` transmits the
//    objects reachable from the refs it sends, and a clone receives exactly
//    those. Measured here: the object database holds 271 blobs and 270 are
//    reachable. The odd one is a pre-rewrite version of a file that the rewrite
//    orphaned and the next `git gc` will drop — it is in no clone, and a walk
//    over `--batch-all-objects` would turn it red on precisely the thing the
//    rewrite removed. So `--all` (every ref, plus `HEAD`) is not a convenience
//    spelling; it is the corpus.
//
// # Where this lives, and the trade that decides it
//
// Here, in the file that already owns the coordinate allowlist, the instant
// allowlist and the deixis phrase list. The alternative was
// `hooks/tests/test_publication.py`, which already walks the history for commit
// MESSAGES — and it would have had to carry a second copy of all three
// grammars. Two graders drift, and the one that drifts is the one nobody reads.
// The split stays where it was: this file owns the coordinate, instant and
// deixis grammars over BOTH surfaces; that file owns the census grammar over
// `hooks/` prose and over every commit body.
//
// The cost of choosing Rust is that the hook pack's mutation campaign cannot
// reach this code. That cost is zero. `mutate.py` copies `hooks/` alone into a
// temporary directory, so nothing in this crate has ever been under mutation,
// and the same copy makes `is_this_repository()` false — which is why the
// Python history walk cannot be mutation-proved either, as its own comment
// says. Nothing was given up by not putting the walk there. What replaces
// mutation here is a control that builds a real repository with a real leak in
// its history and requires this walk to name it:
// [`the_history_walk_sees_a_leak_that_is_only_in_history`].
//
// # Cost, measured, and what happens as this grows
//
// 30 commits, 270 reachable blobs, 5.9 MB of content. `git rev-list --objects
// --all` piped into `git cat-file --batch` reads all of it in about 0.02 s —
// two processes, not one per object. The walk is linear in DISTINCT BLOB BYTES,
// which is the smallest corpus that is still complete, and the grammars are
// substring scans over each blob once. The whole test binary — this walk, plus
// a planted repository built from nothing and a shallow clone of this one —
// finishes in 0.69 s.
//
// The number that grows is total blob bytes, not commits: a thousand commits
// touching one file cost one blob each, and a repository that never rewrites
// history only ever adds. At the point where this stops being free — call it
// hundreds of megabytes of distinct blob content — the fix is to remember the
// last-scanned commit and walk `<last>..--all` instead, which is a cache and
// needs somewhere durable to keep it. It is not needed now and a cache added
// early would be a second thing to be wrong.
//
// # Shallow clones
//
// `actions/checkout` defaults to depth 1, and one commit with nothing to flag
// reads exactly like a clean history: no failure, no output, exit 0. So the
// depth is ASSERTED rather than assumed, in both directions —
// [`a_shallow_checkout_is_refused_rather_than_read_as_clean`] requires this
// checkout not to be shallow AND proves the probe can tell, by making a shallow
// clone and detecting it. Both CI jobs check out with `fetch-depth: 0`.

/// Run git inside `repo`, returning stdout when it succeeds.
fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run git inside `repo` and require it to succeed.
fn git_must(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} in {}: {e}", repo.display()));
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}",
        repo.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A unique path under the system temporary directory. Not created.
///
/// Unique per process AND per call, because this machine runs many sessions at
/// once and `cargo test` runs these cases on parallel threads.
fn scratch(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "keyless-publication-{tag}-{}-{seq}",
        std::process::id()
    ))
}

/// Is this checkout missing part of its own history?
fn is_shallow(repo: &Path) -> bool {
    git(repo, &["rev-parse", "--is-shallow-repository"])
        .unwrap_or_else(|| {
            panic!(
                "`git rev-parse` failed in {}. This gate reads the published \
                 history, so it cannot run outside a git checkout — and it \
                 fails rather than skipping, because a walk that read nothing \
                 and a clean history are the same empty result.",
                repo.display()
            )
        })
        .trim()
        == "true"
}

/// Every blob reachable from any ref, with every path it was ever stored under.
///
/// One `rev-list` and one `cat-file --batch`, so the process count does not
/// grow with the object count. The object list reaches `--batch` through a file
/// rather than a pipe this thread would have to feed and drain at the same
/// time: a writer that fills the pipe buffer while nobody is reading stdout
/// deadlocks, and it deadlocks only once the repository is big enough to matter.
fn reachable_blobs(repo: &Path) -> Vec<(String, BTreeSet<String>, Vec<u8>)> {
    let listing = git_must(repo, &["rev-list", "--objects", "--all"]);

    // `<oid> SP <path>` for a blob or a tree, `<oid>` alone for a commit.
    let mut paths: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in listing.lines() {
        if let Some((oid, path)) = line.split_once(' ') {
            paths
                .entry(oid.to_owned())
                .or_default()
                .insert(path.to_owned());
        }
    }

    let list_file = scratch("objects");
    let mut names: String = paths.keys().cloned().collect::<Vec<_>>().join("\n");
    names.push('\n');
    std::fs::write(&list_file, &names).expect("write the object list");
    let stdin = std::fs::File::open(&list_file).expect("reopen the object list");

    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::from(stdin))
        .output()
        .expect("git cat-file --batch");
    let _ = std::fs::remove_file(&list_file);
    assert!(
        out.status.success(),
        "git cat-file --batch failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `<oid> SP <type> SP <size> LF <content> LF`, or `<oid> SP missing LF`.
    let stream = out.stdout;
    let mut blobs = Vec::new();
    let mut at = 0usize;
    while at < stream.len() {
        let Some(offset) = stream[at..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let header = String::from_utf8_lossy(&stream[at..at + offset]).into_owned();
        at += offset + 1;

        let mut fields = header.split(' ');
        let oid = fields.next().unwrap_or_default().to_owned();
        let kind = fields.next().unwrap_or_default().to_owned();
        let Some(size) = fields.next() else {
            // `missing`, which carries no body. Nothing follows to skip.
            continue;
        };
        let size: usize = size
            .parse()
            .unwrap_or_else(|e| panic!("`cat-file --batch` header {header:?}: {e}"));
        let end = (at + size).min(stream.len());
        if kind == "blob" {
            let seen = paths.get(&oid).cloned().unwrap_or_default();
            blobs.push((oid, seen, stream[at..end].to_vec()));
        }
        at = end + 1;
    }
    blobs
}

/// The values this file plants in its own negative controls.
///
/// **None of them is on an allowlist, and that is what makes the controls
/// controls.** `the_coordinate_scanner_can_actually_fail` and
/// `the_timestamp_scanner_can_actually_fail` each assert that their planted
/// value is NOT allowlisted; adding one to `DECOY_COORDINATES` or
/// `FIXTURE_INSTANTS` to keep the history walk quiet would leave both tests
/// green and asserting nothing.
///
/// So the history walk discriminates by FILE instead: a value below is forgiven
/// only in a blob whose every path is this guard. Any other value in a blob of
/// this file is an offence like any other, which is a far narrower exemption
/// than the tree scan's — that one drops the whole file.
///
/// The list is not maintained by hand.
/// [`the_guards_own_plants_are_exactly_what_the_history_walk_forgives`] scans
/// this file and requires it to yield exactly these, so a new plant fails
/// loudly here rather than reading as a leak in the history.
const GUARD_PLANTS: &[&str] = &[
    "NOT-A-DECOY",
    "NOT-A-DECOY/item/password",
    "NOT-ON-THE-ALLOWLIST",
    "2019-03-14T11:07:42",
    "2026-08-08T09:09:01",
];

/// Blobs that carry machine deixis, and that only a history rewrite can remove.
///
/// **This is the third instance of the defect at the top of this section, and
/// it is the one nobody has remediated.** Both earlier rounds ended in a
/// history rewrite. The deixis class was scrubbed by an ordinary commit
/// instead, so the tree is clean and the blobs behind it are not: 25 blobs
/// across 8 paths, in prose that says what one machine did.
///
/// A gate that went red on all 25 would be deleted within the week, and a gate
/// that ignored them would be the hole this whole section exists to close. So
/// they are a RATCHET, spelled the way `KNOWN_UNSCRUBBED` is spelled next door,
/// and checked in both directions by
/// [`historical_machine_deixis_is_confined_to_a_shrinking_ratchet`]:
///
/// - a blob that offends and is NOT on this list fails the gate; and
/// - an entry that is unreachable, or that no longer offends, ALSO fails it.
///
/// **A blob is immutable, so this list cannot forgive anything it was not
/// written for.** A new commit that adds one of these phrases writes a new
/// blob, with a new sha, which is not on the list. That is the whole security
/// argument, and it is why the key is a sha rather than a path: a path-keyed
/// entry would forgive every future version of the same file.
///
/// **It names no private fact.** A sha is not evidence of anything, and every
/// phrase involved is already spelled out in `MACHINE_DEIXIS` — that list
/// forbids the phrases in order to name the class, which is the deliberate
/// exception the header of this file states.
///
/// The only way to empty it is a third rewrite of every sha in this repository.
/// If that is done, this whole list goes unreachable at once and the test says
/// so.
const HISTORY_DEIXIS_RATCHET: &[&str] = &[
    "8e00f0bb4eb9aa90e9094cbef8082e34a5a2f10f", // README.md
    "aa83f9bb1d4c527da1fe4fc842c9a0aba0177b5b", // hooks/README.md
    "cf915ec5ffae3f2d01210501aedf8e0a49f1ff4a", // hooks/README.md
    "40dce12fa8e353a619ef9ed4ead63eefa2dd8ea5", // src/config.rs
    "88e46832f216dd1183cab64ac8e1d817908bcaaf", // src/config.rs
    "de174c8b0a8ac7e02e5173eaed5ba2269090c5d6", // src/config.rs
    "14a3162c4a84189ca3d7ca99a98fd66ed6c15120", // src/daemon/mod.rs
    "8757f82e60b53ddd1441d70ef97a37050843ed64", // src/daemon/mod.rs
    "af169490eda5f1f21175eccf80f613685a3255ad", // src/daemon/mod.rs
    "b2e3e1d3f990aac374f02adfc150551524c7b00c", // src/daemon/mod.rs
    "edb7825b999c759701f505653e0ad81465a73df0", // src/daemon/mod.rs
    "08b1e46d993c4f45c895200c466a00947766d0fd", // tests/cli.rs
    "0fedc1c5585d53c6fe883a2e2d08c2ed92af5152", // tests/cli.rs
    "92fb3cbbfea5604529403e4a7fd7ff941ec93f55", // tests/never_block.rs
    "c164020b6edec941728f4db27cf2d12e77ed142f", // tests/never_block.rs
    "fa74f5fb61de42980af85034381230bb8df581e4", // tests/never_block.rs
    "8ff9a8c9e5abb30aa0ea43d0ecdc7d9386fa8259", // tests/stores.rs
    "b5d5b12e7b173588b6f275187514a08e866d404c", // tests/stores.rs
    "c9ff9ff885c3d3acea9e2c67a568c5feea993680", // tests/stores.rs
    "24df2c8ce273c00209a5c44974957b87c2d2c219", // tests/support/mod.rs
    "2dc2f0a8311f4e194c690466b17fc494f1cacbf0", // tests/support/mod.rs
    "499c1b714e082924e19e9e1d20877463f5d16dc7", // tests/support/mod.rs
    "7529bb41df80a5e185c01160ede326f26e9e000b", // tests/support/mod.rs
    "9df884b6da1fa4da3b64724d19f40f1574d2c358", // tests/support/mod.rs
    "ddbe5be13de4d3b2cbc9068b37c9e67c26bc40dc", // tests/support/mod.rs
];

/// What the history walk found, and how much of it there was to find.
struct HistoryFindings {
    commits: usize,
    blobs: usize,
    /// Every blob sha the walk reached, so the ratchet below can ask whether an
    /// entry is still reachable without paying for a second walk.
    blob_shas: BTreeSet<String>,
    coordinates_seen: usize,
    instants_seen: usize,
    /// Every value the two extractors saw anywhere in the history, allowlisted
    /// or not. Read by the ratchet checks on [`HISTORICAL_COORDINATES`] and
    /// [`HISTORICAL_INSTANTS`], which have to prove an entry is still needed.
    coordinates_seen_values: BTreeSet<String>,
    instants_seen_values: BTreeSet<String>,
    /// A blob that is not valid UTF-8, so no grammar here could read it.
    unreadable: Vec<String>,
    coordinate_offenders: Vec<String>,
    instant_offenders: Vec<String>,
    /// sha -> the phrases it carries, for the ratchet.
    deixis: BTreeMap<String, Vec<&'static str>>,
}

/// Run all three grammars over every blob `repo` publishes.
fn scan_history(repo: &Path) -> HistoryFindings {
    let commits = git_must(repo, &["rev-list", "--all", "--count"])
        .trim()
        .parse()
        .expect("a commit count");

    let guard = file!();
    let mut findings = HistoryFindings {
        commits,
        blobs: 0,
        blob_shas: BTreeSet::new(),
        coordinates_seen: 0,
        instants_seen: 0,
        coordinates_seen_values: BTreeSet::new(),
        instants_seen_values: BTreeSet::new(),
        unreadable: Vec::new(),
        coordinate_offenders: Vec::new(),
        instant_offenders: Vec::new(),
        deixis: BTreeMap::new(),
    };

    for (sha, paths, bytes) in reachable_blobs(repo) {
        findings.blobs += 1;
        findings.blob_shas.insert(sha.clone());
        let where_ = paths.iter().cloned().collect::<Vec<_>>().join(", ");
        let short = &sha[..12.min(sha.len())];

        let Ok(text) = String::from_utf8(bytes) else {
            // Not scannable and not silently skipped. Today this list is empty
            // and the test asserts it stays empty; a binary that has to be
            // published is a decision somebody makes out loud.
            findings.unreadable.push(format!("{short}: {where_}"));
            continue;
        };

        // A blob of THIS file plants values on purpose. Only those values are
        // forgiven, and only here — see `GUARD_PLANTS`.
        let is_guard = !paths.is_empty() && paths.iter().all(|path| path == guard);
        let forgiven = |value: &str| is_guard && GUARD_PLANTS.contains(&value);

        let rust = paths.iter().any(|path| path.ends_with(".rs"));
        for (marker, value) in coordinates(&text, rust) {
            findings.coordinates_seen += 1;
            let allowed = DECOY_COORDINATES.contains(&value.as_str())
                || HISTORICAL_COORDINATES.contains(&value.as_str())
                || forgiven(&value);
            if !allowed {
                findings
                    .coordinate_offenders
                    .push(format!("{short} ({where_}): `{marker}` -> `{value}`"));
            }
            findings.coordinates_seen_values.insert(value);
        }

        for instant in instants(&text) {
            findings.instants_seen += 1;
            let allowed = FIXTURE_INSTANTS.contains(&instant.as_str())
                || HISTORICAL_INSTANTS.contains(&instant.as_str())
                || forgiven(&instant);
            if !allowed {
                findings
                    .instant_offenders
                    .push(format!("{short} ({where_}): `{instant}`"));
            }
            findings.instants_seen_values.insert(instant);
        }

        // The deixis list is quoted in full by this file and by its Python
        // sibling, both of which name the class in order to forbid it. That is
        // the same exemption `DEIXIS_EXEMPT` grants in the tree, applied to
        // every version of the same two files.
        let exempt = !paths.is_empty()
            && paths
                .iter()
                .all(|path| path == guard || DEIXIS_EXEMPT.contains(&path.as_str()));
        if !exempt {
            let phrases = deixis_in(&text);
            if !phrases.is_empty() {
                findings.deixis.insert(sha.clone(), phrases);
            }
        }
    }

    findings
}

/// The one walk of THIS repository, shared by every test below.
///
/// Seven cases read the same immutable history, and `cargo test` runs them on
/// parallel threads in one process. Without this they would each pay for the
/// whole walk, so the cost of the layer would be seven times the cost of the
/// thing it measures — and a gate that is slow for no reason is a gate somebody
/// puts behind a flag. A `OnceLock` makes it exactly one walk per run, and the
/// corpus cannot change under a running process.
///
/// A foreign repository — the planted control, a shallow clone — calls
/// [`scan_history`] directly, because there is nothing to share.
fn history() -> &'static HistoryFindings {
    static WALK: std::sync::OnceLock<HistoryFindings> = std::sync::OnceLock::new();
    WALK.get_or_init(|| scan_history(manifest_dir()))
}

#[test]
fn the_history_walk_reads_a_corpus_and_says_how_big_it_is() {
    // A clean history and a walk that read nothing produce the same empty
    // lists. Every floor here is set well under what was measured, so it
    // catches a walk that COLLAPSED rather than one that lost a commit.
    let found = history();

    assert!(
        found.commits >= 25,
        "the walk saw only {} commits. Either this checkout is not the one it \
         thinks it is, or `rev-list --all` has stopped resolving refs.",
        found.commits
    );
    assert!(
        found.blobs >= 200,
        "the walk read only {} blobs, so `cat-file --batch` is not returning \
         the objects `rev-list` named",
        found.blobs
    );
    assert!(
        found.coordinates_seen >= 800,
        "the walk found only {} coordinate positions across the whole history, \
         so the extractor has stopped reading and its silence proves nothing",
        found.coordinates_seen
    );
    assert!(
        found.instants_seen >= 80,
        "the walk found only {} instants across the whole history, so the \
         timestamp extractor has stopped matching",
        found.instants_seen
    );
    assert!(
        found.unreadable.is_empty(),
        "a published blob is not valid UTF-8, so no grammar here can read it. \
         Nothing in this repository is meant to be binary: {:?}",
        found.unreadable
    );
}

#[test]
fn every_historical_blob_carries_only_allowlisted_coordinates() {
    let offenders = &history().coordinate_offenders;
    assert!(
        offenders.is_empty(),
        "a coordinate outside the decoy allowlist is in the published history.\n\
         The working tree is not where this lives, so editing a file will not \
         remove it: the blob is reachable from a ref and a clone receives it.\n\
         If it is invented, add it to DECOY_COORDINATES. If it names anything \
         in a real account, the history has to be rewritten.\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn every_historical_blob_carries_only_allowlisted_instants() {
    let offenders = &history().instant_offenders;
    assert!(
        offenders.is_empty(),
        "a wall-clock instant outside the fixture allowlist is in the published \
         history. If it was transcribed from a real record it is the moment \
         somebody created that record, and only a history rewrite removes it.\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn historical_machine_deixis_is_confined_to_a_shrinking_ratchet() {
    let found = history();
    let offending: BTreeSet<&str> = found.deixis.keys().map(String::as_str).collect();
    let ratchet: BTreeSet<&str> = HISTORY_DEIXIS_RATCHET.iter().copied().collect();

    let new: Vec<String> = offending
        .difference(&ratchet)
        .map(|sha| {
            let phrases = found.deixis.get(*sha).expect("a scanned blob").join(", ");
            format!("{}: {phrases}", &sha[..12.min(sha.len())])
        })
        .collect();
    assert!(
        new.is_empty(),
        "a blob in the published history speaks about the machine it was \
         written on, and it is not one of the ones already stuck there.\n\
         A NEW commit writes a NEW blob, so this is almost certainly a claim \
         you can still delete from the working tree before it is committed. \
         Keep the reasoning and drop the machine.\n  {}",
        new.join("\n  ")
    );

    // The other direction, which is what stops the list becoming permanent. A
    // rewrite that scrubs the class replaces every sha below at once.
    let stale: Vec<&str> = ratchet
        .iter()
        .copied()
        .filter(|sha| !found.blob_shas.contains(*sha) || !offending.contains(*sha))
        .collect();
    assert!(
        stale.is_empty(),
        "an entry in HISTORY_DEIXIS_RATCHET is unreachable or no longer \
         offends, so the rewrite that removes this class has landed. Delete \
         these entries — a forgiveness for something that is gone is how a \
         ratchet becomes a permanent hole.\n  {stale:?}"
    );
}

#[test]
fn the_guards_own_plants_are_exactly_what_the_history_walk_forgives() {
    // `GUARD_PLANTS` is the only exemption the history walk grants inside a
    // blob, so it must not be maintained by hand and must not be wider than
    // what this file actually plants. Both halves are asserted by ONE equality:
    // a new plant fails here, and a stale entry fails here too.
    let source = read(&guard_path());

    let mut planted: BTreeSet<String> = coordinates(&source, true)
        .into_iter()
        .map(|(_, value)| value)
        .filter(|value| !DECOY_COORDINATES.contains(&value.as_str()))
        .collect();
    planted.extend(
        instants(&source)
            .into_iter()
            .filter(|instant| !FIXTURE_INSTANTS.contains(&instant.as_str()))
            .filter(|instant| !HISTORICAL_INSTANTS.contains(&instant.as_str())),
    );

    let declared: BTreeSet<String> = GUARD_PLANTS.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        planted, declared,
        "this file's planted control values and GUARD_PLANTS have diverged. \
         The history walk forgives exactly GUARD_PLANTS inside a blob of this \
         file and nothing else, so a plant missing from that list reads as a \
         leak in the history, and a stale entry there is an exemption for \
         something nobody planted."
    );
}

#[test]
fn the_history_walk_sees_a_leak_that_is_only_in_history() {
    // The control, and it is built rather than described: a real repository
    // whose HEAD is clean and whose history is not. That is the exact shape
    // that beat the tree scanners twice, and every scanner above reports this
    // repository clean.
    //
    // The values planted here are invented, for the reason the header gives:
    // a guard that carries a real coordinate in order to prove it can catch one
    // is the disclosure it exists to prevent.
    let repo = scratch("planted-history");
    std::fs::create_dir_all(&repo).expect("a scratch repository");
    git_must(&repo, &["init", "-q"]);

    let fixture = repo.join("fixture.rs");
    let dirty = "\
        const RECORD: &str = r#\"{\"service\":\"NOT-A-REAL-SERVICE\",\
        \"account\":\"NOT-A-REAL-ACCOUNT\",\"create_time\":\"2019-03-14T11:07:42\"}\"#;\n";
    std::fs::write(&fixture, dirty).expect("write the planted fixture");
    git_must(&repo, &["add", "fixture.rs"]);
    // Every setting a stranger's global config could otherwise impose on this
    // throwaway repository. A missing `user.name`, a signing key that is not
    // present, or a `core.hooksPath` pointing at another project's hooks would
    // each fail this commit for a reason that has nothing to do with what is
    // being tested — and a gate that fails for unrelated reasons is a gate
    // somebody switches off.
    let identity = [
        "-c",
        "user.name=publication test",
        "-c",
        "user.email=publication@example.invalid",
        "-c",
        "commit.gpgsign=false",
    ];
    let commit = |message: &str| {
        let mut args: Vec<&str> = identity.to_vec();
        args.extend(["commit", "-q", "--no-verify", "-m", message]);
        git_must(&repo, &args);
    };
    commit("a fixture with a real-shaped coordinate and a transcribed instant");

    // The scrub, exactly as it landed here twice: the TREE is clean afterwards.
    let clean = "\
        const RECORD: &str = r#\"{\"service\":\"demo\",\"account\":\"acct\",\
        \"create_time\":\"2000-01-01T00:00:00\"}\"#;\n";
    std::fs::write(&fixture, clean).expect("write the scrubbed fixture");
    git_must(&repo, &["add", "fixture.rs"]);
    commit("scrub the fixture");

    // Half the control: at HEAD there is nothing to find, so a tree scanner
    // reports this repository clean and would be right about the tree.
    //
    // Counted before it is judged. `all()` over an empty iterator is TRUE, so
    // an extractor that had stopped reading would report the scrubbed fixture
    // clean for the wrong reason, and this control would still be green while
    // proving nothing about either half.
    let head = read(&fixture);
    let head_coordinates = coordinates(&head, true);
    let head_instants = instants(&head);
    assert_eq!(
        head_coordinates.len(),
        2,
        "the scrubbed fixture yielded {head_coordinates:?}, not the two \
         coordinates it is written to carry"
    );
    assert_eq!(
        head_instants.len(),
        1,
        "the scrubbed fixture yielded {head_instants:?}, not the one instant \
         it is written to carry"
    );
    assert!(
        head_coordinates
            .into_iter()
            .all(|(_, value)| DECOY_COORDINATES.contains(&value.as_str())),
        "the scrubbed fixture is not clean, so this control proves nothing \
         about a leak being HISTORY-only"
    );
    assert!(
        head_instants
            .iter()
            .all(|instant| FIXTURE_INSTANTS.contains(&instant.as_str())),
        "the scrubbed fixture still carries a non-fixture instant"
    );

    // The other half: the history walk names both classes, by value.
    let found = scan_history(&repo);
    let coordinates_found = found.coordinate_offenders.join("\n");
    let instants_found = found.instant_offenders.join("\n");

    assert!(
        coordinates_found.contains("NOT-A-REAL-SERVICE"),
        "the history walk missed a keychain service that is only in a parent \
         commit. Offenders: {coordinates_found:?}"
    );
    assert!(
        coordinates_found.contains("NOT-A-REAL-ACCOUNT"),
        "the history walk missed a keychain account that is only in a parent \
         commit. Offenders: {coordinates_found:?}"
    );
    assert!(
        instants_found.contains("2019-03-14T11:07:42"),
        "the history walk missed a transcribed instant that is only in a parent \
         commit. Offenders: {instants_found:?}"
    );
    assert_eq!(
        found.commits, 2,
        "the planted repository does not have the two commits this control needs"
    );

    let _ = std::fs::remove_dir_all(&repo);
}

#[test]
fn a_shallow_checkout_is_refused_rather_than_read_as_clean() {
    // A depth-1 checkout hands the walk one commit. One commit with nothing to
    // flag is not a clean history; it is an unread one, and the two produce the
    // same empty result.
    assert!(
        !is_shallow(manifest_dir()),
        "this checkout is shallow, so the history walk above read a fraction of \
         the published objects and its clean verdict means nothing. Run \
         `git fetch --unshallow`; in CI, check out with `fetch-depth: 0`."
    );

    // And the probe can actually tell, which is the half that would otherwise
    // be an assumption. `file://` rather than a plain path, because git only
    // performs a real shallow fetch over a transport.
    let clone = scratch("shallow-clone");
    let url = format!("file://{}", manifest_dir().display());
    // `protocol.file.allow` is `user` by default but plenty of people set it to
    // `never` by hand after CVE-2022-39253. Named here so this control tests the
    // shallow probe rather than the reader's git configuration.
    let out = Command::new("git")
        .args([
            "-c",
            "protocol.file.allow=always",
            "clone",
            "--quiet",
            "--depth",
            "1",
            &url,
        ])
        .arg(&clone)
        .output()
        .expect("git clone");
    assert!(
        out.status.success(),
        "the shallow clone failed, so this control did not run: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        is_shallow(&clone),
        "a `--depth 1` clone is not detected as shallow, so the assertion above \
         cannot fail and is not protecting anything"
    );

    // And it is visibly smaller, so the refusal is about missing history rather
    // than about a flag nobody reads.
    let shallow_commits: usize = git_must(&clone, &["rev-list", "--all", "--count"])
        .trim()
        .parse()
        .expect("a commit count");
    assert!(
        shallow_commits < history().commits,
        "the shallow clone has as many commits as the full one, so `--depth 1` \
         did nothing and this control is vacuous"
    );

    let _ = std::fs::remove_dir_all(&clone);
}
