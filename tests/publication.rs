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
//! # What this does NOT cover, stated so nobody reads silence as coverage
//!
//! - **Commit messages.** No scanner here reads `git log`, and five of this
//!   repository's own messages carry a census figure while every check here is
//!   green. That gate is `publication`'s commit-message direction in
//!   `hooks/tests/test_publication.py`, which owns the prose grammar; putting a
//!   second copy of that grammar here would give the repository two graders
//!   that drift apart.
//! - **A number that is a measurement of one machine.** That is a grammar over
//!   prose, and it was measured over this crate: 26 hits on `src/` + `tests/` +
//!   `README.md`, and every one of them a false positive — `Property 1 of 4`,
//!   `6 of 13 encodings`, `~20 concurrent sessions`, `64 hex`. It also missed
//!   the real leak here, which was spelled `saw two vaults` in words. A gate
//!   that refuses correct work gets deleted, so this file does not carry one;
//!   the same grammar stays where it measured clean, over `hooks/` prose.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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
            let mut i = at + hit + marker.len();
            at = i;
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

/// Every wall-clock instant a fixture is allowed to carry.
///
/// A `create_time` copied out of a real vault view is the moment somebody
/// created that item, and it reads exactly like a made-up one. Six fixture
/// records in this crate carried a real pair, transcribed with the rest of the
/// record, and survived a scrub that had already replaced the item's title —
/// because nobody looks at a timestamp.
///
/// The fixtures are now spelled so that nobody has to look: midnight on the
/// first three days of 2000 cannot be mistaken for an observation.
///
/// The entries under `src/time.rs` are epoch-conversion vectors — leap days,
/// the 2100 non-leap year, the `1_000_000_000` epoch second. They are
/// arithmetic, they are derivable from the constant beside them, and they name
/// nothing.
const FIXTURE_INSTANTS: &[&str] = &[
    // Proton record fixtures.
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
    // The README's illustrative audit row.
    "2026-08-06T14:22:01",
];

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
