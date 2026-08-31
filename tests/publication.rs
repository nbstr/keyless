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
//! # The rule the four scanners below share
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
//! Four scanners, because inventory reaches source in four different shapes:
//!
//! | scanner | shape | control |
//! |---|---|---|
//! | [`every_coordinate_is_an_allowlisted_decoy`] | a vault, item, share, account or service name | [`the_coordinate_scanner_can_actually_fail`] |
//! | [`no_source_file_speaks_about_the_authors_own_machine`] | prose that makes a claim about the machine it was written on | [`the_deixis_scanner_can_actually_fail`] |
//! | [`every_record_timestamp_is_an_allowlisted_fixture`] | a wall-clock instant transcribed out of a real record | [`the_timestamp_scanner_can_actually_fail`] |
//! | [`no_published_file_names_somebodys_home_directory`] | a path rooted at one person's home directory | [`the_home_directory_scanner_can_actually_fail`] |
//!
//! …and one corpus, because all four of them read the WORKING TREE, and a
//! published repository is not its working tree. The same four grammars run a
//! second time over every blob any ref can reach — see the section headed *The
//! history* at the foot of this file, and
//! [`the_history_walk_sees_a_leak_that_is_only_in_history`] for the control that
//! proves it catches what a tree scanner structurally cannot.
//!
//! # What a scanner is pointed AT, which is where this went wrong
//!
//! The grammars were never the weak half. The CORPUS was: the tree scan
//! admitted a file if its extension was on a list of ten, so `site/_headers`
//! and `.gitignore` were read by nothing, while the history walk — which has
//! never had a name filter — read both. A gate silent on the working tree and
//! loud on the history is not a gap, it is a trapdoor: it says nothing while a
//! leak is one `git checkout` from gone, and speaks only once the blob is
//! permanent and its own failure text says a rewrite is the remedy.
//!
//! So the corpus is no longer a name test. [`publishable_paths`] asks GIT what
//! this repository publishes and [`as_text`] decides what is readable from the
//! BYTES, which makes binary the excluded thing rather than the admitted one: a
//! file type nobody anticipated is scanned by default, and a mistake
//! over-scans. Both surfaces answer to that one rule, and
//! [`the_tree_corpus_covers_every_path_in_the_published_commit`] is the
//! equality that stops them narrowing independently again.
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
//!
//!   That was re-measured when Scanner 4 was added, over the whole tree and in
//!   both the line and the paragraph search scopes. It still finds the same
//!   thing: fewer than one hit in six is a real measurement of one machine, and
//!   the rest are `Property 1 of 4`, `6 of 13 encodings`, a byte offset and an
//!   argv slice. What DOES separate cleanly is deixis and a home directory,
//!   which is why the two scanners that shipped are grammars over words and
//!   paths rather than over numbers.
//! - **What is already in the history.** The walk NAMES it and stops it growing;
//!   it cannot remove it. Four lists exist to carry that residue —
//!   [`HISTORICAL_COORDINATES`], [`HISTORICAL_INSTANTS`],
//!   [`HISTORY_DEIXIS_RATCHET`] and [`HISTORY_HOME_PATH_RATCHET`]. One of the
//!   four is EMPTY: the rewrite that removes a class empties its list, and the
//!   both-direction check then makes the walk assert the class is gone rather
//!   than forgiven. Read a green walk as "nothing outside these lists", never
//!   as "the lists are empty" — check them.
//!
//!   The two ratchets are NOT residue somebody declined to clean. Both were
//!   filled by the change that added their grammars, over blobs written while
//!   nothing was looking; every one of those paths is clean at `HEAD`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ───────────────────────────────────────────────────────────────────────────
// The corpus
// ───────────────────────────────────────────────────────────────────────────

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

/// Is this content text? Answered from the BYTES, never from the name.
///
/// The name was the wrong question, and asking it is the whole of the defect
/// this replaced. A NUL byte is git's own binary test, and it is the one signal
/// an extension cannot fake in either direction: `site/_headers` carries no
/// extension and no NUL, and a PNG copied to `notes.md` carries a NUL in its
/// first line.
///
/// **Failing this is never "skip it".** Both corpora record what they could not
/// read and both assert that record is EMPTY — see
/// [`nothing_published_is_beyond_the_reach_of_the_grammars`] — so a file that
/// stops being scannable is a red gate rather than a quiet subtraction. That is
/// the inversion: a file type nobody anticipated is scanned by default, and the
/// cost of being wrong is over-scanning rather than under-scanning.
fn as_text(bytes: Vec<u8>) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Every path this repository publishes, as git itself lists them.
///
/// Tracked files, plus files that are neither tracked nor ignored — the set the
/// next commit would carry, which is the set a clone receives. There is no name
/// pattern in it, so there is no list here that can narrow.
///
/// **This replaced four hand-written lists, and each one was a narrowing.** A
/// directory allow-list, a root-file list, a skipped-directory list and an
/// extension allow-list. The extension list is the one that was measured:
/// `site/_headers` and `.gitignore` carry no extension, so they entered no tree
/// scan at all — while the history walk below, which has never had a name
/// filter, read both. The gate was therefore SILENT while a leak was still one
/// `git checkout` away from gone, and spoke only once the blob was permanent.
/// That is worse than a gap. It converts a one-second fix into a history
/// rewrite, and this repository has already paid for three of those.
///
/// Asking git also puts both corpora under one authority. They cannot be one
/// enumeration — this one is keyed by working-tree path, the history walk is
/// keyed by blob object, and no single function returns both — so what is
/// shared is the AUTHORITY and the admission rule ([`as_text`]), and
/// [`the_tree_corpus_covers_every_path_in_the_published_commit`] is the
/// reconciliation that stops the two drifting apart again.
///
/// It fails rather than skipping outside a git checkout, for the same reason
/// [`is_shallow`] does: a corpus that read nothing and a clean repository are
/// the same empty result.
///
/// **So every case in this file now needs a checkout, not only the history
/// half, and `cargo mutants` does not copy `.git` unless it is told to.**
/// Without `--copy-vcs true` the UNMUTATED baseline fails, the campaign tests
/// zero mutants and reports no outcomes — a dead gate that reads like a quiet
/// one. `scripts/mutants.sh` passes the flag and says why. Keep it:
/// the alternative is to skip when `.git` is absent, which is the empty-result
/// trap this whole file exists to close.
fn publishable_paths(repo: &Path) -> Vec<PathBuf> {
    let listing = git_must(
        repo,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    );
    let mut paths: BTreeSet<PathBuf> = listing
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .map(|entry| repo.join(entry))
        .collect();
    paths.remove(&guard_path());
    paths.into_iter().collect()
}

/// The working tree, read once and classified once.
struct TreeCorpus {
    /// Every published text file, with the exact bytes the grammars read. The
    /// content is carried rather than re-read, so the file that was classified
    /// and the file that is scanned cannot be two different reads.
    text: Vec<(PathBuf, String)>,
    /// Every published file [`as_text`] refused. Asserted empty: a binary that
    /// has to be published is a decision somebody makes out loud.
    binary: Vec<PathBuf>,
}

/// The one read of this working tree, shared by every tree scan below.
fn tree() -> &'static TreeCorpus {
    static CORPUS: std::sync::OnceLock<TreeCorpus> = std::sync::OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut corpus = TreeCorpus {
            text: Vec::new(),
            binary: Vec::new(),
        };
        for path in publishable_paths(manifest_dir()) {
            if !path.is_file() {
                // Tracked and deleted from the working tree. There is nothing
                // here to read, and the blob it left behind belongs to the
                // history walk's corpus rather than to this one.
                continue;
            }
            let bytes =
                std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            match as_text(bytes) {
                Some(text) => corpus.text.push((path, text)),
                None => corpus.binary.push(path),
            }
        }
        corpus.text.sort_by(|left, right| left.0.cmp(&right.0));
        corpus.binary.sort();
        corpus
    })
}

/// Every published text file, this guard excluded.
fn published_files() -> Vec<PathBuf> {
    tree().text.iter().map(|(path, _)| path.clone()).collect()
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
    // The vendor's `<vault>:<permission>` syntax for `op service-account
    // create --vault`, on the decoy vault above.
    "company:read_items",
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
    // 1Password's own built-in field names: `credential` on an API
    // Credential item, `notesPlain` on every item. Vendor vocabulary, not
    // anybody's inventory.
    "credential",
    "expires",
    "first hidden field",
    "notesPlain",
    // The vendor's documented query form, quoted in the 1Password adapter's
    // test that a `?` in a field is refused.
    "otp?attribute=otp",
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
/// **It is EMPTY, and empty is the state to keep it in.** It held two field
/// labels copied from a real item, which had survived a scrub that already
/// replaced the item's title. A history rewrite replaced the blobs that carried
/// them, so there is nothing left to forgive — and with the list empty, the
/// coordinate walk asserts outright that every coordinate in every reachable
/// blob is a decoy.
///
/// An entry here is NEVER in [`DECOY_COORDINATES`], and that is the whole point
/// of a second list: a decoy is invented, and anything landing here was not.
/// Adding one is a statement that a real coordinate is now permanent in the
/// published history, so it belongs to whoever can prove a rewrite is
/// impossible — not to whoever is trying to get a red gate green.
const HISTORICAL_COORDINATES: &[&str] = &[];

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

    for (path, source) in &tree().text {
        let rust = path.extension().is_some_and(|ext| ext == "rs");
        for (marker, value) in coordinates(source, rust) {
            seen += 1;
            if !DECOY_COORDINATES.contains(&value.as_str()) {
                offenders.push(format!("{}: `{marker}` -> `{value}`", shown(path)));
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
///
/// # The two shapes added after this list first shipped, and why bare `this
/// machine` still is not one of them
///
/// The list above was written and the tree went green while `src/freshness.rs`
/// opened with a dated reading of one particular machine and `src/checkout.rs`,
/// `install/install.sh` and `src/freshness.rs` all named a second one. Neither
/// sentence matched a phrase here, and both are the class this scanner is for.
/// So two shapes are added, each of them narrow on purpose:
///
/// - **A PROVENANCE VERB bound to `this machine`.** `measured on this machine`
///   is a reading somebody took standing at one keyboard; `~20 agent sessions
///   on this machine can append at once` is a property of whatever machine is
///   running the tool. Both spell `this machine`, and only the verb tells them
///   apart. So the verb is what is matched, and the bare phrase stays legal —
///   the same discrimination the paragraph above makes with `the` against
///   `their`, and for the same reason: a rule that refused the second sentence
///   would be switched off within a week.
/// - **A NAME for a machine.** `the remote box` identifies one host that is not
///   the reader's, so nothing it is said to have done is checkable by anybody.
///   A tool other people run has no second machine to refer to, which is what
///   makes these safe to forbid outright rather than only beside a verb.
///
// debt: this grammar gates the TREE and the HISTORY, and not a commit message.
//       Watched refusing: `install/commit-msg.sh` exits 1 on a census claim and
//       exits 0 on `Measured on the remote box`, because the message gate in
//       `hooks/tests/test_publication.py` owns the census grammar and only
//       that one. Ceiling: a message may still say what no file may.
//       The fix is NOT a copy of this list in Python — the header of this file
//       forbids two graders that drift apart, and it is right. It is to make
//       one of the two the single owner of the deixis grammar and have the
//       other call it, which is a cross-language move and larger than the
//       sweep that found this.
//       Upgrade trigger: a commit message lands carrying a machine name or a
//       home directory. `KNOWN_UNSCRUBBED` next door is where that becomes
//       visible, and it growing is the signal.
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
    // A reading taken at one keyboard. The verb is the whole discrimination —
    // see the section above for why the bare phrase is not here.
    "measured on this machine",
    "measured on this box",
    "observed on this machine",
    "observed on this box",
    "happened on this machine",
    // A name for a machine that is not the reader's.
    "the remote box",
    "the build box",
    "the dev box",
    "my box",
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

    for (path, source) in &tree().text {
        let relative = shown(path);
        if DEIXIS_EXEMPT
            .iter()
            .any(|exempt| relative.ends_with(exempt))
        {
            continue;
        }
        for phrase in deixis_in(source) {
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

    // The two shapes that were in the tree while this scanner was green, in the
    // spelling they were really written in — with the magnitudes invented, for
    // the reason the header gives.
    assert!(
        !deixis_in("Measured on this machine 2000-01-01: the binary was older than the tree")
            .is_empty(),
        "a dated reading of one machine must be an offence"
    );
    assert!(
        !deixis_in("The remote box has the same shape").is_empty(),
        "naming a second machine must be an offence"
    );

    // And the sentence a verb-free rule would have to refuse in order to catch
    // them. It is correct writing about whatever machine is running the tool,
    // it is in this crate today, and a gate that refused it would be deleted.
    assert!(
        deixis_in("how loaded this machine has to be before a passing test reports a failure")
            .is_empty(),
        "`this machine` without a provenance verb is a property of the host, not a reading"
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

    // Scanner 4's exemption, held to the same standard. The history walk skips
    // this file's own blobs, which is only safe while scanning it still finds
    // something: an extractor that had stopped matching would make that skip
    // indistinguishable from a clean file, and every home-directory verdict
    // above would be worthless.
    assert!(
        !home_paths_in(&read(&guard_path())).is_empty(),
        "this guard no longer contains the home directories it plants, so the \
         home-path matcher has stopped matching"
    );

    // And the sibling, which is NOT exempt from Scanner 4 because it commits no
    // offence. Asserted rather than assumed: the day it grows one, this says so
    // instead of the history walk reding on a file nobody was watching.
    assert!(
        home_paths_in(&read(&sibling)).is_empty(),
        "the Python sibling now carries a home directory. Scanner 4 grants it no \
         exemption, so either the path is a real leak or it needs one stated here."
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Scanner 4 — somebody's home directory
// ───────────────────────────────────────────────────────────────────────────

/// The names a home directory may be spelled with in a published file.
///
/// A path rooted at a home directory says who was sitting at the machine. It is
/// the same class as a vault coordinate and it is spelled two ways: absolute
/// (`/Users/<name>/…`, `/home/<name>/…`) and tilde (`~/<something>`). Both were
/// in this tree while every scanner above was green — one of them in `tests/`,
/// which no sweep had ever covered.
///
/// **Absolute is an allowlist of METAVARIABLES**, because a real login name is
/// the offence and a documentation stand-in is not. The README writes
/// `/Users/you/.config/keyless/config.json` and means "wherever your home is";
/// anything else in that position is a name.
const HOME_SEGMENT_METAVARIABLES: &[&str] = &[
    "you", "your", "user", "username", "me", "someone", "<user>", "<you>", "<name>", "home",
];

/// The tilde spellings this repository legitimately writes.
///
/// **A dot-segment is exempt without being listed**, and that is the rule that
/// makes this grammar shippable rather than noisy. `~/.config`, `~/.cargo/bin`,
/// `~/.ssh/id_*`, `~/.keyless-pass-session` and the rest of the credential
/// estate this tool exists to talk about are locations that mean the same thing
/// in everybody's home. A home directory's own name never begins with a dot, so
/// exempting the dot-segments costs nothing and removes the entire body of
/// correct writing at once.
///
/// What is left is a `~/` followed by an ordinary directory name, and each one
/// has to be answered for out loud — the argument this file's header already
/// makes for an allowlist over a denylist. There are five, and each is legal
/// for a reason a reader can check without knowing whose machine it was:
///
/// - `~/Library` is a macOS location, identical in every account.
/// - `~/work` is the README's own placeholder for a project directory.
/// - `~/foo`, `~/README.md` and `~/no-home-here` are fixture inputs: strings fed
///   to a resolver in order to watch what it does with them.
///
/// A sixth entry would have been `~/projects/…`, which is where this grammar
/// came from. It is a real directory on a real machine and it is exactly what
/// this list must never grow to hold.
const HOME_TILDE_SEGMENTS: &[&str] = &["Library", "work", "foo", "README.md", "no-home-here"];

/// Is this byte part of a path segment rather than a separator?
fn is_segment_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'+' | b'<' | b'>')
}

/// The segment starting at `from`, and where it ends.
fn segment_at(bytes: &[u8], from: usize) -> (String, usize) {
    let mut end = from;
    while end < bytes.len() && is_segment_byte(bytes[end]) {
        end += 1;
    }
    (String::from_utf8_lossy(&bytes[from..end]).into_owned(), end)
}

/// Every home-directory reference a published file may not carry.
///
/// Deliberately NOT a regex and deliberately case-sensitive on the two roots:
/// `/Users/` and `/home/` are the spellings the two platforms use, and lowering
/// the whole text first would make `~/library` and `~/Library` the same string
/// in an allowlist whose entries name real directories.
fn home_paths_in(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();

    for root in ["/Users/", "/home/"] {
        let mut from = 0;
        while let Some(offset) = text[from..].find(root) {
            let start = from + offset;
            let (segment, end) = segment_at(bytes, start + root.len());
            // `/home/` with nothing after it is a prefix in prose, not a path.
            if !segment.is_empty()
                && !HOME_SEGMENT_METAVARIABLES.contains(&segment.to_lowercase().as_str())
            {
                found.push(format!("{root}{segment}"));
            }
            from = end.max(start + 1);
        }
    }

    let mut from = 0;
    while let Some(offset) = text[from..].find("~/") {
        let start = from + offset;
        let (segment, end) = segment_at(bytes, start + 2);
        if !segment.is_empty()
            && !segment.starts_with('.')
            && !HOME_TILDE_SEGMENTS.contains(&segment.as_str())
        {
            found.push(format!("~/{segment}"));
        }
        from = end.max(start + 1);
    }

    found
}

#[test]
fn no_published_file_names_somebodys_home_directory() {
    let mut offenders: Vec<String> = Vec::new();

    for (path, source) in &tree().text {
        let relative = shown(path);
        for hit in home_paths_in(source) {
            offenders.push(format!("{relative}: `{hit}`"));
        }
    }

    assert!(
        offenders.is_empty(),
        "a published file is rooted at somebody's home directory.\n\
         A real login name goes; a metavariable (`/Users/you/…`) or a location that means \
         the same thing in every account (`~/.config/…`) stays. If this one really is \
         neither, it belongs in HOME_TILDE_SEGMENTS with a reason a reader can check.\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_home_directory_scanner_can_actually_fail() {
    // The two spellings that were really in this tree, with the name replaced
    // by an invented one — carrying the real one in order to forbid it is the
    // disclosure this file exists to prevent.
    for planted in [
        "/Users/qwilfish/.keyless-pass-session/.session/session.json",
        "/home/qwilfish/src/keyless",
        "a symlink into ~/projects/keyless-published/target/release/",
    ] {
        assert!(
            !home_paths_in(planted).is_empty(),
            "`{planted}` is a home directory and was not read as one"
        );
    }

    // And every exemption, which must survive. Without these the grammar would
    // refuse the README, the config documentation and six fixtures at once,
    // which is the failure that ends with the gate deleted.
    for exempt in [
        "keyless 0.1.0   /Users/you/.config/keyless/config.json",
        "\"cwd\":\"/Users/You/src/app\"",
        "`cargo install` writes to ~/.cargo/bin",
        "~/.config/keyless/config.json",
        "PROTON_PASS_SESSION_DIR=~/.keyless-pass-session",
        "\"config_dir\": \"~/work/api\"",
        "~/Library/Application Support",
        "the resolver is handed ~/foo and ~/no-home-here",
        "under /home/ on Linux",
    ] {
        assert!(
            home_paths_in(exempt).is_empty(),
            "`{exempt}` is correct writing and was refused"
        );
    }

    // A segment is read to its end rather than by prefix, or `~/.cargo` would
    // clear `~/.cargoes-of-mine` too and a real directory could hide behind a
    // legal one.
    assert_eq!(home_paths_in("~/Libraryish/notes"), vec!["~/Libraryish"]);
    assert_eq!(
        home_paths_in("/Users/younger/keyless"),
        vec!["/Users/younger"]
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
/// history, in blobs of `README.md` that predate the tree fix. A history
/// rewrite could reach those blobs and deliberately has not: the value is
/// INVENTED, checked against the live audit log, which holds no row on that
/// date. It is not an observation of anything, so removing it would buy nothing
/// and cost every sha in the repository. A walk that greened without naming it
/// would be a walk that was not looking.
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

    for (path, source) in &tree().text {
        for instant in instants(source) {
            seen += 1;
            if !FIXTURE_INSTANTS.contains(&instant.as_str()) {
                offenders.push(format!("{}: `{instant}`", shown(path)));
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
fn the_text_classifier_reads_content_and_not_a_name() {
    // Both directions, because a classifier that says yes to everything and one
    // that says no to everything both leave the corpus above looking settled.
    assert_eq!(
        as_text(b"# a published file with no extension\n".to_vec()).as_deref(),
        Some("# a published file with no extension\n"),
        "an extensionless UTF-8 file is text, and deciding that from its name is \
         the defect this replaced"
    );
    assert!(
        as_text(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec()).is_none(),
        "a PNG is binary whatever it is called, including `notes.md`"
    );
    assert!(
        as_text(vec![0xff, 0xfe, 0x41, 0x00]).is_none(),
        "bytes that are not UTF-8 are not text"
    );
    assert!(
        as_text(Vec::new()).is_some(),
        "an empty file is text, and refusing it would put every empty published \
         file on the binary list"
    );
}

#[test]
fn nothing_published_is_beyond_the_reach_of_the_grammars() {
    // One admission rule, asserted over both corpora in one place. The history
    // walk's own size test asserts the same emptiness, but for the other
    // reason: that one catches a walk that COLLAPSED, this one catches content
    // that no grammar here can read.
    let unreadable: Vec<String> = tree().binary.iter().map(|path| shown(path)).collect();
    assert!(
        unreadable.is_empty(),
        "a published file is not text, so none of the four grammars reads it: \
         {unreadable:?}.\n\
         Nothing in this repository is meant to be binary. If one has to be, say \
         so out loud rather than letting the scan step over it."
    );
    assert!(
        history().unreadable.is_empty(),
        "a published blob is not text: {:?}",
        history().unreadable
    );
}

#[test]
fn a_published_file_with_no_extension_is_scanned() {
    // The measured defect, asserted rather than described.
    //
    // The corpus filtered on extension, `site/_headers` has none, and it entered
    // no tree scan at all — while the history walk read it the moment it was
    // committed, and says in its own failure text that only a rewrite removes
    // what it finds. So the tree scan was silent exactly while the fix was
    // cheap. `.gitignore` was invisible for a SECOND reason, and that is why
    // finding one narrowing was not the end of the search: the root-file audit
    // skipped every name beginning with a dot, so no list mentioned it and no
    // test missed it.
    //
    // Computed rather than named, so it keeps holding when the files change.
    let scanned: BTreeSet<PathBuf> = published_files().into_iter().collect();
    let mut extensionless: Vec<String> = Vec::new();
    let mut unscanned: Vec<String> = Vec::new();

    for path in publishable_paths(manifest_dir()) {
        if !path.is_file() || path.extension().is_some() {
            continue;
        }
        extensionless.push(shown(&path));
        if !scanned.contains(&path) {
            unscanned.push(shown(&path));
        }
    }

    assert!(
        extensionless.len() >= 2,
        "this repository publishes {} files with no extension, so this case has \
         nothing to prove and passes for the wrong reason. It is the class that \
         was unscanned; a repository holding none of them needs a different \
         control, not this one.",
        extensionless.len()
    );
    assert!(
        unscanned.is_empty(),
        "a published file with no extension is scanned by nothing: {unscanned:?}.\n\
         The corpus is supposed to admit by CONTENT. Something has put a name \
         test back in front of it."
    );
}

#[test]
fn the_tree_corpus_covers_every_path_in_the_published_commit() {
    // The control this file did not have, and the reason it did not have one:
    // every existing check on the corpus was a FLOOR — `files.len() >= 90`,
    // `seen >= 200` — and a floor cannot see one class go missing while nine
    // others stay. Two files were absent from every tree scan and every count
    // sat comfortably above its floor.
    //
    // So this is an EQUALITY against git's listing of the commit that gets
    // published, and it NAMES what is missing rather than subtracting it. It is
    // also the reconciliation between the two corpora: they cannot be one
    // enumeration, so this is what stops them narrowing independently, which is
    // exactly how the extension filter survived on one side and never existed
    // on the other.
    let scanned: BTreeSet<String> = tree()
        .text
        .iter()
        .map(|(path, _)| shown(path))
        .chain(tree().binary.iter().map(|path| shown(path)))
        .collect();

    let listing = git_must(
        manifest_dir(),
        &["ls-tree", "-r", "-z", "--name-only", "HEAD"],
    );
    let committed: Vec<&str> = listing
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .collect();

    let mut missing: Vec<&str> = Vec::new();
    let mut directories: BTreeSet<&str> = BTreeSet::new();
    for path in &committed {
        if *path == file!() {
            continue; // this guard, which is excluded from its own scans
        }
        if !manifest_dir().join(path).is_file() {
            continue; // deleted since the commit; its blob is the walk's corpus
        }
        directories.insert(path.split('/').next().unwrap_or_default());
        if !scanned.contains(*path) {
            missing.push(path);
        }
    }

    assert!(
        committed.len() >= 100,
        "`git ls-tree HEAD` named only {} paths, so this comparison is against \
         almost nothing and would pass however narrow the corpus had become",
        committed.len()
    );
    assert!(
        missing.is_empty(),
        "a path in the published commit is in no corpus: {missing:?}.\n\
         Every file git publishes is read by the four grammars or is named as \
         binary. There is no third outcome, and a file reaching one would be \
         invisible to this gate until somebody committed it."
    );

    // And every top level the commit contains contributed something. A whole
    // directory going quiet is the same failure one size larger, and the
    // equality above would report it as a long list rather than as a cause.
    for directory in &directories {
        assert!(
            scanned.iter().any(|path| path.starts_with(directory)),
            "`{directory}` is published and contributed no scanned file at all"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// The history — the same four grammars, over every blob a ref can reach
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
// MESSAGES — and it would have had to carry a second copy of all four
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
/// **It is EMPTY.** Scrubbing a class with an ordinary commit cleans the TREE
/// and leaves every earlier blob intact, so the class survives in the history
/// with nothing on the tree surface to show it. That mechanism has produced a
/// residue three times on this repository, and it is the reason this walk reads
/// blobs rather than files. A history rewrite has replaced the blobs behind
/// this class, so the list has nothing left to point at.
///
/// Keep it empty. With no entries, the first assertion below stops being "no
/// NEW blob offends" and becomes "NO blob offends", which is the property this
/// file is for. A non-empty list is a RATCHET, spelled the way
/// `KNOWN_UNSCRUBBED` is spelled next door, and checked in both directions by
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
/// Emptying it takes a rewrite of every sha in this repository, because a blob
/// is immutable and there is no smaller edit that reaches one. Refilling it is
/// therefore never the fix for a red gate: a NEW offending blob is one you can
/// still delete from the working tree, and the assertion below says so in its
/// own failure message.
///
/// **There is exactly one other way an entry gets here, and it is the way these
/// six did: the GRAMMAR widened.** `MACHINE_DEIXIS` grew two shapes it had been
/// silent on, and blobs written before that were immediately in scope. The
/// working tree was fixed in the same change — nothing below is still in a
/// published file — but a blob cannot be. Distinguishing the two cases is the
/// author's job and it is not automatable: what the gate can check, and does,
/// is that no entry outlives the offence it was added for.
const HISTORY_DEIXIS_RATCHET: &[&str] = &[
    "15da4d88fa3043fe0a6119800d0e5b63f8093404",
    "5fd0ad5fa50364423e67f4617dff6d42d55df856",
    "91cfe82e74d19830452260c6bd740b8c70416b28",
    "c3a9dc2cab367e5f60b4c8cd900ae621d7478893",
    "cdc09047c6bd7b4aca6f466a9fb86d5405afde91",
    "d19c5f901317ea8a923f13ba6fdb0d9398954516",
];

/// Blobs that carry somebody's home directory and can no longer be edited.
///
/// The same ratchet as [`HISTORY_DEIXIS_RATCHET`], for Scanner 4, checked in
/// the same two directions by
/// [`historical_home_directories_are_confined_to_a_shrinking_ratchet`]. It is
/// populated for the same reason: the grammar did not exist when these blobs
/// were written.
const HISTORY_HOME_PATH_RATCHET: &[&str] = &[
    "001d5fb7021a4a81cd46ff3cd72b93de9bd7da0f",
    "0583cd8d3e4b410ffb23a5c8810cbcef4362f1ce",
    "1239a323c19e288cecacd0e54e4526d1a073ea08",
    "42f5988371e0d05ef8b43d1b624e0abda01d6485",
    "5fd0ad5fa50364423e67f4617dff6d42d55df856",
    "84a5d58614ceec4a2f3965fd59cec75445fa40df",
    "91cfe82e74d19830452260c6bd740b8c70416b28",
    "c3a9dc2cab367e5f60b4c8cd900ae621d7478893",
    "cdc09047c6bd7b4aca6f466a9fb86d5405afde91",
    "d19c5f901317ea8a923f13ba6fdb0d9398954516",
    "e02c38d91c92fad29c457daf203db790ba7b6867",
    "fb106a867b181056aa31c7ec3120f1a58c4cfb4f",
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
    /// Every blob carrying a home-directory path, keyed by sha. Same shape and
    /// same reason as `deixis`.
    home_paths: BTreeMap<String, Vec<String>>,
}

/// Run all four grammars over every blob `repo` publishes.
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
        home_paths: BTreeMap::new(),
    };

    for (sha, paths, bytes) in reachable_blobs(repo) {
        findings.blobs += 1;
        findings.blob_shas.insert(sha.clone());
        let where_ = paths.iter().cloned().collect::<Vec<_>>().join(", ");
        let short = &sha[..12.min(sha.len())];

        // The SAME admission rule the tree corpus uses, so the two surfaces
        // cannot come to disagree about what counts as scannable. That is what
        // went wrong before: this walk admitted every blob it could decode and
        // the tree scan admitted ten file extensions, and nothing compared them.
        let Some(text) = as_text(bytes) else {
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

        // THIS FILE IS EXEMPT FROM SCANNER 4, and the first version of this
        // walk was not — it asserted that the plants in
        // `the_home_directory_scanner_can_actually_fail` were harmless because
        // the login name in them is invented. That is wrong twice over. The
        // grammar reads a POSITION, not a name, so `/Users/qwilfish` offends
        // exactly as loudly as a real one; and the plants are what make the
        // scanner provable, so every future version of this file would write a
        // fresh blob carrying them, with a fresh sha that no ratchet can hold.
        // A gate that reds on its own control is a gate somebody deletes.
        //
        // The Python sibling gets no exemption here, unlike in the deixis walk
        // above: it carries no home path, so forgiving it would be a hole that
        // could never be observed to work. Only this file offends, and
        // `the_guards_own_exemption_is_a_real_exemption` proves it still does.
        let is_this_guard = !paths.is_empty() && paths.iter().all(|path| path == guard);
        if !is_this_guard {
            let homes = home_paths_in(&text);
            if !homes.is_empty() {
                findings.home_paths.insert(sha.clone(), homes);
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
fn historical_home_directories_are_confined_to_a_shrinking_ratchet() {
    let found = history();
    let offending: BTreeSet<&str> = found.home_paths.keys().map(String::as_str).collect();
    let ratchet: BTreeSet<&str> = HISTORY_HOME_PATH_RATCHET.iter().copied().collect();

    let new: Vec<String> = offending
        .difference(&ratchet)
        .map(|sha| {
            let hits = found
                .home_paths
                .get(*sha)
                .expect("a scanned blob")
                .join(", ");
            format!("{}: {hits}", &sha[..12.min(sha.len())])
        })
        .collect();
    assert!(
        new.is_empty(),
        "a blob in the published history is rooted at somebody's home \
         directory, and it is not one of the ones already stuck there.\n\
         A NEW commit writes a NEW blob, so this is almost certainly a path \
         you can still delete from the working tree before it is committed.\n  {}",
        new.join("\n  ")
    );

    let stale: Vec<&str> = ratchet
        .iter()
        .copied()
        .filter(|sha| !found.blob_shas.contains(*sha) || !offending.contains(*sha))
        .collect();
    assert!(
        stale.is_empty(),
        "an entry in HISTORY_HOME_PATH_RATCHET is unreachable or no longer \
         offends, so the rewrite that removes this class has landed. Delete \
         these entries.\n  {stale:?}"
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
