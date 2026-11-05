//! Assertions that read a report state word as a SUBSTRING.
//!
//! `oracle_independence.rs` asks whether an assertion's two sides are
//! independent. `suite_hygiene.rs` asks whether a fixture's numbers are honest.
//! This file asks a third question about the same suite: when a test names one
//! of the report's state words, can that assertion fail on the change it is
//! named for?
//!
//! # The defect class
//!
//! `doctor`, `init` and `setup` render rows of the shape
//!
//! ```text
//!   +  keychain  proven     service "keyless"
//! ```
//!
//! The third column is one word from a closed vocabulary, and the vocabulary's
//! whole job is to keep those words APART: `proven` and `unproven` are opposite
//! verdicts and one contains the other. So
//!
//! ```text
//! assert!(text.contains("proven"), "{text}");
//! ```
//!
//! holds when the row says `unproven`. It is satisfied by the single state it
//! exists to exclude, and a green `+` printed beside the word that denies it
//! passes it too.
//!
//! Measured on this tree before `b3e641b`: rewriting every `proven` the crate
//! renders to `unproven` — 29 sites — left the whole suite green. Suffixing any
//! word in the vocabulary, one word at a time, left it green as well: a
//! `contains` check cannot see a boundary at either end, so `blockedX` satisfies
//! `contains("blocked")` exactly as `unproven` satisfies `contains("proven")`.
//!
//! The accepted form reads the whole column:
//!
//! ```text
//! assert_eq!(state_of(row), "proven", "{report}");
//! assert!(text.split_whitespace().any(|word| word == "blocked"), "{text}");
//! ```
//!
//! That mutation is the negative control for this whole file, and it is cheap to
//! re-run: give `status::row` a `let state = format!("{state}X");` and every
//! state word in the report gains a suffix at once. Measured on this tree,
//! **20 tests go red**. On the tree before `b3e641b`, none did.
//!
//! Run it as `cargo test --no-fail-fast`. Without that flag the run stops at the
//! first target that fails and reports a fraction of the count — nine, on this
//! tree, because the lib target reds first and the integration tests never
//! execute. A count that low reads as a gate that has rotted rather than as a
//! run that stopped early.
//!
//! # Why a gate rather than a sweep
//!
//! The sweep happened: `b3e641b` tightened ten assertions by hand. It closed the
//! instances and not the class — this scanner, run over the tree that commit
//! produced, found ten more it had missed: six in `tests/` across four files,
//! and four in the `#[cfg(test)]` modules under `src/cmd/doctor`. A sweep finds
//! the word it went looking for, and `proven` is the word anybody sweeping for
//! this thinks of; `absent`, `off`, `stale` and `config` are the ones it walks
//! past. Nothing else in the suite can reach this class either.
//! `oracle_independence.rs` excludes it in
//! its own words ("`assert!(...)` with one argument. A boolean predicate has no
//! two sides to compare"), and `cargo-mutants` cannot produce it at any scope:
//! its operators replace function bodies, replace binary operators, delete `!`
//! and delete match arms, and none of those rewrites a string literal. There is
//! no mutation that turns `"proven"` into `"unproven"`.
//!
//! # What counts as a violation
//!
//! A `.contains("<word>")` whose literal IS a vocabulary word, in a POSITIVE
//! position.
//!
//! Position is the whole of the second half. A NEGATIVE check is made STRICTER
//! by a superstring, never weaker: `!row.contains("proven")` fails the moment
//! the row says `unproven`, because `unproven` contains `proven`. Flagging it
//! would be reding correct work, and a gate that reds on correct work is a gate
//! somebody deletes — taking the real flags with it. So negation is detected and
//! spared, through `!x.contains(…)`, `!(x.contains(…))` and the `&&`/`||` chains
//! the suite writes them in.
//!
//! # An instance this gate cannot fix yet
//!
//! [`OPEN`] is empty, and empty is its correct state. It exists for the case a
//! gate like this one otherwise cannot survive: an instance that IS this defect
//! and cannot be edited right now — a file under other work in flight, say —
//! where the alternatives are blessing it in [`ACCEPTED`], which is a lie, or
//! not committing the gate at all, which protects nothing against the instance
//! somebody writes next month.
//!
//! A row there names its fix and is deleted BY that fix: the stale-row check
//! reds on a row that stops flagging, so the list cannot quietly become the
//! permanent shape of this gate. Both directions are load-bearing — delete a
//! row without fixing its site and the corpus scan reds instead.
//!
//! # Where the rest lives
//!
//! `state_vocabulary_derivation.rs` proves the vocabulary this gate reads is
//! the one the report documents, `state_vocabulary_scanner.rs` proves the
//! scanner can flag and spare, and `state_vocabulary_support/` holds the
//! scanner both of them and this file share.

mod state_vocabulary_support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use state_vocabulary_support::contains::contains_calls;
use state_vocabulary_support::rust_text::{
    collect_rust_sources, enclosing, functions, is_this_gate, relative, squeeze, strip_comments,
    test_regions,
};
use state_vocabulary_support::vocabulary::vocabulary;
/// The key is `<path>::<enclosing fn>::<word>`. The reason is the whole point of
/// the row: a bare list of exemptions is a list of assertions nobody has to
/// justify.
///
/// **What may NOT be recorded here:** "the row is asserted somewhere else
/// anyway", or "the word cannot change". The only admissible reason is that the
/// assertion is not about a STATE COLUMN at all — that the word is prose in a
/// detail, a heading, or a path, and the vocabulary merely happens to contain
/// the same English word. Anything that is about a state column belongs in
/// [`OPEN`] or, better, fixed.
const ACCEPTED: &[(&str, &str)] = &[(
    "src/cmd/doctor/stores.rs::a_proven_infisical_row_never_reads_as_having_established_the_instance::config",
    "NOT A STATE COLUMN. The subject is `points_at`'s DETAIL, which reads \
     `path /backend, project p-decoy — from this config. WHICH INSTANCE …`, and \
     the assertion's claim is that the coordinates are attributed rather than \
     stated as a reading. `config` is an ordinary English word here and the row \
     it belongs to is `proven`, not `config`. A whole-word split would have to \
     carry the sentence's full stop, which pins punctuation instead of meaning.",
)];

/// Flags that ARE this defect and are not fixed yet, each with its fix.
///
/// A row here is a DEFERRAL, not an exemption, and it is the only honest way to
/// keep this gate green while an instance is out of reach: without it the gate
/// cannot be committed at all, and a gate nobody can commit protects nothing
/// against the instance somebody writes next month.
///
/// A row must name the fix, and it is deleted BY the fix — the stale-row check
/// below reds on a row that no longer flags anything, so this list cannot
/// quietly become permanent.
const OPEN: &[(&str, &str)] = &[];

/// Directories scanned, relative to the crate root.
const SCANNED: &[&str] = &["src", "tests"];

/// Below this, the walk has collapsed rather than found a clean tree.
///
/// Re-measure rather than quoting a number: `find src tests -name '*.rs' | wc -l`.
const MIN_FILES: usize = 30;

/// The floor on `.contains("<literal>")` calls seen in test regions.
///
/// This is the blindness guard for the matcher itself. Measured on this tree:
/// 388. A floor well under that catches a matcher that stopped recognising the
/// spelling the suite uses — which would report zero flags, and zero flags is
/// what this gate passing looks like.
const MIN_CONTAINS_CALLS: usize = 200;
#[test]
fn no_assertion_reads_a_state_word_as_a_substring() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for dir in SCANNED {
        collect_rust_sources(&root.join(dir), &mut sources);
    }
    sources.sort();
    assert!(
        sources.len() >= MIN_FILES,
        "only {} source file(s) were found under {SCANNED:?} in {}. The suite has \
         more than that, so the walk collapsed — and a walk that reads nothing \
         flags nothing, which is indistinguishable from a clean suite.",
        sources.len(),
        root.display()
    );

    let vocabulary = vocabulary(&root, &sources);
    let mut seen_calls = 0usize;
    let mut flagged: BTreeMap<String, String> = BTreeMap::new();
    for path in &sources {
        if is_this_gate(&root, path) {
            continue;
        }
        let text = strip_comments(
            &std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
        );
        let regions = test_regions(&root, path, &text);
        let functions = functions(&text);
        let key_prefix = relative(&root, path);
        for call in contains_calls(&text) {
            if !regions.iter().any(|(a, b)| (*a..*b).contains(&call.at)) {
                continue;
            }
            seen_calls += 1;
            let Some(word) = vocabulary.get(call.literal.trim()) else {
                continue;
            };
            if call.negated {
                continue;
            }
            let owner = enclosing(&functions, call.at).unwrap_or("<file>");
            flagged.insert(
                format!("{key_prefix}::{owner}::{word}"),
                text.get(call.from..call.end)
                    .map(squeeze)
                    .unwrap_or_default(),
            );
        }
    }

    assert!(
        seen_calls >= MIN_CONTAINS_CALLS,
        "only {seen_calls} `.contains(\"…\")` call(s) were found in the test \
         regions of {SCANNED:?}, and the floor is {MIN_CONTAINS_CALLS}. The \
         matcher has stopped seeing the shape the suite writes, so most of it is \
         no longer being read — and a scanner that reads nothing flags nothing, \
         which is exactly what this gate passing looks like."
    );

    let known: BTreeSet<&str> = ACCEPTED
        .iter()
        .chain(OPEN.iter())
        .map(|(key, _)| *key)
        .collect();

    let unclassified: Vec<String> = flagged
        .iter()
        .filter(|(key, _)| !known.contains(key.as_str()))
        .map(|(key, excerpt)| format!("{key}\n      {excerpt}"))
        .collect();
    assert!(
        unclassified.is_empty(),
        "assertion(s) that read a report state word as a substring:\n  {}\n\n\
         `unproven` CONTAINS `proven`, and `blockedX` contains `blocked`, so a \
         `contains` check on a state word cannot fail on the change it is named \
         for. Measured over this tree: every `proven` the crate renders can be \
         rewritten to `unproven`, leaving a green mark beside the word that \
         denies it, and a suite made of these stays green.\n\n\
         THE FIX IS TO READ THE WHOLE COLUMN. A rendered row is `<mark> \
         <subject> <state> <detail>`, so the state is \
         `row.split_whitespace().nth(2)` — every file that needs it already has \
         a `state_of` helper, and `assert_eq!(state_of(row), \"proven\")` is the \
         shape. Where the row is not pinned down, \
         `text.split_whitespace().any(|word| word == \"blocked\")` at least \
         compares whole words.\n\n\
         If the word is prose rather than a state column, add a row to ACCEPTED \
         in tests/state_vocabulary.rs saying so.",
        unclassified.join("\n  ")
    );

    let stale: Vec<&str> = known
        .iter()
        .copied()
        .filter(|key| !flagged.contains_key(*key))
        .collect();
    assert!(
        stale.is_empty(),
        "ACCEPTED/OPEN row(s) that no longer flag anything:\n  {}\n\n\
         Either the assertion was fixed and its row belongs deleted — which is \
         what an OPEN row is FOR — or it was renamed, or the scanner stopped \
         seeing it. The third is the one that matters and it is why this \
         direction is checked at all.",
        stale.join("\n  ")
    );
}
