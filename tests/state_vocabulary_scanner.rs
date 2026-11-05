//! The scanner behind `state_vocabulary.rs`, held to fixtures.
//!
//! # What this scanner CANNOT see
//!
//! * **A longer literal that embeds a state word.** `contains("proven ")` is the
//!   same defect and is not flagged; only a literal that is exactly a state word
//!   (bare, or padded with whitespace on one side) is. The narrow rule is a
//!   deliberate trade: `config`, `off`, `absent`, `broken` and `stale` are
//!   ordinary English words, and flagging every literal that embeds one turns
//!   `contains("config.toml")` and `contains("SWITCHED OFF")` into flags. That
//!   is the noise that gets a gate deleted.
//! * **A substring operator other than `contains`.** `starts_with`, `ends_with`
//!   and `find` would all carry the defect. Measured on this tree: not one of
//!   them is called with a state-word literal anywhere in `src/` or `tests/`, so
//!   the rule is written for the operator the suite actually uses. Add them here
//!   when one appears, rather than widening the literal rule.
//! * **A state word reaching `contains` through a variable.** The argument has to
//!   be a literal at the call site.
//! * **Whether the row it read was the right row.** `contains` over a whole
//!   report is weak in a second way — any row can satisfy it — and this scanner
//!   has no opinion about it. `state_of(row_for(&report, "keychain"))` fixes
//!   both; this gate only forces the first.
//! * **Production code.** Only test regions are scanned: all of `tests/`, the
//!   inline `#[cfg(test)]` modules in `src/`, and the files under `src/` such a
//!   module is loaded from — `tests.rs`, `*_tests.rs` and anything in a
//!   `tests/` directory. A `contains` in the tool itself is string handling,
//!   not an assertion.
//!
//! # The self-test is not decoration
//!
//! A scanner that stopped matching the spelling the sources use would report
//! zero flags, which reads exactly like a clean suite — and this gate's success
//! condition IS zero flags. So
//! `the_scanner_flags_a_substring_check_and_spares_the_forms_that_are_safe` runs
//! it against two fixtures written into this file: one that violates the rule in
//! both of the shapes `b3e641b` had to fix, and one holding every safe form the
//! suite writes, including the negations and a doc comment that quotes the
//! defect verbatim. Breaking the scanner reds that test before it can bless
//! anything, and the corpus scan carries floors of its own for the same reason.

mod state_vocabulary_support;

use std::collections::BTreeSet;
use std::path::Path;

use state_vocabulary_support::contains::contains_calls;
use state_vocabulary_support::rust_text::{strip_comments, test_regions};

/// Two violations, in the two shapes `b3e641b` had to fix by hand.
const VIOLATING_FIXTURE: &str = r#"
#[test]
fn probe_reports_presence_and_never_a_value() {
    let (text, code) = report(&load, registry, true);
    assert!(text.contains("proven"), "{text}");
    assert!(row_for(&text, "keychain").contains( "blocked" ), "{text}");
    assert_eq!(code, 0, "{text}");
}
"#;

/// Every safe form the suite writes, and the ones that broke a prototype.
const SAFE_FIXTURE: &str = r#"
/// The state column of a rendered row.
///
/// Read as a whole column, because `unproven` CONTAINS `proven` — so
/// `contains("proven")` passes on the one state it exists to exclude.
fn state_of(row: &str) -> &str { row.split_whitespace().nth(2).unwrap_or_default() }

#[test]
fn a_dead_session_is_absent_rather_than_broken() {
    let (report, code) = doctor_report(&dir, &config);
    // A negative check is made STRICTER by a superstring, never weaker.
    assert!(!proton_row(&report).contains("proven"), "{report}");
    assert!(!(report.contains("blocked")), "{report}");
    assert!(!report.contains("broken") && !report.contains("off"), "{report}");
    // The accepted forms.
    assert_eq!(state_of(proton_row(&report)), "absent", "{report}");
    assert!(report.split_whitespace().any(|word| word == "blocked"), "{report}");
    // Words that merely embed a state word, in prose, a path and a heading.
    assert!(report.contains("SWITCHED OFF"), "{report}");
    assert!(report.contains("config.toml"), "{report}");
    assert!(report.contains("no upstream to be behind"), "{report}");
    // A slice membership test, which compares whole elements already.
    assert!(FORWARDED_EXACT.contains(&"proven"), "{report}");
    assert_eq!(code, 1, "{report}");
}
"#;

#[test]
fn the_scanner_flags_a_substring_check_and_spares_the_forms_that_are_safe() {
    // A control in both directions. Without the negative one, a scanner that
    // flagged EVERYTHING would pass the positive case and look correct; without
    // the positive one, a scanner that matched nothing would pass the negative
    // case and look correct. Each alone is satisfied by a broken scanner.
    let vocabulary: BTreeSet<&str> = ["proven", "unproven", "blocked", "absent", "off", "broken"]
        .into_iter()
        .collect();
    let hits = |fixture: &str| -> Vec<String> {
        let text = strip_comments(fixture);
        contains_calls(&text)
            .into_iter()
            .filter(|call| !call.negated && vocabulary.contains(call.literal.trim()))
            .map(|call| call.literal)
            .collect()
    };

    assert_eq!(
        hits(VIOLATING_FIXTURE),
        vec!["proven".to_owned(), "blocked".to_owned()],
        "the scanner missed a known substring check — it is now blessing \
         whatever it reads."
    );

    let spared = hits(SAFE_FIXTURE);
    assert!(
        spared.is_empty(),
        "the scanner flagged a safe form: {spared:?}. A negative check is made \
         stricter by a superstring, and a word inside a path or a heading is not \
         a state column. A gate that reds on correct work gets deleted, and then \
         the real flags go with it."
    );

    // The matcher must see the calls it is sparing, or `spared.is_empty()` is
    // satisfied by a matcher that found nothing at all.
    //
    // Seven, not eight: the fixture's `FORWARDED_EXACT.contains(&"proven")` is a
    // slice membership test, whose `&` is what keeps it out. That exclusion is
    // load-bearing rather than incidental — a slice `contains` compares whole
    // elements and is never this defect — so it is pinned by the count here.
    // The doc comment above the fixture quotes the defect verbatim and is not
    // among them either, which is what proves the comment blanking runs.
    let seen = contains_calls(&strip_comments(SAFE_FIXTURE)).len();
    assert_eq!(
        seen, 7,
        "the matcher found {seen} `.contains(\"…\")` call(s) in the safe \
         fixture, which holds 7 it must read. It is not reading them and then \
         sparing them; it is not reading them.",
    );
}

#[test]
fn a_split_out_test_file_is_read_whole_and_its_declaration_marks_nothing() {
    let root = Path::new("/checkout/tests/keyless");
    let body = "fn f() {}";
    for file in [
        "tests/cli.rs",
        "src/daemon/config/tests.rs",
        "src/store/proton_tests.rs",
        "src/daemon/config/tests/cache.rs",
    ] {
        assert_eq!(
            test_regions(root, &root.join(file), body),
            vec![(0, body.len())],
            "{file} is test code and was not read as such"
        );
    }

    let declaring = "#[cfg(test)]\nmod tests;\n\nfn production() { row(); }\n";
    assert_eq!(
        test_regions(root, &root.join("src/daemon/config.rs"), declaring),
        Vec::new(),
        "an out-of-line `mod tests;` marked the production item after it as test code"
    );
    assert_eq!(
        test_regions(root, &root.join("src/daemon/config.rs"), body),
        Vec::new(),
        "a production file was read as test code because its checkout sits under a `tests` directory"
    );
}
