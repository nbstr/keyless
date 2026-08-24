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
//! # Where the vocabulary comes from
//!
//! Not from a list typed here. A second copy of a closed vocabulary rots, and it
//! rots silently in the direction that matters: a word this file has never heard
//! of is a word it cannot flag a `contains` on.
//!
//! It is derived twice, from two independent places in `src/`, and the two are
//! required to agree:
//!
//! * **Rendered.** Every string literal that reaches [`keyless::cmd::status::row`]
//!   as its `state` argument, in the three shapes this crate writes it: the
//!   sixth positional argument of a `row(…)` call, a `state: "…"` struct field,
//!   and the literal in a `(Mark::Variant, "…", …)` tuple. Test code is excluded,
//!   so a fixture that renders an invented row cannot enlarge the vocabulary.
//! * **Documented.** The table in the rustdoc above `row`, which declares the
//!   list closed and is what `STATE_WIDTH` is sized from.
//!
//! `the_state_vocabulary_is_the_one_the_report_documents` asserts set equality
//! in both directions, which is what makes the derivation self-checking: a word
//! rendered through a fourth shape goes missing from `rendered` and reds, and a
//! word deleted from the code but left in the table reds too. That check earned
//! itself immediately — the table declared eight words while the report rendered
//! ten, `stale` and `behind` having arrived with the BUILD section and never
//! been written down.
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
//! * **Production code.** Only test regions are scanned: all of `tests/`, and
//!   the `#[cfg(test)]` modules in `src/`. A `contains` in the tool itself is
//!   string handling, not an assertion.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Flags whose `contains` is genuinely NOT this defect, and why.
///
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
fn the_state_vocabulary_is_the_one_the_report_documents() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let status = std::fs::read_to_string(root.join("src/cmd/status.rs")).expect("read status.rs");

    let documented = documented_vocabulary(&status);
    assert!(
        documented.len() >= 8,
        "only {} word(s) were read out of the state-word table in \
         src/cmd/status.rs: {documented:?}. The table is the closed vocabulary \
         this gate is built on, so a parse that reads part of it silently \
         narrows every check below.",
        documented.len()
    );

    // The renderer sizes its column to the longest word in that table and says
    // so. Reading the same number back proves this parse found the whole table
    // rather than a prefix of it.
    let width = state_width(&status);
    let longest = documented.iter().map(String::len).max().unwrap_or(0);
    assert_eq!(
        longest, width,
        "the longest documented state word is {longest} character(s) and \
         STATE_WIDTH is {width}. Either the table gained a word wider than the \
         column it is rendered in — which truncates nothing but shifts every \
         detail on that row — or this parse is not reading the whole table.",
    );

    let mut sources = Vec::new();
    collect_rust_sources(&root.join("src"), &mut sources);
    let rendered = rendered_vocabulary(&root, &sources);
    let rendered_words: BTreeSet<String> = rendered.keys().cloned().collect();

    let undocumented: Vec<String> = rendered_words
        .difference(&documented)
        .map(|word| {
            format!(
                "{word} ({})",
                rendered[word]
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .collect();
    assert!(
        undocumented.is_empty(),
        "state word(s) the report renders and the vocabulary does not \
         declare:\n  {}\n\n\
         The table above `row` in src/cmd/status.rs says the list is closed, and \
         a reader deciding what a row means reads that table. Add the word to \
         it — or, as its last line says, replace one of the words already there.",
        undocumented.join("\n  ")
    );

    let unrendered: Vec<&String> = documented.difference(&rendered_words).collect();
    assert!(
        unrendered.is_empty(),
        "state word(s) declared in the table and rendered nowhere: {}\n\n\
         Either the word is gone from the report and the table should lose it, \
         or it is rendered in a shape `rendered_vocabulary` cannot see — and \
         that second one is why this direction is checked at all. A shape this \
         scan misses is a word `no_assertion_reads_a_state_word_as_a_substring` \
         stops guarding, silently.",
        unrendered
            .iter()
            .map(|word| word.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

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
        // This file's own fixtures are deliberately in violation, and its prose
        // quotes the defect verbatim. Scanning it would flag the controls that
        // prove the scanner works.
        if is_this_file(path) {
            continue;
        }
        let text = strip_comments(
            &std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
        );
        let regions = test_regions(path, &text);
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

// ---------------------------------------------------------------------------
// The vocabulary, derived from the code that renders it.
// ---------------------------------------------------------------------------

/// Every word in the state vocabulary, from both derivations at once.
fn vocabulary(root: &Path, sources: &[PathBuf]) -> BTreeSet<String> {
    let status = std::fs::read_to_string(root.join("src/cmd/status.rs")).expect("read status.rs");
    let mut words = documented_vocabulary(&status);
    words.extend(rendered_vocabulary(root, sources).into_keys());
    words
}

/// The state words declared in the rustdoc table above `status::row`.
///
/// Read from the raw source rather than a comment-stripped copy, because the
/// table IS a comment. Rows look like ``/// | `proven` | [`Mark::Proven`] | … |``;
/// the header and the `|---|` separator carry no backticked first cell and fall
/// out on their own.
fn documented_vocabulary(status: &str) -> BTreeSet<String> {
    let mut words = BTreeSet::new();
    for line in status.lines() {
        let Some(rest) = line.trim_start().strip_prefix("///") else {
            continue;
        };
        let rest = rest.trim();
        if !rest.starts_with('|') {
            continue;
        }
        let Some(cell) = rest.trim_matches('|').split('|').next() else {
            continue;
        };
        let cell = cell.trim();
        if let Some(word) = cell.strip_prefix('`').and_then(|c| c.strip_suffix('`'))
            && is_state_word(word)
        {
            words.insert(word.to_owned());
        }
    }
    words
}

/// The width `status::row` pads the state column to.
fn state_width(status: &str) -> usize {
    const KEY: &str = "const STATE_WIDTH: usize = ";
    let at = status
        .find(KEY)
        .unwrap_or_else(|| panic!("STATE_WIDTH is gone from src/cmd/status.rs"));
    status[at + KEY.len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("STATE_WIDTH is a number")
}

/// Every literal that reaches `status::row` as its `state`, and where from.
///
/// Three shapes, because that is how many the crate writes:
///
/// * `row(out, style, mark, subject, width, "unproven", detail)` — the sixth
///   positional argument.
/// * `state: "off"` — the field of a row struct that is destructured into a
///   `row(…)` call.
/// * `(Mark::Broken, "stale", detail, next)` — the tuple a `match` arm yields,
///   whose second element is the state. The `(` immediately before `Mark::` is
///   what tells this shape apart from a `row(…)` call, where the literal after
///   the mark is the SUBJECT rather than the state.
///
/// Test regions are excluded: a fixture rendering an invented row must not
/// enlarge the vocabulary every assertion in the suite is then measured against.
fn rendered_vocabulary(root: &Path, sources: &[PathBuf]) -> BTreeMap<String, BTreeSet<String>> {
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in sources {
        if is_this_file(path) {
            continue;
        }
        let text = strip_comments(
            &std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
        );
        let regions = test_regions(path, &text);
        let where_from = relative(root, path);
        let mut record = |word: String, at: usize| {
            if regions.iter().any(|(a, b)| (*a..*b).contains(&at)) {
                return;
            }
            found.entry(word).or_default().insert(where_from.clone());
        };

        let bytes = text.as_bytes();
        for at in occurrences(&text, "row(") {
            if at > 0 && is_ident_byte(bytes[at - 1]) {
                continue;
            }
            let args = call_args(&text, at + 3);
            if let Some(state) = args.get(5)
                && let Some(word) = as_literal(state)
            {
                record(word, at);
            }
        }
        for at in occurrences(&text, "state:") {
            if at > 0 && is_ident_byte(bytes[at - 1]) {
                continue;
            }
            if let Some(word) = as_literal(text[at + 6..].trim_start()) {
                record(word, at);
            }
        }
        for at in occurrences(&text, "Mark::") {
            // A tuple, not a call: the mark is the first element.
            let before = text[..at].trim_end();
            if !before.ends_with('(') {
                continue;
            }
            let rest = &text[at + 6..];
            let after = rest.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_');
            if let Some(after) = after.trim_start().strip_prefix(',')
                && let Some(word) = as_literal(after.trim_start())
            {
                record(word, at);
            }
        }
    }
    found
}

/// The leading string literal of `expr`, when it is a plausible state word.
fn as_literal(expr: &str) -> Option<String> {
    let rest = expr.trim().strip_prefix('"')?;
    let word = rest.split('"').next()?;
    is_state_word(word).then(|| word.to_owned())
}

/// A word that could be a state: short, lower-case ASCII, one word.
///
/// The filter keeps a detail sentence and a path out of the vocabulary without
/// naming any word in advance.
fn is_state_word(word: &str) -> bool {
    !word.is_empty() && word.len() <= 12 && word.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

// ---------------------------------------------------------------------------
// The scanner.
// ---------------------------------------------------------------------------

/// One `<receiver>.contains("<literal>")` call.
struct ContainsCall {
    /// Byte offset of the receiver's first character.
    from: usize,
    /// Byte offset of the `.` in `.contains(`.
    at: usize,
    /// Byte offset just past the closing `)`.
    end: usize,
    /// The argument, with its quotes removed and its escapes left alone.
    literal: String,
    /// Whether the call sits under a `!`.
    negated: bool,
}

/// Every `.contains("<literal>")` in `text`, which must be comment-stripped.
///
/// The argument has to be a bare literal: `contains(&"HOME")` is a slice
/// membership test that compares whole elements, and `contains(&format!(…))`
/// carries no literal to read.
fn contains_calls(text: &str) -> Vec<ContainsCall> {
    const NEEDLE: &str = ".contains(";
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for at in occurrences(text, NEEDLE) {
        let after = &text[at + NEEDLE.len()..];
        let trimmed = after.trim_start();
        let Some(rest) = trimmed.strip_prefix('"') else {
            continue;
        };
        // No escape handling: a state word has none, and a literal with one is
        // not a bare state word anyway.
        let Some(close) = rest.find('"') else {
            continue;
        };
        let literal = &rest[..close];
        let tail = rest[close + 1..].trim_start();
        if !tail.starts_with(')') {
            continue;
        }
        let end = text.len() - tail.len() + 1;
        let from = receiver_start(bytes, at);
        out.push(ContainsCall {
            from,
            at,
            end,
            literal: literal.to_owned(),
            negated: is_negated(bytes, from),
        });
    }
    out
}

/// The start of the receiver expression whose `.contains(` is at `at`.
///
/// Walks back over identifier characters, field and method separators, and
/// balanced `(…)`/`[…]`, which is what carries `row_for(&report, "keychain")`
/// and `x[0].y()` back to their first character.
fn receiver_start(bytes: &[u8], at: usize) -> usize {
    let mut i = at;
    while i > 0 {
        match bytes[i - 1] {
            b if is_ident_byte(b) => i -= 1,
            b'.' | b'?' | b'&' => i -= 1,
            close @ (b')' | b']') => {
                let open = if close == b')' { b'(' } else { b'[' };
                let mut depth = 0usize;
                let mut j = i - 1;
                loop {
                    if bytes[j] == close {
                        depth += 1;
                    } else if bytes[j] == open {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    if j == 0 {
                        return i;
                    }
                    j -= 1;
                }
                i = j;
            }
            _ => break,
        }
    }
    i
}

/// Whether the expression starting at `from` sits under a `!`.
///
/// The `!` of `assert!(` is the trap: walking out of `assert!(text.contains(…))`
/// reaches a `(` whose `!` belongs to a macro NAME, and reading that as negation
/// would spare every violation in the suite — the failure that leaves this gate
/// green forever. A `!` counts only when what precedes it is not an identifier.
fn is_negated(bytes: &[u8], from: usize) -> bool {
    let mut i = from;
    loop {
        i = skip_space_back(bytes, i);
        if i == 0 {
            return false;
        }
        match bytes[i - 1] {
            b'!' => {
                let before = skip_space_back(bytes, i - 1);
                return before == 0 || !is_ident_byte(bytes[before - 1]);
            }
            b'(' => {
                // Step out of a bare `(…)` group. A `(` that follows a NAME
                // opens a call, and a call's argument is not negated by anything
                // outside it.
                let before = skip_space_back(bytes, i - 1);
                if before > 0 && is_ident_byte(bytes[before - 1]) {
                    return false;
                }
                if before > 0 && bytes[before - 1] == b'!' {
                    // `!(…)` is a negated group; `assert!(…)` is a macro whose
                    // `!` is part of its name. What precedes the `!` is the only
                    // thing that tells them apart.
                    let name = skip_space_back(bytes, before - 1);
                    if name > 0 && is_ident_byte(bytes[name - 1]) {
                        return false;
                    }
                }
                i = before;
            }
            _ => return false,
        }
    }
}

fn skip_space_back(bytes: &[u8], mut i: usize) -> usize {
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    i
}

// ---------------------------------------------------------------------------
// Reading Rust as text.
// ---------------------------------------------------------------------------

/// The regions of `path` that are test code: all of an integration test, and
/// the `#[cfg(test)]` modules of a source file.
fn test_regions(path: &Path, text: &str) -> Vec<(usize, usize)> {
    if path.components().any(|part| part.as_os_str() == "tests") {
        return vec![(0, text.len())];
    }
    let mut out = Vec::new();
    for at in occurrences(text, "#[cfg(test)]") {
        let Some(open) = text[at..].find('{').map(|offset| at + offset) else {
            continue;
        };
        if let Some(close) = balanced(text, open) {
            out.push((open, close));
        }
    }
    out
}

/// `(name, start, end)` for every `fn` in `text`, innermost last.
fn functions(text: &str) -> Vec<(String, usize, usize)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for at in occurrences(text, "fn ") {
        if at > 0 && is_ident_byte(bytes[at - 1]) {
            continue;
        }
        let rest = &text[at + 3..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let Some(open) = rest.find('{').map(|offset| at + 3 + offset) else {
            continue;
        };
        if let Some(close) = balanced(text, open) {
            out.push((name, open, close));
        }
    }
    out
}

/// The name of the innermost function containing `at`.
fn enclosing(functions: &[(String, usize, usize)], at: usize) -> Option<&str> {
    functions
        .iter()
        .filter(|(_, start, end)| (*start..*end).contains(&at))
        .min_by_key(|(_, start, end)| end - start)
        .map(|(name, _, _)| name.as_str())
}

/// The offset of the `}` closing the `{` at `open`.
fn balanced(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    for (offset, byte) in bytes[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// The comma-separated arguments of the call whose `(` is at `open`.
fn call_args(text: &str, open: usize) -> Vec<String> {
    let bytes = text.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut chars = text[open..].chars().peekable();
    while let Some(c) = chars.next() {
        if in_string {
            current.push(c);
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                current.push(c);
            }
            '(' | '[' | '{' => {
                depth += 1;
                if depth > 1 {
                    current.push(c);
                }
            }
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    out.push(current.trim().to_owned());
                    break;
                }
                current.push(c);
            }
            ',' if depth == 1 => {
                out.push(current.trim().to_owned());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    out
}

/// Blank every comment, keeping the file's byte length and its line breaks.
///
/// Byte length is the point: every offset this file computes is an offset into
/// the stripped copy, and a rewrite that changed lengths would misplace them
/// against a multi-byte character. Comments are blanked rather than removed
/// because this crate's prose QUOTES the defect — `contains("proven")` appears
/// in five doc comments — and a scanner that read them would flag the
/// documentation that warns about it.
fn strip_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push(b);
            i += 1;
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let mut depth = 0usize;
            while i < bytes.len() {
                if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                    continue;
                }
                if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                    continue;
                }
                out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                i += 1;
            }
            continue;
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).expect("blanking a comment cannot split a character")
}

/// Every byte offset at which `needle` occurs in `hay`.
fn occurrences(hay: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = hay[from..].find(needle) {
        out.push(from + at);
        from += at + needle.len();
    }
    out
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// One line, trimmed, for a failure message.
fn squeeze(expr: &str) -> String {
    let flat: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.char_indices().nth(90) {
        Some((cut, _)) => format!("{}…", &flat[..cut]),
        None => flat,
    }
}

fn is_this_file(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name == "state_vocabulary.rs")
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
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
