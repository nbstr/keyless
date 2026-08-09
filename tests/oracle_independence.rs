//! Assertions whose expected value is produced by the code under test.
//!
//! `suite_hygiene.rs` asks whether a fixture's NUMBERS are honest. This file
//! asks the prior question: can the assertion fail at all?
//!
//! # The defect class
//!
//! An assertion is TAUTOLOGICAL when the value it compares against is computed
//! by the same code it is checking. Both sides then move together under any
//! change, the equality holds forever, and the test reads as coverage while
//! measuring nothing.
//!
//! The worked example is `Masker::could_grow_into_a_needle`. A test named
//! `the_carry_point_is_never_beyond_what_is_provably_safe` states its
//! expectation in terms of `could_grow_into_a_needle` itself:
//!
//! ```text
//! let point = masker.carry_point(buf);          // the subject
//! for at in point..buf.len() {
//!     if masker.could_grow_into_a_needle(held) {  // the oracle — same function
//!         assert_eq!(at, point);
//! ```
//!
//! Widen that comparison from `>` to `>=` and BOTH sides move. Measured on this
//! tree, 2026-08-09: the mutation is applied, the test runs, and it passes. The
//! defect it is named for — a complete needle answering "yes" to its own
//! question, so a finished match is withheld from a live terminal indefinitely —
//! is caught by `a_tail_that_is_already_the_whole_secret_is_masked_without_
//! waiting` and by nothing else in the suite.
//!
//! # Why a gate rather than a sweep
//!
//! Three instances of this class surfaced in one day, each found by a different
//! accident: a reversed sort caught by reading code, a mutation caught by a
//! campaign, a collapsed directory walk caught by an unrelated freshness test.
//! Three accidents are not a process. A sweep finds today's; a gate finds the
//! one somebody writes next month.
//!
//! # What this scanner DOES see
//!
//! One shape, precisely: an `assert_eq!` or `assert_ne!` whose two sides BOTH
//! reach the crate under test — directly, or through a local bound from a call
//! that does, or through a helper defined in the same file that does. Taint
//! follows `let` bindings and `for` loop variables, which is what carries
//! `point` into `assert_eq!(at, point)`.
//!
//! # What it CANNOT see, which is most of the reason to read it
//!
//! * **The other two instances of the class.** This is the important admission.
//!   A reversed sort and a collapsed walk are not oracle defects: those tests
//!   had honest, literal expectations and simply never REACHED the branch, or
//!   observed at a point where the defect was invisible. No static rule about
//!   assertion shape can see either. `cargo-mutants` sees all three, because a
//!   surviving mutant means "no test distinguishes this program from that one"
//!   whatever the cause. This gate is a cheap complement to that campaign, never
//!   a replacement — see `.github/workflows/mutants.yml`.
//! * **A tautology spread across more than one assertion**, or one whose oracle
//!   arrives through a struct field, a closure capture or a channel. The taint
//!   pass follows `let` and `for`, and nothing else.
//! * **`assert!(...)` with one argument.** A boolean predicate has no two sides
//!   to compare, so the rule does not apply to it. Real tautologies live there
//!   too and this cannot reach them.
//! * **An expected value that is a CONSTANT imported from the module under
//!   test.** Deliberately out of scope, and measured rather than assumed: the
//!   rule was prototyped over this repository on 2026-08-09 and produced 29
//!   flags, of which roughly three were real — the rest were constants declared
//!   in the test file itself, which a source scan cannot tell apart from crate
//!   constants without resolving every import. A gate that is nine-tenths noise
//!   is a gate somebody deletes, and then the signal goes with it.
//! * **A round trip with no assertion on the intermediate form.** `decode(encode
//!   (x)) == x` has one side literal, so it passes this rule while holding for
//!   the identity function. There is no such pair in this crate today; if one
//!   lands, this scanner will not be what catches it.
//!
//! # One interaction worth knowing about before it surprises somebody
//!
//! This gate READS the source, and `cargo mutants` REWRITES the source. Two of
//! the three files named in `CLASSIFIED` sit inside the campaign's scope
//! (`src/mask/**`), so a mutant that empties a function body can in principle
//! change which helpers this scanner promotes to seeds, drop a flag, and red
//! the stale-row check — which cargo-mutants would then score as that mutant
//! being CAUGHT.
//!
//! It does not happen today and the reason is structural rather than lucky:
//! cargo-mutants leaves `#[cfg(test)]` code alone, so every helper these tests
//! actually reach the crate through is untouched, and the test bodies that
//! carry the taint name crate TYPES (`Masker`, `Secret`) which no mutation can
//! remove. Written down because a spurious kill inflates the caught count in
//! the direction nobody audits, and because the next person to widen this
//! scanner needs to know the constraint exists.
//!
//! # The self-test is not decoration
//!
//! A scanner that stopped matching the spelling the sources use would report
//! zero flags, which reads exactly like a clean suite. So
//! `the_scanner_flags_a_tautology_and_spares_an_independent_oracle` runs it
//! against two fixtures written into this file: one that IS tautological — a
//! reduction of the real `carry_point` defect above — and one that is not.
//! Breaking the scanner reds that test before it can quietly bless anything.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every assertion in this project whose two sides are both computed by the
/// code under test, and the reason each is allowed to stay that way.
///
/// The key is `<path>::<test fn>`. The reason is the entire point of the row:
/// a bare list of exemptions is a list of tests nobody has to justify.
///
/// This is checked in BOTH directions. A flag with no row is a tautology
/// somebody introduced. A row that flags nothing is a row somebody fixed and
/// left behind, and it reds too — otherwise the table slowly becomes a list of
/// claims about code that no longer exists.
///
/// **What may NOT be recorded here:** "the fix belongs to somebody else", or
/// "this is fine because it is only a test". The only admissible reason is that
/// the assertion's shape is genuinely not a tautology, or that the invariant it
/// names is pinned elsewhere BY NAME. A row that names no other guard is a hole
/// wearing a justification.
const CLASSIFIED: &[(&str, &str)] = &[
    (
        "src/mask/encodings.rs::every_encoding_has_a_distinct_label",
        "NOT A TAUTOLOGY. `count` is the label count BEFORE `dedup` and \
         `labels.len()` is the count after it. Both derive from `ALL`, but the \
         relation between them is `dedup`'s, not `ALL`'s: two encodings sharing \
         a label makes the second number smaller whatever `ALL` contains. There \
         is no literal that could replace either side without hard-coding the \
         number of encodings, which is the drift `masking.rs`'s table already \
         guards.",
    ),
    (
        "src/mask/mod.rs::the_carry_point_is_never_beyond_what_is_provably_safe",
        "TAUTOLOGY, PINNED ELSEWHERE. It asserts `carry_point`'s result using \
         `could_grow_into_a_needle`, the function `carry_point` is built from, \
         so a mutation inside it moves both sides. Proven on 2026-08-09: `>` \
         widened to `>=`, this test passes. The invariant it is named for is \
         held by `mask::tests::a_tail_that_is_already_the_whole_secret_is_ \
         masked_without_waiting`, which observes MID-STREAM and goes red on the \
         same mutation. This row records a test that costs nothing and proves \
         nothing; deleting it belongs to whoever owns `src/mask/mod.rs`.",
    ),
    (
        "src/random.rs::two_generated_values_differ",
        "RELATION WITH NO ANCHOR, AND THAT IS ITS CEILING. Two outputs of one \
         generator are compared to each other, so it can only ever catch a \
         generator that repeats — a constant, an uninitialised buffer. A \
         counter, or any low-entropy source that still varies, passes. That is \
         the whole claim the test makes and its comment says so. Randomness \
         quality is not testable this way and no literal would help.",
    ),
];

/// Directories scanned, relative to the crate root.
const SCANNED: &[&str] = &["src", "tests"];

/// Below this, the directory walk has collapsed rather than found a clean tree.
///
/// Set well under the count measured on 2026-08-09 — 59 files — so it catches a
/// walk that reads nothing rather than a tree that lost a file. Re-measure
/// rather than quoting that number: `find src tests -name '*.rs' | wc -l`.
const MIN_FILES: usize = 30;

/// The share of `#[test]` attributes the block parser has to actually turn into
/// bodies.
///
/// An absolute floor cannot do this job. The measured count is 546 blocks from
/// 567 attributes, so a floor low enough to survive normal churn — 200, as this
/// first stood — leaves a parser free to degrade by two thirds and still pass.
/// A parser that silently stops matching most of the suite flags nothing, and
/// flagging nothing is this gate's success condition. So the check is a RATIO
/// against the same files' raw attribute count, which moves with the suite and
/// cannot be satisfied by a scanner that has quietly gone blind.
///
/// The gap between the two counts is real and allowed for: an attribute inside
/// a `//!` example, or one the parser reaches differently from a plain string
/// count, is not a defect. Two thirds of the suite going missing is.
const MIN_PARSED_SHARE: (usize, usize) = (9, 10);

#[test]
fn no_assertion_takes_its_expected_value_from_the_code_under_test() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    for dir in SCANNED {
        collect_rust_sources(&root.join(dir), &mut sources);
    }
    sources.sort();

    assert!(
        sources.len() >= MIN_FILES,
        "only {} source file(s) were found under {SCANNED:?} in {}. The suite \
         has more than that, so the walk collapsed — and a walk that reads \
         nothing flags nothing, which is indistinguishable from a clean suite.",
        sources.len(),
        root.display()
    );

    let mut seen_tests = 0usize;
    let mut declared_tests = 0usize;
    let mut flagged: BTreeSet<String> = BTreeSet::new();
    for path in &sources {
        // This file's own fixtures are deliberately tautological. Scanning them
        // would flag the controls that prove the scanner works.
        if path
            .file_name()
            .is_some_and(|name| name == "oracle_independence.rs")
        {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let key_prefix = relative(&root, path);
        declared_tests += text.matches("#[test]").count();
        let seeds = crate_seeds(&text);
        for (name, body) in test_blocks(&text) {
            seen_tests += 1;
            if !tautological_assertions(&body, &seeds).is_empty() {
                flagged.insert(format!("{key_prefix}::{name}"));
            }
        }
    }

    let (numerator, denominator) = MIN_PARSED_SHARE;
    assert!(
        declared_tests > 0 && seen_tests * denominator >= declared_tests * numerator,
        "the block parser turned {seen_tests} of {declared_tests} `#[test]` \
         attribute(s) into bodies across {} file(s), which is under {numerator}/\
         {denominator}. It has stopped matching the spelling the sources use, so \
         most of the suite is no longer being read — and a scanner that reads \
         nothing flags nothing, which is exactly what this gate passing looks \
         like.",
        sources.len()
    );

    let known: BTreeSet<&str> = CLASSIFIED.iter().map(|(key, _)| *key).collect();

    let unclassified: Vec<&String> = flagged
        .iter()
        .filter(|key| !known.contains(key.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "assertion(s) whose expected value is computed by the code under test:\n  {}\n\n\
         Both sides move together under a change to that code, so the equality \
         holds whatever the code does.\n\n\
         THE FIX IS ALMOST ALWAYS TO WRITE THE LITERAL. A value spelled out in \
         the test cannot be edited by editing the implementation. Where a \
         literal is genuinely impossible, assert a CONSEQUENCE the defect would \
         change — and if the defect is mid-stream, observe mid-stream, because \
         a test that only looks at the final bytes cannot see a delay, a \
         re-order that self-corrects, or a residue that is later overwritten.\n\n\
         If it is not a tautology, add a row to CLASSIFIED in \
         tests/oracle_independence.rs saying why.",
        unclassified
            .iter()
            .map(|key| key.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    let stale: Vec<&str> = known
        .iter()
        .copied()
        .filter(|key| !flagged.contains(*key))
        .collect();
    assert!(
        stale.is_empty(),
        "CLASSIFIED row(s) that no longer flag anything:\n  {}\n\n\
         Either the test was fixed and its row belongs deleted, or it was \
         renamed, or the scanner stopped seeing it. The third is the one that \
         matters and it is why this direction is checked at all.",
        stale.join("\n  ")
    );
}

/// A tautology the scanner MUST flag: a reduction of the real `carry_point`
/// defect, with the oracle reached through a `for` loop variable.
const TAUTOLOGICAL_FIXTURE: &str = r#"
use keyless::mask::Masker;

fn masker_for(value: &str) -> Masker { Masker::from_secrets([("D", value)]) }

#[test]
fn the_carry_point_is_never_beyond_what_is_provably_safe() {
    let masker = masker_for("decoy");
    let buf = b"prefix";
    let point = masker.carry_point(buf);
    for at in point..buf.len() {
        if masker.could_grow_into_a_needle(&buf[at..]) {
            assert_eq!(at, point, "the carry started later than it had to");
        }
    }
}
"#;

/// An honest test the scanner must NOT flag: the expectation is a literal, and
/// a constant path into the crate is a fixed value rather than a computed one.
const INDEPENDENT_FIXTURE: &str = r#"
use keyless::mask::{Masker, encodings::Encoding};
use keyless::secret::Secret;

fn masker_for(value: &str) -> Masker { Masker::from_secrets([("D", value)]) }

#[test]
fn a_credential_embedded_in_a_url_is_caught() {
    let masker = masker_for("s3cr3t");
    let masked = masker.mask_str("postgres://app:s3cr3t@db");
    assert_eq!(masked, "postgres://app:[keyless:D]@db");
    assert_eq!(Encoding::Base64Std.encode("ab"), "YWI=");
    assert_eq!(masked.len(), super::EXPECTED_LEN);

    // A local whose name is also a module segment on the expected side. This
    // line is the regression: `secret` matched inside `crate::secret::…` and
    // turned a comparison against a unit enum variant — a constant — into a
    // flag. Neither fixture caught it; the real tree did.
    let secret = Secret::new("x".to_owned());
    let state = crate::secret::scrub_probe::released_state(&secret);
    assert_eq!(state, crate::secret::scrub_probe::Released::Scrubbed);
}
"#;

#[test]
fn the_scanner_flags_a_tautology_and_spares_an_independent_oracle() {
    // A control in both directions. Without the negative one, a scanner that
    // flagged EVERYTHING would pass the positive case and look correct; without
    // the positive one, a scanner that matched nothing would pass the negative
    // case and look correct. Each alone is satisfied by a broken scanner.
    let seeds = crate_seeds(TAUTOLOGICAL_FIXTURE);
    let blocks = test_blocks(TAUTOLOGICAL_FIXTURE);
    assert_eq!(blocks.len(), 1, "the fixture holds exactly one #[test]");
    let hits = tautological_assertions(&blocks[0].1, &seeds);
    assert_eq!(
        hits.len(),
        1,
        "the scanner missed the known tautology — it is now blessing whatever it \
         reads. Flags found: {hits:?}"
    );

    let seeds = crate_seeds(INDEPENDENT_FIXTURE);
    let blocks = test_blocks(INDEPENDENT_FIXTURE);
    assert_eq!(blocks.len(), 1, "the fixture holds exactly one #[test]");
    let hits = tautological_assertions(&blocks[0].1, &seeds);
    assert!(
        hits.is_empty(),
        "the scanner flagged an assertion whose expected value is a literal. A \
         gate that reds on correct work gets deleted, and then the real flags go \
         with it. Flags found: {hits:?}"
    );
}

// ---------------------------------------------------------------------------
// The scanner.
// ---------------------------------------------------------------------------

/// Every `assert_eq!` / `assert_ne!` in `body` whose two sides both reach the
/// crate, rendered as `left | right` for the failure message.
fn tautological_assertions(body: &str, seeds: &BTreeSet<String>) -> Vec<String> {
    let taint = tainted_locals(body, seeds);
    let mut out = Vec::new();
    for macro_name in ["assert_eq", "assert_ne"] {
        for args in macro_calls(body, macro_name) {
            let parts = split_top_level(&args);
            if parts.len() < 2 {
                continue;
            }
            if reaches_crate(&parts[0], seeds, &taint) && reaches_crate(&parts[1], seeds, &taint) {
                out.push(format!("{} | {}", squeeze(&parts[0]), squeeze(&parts[1])));
            }
        }
    }
    out
}

/// Names through which this file reaches the crate under test.
///
/// Seeded from `use` statements naming `keyless::`, `crate::` or `super::`,
/// then grown by a fixpoint over the file's own helper functions: a helper
/// whose body reaches the crate is itself a way of reaching the crate, which is
/// what carries `masker_for(...)` into the taint set.
///
/// Deriving the seeds from the imports rather than from a hard-coded list of
/// type names is what keeps this from rotting: a new type reaches the scanner
/// the moment a test imports it.
fn crate_seeds(text: &str) -> BTreeSet<String> {
    let stripped = strip_literals(text);
    let mut seeds: BTreeSet<String> = ["keyless", "crate", "super"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    for line in stripped.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("use ") else {
            continue;
        };
        if !(rest.starts_with("keyless::")
            || rest.starts_with("crate::")
            || rest.starts_with("super::"))
        {
            continue;
        }
        for word in rest.split(|c: char| !c.is_alphanumeric() && c != '_') {
            // A path segment is lowercase and a module; an imported ITEM starts
            // uppercase or is SCREAMING_CASE. Taking only those keeps `mask` and
            // `encodings` out of the seed set, where they would match far too
            // much.
            if word.len() >= 2 && word.starts_with(|c: char| c.is_ascii_uppercase()) {
                seeds.insert(word.to_owned());
            }
        }
    }

    // Fixpoint over helper functions. Two passes is enough for the depth this
    // crate's tests actually use; a third changes nothing here and the loop is
    // cheap enough to run anyway.
    for _ in 0..3 {
        let mut added = false;
        for (name, body) in free_functions(&stripped) {
            if seeds.contains(&name) || !may_become_a_seed(&name) {
                continue;
            }
            if reaches_crate(&body, &seeds, &BTreeSet::new()) {
                seeds.insert(name);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    seeds
}

/// Whether a function found in the file may be promoted to a seed.
///
/// The parser below finds every `fn`, inherent methods included, and a seed is
/// matched wherever its name is CALLED. So promoting an ubiquitous method name
/// poisons everything: make `new` a seed and `Vec::new()` reaches the crate, at
/// which point every local in the suite is tainted and every assertion is
/// flagged. That failure is silent in the direction that matters — it produces
/// more flags, not fewer, so it would be caught by a reviewer rather than
/// blessed. It is refused here anyway, because a gate that reds on correct work
/// gets deleted.
///
/// The rule is deliberately crude: short names and a handful of std spellings.
/// Every helper this suite actually uses — `masker_for`, `through_stream`,
/// `seen_so_far`, `encoding_named`, `pump_script` — clears it comfortably.
fn may_become_a_seed(name: &str) -> bool {
    const UBIQUITOUS: &[&str] = &[
        "new", "from", "into", "len", "get", "push", "next", "read", "write", "clone", "default",
        "drop", "fmt", "eq", "hash", "iter", "parse", "value", "build", "with", "run", "start",
        "stop", "add", "take", "find", "count", "first", "last", "collect", "map", "filter",
    ];
    name.len() >= 5 && !UBIQUITOUS.contains(&name)
}

/// Whether `expr` computes something with the code under test.
///
/// A CALL through a seed counts. A bare constant path does not: `super::
/// MIN_NEEDLE_LEN` and `Released::Scrubbed` are fixed values, and comparing a
/// computed thing against a fixed one is exactly what a test is supposed to do.
fn reaches_crate(expr: &str, seeds: &BTreeSet<String>, taint: &BTreeSet<String>) -> bool {
    let expr = strip_literals(expr);
    if taint.iter().any(|local| mentions_local(&expr, local)) {
        return true;
    }
    seeds.iter().any(|seed| is_crate_call(&expr, seed))
}

/// `name` used as a VALUE in `expr` — a local, never a path segment.
///
/// The `::` exclusion is not tidiness. Without it a local named `secret`
/// matched inside `crate::secret::scrub_probe::Released::Scrubbed`, and
/// `a_needle_buffer_reaches_the_allocator_scrubbed` was reported as comparing
/// two computed values when its expected side is a unit enum variant — a
/// constant. That false positive survived both fixtures in this file and was
/// found only by running the scanner over the real tree, which is the argument
/// for a gate that reads the sources rather than a rule that reads well.
fn mentions_local(expr: &str, name: &str) -> bool {
    let bytes = expr.as_bytes();
    let mut from = 0usize;
    while let Some(at) = expr[from..].find(name) {
        let start = from + at;
        let end = start + name.len();
        from = end;
        if start > 0 && is_ident_byte(bytes[start - 1]) {
            continue;
        }
        if end < bytes.len() && is_ident_byte(bytes[end]) {
            continue;
        }
        // A segment of a path is a name in the source code, not a value the
        // test computed.
        if start > 0 && bytes[start - 1] == b':' {
            continue;
        }
        if end < bytes.len() && bytes[end] == b':' {
            continue;
        }
        return true;
    }
    false
}

/// `name` appearing in `hay` at a word boundary and being CALLED through.
///
/// A bare path is not a call, and that distinction is the rule: `super::
/// MIN_NEEDLE_LEN` and `Released::Scrubbed` are fixed values, and comparing
/// something computed against something fixed is what a test is FOR.
fn is_crate_call(hay: &str, name: &str) -> bool {
    let bytes = hay.as_bytes();
    let mut from = 0usize;
    while let Some(at) = hay[from..].find(name) {
        let start = from + at;
        let end = start + name.len();
        from = end;
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if !before_ok || !after_ok {
            continue;
        }
        // Walk forward over `::seg`, `.field` and whitespace; a `(` before
        // anything else means this name is being CALLED through.
        let mut k = end;
        while k < bytes.len() {
            let c = bytes[k] as char;
            if c == '(' {
                return true;
            }
            if is_ident_byte(bytes[k]) || c == ':' || c == '.' || c.is_whitespace() {
                k += 1;
                continue;
            }
            break;
        }
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Locals that hold something computed by the crate.
///
/// Follows `let NAME = <init>;` and `for NAME in <iter> {`. The loop form is
/// not an extra: `assert_eq!(at, point)` in the real defect compares a loop
/// variable ranging over `point..` against `point`, and without it that
/// assertion has one untainted side and is never flagged.
fn tainted_locals(body: &str, seeds: &BTreeSet<String>) -> BTreeSet<String> {
    let body = strip_literals(body);
    let mut taint: BTreeSet<String> = BTreeSet::new();
    for _ in 0..4 {
        let before = taint.len();
        for (name, init) in bindings(&body) {
            if taint.contains(&name) {
                continue;
            }
            if reaches_crate(&init, seeds, &taint) {
                taint.insert(name);
            }
        }
        if taint.len() == before {
            break;
        }
    }
    taint
}

/// `(name, initialiser)` for every `let` binding and `for` loop variable.
fn bindings(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (keyword, terminator) in [("let ", ';'), ("for ", '{')] {
        let mut from = 0usize;
        while let Some(at) = body[from..].find(keyword) {
            let start = from + at;
            from = start + keyword.len();
            if start > 0 && is_ident_byte(body.as_bytes()[start - 1]) {
                continue;
            }
            let rest = &body[start + keyword.len()..];
            let rest = rest
                .trim_start()
                .strip_prefix("mut ")
                .unwrap_or(rest.trim_start());
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            let after = &rest[name.len()..];
            let Some(end) = after.find(terminator) else {
                continue;
            };
            let init = if keyword == "let " {
                match after[..end].find('=') {
                    // A `let` with no `=` is a declaration; nothing flows in.
                    None => continue,
                    Some(eq) => &after[eq + 1..end],
                }
            } else {
                match after[..end].find(" in ") {
                    None => continue,
                    Some(inx) => &after[inx + 4..end],
                }
            };
            out.push((name, init.to_owned()));
        }
    }
    out
}

/// `(name, body)` for every `#[test]` function.
fn test_blocks(text: &str) -> Vec<(String, String)> {
    blocks_after(text, "#[test]")
}

/// `(name, body)` for every `fn` in the file, test or not.
fn free_functions(text: &str) -> Vec<(String, String)> {
    blocks_after(text, "fn ")
}

fn blocks_after(text: &str, marker: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = text[from..].find(marker) {
        let start = from + at;
        from = start + marker.len();
        let after = &text[start..];
        let Some(fn_at) = after.find("fn ") else {
            continue;
        };
        let rest = &after[fn_at + 3..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let Some(open) = rest.find('{') else { continue };
        let body_start = start + fn_at + 3 + open;
        let Some(body) = balanced(text, body_start) else {
            continue;
        };
        out.push((name, body));
    }
    out
}

/// The brace-balanced block starting at `open`, which must be a `{`.
fn balanced(text: &str, open: usize) -> Option<String> {
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
                    return Some(text[open..=open + offset].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// The argument text of every `name!( … )` in `body`.
fn macro_calls(body: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = format!("{name}!");
    let mut from = 0usize;
    while let Some(at) = body[from..].find(&needle) {
        let start = from + at;
        from = start + needle.len();
        if start > 0 && is_ident_byte(body.as_bytes()[start - 1]) {
            continue;
        }
        let after = &body[start + needle.len()..];
        let Some(open) = after.find('(') else {
            continue;
        };
        if !after[..open].trim().is_empty() {
            continue;
        }
        let bytes = after.as_bytes();
        let mut depth = 0usize;
        for (offset, byte) in bytes[open..].iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(after[open + 1..open + offset].to_owned());
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Split a macro argument list on its top-level commas.
fn split_top_level(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut chars = args.chars().peekable();
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
                current.push(c);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => {
                out.push(current.trim().to_owned());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_owned());
    }
    out.retain(|part| !part.is_empty());
    out
}

/// Blank the contents of string literals, keeping their quotes and their
/// length.
///
/// Without this, a local named `line` matches inside the prose of an assertion
/// message — measured, and it turned four honest assertions into flags on the
/// first prototype run.
fn strip_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if in_string {
            if c == '\\' {
                out.push(' ');
                if chars.next().is_some() {
                    out.push(' ');
                }
            } else if c == '"' {
                in_string = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else if c == '"' {
            in_string = true;
            out.push('"');
        } else {
            out.push(c);
        }
    }
    out
}

/// One line, trimmed, for a failure message.
fn squeeze(expr: &str) -> String {
    let flat: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.len() > 70 {
        format!("{}…", &flat[..70])
    } else {
        flat
    }
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
