//! The state vocabulary, derived from the code that renders it.
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

mod state_vocabulary_support;

use std::collections::BTreeSet;
use std::path::PathBuf;

use state_vocabulary_support::rust_text::collect_rust_sources;
use state_vocabulary_support::vocabulary::{
    documented_vocabulary, rendered_vocabulary, state_width,
};

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
