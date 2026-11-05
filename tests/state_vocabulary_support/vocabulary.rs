use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::rust_text::{
    call_args, is_ident_byte, is_this_gate, occurrences, relative, strip_comments, test_regions,
};

/// Every word in the state vocabulary, from both derivations at once.
pub fn vocabulary(root: &Path, sources: &[PathBuf]) -> BTreeSet<String> {
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
pub fn documented_vocabulary(status: &str) -> BTreeSet<String> {
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
pub fn state_width(status: &str) -> usize {
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
pub fn rendered_vocabulary(root: &Path, sources: &[PathBuf]) -> BTreeMap<String, BTreeSet<String>> {
    let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for path in sources {
        if is_this_gate(root, path) {
            continue;
        }
        let text = strip_comments(
            &std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display())),
        );
        let regions = test_regions(root, path, &text);
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
pub fn as_literal(expr: &str) -> Option<String> {
    let rest = expr.trim().strip_prefix('"')?;
    let word = rest.split('"').next()?;
    is_state_word(word).then(|| word.to_owned())
}

/// A word that could be a state: short, lower-case ASCII, one word.
///
/// The filter keeps a detail sentence and a path out of the vocabulary without
/// naming any word in advance.
pub fn is_state_word(word: &str) -> bool {
    !word.is_empty() && word.len() <= 12 && word.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}
