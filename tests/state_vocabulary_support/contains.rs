use super::rust_text::{is_ident_byte, occurrences};

/// One `<receiver>.contains("<literal>")` call.
pub struct ContainsCall {
    /// Byte offset of the receiver's first character.
    pub from: usize,
    /// Byte offset of the `.` in `.contains(`.
    pub at: usize,
    /// Byte offset just past the closing `)`.
    pub end: usize,
    /// The argument, with its quotes removed and its escapes left alone.
    pub literal: String,
    /// Whether the call sits under a `!`.
    pub negated: bool,
}

/// Every `.contains("<literal>")` in `text`, which must be comment-stripped.
///
/// The argument has to be a bare literal: `contains(&"HOME")` is a slice
/// membership test that compares whole elements, and `contains(&format!(…))`
/// carries no literal to read.
pub fn contains_calls(text: &str) -> Vec<ContainsCall> {
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
pub fn receiver_start(bytes: &[u8], at: usize) -> usize {
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
pub fn is_negated(bytes: &[u8], from: usize) -> bool {
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

pub fn skip_space_back(bytes: &[u8], mut i: usize) -> usize {
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    i
}
