use std::path::{Path, PathBuf};

/// The regions of `path` that are test code: the whole of a test file, and
/// the inline `#[cfg(test)]` modules of a source file.
///
/// A test file is anything under the crate's `tests/`, and under `src/` a
/// `tests.rs`, a `*_tests.rs` or anything inside a `tests/` directory — the
/// shapes a `#[cfg(test)] mod tests;` declaration loads from. Those carry no
/// `#[cfg(test)]` of their own, so reading only inline blocks would drop them.
pub fn test_regions(root: &Path, path: &Path, text: &str) -> Vec<(usize, usize)> {
    if is_test_file(path.strip_prefix(root).unwrap_or(path)) {
        return vec![(0, text.len())];
    }
    let mut out = Vec::new();
    for at in occurrences(text, "#[cfg(test)]") {
        let item = &text[at..];
        let Some(open) = item.find('{') else {
            continue;
        };
        if declares_out_of_line_module(item, open) {
            continue;
        }
        if let Some(close) = balanced(text, at + open) {
            out.push((at + open, close));
        }
    }
    out
}

/// `#[cfg(test)] mod tests;` reaches its `;` before any `{`, and the next
/// brace belongs to whatever production item follows it.
fn declares_out_of_line_module(item: &str, first_brace: usize) -> bool {
    item.find(';').is_some_and(|semi| semi < first_brace)
}

fn is_test_file(relative: &Path) -> bool {
    let mut parts = relative.components().map(|part| part.as_os_str());
    if parts.next().is_some_and(|first| first == "tests") {
        return true;
    }
    if relative
        .parent()
        .is_some_and(|dir| dir.components().any(|part| part.as_os_str() == "tests"))
    {
        return true;
    }
    relative
        .file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem == "tests" || stem.ends_with("_tests"))
}

/// `(name, start, end)` for every `fn` in `text`, innermost last.
pub fn functions(text: &str) -> Vec<(String, usize, usize)> {
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
pub fn enclosing(functions: &[(String, usize, usize)], at: usize) -> Option<&str> {
    functions
        .iter()
        .filter(|(_, start, end)| (*start..*end).contains(&at))
        .min_by_key(|(_, start, end)| end - start)
        .map(|(name, _, _)| name.as_str())
}

/// The offset of the `}` closing the `{` at `open`.
pub fn balanced(text: &str, open: usize) -> Option<usize> {
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
pub fn call_args(text: &str, open: usize) -> Vec<String> {
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
pub fn strip_comments(text: &str) -> String {
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
pub fn occurrences(hay: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(at) = hay[from..].find(needle) {
        out.push(from + at);
        from += at + needle.len();
    }
    out
}

pub fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// One line, trimmed, for a failure message.
pub fn squeeze(expr: &str) -> String {
    let flat: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.char_indices().nth(90) {
        Some((cut, _)) => format!("{}…", &flat[..cut]),
        None => flat,
    }
}

/// Whether `path` is one of this gate's own files, whose fixtures are
/// deliberately in violation and whose prose quotes the defect verbatim.
pub fn is_this_gate(root: &Path, path: &Path) -> bool {
    path.strip_prefix(root.join("tests"))
        .ok()
        .and_then(|rest| rest.components().next())
        .and_then(|first| first.as_os_str().to_str())
        .is_some_and(|name| name.starts_with("state_vocabulary"))
}

pub fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
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

pub fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
