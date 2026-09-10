//! Every function that spawns the Proton Pass vendor binary switches off its
//! telemetry and its update check.
//!
//! # Why a scanner rather than trusting the three call sites
//!
//! `set_vendor_switch_offs` is called from exactly three places today —
//! `ProtonStore::scope`, `ProtonManager::scope` and `daemon::login::scope` —
//! and each of those is called from every builder that constructs a `pass-cli`
//! command. Correct, and unenforced: nothing stops a fifth spawn site being
//! added straight against `Command::new`, past every `scope` function, the way
//! the fix this scanner was written for did — twice, by hand, in
//! `src/store/proton_manager.rs`, before `ProtonManager` had a `scope` of its
//! own.
//!
//! # What this CANNOT see, which is most of the reason to read it
//!
//! * **It finds a function's body by counting braces, not by parsing Rust.**
//!   The count opens at the signature and closes where the depth returns to
//!   zero, so a body written entirely on its signature line ends there rather
//!   than running on into whatever follows it. A brace inside a string literal
//!   counts like any other: every such literal in this crate is balanced, and
//!   an unbalanced one would end a function EARLY, which surfaces as a false
//!   positive rather than as a silent miss.
//! * **Coverage is read from code, never from a comment.** A line's `//`
//!   remainder is cut before the scan, on both halves — the spawn line and
//!   the coverage call — so a `// TODO: route this through scope()` beside an
//!   unswitched spawn does not launder it.
//! * **A file is in the corpus only if it mentions one of four Proton-specific
//!   identifiers** — `SESSION_DIR_VAR`, `KEY_PROVIDER_VAR`,
//!   `DISABLE_TELEMETRY_VAR`, `NO_UPDATE_CHECK_VAR` — never a generic pattern
//!   like `Command::new(&self.binary)`, which every adapter in `src/store/`
//!   spells the same way for its OWN vendor. A file that spawns `pass-cli`
//!   without ever naming one of those four is invisible here; building a
//!   sensible Proton command without any of them is not a realistic case.
//! * **Coverage is a call literally spelled `set_vendor_switch_offs(` or
//!   `scope(` inside the spawning function's own body.** It trusts that a
//!   function named `scope` does what every `scope` in this crate does today;
//!   it does not read `scope`'s own body to confirm it. The same trust
//!   `tests/session_coordinate.rs`'s `RENDERERS` list places in its own
//!   renderers.

use std::path::PathBuf;
use std::process::Command;

/// Function names exempt from carrying the switch-off call directly, each
/// with why. Empty today — every spawn site reaches `set_vendor_switch_offs`
/// through one of the three `scope` functions. Add an entry here, named, with
/// the reason it does not need one, rather than weakening the scan itself.
const EXEMPT: &[(&str, &str)] = &[];

/// Every path the published repository carries, asked of git rather than
/// named — see `tests/session_coordinate.rs`, which this scanner is modelled
/// on: a corpus built from a list of directories silently stops covering the
/// file somebody adds next.
fn published_rust_sources() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("git")
        .arg("-C")
        .arg(&root)
        .arg("ls-files")
        .arg("-z")
        .arg("--")
        .arg("src")
        .output()
        .expect("git ls-files");
    assert!(output.status.success(), "git ls-files failed");
    String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|name| !name.is_empty() && name.ends_with(".rs"))
        .map(|name| root.join(name))
        .collect()
}

/// Whether `text` is plausibly building a Proton Pass command at all.
///
/// Keyed on the four environment-variable identifiers this crate defines for
/// `pass-cli`, rather than on `Command::new(&self.binary)` — every vendor
/// adapter in `src/store/` spawns its own binary through that exact shape, so
/// keying on it would flag Infisical, the macOS keychain helper and 1Password
/// as though they were Proton spawns too.
fn touches_proton(text: &str) -> bool {
    [
        "SESSION_DIR_VAR",
        "KEY_PROVIDER_VAR",
        "DISABLE_TELEMETRY_VAR",
        "NO_UPDATE_CHECK_VAR",
    ]
    .iter()
    .any(|signal| text.contains(signal))
}

/// Whether `line` builds a `Command` against a vendor's own binary field —
/// `&self.binary`, `&coordinates.binary`, or a spelling close enough — and is
/// not merely mentioning the shape in a comment.
fn spawns_the_vendor_binary(line: &str) -> bool {
    if line.trim_start().starts_with("//") {
        return false;
    }
    line.contains("Command::new(&") && line.contains(".binary)")
}

/// The name of the function this line declares, if it declares one.
///
/// A signature line starts, after any `pub`/`pub(crate)`/`async` modifiers,
/// with `fn `. Good enough for this crate's own `rustfmt` output; it does not
/// parse Rust and is not asked to.
fn fn_name(line: &str) -> Option<&str> {
    let mut rest = line.trim_start();
    if let Some(after_pub) = rest.strip_prefix("pub") {
        rest = after_pub.trim_start();
        if let Some(after_paren) = rest.strip_prefix('(') {
            let close = after_paren.find(')')?;
            rest = after_paren[close + 1..].trim_start();
        }
    }
    if let Some(after_async) = rest.strip_prefix("async") {
        rest = after_async.trim_start();
    }
    let rest = rest.strip_prefix("fn ")?.trim_start();
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    let name = &rest[..end];
    (!name.is_empty()).then_some(name)
}

/// `line` with any comment cut off it, so a scan reads code and nothing else.
///
/// A `//` that follows a `:` opens no comment — that is the shape a URL takes
/// inside a string literal, and cutting there would drop the rest of a line
/// this scanner still has to count braces in.
fn code_only(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(found) = line[from..].find("//") {
        let at = from + found;
        if at > 0 && bytes[at - 1] == b':' {
            from = at + 2;
            continue;
        }
        return &line[..at];
    }
    line
}

/// How many braces `line` opens and closes, comments excluded.
///
/// Both counts, never their difference: a body written on its signature line
/// opens and closes in the same line, so a net of zero is what a function that
/// finished looks like AND what a line before any body looks like. Only the
/// opens tell those apart.
fn braces(line: &str) -> (i32, i32) {
    let code = code_only(line);
    let count = |brace| i32::try_from(code.matches(brace).count()).unwrap_or(i32::MAX);
    (count('{'), count('}'))
}

/// Every function in `text`, as (name, 1-based declaration line, its whole
/// source from the `fn` keyword to its own closing brace).
///
/// Bounded by [`braces`], counted from the signature line: the function ends
/// where the depth first returns to zero after opening. A one-line body ends
/// on its own line, rather than leaving the search to walk into the next
/// function and swallow it — a merge that would let the NEXT function's
/// `scope(` call stand in as the one-liner's coverage. A function whose depth
/// never closes runs to the end of `text`, which happens only on a malformed
/// fixture in this file's own tests.
fn functions(text: &str) -> Vec<(&str, usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some(name) = fn_name(lines[i]) else {
            i += 1;
            continue;
        };
        let mut depth = 0;
        let mut opened = false;
        let mut end = lines.len() - 1;
        for (j, line) in lines.iter().enumerate().skip(i) {
            let (opens, closes) = braces(line);
            if opens > 0 {
                opened = true;
            }
            depth += opens - closes;
            if opened && depth <= 0 {
                end = j;
                break;
            }
        }
        found.push((name, i + 1, lines[i..=end].join("\n")));
        i = end + 1;
    }
    found
}

/// Whether `body` — one function's own source — reaches the switch-off call,
/// directly or through a `scope` function. See the module doc for what that
/// trust does not verify.
///
/// Read from code alone: a mention inside a comment is not a call, and taking
/// one for a call is how an unswitched spawn would pass with a `// TODO`
/// beside it.
fn covered(body: &str) -> bool {
    body.lines()
        .map(code_only)
        .any(|code| code.contains("set_vendor_switch_offs(") || code.contains("scope("))
}

/// Every function in `text` that spawns the vendor binary and neither reaches
/// the switch-off call nor is named on [`EXEMPT`].
///
/// Returns `(declaration line, function name)` so a failure says where to
/// look rather than only that something is wrong.
fn unswitched_spawns(text: &str) -> Vec<(usize, String)> {
    functions(text)
        .into_iter()
        .filter(|(_, _, body)| body.lines().any(spawns_the_vendor_binary))
        .filter(|(name, _, body)| {
            !covered(body) && !EXEMPT.iter().any(|(exempt, _)| exempt == name)
        })
        .map(|(name, line, _)| (line, name.to_owned()))
        .collect()
}

#[test]
fn every_spawn_of_the_vendor_binary_switches_off_its_telemetry_and_update_check() {
    let paths = published_rust_sources();
    let mut scanned = 0usize;
    let mut violations = Vec::new();

    for path in &paths {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        if !touches_proton(&text) {
            continue;
        }
        scanned += 1;
        for (line, name) in unswitched_spawns(&text) {
            violations.push(format!(
                "{}:{line}: `{name}` spawns the vendor binary and calls neither \
                 `set_vendor_switch_offs` nor a `scope` that does",
                path.display()
            ));
        }
    }

    // A corpus that quietly emptied would report the same clean result as a
    // corpus with nothing wrong in it.
    assert!(
        scanned > 0,
        "the corpus was empty — nothing under src/ mentions a Proton-specific identifier"
    );
    assert!(
        violations.is_empty(),
        "a `pass-cli` spawn that never switches off telemetry or the update check:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_scanner_catches_a_spawn_with_no_switch_off() {
    // The control. Without it, the test above goes green while saying
    // nothing: a scanner that flags nothing is indistinguishable from one
    // that works.
    let text = "\
impl ProtonStore {
    fn probe_command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command.arg(\"run\");
        command
    }
}
";
    let found = unswitched_spawns(text);
    assert_eq!(
        found
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["probe_command"],
        "the scanner missed a spawn carrying no switch-off: {found:?}"
    );
}

#[test]
fn a_one_line_spawn_is_not_covered_by_the_function_after_it() {
    // The shape that defeated the first version of this scanner: a body
    // written entirely on its signature line has no closing brace of its own
    // to find, so bounding it by "the next line that is just `}`" ran the
    // search into the NEXT function — and that function's legitimate `scope(`
    // call then read as the one-liner's coverage.
    let text = "\
impl ProtonStore {
    fn probe_command(&self) -> Command { Command::new(&self.binary) }

    fn list_command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        self.scope(&mut command);
        command
    }
}
";
    let found = unswitched_spawns(text);
    assert_eq!(
        found
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["probe_command"],
        "the one-line spawn was laundered by its neighbour: {found:?}"
    );
}

#[test]
fn a_comment_is_not_coverage() {
    // A mention is not a call. Without this, an unswitched spawn ships as
    // long as somebody left a note about the call it never makes.
    let text = "\
impl ProtonStore {
    fn probe_command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        // TODO: route this through scope() like the others
        command
    }
}
";
    let found = unswitched_spawns(text);
    assert_eq!(
        found
            .iter()
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>(),
        vec!["probe_command"],
        "a commented-out call read as coverage: {found:?}"
    );
}

#[test]
fn the_scanner_passes_what_it_must_not_flag() {
    // The other half of the control. A gate that flags correct work gets
    // turned off, and then the real violations flow again.
    let cases = [
        // Covered through a `scope` method — the shape every real builder in
        // this crate takes.
        "\
impl ProtonStore {
    fn list_command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        self.scope(&mut command);
        command
    }
}
",
        // Covered directly, the free-function shape `daemon::login` uses.
        "\
fn login_command(coordinates: &Coordinates) -> Command {
    let mut command = Command::new(&coordinates.binary);
    set_vendor_switch_offs(&mut command);
    command
}
",
        // Not the vendor binary at all: a literal program name, never a
        // `.binary` field, so this is not a spawn site in the first place.
        "\
fn run_git() -> Command {
    Command::new(\"git\")
}
",
        // A comment shaped like a spawn site is not one.
        "\
fn documented_only() -> Command {
    // Once looked like: Command::new(&self.binary)
    Command::new(\"git\")
}
",
    ];
    for text in cases {
        let found = unswitched_spawns(text);
        assert!(found.is_empty(), "false positive on: {text} -> {found:?}");
    }
}
