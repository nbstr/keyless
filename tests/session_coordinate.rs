//! No published file may write a `pass-cli` command line without its session.
//!
//! # The incident, twice, on two machines
//!
//! `pass-cli` keeps one logged-in identity per **session directory**, and the
//! directory travels in `PROTON_PASS_SESSION_DIR` and in nothing else. There is
//! no `--session-dir` flag — `pass-cli --session-dir <dir> login` answers
//! `unexpected argument`, which reads as a version problem. Moving `HOME`
//! instead moves the macOS keychain out from under the vendor and dies at
//! `-25307`, which reads as a broken keychain. And a bare `pass-cli login` logs
//! into the DEFAULT session, where a machine that has ever had a full-account
//! login answers `Already authenticated` — which reads as nothing being wrong at
//! all.
//!
//! So every wrong spelling has a plausible explanation that is not the real one,
//! and the operator who finds the right one finds it by exhausting the others.
//! That happened twice, on two machines, for hours each time, and BOTH times it
//! started the same way: somebody read a `pass-cli` command line that had been
//! WRITTEN DOWN without the variable, and typed it.
//!
//! # Why a scanner rather than a wrapper verb
//!
//! A `keyless` verb that runs `pass-cli` for you closes the command lines that
//! go through `keyless`. It does not reach the ones that go through a person's
//! own shell, which is every one of the observed failures — and the general form
//! of such a verb (`keyless proton -- <any args>`) would put `pass-cli item view
//! --field password` one hop from a prompt, which is a `get` verb with extra
//! steps. See the report in `src/store/proton.rs`.
//!
//! What can be closed mechanically is the **writing down**. Every command line
//! this repository publishes is scanned here, and one that names a session-scoped
//! verb without naming the variable fails the suite.
//!
//! # What this CANNOT see, which is most of the reason to read it
//!
//! * **It checks that the coordinate is NAMED next to the command, not that the
//!   command is correct.** A paragraph that mentions `PROTON_PASS_SESSION_DIR`
//!   in an unrelated sentence passes with a wrong command line beside it. The
//!   thing that makes the command itself right is that
//!   [`keyless::store::proton::scoped_command`] is the only place the prefix is
//!   assembled; this scan is what stops a second place appearing.
//! * **A verb the vendor adds later is invisible.** The trigger is an allowlist
//!   ([`keyless::store::proton::SESSION_SCOPED_VERBS`]), because the alternative
//!   — treating any word after `pass-cli` as a verb — flags ordinary prose such
//!   as "`pass-cli` parses with clap", and a gate that cries wolf gets deleted.
//!   The vendor's own `agent instructions` names a verb (`test`) that `pass-cli`
//!   2.2.5 does not have, so the vendor's list is not a substitute either.
//! * **Prose is deliberately exempt in Markdown and in comments.** "a bare
//!   `pass-cli login` logs into the default session" is a WARNING about the
//!   wrong spelling and must stay sayable. Only a copyable command line is
//!   flagged: a `$ ` line or a bare command in Markdown, and a string literal in
//!   source. Nobody types a sentence out of a paragraph.
//! * **Anything outside this repository.** The vendor's `pass-cli agent
//!   instructions` — which is what an agent is told to memorise — tells its
//!   reader to `export PROTON_PASS_SESSION_DIR` and then, on any authentication
//!   error, to run `pass-cli logout --force`. In a shell where the export did
//!   not happen, that second instruction logs out the human's own account
//!   session. No gate here can reach that text.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

use keyless::store::proton::SESSION_SCOPED_VERBS;

/// The variable that decides which identity a `pass-cli` command runs as.
const COORDINATE: &str = "PROTON_PASS_SESSION_DIR";

/// Spellings that RENDER the coordinate rather than spelling it out.
///
/// A call to one of these is as good as the variable itself, and better: the
/// function cannot produce a command line without it. Naming them here is what
/// keeps `interrupted_write_detail` — whose remedy is `{}` filled by
/// [`keyless::store::proton::login_into`] — from being reported as a bare
/// command line.
const RENDERERS: &[&str] = &[
    "scoped_command",
    "scoped_command_template",
    "login_into",
    "login_with_token",
    "SESSION_DIR_VAR",
];

/// Where `keyless` SPEAKS TO ITS OPERATOR, which is the corpus and not the repo.
///
/// The first run of this scan read every published file and found 30 hits, of
/// which two were real. The other 28 say something worth writing down: a
/// `pass-cli` command line appears in this repository in four different roles,
/// and only one of them is advice.
///
/// | where | role | prescribing a session directory would be |
/// |---|---|---|
/// | `src/**`, `README.md` | what `keyless` tells its operator to run | correct — this is the corpus |
/// | `tests/**` | an INPUT to a fixture, or an assertion about one | meaningless |
/// | `hooks/**` | the guard's remedy table, covering every vendor CLI alike | **wrong** — see below |
/// | `site/**` | the command `keyless` exists to refuse, shown as such | wrong |
///
/// The `hooks` row is the one that decides the shape. That table answers "which
/// VERB prints a value, and which one does not" for `infisical`, `op`,
/// `pass-cli`, `pass`, `vault` and more; its `pass-cli run -- <cmd>` remedy is
/// about the operator's OWN `pass-cli`, against whatever session they keep.
/// Attaching `keyless`'s session directory to it would send somebody's personal
/// command into an agent's vault-scoped identity. A gate that demands a wrong
/// edit is worse than no gate.
///
/// **So the hole is named rather than covered: an advice string added outside
/// `src/` is not seen here.** Within the corpus, `git ls-files` answers for the
/// file list, so a new file under `src/` is scanned by default.
fn in_corpus(path: &std::path::Path) -> bool {
    let text = path.to_string_lossy();
    // This file is the grammar. Its own examples are the thing being described,
    // and quoting a bare command line here is how the failure is documented.
    if path
        .file_name()
        .is_some_and(|name| name == "session_coordinate.rs")
    {
        return false;
    }
    text.contains("/src/") || text.ends_with("README.md")
}

/// Every path the published repository carries, asked of git rather than named.
///
/// A corpus built from a list of directories is a corpus that silently stops
/// covering the file somebody adds next. `git ls-files` answers with what is
/// actually published, so a new file is scanned by default.
fn published_paths() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("git")
        .arg("-C")
        .arg(&root)
        .arg("ls-files")
        .arg("-z")
        .output()
        .expect("git ls-files");
    assert!(output.status.success(), "git ls-files failed");
    String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|name| !name.is_empty())
        .map(|name| root.join(name))
        .collect()
}

/// A maximal run of consecutive non-blank lines, and where it starts.
///
/// This is the unit a human reads as one instruction. In Rust it is a multi-line
/// string literal together with the code that fills it in; in Markdown it is a
/// paragraph or a fenced block. A blank line is where one instruction stops
/// vouching for the next.
fn paragraphs(text: &str) -> Vec<(usize, Vec<&str>)> {
    let mut found: Vec<(usize, Vec<&str>)> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut started = 0;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                found.push((started, std::mem::take(&mut current)));
            }
            continue;
        }
        if current.is_empty() {
            started = index + 1;
        }
        current.push(line);
    }
    if !current.is_empty() {
        found.push((started, current));
    }
    found
}

/// Whether a line is prose rather than something a reader would copy.
///
/// Markdown is prose unless the line is plainly a command: a `$ ` prompt, or a
/// line that begins with the program's own name inside a fence or an indented
/// block. Everything else — Rust, Python, shell — is prose only when the line is
/// a comment, because everything that is not a comment there is a string literal
/// somebody's terminal will show them.
fn is_prose(line: &str, markdown: bool) -> bool {
    let trimmed = line.trim_start();
    if markdown {
        return !(trimmed.starts_with("$ ") || trimmed.starts_with("pass-cli "));
    }
    trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*')
}

/// The session-scoped verb this line invokes, if it invokes one.
///
/// `pass-cli` followed by whitespace and then a word from the allowlist. That
/// shape is what excludes `pass-cli.argv` (a fixture filename), `pass-cli 2.2.5`
/// (a version) and "`pass-cli` parses with clap" (prose about the parser).
fn scoped_verb(line: &str) -> Option<&'static str> {
    let mut rest = line;
    while let Some(at) = rest.find("pass-cli") {
        let after = &rest[at + "pass-cli".len()..];
        let word = after
            .trim_start_matches([' ', '\t'])
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .next()
            .unwrap_or_default();
        if after.starts_with([' ', '\t'])
            && let Some(verb) = SESSION_SCOPED_VERBS.iter().find(|known| **known == word)
        {
            return Some(verb);
        }
        rest = after;
    }
    None
}

/// Every command line in `text` whose paragraph never names the coordinate.
///
/// Returns `(line number, the verb, the line)` so a failure says where to look
/// rather than only that something is wrong.
fn unscoped_command_lines(text: &str, markdown: bool) -> Vec<(usize, &'static str, String)> {
    let mut found = Vec::new();
    for (start, lines) in paragraphs(text) {
        // A RENDERER only vouches for a paragraph from a line of CODE. A comment
        // that merely mentions one is prose, and prose vouches for nothing: a
        // mutation that reverted an advice string to its bare form survived this
        // scan, because the explanatory comment left above it still named
        // `scoped_command_template`. The comment was true and the string beneath
        // it was wrong, which is the exact pairing this gate exists to notice.
        //
        // The variable itself is accepted from anywhere, including prose. Writing
        // `PROTON_PASS_SESSION_DIR` next to a command is the whole instruction —
        // there is nothing left to get wrong once it is on the page.
        let scoped = lines.iter().any(|line| {
            line.contains(COORDINATE)
                || (!is_prose(line, markdown)
                    && RENDERERS.iter().any(|render| line.contains(render)))
        });
        if scoped {
            continue;
        }
        for (offset, line) in lines.iter().enumerate() {
            if is_prose(line, markdown) {
                continue;
            }
            if let Some(verb) = scoped_verb(line) {
                found.push((start + offset, verb, (*line).trim().to_owned()));
            }
        }
    }
    found
}

/// The corpus is what git publishes, minus what cannot be read as text.
fn readable(path: &PathBuf) -> Option<(String, bool)> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let markdown = path.extension().is_some_and(|kind| kind == "md");
    Some((text, markdown))
}

#[test]
fn no_published_file_writes_a_pass_cli_command_without_its_session() {
    let paths = published_paths();
    let mut scanned = BTreeSet::new();
    let mut violations = Vec::new();

    for path in &paths {
        if !in_corpus(path) {
            continue;
        }
        let Some((text, markdown)) = readable(path) else {
            continue;
        };
        scanned.insert(path.clone());
        for (line, verb, content) in unscoped_command_lines(&text, markdown) {
            violations.push(format!(
                "{}:{line}: `pass-cli {verb}` with no {COORDINATE} in its paragraph\n    {content}",
                path.display()
            ));
        }
    }

    // A corpus that quietly emptied would report the same clean result as a
    // corpus with nothing wrong in it.
    assert!(
        scanned.iter().any(|path| path.ends_with("README.md")),
        "the corpus did not include README.md — it holds {} files",
        scanned.len()
    );
    assert!(
        scanned
            .iter()
            .any(|path| path.ends_with("src/store/proton.rs")),
        "the corpus did not include the Proton adapter"
    );

    assert!(
        violations.is_empty(),
        "a command line nobody can follow — the directory travels in {COORDINATE}, \
         there is no --session-dir flag, and a bare `pass-cli` verb answers about the \
         DEFAULT session:\n{}",
        violations.join("\n")
    );
}

#[test]
fn the_scanner_catches_every_spelling_the_incident_produced() {
    // The control. Each of these is a real string that reached an operator, or
    // the shape of one; if the grammar stops seeing them the test above goes
    // green while saying nothing.
    let cases: &[(&str, bool, &str)] = &[
        (
            "`pass-cli login` into a session directory, then set\n`stores.proton.session_dir` to it",
            false,
            "login",
        ),
        (
            "Proton needs `pass-cli login` into a session directory that does not copy",
            false,
            "login",
        ),
        (
            "put a SECOND agent token there: `pass-cli agent create <name> --expiration 3m`",
            false,
            "agent",
        ),
        (
            "$ pass-cli agent create keyless-manager --vault personal",
            true,
            "agent",
        ),
        ("    pass-cli logout --force", true, "logout"),
        // The one that got away, found by mutation and not by reading. A comment
        // above the string named the renderer, and the paragraph was counted as
        // scoped on the strength of prose describing what the code below it no
        // longer did.
        (
            "// See `crate::store::proton::scoped_command_template`.\n\
             _ => \"`pass-cli login` into a session directory\".to_owned(),",
            false,
            "login",
        ),
    ];
    for (text, markdown, verb) in cases {
        let found = unscoped_command_lines(text, *markdown);
        assert_eq!(
            found.iter().map(|(_, verb, _)| *verb).collect::<Vec<_>>(),
            vec![*verb],
            "the grammar missed a spelling that cost hours: {text}"
        );
    }
}

#[test]
fn the_scanner_passes_what_it_must_not_flag() {
    // The other half of the control. A gate that flags correct work gets turned
    // off, and then the real violations flow again.
    let cases: &[(&str, bool)] = &[
        // The correct spelling, which is the whole point.
        (
            "PROTON_PASS_SESSION_DIR=/home/me/.keyless-pass-session pass-cli login",
            false,
        ),
        (
            "$ PROTON_PASS_SESSION_DIR=~/.keyless-pass-session pass-cli vault list",
            true,
        ),
        // A renderer call: the variable is not in the source, it is in the output.
        (
            "format!(\"log in again: `{}`\", login_into(session_dir))",
            false,
        ),
        // Prose that deliberately names the WRONG spelling, in order to warn.
        (
            "/// a bare `pass-cli login` logs into the DEFAULT session",
            false,
        ),
        ("# then `pass-cli agent create` mints one", false),
        (
            "A bare `pass-cli login` answers `Already authenticated`.",
            true,
        ),
        // Not a verb: a fixture filename, a version, prose about the parser.
        (
            "let argv = recorded_lines(&dir.join(\"pass-cli.argv\"));",
            false,
        ),
        ("measured against `pass-cli` 2.2.5 on a live account", true),
        (
            "pass-cli parses with clap, which reads a standalone argument",
            false,
        ),
    ];
    for (text, markdown) in cases {
        let found = unscoped_command_lines(text, *markdown);
        assert!(found.is_empty(), "false positive on: {text} -> {found:?}");
    }
}
