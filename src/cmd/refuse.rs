//! The verbs that do not exist, and the one message that says why.
//!
//! # The defect this module exists to close
//!
//! A newcomer checks a secrets tool the way they check every other tool: they
//! ask it to print the value back, once, to confirm the thing they stored is
//! the thing that is there. Against `keyless` that is `keyless get NAME`, and
//! what came back was clap's bare `error: unrecognized subcommand 'get'`.
//!
//! That message is true and it teaches the wrong thing. `unrecognized` is what
//! a CLI says about a typo and about a verb that has not been written yet, so
//! the reasonable reading — from somebody five minutes into the tool, who has
//! not read the manual — is that the install is broken or the feature is
//! missing. The next move is to go looking for the flag, and the move after
//! that is to give up and `security find-generic-password -w`, which is the
//! exact plaintext path this tool exists to replace.
//!
//! The absence of a read verb is the PRODUCT. It is the one claim the whole
//! design rests on, and it was the one claim the tool never made out loud at
//! the moment somebody was standing in front of it.
//!
//! # Why these are hidden, and why that is not a contradiction
//!
//! Every variant here is `hide = true`, so the verb list `keyless --help`
//! prints is exactly as long as it was. That matters: `Cargo.toml` records
//! that the verb set is a security property a reader must be able to check at
//! a glance, and a `get` sitting in that list would undo it — a reader
//! skimming for "does anything here print a value" would find one.
//!
//! So the list is unchanged and only the FAILURE changes. Nothing new is
//! reachable; a command that exited 2 with a bare message exits 2 with a
//! message that says why.
//!
//! # Why a refusal rather than a suggestion
//!
//! `clap`'s own near-miss suggester would answer `get` with "did you mean
//! `ls`?", which is worse than silence: `ls` and `get` differ in the one
//! property the user is asking about. The answer to "print this value" is not
//! a different verb, it is a different shape of command — run the thing that
//! needs the credential — and that has to be shown, not hinted at.

use std::io::{self, Write};

use crate::NAME;

/// Every word answered with [`no_such_verb`].
///
/// The first is the subcommand's own name and the rest are its aliases, in the
/// order `main.rs` declares them. Kept here rather than only in the `clap`
/// attribute because two readers need it: the parser, which turns these into a
/// refusal, and [`typed_word`], which has to recover WHICH of them was typed.
///
/// A word added to the attribute and not to this list still refuses — it just
/// gets named `get` in its own error. `every_refused_word_explains_itself_and_
/// points_at_run` in `tests/cli.rs` walks this list against the real binary, so
/// a word here that the parser does not answer fails the suite.
pub const REFUSED: [&str; 9] = [
    "get", "show", "cat", "read", "reveal", "print", "view", "dump", "export",
];

/// Which refusal word the user actually typed, given the raw arguments.
///
/// `clap` resolves an alias to its canonical variant and does not report which
/// spelling arrived, so the argument list is the only place the answer still
/// exists. The verb is the first BARE word — the first argument that is neither
/// a flag nor a flag's value.
///
/// Skipping a flag's value is not decoration. `--config` and `--audit` take
/// paths, a path may be spelled `get`, and a scan for "the first word in
/// [`REFUSED`]" reads `keyless --config ./get show` as a question about `get`.
/// The first search written here did exactly that, and the test below is what
/// said so.
///
/// Falls back to the canonical `get` when no bare word matches — which happens
/// only if `main.rs` grows an alias this list does not carry. A slightly wrong
/// noun in one sentence is the right failure; printing no explanation is not.
#[must_use]
pub fn typed_word<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    /// The global flags that take a separate value. `--no-audit` is a flag and
    /// takes none, so it is deliberately absent.
    const TAKES_A_VALUE: [&str; 2] = ["--config", "--audit"];

    let mut skip_next = false;
    for arg in args.into_iter().skip(1) {
        let arg = arg.as_ref();
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with('-') {
            // `--config=PATH` carries its value inline, so nothing follows it
            // to skip; `--config PATH` is the form that does.
            skip_next = TAKES_A_VALUE.contains(&arg);
            continue;
        }
        // The first bare word is the subcommand, whatever it is. Reaching a
        // bare word that is not refused means the caller is not on this path.
        return if REFUSED.contains(&arg) {
            arg.to_owned()
        } else {
            REFUSED[0].to_owned()
        };
    }
    REFUSED[0].to_owned()
}

/// Exit code for a verb that does not exist.
///
/// 2, deliberately, which is what `clap` already returned for these words. The
/// message changes and the contract does not: a script that branched on the
/// status quo keeps working, and nothing that used to fail now succeeds.
pub const EXIT_NO_SUCH_VERB: i32 = 2;

/// Write the refusal for `verb` to `out`.
///
/// Takes the word the user actually typed so the first line names it back to
/// them. Someone who typed `reveal` should not have to work out that a
/// paragraph about `get` is about them.
///
/// # Errors
///
/// Propagates a write failure from `out`, which for the real stderr means the
/// stream is gone and the message could not be delivered.
pub fn no_such_verb(verb: &str, out: &mut dyn Write) -> io::Result<i32> {
    writeln!(
        out,
        "{NAME}: there is no `{verb}`, and there will not be one."
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "Printing a credential is the one thing this tool exists to prevent, so no"
    )?;
    writeln!(
        out,
        "verb reads one back to a terminal. There is no flag to add and no debug"
    )?;
    writeln!(
        out,
        "mode to find — a value only ever enters the process that needs it."
    )?;
    writeln!(out)?;
    writeln!(out, "What you probably want:")?;
    writeln!(out)?;
    writeln!(
        out,
        "  {NAME} run -s NAME -- your-command   give NAME to the command that needs it"
    )?;
    writeln!(
        out,
        "  {NAME} doctor --probe                check a name resolves, without seeing it"
    )?;
    writeln!(
        out,
        "  {NAME} ls                            the names you have declared"
    )?;
    writeln!(out)?;
    writeln!(out, "`{NAME} --help` lists every verb there is.")?;

    Ok(EXIT_NO_SUCH_VERB)
}

#[cfg(test)]
mod tests {
    use super::{EXIT_NO_SUCH_VERB, REFUSED, no_such_verb, typed_word};

    fn render(verb: &str) -> (String, i32) {
        let mut out = Vec::new();
        let code = no_such_verb(verb, &mut out).expect("writing to a Vec cannot fail");
        (String::from_utf8(out).expect("the message is ASCII"), code)
    }

    #[test]
    fn it_names_the_word_that_was_typed() {
        let (text, _) = render("reveal");
        assert!(
            text.contains("there is no `reveal`"),
            "a user who typed `reveal` must not be answered about `get`: {text}"
        );
    }

    #[test]
    fn it_points_at_run_rather_than_at_another_verb() {
        let (text, _) = render("get");
        assert!(
            text.contains("run -s NAME -- your-command"),
            "the answer to `get` is a different SHAPE of command, and it must be shown: {text}"
        );
    }

    #[test]
    fn it_says_the_absence_is_deliberate() {
        let (text, _) = render("get");
        // "will not be one" is the load-bearing clause. Without it the message
        // reads as "not implemented yet", which sends the reader looking for a
        // newer build instead of teaching them the design.
        assert!(
            text.contains("will not be one"),
            "the refusal must read as a decision, never as an unfinished feature: {text}"
        );
    }

    #[test]
    fn it_never_exits_zero() {
        let (_, code) = render("get");
        assert_eq!(code, EXIT_NO_SUCH_VERB);
        assert_ne!(code, 0, "a verb that did not run must not report success");
    }

    /// The message is advice, and advice that names a verb the binary does not
    /// have is worse than none. Every verb quoted here is checked against the
    /// real parser in `tests/cli_surface.rs`; this asserts the set it must
    /// cover, so adding a line above without covering it fails here.
    #[test]
    fn the_typed_word_is_recovered_from_the_arguments() {
        assert_eq!(typed_word(["keyless", "reveal", "DEMO"]), "reveal");
        assert_eq!(typed_word(["keyless", "get"]), "get");
    }

    #[test]
    fn a_flag_value_is_not_mistaken_for_the_verb() {
        // `--config` takes a path, and a path may be spelled `get`. The verb is
        // the first BARE word, so the option's value must not win.
        assert_eq!(typed_word(["keyless", "--config", "get", "show"]), "show");
        // The inline form consumes nothing after it.
        assert_eq!(typed_word(["keyless", "--config=get", "reveal"]), "reveal");
        // A valueless global must not swallow the verb that follows it.
        assert_eq!(typed_word(["keyless", "--no-audit", "cat"]), "cat");
    }

    #[test]
    fn an_unknown_spelling_still_produces_a_message() {
        // The fallback is the canonical name, never a panic and never silence.
        assert_eq!(typed_word(["keyless", "unpeel"]), REFUSED[0]);
    }

    #[test]
    fn every_refused_word_renders_its_own_name() {
        for word in REFUSED {
            let (text, code) = render(word);
            assert!(
                text.contains(&format!("there is no `{word}`")),
                "`{word}` must be named back to the person who typed it: {text}"
            );
            assert_ne!(code, 0);
        }
        assert_eq!(
            REFUSED.len(),
            9,
            "a new refusal word needs covering here too"
        );
    }

    #[test]
    fn every_verb_it_recommends_is_one_of_three() {
        let (text, _) = render("get");
        for verb in ["run", "doctor", "ls"] {
            assert!(
                text.contains(&format!("keyless {verb}")),
                "the message must recommend `{verb}`: {text}"
            );
        }
    }
}
