//! `keyless disable` and `keyless enable`: the one write that switches the
//! guards, and the question a person answers before any of them turns off.

use std::io::{self, BufRead, Write};

use crate::paths::SetupPaths;

use super::super::status::{Mark, Style, action, heading, note, row, verbatim};
use super::{Guards, SUBJECT, guards};

/// `keyless disable` and `keyless enable`, which are the same write.
///
/// It touches ONE file, and that file belongs to `keyless`. Nothing in the
/// agent's settings is edited, nothing is unregistered, and no state is lost —
/// so the reverse is one word and costs nothing. The alternative designs were
/// both worse: unregistering the pack means editing another program's config to
/// express a temporary preference, and an environment variable cannot be set by
/// the person who is being got in the way of, because they are not the process.
///
/// # Errors
///
/// The config file cannot be read, parsed, or written.
pub fn switch_guards(
    setup: &SetupPaths,
    style: Style,
    enable: bool,
    out: &mut dyn Write,
) -> io::Result<i32> {
    let path = &setup.hooks_config;
    let mut value: serde_json::Value = match std::fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text).map_err(|problem| {
            io::Error::other(format!(
                "{}: {problem}. This file holds your own hook settings, so it is \
                 not overwritten — fix or move it and run this again",
                path.display()
            ))
        })?,
        _ => serde_json::json!({}),
    };
    let Some(object) = value.as_object_mut() else {
        return Err(io::Error::other(format!(
            "{}: the top level is not an object, so nothing here can be merged into it",
            path.display()
        )));
    };

    let was = guards(setup);
    // `enabled` is removed rather than set to `true`: the pack's default is on,
    // and a file left holding `"enabled": true` reads as a setting somebody
    // chose, which is exactly what it is not.
    if enable {
        object.remove("enabled");
    } else {
        object.insert("enabled".to_owned(), serde_json::Value::Bool(false));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(&value).map_err(io::Error::other)?;
    std::fs::write(path, body + "\n")?;

    heading(out, style, "GUARDS")?;
    if enable {
        row(
            out,
            style,
            Mark::Proven,
            "guards",
            SUBJECT,
            "proven",
            if was == Guards::Disabled {
                "back on. Every check fires again."
            } else {
                "already on. Nothing changed."
            },
        )?;
    } else {
        row(
            out,
            style,
            Mark::Off,
            "guards",
            SUBJECT,
            "off",
            "no check fires. Nothing was deleted, nothing was unregistered, and \
             your config is untouched.",
        )?;
        action(
            out,
            style,
            &format!("{} enable   turns them back on, instantly", crate::NAME),
        )?;
    }
    verbatim(out, style, &path.display().to_string())?;
    note(
        out,
        style,
        "The broker itself is unaffected either way: `keyless run` resolves names \
         exactly as before.",
    )?;
    if !enable {
        note(
            out,
            style,
            "The daemon, if you stood one up, is also still running. Stopping it \
             would stop credentials resolving, which is not what `disable` means.",
        )?;
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// asking a person before every guard turns off
// ---------------------------------------------------------------------------

/// Exit code for `disable` and `uninstall` refusing to run at all.
///
/// Picked from the same free space [`crate::cmd::refuse::EXIT_NO_SUCH_VERB`] picks
/// from `clap`'s — nothing else in this binary returns 77. Nothing unlocks it:
/// no flag, no environment variable, no workaround, because a flag or a
/// variable is exactly what an unattended caller would add for itself.
pub const EXIT_REFUSED: i32 = 77;

/// Why a switch verb did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Stdin and stdout are not both terminals, so there is nobody to ask.
    NoTerminal,
    /// A terminal answered with something other than the verb's own name —
    /// EOF included.
    Declined,
}

impl Refusal {
    /// The audit vocabulary this refusal is recorded under.
    #[must_use]
    pub const fn decision(self) -> &'static str {
        match self {
            Refusal::NoTerminal => "refused-no-terminal",
            Refusal::Declined => "refused-unconfirmed",
        }
    }
}

/// Ask a person before `verb` turns every guard off, and read exactly one
/// answer.
///
/// The only accepted answer is `verb` itself, trimmed — never `y`, never
/// `yes`, and never silence. Those are exactly the words `yes | keyless
/// disable` supplies to a prompt it never read, and the question exists to
/// stop precisely that caller.
///
/// Takes a `BufRead` and a `Write` rather than reading `stdin`/`stdout`
/// itself, so this is provable by calling a function rather than by
/// scraping a real terminal — `main.rs` computes `interactive` and wires the
/// real streams.
///
/// # Errors
///
/// A write failure on `prompt`, or a read failure on `stdin` other than EOF.
pub fn confirm_switch(
    verb: &str,
    interactive: bool,
    stdin: &mut dyn BufRead,
    prompt: &mut dyn Write,
) -> io::Result<Result<(), Refusal>> {
    if !interactive {
        return Ok(Err(Refusal::NoTerminal));
    }
    write!(
        prompt,
        "`{} {verb}` turns every guard off, for every command that runs afterwards, until \
         `{} enable` turns them back on. Type `{verb}` to continue: ",
        crate::NAME,
        crate::NAME
    )?;
    prompt.flush()?;

    let mut line = String::new();
    let read = stdin.read_line(&mut line)?;
    if read > 0 && line.trim() == verb {
        Ok(Ok(()))
    } else {
        Ok(Err(Refusal::Declined))
    }
}

/// Say why `verb` did not run, on `err`.
///
/// # Errors
///
/// A write failure on `err`.
pub fn explain_refusal(verb: &str, why: Refusal, err: &mut dyn Write) -> io::Result<()> {
    writeln!(
        err,
        "{}: `{verb}` turns every guard off, for every command that runs afterwards, so it \
         asks a person before it does that.",
        crate::NAME
    )?;
    match why {
        Refusal::NoTerminal => writeln!(
            err,
            "Nothing here is a terminal a person is answering, so nothing changed. A person \
             runs `{} {verb}` from their own terminal.",
            crate::NAME
        )?,
        Refusal::Declined => writeln!(
            err,
            "That was not `{verb}` — nothing changed. Run it again and type `{verb}` at the \
             prompt."
        )?,
    }
    writeln!(
        err,
        "There is no flag, no environment variable, and no other way to skip this."
    )
}

#[cfg(test)]
mod tests {
    use super::super::{Guards, guards};
    use super::{Refusal, confirm_switch, switch_guards};
    use crate::cmd::status::Style;
    use crate::paths::SetupPaths;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-setup-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn the_switch_is_off_then_on_and_leaves_other_settings_alone() {
        // The property that makes `disable` safe to reach for: it is a merge
        // into one key of a file that may hold a person's own tuning, and
        // `enable` puts the file back exactly as it was.
        let dir = scratch("switch");
        let setup = SetupPaths::under(&dir);
        std::fs::write(
            &setup.hooks_config,
            "{\"protected_add\": [\"my-secrets.json\"]}",
        )
        .expect("write");

        assert_eq!(guards(&setup), Guards::Armed);
        let mut out: Vec<u8> = Vec::new();
        switch_guards(&setup, Style::PLAIN, false, &mut out).expect("disable");
        assert_eq!(guards(&setup), Guards::Disabled);

        let text = std::fs::read_to_string(&setup.hooks_config).expect("read");
        assert!(text.contains("my-secrets.json"), "{text}");

        switch_guards(&setup, Style::PLAIN, true, &mut out).expect("enable");
        assert_eq!(guards(&setup), Guards::Armed);
        let text = std::fs::read_to_string(&setup.hooks_config).expect("read");
        assert!(text.contains("my-secrets.json"), "{text}");
        // Re-enabling removes the key rather than writing `true`, so the file
        // never claims a setting the user did not choose.
        assert!(!text.contains("enabled"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabling_with_no_config_file_still_works() {
        // The tilted-user path: nothing has been configured, the guards are in
        // the way, and the off switch has to work anyway.
        let dir = scratch("no-config");
        let setup = SetupPaths::under(&dir);
        let mut out: Vec<u8> = Vec::new();
        switch_guards(&setup, Style::PLAIN, false, &mut out).expect("disable");
        assert_eq!(guards(&setup), Guards::Disabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unparseable_guard_config_reads_as_armed() {
        // The pack itself fails open on a config it cannot read. If this
        // reported "disabled" the two would disagree, and `doctor` would tell
        // somebody they are unprotected while every check is still firing —
        // or, worse, the reverse.
        let dir = scratch("corrupt");
        let setup = SetupPaths::under(&dir);
        std::fs::write(&setup.hooks_config, "{ not json").expect("write");
        assert_eq!(guards(&setup), Guards::Armed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn switching_refuses_to_overwrite_a_config_it_cannot_parse() {
        let dir = scratch("refuse");
        let setup = SetupPaths::under(&dir);
        std::fs::write(&setup.hooks_config, "{ not json").expect("write");
        let mut out: Vec<u8> = Vec::new();
        assert!(switch_guards(&setup, Style::PLAIN, false, &mut out).is_err());
        assert_eq!(
            std::fs::read_to_string(&setup.hooks_config).expect("read"),
            "{ not json"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirmation_refuses_outright_with_no_terminal() {
        let mut stdin = Cursor::new(Vec::new());
        let mut prompt: Vec<u8> = Vec::new();
        let result = confirm_switch("disable", false, &mut stdin, &mut prompt).expect("call");
        assert_eq!(result, Err(Refusal::NoTerminal));
        assert!(
            prompt.is_empty(),
            "a non-interactive caller must not even be asked: {:?}",
            String::from_utf8_lossy(&prompt)
        );
    }

    #[test]
    fn confirmation_proceeds_only_on_the_verbs_own_name() {
        let mut stdin = Cursor::new(b"disable\n".to_vec());
        let mut prompt: Vec<u8> = Vec::new();
        let result = confirm_switch("disable", true, &mut stdin, &mut prompt).expect("call");
        assert_eq!(result, Ok(()));
        assert!(
            String::from_utf8_lossy(&prompt).contains("Type `disable` to continue"),
            "{}",
            String::from_utf8_lossy(&prompt)
        );
    }

    #[test]
    fn confirmation_trims_the_typed_line() {
        let mut stdin = Cursor::new(b"disable   \n".to_vec());
        let mut prompt: Vec<u8> = Vec::new();
        let result = confirm_switch("disable", true, &mut stdin, &mut prompt).expect("call");
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn confirmation_refuses_yes_and_y_and_the_wrong_verb() {
        for typed in ["yes\n", "y\n", "enable\n"] {
            let mut stdin = Cursor::new(typed.as_bytes().to_vec());
            let mut prompt: Vec<u8> = Vec::new();
            let result = confirm_switch("disable", true, &mut stdin, &mut prompt).expect("call");
            assert_eq!(
                result,
                Err(Refusal::Declined),
                "`{typed}` must not confirm a disable"
            );
        }
    }

    #[test]
    fn confirmation_refuses_eof_exactly_as_a_wrong_answer() {
        // Nobody typed anything and stdin closed — `yes | keyless disable` and
        // an unattended EOF both land here, and both must be refused.
        let mut stdin = Cursor::new(Vec::new());
        let mut prompt: Vec<u8> = Vec::new();
        let result = confirm_switch("disable", true, &mut stdin, &mut prompt).expect("call");
        assert_eq!(result, Err(Refusal::Declined));
    }

    #[test]
    fn the_refusal_names_no_flag_env_var_or_workaround() {
        let mut err: Vec<u8> = Vec::new();
        super::explain_refusal("disable", Refusal::NoTerminal, &mut err).expect("write");
        let text = String::from_utf8_lossy(&err);
        assert!(text.contains("turns every guard off"), "{text}");
        assert!(text.contains("asks a person"), "{text}");
        assert!(
            text.contains("no flag") || text.contains("No flag"),
            "{text}"
        );
        assert!(text.contains("environment variable"), "{text}");
        for named in ["--", "KEYLESS_", "yes |"] {
            assert!(
                !text.contains(named),
                "the refusal names a workaround: {text}"
            );
        }
    }
}
