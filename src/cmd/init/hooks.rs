//! The GUARDS step: whether the hook pack is registered, and installing it.

use std::io::{self, Write};

use super::InitRequest;
use crate::cmd::status::{Mark, action, heading, row, verbatim};

/// The Claude Code settings file the pack registers itself in.
///
/// `init` is the older, narrower verb and reports on the default location only.
/// `setup` resolves it properly, honours `--claude-dir`, and prints what it
/// resolved — see [`crate::paths::SetupPaths`].
fn settings_file() -> Option<std::path::PathBuf> {
    crate::paths::home().map(|home| home.join(".claude").join("settings.json"))
}

/// Whether the pack is already registered in the settings file.
///
/// A substring test for the handler script's own name, which is the same signal
/// `hooks/install.py` uses to recognise itself. It does NOT see a pack reached
/// through somebody's own forwarder script — that reports `absent`, and running
/// `--hooks` then is a no-op, because the installer recognises the folded
/// arrangement even though this does not.
fn hooks_are_registered() -> bool {
    settings_file()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|text| text.contains("keyless_hook.py"))
}

/// The GUARDS row, and the install when it was asked for.
pub(super) fn report_hooks(
    request: &InitRequest<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<()> {
    let style = request.style;
    heading(out, style, "GUARDS")?;

    let installer = match crate::cmd::setup::hooks_installer() {
        Ok(path) => path,
        Err(reason) => {
            // Not a problem and not a failure. A packaged binary with no pack
            // beside it is a legitimate install, and calling it broken would
            // make this row noise on every machine that has one.
            row(out, style, Mark::Off, "hooks", 9, "off", &reason)?;
            return Ok(());
        }
    };

    if hooks_are_registered() && !request.install_hooks {
        row(
            out,
            style,
            Mark::Proven,
            "hooks",
            9,
            "proven",
            "the pack is registered in your Claude Code settings",
        )?;
        return Ok(());
    }

    if !request.install_hooks {
        row(
            out,
            style,
            Mark::NotSetUp,
            "hooks",
            9,
            "absent",
            "no pack registered, so nothing refuses a command that would print a credential",
        )?;
        action(
            out,
            style,
            &format!(
                "{} init --hooks   merges it in, keeping everything already there",
                crate::NAME
            ),
        )?;
        return Ok(());
    }

    // The write itself belongs to the installer. It re-parses before replacing,
    // replaces atomically, and is idempotent — so this runs it and repeats what
    // it said rather than deciding anything about a file it does not own.
    let output = std::process::Command::new("python3")
        .arg(&installer)
        .output();
    match output {
        Ok(done) if done.status.success() => {
            // 🔴 EXIT 0 IS NOT A REGISTRATION. The installer refuses to invent an
            // agent harness that is not there: on a machine with no `~/.claude`
            // it writes nothing, says so, and exits 0 — which is correct, and is
            // not a failure. Read from the status alone, that printed a green
            // `proven` directly above the installer's own "Nothing was written",
            // so the word denied the sentence under it and the one flag that
            // closes the guards hole reported success having closed nothing.
            //
            // The registration is therefore read BACK, through the same
            // predicate the "already registered" row above uses. Two answers to
            // "is the pack registered" have to come from one place, or this row
            // and that one disagree on the same machine.
            let (mark, state, detail) = if hooks_are_registered() {
                (
                    Mark::Proven,
                    "proven",
                    format!("installed by {}", installer.display()),
                )
            } else {
                (
                    Mark::NotSetUp,
                    "absent",
                    format!(
                        "{} wrote nothing, so no pack is registered and nothing refuses a \
                         command that would print a credential",
                        installer.display()
                    ),
                )
            };
            row(out, style, mark, "hooks", 9, state, &detail)?;
            for line in String::from_utf8_lossy(&done.stdout).lines() {
                verbatim(out, style, line)?;
            }
            Ok(())
        }
        Ok(done) => {
            row(
                out,
                style,
                Mark::Broken,
                "hooks",
                9,
                "broken",
                &format!("{} exited {}", installer.display(), done.status),
            )?;
            // The installer's own words, on the stream errors already go to.
            write!(err, "{}", String::from_utf8_lossy(&done.stderr))?;
            Ok(())
        }
        Err(problem) => {
            row(
                out,
                style,
                Mark::Broken,
                "hooks",
                9,
                "broken",
                &format!("cannot run python3: {problem}"),
            )?;
            Ok(())
        }
    }
}
