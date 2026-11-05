//! `keyless uninstall`: removing exactly what setup recorded putting there,
//! and nothing a person wrote.

use std::io::{self, Write};

use crate::cmd::receipt::{ClaudeRecord, Receipt, unchanged};

use super::super::status::{Mark, heading, note, row, verbatim};
use super::{SUBJECT, SetupRequest, hooks_installer};

/// Take back exactly what setup created.
///
/// The whole verb is a walk over the receipt. Nothing is matched by name,
/// nothing is matched against a shipped list, and nothing is removed that setup
/// did not record putting there. What it deliberately keeps is stated on screen
/// every time: a tool that removes your record of what it did while removing
/// itself is doing something worse than leaving a file behind.
///
/// # Errors
///
/// A write failure on `out`, or on a file the receipt named.
pub fn uninstall(
    request: &SetupRequest<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<i32> {
    let style = request.style;
    let receipt = match Receipt::load(&request.setup.receipt) {
        Ok(Some(receipt)) => receipt,
        Ok(None) => {
            heading(out, style, "UNINSTALL")?;
            row(
                out,
                style,
                Mark::Off,
                "receipt",
                SUBJECT,
                "off",
                &format!(
                    "{} does not exist, so this machine has no record of a setup \
                     run. Nothing was removed.",
                    request.setup.receipt.display()
                ),
            )?;
            note(
                out,
                style,
                "A pack installed by hand is removed by hand: `hooks/install.sh \
                 --uninstall`. Nothing here guesses at entries it did not write.",
            )?;
            return Ok(0);
        }
        Err(problem) => {
            writeln!(err, "{}: {problem}", crate::NAME)?;
            return Ok(1);
        }
    };

    heading(out, style, "UNINSTALL")?;
    let mut problems = 0;

    if let Some(claude) = &receipt.claude {
        problems += remove_claude(request, claude, out, err)?;
    }

    for record in &receipt.files {
        if !record.remove_on_uninstall {
            row(
                out,
                style,
                Mark::Off,
                "kept",
                SUBJECT,
                "off",
                &format!("{}   yours, not ours", record.path.display()),
            )?;
            continue;
        }
        if !record.path.exists() {
            row(
                out,
                style,
                Mark::Proven,
                "gone",
                SUBJECT,
                "proven",
                &format!("{}   already removed", record.path.display()),
            )?;
            continue;
        }
        if unchanged(&record.path, &record.sha256) {
            std::fs::remove_file(&record.path)?;
            // Only a directory this file was alone in, and only if empty. A
            // `remove_dir_all` here would take a sibling somebody else put there.
            if let Some(parent) = record.path.parent() {
                let _ = std::fs::remove_dir(parent);
            }
            row(
                out,
                style,
                Mark::Proven,
                "removed",
                SUBJECT,
                "proven",
                &record.path.display().to_string(),
            )?;
        } else {
            row(
                out,
                style,
                Mark::Off,
                "kept",
                SUBJECT,
                "off",
                &format!(
                    "{}   edited since setup wrote it, so it is yours now",
                    record.path.display()
                ),
            )?;
        }
    }

    std::fs::remove_file(&request.setup.receipt)?;

    heading(out, style, "DELIBERATELY LEFT BEHIND")?;
    verbatim(
        out,
        style,
        &format!(
            "{}   your store configuration",
            request.paths.config.display()
        ),
    )?;
    verbatim(
        out,
        style,
        &format!(
            "{}   the record of what was asked for",
            request.paths.audit.display()
        ),
    )?;
    verbatim(
        out,
        style,
        &format!(
            "{}   your own guard settings",
            request.setup.hooks_config.display()
        ),
    )?;
    note(
        out,
        style,
        "Your store sessions are untouched: an Infisical login, a 1Password sign-in \
         and a Proton session are credentials of yours, and removing a tool is not \
         a reason to invalidate them.",
    )?;
    note(
        out,
        style,
        "The binaries are removed the way they were placed — `cargo uninstall \
         keyless`, or `install/uninstall.sh --commit` for a daemon install.",
    )?;
    Ok(i32::from(problems > 0))
}

/// Hand the settings-file removal back to the installer that performed it.
fn remove_claude(
    request: &SetupRequest<'_>,
    claude: &ClaudeRecord,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<u32> {
    let style = request.style;
    let installer = match hooks_installer() {
        Ok(path) => path,
        Err(reason) => {
            row(
                out,
                style,
                Mark::Broken,
                "guards",
                SUBJECT,
                "broken",
                &reason,
            )?;
            return Ok(1);
        }
    };
    let done = std::process::Command::new("python3")
        .arg(&installer)
        .arg("--uninstall")
        .arg("--claude-dir")
        .arg(&request.setup.claude_dir)
        .arg("--receipt")
        .arg(&request.setup.receipt)
        .arg("--report")
        .output()?;
    if done.status.success() {
        row(
            out,
            style,
            Mark::Proven,
            "guards",
            SUBJECT,
            "proven",
            &format!("removed from {}", claude.settings.display()),
        )?;
        for line in String::from_utf8_lossy(&done.stdout).lines() {
            verbatim(out, style, line)?;
        }
        Ok(0)
    } else {
        row(
            out,
            style,
            Mark::Broken,
            "guards",
            SUBJECT,
            "broken",
            &format!("{} exited {}", installer.display(), done.status),
        )?;
        write!(err, "{}", String::from_utf8_lossy(&done.stderr))?;
        Ok(1)
    }
}
