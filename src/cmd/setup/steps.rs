//! The steps `keyless setup` takes for the binaries, the config, the guards
//! and the daemon, each reporting what it found and what it changed.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::cmd::receipt::{FileRecord, Receipt, digest_of};

use super::super::status::{Mark, action, heading, note, row, verbatim};
use super::{SUBJECT, SetupRequest, hooks_installer, packaged};

/// Where the binaries are, and whether the one on `PATH` is the one running.
///
/// Reports and never writes. Placing a binary is `cargo install` or
/// `install/install.sh`, and a setup verb that copied itself somewhere would be
/// installing a second copy nobody asked for and nothing tracks.
pub(super) fn step_binaries(request: &SetupRequest<'_>, out: &mut dyn Write) -> io::Result<u32> {
    let style = request.style;
    heading(out, style, "BINARIES")?;
    let running = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("keyless"));
    row(
        out,
        style,
        Mark::Proven,
        "keyless",
        SUBJECT,
        "proven",
        &running.display().to_string(),
    )?;

    match which("keylessd") {
        Some(path) => row(
            out,
            style,
            Mark::Proven,
            "keylessd",
            SUBJECT,
            "proven",
            &path.display().to_string(),
        )?,
        None => {
            row(
                out,
                style,
                Mark::Off,
                "keylessd",
                SUBJECT,
                "off",
                "the daemon binary is not on PATH. Everything works without it; \
                 it is what moves the store behind a second uid.",
            )?;
        }
    }
    Ok(0)
}

/// The first `name` on `PATH`.
pub(super) fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Detect the stores, and write the config when there is none.
pub(super) fn step_config(
    request: &SetupRequest<'_>,
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
    receipt: &mut Receipt,
) -> io::Result<u32> {
    let style = request.style;
    let existed = request.paths.config.exists();
    let init_request = crate::cmd::init::InitRequest {
        paths: request.paths,
        force: false,
        assume_yes: request.assume_yes,
        only: request.only,
        interactive: request.interactive,
        // The guards are this module's step, and running the older reporter here
        // as well would print the same row twice — about a DIFFERENT settings
        // file, because `init` resolves only the default location.
        install_hooks: false,
        report_guards: false,
        style,
    };
    let code = crate::cmd::init::init(&init_request, stdin, out, err)?;

    if !existed && request.paths.config.exists() {
        let body = std::fs::read(&request.paths.config)?;
        receipt.record_file(FileRecord {
            path: request.paths.config.clone(),
            created: true,
            sha256: digest_of(&body),
            // Your configuration is yours the moment it exists. Uninstalling the
            // tool must not take away the record of how you had it set up.
            remove_on_uninstall: false,
        });
    }
    Ok(u32::from(code != 0))
}

/// Register the guards, or say exactly why that was skipped.
pub(super) fn step_guards(
    request: &SetupRequest<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    receipt: &mut Receipt,
) -> io::Result<u32> {
    let style = request.style;
    heading(out, style, "GUARDS")?;

    let settings = request.setup.settings();
    if !request.setup.claude_dir.is_dir() {
        // Requirement, not a fallback: `keyless` is a general tool and most
        // machines running it have no agent harness at all. Creating another
        // program's configuration directory on the chance it might one day want
        // one is the same overreach as editing a config nobody asked us to.
        row(
            out,
            style,
            Mark::Off,
            "guards",
            SUBJECT,
            "off",
            &format!(
                "no agent harness here — {} does not exist, so there is nothing to \
                 register the pack in. Everything else is installed.",
                request.setup.claude_dir.display()
            ),
        )?;
        action(
            out,
            style,
            &format!(
                "{} setup --claude-dir <path>   if your harness keeps its settings elsewhere",
                crate::NAME
            ),
        )?;
        return Ok(0);
    }

    let installer = match hooks_installer() {
        Ok(path) => path,
        Err(reason) => {
            row(
                out,
                style,
                Mark::NotSetUp,
                "guards",
                SUBJECT,
                "absent",
                &reason,
            )?;
            return Ok(1);
        }
    };

    let mut arguments = vec![
        installer.as_os_str().to_owned(),
        "--claude-dir".into(),
        request.setup.claude_dir.as_os_str().to_owned(),
        "--receipt".into(),
        request.setup.receipt.as_os_str().to_owned(),
        "--report".into(),
    ];
    if request.restore {
        arguments.push("--restore".into());
    }

    let done = match std::process::Command::new("python3")
        .args(&arguments)
        .output()
    {
        Ok(done) => done,
        Err(problem) => {
            row(
                out,
                style,
                Mark::Broken,
                "guards",
                SUBJECT,
                "broken",
                &format!(
                    "cannot run python3: {problem}. The pack is a Python program \
                     and the harness runs it with python3 too."
                ),
            )?;
            return Ok(1);
        }
    };
    // The installer wrote the receipt's `claude` key itself, so re-read it here
    // rather than reconstructing what it did. One writer per key.
    if let Ok(Some(fresh)) = Receipt::load(&request.setup.receipt) {
        receipt.claude = fresh.claude;
    }

    if done.status.success() {
        row(
            out,
            style,
            Mark::Proven,
            "guards",
            SUBJECT,
            "proven",
            &settings.display().to_string(),
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

/// Report the daemon, and stand it up when that was asked for.
///
/// The escalation is deliberate and it is the only one: creating a system user,
/// writing under `/usr/local` and bootstrapping a launch daemon are root acts,
/// and a setup verb that acquired root without being told to would be a worse
/// thing than the hole it closes. `--daemon` is that instruction, and `sudo`
/// asks the person directly.
pub(super) fn step_daemon(
    request: &SetupRequest<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<u32> {
    let style = request.style;
    heading(out, style, "DAEMON")?;
    let plist = Path::new("/Library/LaunchDaemons/sh.keyless.keylessd.plist");
    let installed = plist.exists();

    if !request.with_daemon {
        if installed {
            row(
                out,
                style,
                Mark::Proven,
                "daemon",
                SUBJECT,
                "proven",
                "a launch daemon is installed. `keyless doctor` says whether it is answering.",
            )?;
        } else {
            row(
                out,
                style,
                Mark::Off,
                "daemon",
                SUBJECT,
                "off",
                "not installed. Without it `keyless` reads your keychain as you, \
                 which is a habit rather than a boundary.",
            )?;
            action(
                out,
                style,
                &format!(
                    "{} setup --daemon   creates the second uid, under sudo. It is \
                     a separate act because it needs root and because your secrets \
                     have to MOVE, which only you can decide.",
                    crate::NAME
                ),
            )?;
        }
        return Ok(0);
    }

    let script = match packaged(&["install", "install.sh"]) {
        Ok(path) => path,
        Err(reason) => {
            row(
                out,
                style,
                Mark::NotSetUp,
                "daemon",
                SUBJECT,
                "absent",
                &reason,
            )?;
            return Ok(1);
        }
    };
    note(
        out,
        style,
        "The daemon installer runs under sudo and prints every command it runs. \
         It is a shell script you can read first:",
    )?;
    verbatim(out, style, &script.display().to_string())?;

    let status = std::process::Command::new("sudo")
        .arg(&script)
        .arg("--commit")
        .status();
    match status {
        Ok(code) if code.success() => {
            row(
                out,
                style,
                Mark::Proven,
                "daemon",
                SUBJECT,
                "proven",
                "installed. Your secrets are NOT moved — read the installer's \
                 closing notes, that step is yours.",
            )?;
            Ok(0)
        }
        Ok(code) => {
            row(
                out,
                style,
                Mark::Broken,
                "daemon",
                SUBJECT,
                "broken",
                &format!("{} exited {code}", script.display()),
            )?;
            Ok(1)
        }
        Err(problem) => {
            writeln!(err, "{}: cannot run sudo: {problem}", crate::NAME)?;
            row(
                out,
                style,
                Mark::Broken,
                "daemon",
                SUBJECT,
                "broken",
                "sudo did not run",
            )?;
            Ok(1)
        }
    }
}

// ---------------------------------------------------------------------------
// uninstall
// ---------------------------------------------------------------------------
