//! `keyless setup`, `keyless disable`, `keyless enable`, `keyless uninstall` —
//! one way in and two ways out.
//!
//! # The hole this closes
//!
//! There were two installers and neither mentioned the other. `install/install.sh`
//! placed the binaries and stood up the daemon; `hooks/install.py` registered the
//! guards. A stranger who cloned, built and installed got the broker with **none
//! of its guards**, and nothing on the machine said so. The protection existed on
//! one machine because that machine's settings file happened to point at a
//! checkout by hand — which is the definition of not standalone.
//!
//! # Why the binary owns this and not a script
//!
//! A shell script and a Rust binary rot apart, and only one of them ships, gets
//! tested and gets versioned. `install/install.sh` remains — it is the ONE step
//! that needs root, and a dry-run-by-default script somebody reads before running
//! under `sudo` is the right shape for that. Everything else is this verb, and
//! this verb reports the daemon rather than pretending it does not exist.
//!
//! # The rules this verb follows, in order of how expensive breaking them is
//!
//! 1. **It names every file before it touches it.** The plan is printed first,
//!    and `--dry-run` stops there.
//! 2. **It never clobbers.** A file another program owns is MERGED into, never
//!    replaced; a file this tool owns is left alone the moment its content
//!    differs from what setup wrote. Something already there and different is
//!    reported and kept.
//! 3. **It re-adds nothing you removed.** See [`super::receipt`] — without a
//!    record, "never installed" and "installed and thrown out" are the same
//!    observation, and an installer that treats them alike overwrites a decision
//!    every time it runs.
//! 4. **It works with no agent harness present.** `keyless` is a general tool.
//!    A machine with no settings file gets the broker, the config and the
//!    report, and the agent-specific steps are SKIPPED and named — never failed.
//! 5. **It cannot mint a per-person credential and does not pretend to.** A
//!    Proton session directory does not copy between accounts and Infisical
//!    needs its own login. Setup says which login is missing and stops.
//!
//! # Why the off switch is a first-class verb
//!
//! A guard that cannot be turned off gets destroyed instead. Somebody who cannot
//! find the switch hand-edits a hook, guts their settings file, or works around
//! the pack permanently — and then the protection is gone silently, which is
//! strictly worse than it being off on purpose. So `keyless disable` loses
//! nothing, is reversed by `keyless enable`, and `keyless doctor` says plainly
//! that it is off. A disabled install that reports healthy would be the worst
//! false green in the tool.
//!
//! It is instant for a PERSON and refused for everyone else. `disable` and
//! `uninstall` each turn off protection for every command that runs
//! afterwards, so both ask at a terminal before doing that — one line, and
//! the only accepted answer is the verb's own name, typed back. A caller
//! whose stdin and stdout are not both terminals is refused outright: a script, an agent,
//! or a pipe is exactly the caller this question exists to stop, and no flag
//! or environment variable is offered to skip it. See
//! [`switch::confirm_switch`] for the mechanism.
//!
//! ⚠️ **The off switch is deliberately NOT advertised in what the guards print
//! when they refuse a command.** That text is read by the agent, not by the
//! person: handing an agent the sentence "run `keyless disable` to stop this"
//! turns every block into an instruction for removing the block. The refusal
//! says a person can turn the guards off, and does not say how. The verb is
//! discoverable where a PERSON looks — `keyless --help`, and `keyless doctor`.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::cmd::receipt::Receipt;
use crate::paths::{Paths, SetupPaths};

use super::status::{Style, command, heading, note, verbatim};

mod skill;
mod steps;
pub mod switch;
pub mod uninstall;

use skill::skill_file;
use steps::{step_binaries, step_config, step_daemon, step_guards};

/// The width every row in this report pads its subject to.
const SUBJECT: usize = 9;

/// Everything a setup run needs that is not the terminal it writes to.
pub struct SetupRequest<'a> {
    /// The config file and the audit log.
    pub paths: &'a Paths,
    /// The receipt, the guards' config, and the agent directory.
    pub setup: &'a SetupPaths,
    /// Print the plan and change nothing.
    pub dry_run: bool,
    /// Put back the entries a previous setup installed and somebody removed.
    pub restore: bool,
    /// Also stand up the daemon, which needs root.
    pub with_daemon: bool,
    /// Install the agent instructions.
    pub with_skill: bool,
    /// Whether a question may be asked at all.
    pub interactive: bool,
    /// Take the detected answer without asking.
    pub assume_yes: bool,
    /// Write this backend as the default rather than deciding.
    pub only: Option<&'a str>,
    /// Colour and character set.
    pub style: Style,
}

/// Where the packaged file `relative` is, or the reason it could not be found.
///
/// Three places, in order. The third covers the reported gap: `cargo install
/// --path .` puts the binary on `PATH` and leaves the repository where it was,
/// so a binary that remembers where it was built can still reach its own data
/// files. A binary COPIED to another machine cannot, and that is what
/// `KEYLESS_PACK_DIR` exists for — said out loud rather than guessed at.
///
/// # Errors
///
/// Nothing on the list is a file. The message lists every path that was tried.
pub fn packaged(relative: &[&str]) -> Result<PathBuf, String> {
    let join = |base: &Path| {
        relative
            .iter()
            .fold(base.to_path_buf(), |at, part| at.join(part))
    };
    let mut looked = Vec::new();
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(dir) = std::env::var(PACK_DIR_ENV)
        && !dir.is_empty()
    {
        candidates.push(join(Path::new(&dir)));
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut at = exe.parent().map(Path::to_path_buf);
        // Three levels: a build tree puts the binary at `target/<profile>/`, an
        // install puts it at `<prefix>/bin`, and a `cargo install --path .` in a
        // workspace can put it one deeper still.
        for _ in 0..3 {
            if let Some(dir) = at {
                candidates.push(join(&dir));
                at = dir.parent().map(Path::to_path_buf);
            }
        }
    }
    candidates.push(join(Path::new(env!("CARGO_MANIFEST_DIR"))));

    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
        looked.push(candidate.display().to_string());
    }
    Err(format!(
        "`{}` is not on this machine. Looked in: {}. Set {PACK_DIR_ENV} to the \
         directory holding the repository's `hooks/` and `install/`",
        relative.join("/"),
        looked.join(", ")
    ))
}

/// Names the directory holding the packaged `hooks/` and `install/` trees.
pub const PACK_DIR_ENV: &str = "KEYLESS_PACK_DIR";

/// The older, narrower spelling: the hook pack's own directory.
///
/// Kept because it is what `init --hooks` has always documented, and because it
/// points at `hooks/` itself rather than at the repository root — a distinction
/// that matters to anybody who has vendored the pack on its own.
pub const HOOKS_DIR_ENV: &str = "KEYLESS_HOOKS_DIR";

/// Where `hooks/install.py` is.
///
/// # Errors
///
/// Neither `KEYLESS_HOOKS_DIR` nor any packaged location holds it.
pub fn hooks_installer() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var(HOOKS_DIR_ENV)
        && !dir.is_empty()
    {
        let candidate = Path::new(&dir).join("install.py");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    packaged(&["hooks", "install.py"])
}

// ---------------------------------------------------------------------------
// the guards' own switch
// ---------------------------------------------------------------------------

/// Whether the guards are armed, and how anybody could tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guards {
    /// Firing.
    Armed,
    /// Switched off in the pack's own config. Nothing is deleted.
    Disabled,
    /// Recording every decision and blocking nothing.
    Observing,
}

/// Read the guards' switch.
///
/// A config that does not parse reads as ARMED, which is what the pack itself
/// does with an unreadable config — it fails open with a record and never
/// disables itself. Two answers to the same question have to agree, or `doctor`
/// says armed while the pack is off.
#[must_use]
pub fn guards(setup: &SetupPaths) -> Guards {
    let Ok(text) = std::fs::read_to_string(&setup.hooks_config) else {
        return Guards::Armed;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Guards::Armed;
    };
    if value.get("enabled") == Some(&serde_json::Value::Bool(false)) {
        return Guards::Disabled;
    }
    if value.get("observe") == Some(&serde_json::Value::Bool(true)) {
        return Guards::Observing;
    }
    Guards::Armed
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------

/// The one command that leaves a machine complete.
///
/// # Errors
///
/// A write failure on `out`, or on a file the plan named.
pub fn setup(
    request: &SetupRequest<'_>,
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<i32> {
    let style = request.style;
    let mut receipt = match Receipt::load(&request.setup.receipt) {
        Ok(found) => found.unwrap_or_default(),
        Err(problem) => {
            writeln!(err, "{}: {problem}", crate::NAME)?;
            writeln!(
                err,
                "That file records what a previous setup created. Setup stops \
                 rather than installing over a record it cannot read — move it \
                 aside to start fresh."
            )?;
            return Ok(1);
        }
    };

    writeln!(out, "{} {}", crate::NAME, env!("CARGO_PKG_VERSION"))?;
    plan(request, out)?;
    if request.dry_run {
        note(
            out,
            style,
            "Dry run. Nothing above was touched. Run the same command without \
             --dry-run to apply it.",
        )?;
        return Ok(0);
    }

    let mut problems = 0;
    problems += step_binaries(request, out)?;
    problems += step_config(request, stdin, out, err, &mut receipt)?;
    problems += step_guards(request, out, err, &mut receipt)?;
    if request.with_skill {
        problems += skill::step_skill(request, out, &mut receipt)?;
    }
    problems += step_daemon(request, out, err)?;

    receipt.written_at = crate::time::rfc3339_utc(crate::time::now_unix_millis());
    receipt.tool_version = env!("CARGO_PKG_VERSION").to_owned();
    receipt.save(&request.setup.receipt)?;

    heading(out, style, "WHAT SETUP CANNOT DO")?;
    note(
        out,
        style,
        &format!(
            "A store credential is per-person and this command cannot mint one. \
             Infisical needs `infisical login` against your own account. 1Password needs \
             `op signin` and the name of the one vault it may read. Proton needs \
             `{}` — a session directory that does not copy between machines or \
             accounts, named by that variable and by nothing else.",
            crate::store::proton::scoped_command_template("login")
        ),
    )?;
    note(
        out,
        style,
        "So a fresh machine is finished by exactly one login, performed by you. \
         Run this again afterwards and the row turns green.",
    )?;

    heading(out, style, "IF IT IS EVER IN YOUR WAY")?;
    command(
        out,
        style,
        &format!("{} disable", crate::NAME),
        "asks you to confirm at a terminal, then the guards stop firing. Nothing is deleted.",
    )?;
    command(out, style, &format!("{} enable", crate::NAME), "back on")?;
    command(
        out,
        style,
        &format!("{} uninstall", crate::NAME),
        "removes exactly what this command created, and nothing you wrote",
    )?;

    verbatim(
        out,
        style,
        &format!("receipt: {}", request.setup.receipt.display()),
    )?;
    Ok(i32::from(problems > 0))
}

/// Every file this run may touch, before it touches any of them.
fn plan(request: &SetupRequest<'_>, out: &mut dyn Write) -> io::Result<()> {
    let style = request.style;
    heading(out, style, "FILES THIS TOUCHES")?;
    verbatim(
        out,
        style,
        &format!(
            "{}   your store configuration",
            request.paths.config.display()
        ),
    )?;
    // A plan that lists a file the run is about to skip is a plan that was
    // wrong. The agent's two files are conditional on the harness existing, so
    // the condition is stated here rather than discovered three rows later.
    let agent = if request.setup.claude_dir.is_dir() {
        ""
    } else {
        " — SKIPPED, no agent harness at that directory"
    };
    verbatim(
        out,
        style,
        &format!(
            "{}   the guards' registration, MERGED into{agent}",
            request.setup.settings().display()
        ),
    )?;
    if request.with_skill {
        verbatim(
            out,
            style,
            &format!(
                "{}   the agent instructions{agent}",
                skill_file(request.setup).display()
            ),
        )?;
    }
    verbatim(
        out,
        style,
        &format!(
            "{}   what was created, so uninstall can be exact",
            request.setup.receipt.display()
        ),
    )?;
    if request.with_daemon {
        verbatim(
            out,
            style,
            "/usr/local/{bin,etc,var}/keyless…   the daemon, under sudo, by install/install.sh",
        )?;
    }
    note(
        out,
        style,
        "Nothing else is written. Your audit log, your store and your shell \
         profile are not touched.",
    )
}
