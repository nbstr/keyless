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
//! strictly worse than it being off on purpose. So `keyless disable` is instant,
//! loses nothing, is reversed by `keyless enable`, and `keyless doctor` says
//! plainly that it is off. A disabled install that reports healthy would be the
//! worst false green in the tool.
//!
//! ⚠️ **The off switch is deliberately NOT advertised in what the guards print
//! when they refuse a command.** That text is read by the agent, not by the
//! person: handing an agent the sentence "run `keyless disable` to stop this"
//! turns every block into an instruction for removing the block. The refusal
//! says a person can turn the guards off, and does not say how. The verb is
//! discoverable where a PERSON looks — `keyless --help`, and `keyless doctor`.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::cmd::receipt::{ClaudeRecord, FileRecord, Receipt, digest_of, unchanged};
use crate::paths::{Paths, SetupPaths};

use super::status::{Mark, Style, action, command, heading, note, row, verbatim};

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
        problems += step_skill(request, out, &mut receipt)?;
    }
    problems += step_daemon(request, out, err)?;

    receipt.written_at = crate::time::rfc3339_utc(crate::time::now_unix_millis());
    receipt.tool_version = env!("CARGO_PKG_VERSION").to_owned();
    receipt.save(&request.setup.receipt)?;

    heading(out, style, "WHAT SETUP CANNOT DO")?;
    note(
        out,
        style,
        "A store credential is per-person and this command cannot mint one. \
         Infisical needs `infisical login` against your own account. Proton \
         needs `pass-cli login` into a session directory that does not copy \
         between machines or accounts.",
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
        "the guards stop firing, instantly. Nothing is deleted.",
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

/// Where the binaries are, and whether the one on `PATH` is the one running.
///
/// Reports and never writes. Placing a binary is `cargo install` or
/// `install/install.sh`, and a setup verb that copied itself somewhere would be
/// installing a second copy nobody asked for and nothing tracks.
fn step_binaries(request: &SetupRequest<'_>, out: &mut dyn Write) -> io::Result<u32> {
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
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Detect the stores, and write the config when there is none.
fn step_config(
    request: &SetupRequest<'_>,
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
    receipt: &mut Receipt,
) -> io::Result<u32> {
    let style = request.style;
    let existed = request.paths.config.exists();
    let init_request = super::init::InitRequest {
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
    let code = super::init::init(&init_request, stdin, out, err)?;

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
fn step_guards(
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

/// Where the agent instructions live.
fn skill_file(setup: &SetupPaths) -> PathBuf {
    setup
        .claude_dir
        .join("skills")
        .join(crate::NAME)
        .join("SKILL.md")
}

/// The agent instructions, and why there are so few of them.
///
/// Every line here had to survive one question: **could this have been designed
/// away instead?** Most could, and were:
///
/// - "there is no verb that prints a value" teaches itself — `keyless get`
///   answers with the reason rather than an unknown-subcommand error.
/// - "do not `cat` a `.env`" teaches itself — the guard refuses the read and
///   names the working command in the same breath.
/// - "quote the body and keep it inside `sh -c`" is now half a runtime warning:
///   an unexpanded `$NAME` handed to a program that is not a shell is reported
///   by `run` itself, at the moment it happens, naming the corrected line.
///
/// What is left is the half no design can remove: a `run` whose credential did
/// not resolve is INDISTINGUISHABLE from a successful one by exit code, because
/// the exit code belongs to the child and this tool refuses to invent one.
/// There is no mechanism that can teach that at the moment it matters, because
/// at that moment nothing has gone wrong yet.
const SKILL: &str = concat!(
    "---\n",
    "name: keyless\n",
    "description: >-\n",
    "  Use a credential without ever reading one. Load when a command needs an API key,\n",
    "  a token, a database URL or any other secret; when a `.env` or credential file read\n",
    "  is refused; or when a command fails to authenticate and the value came from a\n",
    "  secret store.\n",
    "---\n",
    "\n",
    "# keyless\n",
    "\n",
    "A named credential reaches one child process's environment and nothing else.\n",
    "You never receive the value, and this transcript never contains it.\n",
    "\n",
    "```\n",
    "keyless run -s DATABASE_URL -- psql\n",
    "keyless run -s GITHUB_TOKEN -- gh pr list\n",
    "keyless ls                                 the names you can use\n",
    "```\n",
    "\n",
    "## The one thing no error will tell you\n",
    "\n",
    "**`keyless run` never refuses to run your command.** A name that does not\n",
    "resolve is a warning on stderr, and the child runs with an untouched\n",
    "environment — so a missing credential arrives as your program's own 401, at\n",
    "your program's own exit code.\n",
    "\n",
    "**So the exit code cannot tell you the credential arrived. Read stderr for\n",
    "`DEGRADED`.** Exit 0 with a `DEGRADED` banner means the command ran without\n",
    "the secret.\n",
    "\n",
    "## Quoting\n",
    "\n",
    "The variable is set in the CHILD, so only the child's own shell can expand it:\n",
    "\n",
    "```\n",
    "keyless run -s TOKEN -- sh -c 'curl -H \"Authorization: Bearer $TOKEN\" $URL'\n",
    "```\n",
    "\n",
    "Single-quote the body. Double quotes let YOUR shell expand `$TOKEN` first,\n",
    "where it is unset, and an empty credential is sent instead of a missing one.\n",
    "\n",
    "## There is no way to see the value\n",
    "\n",
    "No verb prints one, no flag prints one, and none is coming. If a command\n",
    "needs the credential, run that command under `keyless run`.\n",
    "\n",
    "*Installed by `keyless setup`. `keyless uninstall` removes it.*\n"
);

/// Write the agent instructions, or leave a file somebody else has taken over.
fn step_skill(
    request: &SetupRequest<'_>,
    out: &mut dyn Write,
    receipt: &mut Receipt,
) -> io::Result<u32> {
    let style = request.style;
    heading(out, style, "AGENT INSTRUCTIONS")?;
    let path = skill_file(request.setup);

    if !request.setup.claude_dir.is_dir() {
        row(
            out,
            style,
            Mark::Off,
            "skill",
            SUBJECT,
            "off",
            "no agent harness here, so there is nothing that would load them.",
        )?;
        return Ok(0);
    }

    let wanted = digest_of(SKILL.as_bytes());
    if path.exists() {
        let current = std::fs::read(&path).map(|bytes| digest_of(&bytes)).ok();
        if current.as_deref() == Some(wanted.as_str()) {
            row(
                out,
                style,
                Mark::Proven,
                "skill",
                SUBJECT,
                "proven",
                &format!("{} is already what this version installs", path.display()),
            )?;
            return Ok(0);
        }
        let ours = receipt
            .file(&path)
            .is_some_and(|record| current.as_deref() == Some(record.sha256.as_str()));
        if !ours {
            // Somebody edited it, or wrote their own. Either way it is theirs
            // now, and replacing it would delete work with no way back.
            row(
                out,
                style,
                Mark::Off,
                "skill",
                SUBJECT,
                "off",
                &format!(
                    "{} exists and is not what setup wrote. It is left exactly as \
                     it is; nothing here overwrites a file somebody edited.",
                    path.display()
                ),
            )?;
            return Ok(0);
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let created = !path.exists();
    std::fs::write(&path, SKILL)?;
    receipt.record_file(FileRecord {
        path: path.clone(),
        created,
        sha256: wanted,
        remove_on_uninstall: true,
    });
    row(
        out,
        style,
        Mark::Proven,
        "skill",
        SUBJECT,
        "proven",
        &path.display().to_string(),
    )?;
    Ok(0)
}

/// Report the daemon, and stand it up when that was asked for.
///
/// The escalation is deliberate and it is the only one: creating a system user,
/// writing under `/usr/local` and bootstrapping a launch daemon are root acts,
/// and a setup verb that acquired root without being told to would be a worse
/// thing than the hole it closes. `--daemon` is that instruction, and `sudo`
/// asks the person directly.
fn step_daemon(
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
        "Your store sessions are untouched: an Infisical login and a Proton \
         session are credentials of yours, and removing a tool is not a reason \
         to invalidate them.",
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

#[cfg(test)]
mod tests {
    use super::{Guards, SKILL, guards, switch_guards};
    use crate::cmd::status::Style;
    use crate::paths::SetupPaths;
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
    fn the_skill_declares_the_two_fields_a_harness_needs() {
        assert!(SKILL.starts_with("---\nname: keyless\n"), "{SKILL}");
        assert!(SKILL.contains("\ndescription:"), "{SKILL}");
        assert!(SKILL.matches("---\n").count() >= 2, "{SKILL}");
    }

    #[test]
    fn the_agent_instructions_carry_no_value_and_no_off_switch() {
        // Two properties at once. The guards' off switch must not appear in
        // text an AGENT loads, because an agent that is being blocked will
        // reach for it — and neither may the words somebody would try in order
        // to print a value, because naming them is teaching them.
        for forbidden in ["disable", "--reveal", "KEYLESS_HOOKS_DISABLE"] {
            assert!(
                !SKILL.contains(forbidden),
                "the skill hands an agent `{forbidden}`"
            );
        }
    }
}
