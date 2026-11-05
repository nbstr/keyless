//! `keyless init` — from nothing to one proven store.
//!
//! # What this verb is NOT, and why the smaller shape is the honest one
//!
//! The obvious `init` is a wizard that asks what secrets you have and writes
//! them down. That verb cannot exist here, and the reason is worth stating
//! before the code:
//!
//! - **The config holds no secrets and is eight lines long.** Writing it was
//!   never the hard part, so an `init` whose product is the file solves the
//!   cheap half of the problem.
//! - **The expensive half is a per-person login this tool cannot perform.**
//!   `infisical login` and `pass-cli login` mint credentials against an
//!   account. `keyless` brokers credentials; it does not hold one it could log
//!   in with, and driving a vendor's interactive login from inside a broker
//!   would put an unattended prompt in the middle of a program whose entire
//!   contract is that it never blocks.
//! - **`init` cannot know a single one of your `secrets` coordinates.** Which
//!   vault, which item, which field, which environment — every one of those is
//!   a fact about your account. A form asking for them is a form nobody can
//!   fill in, and a guessed answer resolves a name against the wrong tenant,
//!   which is the exact failure `stores.default` exists to prevent.
//!
//! So `init`'s product is **the first proven row**, and the config file is a
//! byproduct of getting there. It detects what is installed, proves what it can
//! prove, writes the smallest config that makes that provable thing the default,
//! and hands the `secrets` half off to `items` and `fields` — two verbs that
//! already discover coordinates without ever reading a value.
//!
//! Exactly one backend can go from nothing to proven with no input from anybody:
//! the **keychain**. It is already on the machine, it needs no login, and its
//! read path can be proven against an item that does not exist. That is why it
//! is the default this verb writes, and it is the same path the README's first
//! five minutes takes.
//!
//! # Never a prompt this process cannot escape
//!
//! `init` asks at most one question, and only when stdin and stdout are both
//! terminals. Every other path is decided from flags or from what was detected.
//! A blocked prompt in CI is not a nuisance here, it is the never-block
//! invariant broken by the one verb that was allowed to be interactive.
//!
//! # The guards, and why they are a step rather than a side effect
//!
//! **The complete install is [`crate::cmd::setup`], and it is what a stranger
//! runs.** This verb is the config half of it, kept as its own word because
//! writing a `stores` block is a thing people want on its own. It reports the
//! guards and installs them under `--hooks`; it does not install the agent
//! instructions and it does not stand up the daemon.
//!
//! It is a NAMED step rather than a silent one, for two reasons that are not
//! symmetric with writing a config:
//!
//! - The config file belongs to `keyless`. `~/.claude/settings.json` belongs to
//!   **another program**, and a secrets broker that edits a neighbour's
//!   configuration without being asked is doing the thing this tool exists to
//!   argue against.
//! - Not everybody running `keyless` runs Claude Code at all, and for them the
//!   write has no meaning and the file has no business existing.
//!
//! So `init` REPORTS the pack as a row — present, absent, or unreachable — and
//! installs it when `--hooks` says to. `hooks/install.py` does the write, and it
//! already refuses to overwrite blindly, refuses outright to touch a settings
//! file it cannot parse, re-parses the merged file before replacing the original
//! through an atomic rename, and is idempotent in both directions. Nothing here
//! re-implements any of that; this verb finds the script, runs it, and prints
//! what it said, verbatim.
//!
//! # Never a GUI dialog
//!
//! Detection runs the same store health checks `doctor` runs, and those refuse
//! to spawn `security` when this `HOME` has no keychain — see
//! [`crate::store::keychain`]. A modal window with a **Reset To Defaults** button
//! is not a failure mode a setup command may have.

use std::io::{self, BufRead, Write};

use crate::config::Config;
use crate::paths::Paths;

use super::status::{Mark, Style, action, heading, row, verbatim};

mod body;
mod choose;
mod hooks;
mod next_steps;
mod probe;

#[cfg(test)]
mod body_tests;
#[cfg(test)]
mod choose_tests;
#[cfg(test)]
mod existing_config_tests;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod probe_tests;

/// What `init` found out about one backend, without asking anybody anything.
pub struct Finding {
    /// The backend name, as it appears in the config and in `doctor`.
    ///
    /// Not called `id`: a published-source gate reads `id:` as a store
    /// coordinate marker, and every literal in this file would land in its
    /// offender list. The field names the same thing either way.
    pub store: &'static str,
    /// How far it was proven.
    pub mark: Mark,
    /// The state word. Same closed vocabulary as [`crate::cmd::status`].
    pub state: &'static str,
    /// What was observed. Never a value; nothing here reads one.
    pub detail: String,
    /// What a person does next to move this row forward.
    pub next: Option<String>,
}

impl Finding {
    /// Whether `init` can write this backend into a config and expect it to work.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.mark == Mark::Proven
    }
}

/// Everything `init` needs that is not the terminal it writes to.
pub struct InitRequest<'a> {
    /// Where the config would be written.
    pub paths: &'a Paths,
    /// Replace an existing config's store choice, keeping its declared
    /// secrets.
    pub force: bool,
    /// Take the detected answer without asking. Required when there is a
    /// question and no terminal to ask it on.
    pub assume_yes: bool,
    /// Write this backend as the default, rather than deciding.
    pub only: Option<&'a str>,
    /// Whether a question may be asked at all: stdin AND stdout are terminals.
    pub interactive: bool,
    /// Install the hook pack into the Claude Code settings file.
    pub install_hooks: bool,
    /// Whether to report the guards at all.
    ///
    /// `false` when [`crate::cmd::setup`] is driving, because that verb owns the
    /// guards step and resolves the settings file properly — honouring
    /// `--claude-dir`, which this verb does not. Left on, the two disagreed in
    /// the worst possible way: a `setup` aimed at one directory printed a green
    /// guards row about the DEFAULT one, so the report described a machine the
    /// command was not touching.
    pub report_guards: bool,
    /// Colour and character set.
    pub style: Style,
}

/// Exit code for "this needs an answer and there is nobody to ask".
///
/// `EX_USAGE`, because the fix is a flag on the command line. Deliberately not a
/// hang and deliberately not a guess.
pub const EXIT_NEEDS_AN_ANSWER: i32 = 64;

/// Detect, decide, write, and prove.
///
/// # Errors
///
/// A write failure on `out`, or a failure to create or write the config file.
pub fn init(
    request: &InitRequest<'_>,
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<i32> {
    let style = request.style;
    // The config the rest of this machine reads, so DETECTED describes THIS
    // machine rather than a hypothetical empty one. `load` never fails: an
    // absent file gives the defaults, which is what a fresh install is.
    let loaded = crate::config::Config::load(&request.paths.config);
    let findings = detect(&loaded.config);

    writeln!(
        out,
        "{} {}   {}",
        crate::NAME,
        env!("CARGO_PKG_VERSION"),
        request.paths.config.display()
    )?;

    heading(out, style, "DETECTED")?;
    // A file that exists and will not parse is the one case where the rows
    // below are about the defaults again. Said out loud, because the whole
    // point of reading the config was that a row must never quietly describe a
    // machine other than this one.
    if let Some(problem) = &loaded.problem {
        row(
            out,
            style,
            Mark::Broken,
            "config",
            6,
            "broken",
            &format!(
                "{problem}. Every row below therefore describes a machine with no \
                 config, not yours."
            ),
        )?;
    }
    let width = findings
        .iter()
        .map(|f| f.store.len())
        .max()
        .unwrap_or(6)
        .max(6);
    for finding in &findings {
        row(
            out,
            style,
            finding.mark,
            finding.store,
            width,
            finding.state,
            &finding.detail,
        )?;
        if let Some(next) = &finding.next {
            action(out, style, next)?;
        }
    }

    // 🔴 THE GUARDS ARE REPORTED BEFORE THE EARLY RETURN BELOW, and that order is
    // the whole of a bug this verb shipped with. The return fires whenever a
    // config already exists — which is every machine after the first run — so
    // `init --hooks` printed "already exists; nothing was written" and installed
    // nothing at all. The one flag that closes the guards hole was reachable
    // only on a machine that had never run this verb.
    if request.report_guards {
        hooks::report_hooks(request, out, err)?;
    }

    // An existing config is never rewritten by accident. Running `init` twice is
    // safe, and the second run is still useful: it re-detects and re-proves, so
    // it answers "is my setup still good?" without touching anything.
    let existing = request.paths.config.exists();
    if existing && !request.force {
        heading(out, style, "CONFIG")?;
        row(
            out,
            style,
            Mark::Proven,
            "config",
            width,
            "proven",
            "already exists; nothing was written",
        )?;
        action(
            out,
            style,
            &format!(
                "{} doctor  reads it and checks every store; \
                 `{} init --force` would replace it",
                crate::NAME,
                crate::NAME
            ),
        )?;
        return Ok(0);
    }

    // `--force` is the escape hatch from the guard above, and its own promise
    // is "replace an existing config file" — the store choice, not the names
    // declared under it. Reading the declared secrets before they are
    // overwritten, and carrying them into the new body, is what keeps that
    // promise: a re-run to switch backends must not double as a silent wipe
    // of every `secrets` entry the user (or another tool reading this file)
    // already declared.
    let preserved = if existing {
        Config::load(&request.paths.config).config.secrets
    } else {
        std::collections::BTreeMap::new()
    };

    let usable: Vec<&Finding> = findings.iter().filter(|f| f.is_usable()).collect();
    let chosen = match choose::choose(request, &usable, stdin, out, err)? {
        choose::Choice::Backend(id) => id,
        choose::Choice::Stop(code) => return Ok(code),
    };

    let body = body::with_preserved_secrets(&body::render(chosen), &preserved);
    if let Some(parent) = request.paths.config.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&request.paths.config, &body)?;
    if !preserved.is_empty() {
        heading(out, style, "CONFIG")?;
        row(
            out,
            style,
            Mark::Proven,
            "secrets",
            width,
            "proven",
            &format!(
                "{} declared name(s) carried over from the replaced file",
                preserved.len()
            ),
        )?;
    }

    heading(out, style, "WRITTEN")?;
    row(
        out,
        style,
        Mark::Proven,
        "config",
        width,
        "proven",
        &request.paths.config.display().to_string(),
    )?;
    for line in body.lines() {
        verbatim(out, style, line)?;
    }

    next_steps::next_steps(chosen, &findings, style, out)?;
    Ok(0)
}

/// The backends this verb knows how to write, in the order it prefers them.
///
/// The order is "how much does this need from the user", cheapest first. The
/// keychain is on the machine already and needs no login; Infisical needs a
/// login and a project; 1Password needs a login and the name of one vault;
/// Proton needs a login and a session directory that has no safe default.
const KNOWN: [&str; 4] = ["keychain", "infisical", "onepassword", "proton"];

/// Probe each backend on its own, against the config that will actually be used.
///
/// Each candidate is built as the ONLY store enabled, which is what makes the
/// answers independent: with several enabled at once an ambiguous route would
/// decide the outcome of a detection that is supposed to be about installation.
///
/// 🚨 **ISOLATING A BACKEND MEANS TURNING THE OTHERS OFF — IT NEVER MEANT
/// DISCARDING THE COORDINATES.** This built each candidate from a literal
/// `{"stores": {...}}` string instead, so every probe ran against a config with
/// no `secrets`, no `project_id` and no `session_dir`. Two consequences, and the
/// second is worse than the first:
///
/// - The rows were FALSE on a configured machine, and `doctor` — same binary,
///   same file, seconds later — contradicted them. DETECTED said "no Infisical
///   environment is declared anywhere" about a config declaring four, and
///   "`stores.proton.session_dir` is not set" about one that sets it.
/// - Infisical and Proton could therefore never reach `proven`, on ANY machine.
///   `health_coordinates` needs an `env` off a declared name and `session_dir`
///   needs the key, and the throwaway config had neither by construction. So
///   [`choose::choose`] never saw them as usable, and detection could only ever offer
///   the keychain.
///
/// Given the real config, the rows say what this machine can do and agree with
/// `doctor` because both read the same file. With no config file at all,
/// `Config::default()` is exactly the old behaviour, so a fresh machine reports
/// what it always did.
#[must_use]
pub fn detect(base: &Config) -> Vec<Finding> {
    KNOWN.iter().map(|id| probe::probe_one(base, id)).collect()
}
