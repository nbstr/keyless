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
//! already refuses to overwrite blindly, backs up before every write, re-parses
//! the merged file before replacing the original, and is idempotent in both
//! directions. Nothing here re-implements any of that; this verb finds the
//! script, runs it, and prints what it said, verbatim.
//!
//! # Never a GUI dialog
//!
//! Detection runs the same store health checks `doctor` runs, and those refuse
//! to spawn `security` when this `HOME` has no keychain — see
//! [`crate::store::keychain`]. A modal window with a **Reset To Defaults** button
//! is not a failure mode a setup command may have.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

use crate::config::Config;
use crate::paths::Paths;
use crate::store::{self, Invocation};

use super::status::{Mark, Style, action, command, heading, note, row, verbatim};

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
    /// Overwrite an existing config.
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
    let findings = detect();

    writeln!(
        out,
        "{} {}   {}",
        crate::NAME,
        env!("CARGO_PKG_VERSION"),
        request.paths.config.display()
    )?;

    heading(out, style, "DETECTED")?;
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
        report_hooks(request, out, err)?;
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

    let usable: Vec<&Finding> = findings.iter().filter(|f| f.is_usable()).collect();
    let chosen = match choose(request, &usable, stdin, out, err)? {
        Choice::Backend(id) => id,
        Choice::Stop(code) => return Ok(code),
    };

    let body = render(chosen);
    if let Some(parent) = request.paths.config.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&request.paths.config, &body)?;

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

    next_steps(chosen, &findings, style, out)?;
    Ok(0)
}

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
fn report_hooks(
    request: &InitRequest<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<()> {
    let style = request.style;
    heading(out, style, "GUARDS")?;

    let installer = match super::setup::hooks_installer() {
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
                "{} init --hooks   merges it in, after backing the file up",
                crate::NAME
            ),
        )?;
        return Ok(());
    }

    // The write itself belongs to the installer. It backs up, re-parses before
    // replacing, and is idempotent — so this runs it and repeats what it said
    // rather than deciding anything about a file it does not own.
    let output = std::process::Command::new("python3")
        .arg(&installer)
        .output();
    match output {
        Ok(done) if done.status.success() => {
            row(
                out,
                style,
                Mark::Proven,
                "hooks",
                9,
                "proven",
                &format!("installed by {}", installer.display()),
            )?;
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

/// What `choose` concluded.
enum Choice {
    /// Write this backend as the default.
    Backend(&'static str),
    /// Stop, with this exit code. Everything worth saying has been said.
    Stop(i32),
}

/// Decide which backend becomes `stores.default`, asking at most once.
///
/// The order is deliberate: an explicit `--store` wins outright, then a single
/// usable backend needs no question at all, then — and only then — a terminal is
/// asked. Every branch that would need an answer and cannot get one exits with
/// [`EXIT_NEEDS_AN_ANSWER`] and names the flag that supplies it.
fn choose(
    request: &InitRequest<'_>,
    usable: &[&Finding],
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<Choice> {
    let style = request.style;

    if let Some(id) = request.only {
        let Some(known) = KNOWN.iter().find(|known| **known == id) else {
            writeln!(
                err,
                "{}: `--store {id}` names no backend. This build has: {}",
                crate::NAME,
                KNOWN.join(", ")
            )?;
            return Ok(Choice::Stop(EXIT_NEEDS_AN_ANSWER));
        };
        // Written even when it did not prove, on purpose: `--store proton` from
        // somebody who is about to log in is a legitimate thing to ask for, and
        // refusing it would send them to a text editor to write the same six
        // lines by hand.
        return Ok(Choice::Backend(known));
    }

    match usable {
        [] => {
            heading(out, style, "NOTHING TO WRITE")?;
            note(
                out,
                style,
                "No backend proved a read path, so any config written now would \
                 describe a store that cannot answer.",
            )?;
            note(
                out,
                style,
                "Every row above says what it is waiting for. Take one of those \
                 steps and run this again,",
            )?;
            note(
                out,
                style,
                &format!(
                    "or write the config anyway with `{} setup --store <backend>`.",
                    crate::NAME
                ),
            )?;
            Ok(Choice::Stop(1))
        }
        [only] => Ok(Choice::Backend(only.store)),
        several => {
            let ids: Vec<&str> = several.iter().map(|f| f.store).collect();
            if request.assume_yes {
                // The detection order is the preference order, and `KNOWN` is
                // that order: the backend needing least of the user comes first.
                return Ok(Choice::Backend(several[0].store));
            }
            if !request.interactive {
                // Never a hang, never a guess. The one place this verb could
                // block is closed by a check, not by a timeout — a timeout
                // cannot tell "nobody is there" from "somebody is reading".
                writeln!(
                    err,
                    "{}: {} backends are usable ({}) and there is no terminal to ask on. \
                     Pass `--store <backend>` to pick one, or `--yes` to take `{}`.",
                    crate::NAME,
                    ids.len(),
                    ids.join(", "),
                    several[0].store
                )?;
                return Ok(Choice::Stop(EXIT_NEEDS_AN_ANSWER));
            }
            heading(out, style, "ONE QUESTION")?;
            note(
                out,
                style,
                "Which store should a name resolve against when it pins none?",
            )?;
            write!(out, "\n  [{}] > ", ids.join(" / "))?;
            out.flush()?;
            let mut answer = String::new();
            // A closed stdin returns 0 bytes rather than blocking, so the
            // `is_empty` branch below is the EOF case and not a silent default.
            if stdin.read_line(&mut answer)? == 0 {
                writeln!(
                    err,
                    "\n{}: stdin ended without an answer. Pass `--store <backend>` or `--yes`.",
                    crate::NAME
                )?;
                return Ok(Choice::Stop(EXIT_NEEDS_AN_ANSWER));
            }
            let answer = answer.trim();
            match several.iter().find(|f| f.store == answer) {
                Some(found) => Ok(Choice::Backend(found.store)),
                None if answer.is_empty() => Ok(Choice::Backend(several[0].store)),
                None => {
                    writeln!(
                        err,
                        "{}: `{answer}` is not one of {}. Nothing was written.",
                        crate::NAME,
                        ids.join(", ")
                    )?;
                    Ok(Choice::Stop(EXIT_NEEDS_AN_ANSWER))
                }
            }
        }
    }
}

/// The backends this verb knows how to write, in the order it prefers them.
///
/// The order is "how much does this need from the user", cheapest first. The
/// keychain is on the machine already and needs no login; Infisical needs a
/// login and a project; Proton needs a login and a session directory that has no
/// safe default.
const KNOWN: [&str; 3] = ["keychain", "infisical", "proton"];

/// Probe each backend on its own, so one bad one cannot mask another.
///
/// Each candidate is built as the ONLY store in a throwaway config, which is
/// what makes the answers independent: with several enabled at once an ambiguous
/// route would decide the outcome of a detection that is supposed to be about
/// installation.
#[must_use]
pub fn detect() -> Vec<Finding> {
    KNOWN.iter().map(|id| probe_one(id)).collect()
}

fn probe_one(id: &'static str) -> Finding {
    let config: Config = serde_json::from_str(&sole_store(id)).expect("a literal config");
    let built = store::build(&config, &Invocation::for_verb("init"));
    let Some(store) = built.registry.stores().first() else {
        return Finding {
            store: id,
            mark: Mark::Off,
            state: "off",
            detail: "this build did not construct the backend".to_owned(),
            next: None,
        };
    };

    match store.health() {
        Ok(()) => Finding {
            store: id,
            mark: Mark::Proven,
            state: "proven",
            detail: proven_detail(id),
            next: None,
        },
        Err(error) => {
            let (mark, state) = match error {
                // Not installed, not logged in, nothing to reach.
                crate::error::StoreError::Unavailable { .. } => (Mark::NotSetUp, "absent"),
                // Reachable in principle, and missing a coordinate only its
                // owner can supply. This is the normal answer for Infisical and
                // Proton on a fresh machine, and it is not a fault.
                crate::error::StoreError::Misconfigured { .. } => (Mark::NotSetUp, "config"),
                crate::error::StoreError::Backend { .. } => (Mark::Broken, "broken"),
            };
            Finding {
                store: id,
                mark,
                state,
                detail: match &error {
                    crate::error::StoreError::Unavailable { detail, .. }
                    | crate::error::StoreError::Backend { detail, .. }
                    | crate::error::StoreError::Misconfigured { detail, .. } => detail.clone(),
                },
                next: Some(setup_step(id)),
            }
        }
    }
}

/// A config with exactly one backend switched on.
fn sole_store(id: &str) -> String {
    let mut flags: BTreeMap<&str, bool> = KNOWN.iter().map(|known| (*known, false)).collect();
    flags.insert(id, true);
    let body: Vec<String> = flags
        .iter()
        .map(|(name, on)| format!("\"{name}\":{{\"enabled\":{on}}}"))
        .collect();
    format!("{{\"stores\":{{{}}}}}", body.join(","))
}

fn proven_detail(id: &str) -> String {
    match id {
        "keychain" => "the login keychain answered a search".to_owned(),
        "infisical" => "the CLI fetched a non-credential key".to_owned(),
        _ => "the session listed its vaults".to_owned(),
    }
}

/// The one step that moves a backend from "not yet" to usable.
fn setup_step(id: &str) -> String {
    match id {
        "keychain" => "the login keychain must be present and unlocked; \
                       open Keychain Access"
            .to_owned(),
        "infisical" => "`infisical login`, then add \"project_id\" under \
                        `stores.infisical` and an \"env\" on each name"
            .to_owned(),
        _ => "`pass-cli login` into a session directory, then set \
              `stores.proton.session_dir` to it"
            .to_owned(),
    }
}

/// The smallest config that makes `chosen` the store an unpinned name uses.
///
/// `secrets` is written empty rather than omitted, because the empty object is
/// the thing a reader edits next and an absent key is a thing they have to know
/// to add. There is no field here a value fits in; see [`crate::config`].
fn render(chosen: &str) -> String {
    let others: Vec<String> = KNOWN
        .iter()
        .filter(|id| **id != chosen)
        .map(|id| format!("    \"{id}\": {{ \"enabled\": false }},\n"))
        .collect();
    format!(
        "{{\n  \"stores\": {{\n{}    \"{chosen}\": {{ \"enabled\": true }},\n    \"default\": \"{chosen}\"\n  }},\n  \"secrets\": {{}}\n}}\n",
        others.concat()
    )
}

/// The path from a written config to a name that resolves.
///
/// Named commands rather than prose. The `secrets` half is handed to `items` and
/// `fields` because those are the verbs that discover coordinates without ever
/// reading a value — which is the same reason they exist at all.
fn next_steps(
    chosen: &str,
    findings: &[Finding],
    style: Style,
    out: &mut dyn Write,
) -> io::Result<()> {
    let name = crate::NAME;
    heading(out, style, "NEXT")?;
    if chosen == "keychain" {
        command(
            out,
            style,
            &format!("{name} new FIRST_SECRET"),
            "generates a credential and stores it, showing it to nobody",
        )?;
    } else {
        command(
            out,
            style,
            &format!("{name} items"),
            "lists what the store holds: titles and states, never a value",
        )?;
        command(
            out,
            style,
            &format!("{name} fields --item <TITLE>"),
            "lists that item's field names: never a value, never a length",
        )?;
    }
    command(
        out,
        style,
        &format!("{name} run -s NAME -- <cmd>"),
        "the only way a value ever leaves a store",
    )?;
    command(
        out,
        style,
        &format!("{name} doctor"),
        "what is proven right now, and what is not",
    )?;

    // The half no config can supply, said once, at the moment it becomes the
    // reader's next obstacle rather than buried in a README they have closed.
    let waiting: Vec<&str> = findings
        .iter()
        .filter(|f| !f.is_usable() && f.mark != Mark::Off)
        .map(|f| f.store)
        .collect();
    if !waiting.is_empty() {
        let subject = match waiting.as_slice() {
            [one] => format!("`{one}` is"),
            several => format!("`{}` are", several.join("` and `")),
        };
        note(
            out,
            style,
            &format!(
                "{subject} still waiting on a login only you can perform. \
                 Run `{name} setup` again afterwards."
            ),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{EXIT_NEEDS_AN_ANSWER, Finding, InitRequest, KNOWN, init, render, sole_store};
    use crate::cmd::status::{Mark, Style};
    use crate::paths::Paths;
    use std::io::Cursor;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-init-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn request<'a>(paths: &'a Paths, interactive: bool) -> InitRequest<'a> {
        InitRequest {
            paths,
            force: false,
            assume_yes: false,
            only: None,
            interactive,
            install_hooks: false,
            report_guards: true,
            style: Style::PLAIN,
        }
    }

    #[test]
    fn a_written_config_parses_as_a_config() {
        // The one property that makes the whole verb worth having: what it
        // writes must be loadable by the thing that reads it. A hand-built JSON
        // string is exactly the kind of output that looks right and is not.
        for chosen in KNOWN {
            let body = render(chosen);
            let config: crate::config::Config =
                serde_json::from_str(&body).unwrap_or_else(|e| panic!("{chosen}: {e}\n{body}"));
            assert_eq!(
                config.stores.default_store.as_deref(),
                Some(chosen),
                "{body}"
            );
            assert!(config.secrets.is_empty(), "{body}");
        }
    }

    #[test]
    fn the_written_config_enables_exactly_the_chosen_backend() {
        // Without this, the test above passes on a renderer that turns every
        // backend on — which would put an unpinned name back into the ambiguity
        // `stores.default` exists to remove.
        let config: crate::config::Config =
            serde_json::from_str(&render("keychain")).expect("valid");
        assert!(config.stores.keychain.enabled);
        assert!(!config.stores.infisical.enabled);
        assert!(!config.stores.proton.enabled);
    }

    #[test]
    fn the_detection_config_isolates_one_backend_at_a_time() {
        for id in KNOWN {
            let config: crate::config::Config =
                serde_json::from_str(&sole_store(id)).expect("valid");
            let on = crate::store::enabled_stores(&config);
            assert_eq!(on, vec![id], "detecting `{id}` enabled {on:?}");
        }
    }

    #[test]
    fn an_existing_config_is_never_clobbered_and_says_so() {
        let dir = scratch("idempotent");
        let paths = Paths::under(&dir);
        std::fs::create_dir_all(paths.config.parent().expect("a parent")).expect("mkdir");
        std::fs::write(&paths.config, "{\"secrets\":{\"MINE\":{}}}").expect("write");

        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let code = init(
            &request(&paths, false),
            &mut Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .expect("write");

        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
        assert_eq!(
            std::fs::read_to_string(&paths.config).expect("read"),
            "{\"secrets\":{\"MINE\":{}}}",
            "init overwrote a config it was not asked to touch"
        );
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("already exists"), "{text}");
        assert!(text.contains("--force"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_interactive_run_never_waits_for_an_answer() {
        // Two agents were killed by a stall watchdog today. A setup verb that
        // can block on a prompt in a pipeline is the same defect with a friendly
        // face — so the ambiguous case exits and names the flag rather than
        // reading a stdin nobody is attached to.
        let dir = scratch("no-tty");
        let paths = Paths::under(&dir);
        let usable = [
            Finding {
                store: "keychain",
                mark: Mark::Proven,
                state: "proven",
                detail: String::new(),
                next: None,
            },
            Finding {
                store: "proton",
                mark: Mark::Proven,
                state: "proven",
                detail: String::new(),
                next: None,
            },
        ];
        let refs: Vec<&Finding> = usable.iter().collect();

        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let choice = super::choose(
            &request(&paths, false),
            &refs,
            &mut Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .expect("write");
        match choice {
            super::Choice::Stop(code) => assert_eq!(code, EXIT_NEEDS_AN_ANSWER),
            super::Choice::Backend(id) => {
                panic!("a non-interactive run guessed `{id}` instead of asking for a flag")
            }
        }
        let text = String::from_utf8(err).expect("utf-8");
        assert!(text.contains("--store"), "{text}");
        assert!(text.contains("--yes"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_terminal_whose_stdin_ends_is_not_a_hang_either() {
        // The second shape of the same hazard: `interactive` is true because
        // both streams are terminals, and the answer never comes. `read_line`
        // returning zero is EOF, and EOF is an answer to act on — not a default
        // to silently take.
        let dir = scratch("eof");
        let paths = Paths::under(&dir);
        let usable = [
            Finding {
                store: "keychain",
                mark: Mark::Proven,
                state: "proven",
                detail: String::new(),
                next: None,
            },
            Finding {
                store: "proton",
                mark: Mark::Proven,
                state: "proven",
                detail: String::new(),
                next: None,
            },
        ];
        let refs: Vec<&Finding> = usable.iter().collect();
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let choice = super::choose(
            &request(&paths, true),
            &refs,
            &mut Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .expect("write");
        assert!(matches!(choice, super::Choice::Stop(EXIT_NEEDS_AN_ANSWER)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_usable_backend_is_never_a_question() {
        // The control for the two tests above. Without it they pass on an
        // implementation that refuses to decide anything at all, which would
        // make `init` useless on exactly the machine it is for.
        let dir = scratch("single");
        let paths = Paths::under(&dir);
        let usable = [Finding {
            store: "keychain",
            mark: Mark::Proven,
            state: "proven",
            detail: String::new(),
            next: None,
        }];
        let refs: Vec<&Finding> = usable.iter().collect();
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let choice = super::choose(
            &request(&paths, false),
            &refs,
            &mut Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .expect("write");
        assert!(matches!(choice, super::Choice::Backend("keychain")));
        assert!(String::from_utf8(err).expect("utf-8").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_usable_writes_nothing_and_says_what_it_is_waiting_for() {
        let dir = scratch("empty");
        let paths = Paths::under(&dir);
        let mut out: Vec<u8> = Vec::new();
        let mut err: Vec<u8> = Vec::new();
        let choice = super::choose(
            &request(&paths, false),
            &[],
            &mut Cursor::new(Vec::new()),
            &mut out,
            &mut err,
        )
        .expect("write");
        assert!(matches!(choice, super::Choice::Stop(1)));
        assert!(!paths.config.exists(), "a config was written with no store");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(text.contains("--store"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_init_writes_can_hold_a_value() {
        // The standing invariant, asserted against this verb's own output. The
        // config format has no field a value fits in, and this test exists so
        // that adding one is visibly a breaking change here.
        for chosen in KNOWN {
            let body = render(chosen);
            for forbidden in ["value", "secret\":", "password", "token"] {
                assert!(
                    !body.contains(forbidden),
                    "`init` wrote a `{forbidden}` field:\n{body}"
                );
            }
        }
    }
}
