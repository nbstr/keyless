//! `keyless setup` and the two ways out, driven against the built binary.
//!
//! # Why these are end-to-end and not unit tests
//!
//! Every claim here is about files on a disk — which ones are created, which
//! survive, which come back. A unit test proves a function computed a plan; it
//! cannot prove the plan reached the filesystem, and the defect this whole verb
//! exists to fix was precisely that: two installers, each correct on its own,
//! and nothing that put both on one machine.
//!
//! # How a fresh machine is simulated, and why not by moving `HOME`
//!
//! Every path this verb touches is nameable — `--config`, `--claude-dir`,
//! `--receipt`, and `XDG_CONFIG_HOME` for the guards' switch — so a run can be
//! aimed entirely inside a scratch directory while `HOME` stays exactly where it
//! is.
//!
//! **`HOME` is deliberately NOT redirected.** On macOS a process that runs with
//! a rewritten `HOME` and then touches the keychain gets a modal dialog — with a
//! destructive **Reset To Defaults** button — on the screen of whoever happens to
//! be logged in. A test suite may not do that, so the isolation is explicit
//! paths rather than a moved home directory.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::scratch;

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// A machine: a config, a receipt, an agent directory, and the guards' switch.
struct Machine {
    root: PathBuf,
}

impl Machine {
    fn fresh(tag: &str) -> Machine {
        Machine { root: scratch(tag) }
    }

    fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    fn receipt(&self) -> PathBuf {
        self.root.join("setup-receipt.json")
    }

    fn claude(&self) -> PathBuf {
        self.root.join("claude")
    }

    fn settings(&self) -> PathBuf {
        self.claude().join("settings.json")
    }

    /// Run the binary with every path pointed inside this machine.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .arg("--config")
            .arg(self.config())
            .arg("--audit")
            .arg(self.root.join("audit.jsonl"))
            // The guards' switch is resolved from XDG like everything else, so
            // this is what keeps `disable` out of the real one.
            .env("XDG_CONFIG_HOME", self.root.join("xdg-config"))
            .env("XDG_STATE_HOME", self.root.join("xdg-state"))
            .env("NO_COLOR", "1")
            .env("KEYLESS_ASCII", "1")
            .output()
            .expect("the binary must run")
    }

    /// A setup run, with the agent directory and receipt named explicitly.
    fn setup(&self, extra: &[&str]) -> Output {
        let claude = self.claude();
        let receipt = self.receipt();
        let mut args = vec![
            "setup",
            "--claude-dir",
            claude.to_str().expect("utf-8"),
            "--receipt",
            receipt.to_str().expect("utf-8"),
            "--store",
            "keychain",
            "--yes",
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    fn uninstall(&self) -> Output {
        let claude = self.claude();
        let receipt = self.receipt();
        self.run(&[
            "uninstall",
            "--claude-dir",
            claude.to_str().expect("utf-8"),
            "--receipt",
            receipt.to_str().expect("utf-8"),
        ])
    }

    /// Give this machine an agent harness, holding `settings`.
    fn with_harness(self, settings: &str) -> Machine {
        std::fs::create_dir_all(self.claude()).expect("mkdir");
        std::fs::write(self.settings(), settings).expect("write settings");
        self
    }

    fn settings_json(&self) -> serde_json::Value {
        let text = std::fs::read_to_string(self.settings()).expect("settings must exist");
        serde_json::from_str(&text).expect("settings must parse")
    }
}

fn out(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The state column of the rendered row whose subject column says `subject`:
/// `<mark> <subject> <state> <detail>`.
///
/// Read as a whole column, because `unproven` CONTAINS `proven` — so
/// `contains("proven")` passes on the one state it exists to exclude. Measured
/// over this tree: every `proven` in the crate can be rewritten to `unproven`,
/// leaving a green mark beside the word that denies it, and the suite stays
/// green.
fn state_of(text: &str, subject: &str) -> String {
    text.lines()
        .find(|line| line.split_whitespace().nth(1) == Some(subject))
        .unwrap_or_else(|| panic!("no `{subject}` row in:\n{text}"))
        .split_whitespace()
        .nth(2)
        .unwrap_or_default()
        .to_owned()
}

// ---------------------------------------------------------------------------
// one command, and then the same command again
// ---------------------------------------------------------------------------

#[test]
fn setup_installs_everything_and_names_every_file_it_touches() {
    let machine = Machine::fresh("setup-complete").with_harness("{}");
    let first = machine.setup(&[]);
    let text = out(&first);

    // Named BEFORE anything is touched. A setup command that edits another
    // program's configuration without saying which file is doing the thing this
    // tool exists to argue against.
    for named in [
        machine.config().display().to_string(),
        machine.settings().display().to_string(),
        machine.receipt().display().to_string(),
    ] {
        assert!(text.contains(&named), "`{named}` is not named:\n{text}");
    }

    assert!(
        machine.receipt().exists(),
        "no receipt was written:\n{text}"
    );
    let settings = machine.settings_json();
    assert!(
        settings["hooks"]["PreToolUse"].is_array(),
        "the guards were not registered:\n{text}"
    );
    assert!(
        machine
            .claude()
            .join("skills")
            .join("keyless")
            .join("SKILL.md")
            .exists(),
        "the agent instructions were not installed:\n{text}"
    );
}

#[test]
fn a_second_run_changes_nothing_and_says_so() {
    let machine = Machine::fresh("setup-twice").with_harness("{}");
    machine.setup(&[]);
    let after_first = std::fs::read_to_string(machine.settings()).expect("read");

    let second = machine.setup(&[]);
    let text = out(&second);
    assert!(second.status.success(), "the second run failed:\n{text}");
    assert!(
        text.contains("already"),
        "the second run does not say it was a no-op:\n{text}"
    );
    assert_eq!(
        std::fs::read_to_string(machine.settings()).expect("read"),
        after_first,
        "the second run rewrote the settings file"
    );
}

// ---------------------------------------------------------------------------
// the way out
// ---------------------------------------------------------------------------

#[test]
fn uninstall_removes_what_setup_made_and_keeps_what_the_user_wrote() {
    // The planted setting is the whole case. `Bash(keyless ls:*)` is a rule this
    // pack SHIPS, and the user wrote it first: the install correctly adds
    // nothing, and an uninstall that matched against the shipped list rather
    // than a record of what it added would delete it anyway.
    let machine = Machine::fresh("uninstall-keeps").with_harness(
        r#"{
             "model": "opus",
             "permissions": { "allow": ["Bash(keyless ls:*)", "Bash(git status:*)"] }
           }"#,
    );
    machine.setup(&[]);
    let installed = machine.settings_json();
    assert!(
        installed["hooks"]["PreToolUse"].is_array(),
        "nothing was installed, so the removal proves nothing"
    );

    let removed = machine.uninstall();
    let text = out(&removed);
    assert!(removed.status.success(), "{text}");

    let after = machine.settings_json();
    assert!(
        after.get("hooks").is_none(),
        "the handlers were left behind:\n{after:#}"
    );
    let allow = after["permissions"]["allow"]
        .as_array()
        .expect("the user's own allow list must survive");
    for kept in ["Bash(keyless ls:*)", "Bash(git status:*)"] {
        assert!(
            allow.iter().any(|rule| rule == kept),
            "uninstall removed `{kept}`, which the user wrote:\n{after:#}"
        );
    }
    assert_eq!(after["model"], "opus", "an unrelated setting was lost");
    assert!(
        !machine.receipt().exists(),
        "the receipt outlived the uninstall"
    );

    // THE CONTROL. Without it every assertion above passes on an uninstall that
    // removes nothing at all.
    assert!(
        allow.iter().all(|rule| rule != "Bash(keyless doctor:*)"),
        "a rule the pack installed was not removed:\n{after:#}"
    );
}

#[test]
fn uninstall_keeps_the_config_and_says_which_files_it_kept() {
    let machine = Machine::fresh("uninstall-keeps-config").with_harness("{}");
    machine.setup(&[]);
    assert!(machine.config().exists(), "setup wrote no config");

    let text = out(&machine.uninstall());
    assert!(
        machine.config().exists(),
        "uninstall deleted the user's configuration:\n{text}"
    );
    assert!(
        text.contains("LEFT BEHIND"),
        "uninstall does not say what it kept:\n{text}"
    );
}

#[test]
fn uninstall_with_no_receipt_removes_nothing_and_says_why() {
    let machine = Machine::fresh("uninstall-bare").with_harness(
        r#"{"hooks": {"PreToolUse": [{"hooks": [{"type":"command","command":"python3 /elsewhere/keyless_hook.py"}]}]}}"#,
    );
    let before = std::fs::read_to_string(machine.settings()).expect("read");
    let output = machine.uninstall();
    let text = out(&output);
    assert!(output.status.success(), "{text}");
    assert_eq!(
        std::fs::read_to_string(machine.settings()).expect("read"),
        before,
        "an uninstall with no record still edited a settings file"
    );
    assert!(
        text.contains("no record") || text.contains("does not exist"),
        "{text}"
    );
}

// ---------------------------------------------------------------------------
// the machine with no agent harness at all
// ---------------------------------------------------------------------------

#[test]
fn a_machine_with_no_harness_installs_cleanly_and_reports_what_it_skipped() {
    // `keyless` is a general tool. Most machines running it have no agent
    // harness, and inventing one for them — creating another program's config
    // directory on the chance it might want one — is the same overreach this
    // whole verb is careful about in the other direction.
    let machine = Machine::fresh("no-harness");
    let output = machine.setup(&[]);
    let text = out(&output);

    assert!(
        output.status.success(),
        "a machine with no harness failed to install:\n{text}"
    );
    assert!(
        !machine.claude().exists(),
        "setup created an agent directory on a machine that has no agent"
    );
    assert!(
        machine.config().exists(),
        "the parts that do not need an agent were skipped too:\n{text}"
    );
    assert!(
        text.contains("no agent harness"),
        "the skip was silent:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// the off switch
// ---------------------------------------------------------------------------

#[test]
fn disable_stops_the_guards_and_doctor_says_so_and_enable_undoes_it() {
    // The safety property. Somebody who cannot find the switch guts their
    // settings file by hand instead, and then the protection is gone silently.
    let machine = Machine::fresh("disable").with_harness("{}");
    machine.setup(&[]);

    let armed = out(&machine.run(&["doctor"]));
    assert!(
        armed.contains("GUARDS"),
        "doctor has no guards row:\n{armed}"
    );

    let off = out(&machine.run(&["disable"]));
    assert_eq!(state_of(&off, "guards"), "off", "{off}");
    // Nothing was unregistered: the pack is still in the settings file, and the
    // switch is one key in a file `keyless` owns.
    assert!(
        machine.settings_json()["hooks"]["PreToolUse"].is_array(),
        "disable unregistered the pack instead of switching it off"
    );

    let sick = out(&machine.run(&["doctor"]));
    assert!(
        sick.contains("SWITCHED OFF"),
        "a disabled install reports healthy, which is the worst false green \
         available here:\n{sick}"
    );

    let on = out(&machine.run(&["enable"]));
    assert_eq!(state_of(&on, "guards"), "proven", "{on}");
    let healthy = out(&machine.run(&["doctor"]));
    assert!(
        !healthy.contains("SWITCHED OFF"),
        "enable did not re-arm them:\n{healthy}"
    );
}

#[test]
fn disable_works_before_anything_has_been_set_up() {
    // A tilted user has not necessarily run setup, and the off switch that only
    // works on a configured machine is the one that is missing when it matters.
    let machine = Machine::fresh("disable-bare");
    let output = machine.run(&["disable"]);
    assert!(output.status.success(), "{}", out(&output));
    let switch = machine
        .root
        .join("xdg-config")
        .join("keyless")
        .join("hooks.json");
    assert!(switch.exists(), "no switch file was written");
    let text = std::fs::read_to_string(&switch).expect("read");
    assert!(text.contains("\"enabled\""), "{text}");
    // And the pack itself reads exactly that file, so the two agree. Asserted
    // through the pack's own loader rather than by eye.
    assert!(pack_reads_disabled(&switch), "{text}");
}

/// Ask the hook pack's own config loader whether it considers itself off.
///
/// The one assertion in this file that crosses the language boundary, and it is
/// the one that matters most: a switch `keyless` writes and the pack does not
/// read is a kill switch that kills nothing, and every other test here would
/// still pass.
fn pack_reads_disabled(switch: &Path) -> bool {
    let hooks = Path::new(env!("CARGO_MANIFEST_DIR")).join("hooks");
    let program = "import sys; from keyless_hooks.config import load; \
                   print('disabled' if not load().enabled else 'armed')";
    let output = Command::new("python3")
        .arg("-c")
        .arg(program)
        .env("PYTHONPATH", &hooks)
        .env("KEYLESS_HOOKS_CONFIG", switch)
        .output()
        .expect("python3 must run");
    String::from_utf8_lossy(&output.stdout).contains("disabled")
}

// ---------------------------------------------------------------------------
// the plan, before the act
// ---------------------------------------------------------------------------

#[test]
fn a_dry_run_names_every_file_and_writes_none_of_them() {
    let machine = Machine::fresh("dry-run").with_harness("{}");
    let before = std::fs::read_to_string(machine.settings()).expect("read");
    let text = out(&machine.setup(&["--dry-run"]));

    assert!(
        text.contains(&machine.settings().display().to_string()),
        "{text}"
    );
    assert!(!machine.config().exists(), "a dry run wrote the config");
    assert!(!machine.receipt().exists(), "a dry run wrote the receipt");
    assert_eq!(
        std::fs::read_to_string(machine.settings()).expect("read"),
        before,
        "a dry run edited the settings file"
    );
}

// ---------------------------------------------------------------------------
// what the receipt is allowed to say
// ---------------------------------------------------------------------------

#[test]
fn a_guard_registered_by_hand_survives_setup_and_uninstall() {
    // The measured defect, at the level a person meets it. A machine that
    // registered this pack by hand months ago hands `setup` a PreToolUse
    // handler it did not create. `setup` correctly adds none — and the receipt
    // recorded the event anyway, so `uninstall` walked that record and stripped
    // a registration nobody here installed.
    //
    // The receipt is written between the two commands, which is why this is end
    // to end and not a unit test of the merge: the claim lived in the file.
    let theirs = "python3 /theirs/keyless_hook.py";
    let machine = Machine::fresh("preexisting-guard").with_harness(&format!(
        r#"{{"hooks": {{"PreToolUse": [{{"hooks": [
             {{"type": "command", "command": "{theirs}"}}]}}]}}}}"#
    ));

    let installed = out(&machine.setup(&[]));
    let receipt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(machine.receipt()).expect("a receipt"))
            .expect("the receipt must parse");
    assert_eq!(
        receipt["claude"]["events"],
        serde_json::json!(["PostToolUse"]),
        "the receipt claimed an event setup did not register\n{installed}"
    );

    let removed = out(&machine.uninstall());
    let after = machine.settings_json();
    assert_eq!(
        after["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        serde_json::json!(theirs),
        "uninstall deleted a registration setup never created\n{removed}"
    );
    // THE CONTROL. Without it this passes on an uninstall that has quietly
    // stopped removing handlers at all, which would be the opposite defect.
    assert!(
        after["hooks"].get("PostToolUse").is_none(),
        "uninstall left behind the handler it DID install\n{after:#}"
    );
}

// ---------------------------------------------------------------------------
// what DETECTED is allowed to say
// ---------------------------------------------------------------------------

#[test]
fn detected_reads_the_config_this_machine_actually_uses() {
    // DETECTED probed each backend inside a config built from a literal string,
    // so every probe ran with no `secrets`, no `project_id` and no
    // `session_dir`. Two things followed, and this pins both:
    //
    // - the rows were FALSE on a configured machine — "no Infisical environment
    //   is declared anywhere" about a config declaring one — and `doctor`, same
    //   binary and same file, contradicted them.
    // - Infisical and Proton could never reach `proven` at all, on any machine,
    //   so `init` could only ever offer the keychain as a default.
    //
    // Both stores answer here, so `proven` is reachable and is the assertion.
    let machine = Machine::fresh("detected-reads-the-config");
    let session = machine.root.join("proton-session");
    std::fs::create_dir_all(&session).expect("mkdir");
    let infisical = support::stub_infisical(&machine.root, &support::Backend::Injects("probe"));
    let pass_cli = support::stub_pass_cli_discovery(
        &machine.root,
        r#"{"vaults":[{"name":"personal","id":"V1"}]}"#,
        "{}",
        "{}",
    );
    std::fs::write(
        machine.config(),
        format!(
            r#"{{"stores": {{
                 "keychain": {{"enabled": false}},
                 "infisical": {{"enabled": true, "binary": "{}", "project_id": "proj"}},
                 "proton": {{"enabled": true, "binary": "{}", "session_dir": "{}"}},
                 "default": "infisical"
               }},
               "secrets": {{"DECOY": {{"store": "infisical", "env": "staging"}}}}}}"#,
            infisical.display(),
            pass_cli.display(),
            session.display()
        ),
    )
    .expect("write config");

    let text = out(&machine.run(&["init"]));
    for store in ["infisical", "proton"] {
        assert_eq!(
            state_of(&text, store),
            "proven",
            "`{store}` cannot reach proven in DETECTED, whatever the config says\n{text}"
        );
    }
}
