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
//! # How a fresh machine is simulated
//!
//! A machine is a directory, and `HOME` is redirected into it for every run —
//! along with `--config`, `--audit`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME`.
//! Naming the paths a verb accepts as flags is not enough on its own: a verb
//! that takes no flag for a path still resolves it, and it resolves it from
//! `$HOME`. `keyless init` reads `~/.claude/settings.json` straight off `HOME`
//! and honours no override at all, and `doctor`'s guards row reads whatever
//! `--claude-dir` was not given to it. Both then report on the developer's own
//! machine while claiming to describe the scratch one, which is a green that
//! says nothing — the exact defect this suite exists to catch, wearing the
//! costume of a passing test.
//!
//! So the machine's agent directory lives at the default location *inside* the
//! machine's own home, and every path resolves there whether the verb under
//! test takes a flag for it or not.
//!
//! Redirecting `HOME` is safe against the keychain, which is the hazard that
//! would otherwise rule it out: on macOS a process that runs `security` against
//! a `HOME` with no login keychain gets a modal dialog — with a destructive
//! **Reset To Defaults** button — on the screen of whoever is logged in. The
//! keychain store refuses before it spawns anything when `$HOME/Library/
//! Keychains` is absent, which a scratch home always is, and it skips the check
//! entirely when the binary is one of this suite's stubs rather than the stock
//! `/usr/bin/security`. No run from here can reach the real binary with a real
//! home, so no run from here can raise that dialog.

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
        let machine = Machine { root: scratch(tag) };
        // Created rather than merely named: `HOME` pointing at nothing is a
        // fourth machine state that no real one has, and it makes every path
        // resolved from it unwritable for reasons the verb under test did not
        // cause.
        std::fs::create_dir_all(machine.home()).expect("mkdir");
        machine
    }

    /// This machine's home directory.
    ///
    /// Every run gets it as `HOME`, so a path resolved from the environment
    /// lands inside this machine instead of on the developer's own — see the
    /// module header for why naming the flags is not enough on its own.
    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    fn receipt(&self) -> PathBuf {
        self.root.join("setup-receipt.json")
    }

    /// The agent harness's directory, at the location a harness actually uses.
    ///
    /// Under this machine's home rather than beside it, so the path
    /// `--claude-dir` names and the path a verb resolves when nobody names one
    /// are the SAME directory. Split, the two disagree silently: `setup`
    /// installs into one and `doctor` reports on the other, and the report is
    /// green about a machine the command never touched.
    fn claude(&self) -> PathBuf {
        self.home().join(".claude")
    }

    fn settings(&self) -> PathBuf {
        self.claude().join("settings.json")
    }

    /// The agent instructions setup writes, at the path `setup` resolves.
    fn skill(&self) -> PathBuf {
        self.claude()
            .join("skills")
            .join("keyless")
            .join("SKILL.md")
    }

    /// The guards' own config — the one file `disable`, `enable` and `observe`
    /// live in, resolved from `XDG_CONFIG_HOME` exactly as the pack resolves it.
    fn switch(&self) -> PathBuf {
        self.root
            .join("xdg-config")
            .join("keyless")
            .join("hooks.json")
    }

    /// Run the binary with every path pointed inside this machine.
    fn run(&self, args: &[&str]) -> Output {
        self.run_with_path(args, None)
    }

    /// The same, with `first` prepended to `PATH`.
    ///
    /// Prepended rather than replacing it: `setup` runs the hook installer with
    /// `python3`, so a `PATH` built from scratch would break a step that has
    /// nothing to do with what the caller is aiming at.
    fn run_with_path(&self, args: &[&str], first: Option<&Path>) -> Output {
        let mut command = Command::new(BIN);
        command
            .args(args)
            .arg("--config")
            .arg(self.config())
            .arg("--audit")
            .arg(self.root.join("audit.jsonl"))
            // What confines the paths NO flag names: `init` resolves the
            // settings file from `HOME` alone, and `doctor` resolves the agent
            // directory from it whenever `--claude-dir` is absent.
            .env("HOME", self.home())
            // The guards' switch is resolved from XDG like everything else, so
            // this is what keeps `disable` out of the real one.
            .env("XDG_CONFIG_HOME", self.root.join("xdg-config"))
            .env("XDG_STATE_HOME", self.root.join("xdg-state"))
            .env("NO_COLOR", "1")
            .env("KEYLESS_ASCII", "1");
        if let Some(first) = first {
            let inherited = std::env::var_os("PATH").unwrap_or_default();
            let mut dirs = vec![first.to_path_buf()];
            dirs.extend(std::env::split_paths(&inherited));
            command.env("PATH", std::env::join_paths(dirs).expect("join PATH"));
        }
        command.output().expect("the binary must run")
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
        machine.skill().exists(),
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
    let switch = machine.switch();
    assert!(switch.exists(), "no switch file was written");
    let text = std::fs::read_to_string(&switch).expect("read");
    assert!(text.contains("\"enabled\""), "{text}");
    // And the pack itself reads exactly that file, so the two agree. Asserted
    // through the pack's own loader rather than by eye.
    assert_eq!(pack_reads(&switch), "disabled", "{text}");
}

/// Ask the hook pack's own config loader which of its three states it is in.
///
/// The one assertion in this file that crosses the language boundary, and it is
/// the one that matters most: a switch `keyless` writes and the pack does not
/// read is a kill switch that kills nothing, and every other test here would
/// still pass. The same argument applies to `observe`, which is the state where
/// every check runs and none of them blocks — a `doctor` that calls that armed
/// is telling somebody they are protected while nothing is refusing anything.
///
/// Answers with the pack's word — `disabled`, `observing` or `armed` — rather
/// than a bool, because two of the three are not-armed and a bool would let them
/// pass for each other.
fn pack_reads(switch: &Path) -> String {
    let hooks = Path::new(env!("CARGO_MANIFEST_DIR")).join("hooks");
    let program = "import sys; from keyless_hooks.config import load; \
                   cfg = load(); \
                   print('disabled' if not cfg.enabled \
                         else 'observing' if cfg.observe else 'armed')";
    let output = Command::new("python3")
        .arg("-c")
        .arg(program)
        .env("PYTHONPATH", &hooks)
        .env("KEYLESS_HOOKS_CONFIG", switch)
        .output()
        .expect("python3 must run");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
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

// ---------------------------------------------------------------------------
// rule 3: it re-adds nothing you removed
// ---------------------------------------------------------------------------

/// Read the settings file, hand it to `edit`, write it back.
fn amend_settings(machine: &Machine, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut settings = machine.settings_json();
    edit(&mut settings);
    std::fs::write(
        machine.settings(),
        serde_json::to_string_pretty(&settings).expect("serialize"),
    )
    .expect("write settings");
}

/// Every `permissions.allow` rule currently in the settings file.
fn allow_rules(machine: &Machine) -> Vec<String> {
    machine.settings_json()["permissions"]["allow"]
        .as_array()
        .map(|rules| {
            rules
                .iter()
                .filter_map(|rule| rule.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn what_you_removed_stays_removed_until_you_ask_for_it_back() {
    // The rule the receipt exists for, at the level a person meets it. Without a
    // record, "never installed" and "installed and then thrown out" are the same
    // observation — an absent entry — and an installer that treats them alike
    // overwrites a decision every time it runs.
    //
    // Both halves are asserted, because each alone has a way to pass while the
    // behaviour is wrong: an installer that re-added nothing EVER would pass the
    // first half, and one that re-added everything ALWAYS would pass the second.
    let machine = Machine::fresh("removed-stays-removed").with_harness("{}");
    machine.setup(&[]);

    let rule = "Bash(keyless doctor:*)";
    assert!(
        allow_rules(&machine).iter().any(|have| have == rule),
        "the first run installed no `{rule}`, so removing it proves nothing"
    );
    assert!(
        machine.settings_json()["hooks"]["PostToolUse"].is_array(),
        "the first run registered no PostToolUse handler"
    );

    // The person removes one of each kind by hand: a permission rule and a
    // whole event's handler.
    amend_settings(&machine, |settings| {
        let allow = settings["permissions"]["allow"]
            .as_array_mut()
            .expect("an allow list");
        allow.retain(|have| have != rule);
        settings["hooks"]
            .as_object_mut()
            .expect("a hooks object")
            .remove("PostToolUse");
    });

    let again = out(&machine.setup(&[]));
    assert!(
        allow_rules(&machine).iter().all(|have| have != rule),
        "a plain re-run put back `{rule}`, which the person deleted:\n{again}"
    );
    assert!(
        machine.settings_json()["hooks"]
            .get("PostToolUse")
            .is_none(),
        "a plain re-run put back a handler the person deleted:\n{again}"
    );
    assert!(
        again.contains("left alone"),
        "the re-run restored nothing and did not say so either:\n{again}"
    );

    // And the way back is one word, said out loud.
    let restored = out(&machine.setup(&["--restore"]));
    assert!(
        allow_rules(&machine).iter().any(|have| have == rule),
        "--restore did not put back `{rule}`:\n{restored}"
    );
    assert!(
        machine.settings_json()["hooks"]["PostToolUse"].is_array(),
        "--restore did not put back the handler:\n{restored}"
    );
}

// ---------------------------------------------------------------------------
// the third state of the switch
// ---------------------------------------------------------------------------

#[test]
fn a_pack_that_only_records_is_never_reported_as_armed() {
    // `observe` is the state that reads as healthy and protects nothing: every
    // check runs, the pack is registered, and NOTHING is blocked. A `doctor`
    // that calls it armed is the same false green as one that calls a disabled
    // install healthy — worse, in fact, because the registration is really
    // there, so every other signal agrees with the wrong answer.
    let machine = Machine::fresh("observing").with_harness("{}");
    machine.setup(&[]);

    let armed = out(&machine.run(&["doctor"]));
    assert_eq!(
        state_of(&armed, "guards"),
        "proven",
        "the guards were not armed to begin with, so switching them to \
         recording-only proves nothing:\n{armed}"
    );

    std::fs::create_dir_all(machine.switch().parent().expect("a parent")).expect("mkdir");
    std::fs::write(machine.switch(), "{\"observe\": true}\n").expect("write switch");

    // The pack's own loader first: a state `keyless` invents and the pack does
    // not implement would make every assertion below a report about nothing.
    assert_eq!(pack_reads(&machine.switch()), "observing");

    let recording = out(&machine.run(&["doctor"]));
    assert_eq!(
        state_of(&recording, "guards"),
        "off",
        "a pack that blocks nothing is reported as armed:\n{recording}"
    );
    assert!(
        recording.contains("NOTHING is blocked"),
        "the recording-only state is not named, so a reader cannot tell it from \
         a healthy install:\n{recording}"
    );
}

// ---------------------------------------------------------------------------
// rule 2: it never clobbers
// ---------------------------------------------------------------------------

#[test]
fn agent_instructions_somebody_took_over_survive_a_second_setup() {
    // The file lives under the agent's own directory and a person is free to
    // rewrite it. Setup wrote it once; the moment its content differs from what
    // setup wrote, it is theirs, and replacing it would delete work with no way
    // back.
    let machine = Machine::fresh("skill-taken-over").with_harness("{}");
    machine.setup(&[]);
    assert!(
        machine.skill().exists(),
        "setup installed no agent instructions, so editing them proves nothing"
    );

    let theirs = "# keyless\n\nMy own notes, which nothing here may take away.\n";
    std::fs::write(machine.skill(), theirs).expect("write skill");

    let again = out(&machine.setup(&[]));
    assert_eq!(
        std::fs::read_to_string(machine.skill()).expect("read"),
        theirs,
        "setup overwrote instructions somebody had taken over:\n{again}"
    );
    assert_eq!(
        state_of(&again, "skill"),
        "off",
        "the file was kept and the report claims it was installed:\n{again}"
    );
    assert!(
        again.contains("not what setup wrote"),
        "the report does not say why the file was left alone:\n{again}"
    );
}

#[test]
fn uninstall_takes_back_its_own_instructions_and_never_an_edited_copy() {
    // Two machines, differing in one byte of a file, because the assertion is
    // about the DIFFERENCE. The removal on its own passes on an uninstaller that
    // deletes unconditionally; the keep on its own passes on one that has
    // quietly stopped deleting anything at all.
    let ours = Machine::fresh("skill-removed").with_harness("{}");
    ours.setup(&[]);
    let untouched = out(&ours.uninstall());
    assert!(
        !ours.skill().exists(),
        "uninstall left behind the instructions it installed itself:\n{untouched}"
    );

    let theirs = Machine::fresh("skill-kept").with_harness("{}");
    theirs.setup(&[]);
    let edited = "# keyless\n\nEdited after setup wrote it.\n";
    std::fs::write(theirs.skill(), edited).expect("write skill");

    let kept = out(&theirs.uninstall());
    assert_eq!(
        std::fs::read_to_string(theirs.skill()).expect("read"),
        edited,
        "uninstall deleted a file somebody had edited:\n{kept}"
    );
    assert!(
        kept.contains("edited since setup wrote it"),
        "the file was kept and the report does not say so:\n{kept}"
    );
}

// ---------------------------------------------------------------------------
// a record it cannot read
// ---------------------------------------------------------------------------

#[test]
fn setup_stops_rather_than_installing_over_a_record_it_cannot_read() {
    // The receipt is the only thing that separates "never installed" from
    // "installed and thrown out". Installing over one that will not parse
    // discards that distinction silently and then writes a fresh record
    // claiming everything present is ours — which hands the next uninstall a
    // licence to delete entries this tool never created.
    let machine = Machine::fresh("unreadable-receipt").with_harness("{}");
    let before = std::fs::read_to_string(machine.settings()).expect("read");
    std::fs::write(machine.receipt(), "{ not json").expect("write receipt");

    let output = machine.setup(&[]);
    let text = out(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "setup installed over a record it could not read:\n{text}"
    );
    assert_eq!(
        std::fs::read_to_string(machine.settings()).expect("read"),
        before,
        "setup edited the settings file after refusing to read its own record"
    );
    assert!(
        !machine.config().exists(),
        "setup wrote a config after refusing to read its own record"
    );
    assert_eq!(
        std::fs::read_to_string(machine.receipt()).expect("read"),
        "{ not json",
        "setup overwrote the record it refused to read, which is the one file \
         that could still be repaired by hand"
    );
    assert!(
        text.contains("move it aside"),
        "the refusal does not say how to get past it:\n{text}"
    );
}

// ---------------------------------------------------------------------------
// the off switch, on a machine where something else went wrong first
// ---------------------------------------------------------------------------

#[test]
fn the_off_switch_works_on_an_empty_config_file() {
    // An absent config and an EMPTY one are different files and take different
    // branches. Empty is what a half-finished write leaves behind, and JSON has
    // no empty document — so the parse that treats the two alike refuses, and
    // the one thing this verb may never do is fail. Somebody who cannot turn
    // the guards off guts their settings file by hand instead.
    let machine = Machine::fresh("switch-empty");
    std::fs::create_dir_all(machine.switch().parent().expect("a parent")).expect("mkdir");
    std::fs::write(machine.switch(), "").expect("write switch");

    let output = machine.run(&["disable"]);
    let text = out(&output);
    assert!(
        output.status.success(),
        "the off switch failed on an empty config file:\n{text}"
    );
    assert_eq!(state_of(&text, "guards"), "off", "{text}");
    // Through the pack's own loader, so this is the pack being off and not a
    // sentence about being off.
    assert_eq!(pack_reads(&machine.switch()), "disabled", "{text}");
}

#[test]
fn re_enabling_says_whether_anything_actually_changed() {
    // Two runs of `enable`, one of which turned something back on and one of
    // which did nothing. Reporting both as the same event is a small lie with a
    // specific cost: somebody checking whether their `disable` ever took effect
    // reads "back on" from a command that changed nothing and concludes it had.
    let machine = Machine::fresh("enable-twice");

    machine.run(&["disable"]);
    let back_on = out(&machine.run(&["enable"]));
    assert!(
        back_on.contains("back on"),
        "enabling a disabled install does not say it changed anything:\n{back_on}"
    );

    let already = out(&machine.run(&["enable"]));
    assert!(
        already.contains("already on"),
        "enabling an install that was never off claims it turned something \
         back on:\n{already}"
    );
    // THE CONTROL. Both branches print a `proven` guards row, so the state word
    // alone cannot tell them apart — which is exactly why the detail is the
    // subject here.
    assert_eq!(state_of(&already, "guards"), "proven", "{already}");
}

// ---------------------------------------------------------------------------
// the exit code, which nothing had ever seen be non-zero
// ---------------------------------------------------------------------------

#[test]
fn a_step_that_breaks_costs_the_exit_code_and_names_itself() {
    // `setup` counts its broken steps and returns `problems > 0`. Every test
    // above drives a run where nothing fails, so that whole accumulator could
    // be inverted, zeroed or multiplied and the suite stayed green — a setup
    // that reported success no matter what happened would have passed.
    //
    // A settings file whose `permissions` is not an object is the reachable
    // break: the hook installer refuses it by name rather than writing over it,
    // and `setup` has to carry that refusal out to the caller.
    let machine = Machine::fresh("step-breaks").with_harness(r#"{"permissions": "not an object"}"#);
    let before = std::fs::read_to_string(machine.settings()).expect("read");

    let output = machine.setup(&[]);
    let text = out(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a run with a broken step exited 0, so nothing that goes wrong here \
         can ever be noticed by a script:\n{text}"
    );
    assert_eq!(
        state_of(&text, "guards"),
        "broken",
        "the broken step is not named in the report:\n{text}"
    );
    assert!(
        text.contains("REFUSING"),
        "the installer's own reason was swallowed:\n{text}"
    );
    assert_eq!(
        std::fs::read_to_string(machine.settings()).expect("read"),
        before,
        "a refused merge still edited the settings file"
    );

    // THE CONTROL. The steps that did not break must not be reported as broken,
    // or "broken" would just be what every row says on a failed run.
    assert_eq!(state_of(&text, "keyless"), "proven", "{text}");
}

#[test]
fn the_binaries_row_reports_the_daemon_it_actually_found() {
    // `which` is the only thing that decides this row, and it had no test at
    // all: it could answer `None` for every machine, or answer with an empty
    // path, and the report would still render a row somebody reads as a fact.
    let machine = Machine::fresh("binaries-row").with_harness("{}");
    let bin = machine.root.join("fake-bin");
    std::fs::create_dir_all(&bin).expect("mkdir");
    let daemon = bin.join("keylessd");
    std::fs::write(&daemon, "#!/bin/sh\nexit 0\n").expect("write daemon");

    let claude = machine.claude();
    let receipt = machine.receipt();
    let text = out(&machine.run_with_path(
        &[
            "setup",
            "--claude-dir",
            claude.to_str().expect("utf-8"),
            "--receipt",
            receipt.to_str().expect("utf-8"),
            "--store",
            "keychain",
            "--yes",
        ],
        Some(&bin),
    ));

    assert!(
        text.contains(&daemon.display().to_string()),
        "the daemon on PATH is not named in the report:\n{text}"
    );
}

#[test]
fn only_the_off_switch_mentions_the_daemon_it_leaves_running() {
    // `disable` stops the guards and deliberately does NOT stop the daemon —
    // stopping it would stop credentials resolving, which is not what the word
    // means. That note belongs on the way out and nowhere else; printed on
    // `enable` it would read as a warning about an action that just undid the
    // thing being warned about.
    let machine = Machine::fresh("switch-note");
    let off = out(&machine.run(&["disable"]));
    assert!(
        off.contains("is also still running"),
        "disable does not say the daemon is left running:\n{off}"
    );
    let on = out(&machine.run(&["enable"]));
    assert!(
        !on.contains("is also still running"),
        "enable carries a note that only makes sense on the way out:\n{on}"
    );
}
