//! `keyless init` — the detection, the one question, and the guards row.
//!
//! # Why this file exists at all
//!
//! A mutation campaign over `src/cmd/init.rs` changed more than half of what
//! this verb does and the whole suite stayed green. The clusters were the ones
//! nothing had ever driven: the interactive prompt (never fed a byte of stdin),
//! the NEXT section, the GUARDS row, and every per-backend sentence — each of
//! which could be emptied, or swapped for another backend's, without a single
//! assertion noticing.
//!
//! # How detection is made deterministic, on any machine
//!
//! `init` probes all three backends against the config it is about to write
//! into, so what is "usable" is normally a fact about the developer's laptop.
//! Every probe here is aimed at a stub instead, which is what lets a test say
//! "exactly these two proved" and mean it:
//!
//! - **The keychain answers or it does not, and neither depends on macOS.**
//!   `KeychainStore` skips its modal-dialog guard entirely when the binary is
//!   not the stock `/usr/bin/security`, so a stub proves on Linux and on macOS
//!   alike — and the real `security` is never spawned, from any test here.
//! - **A backend is made unreachable by naming a binary that is not there**,
//!   never by disabling it: `sole_store` turns the `enabled` flags on and off
//!   itself, so a config that says `"enabled": false` proves nothing about what
//!   detection does.
//!
//! # `HOME` is redirected in the subprocess cases, and only there
//!
//! `settings_file` reads `HOME` and nothing else — no flag reaches it, which is
//! the documented difference between this verb and `setup`. So the GUARDS row
//! can only be driven by moving `HOME`, and moving `HOME` inside a test process
//! that runs on several threads is a race. Those cases spawn the built binary
//! instead, with `HOME` pointed inside the scratch directory.
//!
//! Doing that is safe here for the same reason `keychain::default_keychain_is_reachable`
//! exists: with `HOME` moved, the stock `security` is refused before it is
//! spawned rather than after, so no modal window can reach anybody's screen.
//! Those runs also name a keychain binary that does not exist, so the question
//! never arises.
//!
//! **Nothing here reads the developer's own `~/.claude/settings.json`.** A
//! GUARDS assertion that passed by looking at the real home directory would be
//! green on the machine that wrote it and red everywhere else, which is worse
//! than no assertion.

mod support;

use std::io::Cursor;
use std::path::PathBuf;
use std::process::{Command, Output};

use keyless::cmd::init::{EXIT_NEEDS_AN_ANSWER, Finding, InitRequest, detect, init};
use keyless::cmd::status::{Mark, Style};
use keyless::config::Config;
use keyless::paths::Paths;
use support::{Backend, Stub, scratch, stub_infisical, stub_pass_cli_discovery, stub_security};

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// One vault, which is all a `vault list` health probe has to come back with.
const ONE_VAULT: &str = r#"{"vaults":[{"name":"personal","id":"V1"}]}"#;

// ---------------------------------------------------------------------------
// the fixture
// ---------------------------------------------------------------------------

/// A machine with a config, and a stub for each backend that is meant to answer.
struct Machine {
    root: PathBuf,
}

/// Whether a backend answers its health probe.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Backing {
    /// A stub that proves the read path.
    Answers,
    /// A binary that is not on this machine, so the probe cannot even start.
    Missing,
}

impl Machine {
    fn fresh(tag: &str) -> Machine {
        Machine { root: scratch(tag) }
    }

    fn paths(&self) -> Paths {
        Paths::under(&self.root)
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("config.json")
    }

    /// A path inside the scratch directory that deliberately holds no file.
    fn absent(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Write a config whose three backends are backed as asked.
    ///
    /// The coordinates are always present — a `project_id`, a declared name with
    /// an `env`, a session directory. Detection reads them through the real
    /// config, so a fixture that left them out would make Infisical and Proton
    /// unprovable for a reason that has nothing to do with the case at hand.
    fn write_config(&self, keychain: Backing, infisical: Backing, proton: Backing) {
        let keychain = match keychain {
            Backing::Answers => stub_security(&self.root, &Stub::NotFound),
            Backing::Missing => self.absent("no-security-here"),
        };
        let infisical = match infisical {
            Backing::Answers => stub_infisical(&self.root, &Backend::Injects("probe")),
            Backing::Missing => self.absent("no-infisical-here"),
        };
        let proton = match proton {
            Backing::Answers => stub_pass_cli_discovery(&self.root, ONE_VAULT, "{}", "{}"),
            Backing::Missing => self.absent("no-pass-cli-here"),
        };
        let session = self.root.join("proton-session");
        std::fs::create_dir_all(&session).expect("the session directory");

        let body = format!(
            r#"{{"stores": {{
                 "keychain": {{"binary": "{keychain}"}},
                 "infisical": {{"binary": "{infisical}", "project_id": "proj-init"}},
                 "proton": {{"binary": "{proton}", "session_dir": "{session}"}}
               }},
               "secrets": {{"DECOY": {{"store": "infisical", "env": "staging"}}}}}}"#,
            keychain = keychain.display(),
            infisical = infisical.display(),
            proton = proton.display(),
            session = session.display(),
        );
        std::fs::write(self.config_path(), &body).expect("write the config");
    }

    /// The config as `detect` would be handed it.
    fn config(&self) -> Config {
        let loaded = Config::load(&self.config_path());
        assert!(
            loaded.problem.is_none(),
            "the fixture config does not parse: {:?}",
            loaded.problem
        );
        loaded.config
    }

    /// What is on disk right now, whether or not `init` rewrote it.
    fn config_text(&self) -> String {
        std::fs::read_to_string(self.config_path()).expect("read the config")
    }
}

/// Everything `init` needs, with the guards row off.
///
/// `report_guards` is false because that row reads the real `HOME` and would
/// run `python3` against the developer's own agent settings. The subprocess
/// cases at the bottom of this file own it.
fn request<'a>(paths: &'a Paths, interactive: bool) -> InitRequest<'a> {
    InitRequest {
        paths,
        // The fixture always writes a config first, so every case that is meant
        // to reach the write has to be allowed past the never-clobber return.
        force: true,
        assume_yes: false,
        only: None,
        interactive,
        install_hooks: false,
        report_guards: false,
        style: Style::PLAIN,
    }
}

/// Drive `init` with `answer` on stdin. Returns the exit code, stdout, stderr.
fn drive(request: &InitRequest<'_>, answer: &str) -> (i32, String, String) {
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let code = init(
        request,
        &mut Cursor::new(answer.as_bytes().to_vec()),
        &mut out,
        &mut err,
    )
    .expect("init must not fail to write");
    (
        code,
        String::from_utf8(out).expect("utf-8"),
        String::from_utf8(err).expect("utf-8"),
    )
}

/// The report with every run of whitespace collapsed to one space.
///
/// Every line the report emits is word-wrapped at a fixed column, so a sentence
/// this file asserts on is one line today and two after somebody adds a word
/// ahead of it. Flattening makes the assertion about the WORDS rather than
/// about the wrap, and it cannot hide a difference: wrapping only ever breaks
/// at a space it already had.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The state word on the row for `subject`, in a `Style::PLAIN` report.
fn state_of(text: &str, subject: &str) -> String {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(glyph) = parts.next() else { continue };
        if !["+", "~", "x", "X", "-"].contains(&glyph) {
            continue;
        }
        if parts.next() != Some(subject) {
            continue;
        }
        return parts.next().unwrap_or_default().to_owned();
    }
    panic!("no row for `{subject}` in:\n{text}");
}

// ---------------------------------------------------------------------------
// what a row says, per backend
// ---------------------------------------------------------------------------

#[test]
fn a_usable_row_is_the_only_kind_init_will_write() {
    // `is_usable` is the whole of the filter that decides what gets offered and
    // what gets written, and it could be replaced by a constant `true`, a
    // constant `false`, or its own negation with nothing failing. Asserted
    // against every mark rather than against the two that happen to be common,
    // so a fourth mark added later is a compile error here and not a silent
    // widening of what counts as provable.
    let finding = |mark| Finding {
        store: "keychain",
        mark,
        state: "whatever",
        detail: String::new(),
        next: None,
    };
    assert!(finding(Mark::Proven).is_usable(), "a proven row is usable");
    for mark in [Mark::Unproven, Mark::NotSetUp, Mark::Broken, Mark::Off] {
        assert!(
            !finding(mark).is_usable(),
            "`init` would write a config against a {mark:?} store"
        );
    }
}

#[test]
fn every_proven_row_says_which_read_path_answered() {
    // Each sentence is a different backend's proof, and each was replaceable by
    // the empty string, by a placeholder, or by the NEXT backend's sentence —
    // the last being the one that reads as correct. A single `contains` over
    // the whole report cannot tell those apart, so this asserts the detail per
    // row, verbatim.
    let machine = Machine::fresh("proven-details");
    machine.write_config(Backing::Answers, Backing::Answers, Backing::Answers);

    let findings = detect(&machine.config());
    let detail = |store: &str| {
        findings
            .iter()
            .find(|f| f.store == store)
            .unwrap_or_else(|| panic!("no `{store}` row"))
    };

    for store in ["keychain", "infisical", "proton"] {
        assert_eq!(
            detail(store).mark,
            Mark::Proven,
            "`{store}` did not prove against its stub: {}",
            detail(store).detail
        );
        assert_eq!(detail(store).state, "proven");
        assert!(
            detail(store).next.is_none(),
            "a proven row was given a next step"
        );
    }

    assert_eq!(
        detail("keychain").detail,
        "the login keychain answered a search"
    );
    assert_eq!(
        detail("infisical").detail,
        "the CLI fetched a non-credential key"
    );
    assert_eq!(detail("proton").detail, "the session listed its vaults");
}

#[test]
fn every_row_that_is_not_proven_names_the_one_step_that_moves_it() {
    // The same shape as the case above, on the other side. A `setup_step` that
    // returns the empty string leaves an arrow pointing at nothing; one whose
    // `keychain` arm is deleted sends a macOS user to `pass-cli`. Both looked
    // identical to the suite.
    let machine = Machine::fresh("next-steps-per-store");
    machine.write_config(Backing::Missing, Backing::Missing, Backing::Missing);

    let findings = detect(&machine.config());
    let step = |store: &str| {
        findings
            .iter()
            .find(|f| f.store == store)
            .unwrap_or_else(|| panic!("no `{store}` row"))
            .next
            .clone()
            .unwrap_or_else(|| panic!("`{store}` is not usable and was given no next step"))
    };

    assert_eq!(
        step("keychain"),
        "the login keychain must be present and unlocked; open Keychain Access"
    );
    assert_eq!(
        step("infisical"),
        "`infisical login`, then add \"project_id\" under `stores.infisical` and an \"env\" on each name"
    );
    assert_eq!(
        step("proton"),
        "`PROTON_PASS_SESSION_DIR=<the session directory you chose> pass-cli login`, then set \
         `stores.proton.session_dir` to that same directory — the variable is not optional, a \
         bare `pass-cli login` logs into the DEFAULT session and reports success"
    );

    // And the step reaches the report, not just the struct.
    let paths = machine.paths();
    let (_, out, _) = drive(&request(&paths, false), "");
    assert!(
        flat(&out).contains("open Keychain Access"),
        "the keychain's next step never reached the report:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// the one question
// ---------------------------------------------------------------------------

#[test]
fn the_question_offers_exactly_the_backends_that_proved() {
    // The prompt had never been driven with a byte of real stdin. Every mutant
    // below stayed green: offering all three backends whether or not they
    // proved, offering the ones that FAILED, and taking an answer other than
    // the one typed.
    let machine = Machine::fresh("question-offers");
    machine.write_config(Backing::Answers, Backing::Missing, Backing::Answers);
    let paths = machine.paths();

    let (code, out, err) = drive(&request(&paths, true), "proton\n");

    assert_eq!(code, 0, "{err}");
    assert_eq!(state_of(&out, "keychain"), "proven", "{out}");
    assert_eq!(state_of(&out, "infisical"), "absent", "{out}");
    assert_eq!(state_of(&out, "proton"), "proven", "{out}");

    // The offer is the list of what proved, in the detection order, and nothing
    // else. `infisical` failed, so naming it here would send somebody to a
    // store that cannot answer.
    assert!(
        flat(&out).contains("[keychain / proton] >"),
        "the question did not offer exactly the two backends that proved:\n{out}"
    );

    // And the answer that was typed is the one that was written.
    let written = machine.config_text();
    assert!(
        written.contains("\"default\": \"proton\""),
        "answering `proton` wrote something else:\n{written}"
    );
    assert!(
        written.contains("\"proton\": { \"enabled\": true }"),
        "the chosen backend was not the one enabled:\n{written}"
    );
}

#[test]
fn an_empty_answer_takes_the_first_offer_rather_than_asking_again() {
    // The documented default, and the one branch a reader is most likely to
    // exercise by pressing return. Without this, an implementation that treated
    // an empty line as an unknown answer — or as end of input — passes.
    let machine = Machine::fresh("question-empty");
    machine.write_config(Backing::Answers, Backing::Missing, Backing::Answers);
    let paths = machine.paths();

    let (code, _out, err) = drive(&request(&paths, true), "\n");

    assert_eq!(code, 0, "{err}");
    let written = machine.config_text();
    assert!(
        written.contains("\"default\": \"keychain\""),
        "an empty answer did not take the first offer:\n{written}"
    );
}

#[test]
fn an_answer_that_names_no_offer_writes_nothing() {
    // A typo must not resolve to whichever backend happens to be first. The
    // config on disk is the fixture's, so "nothing was written" is checked
    // against the bytes rather than against the absence of a file.
    let machine = Machine::fresh("question-wrong");
    machine.write_config(Backing::Answers, Backing::Missing, Backing::Answers);
    let paths = machine.paths();

    let (code, _out, err) = drive(&request(&paths, true), "keychian\n");

    assert_eq!(code, EXIT_NEEDS_AN_ANSWER, "{err}");
    assert!(
        flat(&err).contains("`keychian` is not one of keychain, proton. Nothing was written."),
        "the refusal did not name the answer and the offers:\n{err}"
    );
    assert!(
        machine.config_text().contains("proj-init"),
        "a rejected answer still rewrote the config"
    );
}

#[test]
fn a_pipeline_with_a_choice_to_make_names_the_flags_and_stops() {
    // The never-block invariant, driven through `init` rather than through
    // `choose` alone: with two usable backends and no terminal, the count, the
    // list and the backend `--yes` would take all have to be in the message,
    // because that message is the entire remedy.
    let machine = Machine::fresh("question-piped");
    machine.write_config(Backing::Answers, Backing::Missing, Backing::Answers);
    let paths = machine.paths();

    let (code, _out, err) = drive(&request(&paths, false), "");

    assert_eq!(code, EXIT_NEEDS_AN_ANSWER, "{err}");
    assert!(
        flat(&err).contains(
            "2 backends are usable (keychain, proton) and there is no terminal to ask on."
        ),
        "the refusal did not count or list the usable backends:\n{err}"
    );
    assert!(
        flat(&err).contains("or `--yes` to take `keychain`."),
        "the refusal did not name what `--yes` would take:\n{err}"
    );
    assert!(
        machine.config_text().contains("proj-init"),
        "a run that refused to choose still wrote a config"
    );
}

#[test]
fn yes_takes_the_first_offer_and_asks_nothing() {
    // The control for the case above. Without it, both pass on an `init` that
    // refuses to decide anything at all.
    let machine = Machine::fresh("question-yes");
    machine.write_config(Backing::Answers, Backing::Missing, Backing::Answers);
    let paths = machine.paths();
    let mut asked = request(&paths, false);
    asked.assume_yes = true;

    let (code, out, err) = drive(&asked, "");

    assert_eq!(code, 0, "{err}");
    assert!(
        !out.contains("ONE QUESTION"),
        "`--yes` asked the question anyway:\n{out}"
    );
    assert!(
        machine.config_text().contains("\"default\": \"keychain\""),
        "`--yes` did not take the first offer:\n{}",
        machine.config_text()
    );
}

#[test]
fn nothing_usable_is_a_refusal_and_not_a_config() {
    // The far end of the same filter: with no backend proven there is no honest
    // default to write, so the verb stops. `is_usable` replaced by a constant
    // `true` makes this case write a config against a store that cannot answer.
    let machine = Machine::fresh("question-none");
    machine.write_config(Backing::Missing, Backing::Missing, Backing::Missing);
    let paths = machine.paths();

    let (code, out, _err) = drive(&request(&paths, true), "keychain\n");

    assert_eq!(code, 1, "{out}");
    assert!(out.contains("NOTHING TO WRITE"), "{out}");
    assert!(
        !out.contains("ONE QUESTION"),
        "a question was asked with nothing to offer:\n{out}"
    );
    assert!(
        machine.config_text().contains("proj-init"),
        "a config was written with no store that answers"
    );
}

#[test]
fn store_names_a_backend_this_build_has_or_it_names_none() {
    // `--store` is checked against the build's own list. With the comparison
    // inverted the lookup returns the FIRST backend whose name differs, so a
    // typo silently writes `keychain` and reports success.
    let machine = Machine::fresh("store-unknown");
    machine.write_config(Backing::Answers, Backing::Missing, Backing::Answers);
    let paths = machine.paths();
    let mut asked = request(&paths, false);
    asked.only = Some("keyvault");

    let (code, _out, err) = drive(&asked, "");

    assert_eq!(code, EXIT_NEEDS_AN_ANSWER, "{err}");
    assert!(
        flat(&err).contains(
            "`--store keyvault` names no backend. This build has: keychain, infisical, proton"
        ),
        "the refusal did not list the backends this build has:\n{err}"
    );
    assert!(
        machine.config_text().contains("proj-init"),
        "an unknown `--store` still wrote a config"
    );
}

#[test]
fn store_writes_a_backend_that_has_not_proved_yet() {
    // Deliberate: somebody about to log in asks for the store they are about to
    // have. Refusing would send them to a text editor. The row above still says
    // it has not proved, which is what keeps this from being a false green.
    let machine = Machine::fresh("store-unproven");
    machine.write_config(Backing::Missing, Backing::Missing, Backing::Missing);
    let paths = machine.paths();
    let mut asked = request(&paths, false);
    asked.only = Some("proton");

    let (code, out, err) = drive(&asked, "");

    assert_eq!(code, 0, "{err}");
    assert_eq!(state_of(&out, "proton"), "absent", "{out}");
    assert!(
        machine.config_text().contains("\"default\": \"proton\""),
        "`--store proton` did not write proton:\n{}",
        machine.config_text()
    );
}

// ---------------------------------------------------------------------------
// NEXT: the path from a written config to a name that resolves
// ---------------------------------------------------------------------------

/// Write a config with `store` as the default and hand back the report.
fn next_section_for(tag: &str, store: &str) -> String {
    let machine = Machine::fresh(tag);
    machine.write_config(Backing::Answers, Backing::Answers, Backing::Answers);
    let paths = machine.paths();
    let mut asked = request(&paths, false);
    asked.only = Some(store);
    let (code, out, err) = drive(&asked, "");
    assert_eq!(code, 0, "{err}");
    out
}

#[test]
fn the_keychain_next_step_is_the_verb_that_needs_no_coordinate() {
    // The whole NEXT section could be deleted, and each of its two `==` tests
    // inverted, with nothing failing — so a keychain user was as likely to be
    // sent to `items infisical --env` as to `new`.
    let out = flat(&next_section_for("next-keychain", "keychain"));
    assert!(out.contains("NEXT"), "{out}");
    assert!(
        out.contains("keyless new FIRST_SECRET"),
        "the keychain path does not start where the README starts:\n{out}"
    );
    assert!(
        !out.contains("keyless items infisical"),
        "a keychain config was sent to an Infisical listing:\n{out}"
    );
    assert!(
        !out.contains("keyless fields --item"),
        "a keychain config was sent to a vault's field list:\n{out}"
    );
}

#[test]
fn the_infisical_next_step_names_an_environment_because_nothing_defaults_it() {
    let out = flat(&next_section_for("next-infisical", "infisical"));
    assert!(
        out.contains("keyless items infisical --env <SLUG>"),
        "the Infisical path does not name the environment it cannot default:\n{out}"
    );
    assert!(
        !out.contains("keyless new FIRST_SECRET"),
        "an Infisical config was sent to the keychain's first step:\n{out}"
    );
    assert!(
        !out.contains("keyless fields --item"),
        "an Infisical secret is one value, so a field list has no answer:\n{out}"
    );
}

#[test]
fn a_vault_next_step_lists_items_and_then_fields() {
    let out = flat(&next_section_for("next-proton", "proton"));
    assert!(
        out.contains("keyless items") && out.contains("keyless fields --item <TITLE>"),
        "the vault path does not walk items then fields:\n{out}"
    );
    assert!(
        !out.contains("keyless items infisical"),
        "a vault config was sent to an Infisical listing:\n{out}"
    );
    assert!(
        !out.contains("keyless new FIRST_SECRET"),
        "a vault config was sent to the keychain's first step:\n{out}"
    );
}

#[test]
fn every_next_section_ends_at_the_only_way_a_value_leaves_a_store() {
    // The two lines that are the same whatever was chosen. Both were deletable.
    for (tag, store) in [
        ("next-tail-keychain", "keychain"),
        ("next-tail-infisical", "infisical"),
        ("next-tail-proton", "proton"),
    ] {
        let out = flat(&next_section_for(tag, store));
        assert!(
            out.contains("keyless run -s NAME -- <cmd>"),
            "`{store}`: NEXT never names the verb that resolves a name:\n{out}"
        );
        assert!(
            out.contains("keyless doctor"),
            "`{store}`: NEXT never names the verb that re-checks it:\n{out}"
        );
    }
}

#[test]
fn the_closing_note_names_only_the_backends_still_waiting_on_a_login() {
    // Four separate mutations of this one filter survived, and each produces a
    // note that reads perfectly: the backends that ALREADY work, every backend
    // at once, or no note at all. Only `infisical` failed here, so only
    // `infisical` may be named — and the singular verb is part of the claim,
    // because the plural branch is a different arm.
    let machine = Machine::fresh("waiting-one");
    machine.write_config(Backing::Answers, Backing::Missing, Backing::Answers);
    let paths = machine.paths();
    let mut asked = request(&paths, false);
    asked.assume_yes = true;

    let (code, out, err) = drive(&asked, "");
    assert_eq!(code, 0, "{err}");

    let flattened = flat(&out);
    assert!(
        flattened.contains(
            "`infisical` is still waiting on a login only you can perform. Run `keyless setup` \
             again afterwards."
        ),
        "the closing note did not name the one backend still waiting:\n{out}"
    );
    assert!(
        !flattened.contains("`keychain` and"),
        "a backend that proved was reported as still waiting:\n{out}"
    );
    assert!(
        !flattened.contains("`proton` is still waiting"),
        "a backend that proved was reported as still waiting:\n{out}"
    );
}

#[test]
fn the_closing_note_joins_several_backends_rather_than_naming_one() {
    // The other arm of the same match. With every backend unreachable and one
    // named explicitly, all three are waiting — and the sentence has to read as
    // a list rather than as a singular.
    let machine = Machine::fresh("waiting-several");
    machine.write_config(Backing::Missing, Backing::Missing, Backing::Missing);
    let paths = machine.paths();
    let mut asked = request(&paths, false);
    asked.only = Some("keychain");

    let (code, out, err) = drive(&asked, "");
    assert_eq!(code, 0, "{err}");

    assert!(
        flat(&out).contains(
            "`keychain` and `infisical` and `proton` are still waiting on a login only you can \
             perform."
        ),
        "the closing note did not list every backend still waiting:\n{out}"
    );
}

#[test]
fn a_report_with_nothing_waiting_says_nothing_about_waiting() {
    // The control. Without it, every assertion above passes on an `init` that
    // prints the note unconditionally — which would tell somebody whose whole
    // machine works that it does not.
    let machine = Machine::fresh("waiting-none");
    machine.write_config(Backing::Answers, Backing::Answers, Backing::Answers);
    let paths = machine.paths();
    let mut asked = request(&paths, false);
    asked.assume_yes = true;

    let (code, out, err) = drive(&asked, "");
    assert_eq!(code, 0, "{err}");
    assert!(
        !out.contains("still waiting"),
        "every backend proved and the report still asked for a login:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// GUARDS: the row that reads HOME, driven against the built binary
// ---------------------------------------------------------------------------

/// A scratch machine for the subprocess cases: its own `HOME`, its own config.
struct Guarded {
    root: PathBuf,
}

impl Guarded {
    /// A machine that has an agent harness, which is what a Claude Code user has.
    fn fresh(tag: &str) -> Guarded {
        let machine = Guarded::bare(tag);
        std::fs::create_dir_all(machine.home().join(".claude")).expect("the agent directory");
        machine
    }

    /// A machine with no agent harness at all.
    ///
    /// `hooks/install.py` refuses to invent one, writes nothing, and exits 0 —
    /// which is why this is a different fixture and not a flag.
    fn bare(tag: &str) -> Guarded {
        let root = scratch(tag);
        std::fs::create_dir_all(root.join("home")).expect("the scratch home");
        // Named rather than defaulted: with `HOME` moved, the stock `security`
        // would be refused anyway, but a binary that is not there cannot even
        // be reached — which is one fewer thing this case depends on.
        std::fs::write(
            root.join("config.json"),
            format!(
                r#"{{"stores": {{"keychain": {{"binary": "{}"}}}}}}"#,
                root.join("no-security-here").display()
            ),
        )
        .expect("write the config");
        Guarded { root }
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// Where BOTH `init` and the installer resolve the settings file to.
    ///
    /// `init` builds it from `HOME`; `hooks/install.py` expands `~`. They agree
    /// only because nothing here sets `KEYLESS_CLAUDE_DIR`, and that agreement
    /// is what makes the second run's `proven` mean anything.
    fn settings(&self) -> PathBuf {
        self.home().join(".claude").join("settings.json")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .arg("--config")
            .arg(self.root.join("config.json"))
            .arg("--audit")
            .arg(self.root.join("audit.jsonl"))
            .env("HOME", self.home())
            .env("XDG_CONFIG_HOME", self.root.join("xdg-config"))
            .env("XDG_STATE_HOME", self.root.join("xdg-state"))
            // The pack is found from the source tree rather than from wherever
            // this binary happens to sit, so the case does not depend on the
            // target directory's shape.
            .env("KEYLESS_PACK_DIR", env!("CARGO_MANIFEST_DIR"))
            .env("NO_COLOR", "1")
            .env("KEYLESS_ASCII", "1")
            .output()
            .expect("the binary must run")
    }
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf-8")
}

#[test]
fn the_guards_row_is_absent_until_the_pack_is_registered_and_proven_after() {
    // Three runs, because the row has three answers and each was reachable
    // without any of them being checked: `settings_file` could return `None`,
    // `hooks_are_registered` could return `false`, and the `&&` that separates
    // "already there" from "install it now" could be inverted — after which
    // `--hooks` reports success and installs nothing at all.
    let machine = Guarded::fresh("guards");

    // 1. Nothing registered: the row says so, and names the flag that fixes it.
    let first = stdout_of(&machine.run(&["init", "--store", "keychain"]));
    assert!(first.contains("GUARDS"), "{first}");
    assert_eq!(state_of(&first, "hooks"), "absent", "{first}");
    assert!(
        flat(&first).contains("keyless init --hooks"),
        "the absent row did not name the flag that merges the pack in:\n{first}"
    );
    assert!(
        !machine.settings().exists(),
        "a run without `--hooks` wrote the settings file anyway"
    );

    // 2. `--hooks` runs the installer, and the FILE is the proof — not the row.
    let second = stdout_of(&machine.run(&["init", "--force", "--store", "keychain", "--hooks"]));
    assert_eq!(state_of(&second, "hooks"), "proven", "{second}");
    let settings = std::fs::read_to_string(machine.settings())
        .expect("`--hooks` reported success and wrote no settings file");
    assert!(
        settings.contains("keyless_hook.py"),
        "the installer wrote a settings file with no pack in it:\n{settings}"
    );
    assert!(
        flat(&second).contains("installed by"),
        "the row did not say which installer ran:\n{second}"
    );

    // 3. Registered already: recognised, and the installer is not run again.
    let third = stdout_of(&machine.run(&["init", "--force", "--store", "keychain"]));
    assert_eq!(state_of(&third, "hooks"), "proven", "{third}");
    assert!(
        flat(&third).contains("the pack is registered in your Claude Code settings"),
        "a registered pack was not recognised from the settings file:\n{third}"
    );
    assert!(
        !flat(&third).contains("installed by"),
        "a plain run re-ran the installer:\n{third}"
    );
}

#[test]
fn an_installer_that_fails_is_a_broken_row_and_not_a_proven_one() {
    // The row is built from the installer's exit status, and both failing arms
    // could be replaced by the succeeding one: a pack that refused to install
    // would report `proven` beside a settings file it never touched. That is
    // the false green this file exists for, so it is asserted on the WORD.
    let machine = Guarded::fresh("guards-refused");
    let pack = machine.root.join("failing-pack");
    std::fs::create_dir_all(&pack).expect("mkdir");
    std::fs::write(
        pack.join("install.py"),
        "import sys\nsys.stderr.write('REFUSING: the settings file will not parse\\n')\nsys.exit(3)\n",
    )
    .expect("write the failing installer");

    let output = Command::new(BIN)
        .args(["init", "--store", "keychain", "--hooks"])
        .arg("--config")
        .arg(machine.root.join("config.json"))
        .arg("--audit")
        .arg(machine.root.join("audit.jsonl"))
        .env("HOME", machine.home())
        .env("XDG_CONFIG_HOME", machine.root.join("xdg-config"))
        .env("XDG_STATE_HOME", machine.root.join("xdg-state"))
        .env("KEYLESS_HOOKS_DIR", &pack)
        .env("NO_COLOR", "1")
        .env("KEYLESS_ASCII", "1")
        .output()
        .expect("the binary must run");

    let out = stdout_of(&output);
    assert_eq!(
        state_of(&out, "hooks"),
        "broken",
        "an installer that exited non-zero was not reported as broken:\n{out}"
    );
    assert!(
        flat(&out).contains("exited exit status: 3"),
        "the row did not carry the installer's own status:\n{out}"
    );
    // The installer's words, on the stream errors already go to.
    let err = String::from_utf8(output.stderr.clone()).expect("utf-8");
    assert!(
        err.contains("REFUSING: the settings file will not parse"),
        "the installer's own refusal never reached stderr:\n{err}"
    );
    assert!(
        !machine.settings().exists(),
        "a refused install still produced a settings file"
    );
}

#[test]
fn an_installer_that_registered_nothing_is_never_reported_as_proven() {
    // 🔴 THE FALSE GREEN THIS FILE WAS WRITTEN TO CATCH. `hooks/install.py`
    // refuses to invent an agent harness that is not there: with no `~/.claude`
    // it writes nothing, says so on stdout, and exits 0 — correctly, because
    // that is not a failure. Judged on the exit status alone, `init --hooks`
    // printed a green `proven` directly above the installer's own "Nothing was
    // written", so the state word denied the sentence beneath it and the one
    // flag that closes the guards hole reported having closed it.
    //
    // Asserted on the WORD, because every other signal here agrees with the
    // wrong answer: the installer really did run, and it really did succeed.
    let machine = Guarded::bare("guards-no-harness");
    assert!(
        !machine.home().join(".claude").exists(),
        "the fixture has an agent directory, so this proves nothing"
    );

    let out = stdout_of(&machine.run(&["init", "--store", "keychain", "--hooks"]));

    assert_eq!(
        state_of(&out, "hooks"),
        "absent",
        "an install that registered nothing was reported as proven:\n{out}"
    );
    assert!(
        flat(&out).contains("Nothing was written."),
        "the installer's own account of doing nothing never reached the report:\n{out}"
    );
    assert!(
        !machine.settings().exists(),
        "the installer wrote a settings file after all, so the row was right"
    );
}

// ---------------------------------------------------------------------------
// the guards are reported before the never-clobber return
// ---------------------------------------------------------------------------

#[test]
fn an_existing_config_still_reports_and_installs_the_guards() {
    // The bug this ordering exists to prevent: the early return fires on every
    // machine that has run `init` once, so with the guards reported after it,
    // `init --hooks` printed "already exists; nothing was written" and
    // installed nothing. The one flag that closes the guards hole was reachable
    // only on a machine that had never run the verb.
    let machine = Guarded::fresh("guards-existing-config");

    let out = stdout_of(&machine.run(&["init", "--hooks"]));

    assert!(
        out.contains("already exists"),
        "the fixture did not take the never-clobber path, so this proves nothing:\n{out}"
    );
    assert_eq!(state_of(&out, "hooks"), "proven", "{out}");
    let settings = std::fs::read_to_string(machine.settings())
        .expect("`--hooks` installed nothing on a machine that already had a config");
    assert!(settings.contains("keyless_hook.py"), "{settings}");
}
