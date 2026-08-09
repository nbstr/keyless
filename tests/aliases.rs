//! A name labels a secret; it is not the variable a program reads.
//!
//! # The failure these tests are written against
//!
//! A store holds one credential per environment, so it needs a distinct label
//! for each of them. Every program in every environment reads the same variable.
//! So a declaration routinely says `"LABEL": {"key": "THE_VARIABLE"}` — the two
//! halves written down side by side, in the same file, by the same person.
//!
//! `keyless run -s LABEL -- cmd` used to inject `$LABEL` and nothing else, so
//! `cmd` ran with `$THE_VARIABLE` unset. That failure is quiet in the worst way:
//! the command does not complain about a name, it complains about a missing
//! credential, or makes an unauthenticated call, or exits 0 having done nothing.
//! **Nothing in the command, and nothing `keyless` printed, said the two halves
//! had not been reconciled** — reconciling them was left to whoever typed the
//! command, from knowledge that appears nowhere in it.
//!
//! Measured against the binary before the fix: the child's environment held
//! `LABEL` and no `THE_VARIABLE`, `keyless` wrote **zero bytes** to stderr, and
//! the run's state was `Injected`. There was no banner to improve, because
//! nothing had gone wrong as far as the tool could see.
//!
//! # What is asserted here
//!
//! - the bare form reaches the variable the program reads, with nothing printed;
//! - the declared label still arrives, so nothing that worked before stops;
//! - a spelled `VAR=NAME` stays exactly as narrow as it was typed;
//! - a declaration cannot make the store choose which program the child runs;
//! - the one case that is genuinely undecidable is not decided by flag order.

mod support;

use std::ffi::OsString;
use std::path::Path;

use keyless::State;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::config::Config;
use keyless::store::{self, Invocation, Registry};

use support::{Backend, scratch, stub_infisical, witness_env, witnessed_env};

/// The value the stub backend answers with. Obviously not a credential, and
/// distinctive enough that a leak into stderr is unmistakable.
const DECOY: &str = "decoy-Al17-answers-to-two-names-0707";

/// A config whose Infisical backend is a stub, with the given `secrets` block.
///
/// The deadline is spelled rather than inherited. Nothing here tests a timeout,
/// so the number's only job is to be far above what a stub shell script costs on
/// a loaded machine — a fixture that degraded under load would report this
/// suite's subject as broken when it is not.
fn config_with(stub: &Path, secrets: &str) -> Config {
    let json = format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "infisical":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}},
            "secrets":{secrets}}}"#,
        stub.display()
    );
    serde_json::from_str(&json).expect("the test config must be valid")
}

fn registry_of(config: &Config) -> Registry {
    store::build(config, &Invocation::default()).registry
}

/// Run through the library exactly as the binary does — `Binding::declared`,
/// not `Binding::parse`.
///
/// The distinction is the whole subject: `parse` is syntax and knows no config,
/// so a suite written against it would pass on a build where the binary had
/// stopped consulting a declaration at all.
fn run_declared(config: &Config, specs: &[&str], argv: &[OsString]) -> (State, String) {
    let bindings: Vec<Binding> = specs
        .iter()
        .map(|spec| Binding::declared(spec, config).expect("test specs are well formed"))
        .collect();
    let registry = registry_of(config);
    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &bindings,
            unusable: &[],
            argv,
            registry: &registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("the command exists, so the run must reach it");
    (outcome.state, String::from_utf8_lossy(&notes).into_owned())
}

#[test]
fn a_bare_name_reaches_the_variable_the_program_reads() {
    let dir = scratch("alias-bare");
    let stub = stub_infisical(&dir, &Backend::Injects(DECOY));
    let marker = dir.join("seen");
    let config = config_with(
        &stub,
        r#"{"LABEL_FOR_ONE_ENVIRONMENT":
             {"store":"infisical","env":"staging","key":"THE_VARIABLE"}}"#,
    );

    let argv = witness_env(&marker, &["THE_VARIABLE", "LABEL_FOR_ONE_ENVIRONMENT"]);
    let (state, notes) = run_declared(&config, &["LABEL_FOR_ONE_ENVIRONMENT"], &argv);
    let seen = witnessed_env(&marker);

    // The whole fix, in one assertion: the program's variable is set, from a
    // command that never mentions it.
    assert_eq!(
        seen.get("THE_VARIABLE").map(String::as_str),
        Some(DECOY),
        "the variable the program reads was not set: {seen:?}"
    );
    // And nothing that worked before has stopped working.
    assert_eq!(
        seen.get("LABEL_FOR_ONE_ENVIRONMENT").map(String::as_str),
        Some(DECOY),
        "the declared name stopped arriving: {seen:?}"
    );
    assert_eq!(state, State::Injected);
    // The point of the design rather than a nicety: a lesson nobody has to read
    // is one nobody can skip. A warning here would mean the wall was still
    // there with a sign on it.
    assert_eq!(
        notes, "",
        "nothing needed saying, so nothing may be said: {notes}"
    );
}

#[test]
fn a_spelled_target_stays_exactly_as_narrow_as_it_was_typed() {
    let dir = scratch("alias-spelled");
    let stub = stub_infisical(&dir, &Backend::Injects(DECOY));
    let marker = dir.join("seen");
    let config = config_with(
        &stub,
        r#"{"LABEL":{"store":"infisical","env":"staging","key":"THE_VARIABLE"}}"#,
    );

    let argv = witness_env(&marker, &["CHOSEN", "THE_VARIABLE", "LABEL"]);
    let (_, notes) = run_declared(&config, &["CHOSEN=LABEL"], &argv);
    let seen = witnessed_env(&marker);

    assert_eq!(seen.get("CHOSEN").map(String::as_str), Some(DECOY));
    // `VAR=NAME` is an instruction, not a hint. Widening it would make the one
    // precise form in the tool imprecise, and every escape hatch here depends
    // on it meaning exactly what it says.
    assert_eq!(
        seen.get("THE_VARIABLE").map(String::as_str),
        Some("<unset>")
    );
    assert_eq!(seen.get("LABEL").map(String::as_str), Some("<unset>"));
    assert_eq!(notes, "");
}

#[test]
fn a_name_with_nothing_declared_binds_to_itself_and_nothing_else() {
    let dir = scratch("alias-plain");
    let stub = stub_infisical(&dir, &Backend::Injects(DECOY));
    let marker = dir.join("seen");
    let config = config_with(&stub, r#"{"PLAIN":{"store":"infisical","env":"staging"}}"#);

    let argv = witness_env(&marker, &["PLAIN"]);
    let (state, notes) = run_declared(&config, &["PLAIN"], &argv);

    assert_eq!(
        witnessed_env(&marker).get("PLAIN").map(String::as_str),
        Some(DECOY)
    );
    assert_eq!(state, State::Injected);
    assert_eq!(notes, "");
}

#[test]
fn a_declaration_cannot_choose_which_program_the_child_runs() {
    let dir = scratch("alias-hijack");
    let stub = stub_infisical(&dir, &Backend::Injects(DECOY));
    let marker = dir.join("seen");
    // A config arrives by `--config` or `KEYLESS_CONFIG`, so it is not a trusted
    // input. Bound to `PATH`, the stored VALUE would decide which `sh` runs —
    // and the masker would redact the value out of everything printed while it
    // did. Derived variables go through the same refusal a typed one does.
    let config = config_with(
        &stub,
        r#"{"LABEL":{"store":"infisical","env":"staging","var":"PATH"}}"#,
    );

    let argv = witness_env(&marker, &["PATH", "LABEL"]);
    let (state, _) = run_declared(&config, &["LABEL"], &argv);
    let seen = witnessed_env(&marker);

    assert_ne!(
        seen.get("PATH").map(String::as_str),
        Some(DECOY),
        "a declaration put a stored value in PATH"
    );
    // Dropped, not fatal: the caller asked for a name, and the name still
    // arrives in its own variable.
    assert_eq!(seen.get("LABEL").map(String::as_str), Some(DECOY));
    assert_eq!(state, State::Injected);
}

#[test]
fn two_names_answering_to_one_variable_are_not_decided_by_flag_order() {
    let dir = scratch("alias-collide");
    let stub = stub_infisical(&dir, &Backend::Injects(DECOY));
    let marker = dir.join("seen");
    // The ordinary shape of one credential per environment: two labels, one
    // variable. Asked for together, "the last flag wins" would hand the program
    // a real working credential from the wrong side of a boundary, silently.
    let config = config_with(
        &stub,
        r#"{"LABEL_A":{"store":"infisical","env":"staging","key":"SHARED"},
            "LABEL_B":{"store":"infisical","env":"prod","key":"SHARED"}}"#,
    );

    let argv = witness_env(&marker, &["SHARED", "LABEL_A", "LABEL_B"]);
    let (state, notes) = run_declared(&config, &["LABEL_A", "LABEL_B"], &argv);
    let seen = witnessed_env(&marker);

    assert_eq!(
        seen.get("SHARED").map(String::as_str),
        Some("<unset>"),
        "the shared variable was resolved by ordering: {seen:?}"
    );
    // Nothing is lost: each value is in its own variable, and the run is not
    // blocked.
    assert_eq!(seen.get("LABEL_A").map(String::as_str), Some(DECOY));
    assert_eq!(seen.get("LABEL_B").map(String::as_str), Some(DECOY));
    assert_eq!(state, State::Injected);
    // The one case where the right answer is not knowable from what was asked,
    // and therefore the one case that earns a message.
    assert!(
        notes.contains("SHARED") && notes.contains("LABEL_A") && notes.contains("LABEL_B"),
        "the undecidable case was not reported: {notes}"
    );
    assert!(!notes.contains(DECOY), "a value reached stderr: {notes}");
}

#[test]
fn a_derived_variable_never_displaces_one_the_caller_spelled() {
    let dir = scratch("alias-precedence");
    let stub = stub_infisical(&dir, &Backend::Injects(DECOY));
    let marker = dir.join("seen");
    let config = config_with(
        &stub,
        r#"{"CHOSEN_ONE":{"store":"infisical","env":"prod"},
            "OTHER":{"store":"infisical","env":"staging","key":"TARGET"}}"#,
    );

    let argv = witness_env(&marker, &["TARGET", "OTHER"]);
    let (_, notes) = run_declared(&config, &["TARGET=CHOSEN_ONE", "OTHER"], &argv);
    let seen = witnessed_env(&marker);

    // Both resolve to the same decoy here, so the assertion that carries the
    // property is the STDERR one below: an inference that overwrote an
    // instruction would make the typed form unreliable.
    assert_eq!(seen.get("TARGET").map(String::as_str), Some(DECOY));
    assert_eq!(seen.get("OTHER").map(String::as_str), Some(DECOY));
    assert!(
        notes.contains("TARGET") && notes.contains("OTHER"),
        "the displaced alias was not reported: {notes}"
    );
}
