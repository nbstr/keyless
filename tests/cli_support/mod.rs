#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output};

use crate::support::{Stub, keychain_stub_config};

pub const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// Write a config wired to a `security` stub, so no real keychain is touched.
///
/// `OTHER` is declared and asked for by nobody here: it is what makes the
/// narrowing cases mean something, since a config holding one name cannot show
/// that only the names requested reach the child.
pub fn config_with_stub(dir: &Path, behaviour: &Stub) -> std::path::PathBuf {
    keychain_stub_config(dir, behaviour, r#"{"DECOY":{"note":"a decoy"},"OTHER":{}}"#)
}

pub fn keyless(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .output()
        .expect("the binary must run")
}

pub fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Run the binary with extra environment, and with stdout captured (never a tty).
pub fn keyless_env(env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut command = Command::new(BIN);
    for (key, value) in env {
        command.env(key, value);
    }
    command.args(args).output().expect("the binary must run")
}

/// The one degraded line about `name`, whole, so a message meant for one name
/// cannot be satisfied by the other name's line.
pub fn line_for(stderr: &str, name: &str) -> String {
    let prefix = format!("keyless:   {name}: ");
    stderr
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no degraded line for `{name}` in: {stderr}"))
        .to_owned()
}

/// The one report row whose subject is `subject`.
/// The state column of a rendered row: `<mark> <subject> <state> <detail>`.
///
/// Read as a whole column, because `unproven` CONTAINS `proven` — so
/// `contains("proven")` passes on the one state it exists to exclude. Measured
/// over this tree: every `proven` in the crate can be rewritten to `unproven`,
/// leaving a green mark beside the word that denies it, and the suite stays
/// green.
pub fn state_of(row: &str) -> &str {
    row.split_whitespace().nth(2).unwrap_or_default()
}

pub fn row_for<'a>(report: &'a str, subject: &str) -> &'a str {
    report
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(subject))
        .unwrap_or_else(|| panic!("the report has no `{subject}` row:\n{report}"))
}
