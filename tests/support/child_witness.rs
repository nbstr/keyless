use std::ffi::OsString;
use std::path::Path;

/// A child command that proves it ran.
///
/// It writes the value of `$var` — or the literal `<unset>` when the variable
/// is absent — into `marker`, then exits with `code`. That single file answers
/// both questions a never-block test must ask: did the child run at all, and
/// did it see an environment we did or did not modify.
pub fn witness(marker: &Path, var: &str, code: i32) -> Vec<OsString> {
    vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(format!(
            "printf '%s' \"${{{var}-<unset>}}\" > \"$1\"; exit {code}"
        )),
        OsString::from("sh"),
        OsString::from(marker),
    ]
}

/// A child command that reports SEVERAL names out of one environment.
///
/// It writes one `NAME=value` line per name — the literal `<unset>` where the
/// variable is absent — then exits 0.
///
/// One child rather than one per name, because "did exactly the asked-for set
/// arrive?" is a question about a single environment. Two children are two
/// environments, and a name could be present in one and absent in the other
/// with neither run able to notice.
pub fn witness_env(marker: &Path, vars: &[&str]) -> Vec<OsString> {
    let mut script = String::from(": > \"$1\"");
    for var in vars {
        // The format string is fixed and the value arrives as an argument, so a
        // value holding a `%` is reported rather than interpreted.
        script.push_str(&format!(
            "; printf '%s=%s\\n' '{var}' \"${{{var}-<unset>}}\" >> \"$1\""
        ));
    }
    script.push_str("; exit 0");
    vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(script),
        OsString::from("sh"),
        OsString::from(marker),
    ]
}

/// What a [`witness_env`] child recorded, as a map from name to value.
///
/// # Panics
///
/// When a line is not `NAME=value`. A record this cannot read is a fixture
/// failure, and skipping the line instead would report the name as absent —
/// which is exactly the answer several callers assert on.
pub fn witnessed_env(marker: &Path) -> std::collections::BTreeMap<String, String> {
    witnessed(marker)
        .lines()
        .map(|line| {
            let (name, value) = line.split_once('=').unwrap_or_else(|| {
                panic!("the witness wrote a line that is not NAME=value: {line}")
            });
            (name.to_owned(), value.to_owned())
        })
        .collect()
}

/// A child command that prints `text` to stdout and exits 0.
pub fn echoes(text: &str) -> Vec<OsString> {
    vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from("printf '%s' \"$1\""),
        OsString::from("sh"),
        OsString::from(text),
    ]
}

/// Run one command through the library and return what happened, plus what the
/// caller would have seen on stderr.
///
/// Shared rather than copied into each test crate: every never-block property
/// asks the same three questions of the same call, and two copies of the setup
/// would eventually answer them differently.
pub fn run_with(
    registry: &keyless::store::Registry,
    specs: &[&str],
    argv: &[OsString],
    warnings: &[String],
) -> (keyless::cmd::run::Outcome, String) {
    run_with_tty(
        registry,
        specs,
        argv,
        warnings,
        keyless::cmd::run::TtyPolicy::Pipes,
    )
}

/// The same, choosing how the child's terminal is arranged.
///
/// The policy is named rather than left to `Auto` on purpose. `Auto` reads the
/// *test harness's* stdio, which is a pipe under `cargo test` and a terminal
/// under `cargo test -- --nocapture` from a shell — so an `Auto` here would make
/// these tests take a different code path depending on how they were invoked.
pub fn run_with_tty(
    registry: &keyless::store::Registry,
    specs: &[&str],
    argv: &[OsString],
    warnings: &[String],
    tty: keyless::cmd::run::TtyPolicy,
) -> (keyless::cmd::run::Outcome, String) {
    use keyless::cmd::run::{Binding, RunRequest, run};

    let bindings: Vec<Binding> = specs
        .iter()
        .map(|spec| Binding::parse(spec).expect("test specs are well formed"))
        .collect();
    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &bindings,
            unusable: &[],
            argv,
            registry,
            audit: None,
            warnings,
            tty,
        },
        &mut notes,
    )
    .expect("run must not fail when a command was given");
    (outcome, String::from_utf8_lossy(&notes).into_owned())
}

/// What the witness child recorded.
pub fn witnessed(marker: &Path) -> String {
    std::fs::read_to_string(marker).unwrap_or_else(|error| {
        panic!(
            "the child did not run: {} is unreadable ({error})",
            marker.display()
        )
    })
}
