//! `~` in a config path field, tested where the defect actually was.
//!
//! # The defect
//!
//! `"session_dir": "~/.keyless-pass-session"` was taken literally. `pass-cli`
//! then created a directory whose NAME is `~`, under whatever the working
//! directory happened to be — so ONE config minted a fresh, empty session per
//! directory the user stood in, and `keyless doctor` reported `0 problem(s)`
//! throughout.
//!
//! # Why these tests drive the BINARY rather than the expansion function
//!
//! The bug was at the parse boundary, not in an expansion routine — there was no
//! expansion routine. A test that calls
//! [`keyless::paths::ConfigPath::expand`] directly would have passed on the
//! broken build the moment that function existed, while every config field went
//! on ignoring it. So the tests that matter here start from a config FILE and
//! end at the argument `pass-cli` was actually handed, read out of a stub that
//! records it.
//!
//! Driving the real binary also buys the one thing an in-process test cannot
//! have: a controlled `HOME`. `std::env::set_var` is `unsafe` in edition 2024
//! and this suite runs its tests on several threads, so the expansion is
//! asserted against a home directory this file creates and passes to a child.
//! That turns "the result is absolute" into "the result is exactly this path".

mod config_paths_support;
mod support;

use std::path::{Path, PathBuf};

use keyless::paths::ConfigPath;

use config_paths_support::{Fixture, stderr_of, stdout_of};
use support::scratch;

// ---------------------------------------------------------------------------
// The regression. This is the test that must go red on the code as it was.
// ---------------------------------------------------------------------------

#[test]
fn a_tilde_session_dir_reaches_pass_cli_as_an_absolute_path() {
    // Before the fix, `pass-cli` was handed the four characters `~/.k…`
    // verbatim, and created a directory named `~` beside the caller. This
    // asserts on what the child was GIVEN, read out of the stub — not on what
    // the config struct holds — because the value only matters at that boundary.
    let fixture = Fixture::new("tilde-session");
    let config = fixture.config("~/.keyless-pass-session");

    let output = fixture.keyless(
        &config,
        Some(&fixture.home),
        &["run", "-s", "HOME_WIFI", "--", "/bin/echo", "ran"],
    );

    let seen = fixture
        .session_seen()
        .expect("`pass-cli` was never invoked, so nothing was expanded");
    assert_eq!(
        seen,
        fixture
            .home
            .join(".keyless-pass-session")
            .display()
            .to_string(),
        "the session directory handed to pass-cli"
    );
    assert!(
        Path::new(&seen).is_absolute(),
        "a session directory that is not absolute is a different session per working directory: {seen}"
    );
    assert!(
        !seen.contains('~'),
        "the tilde survived into the child: {seen}"
    );
    // And the run still worked, so this is a fix rather than a new refusal.
    assert!(stdout_of(&output).contains("ran"), "{output:?}");
}

#[test]
fn a_bare_tilde_is_the_home_directory_itself() {
    // `~` and `~/` name the same directory in every shell. Refusing the short
    // form would be an inconsistency bought for nothing.
    let fixture = Fixture::new("bare-tilde");
    let config = fixture.config("~");

    fixture.keyless(
        &config,
        Some(&fixture.home),
        &["run", "-s", "HOME_WIFI", "--", "/bin/echo", "ran"],
    );

    assert_eq!(
        fixture.session_seen().expect("pass-cli must have run"),
        fixture.home.display().to_string(),
        "a bare `~` must be the home directory, with no trailing separator"
    );
}

#[test]
fn an_absolute_session_dir_is_handed_over_byte_for_byte() {
    // The control for every expansion above: a path with no `~` must arrive
    // exactly as written. Without this, "expansion works" is satisfied by an
    // implementation that rewrites every path it sees.
    let fixture = Fixture::new("absolute-session");
    let absolute = fixture.dir.join("agent-session");
    let config = fixture.config(&absolute.display().to_string());

    fixture.keyless(
        &config,
        Some(&fixture.home),
        &["run", "-s", "HOME_WIFI", "--", "/bin/echo", "ran"],
    );

    assert_eq!(
        fixture.session_seen().expect("pass-cli must have run"),
        absolute.display().to_string()
    );
}

// ---------------------------------------------------------------------------
// The three refused forms. Each must be loud, and none may block the command.
// ---------------------------------------------------------------------------

/// Whether the child gets this fixture's fake home, or none at all.
enum Home {
    Fake,
    Unset,
}

/// Every refusal shares this shape: the config is reported as a problem, the
/// command still runs, and no store is left holding the written path.
///
/// The child command binds NO secret, deliberately. A refused parse falls back
/// to the default config, whose keychain backend is enabled and points at the
/// real `/usr/bin/security` — so resolving a name here would be this suite's
/// only invocation of a real vendor binary. Binding nothing consults no store
/// and still proves the two things at issue: the refusal is printed, and the
/// command runs anyway.
fn assert_refused(tag: &str, session_dir: &str, home: &Home, expected: &[&str]) {
    let dir = scratch(tag);
    let fake_home = dir.join("home");
    std::fs::create_dir_all(&fake_home).expect("create the fake home");
    let fixture = Fixture {
        dir,
        home: fake_home,
        binary: PathBuf::from("/nonexistent/keyless-test/pass-cli"),
    };
    let config = fixture.config(session_dir);
    let home = match home {
        Home::Fake => Some(fixture.home.clone()),
        Home::Unset => None,
    };

    let output = fixture.keyless(&config, home.as_deref(), &["run", "--", "/bin/echo", "ran"]);
    let stderr = stderr_of(&output);
    for fragment in expected {
        assert!(
            stderr.contains(fragment),
            "the refusal must name `{fragment}`, said: {stderr}"
        );
    }
    // Never blocks. The whole tool rests on this and a config refusal is no
    // exception: the command runs with an unmodified environment.
    assert!(
        stdout_of(&output).contains("ran"),
        "the child must still run: {output:?}"
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        fixture.session_seen().is_none(),
        "a refused path must reach no child"
    );
}

#[test]
fn another_users_home_is_refused_rather_than_taken_literally() {
    // The standard library cannot read the passwd database and a secrets tool
    // should not spawn `getent` to save a keystroke. Passing it through is the
    // original defect under a different spelling, so it is refused by name.
    assert_refused(
        "tilde-user",
        "~someoneelse/.keyless-pass-session",
        &Home::Fake,
        &["~someoneelse/.keyless-pass-session", "another user's home"],
    );
}

#[test]
fn a_shell_variable_is_refused_rather_than_taken_literally() {
    // A config file is not a shell. `$HOME/x` would otherwise become a
    // directory literally named `$HOME` — the same bug, one character over.
    assert_refused(
        "dollar-home",
        "$HOME/.keyless-pass-session",
        &Home::Fake,
        &["$HOME", "not a shell"],
    );
}

#[test]
fn a_tilde_with_no_home_is_refused_rather_than_taken_literally() {
    // The one case where expansion is impossible. Falling back to the working
    // directory — which is what `Paths::discover` does for the config's OWN
    // location, deliberately — would recreate the defect exactly.
    assert_refused(
        "no-home",
        "~/no-home-here",
        &Home::Unset,
        &["HOME` is unset or empty", "absolute path"],
    );
}

// ---------------------------------------------------------------------------
// Relative: the same defect wearing different clothes.
// ---------------------------------------------------------------------------

#[test]
fn a_relative_session_dir_degrades_the_name_and_still_runs_the_command() {
    let fixture = Fixture::new("relative-session");
    let config = fixture.config("agent-session");

    let output = fixture.keyless(
        &config,
        Some(&fixture.home),
        &["run", "-s", "HOME_WIFI", "--", "/bin/echo", "ran"],
    );
    let stderr = stderr_of(&output);

    assert!(stderr.contains("DEGRADED"), "{stderr}");
    assert!(stderr.contains("relative path"), "{stderr}");
    assert!(
        stderr.contains("working directory"),
        "the message must say WHY relative is wrong: {stderr}"
    );
    assert!(
        fixture.session_seen().is_none(),
        "nothing may be spawned against a relative session directory"
    );
    assert!(stdout_of(&output).contains("ran"), "{output:?}");
}

#[test]
fn doctor_never_calls_a_relative_session_dir_ok() {
    // `doctor` has no power to block anything — its own report says a problem
    // degrades a run and never blocks one — so "refuse it in doctor" can only
    // mean "never report it ok", plus a non-zero exit code.
    let fixture = Fixture::new("relative-doctor");
    let config = fixture.config("agent-session");

    let output = fixture.keyless(&config, Some(&fixture.home), &["doctor"]);
    let report = stdout_of(&output);

    let proton = report
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some("proton"))
        .unwrap_or_else(|| panic!("the report has no `proton` row:\n{report}"));
    assert!(!proton.contains("proven"), "{report}");
    assert!(report.contains("relative path"), "{report}");
    assert!(!report.contains("\n0 problem(s)"), "{report}");
    assert_eq!(output.status.code(), Some(1), "{report}");
}

#[test]
fn a_relative_manager_session_dir_refuses_the_write_outright() {
    // The documented asymmetry: a read degrades because refusing would block
    // somebody's command, and a write refuses because a write that "degraded"
    // would report success with nothing stored.
    let fixture = Fixture::new("relative-manager");
    let path = fixture.dir.join("manager-config.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},"proton":{{"enabled":true,
                 "binary":"{binary}","session_dir":"/tmp/keyless-reader",
                 "timeout_ms":60000,
                 "manager":{{"session_dir":"manager-session"}}}}}},
               "secrets":{{"HOME_WIFI":{{"store":"proton","vault":"Personal",
                 "item":"Router","field":"password"}}}}}}"#,
            binary = fixture.binary.display()
        ),
    )
    .expect("write config");

    let output = fixture.keyless(&path, Some(&fixture.home), &["new", "HOME_WIFI"]);
    let stderr = stderr_of(&output);

    assert!(stderr.contains("manager.session_dir"), "{stderr}");
    assert!(stderr.contains("relative path"), "{stderr}");
    // EX_CONFIG: nothing was attempted and a file needs editing.
    assert_eq!(output.status.code(), Some(78), "{stderr}");
    assert!(
        fixture.session_seen().is_none(),
        "nothing may be written through a relative session directory"
    );
}

// ---------------------------------------------------------------------------
// The rule itself, for the cases a config file cannot reach twice.
// ---------------------------------------------------------------------------

#[test]
fn the_expansion_rule_refuses_by_name_and_passes_the_rest_through() {
    // Driving the function directly, which the tests above deliberately do not.
    // It is worth exactly one test: it pins the WORDING the refusals carry, and
    // it cannot say anything about whether config parsing calls it — that is
    // what everything above this line is for.
    assert!(ConfigPath::expand("~alice/x").is_err());
    assert!(ConfigPath::expand("$HOME/x").is_err());
    assert!(ConfigPath::expand("~alice").is_err());
    assert_eq!(
        ConfigPath::expand("/etc/passwd")
            .expect("absolute")
            .as_path(),
        Path::new("/etc/passwd")
    );
    assert_eq!(
        ConfigPath::expand("relative/thing")
            .expect("relative")
            .as_path(),
        Path::new("relative/thing")
    );
    // A path that genuinely starts with one of the refused characters is still
    // reachable, and the refusals say so.
    assert_eq!(
        ConfigPath::expand("./~odd").expect("escaped").as_path(),
        Path::new("./~odd")
    );
}
