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

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use keyless::config::Config;
#[cfg(any(target_os = "macos", keyless_force_xnu))]
use keyless::daemon::config::DaemonConfig;
use keyless::paths::{ConfigPath, home};
use support::{Backend, Listing, PROTON_DECOY, recorded, scratch, stub_pass_cli_listing};

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// One live item, so the name form resolves without a real vault.
const ONE_LIVE_ITEM: &str = r#"{"items":[{"id":"ITEM1","share_id":"SHARE1",
     "state":"Active","title":"Router","item_type":"login"}]}"#;

/// A scratch directory plus the fake home every child is given.
struct Fixture {
    dir: PathBuf,
    home: PathBuf,
    binary: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let dir = scratch(tag);
        let home = dir.join("home");
        std::fs::create_dir_all(&home).expect("create the fake home");
        let binary = stub_pass_cli_listing(
            &dir,
            &Backend::Injects(PROTON_DECOY),
            &Listing::Json(ONE_LIVE_ITEM),
        );
        Fixture { dir, home, binary }
    }

    /// Write a config whose Proton session directory is `session_dir`, verbatim.
    fn config(&self, session_dir: &str) -> PathBuf {
        let path = self.dir.join("config.json");
        let body = format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "proton":{{"enabled":true,"binary":"{binary}","session_dir":"{session_dir}",
                            "timeout_ms":60000}}}},
               "secrets":{{"HOME_WIFI":{{"vault":"Personal","item":"Router","field":"password"}}}}}}"#,
            binary = self.binary.display()
        );
        std::fs::write(&path, body).expect("write config");
        path
    }

    /// Run the real binary with this fixture's home, or with none at all.
    fn keyless(&self, config: &Path, home: Option<&Path>, args: &[&str]) -> Output {
        let mut command = Command::new(BIN);
        command
            .arg("--config")
            .arg(config)
            .arg("--no-audit")
            .args(args);
        match home {
            Some(path) => command.env("HOME", path),
            None => command.env_remove("HOME"),
        };
        command.output().expect("the binary must run")
    }

    /// What `PROTON_PASS_SESSION_DIR` the stub was handed, if it ran at all.
    fn session_seen(&self) -> Option<String> {
        let path = self.dir.join("pass-cli.session");
        path.exists().then(|| recorded(&path))
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

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

    assert!(report.contains("store    proton PROBLEM"), "{report}");
    assert!(report.contains("relative path"), "{report}");
    assert!(!report.contains("store    proton ok"), "{report}");
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
// Every path field, not only the one the bug was reported against.
// ---------------------------------------------------------------------------

/// A `~` path for one field, and the absolute path it must become.
fn expected(marker: &str) -> (String, PathBuf) {
    let home = home().expect("this suite needs HOME set to check expansion");
    (format!("~/{marker}"), home.join(marker))
}

#[test]
fn every_session_config_path_field_expands() {
    // Written field by field rather than looped over a list the implementation
    // also reads: deleting a field from the config struct breaks this file at
    // compile time, and a list shared with the code would delete itself in the
    // same stroke.
    let fields = [
        "daemon-socket",
        "keychain-binary",
        "infisical-binary",
        "infisical-config-dir",
        "infisical-probe",
        "proton-binary",
        "proton-session",
        "proton-probe",
        "proton-manager-session",
    ];
    let path = |marker: &str| expected(marker).0;
    let json = format!(
        r#"{{"stores":{{
             "daemon":{{"socket":"{}"}},
             "keychain":{{"binary":"{}"}},
             "infisical":{{"binary":"{}","config_dir":"{}","probe_binary":"{}"}},
             "proton":{{"binary":"{}","session_dir":"{}","probe_binary":"{}",
                        "manager":{{"session_dir":"{}"}}}}}}}}"#,
        path(fields[0]),
        path(fields[1]),
        path(fields[2]),
        path(fields[3]),
        path(fields[4]),
        path(fields[5]),
        path(fields[6]),
        path(fields[7]),
        path(fields[8]),
    );
    let config: Config = serde_json::from_str(&json).expect("valid config");
    let stores = &config.stores;
    let proton_manager = stores.proton.manager.as_ref().expect("a manager block");

    let checked: Vec<(&str, PathBuf)> = vec![
        ("daemon-socket", stores.daemon.socket_path()),
        ("keychain-binary", stores.keychain.binary.to_path_buf()),
        ("infisical-binary", stores.infisical.binary.to_path_buf()),
        (
            "infisical-config-dir",
            stores
                .infisical
                .config_dir
                .as_deref()
                .expect("set")
                .to_path_buf(),
        ),
        (
            "infisical-probe",
            stores.infisical.probe_binary.to_path_buf(),
        ),
        ("proton-binary", stores.proton.binary.to_path_buf()),
        (
            "proton-session",
            stores
                .proton
                .session_dir
                .as_deref()
                .expect("set")
                .to_path_buf(),
        ),
        ("proton-probe", stores.proton.probe_binary.to_path_buf()),
        (
            "proton-manager-session",
            proton_manager
                .session_dir
                .as_deref()
                .expect("set")
                .to_path_buf(),
        ),
    ];

    for (marker, actual) in &checked {
        assert_eq!(*actual, expected(marker).1, "field `{marker}`");
    }
    // The tripwire. A path field added to the config and not added here leaves
    // this number stale, and the assertion below is what says so — the loop
    // above cannot, because it only knows what it was told.
    assert_eq!(
        checked.len(),
        9,
        "the session config gained or lost a path field; cover it here"
    );
    assert_eq!(checked.len(), fields.len());
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
#[test]
fn every_daemon_config_path_field_expands() {
    let json = format!(
        r#"{{"socket":"{}","audit":"{}",
             "stores":{{"file":{{"path":"{}"}},
                        "keychain":{{"binary":"{}","keychain":"{}"}}}}}}"#,
        expected("daemon-socket").0,
        expected("daemon-audit").0,
        expected("daemon-file").0,
        expected("daemon-security").0,
        expected("daemon-keychain").0,
    );
    let config: DaemonConfig = serde_json::from_str(&json).expect("valid daemon config");

    let checked: Vec<(&str, PathBuf)> = vec![
        ("daemon-socket", config.socket.to_path_buf()),
        ("daemon-audit", config.audit.to_path_buf()),
        ("daemon-file", config.stores.file.path.to_path_buf()),
        (
            "daemon-security",
            config.stores.keychain.binary.to_path_buf(),
        ),
        (
            "daemon-keychain",
            config
                .stores
                .keychain
                .keychain
                .as_deref()
                .expect("set")
                .to_path_buf(),
        ),
    ];
    for (marker, actual) in &checked {
        assert_eq!(*actual, expected(marker).1, "field `{marker}`");
    }
    assert_eq!(
        checked.len(),
        5,
        "the daemon config gained or lost a path field; cover it here"
    );
}

#[test]
fn a_bare_binary_name_is_left_alone_so_path_lookup_still_works() {
    // The other half of the contract. `binary` is routinely `pass-cli` or
    // `infisical`, which are relative on purpose and resolved through `PATH`.
    // An implementation that made every config path absolute would break every
    // default install, and every test above would still pass.
    let config: Config = serde_json::from_str(
        r#"{"stores":{"proton":{"binary":"pass-cli"},"infisical":{"binary":"infisical"}}}"#,
    )
    .expect("valid config");
    assert_eq!(config.stores.proton.binary.as_path(), Path::new("pass-cli"));
    assert_eq!(
        config.stores.infisical.binary.as_path(),
        Path::new("infisical")
    );
    assert_eq!(
        Config::default().stores.keychain.binary.as_path(),
        Path::new("/usr/bin/security"),
        "a default must not be rewritten either"
    );
}

// ---------------------------------------------------------------------------
// The hole the newtype does NOT close, closed here instead.
// ---------------------------------------------------------------------------

#[test]
fn no_config_field_is_declared_as_a_bare_path_buf() {
    // A newtype guarantees that a field DECLARED as `ConfigPath` expands. It
    // guarantees nothing about the next field somebody declares `PathBuf`,
    // which compiles, runs, and silently reinstates the defect — the compiler
    // has no opinion about which of two path types was meant.
    //
    // So the enforcement is here: the two config modules are read as SOURCE at
    // compile time and every struct field of type `PathBuf` is reported. This
    // is the only thing in the repository that can fail on a field nobody
    // remembered to think about.
    //
    // Deliberately not a check on the whole crate: `PathBuf` is the right type
    // everywhere else, and a rule that fires on correct code gets deleted.
    for (label, source) in [
        ("src/config.rs", include_str!("../src/config.rs")),
        (
            "src/daemon/config.rs",
            include_str!("../src/daemon/config.rs"),
        ),
    ] {
        let offenders: Vec<&str> = source
            .lines()
            .map(str::trim)
            .filter(|line| line.ends_with(": PathBuf,") || line.ends_with(": Option<PathBuf>,"))
            .collect();
        assert!(
            offenders.is_empty(),
            "{label} declares a path field as PathBuf, which skips tilde expansion \
             entirely — declare it `ConfigPath`: {offenders:?}"
        );
    }
}

#[test]
fn the_offender_scan_can_actually_find_something() {
    // The negative control for the test above. A scan that matches nothing
    // because its pattern is wrong is indistinguishable from a clean module,
    // and it passes forever.
    let sample = "pub struct S {\n    pub a: ConfigPath,\n    pub b: PathBuf,\n    pub c: Option<PathBuf>,\n}";
    let found: Vec<&str> = sample
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(": PathBuf,") || line.ends_with(": Option<PathBuf>,"))
        .collect();
    assert_eq!(found, vec!["pub b: PathBuf,", "pub c: Option<PathBuf>,"]);
}

// ---------------------------------------------------------------------------
// The advice must be advice this build accepts.
// ---------------------------------------------------------------------------

/// Every `"key": "value"` a piece of text hands somebody to paste into a config.
///
/// Backslashes are stripped first so the same scan reads a Rust string literal
/// (`\"session_dir\": \"~/…\"`) and a Markdown code block identically.
fn config_values_advised(text: &str) -> Vec<String> {
    let text = text.replace('\\', "");
    let mut found = Vec::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find("\": \"") {
        rest = &rest[at + 4..];
        if let Some(end) = rest.find('"') {
            let value = &rest[..end];
            if !value.is_empty() {
                found.push(value.to_owned());
            }
            rest = &rest[end..];
        }
    }
    found
}

/// The whole point: this build must never print, or document, a path it refuses.
fn assert_advice_is_accepted(label: &str, text: &str, least: usize) {
    let advised = config_values_advised(text);
    for value in &advised {
        assert!(
            ConfigPath::expand(value).is_ok(),
            "{label} tells the reader to write `{value}`, which this build REFUSES: {:?}",
            ConfigPath::expand(value).err()
        );
    }
    // Without this, a scan whose pattern stopped matching passes forever — the
    // exact shape of false green a filtered test run has.
    assert!(
        advised.len() >= least,
        "{label}: the scan found only {} config values, so it has stopped reading the text",
        advised.len()
    );
}

#[test]
fn the_advice_scan_can_actually_find_something() {
    // The negative control. A refused value has to be detectable by this scan,
    // or every assertion built on it is vacuous.
    let sample = r#"set \"session_dir\": \"~bob/x\" and \"binary\": \"pass-cli\""#;
    let advised = config_values_advised(sample);
    assert_eq!(advised, vec!["~bob/x".to_owned(), "pass-cli".to_owned()]);
    assert!(ConfigPath::expand(&advised[0]).is_err());
    assert!(ConfigPath::expand(&advised[1]).is_ok());
}

#[test]
fn the_missing_session_dir_remedy_advises_a_path_this_build_accepts() {
    // The message a `doctor` reader is handed. It carried `~/.keyless-pass-session`
    // while `~` was taken literally, so following it produced the defect.
    let fixture = Fixture::new("remedy-session");
    let path = fixture.dir.join("no-session.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "proton":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}}}}"#,
            fixture.binary.display()
        ),
    )
    .expect("write config");

    let report = stdout_of(&fixture.keyless(&path, Some(&fixture.home), &["doctor"]));
    assert!(report.contains("session_dir` is not set"), "{report}");
    assert_advice_is_accepted("the missing-session_dir remedy", &report, 1);
    assert!(
        report.contains("expanded"),
        "the remedy must say a leading `~` is expanded, or a reader has no reason \
         to trust a tilde inside JSON: {report}"
    );
}

#[test]
fn the_manager_remedy_advises_a_path_this_build_accepts() {
    let fixture = Fixture::new("remedy-manager");
    let path = fixture.dir.join("no-manager.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "proton":{{"enabled":true,"binary":"{}","timeout_ms":60000,
                            "session_dir":"/tmp/keyless-reader"}}}},
               "secrets":{{"HOME_WIFI":{{"vault":"V","item":"I","field":"password"}}}}}}"#,
            fixture.binary.display()
        ),
    )
    .expect("write config");

    let stderr = stderr_of(&fixture.keyless(&path, Some(&fixture.home), &["new", "HOME_WIFI"]));
    assert!(stderr.contains("agent access grant"), "{stderr}");
    assert_advice_is_accepted("the mint-a-manager-token remedy", &stderr, 1);
    assert!(stderr.contains("expanded"), "{stderr}");
    assert!(
        stderr.contains("must not be relative"),
        "the remedy must rule out the other spelling of the same defect: {stderr}"
    );
}

#[test]
fn the_readme_never_advises_a_config_path_this_build_refuses() {
    // The documentation is read far more often than either message above, and
    // it is the one surface no runtime check can reach. Bound to the parser
    // here, so a `~user/…` or `$HOME/…` written into an example fails the suite
    // rather than teaching somebody the defect.
    assert_advice_is_accepted("README.md", include_str!("../README.md"), 20);
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
