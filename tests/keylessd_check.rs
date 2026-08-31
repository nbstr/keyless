//! What `keylessd check` prints, and whether its exit code agrees with it.
//!
//! # Why this drives the binary
//!
//! `check` is the one thing an operator runs to find out whether an install
//! worked. Its value is entirely in two properties that no unit test of a
//! component can see: that it prints EVERY row, and that its exit code says
//! what its rows say. Both were wrong, in the same direction — towards green.
//!
//! A bad pin returned before the identity row and every store row, so the
//! output stopped at the fault. That is during an install, which is when a pin
//! is most likely to be wrong and when those rows are what somebody is standing
//! there to read.
//!
//! And only the config warnings decided the exit code, so a report naming a
//! store that can serve nothing came back successful. A `PROBLEM` row over a
//! zero status is worse than either half alone: anything reading the status —
//! a script, a setup step, a person skimming — is told the install is sound
//! while the report beneath it says it is not.
//!
//! # Reading a row
//!
//! Every assertion here reads a column as a WHOLE WORD. `contains("ok")` is
//! satisfied by a report that says `PROBLEM`, because the detail beside it is a
//! sentence and sentences have `ok` in them; the same defect class
//! `state_vocabulary.rs` gates for the report `doctor` renders.

// Like the daemon it checks, and like `install_scripts.rs`: off macOS this file
// compiles to nothing and reports no tests, which leaves the suite's exact
// ignored count alone.
#![cfg(any(target_os = "macos", keyless_force_xnu))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A pin that decodes: 40 characters, the length of a code hash. Zeroes,
/// because what is exercised here is the parse and not any real image.
const WELL_FORMED_PIN: &str = "0000000000000000000000000000000000000000";

/// What the installer's own dry run prints in place of a hash, and therefore
/// the exact string somebody pastes into a config by mistake.
const PLACEHOLDER_PIN: &str = "<keylessd pin --path /usr/local/bin/keyless>";

/// Write the store at the mode the daemon insists on. A store any other user
/// could read is refused before its contents are looked at, and a fixture that
/// left the umask's mode on it would be testing that refusal instead.
fn write_store(dir: &Path, body: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("secrets.json");
    std::fs::write(&path, body).expect("store");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyless-check-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// This process's uid, read off a file it just made rather than through a
/// libc call, so nothing here needs `unsafe`.
fn own_uid(dir: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dir).expect("stat").uid()
}

/// Write a daemon config into `dir` and return the path to it.
fn config_at(dir: &Path, pin: &str) -> PathBuf {
    let path = dir.join("keylessd.json");
    std::fs::write(
        &path,
        format!(
            r#"{{
                 "socket": "{dir}/keylessd.sock",
                 "audit": "{dir}/audit.jsonl",
                 "peer": {{ "allow_uids": [{uid}], "allow_images": ["{pin}"] }},
                 "stores": {{ "file": {{ "enabled": true, "path": "{dir}/secrets.json" }} }}
               }}"#,
            dir = dir.display(),
            uid = own_uid(dir),
        ),
    )
    .expect("config");
    path
}

/// Run `check` with a `PATH` holding nothing.
///
/// Every case that is not about the `client` row gets an empty `PATH`, so the
/// row goes unproven and the report stays a statement about the fixture rather
/// than about whatever `keyless` happens to be installed on the machine running
/// the suite. Inheriting the real `PATH` here made the sound case red on any
/// machine with this tool installed — the fixture pins forty zeroes, and no
/// real binary has that hash.
fn check(config: &Path) -> Output {
    check_on_path(config, &std::ffi::OsString::new())
}

fn check_on_path(config: &Path, path: &std::ffi::OsStr) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keylessd"))
        .arg("check")
        .arg("--config")
        .arg(config)
        .env("PATH", path)
        .output()
        .expect("keylessd check")
}

/// Two real, differently-signed executables standing in for two builds of the
/// client. A copy keeps the signature it was built with, so each has a stable
/// code hash `codesign` reports — the property the pin rests on, exercised
/// rather than mocked.
const ONE_BUILD: &str = "/bin/ls";
const ANOTHER_BUILD: &str = "/bin/cat";

/// Put a copy of `source` at `<dir>/<sub>/keyless`, and return that directory.
fn plant(dir: &Path, sub: &str, source: &str) -> PathBuf {
    let bin = dir.join(sub);
    std::fs::create_dir_all(&bin).expect("bin dir");
    std::fs::copy(source, bin.join("keyless")).expect("copy");
    bin
}

/// The pin for a file, produced by the binary's own `pin` verb.
///
/// Not by a second implementation in the test: the whole claim is that what
/// `check` compares against `PATH` is what `pin` emits, and a fixture that
/// hashed the file itself would be free to agree with neither.
fn pin_of(file: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_keylessd"))
        .arg("pin")
        .arg("--path")
        .arg(file)
        .output()
        .expect("keylessd pin");
    assert!(
        output.status.success(),
        "pin failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("hex")
        .trim()
        .to_owned()
}

fn rendered(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The word after `subject` on the row `subject` opens, or `None` when the
/// report has no such row at all.
fn word_after<'a>(rows: &'a str, subject: &str) -> Option<&'a str> {
    rows.lines()
        .find(|line| line.split_whitespace().next() == Some(subject))
        .and_then(|line| line.split_whitespace().nth(1))
}

/// The state word of the `store` row for one backend id.
fn store_state<'a>(rows: &'a str, id: &str) -> Option<&'a str> {
    rows.lines()
        .filter(|line| line.split_whitespace().next() == Some("store"))
        .find(|line| line.split_whitespace().nth(1) == Some(id))
        .and_then(|line| line.split_whitespace().nth(2))
}

#[test]
fn a_sound_install_is_green_and_says_so_in_every_row() {
    // The control for both tests below. Without it, an assertion that a broken
    // install exits non-zero is satisfied by a `check` that never exits zero.
    let dir = scratch("sound");
    write_store(&dir, br#"{"DECOY":"decoy-check-0091"}"#);
    let output = check(&config_at(&dir, WELL_FORMED_PIN));

    let rows = rendered(&output);
    assert_ne!(word_after(&rows, "policy"), Some("PROBLEM"), "{rows}");
    assert_eq!(store_state(&rows, "file"), Some("ok"), "{rows}");
    assert!(output.status.success(), "{rows}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_pin_does_not_hide_the_rows_underneath_it() {
    // Measured with the placeholder the installer's own dry run prints, which
    // is the string somebody pastes in by mistake. `check` used to return at
    // the policy row, so the identity row and every store row went unprinted.
    let dir = scratch("pin");
    write_store(&dir, br#"{"DECOY":"decoy-check-0092"}"#);
    let output = check(&config_at(&dir, PLACEHOLDER_PIN));

    let rows = rendered(&output);
    assert_eq!(word_after(&rows, "policy"), Some("PROBLEM"), "{rows}");
    assert_eq!(
        store_state(&rows, "file"),
        Some("ok"),
        "the store rows were suppressed by the policy fault above them: {rows}"
    );
    assert!(
        word_after(&rows, "routing").is_some(),
        "the report stopped at the first fault: {rows}"
    );
    assert!(!output.status.success(), "{rows}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_store_that_was_emptied_is_a_problem_row_and_a_non_zero_status() {
    // The state `install -m 0600 /dev/null` over a full store leaves behind:
    // right mode, right owner, nothing in it. Every permission check passes and
    // no name can resolve. Green here is the whole hazard — losing the store is
    // bad, and reporting healthy afterwards is what makes it unnoticeable.
    let dir = scratch("emptied");
    write_store(&dir, b"");
    let output = check(&config_at(&dir, WELL_FORMED_PIN));

    let rows = rendered(&output);
    assert_eq!(store_state(&rows, "file"), Some("PROBLEM"), "{rows}");
    assert!(rows.contains("holds no names"), "{rows}");
    assert!(
        !output.status.success(),
        "a store that can serve nothing exited successfully: {rows}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The `client` row, driven end to end: two builds on one `PATH`, one of them
/// pinned by the binary's own `pin` verb.
///
/// This is the failure measured on a real install. `install/install.sh` put the
/// client in `/usr/local/bin` and pinned it; a copy from an earlier
/// `cargo install` sat ahead of it on `PATH`; the shell ran that one. What the
/// operator saw was `unrecognized subcommand`, and what a client would have
/// seen is `not a pinned client` — two messages that both name the wrong thing.
/// Nothing in the tool said there were two files.
mod client {
    use super::*;

    #[test]
    fn the_pinned_client_reached_first_is_reported_ok_and_stays_green() {
        // The control. Without it, the shadow assertion below is satisfied by a
        // report that says PROBLEM about every PATH it is ever given.
        let dir = scratch("client-ok");
        write_store(&dir, br#"{"DECOY":"decoy-check-0093"}"#);
        let good = plant(&dir, "good", ONE_BUILD);
        let other = plant(&dir, "other", ANOTHER_BUILD);
        let config = config_at(&dir, &pin_of(&good.join("keyless")));

        let path = std::env::join_paths([good.as_path(), other.as_path()]).expect("a PATH");
        let output = check_on_path(&config, &path);

        let rows = rendered(&output);
        assert_eq!(word_after(&rows, "client"), Some("ok"), "{rows}");
        assert!(output.status.success(), "{rows}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unpinned_client_ahead_of_the_pinned_one_is_a_problem_and_names_both() {
        let dir = scratch("client-shadow");
        write_store(&dir, br#"{"DECOY":"decoy-check-0094"}"#);
        let stale = plant(&dir, "stale", ANOTHER_BUILD);
        let good = plant(&dir, "good", ONE_BUILD);
        let config = config_at(&dir, &pin_of(&good.join("keyless")));

        // The same two files as the test above, in the other order. That is the
        // whole difference between the green case and this one.
        let path = std::env::join_paths([stale.as_path(), good.as_path()]).expect("a PATH");
        let output = check_on_path(&config, &path);

        let rows = rendered(&output);
        assert_eq!(word_after(&rows, "client"), Some("PROBLEM"), "{rows}");
        assert!(
            rows.contains(&stale.join("keyless").display().to_string()),
            "the report did not name the file being reached: {rows}"
        );
        assert!(
            rows.contains(&good.join("keyless").display().to_string()),
            "the report did not name the pinned client: {rows}"
        );
        assert!(
            !output.status.success(),
            "a shadowed client exited successfully: {rows}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_client_this_daemon_cannot_identify_is_read_and_never_touched() {
        // A `keyless` on PATH that is not the pinned image is somebody's file.
        // It is hashed, which reads it, and nothing else may happen to it — and
        // the remedy printed beside it must not tell anybody to delete a file
        // this daemon cannot identify.
        let dir = scratch("client-untouched");
        write_store(&dir, br#"{"DECOY":"decoy-check-0095"}"#);
        let stranger = plant(&dir, "stranger", ANOTHER_BUILD);
        let file = stranger.join("keyless");
        let before = std::fs::read(&file).expect("fixture");
        let good = plant(&dir, "good", ONE_BUILD);
        let config = config_at(&dir, &pin_of(&good.join("keyless")));

        let path = std::env::join_paths([stranger.as_path(), good.as_path()]).expect("a PATH");
        let rows = rendered(&check_on_path(&config, &path));

        assert_eq!(
            word_after(&rows, "client"),
            Some("PROBLEM"),
            "the row that reads this file did not report on it: {rows}"
        );
        assert!(file.exists(), "the file was removed: {rows}");
        assert_eq!(before, std::fs::read(&file).expect("fixture"), "{rows}");
        assert!(
            rows.lines().all(|line| !line.contains("rm ")),
            "a delete was proposed for a file nothing here can identify: {rows}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pin_no_client_on_path_matches_is_a_problem_rather_than_silence() {
        // The other half of the same bug, and the quieter one: the pin is for a
        // binary that is not what the shell reaches. Every request is refused
        // and the config looks correct in isolation.
        let dir = scratch("client-none");
        write_store(&dir, br#"{"DECOY":"decoy-check-0096"}"#);
        let stale = plant(&dir, "stale", ANOTHER_BUILD);
        let elsewhere = plant(&dir, "elsewhere", ONE_BUILD);
        let config = config_at(&dir, &pin_of(&elsewhere.join("keyless")));

        let path = std::env::join_paths([stale.as_path()]).expect("a PATH");
        let output = check_on_path(&config, &path);

        let rows = rendered(&output);
        assert_eq!(word_after(&rows, "client"), Some("PROBLEM"), "{rows}");
        assert!(!output.status.success(), "{rows}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_with_no_client_on_it_is_unproven_and_costs_no_exit_code() {
        // One process's PATH is never the next shell's, so a clean walk is a
        // gap and must not read as a pass — nor as a fault, which would red
        // every daemon-only machine.
        let dir = scratch("client-absent");
        write_store(&dir, br#"{"DECOY":"decoy-check-0097"}"#);
        let empty = plant(&dir, "empty", ONE_BUILD);
        std::fs::remove_file(empty.join("keyless")).expect("empty the directory");
        let config = config_at(&dir, WELL_FORMED_PIN);

        let path = std::env::join_paths([empty.as_path()]).expect("a PATH");
        let output = check_on_path(&config, &path);

        let rows = rendered(&output);
        assert_eq!(word_after(&rows, "client"), Some("unproven"), "{rows}");
        assert!(output.status.success(), "{rows}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
