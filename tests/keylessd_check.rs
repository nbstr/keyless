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

fn check(config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_keylessd"))
        .arg("check")
        .arg("--config")
        .arg(config)
        .output()
        .expect("keylessd check")
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
