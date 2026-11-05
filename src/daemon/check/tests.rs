use super::*;

/// A pin that decodes: 40 characters, the length of a code hash.
const WELL_FORMED_PIN: &str = "0000000000000000000000000000000000000000";

/// What the installer's dry run prints in place of a hash, and therefore
/// the exact string somebody pastes into a config by mistake.
const PLACEHOLDER_PIN: &str = "<keylessd pin --path /usr/local/bin/keyless>";

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyless-check-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// A store at the mode the daemon insists on. A store any other user could
/// read is refused before its contents are looked at, so a fixture left at
/// the umask's mode would be exercising that refusal instead.
fn write_store(dir: &Path, body: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("secrets.json");
    std::fs::write(&path, body).expect("store");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
}

fn config_with(dir: &Path, pin: &str) -> DaemonConfig {
    serde_json::from_str(&format!(
        r#"{{
                 "socket": "{dir}/keylessd.sock",
                 "audit": "{dir}/audit.jsonl",
                 "peer": {{ "allow_uids": [1], "allow_images": ["{pin}"] }},
                 "stores": {{ "file": {{ "enabled": true, "path": "{dir}/secrets.json" }} }}
               }}"#,
        dir = dir.display(),
    ))
    .expect("a valid daemon config")
}

/// Render the report with the client question deliberately unanswerable.
///
/// Every case below is about a row other than `client`, and a walk of the
/// real `PATH` would make each of them a statement about the machine the
/// suite runs on. [`super::super::shadow`] has its own tests for the walk.
fn rendered(config: &DaemonConfig, dir: &Path) -> (String, bool) {
    rendered_for(config, dir, &Client::NoPath)
}

fn rendered_for(config: &DaemonConfig, dir: &Path, client: &Client) -> (String, bool) {
    let mut out: Vec<u8> = Vec::new();
    let sound = report(config, &dir.join("keylessd.json"), client, &mut out).expect("a Vec");
    (String::from_utf8(out).expect("ASCII rows"), sound)
}

/// The word after `subject` on the row it opens. Read as a whole word: `ok`
/// is a substring of the sentences printed beside `PROBLEM`, so a
/// `contains` here would be satisfied by the state it exists to exclude.
fn word_after<'a>(rows: &'a str, subject: &str) -> Option<&'a str> {
    rows.lines()
        .find(|line| line.split_whitespace().next() == Some(subject))
        .and_then(|line| line.split_whitespace().nth(1))
}

fn store_state<'a>(rows: &'a str, id: &str) -> Option<&'a str> {
    rows.lines()
        .filter(|line| line.split_whitespace().next() == Some("store"))
        .find(|line| line.split_whitespace().nth(1) == Some(id))
        .and_then(|line| line.split_whitespace().nth(2))
}

#[test]
fn a_sound_install_reports_sound() {
    // The control for both tests below. Without it, an assertion that a
    // broken install is reported broken is satisfied by a report that is
    // never sound about anything.
    let dir = scratch("sound");
    write_store(&dir, br#"{"DECOY":"decoy-check-0181"}"#);
    let (rows, sound) = rendered(&config_with(&dir, WELL_FORMED_PIN), &dir);

    assert_ne!(word_after(&rows, "policy"), Some("PROBLEM"), "{rows}");
    assert_eq!(store_state(&rows, "file"), Some("ok"), "{rows}");
    assert!(sound, "{rows}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_pin_does_not_hide_the_rows_underneath_it() {
    let dir = scratch("pin");
    write_store(&dir, br#"{"DECOY":"decoy-check-0182"}"#);
    let (rows, sound) = rendered(&config_with(&dir, PLACEHOLDER_PIN), &dir);

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
    assert!(!sound, "{rows}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_store_that_was_emptied_is_a_problem_row_and_not_a_sound_report() {
    // The state `install -m 0600 /dev/null` over a full store leaves
    // behind: right mode, right owner, nothing in it. Every permission
    // check passes and no name can resolve. Green here is the whole hazard
    // — losing the store is bad, and reporting healthy afterwards is what
    // makes it unnoticeable.
    let dir = scratch("emptied");
    write_store(&dir, b"");
    let (rows, sound) = rendered(&config_with(&dir, WELL_FORMED_PIN), &dir);

    assert_eq!(store_state(&rows, "file"), Some("PROBLEM"), "{rows}");
    assert!(rows.contains("holds no names"), "{rows}");
    assert!(
        !sound,
        "a store that can serve nothing was reported sound: {rows}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
