//! An interrupted session write is named, never called plain absent.

mod stores_support;
mod support;

use std::path::Path;
use std::time::Duration;

use support::{SCOPED_SESSION_DIR, scratch, stub_pass_cli_discovery};

use stores_support::{
    LIVE_AND_TRASHED, ONE_VAULT, PROTON_REFERENCE, doctor_report, flattened, proton_config,
    proton_row, state_of,
};

// ---------------------------------------------------------------------------
// Property: an interrupted session write is NAMED, never called plain absent.
//
// The incident this reproduces: an agent fleet was killed mid-run, and one of
// the casualties was a `keyless run` whose `pass-cli` child was part-way
// through writing its session. It left a `.session/session.json` short enough
// to be a partial write beside a zero-byte `session.tmp.<pid>.<n>` stamped in
// the same second. One killed process stranded the whole store, and `doctor`
// reported `absent` — true, and it sends a reader to
// `pass-cli login`, which hits the DEFAULT session, answers `Already
// authenticated`, and changes nothing.
//
// `pass-cli` owns that write: `session.tmp.` and `session.json` are both string
// literals in the vendor binary (2.2.5), and `keyless` writes its only temp file
// — `keyless-probe-<pid>-<n>.env` — into `std::env::temp_dir()`. So keyless
// cannot make the rename atomic. What it CAN do is recognise the shape and say
// which command actually reaches this directory.
// ---------------------------------------------------------------------------

/// A session directory with `.session/session.json` and one unfinished write.
///
/// `temp_idle` is how long ago the unfinished write last moved — the whole
/// discriminator between "abandoned by a killed process" and "a sibling is
/// writing this right now". `session_idle` is how long ago the session file
/// itself last moved, which decides whether the temp file is the LAST thing
/// that happened here or a scar from an attempt that a later login superseded.
/// Both sides of both lines need a fixture, so both are parameters.
fn session_dir_with_an_interrupted_write(
    root: &Path,
    temp: &str,
    temp_idle: Duration,
    session_idle: Duration,
) -> std::path::PathBuf {
    let session = root.join("agent-session").join(".session");
    std::fs::create_dir_all(&session).expect("create the session directory");
    // Bytes that are deliberately not JSON: the real file is an encrypted blob,
    // and a fixture holding parseable JSON would invite an implementation that
    // reads it. Nothing in this crate may open a session file.
    std::fs::write(session.join("session.json"), [0x9c, 0x01, 0x02]).expect("write session.json");
    std::fs::write(session.join(temp), b"").expect("write the temp file");

    backdate(&session.join("session.json"), session_idle);
    backdate(&session.join(temp), temp_idle);

    session
        .parent()
        .expect("the session directory has a parent")
        .to_path_buf()
}

/// Set one file's modification time to `idle` ago.
///
/// Through `std::fs::FileTimes` rather than a `touch` subprocess: the ages under
/// test here are hours and days, and a fixture that had to WAIT for them would
/// be a suite nobody runs.
fn backdate(path: &Path, idle: Duration) {
    let times = std::fs::FileTimes::new().set_modified(std::time::SystemTime::now() - idle);
    std::fs::File::options()
        .write(true)
        .open(path)
        .expect("reopen the file to backdate it")
        .set_times(times)
        .expect("backdate the file");
}

/// A Proton-only config pointed at `binary`, with an explicit session directory.
fn proton_config_at(binary: &Path, session_dir: &Path) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","session_dir":"{}","timeout_ms":60000}}}},
            "secrets":{{"DECOY":{{"reference":"{PROTON_REFERENCE}"}}}}}}"#,
        binary.display(),
        session_dir.display()
    )
}

#[test]
fn doctor_names_an_interrupted_session_write_rather_than_reporting_a_plain_absence() {
    let dir = scratch("doctor-torn-session");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.28182.0",
        Duration::from_secs(3600),
        Duration::from_secs(7200),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));
    let flat = flattened(&report);

    // The state, in words. `absent` alone was true and sent a reader to the
    // wrong command; the row now says WHICH kind of unusable this is.
    assert!(flat.contains("HALF-WRITTEN"), "{report}");
    // Named, so the reader can look at the file the report is talking about.
    assert!(flat.contains("session.tmp.28182.0"), "{report}");
    // And whose write it is, because that decides who can fix it.
    assert!(flat.contains("keyless writes NOTHING"), "{report}");
    // The vendor still speaks for itself.
    assert!(flat.contains("authenticated client"), "{report}");
    assert_eq!(code, 1, "{report}");
}

#[test]
fn the_interrupted_session_remedy_names_this_session_directory_and_the_variable() {
    // The half of the incident that cost the time. `pass-cli login` typed
    // literally logs into the default session and answers `Already
    // authenticated`; the directory travels in `PROTON_PASS_SESSION_DIR`, which
    // is the same variable this adapter puts on every child it spawns.
    let dir = scratch("doctor-torn-remedy");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.31337.0",
        Duration::from_secs(3600),
        Duration::from_secs(7200),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, _) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));
    let flat = flattened(&report);

    let expected = format!(
        "PROTON_PASS_SESSION_DIR={} pass-cli login",
        session_dir.display()
    );
    assert!(
        flat.contains(&expected),
        "the report never printed the command that reaches this session:\n{report}"
    );
}

#[test]
fn a_proton_failure_with_no_interrupted_write_still_names_the_variable() {
    // The generic path, which is every other way a session dies — an expired
    // agent token, a revoked one. The old advice was `pass-cli login` into
    // `stores.proton.session_dir`, which is followable only by someone who
    // already knows the answer. There is no torn write here, so this is the
    // remedy alone.
    let dir = scratch("doctor-dead-session-remedy");
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config(&stub));
    let flat = flattened(&report);

    assert!(!flat.contains("HALF-WRITTEN"), "{report}");
    assert!(
        flat.contains(&format!(
            "PROTON_PASS_SESSION_DIR={SCOPED_SESSION_DIR} pass-cli login"
        )),
        "{report}"
    );
    assert_eq!(code, 1, "{report}");
}

#[test]
fn a_write_from_moments_ago_is_never_called_an_interrupted_one() {
    // The safety property. A zero-byte temp file held by a LIVE `pass-cli` and
    // one abandoned by a killed one are the same file; the only thing that
    // separates them without inspecting open descriptors is that one stops
    // moving. So a fresh one is reported as undecided, and the reader is asked
    // to look again rather than told a session is damaged.
    let dir = scratch("doctor-fresh-write");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.4242.0",
        Duration::from_secs(0),
        Duration::from_secs(7200),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));
    let flat = flattened(&report);

    assert!(
        !flat.contains("HALF-WRITTEN"),
        "a write from this second was reported as damage:\n{report}"
    );
    assert!(
        flat.contains("may be writing this session right now"),
        "{report}"
    );
    assert!(flat.contains("session.tmp.4242.0"), "{report}");
    assert_eq!(code, 1, "{report}");
}

#[test]
fn a_session_that_answers_is_never_reported_as_half_written() {
    // The false-positive control, and the reason the forensics run only after
    // the round trip has already failed. An orphan temp file beside a session
    // that ANSWERS is debris; a health check that calls a working store broken
    // is a health check that gets ignored.
    let dir = scratch("doctor-live-with-orphan-temp");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.11111.0",
        Duration::from_secs(86_400),
        Duration::from_secs(172_800),
    );
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let (report, code) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));

    assert_eq!(state_of(proton_row(&report)), "proven", "{report}");
    assert!(!report.contains("HALF-WRITTEN"), "{report}");
    assert_eq!(code, 0, "{report}");
}

#[test]
fn doctor_leaves_an_interrupted_write_exactly_where_it_found_it() {
    // A broker that eats a live session is far worse than one that reports a
    // torn one. There is no expression in this crate that removes a file from a
    // session directory, and this is the fixture that would notice one arriving.
    let dir = scratch("doctor-torn-untouched");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.55555.0",
        Duration::from_secs(3600),
        Duration::from_secs(7200),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, _) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));

    let session = session_dir.join(".session");
    assert!(
        session.join("session.tmp.55555.0").exists(),
        "doctor removed an unfinished write:\n{report}"
    );
    assert!(
        session.join("session.json").exists(),
        "doctor removed a session file:\n{report}"
    );
}

#[test]
fn a_leftover_older_than_the_session_file_is_a_scar_and_not_a_cause() {
    // The state this check would otherwise get wrong FOREVER, and it is not
    // hypothetical: measured on the incident's own directory on 2026-08-11, the
    // abandoned `session.tmp.28182.0` from 17:47:30 the previous day was still
    // sitting beside a `session.json` rewritten at 06:35:14 that morning. The
    // session had recovered; nothing removed the temp file.
    //
    // `rename` carries the source's modification time, so a `session.json`
    // NEWER than a temp file proves a later write landed. Without that
    // comparison, every unrelated Proton failure from that day on — an expired
    // token, a revoked one — would be reported as a half-written session on the
    // strength of a file that stopped mattering months earlier. That is a
    // permanent false diagnosis, which is worse than the bare `absent` this
    // whole change replaces.
    let dir = scratch("doctor-recovered-leftover");
    let session_dir = session_dir_with_an_interrupted_write(
        &dir,
        "session.tmp.28182.0",
        Duration::from_secs(86_400),
        Duration::from_secs(600),
    );
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config_at(&stub, &session_dir));
    let flat = flattened(&report);

    assert!(
        !flat.contains("HALF-WRITTEN"),
        "a leftover from before the last successful write was reported as damage:\n{report}"
    );
    assert!(
        !flat.contains("session.tmp.28182.0"),
        "a superseded temp file was named as the cause:\n{report}"
    );
    // The generic failure is still reported, and still names the command that
    // reaches this directory rather than the default one.
    assert!(flat.contains("authenticated client"), "{report}");
    assert!(
        flat.contains(&format!(
            "PROTON_PASS_SESSION_DIR={} pass-cli login",
            session_dir.display()
        )),
        "{report}"
    );
    assert_eq!(code, 1, "{report}");
}
