//! A refused run: `keyless run` exits 64 without starting its child, says why
//! for each refused name, and both audit logs record `REFUSED`.
//!
//! Each case runs the client's own run path — against an in-process daemon
//! over its socket where the daemon has a say — and asserts only what a caller
//! sees: whether the child started (a marker file it writes), the exit code,
//! stderr, and the audit rows.

mod support;

use keyless::State;
use keyless::store::Registry;
use keyless::store::keychain::KeychainStore;

use support::{run_with, scratch, witness};

const EX_USAGE: i32 = 64;

#[test]
fn an_empty_name_is_refused_without_a_daemon_too() {
    let dir = scratch("refused-empty-local");
    let marker = dir.join("marker");
    let registry = Registry::new(vec![Box::new(KeychainStore::new(
        dir.join("there-is-no-security-here"),
        "keyless".to_owned(),
    ))]);

    let (outcome, notes) = run_with(&registry, &["VAR="], &witness(&marker, "VAR", 0), &[]);

    assert!(!marker.exists(), "the child started: {notes}");
    assert_eq!(outcome.state, State::Refused);
    assert_eq!(outcome.exit_code, EX_USAGE);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
mod against_a_daemon {
    use std::path::Path;

    use keyless::State;
    use keyless::audit::AuditLog;
    use keyless::cmd::run::{Binding, Outcome, RunRequest, TtyPolicy, run};
    use keyless::store::{self, Invocation};

    use super::EX_USAGE;
    use super::support::client::{client_config, write_secrets};
    use super::support::daemon::{
        daemon_config, policy_allowing_nobody, policy_allowing_self, start_daemon,
    };
    use super::support::{DECOY_VALUE, scratch, witness};

    const TIMEOUT_MS: u64 = 2_000;

    /// Run `specs` against the daemon at `socket`, recording to `client_audit`.
    fn run_specs(
        socket: &Path,
        specs: &[&str],
        marker: &Path,
        client_audit: &Path,
    ) -> (Outcome, String) {
        let config = client_config(socket, TIMEOUT_MS);
        let built = store::build(&config, &Invocation::default());
        let bindings: Vec<Binding> = specs
            .iter()
            .map(|spec| Binding::parse(spec).expect("a parseable spec"))
            .collect();
        let log = AuditLog::new(client_audit.to_path_buf());
        let argv = witness(marker, "DECOY", 0);

        let mut notes: Vec<u8> = Vec::new();
        let outcome = run(
            RunRequest {
                bindings: &bindings,
                unusable: &[],
                argv: &argv,
                registry: &built.registry,
                audit: Some(&log),
                warnings: &built.warnings,
                tty: TtyPolicy::Pipes,
            },
            &mut notes,
        )
        .expect("a refused run is an outcome, not an error");
        (outcome, String::from_utf8_lossy(&notes).into_owned())
    }

    fn rows(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("an audit row is JSON"))
            .collect()
    }

    fn states(rows: &[serde_json::Value]) -> Vec<String> {
        rows.iter()
            .map(|row| {
                row["state"]
                    .as_str()
                    .expect("a row carries a state")
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn an_empty_name_refuses_the_run_and_the_child_never_starts() {
        let dir = scratch("refused-empty-name");
        let config = daemon_config(&dir);
        write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
        let running = start_daemon(&config, policy_allowing_self());
        let marker = dir.join("marker");
        let client_audit = dir.join("client-audit.jsonl");

        let (outcome, notes) = run_specs(running.socket(), &["VAR="], &marker, &client_audit);

        assert!(!marker.exists(), "the child started: {notes}");
        assert_eq!(outcome.state, State::Refused);
        assert_eq!(outcome.exit_code, EX_USAGE);
        assert!(
            notes.contains("VAR="),
            "stderr does not name the empty name: {notes}"
        );
        assert!(
            notes.contains("REFUSED"),
            "stderr does not say refused: {notes}"
        );
        assert_eq!(states(&rows(&client_audit)), ["REFUSED"]);
        let daemon_rows = rows(&config.audit);
        assert_eq!(states(&daemon_rows), ["REFUSED"]);
        assert_eq!(daemon_rows[0]["decision"], "bad-name");

        drop(running);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_refused_name_refuses_the_whole_run() {
        let dir = scratch("refused-one-of-two");
        let config = daemon_config(&dir);
        write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
        let running = start_daemon(&config, policy_allowing_self());
        let marker = dir.join("marker");
        let client_audit = dir.join("client-audit.jsonl");
        let over_long = format!("LONG={}", "n".repeat(10_000));

        let (outcome, notes) = run_specs(
            running.socket(),
            &["DECOY", &over_long],
            &marker,
            &client_audit,
        );

        assert!(!marker.exists(), "the child started: {notes}");
        assert_eq!(outcome.state, State::Refused);
        assert_eq!(outcome.exit_code, EX_USAGE);
        assert!(outcome.injected.is_empty(), "{:?}", outcome.injected);
        assert!(
            !notes.contains(DECOY_VALUE),
            "a value reached stderr: {notes}"
        );
        assert_eq!(states(&rows(&client_audit)), ["REFUSED"]);
        let mut daemon_states = states(&rows(&config.audit));
        daemon_states.sort();
        assert_eq!(daemon_states, ["INJECTED", "REFUSED"]);

        drop(running);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_caller_refused_by_attestation_is_recorded_as_refused_under_its_rule() {
        let dir = scratch("refused-attestation");
        let config = daemon_config(&dir);
        write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
        let running = start_daemon(&config, policy_allowing_nobody());
        let marker = dir.join("marker");
        let client_audit = dir.join("client-audit.jsonl");

        let _ = run_specs(running.socket(), &["DECOY"], &marker, &client_audit);

        assert_eq!(states(&rows(&client_audit)), ["REFUSED"]);
        let daemon_rows = rows(&config.audit);
        assert_eq!(states(&daemon_rows), ["REFUSED"]);
        assert_eq!(daemon_rows[0]["decision"], "no-image-pinned");

        drop(running);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
