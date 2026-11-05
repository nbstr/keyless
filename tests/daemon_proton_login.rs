#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::path::Path;

use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::{
    DECLARED, ITEM, LISTING, TOKEN_DECOY, VAULT, daemon_config_with_proton, session_dir,
    stub_recording_key_provider, vendor_argv, vendor_identity, vendor_list_argv, vendor_token,
};
use support::backend::Backend;
use support::client::{client_config, write_secrets};
use support::daemon::{policy_allowing_self, start_daemon};
use support::proton::Listing;
use support::{PROTON_DECOY, scratch, short_socket_path};

/// The entry, in the daemon's own credential file, that holds the agent token.
const TOKEN_ENTRY: &str = "FIXTURE_AGENT_TOKEN";

// ---------------------------------------------------------------------------
// Whoever runs the vendor owns what it writes, and it writes on reads.
// ---------------------------------------------------------------------------

/// The vendor runs as the uid the audit log names, not as whoever invoked us.
///
/// `pass-cli` WRITES to the session directory on invocations that only read:
/// against a directory holding no identity it creates `.session/pass-cli.db`
/// and `.session/local.key`, owned by whoever ran it. Inside the daemon that is
/// the daemon. Under `keylessd check`, which runs beneath `sudo` and resolves
/// every store to fill in its rows, it was ROOT — so the diagnostic left two
/// root-owned files in the daemon's own session directory, and every later
/// access answered `Error creating local key file: Permission denied`. That
/// reads like a broken token and is a directory the check broke.
///
/// Measured on a real install: a session cleared for repair, one
/// `sudo keylessd check`, and the renewal loop could not recover it.
///
/// This asserts the drop happens AND that dropping to the uid already in force
/// still succeeds — the case that runs inside the daemon itself, on every
/// lookup, where a wrong call here would break every read rather than one.
#[test]
fn the_vendor_runs_as_the_uid_the_audit_log_names() {
    let dir = scratch("daemon-proton-runs-as");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_proton(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    assert!(
        matches!(registry.resolve(DECLARED), Resolution::Found { .. }),
        "the lookup failed, so nothing below is a statement about its uid"
    );

    // The audit log is what the login verbs read the daemon's identity off, so
    // it is what this has to agree with. Comparing against the test process
    // instead would pass on a daemon that never dropped at all.
    use std::os::unix::fs::MetadataExt;
    let audit = std::fs::metadata(dir.join("audit.jsonl")).expect("the audit log");
    assert_eq!(
        support::recorded(&vendor_identity(&dir)),
        format!("{}:{}", audit.uid(), audit.gid()),
        "the vendor ran as somebody other than the uid that owns the daemon's files"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The daemon's own login: where it comes from, and everywhere it must not go.
// ---------------------------------------------------------------------------

/// The same daemon, plus an agent token read out of its own `0600` file.
///
/// The credential file is a file of its OWN, which is the arrangement being
/// asserted: anything in the file the `file` store serves is a name an attested
/// client can ask for, so the token that unlocks the vault would be handed to
/// any session that guessed its label.
fn daemon_config_with_token(dir: &Path, vendor: &Path) -> DaemonConfig {
    support::generations::publish_generation(&session_dir(dir));
    let credentials = dir.join("proton-credentials.json");
    write_secrets(&credentials, &[(TOKEN_ENTRY, TOKEN_DECOY)]);
    // `key_provider: fs` pinned rather than inherited: these cases are about
    // the TOKEN, and under `env` the daemon also names an entry for its own
    // local key, so an unwritten credential file would report the key missing
    // where the case is asking what happens to the token.
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000,
                                   "key_provider":"fs",
                                   "credentials_file":"{credentials}",
                                   "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"{TOKEN_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config")
}

#[test]
fn the_agent_token_reaches_the_vendor_and_no_other_surface() {
    // A daemon cannot inherit a Proton login the way a session does. So the
    // token is read from the daemon's own mode-0600 file at lookup time and
    // set on the vendor's child. This asserts both halves: that it arrives,
    // and that it appears in nothing else the daemon writes or says.
    let dir = scratch("daemon-proton-token");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_token(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let reason = match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => {
            assert_eq!(secret.expose(), PROTON_DECOY);
            "resolved".to_owned()
        }
        other => panic!(
            "the lookup must work, or nothing below is tested: {}",
            other.reason()
        ),
    };

    // It arrived, read from the child's environment by the vendor itself
    // rather than from the adapter's own account of what it set.
    assert_eq!(
        support::recorded(&vendor_token(&dir)),
        TOKEN_DECOY,
        "the agent token did not reach the vendor"
    );

    // And nowhere else. argv is the one this project exists to keep clean, and
    // the audit log is the one the caller cannot edit afterwards.
    let spawned = support::recorded_lines(&vendor_argv(&dir));
    assert!(
        !spawned.iter().any(|arg| arg.contains(TOKEN_DECOY)),
        "the token was put on the vendor's command line: {spawned:?}"
    );
    let listed = support::recorded_lines(&vendor_list_argv(&dir));
    assert!(
        !listed.iter().any(|arg| arg.contains(TOKEN_DECOY)),
        "the token was put on the listing's command line: {listed:?}"
    );
    let audit = std::fs::read_to_string(dir.join("audit.jsonl")).expect("the daemon wrote a row");
    assert!(
        !audit.contains(TOKEN_DECOY),
        "the token reached the audit log"
    );
    // The reason travels to Proton's own audit trail, permanently.
    assert!(
        !support::recorded(&dir.join("pass-cli.reason")).contains(TOKEN_DECOY),
        "the token reached the reason the vendor records"
    );
    assert!(!reason.contains(TOKEN_DECOY), "{reason}");

    // The point of a file of its own: the token is not a name the daemon
    // serves. Asked for by its own entry name over the socket, it is not there.
    match registry.resolve(TOKEN_ENTRY) {
        Resolution::Found { secret, .. } => assert_ne!(
            secret.expose(),
            TOKEN_DECOY,
            "the agent token was served to a client that asked for it by name"
        ),
        other => assert!(
            !other.reason().contains(TOKEN_DECOY),
            "the token leaked through a refusal: {}",
            other.reason()
        ),
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_credential_variable_this_adapter_sets_itself_is_refused() {
    // The narrow allowlist, and the reason it is narrower than the
    // `INFISICAL_*` prefix rule next door. `PROTON_PASS_SESSION_DIR` is a
    // `PROTON_PASS_*` variable, so a prefix rule would accept it here — and it
    // chooses which identity answers, which is the difference between reading
    // one vault and reading a whole account. A credential entry must not be
    // able to say it.
    let dir = scratch("daemon-proton-credential-refused");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    support::generations::publish_generation(&session_dir(&dir));
    let credentials = dir.join("proton-credentials.json");
    write_secrets(&credentials, &[(TOKEN_ENTRY, TOKEN_DECOY)]);
    // `key_provider: fs` pinned rather than inherited: these cases are about
    // the TOKEN, and under `env` the daemon also names an entry for its own
    // local key, so an unwritten credential file would report the key missing
    // where the case is asking what happens to the token.
    let config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000,
                                   "key_provider":"fs",
                                   "credentials_file":"{credentials}",
                                   "credentials":{{"PROTON_PASS_SESSION_DIR":"{TOKEN_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(&dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(&dir).display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config");

    // Said at startup, so an operator finds out while reading the daemon's own
    // output rather than while reading a degraded run a week later.
    let said = config.warnings().join(" ");
    assert!(said.contains("PROTON_PASS_SESSION_DIR"), "{said}");

    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    let reason = registry.resolve(DECLARED).reason();

    assert!(
        !vendor_argv(&dir).exists(),
        "a refused credential still spawned the vendor: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(
        !vendor_list_argv(&dir).exists(),
        "a refused credential still listed a vault: {:?}",
        support::recorded_lines(&vendor_list_argv(&dir))
    );
    assert!(reason.contains("PROTON_PASS_SESSION_DIR"), "{reason}");
    assert!(!reason.contains(TOKEN_DECOY), "{reason}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_token_the_daemons_file_does_not_hold_degrades_without_a_spawn() {
    // The operator wrote down where the token lives and it is not there. That
    // is a misconfiguration, not an absence: every Proton name degrades, the
    // message names the entry to write, and no vendor process is created — so
    // an unauthenticated lookup is never attempted against a real vault.
    let dir = scratch("daemon-proton-token-missing");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_token(&dir, &vendor);
    // Same config, same file, with the one entry it names removed. Rewritten
    // rather than deleted, so the failure is a missing ENTRY and not a missing
    // file — the two have different messages and this is the one that is easy
    // to report as the other.
    write_secrets(
        &dir.join("proton-credentials.json"),
        &[("FIXTURE_SOMETHING_ELSE", TOKEN_DECOY)],
    );
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    let reason = registry.resolve(DECLARED).reason();

    assert!(
        !vendor_list_argv(&dir).exists(),
        "the vendor listed a vault with no login: {:?}",
        support::recorded_lines(&vendor_list_argv(&dir))
    );
    assert!(
        !vendor_argv(&dir).exists(),
        "the vendor was spawned with no login: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(reason.contains(TOKEN_ENTRY), "{reason}");
    assert!(
        !reason.contains(TOKEN_DECOY),
        "the refusal carried the value it could not attribute: {reason}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
