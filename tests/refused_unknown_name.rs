//! A name its store does not hold refuses the run: exit 64, no child, the miss
//! advice on stderr, and `REFUSED` in both audit logs.
//!
//! Each case runs the client's own run path against an in-process daemon over
//! its socket, with a stub vendor standing in for the vault, and asserts only
//! what a caller sees.

#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod catalogue_daemon_support;
mod support;

use std::path::{Path, PathBuf};

use keyless::State;
use keyless::audit::AuditLog;
use keyless::cmd::run::{Binding, Outcome, RunRequest, TtyPolicy, run};
use keyless::store::{Invocation, Registry, build};

use catalogue_daemon_support::{
    DECOY, ONE_VAULT, daemon_over, listing_of, settle, wait_until_served,
};
use support::backend::Backend;
use support::client::client_config;
use support::daemon::{daemon_config, policy_allowing_self, start_daemon};
use support::proton::stub_pass_cli_catalogue;
use support::{scratch, witness};

const EX_USAGE: i32 = 64;

/// What one run of a witness child binding `name` left behind.
struct Ran {
    outcome: Outcome,
    notes: String,
    child_started: bool,
    client_states: Vec<String>,
}

fn run_recorded(registry: &Registry, dir: &Path, name: &str) -> Ran {
    let marker = dir.join(format!("{name}.marker"));
    let client_audit = dir.join(format!("{name}.client-audit.jsonl"));
    let bindings = [Binding::parse(name).expect("a parseable spec")];
    let log = AuditLog::new(client_audit.clone());
    let argv = witness(&marker, name, 0);
    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &bindings,
            unusable: &[],
            argv: &argv,
            registry,
            audit: Some(&log),
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("a command was given");
    Ran {
        outcome,
        notes: String::from_utf8_lossy(&notes).into_owned(),
        child_started: marker.exists(),
        client_states: field_of_rows(&client_audit, "state"),
    }
}

fn field_of_rows(path: &Path, field: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let row: serde_json::Value = serde_json::from_str(line).expect("an audit row is JSON");
            row[field].as_str().unwrap_or_default().to_owned()
        })
        .collect()
}

/// The daemon's newest audit row naming `name`.
fn daemon_row(dir: &Path, name: &str) -> serde_json::Value {
    std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|row| {
            row["names"]
                .as_array()
                .is_some_and(|names| names.iter().any(|listed| listed.as_str() == Some(name)))
        })
        .unwrap_or_else(|| panic!("the daemon recorded nothing for `{name}`"))
}

/// A daemon over one vault holding `titles`, already enumerated, and a session
/// registry speaking to it.
fn serving(
    label: &str,
    titles: &[&str],
    view: &str,
    ready: &str,
) -> (PathBuf, keyless::daemon::Running, Registry) {
    let dir = scratch(label);
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(titles),
        view,
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let registry = build(
        &client_config(running.socket(), 3_000),
        &Invocation::default(),
    )
    .registry;
    wait_until_served(running.socket(), ready);
    settle(&dir);
    (dir, running, registry)
}

#[test]
fn a_misspelt_name_is_refused_with_the_nearest_served_names() {
    let (dir, _running, registry) =
        serving("refused-misspelt", &["decoy alpha"], "{}", "DECOY_ALPHA");

    let ran = run_recorded(&registry, &dir, "DECOY_ALPA");

    assert!(!ran.child_started, "the child started: {}", ran.notes);
    assert_eq!(ran.outcome.state, State::Refused, "{}", ran.notes);
    assert_eq!(ran.outcome.exit_code, EX_USAGE);
    assert!(
        ran.notes.contains("nearest served names: DECOY_ALPHA"),
        "stderr does not offer the nearest served name: {}",
        ran.notes
    );
    assert_eq!(ran.client_states, ["REFUSED"]);
    let row = daemon_row(&dir, "DECOY_ALPA");
    assert_eq!(row["state"], "REFUSED");
    assert_eq!(row["decision"], "absent");
}

/// One item's field view: a note and one extra field, `Expiry Date`.
const DEMO_API_KEY_VIEW: &str = r#"{"item":{"id":"It3mOne","share_id":"ShAr3","state":"Active","revision":2,
    "content":{"item_uuid":"UU1D","title":"demo api key","note":"unread",
      "extra_fields":[{"name":"Expiry Date","content":{"Hidden":"unread"}}]}}}"#;

#[test]
fn a_field_the_item_lacks_is_refused_with_the_fields_it_has() {
    let (dir, _running, registry) = serving(
        "refused-no-such-field",
        &["demo api key"],
        DEMO_API_KEY_VIEW,
        "DEMO_API_KEY",
    );

    let ran = run_recorded(&registry, &dir, "DEMO_API_KEY__NO_SUCH_FIELD");

    assert!(!ran.child_started, "the child started: {}", ran.notes);
    assert_eq!(ran.outcome.state, State::Refused, "{}", ran.notes);
    assert_eq!(ran.outcome.exit_code, EX_USAGE);
    assert!(
        ran.notes.contains("DEMO_API_KEY__EXPIRY_DATE"),
        "stderr does not name the item's real fields: {}",
        ran.notes
    );
    assert_eq!(ran.client_states, ["REFUSED"]);
    assert_eq!(
        daemon_row(&dir, "DEMO_API_KEY__NO_SUCH_FIELD")["state"],
        "REFUSED"
    );
}

#[test]
fn a_store_that_fails_degrades_and_the_child_runs() {
    let dir = scratch("refused-malformed-file-store");
    std::fs::write(dir.join("secrets.json"), "{ not json").expect("write a malformed store");
    let running = start_daemon(&daemon_config(&dir), policy_allowing_self());
    let registry = build(
        &client_config(running.socket(), 3_000),
        &Invocation::default(),
    )
    .registry;

    let ran = run_recorded(&registry, &dir, "ANY_NAME");

    assert!(ran.child_started, "the child never started: {}", ran.notes);
    assert_eq!(ran.outcome.state, State::Degraded, "{}", ran.notes);
    assert_eq!(ran.client_states, ["DEGRADED"]);
    assert_eq!(daemon_row(&dir, "ANY_NAME")["state"], "DEGRADED");
}
