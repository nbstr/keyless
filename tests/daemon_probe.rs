//! `doctor --probe` proving names through the daemon.

// The daemon is macOS-only (`src/lib.rs`), so this whole file is. On any other
// platform the crate below compiles to nothing and the binary reports 0 tests —
// ABSENT rather than ignored, which is why CI's `ignored == 15` assertion is
// unchanged and still means "the Proton live suite, and nothing else".
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::path::Path;

use keyless::State;
use keyless::audit::AuditLog;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::store;
use keyless::store::Invocation;

use support::{
    DECOY_VALUE, client_config, daemon_config, policy_allowing_self, scratch, start_daemon,
    witness, write_secrets,
};

/// `doctor --probe` against a client config naming `names`, each pinned to a
/// local backend the daemon suppresses — the shape a config carries after the
/// daemon is switched on over an existing one.
fn probed_through_the_daemon(dir: &Path, socket: &Path, names: &[&str]) -> (String, i32) {
    let secrets = names
        .iter()
        .map(|name| format!(r#""{name}":{{"store":"proton"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let paths = keyless::paths::Paths::under(dir);
    let mut load = keyless::config::Config::load(&paths.config);
    load.config = serde_json::from_str(&format!(
        r#"{{"stores":{{"daemon":{{"enabled":true,"socket":"{}","timeout_ms":3000}}}},
            "secrets":{{{secrets}}}}}"#,
        socket.display()
    ))
    .expect("valid client config");
    load.loaded = true;
    let built = store::build(&load.config, &Invocation::default());
    let audit = AuditLog::new(paths.audit.clone());

    let mut out: Vec<u8> = Vec::new();
    let code = keyless::cmd::doctor::doctor(
        &keyless::cmd::doctor::DoctorRequest {
            paths: &paths,
            load: &load,
            registry: &built.registry,
            audit: &audit,
            setup: None,
            notes: &[],
            probe: true,
            freshness: &keyless::freshness::Freshness::NoSourceTree,
            checkout: &keyless::checkout::Checkout::NoSourceTree,
            style: keyless::cmd::status::Style::PLAIN,
        },
        &mut out,
    )
    .expect("the report must be writable");
    (String::from_utf8(out).expect("utf-8"), code)
}

/// The state column of `name`'s row, read as a whole word: `unproven`
/// contains `proven`.
fn probed_state<'a>(report: &'a str, name: &str) -> &'a str {
    report
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(name))
        .and_then(|line| line.split_whitespace().nth(2))
        .unwrap_or_else(|| panic!("the report has no `{name}` row:\n{report}"))
}

/// `name`'s row and the indented lines under it, joined into one line.
fn probed_row(report: &str, name: &str) -> String {
    let mut lines = report
        .lines()
        .skip_while(|line| line.split_whitespace().nth(1) != Some(name));
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("the report has no `{name}` row:\n{report}"));
    std::iter::once(first)
        .chain(lines.take_while(|line| line.starts_with("      ")))
        .flat_map(str::split_whitespace)
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn a_name_run_resolves_through_the_daemon_is_proven_by_the_probe() {
    // The probe and the run under ONE config. The name is pinned to a local
    // backend the daemon suppresses, so a probe choosing its store by that pin
    // points at a row that reads `off` and asks nothing, while the run — whose
    // registry dropped the pin — is served by the daemon.
    let dir = scratch("daemon-probe-proven");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let (report, code) = probed_through_the_daemon(&dir, running.socket(), &["DECOY"]);

    let client = client_config(running.socket(), 3_000);
    let built = store::build(&client, &Invocation::default());
    let marker = dir.join("marker");
    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &[Binding::parse("DECOY").expect("valid")],
            unusable: &[],
            argv: &witness(&marker, "DECOY", 0),
            registry: &built.registry,
            audit: None,
            warnings: &[],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("run");
    assert_eq!(
        outcome.state,
        State::Injected,
        "the control: run resolves it"
    );

    assert_eq!(probed_state(&report, "DECOY"), "proven", "{report}");
    assert!(
        !report.split_whitespace().any(|word| word == "blocked"),
        "a name the daemon serves was marked blocked:\n{report}"
    );
    assert!(
        !report.contains(DECOY_VALUE),
        "the value reached the report"
    );
    let length = DECOY_VALUE.len().to_string();
    assert!(
        !report
            .split(|c: char| !c.is_ascii_digit())
            .any(|digits| digits == length),
        "the value's length reached the report:\n{report}"
    );
    assert_eq!(code, 0, "{report}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_name_the_daemon_does_not_serve_fails_the_probe_with_the_daemons_reason() {
    let dir = scratch("daemon-probe-failed");
    let config = daemon_config(&dir);
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let (report, code) = probed_through_the_daemon(&dir, running.socket(), &["DECOY", "MISSING"]);

    assert_eq!(probed_state(&report, "DECOY"), "proven", "{report}");
    assert_eq!(probed_state(&report, "MISSING"), "absent", "{report}");
    // The row's own text, detail and continuation lines alike: the STORES
    // section says "the daemon" on every suppressed row, so a report-wide
    // search is satisfied whatever this row says.
    let row = probed_row(&report, "MISSING");
    assert!(
        row.contains("daemon"),
        "the failing row does not carry the daemon's answer:\n{report}"
    );
    assert!(
        !report.contains(DECOY_VALUE),
        "the value reached the report"
    );
    assert_ne!(code, 0, "a failing name must fail the probe:\n{report}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
