#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::path::Path;
use std::time::Duration;

use keyless::State;
use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Invocation};

use daemon_proton_support::session_verbs::{LogoutAnswer, stub_with_session_verbs};
use daemon_proton_support::warm_cache::{
    FRESHNESS_SECONDS, ITEM_VERDICT, PAST_FRESHNESS, daemon_config_with_a_warm_cache,
};
use daemon_proton_support::{DECLARED, LISTING};
use support::backend::{Backend, NextCall, set_next_call, vendor_call_count, vendor_decoy};
use support::child_witness::{run_with, witness};
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::proton::{Listing, stub_pass_cli_listing};
use support::scratch;

// ---------------------------------------------------------------------------
// The silent window: while a store gives no verdict within its timeout, a run
// still gets the last value that store gave — and never one it disowned.
//
// Every case goes through `keyless run`'s own path against the daemon and reads
// only what a caller can: what the child saw, and the daemon's audit row.
// ---------------------------------------------------------------------------

/// The store's own read ceiling in these cases. A vendor that has not answered
/// by then is silent.
const SILENT_STORE_TIMEOUT_MS: u64 = 1_000;

/// A vendor that has gone quiet: far past [`SILENT_STORE_TIMEOUT_MS`], so the
/// daemon gives up on it rather than the stand-in ever answering.
const QUIET: Duration = Duration::from_secs(30);

/// A silent window no case below reaches the far edge of.
const WIDE_SILENT_WINDOW_SECONDS: u64 = 60;

/// A silent window the case that outlives it can wait past.
const NARROW_SILENT_WINDOW_SECONDS: u64 = 2;

/// Comfortably past [`NARROW_SILENT_WINDOW_SECONDS`].
const PAST_NARROW_SILENT_WINDOW: Duration = Duration::from_millis(2_500);

/// A daemon whose freshness window is one second and whose stale window is
/// shut, so every read past freshness asks the store on the request path and
/// only the silent window can answer it from memory.
fn daemon_config_with_a_silent_window(
    dir: &Path,
    vendor: &Path,
    silent_seconds: u64,
) -> DaemonConfig {
    let mut config = daemon_config_with_a_warm_cache(dir, vendor, FRESHNESS_SECONDS, 0);
    config.cache_silent_seconds = silent_seconds;
    config.stores.proton.timeout_ms = SILENT_STORE_TIMEOUT_MS;
    config
}

/// One `keyless run` naming [`DECLARED`], whose child records what it saw.
fn run_declared(registry: &store::Registry, marker: &Path) -> keyless::cmd::run::Outcome {
    let _ = std::fs::remove_file(marker);
    run_with(registry, &[DECLARED], &witness(marker, DECLARED, 0), &[]).0
}

/// What the child saw, or `None` when no child ran.
fn child_saw(marker: &Path) -> Option<String> {
    std::fs::read_to_string(marker).ok()
}

/// The daemon's audit rows naming [`DECLARED`], oldest first.
fn daemon_rows(config: &DaemonConfig) -> Vec<serde_json::Value> {
    std::fs::read_to_string(&config.audit)
        .expect("read the daemon audit log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("an audit row is JSON"))
        .filter(|row: &serde_json::Value| {
            row["names"]
                .as_array()
                .is_some_and(|names| names.len() == 1 && names[0].as_str() == Some(DECLARED))
        })
        .collect()
}

#[test]
fn a_silent_store_still_hands_the_run_the_last_value_it_gave() {
    // CONTROL — the change that makes this fail: `cache_silent_seconds: 0`.
    // The second run then degrades, its child sees `<unset>`, and the daemon
    // records `DEGRADED`.
    let dir = scratch("daemon-proton-silent-served");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let config = daemon_config_with_a_silent_window(&dir, &vendor, WIDE_SILENT_WINDOW_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    let marker = dir.join("child.seen");
    let held = vendor_decoy(1);

    let first = run_declared(&registry, &marker);
    assert_eq!(first.state, State::Injected);
    assert_eq!(child_saw(&marker).as_deref(), Some(held.as_str()));

    set_next_call(&dir, &NextCall::Slow(QUIET));
    std::thread::sleep(PAST_FRESHNESS);

    let second = run_declared(&registry, &marker);
    assert_eq!(
        child_saw(&marker).as_deref(),
        Some(held.as_str()),
        "a store that went silent took the last value it gave with it"
    );
    assert_eq!(second.state, State::Injected);
    assert!(
        vendor_call_count(&dir) >= 2,
        "the second run never asked the store, so it says nothing about silence"
    );

    drop(running);
    let rows = daemon_rows(&config);
    let served = rows.last().expect("the second run left a daemon row");
    assert_eq!(served["state"].as_str(), Some("INJECTED"), "{served}");
    assert_eq!(served["source"].as_str(), Some("stale"), "{served}");
    assert!(
        served["age_ms"]
            .as_u64()
            .expect("a row served from silence carries its age")
            >= 1_000,
        "{served}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_name_the_store_disowned_is_not_served_when_it_falls_silent() {
    // The silent window never covers a name the store disowned. The verdict
    // run is not enough on its own: it reaches the store and is answered, so
    // it would not get the old value even with the entry still cached. The run
    // after it, against a silent store, is the one that shows the entry gone.
    //
    // CONTROL — the change that makes this fail: the resolver keeping a value
    // a store answered about. The third run would then be served it from the
    // silent window.
    //
    // `stub_with_session_verbs` with `info_answers: true`, because the plain
    // stub answers `info` out of the same `NextCall` and a refusal there reads
    // as a dead session rather than the account speaking about the item.
    let dir = scratch("daemon-proton-silent-disowned");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, true, LogoutAnswer::Ok, None);
    let config = daemon_config_with_a_silent_window(&dir, &vendor, WIDE_SILENT_WINDOW_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    let marker = dir.join("child.seen");
    let held = vendor_decoy(1);

    run_declared(&registry, &marker);
    assert_eq!(child_saw(&marker).as_deref(), Some(held.as_str()));

    set_next_call(&dir, &NextCall::Fails(ITEM_VERDICT));
    std::thread::sleep(PAST_FRESHNESS);
    run_declared(&registry, &marker);
    assert_ne!(
        child_saw(&marker).as_deref(),
        Some(held.as_str()),
        "a run was handed a value its store had just disowned"
    );

    set_next_call(&dir, &NextCall::Slow(QUIET));
    let after = run_declared(&registry, &marker);
    assert_ne!(
        child_saw(&marker).as_deref(),
        Some(held.as_str()),
        "a disowned value came back once the store fell silent"
    );
    assert_ne!(after.state, State::Injected);
    assert!(
        vendor_call_count(&dir) >= 3,
        "the last run never asked the store, so it says nothing about silence"
    );

    drop(running);
    let rows = daemon_rows(&config);
    let last = rows.last().expect("the last run left a daemon row");
    assert_ne!(last["state"].as_str(), Some("INJECTED"), "{last}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_value_older_than_the_silent_window_is_not_served_during_silence() {
    // The window's far edge. The case above it that serves a value is the
    // control: same store, same silence, a younger value.
    let dir = scratch("daemon-proton-silent-expired");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let config = daemon_config_with_a_silent_window(&dir, &vendor, NARROW_SILENT_WINDOW_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    let marker = dir.join("child.seen");

    run_declared(&registry, &marker);
    assert_eq!(
        child_saw(&marker).as_deref(),
        Some(vendor_decoy(1).as_str())
    );

    set_next_call(&dir, &NextCall::Slow(QUIET));
    std::thread::sleep(PAST_NARROW_SILENT_WINDOW);

    let late = run_declared(&registry, &marker);
    assert_eq!(
        child_saw(&marker).as_deref(),
        Some("<unset>"),
        "a value older than the silent window reached the child"
    );
    assert_eq!(late.state, State::Degraded);

    drop(running);
    let rows = daemon_rows(&config);
    let last = rows.last().expect("the late run left a daemon row");
    assert_eq!(last["state"].as_str(), Some("DEGRADED"), "{last}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Past the resolver's thirty-second sweep, which drops every entry no window
/// can serve any more.
const PAST_A_SWEEP: Duration = Duration::from_secs(32);

#[test]
fn a_value_outlives_the_memory_sweep_for_as_long_as_silence_could_serve_it() {
    // Retention: a value nobody reads for a while must still be in memory when
    // its store falls silent. Slow by necessity, because the sweep runs on a
    // fixed interval and only waiting past it shows what it kept.
    //
    // CONTROL — the change that makes this fail: a sweep that keeps entries
    // only to the end of the stale window. It drops the value a second after it
    // was read, and the silent run below degrades.
    let dir = scratch("daemon-proton-silent-retained");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let config = daemon_config_with_a_silent_window(&dir, &vendor, WIDE_SILENT_WINDOW_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    let marker = dir.join("child.seen");
    let held = vendor_decoy(1);

    run_declared(&registry, &marker);
    assert_eq!(child_saw(&marker).as_deref(), Some(held.as_str()));

    set_next_call(&dir, &NextCall::Slow(QUIET));
    std::thread::sleep(PAST_A_SWEEP);

    let later = run_declared(&registry, &marker);
    assert_eq!(
        child_saw(&marker).as_deref(),
        Some(held.as_str()),
        "the sweep dropped a value the silent window could still serve"
    );
    assert_eq!(later.state, State::Injected);

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
