#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::path::Path;
use std::time::Duration;

use keyless::store::{self, Invocation};

use daemon_proton_support::session_fault::{SESSION_FAULT_SENTENCE, info_call_count};
use daemon_proton_support::session_verbs::{LogoutAnswer, stub_with_session_verbs};
use daemon_proton_support::warm_cache::{
    FRESHNESS_SECONDS, PAST_FRESHNESS, STALE_SECONDS, TRANSPORT_FAILURE, TRANSPORT_FRAGMENT,
    daemon_config_with_a_warm_cache, until_the_read_degrades, until_the_vendor_has_been_asked,
    value_from,
};
use daemon_proton_support::{DECLARED, LISTING, published_generation};
use support::backend::{Backend, NextCall, set_next_call, vendor_decoy};
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::proton::{Listing, stub_pass_cli_listing};
use support::scratch;

// ---------------------------------------------------------------------------
// A session fault is not a verdict about a name: a vendor failure that is
// about the daemon's OWN session — never established by matching the
// vendor's wording — keeps the cache warm, is reported as `Unavailable`, and
// wakes the renewal loop; the same failure over a healthy session is still a
// verdict about the item and still evicts.
// ---------------------------------------------------------------------------

/// Remove `.session/session.json` from an already-published generation
/// directory — [`support::generations::publish_generation`] plants one by default, the
/// way a real `pass-cli login` would have left it, so THIS is the explicit
/// step a case takes to model the other half of the structural check: the
/// vendor's own invalidation cleanup having removed it from inside a read.
fn remove_session_file(generation_dir: &Path) {
    let path = generation_dir.join(".session").join("session.json");
    std::fs::remove_file(&path)
        .unwrap_or_else(|error| panic!("remove the planted session.json at {path:?}: {error}"));
}

#[test]
fn a_vendor_failure_whose_info_also_fails_keeps_the_value_and_reports_the_store_unavailable() {
    // CONTROL — the change that makes this fail: `vendor_failed` still
    // classifying every non-transport failure as `StoreError::Backend`, the
    // shape it had before this slice. The value would be evicted instead of
    // kept, and the second `value_from` below would panic rather than read
    // `held` back.
    let dir = scratch("daemon-proton-session-fault-info-fails");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        false, // `info` fails too: the session itself cannot answer
        LogoutAnswer::Ok,
        None,
    );
    // `daemon_config_with_a_warm_cache` publishes the generation this reads
    // through, with a `.session/session.json` already inside it — see
    // `support::generations::publish_generation_aged` — so the structural check's `stat`
    // finds a present, ordinary session and falls through to the coalesced
    // probe below.
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "a session fault must keep the value the daemon already held"
    );
    until_the_vendor_has_been_asked(&dir, 2);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "the value survived the failing refresh and then did not survive the read after it"
    );
    assert!(
        info_call_count(&dir) >= 1,
        "a non-transport failure never asked the session whether it was still alive"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_vendor_failure_whose_info_answers_evicts_the_value_as_a_verdict_about_the_name() {
    // CONTROL — the change that makes this fail: reading a non-transport
    // failure as a session fault unconditionally, without ever asking `info`
    // — the eviction below would never happen and the poll would fail at
    // `NEVER_HAPPENED`.
    let dir = scratch("daemon-proton-session-fault-info-answers");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true, // `info` answers: the session is healthy
        LogoutAnswer::Ok,
        None,
    );
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);
    let _ = registry.resolve(DECLARED);
    until_the_vendor_has_been_asked(&dir, 2);

    set_next_call(&dir, &NextCall::Fails(TRANSPORT_FAILURE));
    let reason = until_the_read_degrades(&registry, DECLARED);

    assert!(
        reason.contains(TRANSPORT_FRAGMENT),
        "the read degraded before the value's absence was what caused it: {reason}"
    );
    assert!(
        !reason.contains(&held),
        "the refusal carried the value it had just disowned"
    );
    assert!(
        info_call_count(&dir) >= 1,
        "a non-transport failure never asked the session whether it was still alive"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_session_json_is_a_session_fault_decided_without_spawning_anything() {
    // CONTROL — the change that makes this fail: `session_is_at_fault`
    // skipping the `stat` and going straight to the coalesced probe. The
    // read below would still keep the value (the probe reads the session as
    // dead too, since `info` fails here as well) but `info_call_count`
    // would come back nonzero — the absence was never enough on its own.
    let dir = scratch("daemon-proton-session-fault-missing-file");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, false, LogoutAnswer::Ok, None);
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    // `daemon_config_with_a_warm_cache` plants a `.session/session.json` by
    // default (see `support::generations::publish_generation_aged`) — removed here so the
    // generation directory holds none at all, the vendor's own invalidation
    // cleanup's signature, per the parent RCA's §3.
    remove_session_file(&published_generation(&dir));
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "a missing session.json must keep the value, exactly as a failing probe does"
    );
    until_the_vendor_has_been_asked(&dir, 2);

    assert_eq!(
        info_call_count(&dir),
        0,
        "a missing session.json still spawned a probe to confirm what the stat already knew"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_same_vendor_sentence_evicts_with_a_healthy_session_and_keeps_the_value_without_one() {
    // CONTROL — the change this whole slice exists to rule out: classifying
    // by matching `SESSION_FAULT_SENTENCE`, or any fixed wording, into the
    // transport allowlist. That would make both halves below evict, or both
    // keep, regardless of the session's own health — the two assertions
    // could never disagree, which is exactly what this test exists to catch.
    let dir = scratch("daemon-proton-session-fault-control");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let healthy_vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, true, LogoutAnswer::Ok, None);
    let config =
        daemon_config_with_a_warm_cache(&dir, &healthy_vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);
    let _ = registry.resolve(DECLARED);
    until_the_vendor_has_been_asked(&dir, 2);

    set_next_call(&dir, &NextCall::Fails(TRANSPORT_FAILURE));
    let reason = until_the_read_degrades(&registry, DECLARED);
    assert!(
        reason.contains(TRANSPORT_FRAGMENT),
        "the healthy-session half degraded before the value's absence was the cause: {reason}"
    );

    drop(running);

    // Second half: the identical sentence, a fresh daemon, a dead session —
    // the only thing that changed.
    let dir2 = scratch("daemon-proton-session-fault-control-2");
    let inner2 = stub_pass_cli_listing(&dir2, &Backend::Controlled, &Listing::Json(LISTING));
    let dead_vendor = stub_with_session_verbs(
        &dir2,
        &inner2,
        Duration::ZERO,
        false,
        LogoutAnswer::Ok,
        None,
    );
    let config2 =
        daemon_config_with_a_warm_cache(&dir2, &dead_vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running2 = start_daemon(&config2, policy_allowing_self());

    let client2 = client_config(running2.socket(), 3_000);
    let registry2 = store::build(&client2, &Invocation::default()).registry;

    assert_eq!(value_from(&registry2, DECLARED), held);
    set_next_call(&dir2, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry2, DECLARED),
        held,
        "the SAME sentence, over a dead session, must keep the value rather than evict it"
    );

    drop(running2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}
