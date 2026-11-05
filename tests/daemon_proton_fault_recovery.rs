#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::path::Path;
use std::time::{Duration, Instant};

use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Invocation};

use daemon_proton_support::generations::{
    until_a_generation_is_published, until_current_moves_past,
};
use daemon_proton_support::session_fault::{SESSION_FAULT_SENTENCE, info_call_count};
use daemon_proton_support::session_verbs::{
    LogoutAnswer, daemon_config_with_generations_loop, stub_with_session_verbs,
};
use daemon_proton_support::warm_cache::{
    FRESHNESS_SECONDS, PAST_FRESHNESS, STALE_SECONDS, value_from,
};
use daemon_proton_support::{DECLARED, ITEM, LISTING, VAULT, session_dir};
use support::backend::{Backend, NextCall, set_next_call, vendor_call_count};
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::generations::current_generation;
use support::proton::{Listing, stub_pass_cli_listing};
use support::{scratch, short_socket_path};

/// A second declared name, addressing the exact same vault, item and field
/// as [`DECLARED`] — a burst across the two still shares one listing and one
/// session either way, and reusing the coordinate keeps this fixture inside
/// the decoy field names `tests/publication.rs` already allowlists rather
/// than inventing a new one. That is what
/// [`a_burst_of_failing_names_costs_one_probe_not_one_per_name`] needs: two
/// failures that can only share a coalesced probe because they share a
/// GENERATION, never because they share a vault entry.
const DECLARED_2: &str = "FIXTURE_DECLARED_2";

/// [`daemon_config_with_a_warm_cache`], with [`DECLARED_2`] added beside
/// [`DECLARED`].
fn daemon_config_with_two_names(
    dir: &Path,
    vendor: &Path,
    freshness_seconds: u64,
    stale_seconds: u64,
) -> DaemonConfig {
    support::generations::publish_generation(&session_dir(dir));
    let mut config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}},
                         "{DECLARED_2}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config");
    config.cache_ttl_seconds = freshness_seconds;
    config.cache_stale_seconds = stale_seconds;
    config
}

#[test]
fn a_burst_of_failing_names_costs_one_probe_not_one_per_name() {
    // CONTROL — the change that makes this fail: `session_is_at_fault`
    // calling the vendor's `info` directly instead of routing it through
    // `Generations::session_fault`'s coalescing. Two names failing together
    // would then spawn two `info` calls, and the count below would read 2,
    // never 1.
    let dir = scratch("daemon-proton-session-fault-burst");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, false, LogoutAnswer::Ok, None);
    let config = daemon_config_with_two_names(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = std::sync::Arc::new(store::build(&client, &Invocation::default()).registry);

    // Warm both names first: each is its own read against the same vault, so
    // the vendor is asked once per field before either failure below.
    let held_1 = value_from(&registry, DECLARED);
    let held_2 = value_from(&registry, DECLARED_2);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);

    // Both names fail at the same instant, on their own threads — a
    // sequential pair of reads would still coalesce inside the probe's
    // window, but only a genuine burst exercises the lock held across the
    // spawn, which is the mechanism under test.
    use std::sync::{Arc, Barrier};
    let barrier = Arc::new(Barrier::new(2));
    let (registry_a, barrier_a) = (Arc::clone(&registry), Arc::clone(&barrier));
    let first = std::thread::spawn(move || {
        barrier_a.wait();
        value_from(&registry_a, DECLARED)
    });
    let (registry_b, barrier_b) = (Arc::clone(&registry), barrier);
    let second = std::thread::spawn(move || {
        barrier_b.wait();
        value_from(&registry_b, DECLARED_2)
    });
    let answer_1 = first.join().expect("the first reader panicked");
    let answer_2 = second.join().expect("the second reader panicked");

    assert_eq!(
        answer_1, held_1,
        "the first name's value did not survive the burst"
    );
    assert_eq!(
        answer_2, held_2,
        "the second name's value did not survive the burst"
    );

    // Pin that BOTH reads actually reached the vendor and failed there,
    // before the probe count is read. Without this the case is green in a run
    // where one name's refresh is still queued or is answered inside
    // `REFRESH_GRACE` from the older value: one vendor failure, one probe,
    // and a passing count over a burst that never happened. The value
    // assertions above cannot close that hole — they read the same `held_N`
    // whether or not that name's refresh ever ran.
    assert!(
        vendor_call_count(&dir) >= 4,
        "the two warm-up reads and the two failing ones did not all reach the vendor, so \
         the probe count below is not measuring a burst: {}",
        vendor_call_count(&dir)
    );
    assert_eq!(
        info_call_count(&dir),
        1,
        "two names failing over one session cost more than one probe"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_session_fault_wakes_the_renewal_loop_inside_min_backoff() {
    // CONTROL — the change that makes this fail: dropping
    // `generations.take_session_fault()` from `run`'s own `due` calculation.
    // The loop would then only ever renew on its age or its own `alive()`
    // check, and neither is due here — `info` answers healthy throughout,
    // and `login_after_minutes` / `probe_interval_seconds` both sit far
    // outside this test's own window — so the poll below would time out
    // with no second login ever recorded.
    let dir = scratch("daemon-proton-session-fault-wakes-loop");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true, // `info` always answers: nothing here is due on liveness
        LogoutAnswer::Ok,
        None,
    );
    // `login_after_minutes: 90` and `probe_interval_seconds: 120` put both
    // ordinary triggers far outside this test's run, so a second login
    // inside the poll below can only be the session-fault event.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 120, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    let original_name = loop {
        if let Some(name) = current_generation(&root) {
            break name;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    // No `.session/session.json` is ever planted under the generation the
    // fake `login` verb "established" — this stand-in never writes one — so
    // the read below is classified a session fault by the cheaper of the
    // two checks, the `stat`, independent of `info_answers` above.
    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    let _ = registry.resolve(DECLARED);

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(name) = current_generation(&root)
            && name != original_name
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no second login happened within 30s of the session-fault event, though the \
             configured interval is 120s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_broken_current_pointer_wakes_the_renewal_loop_inside_min_backoff() {
    // The pointer-read mirror of `a_session_fault_wakes_the_renewal_loop_inside_min_backoff`
    // above: there, a read finds the CURRENT generation's own session dead;
    // here, a read finds `current` itself naming a generation that was never
    // created — struck from outside the daemon, the way a crash mid-retire or
    // a hand-edit would leave it. Both must wake the loop inside `min_backoff`
    // rather than waiting out `probe_interval_seconds`.
    //
    // CONTROL — the change that makes this fail: `ProtonStore::enter` filing
    // no fault on `CurrentFault::Missing` (or `::Malformed`, `::Absent`),
    // leaving only `generations.take_session_fault()`'s ordinary triggers —
    // age and `alive()` — neither due here, so the poll below would time out
    // with `current` still naming the struck generation.
    let dir = scratch("daemon-proton-pointer-fault-wakes-loop");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, true, LogoutAnswer::Ok, None);
    // `login_after_minutes: 90` and `probe_interval_seconds: 120` put both
    // ordinary triggers far outside this test's run, so a new generation
    // published inside the poll below can only be the pointer-fault event.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 120, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    until_a_generation_is_published(&root, Duration::from_secs(30));

    // Struck from outside the daemon: `current` now names a generation this
    // root never created — `Missing`, one of the three shapes a broken
    // pointer takes.
    std::fs::write(root.join("current"), b"gen-1-1\n").expect("plant a broken current pointer");

    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    let _ = registry.resolve(DECLARED);

    // 30s rather than the configured 120s: a new generation replacing the
    // struck pointer this quickly can only be the pointer-fault event, never
    // the ordinary probe interval.
    until_current_moves_past(&root, "gen-1-1", Duration::from_secs(30));

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
