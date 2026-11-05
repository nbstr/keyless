#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::time::Duration;

use keyless::store::{self, Invocation};

use daemon_proton_support::session_verbs::{LogoutAnswer, stub_with_session_verbs};
use daemon_proton_support::warm_cache::{
    FRESHNESS_SECONDS, ITEM_VERDICT, PAST_FRESHNESS, STALE_SECONDS, TRANSPORT_FAILURE,
    TRANSPORT_FRAGMENT, daemon_config_with_a_warm_cache, until_the_read_degrades,
    until_the_vendor_has_been_asked, value_from,
};
use daemon_proton_support::{DECLARED, LISTING};
use support::backend::{Backend, NextCall, set_next_call, vendor_decoy};
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::proton::{Listing, stub_pass_cli_listing};
use support::scratch;

#[test]
fn a_vendor_that_could_not_reach_the_service_leaves_the_value_being_served() {
    // The expensive half of the classification. A transport failure says
    // nothing about the item, so the value stands — and the discriminator is
    // that while the vendor is refusing every call, the first decoy can only
    // have come from the daemon's memory.
    //
    // CONTROL — three changes, each making this fail: dropping the phrase from
    // the adapter's `UNREACHABLE` list, so the sentence is read as the account
    // disowning the item; the adapter reporting a `Backend` error where it
    // reports `Unavailable`; and the resolver evicting on a store that could
    // not answer. Under any of them the reads below degrade instead of
    // answering, because the vendor cannot supply a value any more.
    let dir = scratch("daemon-proton-warm-unreachable");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(TRANSPORT_FAILURE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "a vendor that never reached its service took the value with it"
    );
    until_the_vendor_has_been_asked(&dir, 2);

    // And it is still there afterwards, which is the half a single read cannot
    // show: the refresh has now failed, and the entry it failed on is what
    // answers the next reader.
    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "the value survived the failing refresh and then did not survive the read after it"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_vendor_that_answers_about_the_item_evicts_the_value_and_the_next_read_degrades() {
    // The other half, and the one that costs a credential if it is wrong: the
    // account has spoken about this name, so what the daemon holds is worthless
    // and serving it would hand out a credential its owner has disowned.
    //
    // The vendor is turned SILENT after the verdict, and that is what makes the
    // eviction observable rather than assumed. A transport failure is the one
    // shape that keeps a value alive — the case above this one is exactly that
    // — so if the verdict had left the entry in place, every read below would
    // be answered from it for the whole stale window. Degrading is therefore
    // only possible if the entry is gone.
    //
    // CONTROL — the change that makes this fail: the resolver keeping a value
    // when a store answers about it, or the adapter reporting this sentence as
    // a transport failure. Either way the poll below never degrades and fails
    // at `NEVER_HAPPENED`.
    //
    // Wrapped in `stub_with_session_verbs` with `info_answers: true` since
    // the session-fault slice landed: this test's whole point is a HEALTHY
    // session that the account still refuses an item over, and the plain
    // `Backend::Controlled` stub answers every verb — `info` included —
    // out of the same `NextCall`, which would misread this exact case as a
    // dead session.
    let dir = scratch("daemon-proton-warm-verdict");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, true, LogoutAnswer::Ok, None);
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(ITEM_VERDICT));
    std::thread::sleep(PAST_FRESHNESS);
    let _ = registry.resolve(DECLARED);
    until_the_vendor_has_been_asked(&dir, 2);

    set_next_call(&dir, &NextCall::Fails(TRANSPORT_FAILURE));
    let reason = until_the_read_degrades(&registry, DECLARED);

    // Which failure the degraded read carried, and it is load-bearing. A read
    // that degraded on the VERDICT itself proves nothing about eviction: it
    // would be the vendor's answer travelling to the caller with the entry
    // still in place behind it. Only a read that reached the store and found it
    // unreachable — the shape that keeps a value — says the entry was gone.
    assert!(
        reason.contains(TRANSPORT_FRAGMENT),
        "the read degraded before the value's absence was what caused it: {reason}"
    );
    assert!(
        !reason.contains(&held),
        "the refusal carried the value it had just disowned"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
