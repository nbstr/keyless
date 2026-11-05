#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::time::{Duration, Instant};

use keyless::ipc::client::{Client, ClientError};
use keyless::ipc::protocol::{Reply, Request};
use keyless::store::{self, Invocation};

use daemon_proton_support::warm_cache::{
    FRESHNESS_SECONDS, NEVER_HAPPENED, PAST_FRESHNESS, STALE_SECONDS,
    daemon_config_with_a_warm_cache, until_the_vendor_has_been_asked, value_from,
};
use daemon_proton_support::{DECLARED, ITEM, LISTING, VAULT, daemon_config_with_proton};
use support::backend::{Backend, NextCall, set_next_call, vendor_call_count, vendor_decoy};
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::proton::{Listing, stub_pass_cli_listing};
use support::scratch;

// ---------------------------------------------------------------------------
// The warm cache: what a slow, silent or disowning vendor does to a value the
// daemon is already holding.
//
// # Why these are here rather than beside the resolver
//
// `src/daemon/resolver.rs` already drives every one of these transitions
// against a scripted `Store`, and that store returns whichever `StoreError`
// variant the case asked for. So the resolver's cases assume the classification
// they are testing the consequences of: they say what a `Backend` error does
// and what an `Unavailable` error does, and nothing there fails if the Proton
// adapter starts producing the other one.
//
// That classification is `reached_no_service` plus `vendor_failed` in
// `src/store/proton.rs`, and its input is a SENTENCE a vendor process printed
// on stderr. The cases below are the only ones that hand it a real sentence
// from a real child of a real daemon and read the result at the client's own
// seam — which is where the cost lands: a verdict read as transport keeps
// serving a credential the account has disowned.
//
// # Why nothing below is timed
//
// The stand-in hands out a different decoy on every call, so "which value came
// back" answers "was the store asked" outright. Where a delay is unavoidable it
// is several times the window it has to lose to, and it is a SLEEP — which can
// only ever overshoot, so a loaded machine pushes every one of these further
// into the case being true rather than out of it.
// ---------------------------------------------------------------------------

/// A second name at the same address as [`DECLARED`].
///
/// For the one case that needs two lookups running at once: single-flight
/// coalesces per name, so two reads of one name would be one vendor call and
/// the second read would prove nothing about a cold one.
const DECLARED_AGAIN: &str = "FIXTURE_DECLARED_TOO";

/// The freshness window for the case that has to stay INSIDE it.
///
/// A minute, and generous on purpose: the case asserts that a second read costs
/// no vendor call, so the window has to be wide enough that no amount of load
/// can push the second read out of it and turn a correct daemon red.
const GENEROUS_FRESHNESS_SECONDS: u64 = 60;

/// How long a vendor takes when it has to lose a race against the resolver's
/// one-second refresh grace.
///
/// Five times that grace. The margin is not politeness: the reader's grace
/// expires on a timed wait, and a machine loaded enough to wake that thread
/// four seconds late would be the only way this stand-in answers in time. A
/// sleep cannot finish early, so nothing can shrink the gap from the other end.
const SLOWER_THAN_THE_GRACE: Duration = Duration::from_secs(5);

/// How long a vendor takes when it has to outlast the CLIENT's silence
/// deadline.
///
/// Three times [`SILENCE_MS`], for the same reason and in the same direction.
const SLOWER_THAN_THE_SILENCE: Duration = Duration::from_secs(3);

/// How long the client will hear nothing at all before it gives up.
///
/// The SUBJECT of the cold-read case rather than a ceiling on it, which is why
/// it is small where the rest of this suite is generous: the case is about a
/// lookup that outlives it.
const SILENCE_MS: u64 = 1_000;

/// Read `name` until the answer stops being `held`, and hand back the new one.
///
/// A poll rather than a sleep of the right length: what it is waiting for is a
/// vendor child finishing and a worker thread publishing what it fetched, and
/// the only sleep long enough for that on every machine is one far longer than
/// it takes on this one. A daemon that never refreshes fails this just as
/// surely, at [`NEVER_HAPPENED`].
fn until_the_value_stops_being(registry: &store::Registry, name: &str, held: &str) -> String {
    let deadline = Instant::now() + NEVER_HAPPENED;
    while Instant::now() < deadline {
        let answer = value_from(registry, name);
        if answer != held {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("`{name}` was still being answered from the value it started with");
}

#[test]
fn two_reads_inside_the_freshness_window_cost_one_vendor_probe() {
    // CONTROL — the change that makes this fail: `cache_ttl_seconds: 0`, which
    // is what the fixture next door uses. The second read then reaches the
    // vendor, comes back as the SECOND decoy, and both assertions below break.
    //
    // Nothing here is timed. The stand-in hands out a different value on every
    // call, so a second read answered by a vendor process is visible in the
    // string it returned and does not have to be inferred from how long it
    // took.
    let dir = scratch("daemon-proton-warm-twice");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    // No stale window: this case is about freshness, and a stale window would
    // give a second read a second route to an answer.
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, GENEROUS_FRESHNESS_SECONDS, 0);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    // What the stand-in answers with on its first call, by the FIXTURE's own
    // definition. Both reads are compared against this rather than against each
    // other: two answers from one daemon agree whatever that daemon does, which
    // is the shape `tests/oracle_independence.rs` refuses.
    let first_answer = vendor_decoy(1);

    assert_eq!(
        value_from(&registry, DECLARED),
        first_answer,
        "the cold read did not come from the vendor, so nothing below it is about a cache"
    );
    assert_eq!(
        value_from(&registry, DECLARED),
        first_answer,
        "the second read was answered by a vendor process"
    );
    assert_eq!(
        vendor_call_count(&dir),
        1,
        "a name read twice inside its freshness window cost more than one vendor process"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_vendor_slower_than_the_grace_leaves_the_held_value_in_front_of_the_caller() {
    // The property the whole mechanism exists for, asked of a real vendor
    // process: past freshness, against a store that takes longer than a caller
    // should wait, the caller gets the value the daemon already had.
    //
    // CONTROL — the change that makes this fail: a daemon that waits for the
    // refresh instead of serving what it holds. It would hand back the SECOND
    // decoy, five seconds later, and the assertion on `served` breaks. A daemon
    // that serves the held value and never refreshes fails the second half at
    // `NEVER_HAPPENED`.
    let dir = scratch("daemon-proton-warm-slow");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Slow(SLOWER_THAN_THE_GRACE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "the caller waited on the vendor instead of being handed the value the daemon held"
    );

    // The refresh was started, off this caller's request. Without this the case
    // above would also pass against a daemon that serves a stale value for ever
    // and asks nobody.
    until_the_vendor_has_been_asked(&dir, 2);

    // From here the stand-in answers at once, so the poll below converges as
    // fast as the machine allows. The call already sleeping read its
    // instruction when it started and still sleeps out its five seconds.
    set_next_call(&dir, &NextCall::Answers);
    let refreshed = until_the_value_stops_being(&registry, DECLARED, &held);

    // Which call's decoy this is, is deliberately not asserted: a poll that
    // lands in the wrong second starts a third call, and a third refresh is the
    // same daemon behaving the same way. What is pinned is that the held value
    // stopped being the answer, which no daemon without a refresh can produce.
    assert_ne!(refreshed, vendor_decoy(1));
    assert!(
        vendor_call_count(&dir) >= 2,
        "the value changed without a vendor process being asked for it"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_cold_read_slower_than_the_clients_own_deadline_still_reaches_the_caller() {
    // The Proton adapter's own version of the outage the heartbeat closed. It
    // is worth asking here as well as at `tests/daemon_connection.rs`'s keychain stub,
    // because a cold Proton lookup is TWO vendor children — the vault listing,
    // then the read — so the latency a caller waits out is their sum, and that
    // sum is what was measured overrunning a session's deadline.
    //
    // Both halves go to one daemon over one store and differ in one field, the
    // way that case does. That pairing is the control: if the value arrives
    // either way the deadline was never the thing under test, and if it arrives
    // neither way the heartbeat is not what carries it.
    //
    // Two DIFFERENT names, because single-flight coalesces per name: one name
    // read twice would be one vendor call, and the second read would be handed
    // the first one's answer without ever having been slow.
    let dir = scratch("daemon-proton-cold-and-slow");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    set_next_call(&dir, &NextCall::Slow(SLOWER_THAN_THE_SILENCE));
    // The fixture's own `cache_ttl_seconds: 0`, deliberately: with nothing
    // cached the second lookup pays the vendor's whole cost too, and cannot be
    // answered out of the first one's success.
    let mut config = daemon_config_with_proton(&dir, &vendor);
    config.secrets.insert(
        DECLARED_AGAIN.to_owned(),
        serde_json::from_str(&format!(
            r#"{{"store":"proton","vault":"{VAULT}","item":"{ITEM}","field":"password"}}"#
        ))
        .expect("a valid route"),
    );
    let running = start_daemon(&config, policy_allowing_self());

    // ONE client for both requests, so the deadline in force is provably this
    // one. Built through the two halves' shared object rather than through a
    // config on each: a loud read that outran a deadline nobody in the case can
    // see would pass just as well against a client that had quietly been given
    // a longer one.
    let silence = Duration::from_millis(SILENCE_MS);
    let client = Client::new(running.socket().to_path_buf(), silence);

    let mut asks_for_no_heartbeat = Request::resolve(DECLARED_AGAIN);
    asks_for_no_heartbeat.progress = false;
    match client.request(&asks_for_no_heartbeat) {
        Err(ClientError::Timeout(after)) => assert_eq!(after, silence),
        other => panic!("a daemon that says nothing must time out, got {other:?}"),
    }

    let began = Instant::now();
    let answered = client.request(&Request::resolve(DECLARED));
    let took = began.elapsed();

    match answered {
        // The SECOND decoy, so this read reached a vendor process of its own
        // rather than being handed whatever the mute lookup left behind. The
        // ordinal is settled: the mute lookup's child has been sleeping for a
        // second by the time this request is made.
        Ok(Reply::Value(secret)) => assert_eq!(
            secret.expose(),
            vendor_decoy(2),
            "the value did not come from this lookup's own vendor process"
        ),
        other => panic!("a daemon that says it is working must be waited for, got {other:?}"),
    }
    assert!(
        took > silence,
        "the value came back inside the silence deadline, so nothing outran it and this \
         proves nothing: {took:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
