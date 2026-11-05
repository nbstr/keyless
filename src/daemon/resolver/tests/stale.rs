use super::*;
use crate::daemon::resolver::{FailureKind, Source};
#[test]
fn a_fresh_value_is_served_from_memory_and_says_where_it_came_from() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::ZERO,
        vec![Reply::Value("decoy-warm")],
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    assert_eq!(resolver.resolve("X").source, Source::Store);
    let second = resolver.resolve("X");
    assert_eq!(second.source, Source::Memory);
    assert_eq!(value_of(&second), "decoy-warm");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_store_slower_than_the_grace_is_answered_from_memory_meanwhile() {
    // The property the whole mechanism exists for: past freshness, with a
    // store that takes longer than a caller should wait, the caller gets
    // the value it had rather than the vendor's latency.
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::from_secs(2),
        vec![Reply::Value("decoy-first"), Reply::Value("decoy-second")],
        Duration::from_millis(50),
        Duration::from_secs(60),
    );
    let refresher = Resolver::start(&resolver);

    let cold = resolver.resolve("X");
    assert_eq!(cold.source, Source::Store);
    assert_eq!(value_of(&cold), "decoy-first");

    std::thread::sleep(Duration::from_millis(120));
    let stale = resolver.resolve("X");
    assert_eq!(stale.source, Source::Stale, "{:?}", stale.outcome);
    assert_eq!(value_of(&stale), "decoy-first");

    // The refresh lands on its own, off this caller's request.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the store was asked more than once for the one refresh"
    );
    // What it fetched is what the next reader gets. That reader is past the
    // 50 ms window too, so it is served the new value and starts its own
    // refresh — the source it carries is not what this case is about.
    assert_eq!(value_of(&resolver.resolve("X")), "decoy-second");
    drop(refresher);
}

#[test]
fn a_stale_read_starts_one_refresh_however_many_readers() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::from_millis(400),
        vec![Reply::Value("decoy")],
        Duration::from_millis(50),
        Duration::from_secs(60),
    );
    let refresher = Resolver::start(&resolver);
    let _ = resolver.resolve("X");
    std::thread::sleep(Duration::from_millis(120));

    std::thread::scope(|scope| {
        for _ in 0..10 {
            let resolver = Arc::clone(&resolver);
            scope.spawn(move || {
                let _ = resolver.resolve("X");
            });
        }
    });
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "ten readers past freshness must start one refresh between them"
    );
    drop(refresher);
}

#[test]
fn a_store_that_could_not_answer_keeps_the_value_and_is_not_asked_again_at_once() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::ZERO,
        vec![Reply::Value("decoy-held"), Reply::Silent],
        Duration::from_millis(50),
        Duration::from_secs(60),
    );
    let refresher = Resolver::start(&resolver);
    let _ = resolver.resolve("X");
    std::thread::sleep(Duration::from_millis(120));

    let served = resolver.resolve("X");
    assert_eq!(served.source, Source::Stale);
    assert_eq!(value_of(&served), "decoy-held");

    // The floor holds the next reads off the store while the value is
    // being served from memory anyway.
    for _ in 0..5 {
        let again = resolver.resolve("X");
        assert_eq!(value_of(&again), "decoy-held");
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(refresher);
}

#[test]
fn a_store_that_disowns_the_value_evicts_it_rather_than_serving_it_stale() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::ZERO,
        vec![Reply::Value("decoy-gone"), Reply::Verdict],
        Duration::from_millis(50),
        Duration::from_secs(60),
    );
    let refresher = Resolver::start(&resolver);
    let _ = resolver.resolve("X");
    std::thread::sleep(Duration::from_millis(120));

    let answered = resolver.resolve("X");
    assert_eq!(answered.source, Source::Store);
    assert!(
        matches!(
            &answered.outcome,
            Outcome::Failed { reason, kind: FailureKind::Verdict } if reason.contains("trash")
        ),
        "{:?}",
        answered.outcome
    );
    assert_eq!(resolver.cached_len(), 0, "a disowned value stayed cached");
    drop(refresher);
}

#[test]
fn an_absence_from_a_refresh_evicts_the_value_too() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::ZERO,
        vec![Reply::Value("decoy-removed"), Reply::Absent],
        Duration::from_millis(50),
        Duration::from_secs(60),
    );
    let refresher = Resolver::start(&resolver);
    let _ = resolver.resolve("X");
    std::thread::sleep(Duration::from_millis(120));

    let answered = resolver.resolve("X");
    assert!(
        matches!(answered.outcome, Outcome::Absent),
        "expected the store's own absence, got {:?} from {:?}",
        answered.outcome,
        answered.source
    );
    assert_eq!(resolver.cached_len(), 0);
    drop(refresher);
}

#[test]
fn a_zero_ttl_disables_stale_serving_too() {
    // One key turns the whole mechanism off. A daemon told to cache
    // nothing must not acquire a five-minute window through a second key.
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::ZERO,
        vec![Reply::Value("decoy")],
        Duration::ZERO,
        Duration::from_secs(60),
    );
    for _ in 0..3 {
        assert_eq!(resolver.resolve("X").source, Source::Store);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(resolver.cached_len(), 0);
}

#[test]
fn a_value_past_both_windows_is_fetched_on_the_request_itself() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::ZERO,
        vec![Reply::Value("decoy-old"), Reply::Value("decoy-new")],
        Duration::from_millis(40),
        Duration::from_millis(40),
    );
    let _ = resolver.resolve("X");
    std::thread::sleep(Duration::from_millis(150));
    let answered = resolver.resolve("X");
    assert_eq!(answered.source, Source::Store);
    assert_eq!(value_of(&answered), "decoy-new");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn stale_serving_asks_no_more_often_than_expiry_alone_did() {
    // The volume claim, measured rather than argued: the same read
    // schedule against a resolver with a stale window and one without.
    fn calls_under(stale: Duration) -> u64 {
        let calls = Arc::new(AtomicU64::new(0));
        let resolver = scripted(
            &calls,
            Duration::ZERO,
            vec![Reply::Value("decoy")],
            Duration::from_millis(40),
            stale,
        );
        let refresher = Resolver::start(&resolver);
        for _ in 0..4 {
            let _ = resolver.resolve("X");
            let _ = resolver.resolve("X");
            std::thread::sleep(Duration::from_millis(60));
        }
        std::thread::sleep(Duration::from_millis(300));
        drop(refresher);
        calls.load(Ordering::SeqCst)
    }
    let without = calls_under(Duration::ZERO);
    let with = calls_under(Duration::from_secs(60));
    assert!(
        with <= without,
        "stale serving asked the store more often: {with} against {without}"
    );
}

#[test]
fn clearing_the_cache_during_a_refresh_leaves_it_empty() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = scripted(
        &calls,
        Duration::from_millis(500),
        vec![Reply::Value("decoy-one"), Reply::Value("decoy-two")],
        Duration::from_millis(40),
        Duration::from_secs(60),
    );
    let refresher = Resolver::start(&resolver);
    let _ = resolver.resolve("X");
    std::thread::sleep(Duration::from_millis(80));
    let _ = resolver.resolve("X"); // starts a refresh, serves the old value
    resolver.clear_cache();
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(
        resolver.cached_len(),
        0,
        "a refresh in flight refilled a cache that had been cleared"
    );
    drop(refresher);
}
