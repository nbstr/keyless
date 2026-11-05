use super::*;
use crate::daemon::resolver::fetch::MAX_CACHE_ENTRIES;
#[test]
fn a_cached_value_is_served_without_touching_the_store() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = resolver(
        &calls,
        Duration::ZERO,
        Some("decoy-cached"),
        Duration::from_secs(60),
    );
    for _ in 0..5 {
        assert!(matches!(resolver.resolve("X").outcome, Outcome::Found(_)));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.cached_len(), 1);
}

#[test]
fn an_expired_entry_is_fetched_again() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = resolver(
        &calls,
        Duration::ZERO,
        Some("decoy-expiring"),
        Duration::from_millis(30),
    );
    assert!(matches!(resolver.resolve("X").outcome, Outcome::Found(_)));
    std::thread::sleep(Duration::from_millis(60));
    assert!(matches!(resolver.resolve("X").outcome, Outcome::Found(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn an_absence_is_never_cached_either() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = resolver(&calls, Duration::ZERO, None, Duration::from_secs(600));
    assert!(matches!(resolver.resolve("X").outcome, Outcome::Absent));
    assert!(matches!(resolver.resolve("X").outcome, Outcome::Absent));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(resolver.cached_len(), 0);
}

#[test]
fn the_cache_is_bounded() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = resolver(
        &calls,
        Duration::ZERO,
        Some("decoy"),
        Duration::from_secs(600),
    );
    for i in 0..(MAX_CACHE_ENTRIES + 40) {
        let _ = resolver.resolve(&format!("N{i}"));
    }
    assert!(resolver.cached_len() <= MAX_CACHE_ENTRIES);
}

#[test]
fn clearing_the_cache_makes_the_next_call_real() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = resolver(
        &calls,
        Duration::ZERO,
        Some("decoy"),
        Duration::from_secs(600),
    );
    let _ = resolver.resolve("X");
    resolver.clear_cache();
    let _ = resolver.resolve("X");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
