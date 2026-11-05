use super::*;
use std::sync::Barrier;
#[test]
fn twenty_concurrent_requests_make_one_upstream_call() {
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = Arc::new(resolver(
        &calls,
        Duration::from_millis(80),
        Some("decoy-single-flight"),
        Duration::ZERO,
    ));
    // TTL is zero, so nothing is cached: a second call would show up in the
    // counter. Any coalescing seen here is coalescing, not caching.
    let gate = Arc::new(Barrier::new(20));
    std::thread::scope(|scope| {
        for _ in 0..20 {
            let resolver = Arc::clone(&resolver);
            let gate = Arc::clone(&gate);
            scope.spawn(move || {
                gate.wait();
                match resolver.resolve("SHARED").outcome {
                    Outcome::Found(secret) => {
                        assert_eq!(secret.expose(), "decoy-single-flight");
                    }
                    other => panic!("expected a value, got {other:?}"),
                }
            });
        }
    });
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "twenty simultaneous requests for one name must reach the store once"
    );
    assert_eq!(resolver.upstream_calls(), 1);
}

#[test]
fn different_names_are_not_coalesced_with_each_other() {
    // The negative control for the test above: if `resolve` coalesced
    // everything rather than per name, this would also report one call.
    let calls = Arc::new(AtomicU64::new(0));
    let resolver = Arc::new(resolver(
        &calls,
        Duration::from_millis(40),
        Some("decoy"),
        Duration::ZERO,
    ));
    std::thread::scope(|scope| {
        for i in 0..6 {
            let resolver = Arc::clone(&resolver);
            scope.spawn(move || {
                let _ = resolver.resolve(&format!("NAME_{i}"));
            });
        }
    });
    assert_eq!(calls.load(Ordering::SeqCst), 6);
}
