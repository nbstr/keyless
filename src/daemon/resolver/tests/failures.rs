use super::*;
use crate::daemon::resolver::FailureKind;
#[test]
fn a_failure_is_never_cached() {
    // A store that is briefly down must not pin every session into
    // degraded mode for the whole TTL.
    struct Broken;
    impl Store for Broken {
        fn id(&self) -> &str {
            "broken"
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            Err(StoreError::Unavailable {
                store: "broken".to_owned(),
                detail: "down".to_owned(),
            })
        }
        fn health(&self) -> Result<(), StoreError> {
            Err(StoreError::Unavailable {
                store: "broken".to_owned(),
                detail: "down".to_owned(),
            })
        }
    }
    let resolver = Resolver::new(
        Registry::new(vec![Box::new(Broken)]),
        Duration::from_secs(600),
    );
    for _ in 0..2 {
        assert!(matches!(
            resolver.resolve("X").outcome,
            Outcome::Failed {
                kind: FailureKind::Silent,
                ..
            }
        ));
    }
    assert_eq!(resolver.cached_len(), 0);
    assert_eq!(resolver.upstream_calls(), 2);
}

#[test]
fn a_store_that_refuses_the_item_fails_with_a_verdict_not_a_silence() {
    // The two errors a real store can return read identically as strings —
    // this is the distinction `FailureKind` exists to keep past that.
    struct Refusing;
    impl Store for Refusing {
        fn id(&self) -> &str {
            "refusing"
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            Err(StoreError::Backend {
                store: "refusing".to_owned(),
                detail: "no such item".to_owned(),
            })
        }
        fn health(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }
    let resolver = Resolver::new(
        Registry::new(vec![Box::new(Refusing)]),
        Duration::from_secs(600),
    );
    assert!(matches!(
        resolver.resolve("X").outcome,
        Outcome::Failed {
            kind: FailureKind::Verdict,
            ..
        }
    ));
}

#[test]
fn an_ambiguous_name_says_which_config_file_can_settle_it() {
    // The remedy has to name the daemon's file. A reader who applies it to
    // the session's config changes nothing — `store::build` drops a
    // session's pins whenever the daemon is enabled — and then has a
    // config that looks correct and a run that still degrades.
    let registry = Registry::new(vec![
        Box::new(Counting {
            calls: Arc::new(AtomicU64::new(0)),
            delay: Duration::ZERO,
            value: Some("decoy-one"),
        }),
        Box::new(Named("other")),
    ]);
    match Resolver::new(registry, Duration::ZERO)
        .resolve("DATABASE_URL")
        .outcome
    {
        Outcome::Failed { reason, kind } => {
            assert!(reason.contains("keylessd"), "{reason}");
            assert!(reason.contains("stores.default"), "{reason}");
            assert!(!reason.contains("decoy-"), "the reason leaked a value");
            assert_eq!(kind, FailureKind::Unrouted);
        }
        other => panic!("expected a failure naming the candidates, got {other:?}"),
    }
}

#[test]
fn an_outcome_debug_never_prints_the_value() {
    let outcome = Outcome::Found(std::sync::Arc::new(Secret::new(
        "decoy-must-not-appear-7742".to_owned(),
    )));
    assert!(!format!("{outcome:?}").contains("7742"));
}
