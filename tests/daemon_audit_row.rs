//! What the daemon's audit row says about a failed or remembered lookup.

// The daemon is macOS-only (`src/lib.rs`), so this whole file is. On any other
// platform the crate below compiles to nothing and the binary reports 0 tests —
// ABSENT rather than ignored, which is why CI's `ignored == 15` assertion is
// unchanged and still means "the Proton live suite, and nothing else".
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use keyless::store::Store;
use keyless::store::daemon::DaemonStore;

use support::audit_rows::{decision_for, rows_for};
use support::keychain::slow_after_first_store_stub;
use support::{DECOY_VALUE, daemon_config, policy_allowing_self, scratch, start_daemon};

// ---------------------------------------------------------------------------
// The audit row's failure kind and staleness marker.
//
// Both facts already exist upstream of the audit boundary — `StoreError` says
// whether a store was reached, `resolver::Source` says whether a value came
// from the vendor or from memory — and both used to be dropped at `record`.
// ---------------------------------------------------------------------------

/// A `security` stand-in that exits nonzero with a stderr line, on every
/// lookup — `StoreError::Backend`: the account was asked and refused it.
fn refusing_store_stub(dir: &Path) -> PathBuf {
    let body = "#!/bin/sh\n\
                 case \"$1\" in\n\
                 \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
                 esac\n\
                 echo 'security: SecKeychainSearchCopyNext: User interaction is not allowed.' >&2\n\
                 exit 51\n"
        .to_owned();
    support::install_executable(&dir.join("security-refusing"), &body)
}

#[test]
fn a_dead_session_and_an_account_verdict_read_apart_in_the_audit_row() {
    // Dead: the binary does not exist. `capture` fails to spawn, which the
    // keychain adapter maps to `StoreError::Unavailable` — nothing was asked
    // about the name, so a cached value would still stand had one existed.
    let dead_dir = scratch("daemon-audit-silent");
    let mut dead_config = daemon_config(&dead_dir);
    dead_config.stores.file.enabled = false;
    dead_config.stores.keychain.enabled = true;
    dead_config.stores.keychain.binary = dead_dir.join("no-such-binary").into();
    let dead = start_daemon(&dead_config, policy_allowing_self());
    let dead_store = DaemonStore::new(dead.socket().to_path_buf(), Duration::from_secs(10));
    assert!(dead_store.resolve("SILENT_NAME").is_err());
    drop(dead);

    // Verdict: the store answers and refuses. `security` exits nonzero with
    // stderr, which the adapter maps to `StoreError::Backend` — the account
    // took a position on the name.
    let verdict_dir = scratch("daemon-audit-verdict");
    let mut verdict_config = daemon_config(&verdict_dir);
    verdict_config.stores.file.enabled = false;
    verdict_config.stores.keychain.enabled = true;
    verdict_config.stores.keychain.binary = refusing_store_stub(&verdict_dir).into();
    let verdict = start_daemon(&verdict_config, policy_allowing_self());
    let verdict_store = DaemonStore::new(verdict.socket().to_path_buf(), Duration::from_secs(10));
    assert!(verdict_store.resolve("VERDICT_NAME").is_err());
    drop(verdict);

    let dead_rows = std::fs::read_to_string(&dead_config.audit).expect("read the dead audit log");
    let verdict_rows =
        std::fs::read_to_string(&verdict_config.audit).expect("read the verdict audit log");

    let dead_decision = decision_for(&dead_rows, "SILENT_NAME");
    let verdict_decision = decision_for(&verdict_rows, "VERDICT_NAME");
    assert_eq!(dead_decision, "store-silent");
    assert_eq!(verdict_decision, "store-verdict");
    assert_ne!(
        dead_decision, verdict_decision,
        "a dead session and an account verdict must read apart"
    );

    let _ = std::fs::remove_dir_all(&dead_dir);
    let _ = std::fs::remove_dir_all(&verdict_dir);
}

#[test]
fn a_value_served_past_freshness_carries_its_staleness_in_the_audit_row() {
    let dir = scratch("daemon-audit-stale");
    let mut config = daemon_config(&dir);
    config.stores.file.enabled = false;
    config.stores.keychain.enabled = true;
    config.stores.keychain.binary = slow_after_first_store_stub(&dir, DECOY_VALUE, 3).into();
    config.cache_ttl_seconds = 1;
    config.cache_stale_seconds = 5;

    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(10));

    // Warm the cache. Fresh, so this row carries no age.
    let first = store
        .resolve("STALE_NAME")
        .expect("resolve")
        .expect("a value must come back");
    assert_eq!(first.expose(), DECOY_VALUE);

    // Past freshness, inside the stale window: the refresh this queues sleeps
    // three seconds against a one-second grace, so this read is answered from
    // the cache while that refresh is still in flight.
    std::thread::sleep(Duration::from_millis(1200));
    let second = store
        .resolve("STALE_NAME")
        .expect("resolve")
        .expect("a value must come back");
    assert_eq!(second.expose(), DECOY_VALUE);

    drop(running);

    let rows = std::fs::read_to_string(&config.audit).expect("read the audit log");
    let mut named = rows_for(&rows, "STALE_NAME");
    assert_eq!(named.len(), 2, "rows naming STALE_NAME in:\n{rows}");
    let fresh = named.remove(0);
    let stale = named.remove(0);

    assert_eq!(fresh["decision"].as_str(), Some("allow"), "{fresh:?}");
    assert_eq!(fresh["source"].as_str(), Some("store"), "{fresh:?}");
    assert!(fresh.get("age_ms").is_none(), "{fresh:?}");

    assert_eq!(stale["decision"].as_str(), Some("allow"), "{stale:?}");
    assert_eq!(stale["source"].as_str(), Some("stale"), "{stale:?}");
    assert!(
        stale["age_ms"].as_u64().expect("stale row carries an age") >= 1000,
        "{stale:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_fresh_read_from_memory_carries_no_age() {
    // The control for the case above: served inside the freshness window, a
    // row says `source: "memory"` and no age at all — `age` on `Answer` is
    // only ever `Some` past freshness.
    let dir = scratch("daemon-audit-memory");
    let mut config = daemon_config(&dir);
    config.stores.file.enabled = false;
    config.stores.keychain.enabled = true;
    config.stores.keychain.binary = slow_after_first_store_stub(&dir, DECOY_VALUE, 3).into();
    config.cache_ttl_seconds = 60;
    config.cache_stale_seconds = 60;

    let running = start_daemon(&config, policy_allowing_self());
    let store = DaemonStore::new(running.socket().to_path_buf(), Duration::from_secs(10));

    let _ = store.resolve("MEMORY_NAME").expect("resolve");
    let _ = store.resolve("MEMORY_NAME").expect("resolve");

    drop(running);

    let rows = std::fs::read_to_string(&config.audit).expect("read the audit log");
    let mut named = rows_for(&rows, "MEMORY_NAME");
    assert_eq!(named.len(), 2, "rows naming MEMORY_NAME in:\n{rows}");
    let second = named.remove(1);
    assert_eq!(second["source"].as_str(), Some("memory"), "{second:?}");
    assert!(second.get("age_ms").is_some(), "{second:?}");

    let _ = std::fs::remove_dir_all(&dir);
}
