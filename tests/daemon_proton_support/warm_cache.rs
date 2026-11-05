use std::path::Path;
use std::time::{Duration, Instant};

use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Resolution};

use super::daemon_config_with_proton;
use crate::support::backend::vendor_call_count;

/// The freshness window for the cases that have to go PAST it.
///
/// One second, which is the smallest there is — `cache_ttl_seconds` is whole
/// seconds. Everything below sleeps [`PAST_FRESHNESS`] rather than 1 001 ms so
/// that a loaded machine lands further past the window rather than short of it.
pub const FRESHNESS_SECONDS: u64 = 1;

/// How long a value may still be served once it is past freshness.
///
/// A minute, so no case below reaches the far edge of it and none of them is
/// accidentally measuring the sweep.
pub const STALE_SECONDS: u64 = 60;

/// Comfortably past [`FRESHNESS_SECONDS`].
pub const PAST_FRESHNESS: Duration = Duration::from_millis(1_200);

/// The longest any poll below waits before reporting what never happened.
///
/// It bounds a FAILURE and nothing else — every case here converges in seconds
/// — so being generous costs a passing run nothing and buys a loaded machine
/// all the room it needs.
pub const NEVER_HAPPENED: Duration = Duration::from_secs(20);

/// What `pass-cli` printed while the network was gone.
///
/// Verbatim, measured 2026-09-09 in the daemon's own log and quoted in the
/// adapter's `UNREACHABLE` list. Quoted here rather than approximated: the
/// adapter matches on these words, so a fixture that paraphrased them would be
/// proving the match against a sentence no release has ever printed.
pub const TRANSPORT_FAILURE: &str =
    "failed to connect to host: error resolving destination: unknown error errno=None";

/// Enough of it to recognise in a degraded run's reason.
pub const TRANSPORT_FRAGMENT: &str = "failed to connect to host";

/// The vendor answering about the ITEM rather than about its own reach.
///
/// What makes this a verdict is that it is OUTSIDE the adapter's allowlist, not
/// its wording — the allowlist holds the measured transport phrases and every
/// other sentence is the account speaking about the name. The wording of the
/// allowlist itself is pinned by that adapter's own unit tests; all a fixture
/// here has to be is outside it.
pub const ITEM_VERDICT: &str = "no item titled decoy is readable in vault company";

/// The same daemon as [`daemon_config_with_proton`], with its cache turned on.
///
/// The fixture next door pins `cache_ttl_seconds` at zero because every case
/// above it is about a vendor process that must not be created, and a cache
/// would answer some of those reads without asking anything. These cases are
/// about the cache itself, so they say what they want.
///
/// Set on the parsed struct rather than in the JSON: both keys are read from
/// JSON by the daemon's own config tests, and what these cases need is the
/// window the daemon runs with, not a second proof that the key is spelled
/// right.
pub fn daemon_config_with_a_warm_cache(
    dir: &Path,
    vendor: &Path,
    freshness_seconds: u64,
    stale_seconds: u64,
) -> DaemonConfig {
    let mut config = daemon_config_with_proton(dir, vendor);
    config.cache_ttl_seconds = freshness_seconds;
    config.cache_stale_seconds = stale_seconds;
    config
}

/// The value a name resolved to, or a panic naming why there was none.
///
/// The reason is safe to print: every refusal this daemon produces is built
/// from a store's own error text, and the cases above this section are what
/// hold that down.
pub fn value_from(registry: &store::Registry, name: &str) -> String {
    match registry.resolve(name) {
        Resolution::Found { secret, store } => {
            assert_eq!(
                store, "daemon",
                "the value came from the session's own side"
            );
            secret.expose().to_owned()
        }
        other => panic!("`{name}` did not resolve: {}", other.reason()),
    }
}

/// Wait until the stand-in vendor has been asked for a value `times` over.
///
/// The tally is appended when a call STARTS, so this waits for a spawn rather
/// than for an answer — which is what a case wants before it changes what the
/// next call will do.
pub fn until_the_vendor_has_been_asked(dir: &Path, times: usize) {
    let deadline = Instant::now() + NEVER_HAPPENED;
    while Instant::now() < deadline {
        if vendor_call_count(dir) >= times {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "the vendor was asked {} time(s), never {times}",
        vendor_call_count(dir)
    );
}

/// Read `name` until it degrades, and hand back the reason it gave.
pub fn until_the_read_degrades(registry: &store::Registry, name: &str) -> String {
    let deadline = Instant::now() + NEVER_HAPPENED;
    while Instant::now() < deadline {
        match registry.resolve(name) {
            Resolution::Found { .. } => std::thread::sleep(Duration::from_millis(50)),
            other => return other.reason(),
        }
    }
    panic!("`{name}` never stopped resolving, so nothing was ever evicted");
}
