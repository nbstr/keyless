use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use keyless::attest::Policy;
use keyless::daemon::Daemon;
use keyless::daemon::Running;
use keyless::daemon::config::DaemonConfig;
use keyless::daemon::config::DaemonStores;
use keyless::daemon::config::FileStoreConfig;
use keyless::daemon::config::PeerConfig;
use keyless::ipc::peer;

use super::short_socket_path;

// ---------------------------------------------------------------------------
// Daemon fixtures
// ---------------------------------------------------------------------------

/// This process's own verified identity.
///
/// Both ends of a socketpair belong to us, so attesting one end is attesting
/// ourselves — which is how a test pins the test binary as an authorised
/// client without shelling out to anything.
pub fn own_identity() -> peer::PeerIdentity {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    peer::identify(a.as_fd()).expect("this process must be able to attest itself")
}

/// A policy that authorises this test process and nothing else.
pub fn policy_allowing_self() -> Policy {
    let me = own_identity();
    Policy::new().allow_uid(me.uid).allow_image(me.code_hash)
}

/// A policy that authorises this process's uid but no image at all.
pub fn policy_allowing_nobody() -> Policy {
    Policy::new().allow_uid(own_identity().uid)
}

/// A daemon config rooted in `dir`, backed by a file store.
pub fn daemon_config(dir: &Path) -> DaemonConfig {
    DaemonConfig {
        socket: short_socket_path(dir).into(),
        audit: dir.join("audit.jsonl").into(),
        cache_ttl_seconds: 60,
        // No stale window in the fixtures: a test that wants one says so, and
        // one that does not gets the pre-existing behaviour — a value is
        // served for its freshness window and then fetched again.
        cache_stale_seconds: 0,
        // No silent window either, for the same reason.
        cache_silent_seconds: 0,
        idle_timeout_seconds: 5,
        peer: PeerConfig::default(),
        stores: DaemonStores {
            file: FileStoreConfig {
                enabled: true,
                path: dir.join("secrets.json").into(),
            },
            ..DaemonStores::default()
        },
        // One store, so nothing needs routing. The fixtures that DO run two
        // stores build their config from JSON instead, because an unread key
        // is dropped in silence and a struct literal cannot show that.
        secrets: std::collections::BTreeMap::new(),
    }
}

/// Bind and start serving.
pub fn start_daemon(config: &DaemonConfig, policy: Policy) -> Running {
    let daemon = Daemon::bind(config, policy).expect("bind the daemon");
    Running::spawn(daemon, config).expect("start the accept loop")
}
