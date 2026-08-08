//! The session's side of the privilege boundary.
//!
//! A [`Store`] like any other, which is the whole trick: `run` already knows
//! how to degrade when a store cannot answer, so a daemon that is absent,
//! wedged, or refusing produces exactly the behaviour that already has property
//! tests — one line on stderr, and the child runs with an unmodified
//! environment.
//!
//! # Every failure here is `Err`, and every `Err` degrades
//!
//! Absent socket, stale socket, permission denied, timeout, connection reset,
//! garbage on the wire, a refused attestation: all of them come back as a
//! [`StoreError`], which `run` turns into `DEGRADED`. There is no path in this
//! file that returns a value it did not receive from the daemon, and none that
//! consults anything local. That is invariant 2 — killing the daemon must get
//! you *fewer* secrets, never more — expressed as code rather than as a rule
//! someone has to remember.

use std::time::Duration;

use crate::error::StoreError;
use crate::ipc::client::{Client, ClientError};
use crate::ipc::protocol::{Reply, Request};
use crate::secret::Secret;
use crate::store::Store;

/// The daemon's store id.
///
/// A constant rather than a literal in two places: `build` compares per-name
/// pins against it, and a drift between that comparison and what `id()`
/// returns would silently drop every pin that names the daemon.
pub const DAEMON_STORE_ID: &str = "daemon";

/// Talks to `keylessd` over a Unix socket.
pub struct DaemonStore {
    client: Client,
}

impl DaemonStore {
    /// Point at a socket, with a deadline for each request.
    #[must_use]
    pub fn new(socket: std::path::PathBuf, timeout: Duration) -> Self {
        DaemonStore {
            client: Client::new(socket, timeout),
        }
    }

    /// The socket this store talks to, for `doctor`.
    #[must_use]
    pub fn socket(&self) -> &std::path::Path {
        self.client.socket()
    }

    fn unavailable(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Unavailable {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }

    fn backend(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Backend {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }

    /// Map a transport failure onto the store's two error kinds.
    ///
    /// The split matters only to `doctor`: `Unavailable` means the daemon is
    /// not there, `Backend` means it is there and something else is wrong.
    /// `run` treats both identically, and must.
    fn transport_error(&self, error: &ClientError) -> StoreError {
        match error {
            ClientError::Unreachable(_) | ClientError::Timeout(_) => {
                self.unavailable(error.to_string())
            }
            ClientError::Transport(_) | ClientError::Protocol(_) => self.backend(error.to_string()),
        }
    }
}

impl Store for DaemonStore {
    fn id(&self) -> &str {
        DAEMON_STORE_ID
    }

    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        match self.client.request(&Request::resolve(name)) {
            Ok(Reply::Value(secret)) => Ok(Some(secret)),
            Ok(Reply::Absent) => Ok(None),
            Ok(Reply::Denied(reason)) => {
                Err(self.backend(format!("refused by the daemon: {reason}")))
            }
            Ok(Reply::Failed(reason)) => Err(self.backend(reason)),
            Ok(Reply::Info { .. }) => {
                Err(self.backend("the daemon answered a resolve with an info reply"))
            }
            Err(error) => Err(self.transport_error(&error)),
        }
    }

    fn health(&self) -> Result<(), StoreError> {
        match self.client.request(&Request::ping()) {
            Ok(Reply::Info { .. }) => Ok(()),
            Ok(Reply::Denied(reason)) => {
                Err(self.backend(format!("refused by the daemon: {reason}")))
            }
            Ok(Reply::Failed(reason)) => Err(self.backend(reason)),
            Ok(other) => Err(self.backend(format!(
                "the daemon answered a ping with `{}`",
                other.status()
            ))),
            Err(error) => Err(self.transport_error(&error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DaemonStore;
    use crate::store::Store;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn an_absent_daemon_is_an_error_and_never_a_value() {
        let store = DaemonStore::new(
            PathBuf::from("/nonexistent/keyless/keylessd.sock"),
            Duration::from_millis(200),
        );
        let error = store.resolve("ANY").expect_err("there is no daemon");
        assert!(error.to_string().contains("unavailable"), "{error}");
        assert!(store.health().is_err());
    }

    #[test]
    fn a_stale_socket_file_is_an_error_and_never_a_value() {
        // A leftover socket inode with nothing listening: connect fails with
        // ECONNREFUSED rather than ENOENT, which is a different code path.
        let path = std::env::temp_dir().join(format!("keyless-stale-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
            drop(listener);
        }
        // Recreate the inode without a listener.
        std::fs::write(&path, b"").ok();
        let store = DaemonStore::new(path.clone(), Duration::from_millis(200));
        assert!(store.resolve("ANY").is_err());
        let _ = std::fs::remove_file(&path);
    }
}
