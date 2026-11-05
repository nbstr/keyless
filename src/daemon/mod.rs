//! `keylessd` — the process on the other side of the uid boundary.
//!
//! # What the boundary actually buys
//!
//! Stated precisely, because this is the part it is easy to overclaim.
//!
//! The problem it solves is that **anything readable by a uid is readable by
//! every process running as that uid**, including every agent session and every
//! subagent one spawns. No file mode, no deny rule and no wrapper changes that.
//! On macOS, `security find-generic-password -s <service> -w` returns the
//! plaintext with no prompt and exit 0 to any process running as the item's
//! owner, which is what makes the login keychain no boundary at all here.
//!
//! Running the store behind a second uid changes exactly one thing, and it is
//! the thing that matters: **the store credential is no longer reachable.** A
//! session can ask for `GITHUB_TOKEN` and get `GITHUB_TOKEN`. It cannot read the
//! file, unlock the keychain, or enumerate what else is in there.
//!
//! Three things it does **not** buy, written here rather than left to be
//! assumed:
//!
//! - **It does not stop an agent using a secret it is allowed to use.** An
//!   attested `keyless run -s TOKEN -- sh -c 'echo $TOKEN'` is an attested
//!   client running an arbitrary command, and no attestation scheme detects
//!   that. Attestation says *which program is asking*, never *what it intends*.
//! - **It does not survive `sudo`.** The calling user is typically an
//!   admin. Everything below is a boundary against that user acting as
//!   themselves, which is what an agent session is; it is not a boundary
//!   against a person who types their password.
//! - **It does not migrate anything.** Standing this daemon up next to a login
//!   keychain that still holds the secrets closes nothing at all — the items
//!   are still readable by the session. Moving them somewhere only the daemon's
//!   uid can read, and deleting them from where they were, is the step that
//!   actually shuts the hole, and no code can do it for you.
//!
//! # A panic here aborts, and that is the correct direction
//!
//! The release profile sets `panic = "abort"`, so a panic on a connection
//! thread ends the daemon rather than leaving it running in an unknown state.
//! The blast radius is that every session degrades — one stderr line each, and
//! their commands run with unmodified environments. Degrading the fleet is a
//! bad afternoon; a security daemon continuing past a broken invariant is worse.

pub mod check;
pub mod config;
pub mod credential;
pub mod login;
pub mod resolver;
pub mod session;
pub mod shadow;

mod accept;
mod connection;
mod heartbeat;
mod running;
#[cfg(test)]
mod tests;

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::thread;
use std::time::Duration;

use crate::attest::{Denial, Policy};
use crate::audit::AuditLog;
use crate::store::catalogue::{Catalogue, Rebuilder};
use crate::store::proton_session::Generations;

use self::config::DaemonConfig;
use self::resolver::{Refresher, Resolver};

/// Socket mode: owner and group may connect, nobody else.
///
/// Connecting needs **write** permission on the socket, not read — so `0660`
/// rather than the `0640` that the phrase "group readable" would suggest. The
/// group is what contains the session user; the owner is the daemon.
pub const SOCKET_MODE: u32 = 0o660;

/// Directory mode for the socket's parent: traversable by everyone, writable
/// only by the daemon.
///
/// If the session user could write this directory it could delete the socket
/// and bind its own in place of it, which is the cheapest possible attack on
/// this design.
pub const SOCKET_DIR_MODE: u32 = 0o755;

/// How often a request in flight tells the client it is still there — from
/// the moment its frame is decoded to the moment its reply is written, see
/// `Heartbeat`.
///
/// Sized against the thing it has to stay inside: the client's silence
/// deadline, which defaults to three seconds. Half a second leaves five missed
/// heartbeats of margin before a working daemon is mistaken for a wedged one,
/// and costs one short line on a socket per tick of a request that was going
/// to take seconds anyway.
///
/// It is deliberately not derived from that deadline. The two ends are
/// configured separately and by different people, and a heartbeat that shrank
/// to match a client's short deadline would let one careless session make every
/// other session's daemon chatty.
pub const HEARTBEAT: Duration = Duration::from_millis(500);

/// A bound, listening daemon.
pub struct Daemon {
    listener: UnixListener,
    socket: PathBuf,
    policy: Arc<Policy>,
    resolver: Arc<Resolver>,
    audit: Arc<AuditLog>,
    /// Every name this daemon can serve — the operator's declarations, and
    /// whatever the enumerable stores mint. See [`crate::store::catalogue`].
    catalogue: Arc<Catalogue>,
    /// Keeps that index current.
    ///
    /// Held behind an `Arc` and handed to every connection, because a miss is
    /// the only thing that starts a rebuild and a miss happens on a connection
    /// thread. Its worker stops when the last of those `Arc`s drops, which is
    /// when the accept thread lets go of the daemon.
    rebuilder: Arc<Rebuilder>,
    /// How long a miss waits on the rebuild it started: the timeout of the one
    /// store that mints names.
    rebuild_within: Duration,
    idle: Duration,
    live: Arc<AtomicUsize>,
    /// Shared with the stores this daemon resolves through, and with the
    /// renewal loop that creates and retires generations under it. `None`
    /// when Proton is disabled or names no `session_dir` — see
    /// [`DaemonConfig::generations`]. See [`Running::spawn`].
    generations: Option<Arc<Generations>>,
    /// `stores.proton.token_expires`, read once at bind time — see
    /// [`credential::run_expiry_advisory`] for why every `Op::Resolve` this
    /// daemon answers is checked against it rather than the CLI reading the
    /// same file. Config is read once at startup like every other value here,
    /// so a changed date takes effect on the next restart.
    token_expires: Option<String>,
}
impl Daemon {
    /// Create the socket and get ready to serve.
    ///
    /// The socket's mode is set explicitly after binding rather than left to the
    /// process umask, because a umask of `0` would otherwise produce a
    /// world-writable socket and nothing would say so.
    pub fn bind(config: &DaemonConfig, policy: Policy) -> io::Result<Self> {
        if let Some(parent) = config.socket.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
            // Best effort: on an install where the directory is already owned
            // by root this will fail, and that is fine — the installer set it.
            let _ =
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(SOCKET_DIR_MODE));
        }
        remove_stale_socket(&config.socket)?;

        let listener = UnixListener::bind(&config.socket)?;
        std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(SOCKET_MODE))?;
        listener.set_nonblocking(true)?;

        // Built here because both sides of it are this daemon's: the stores
        // that read through it, and the renewal loop that creates and retires
        // generations under it. The adapter owns the type and knows nothing of
        // the loop; the loop knows nothing of the stores.
        let generations = config.generations();

        // The declared half is fixed here; the derived half arrives from the
        // rebuilder below. Built before the registry because the adapters read
        // their undeclared addresses out of it.
        let catalogue = Arc::new(Catalogue::new(&config.secrets));
        let backends = config.backends(generations.as_ref(), Some(&catalogue));
        // Started, not asked. Nothing is enumerated until something asks a
        // question the declared set cannot answer — a miss, or a listing over a
        // daemon that has never built one. An enumeration at bind would spend a
        // vendor call, and a permanent off-machine audit entry, on every daemon
        // start whether or not anybody ever asks it anything.
        let rebuilder = Arc::new(Rebuilder::start(&catalogue, backends.sources));

        Ok(Daemon {
            listener,
            socket: config.socket.to_path_buf(),
            policy: Arc::new(policy),
            resolver: Arc::new(
                Resolver::new(backends.registry, config.ttl())
                    .with_stale_window(config.stale())
                    .with_silent_window(config.silent()),
            ),
            audit: Arc::new(
                AuditLog::new(config.audit.to_path_buf())
                    .with_mode(crate::audit::MODE_GROUP_READABLE),
            ),
            catalogue,
            rebuilder,
            rebuild_within: Duration::from_millis(config.stores.proton.timeout_ms),
            idle: config.idle_timeout(),
            live: Arc::new(AtomicUsize::new(0)),
            generations,
            token_expires: config.stores.proton.token_expires.clone(),
        })
    }

    /// Where it is listening.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The resolver, so `keylessd` and the tests can read its counters.
    #[must_use]
    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.resolver
    }
}

/// A stale socket file is removed; anything else at the path is not.
///
/// The distinction matters. Unlinking whatever happens to be at the socket path
/// would make a misconfigured `socket` field into a file-deletion primitive
/// running as the daemon's uid.
fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_socket() {
                std::fs::remove_file(path)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "{} exists and is not a socket; refusing to remove it",
                        path.display()
                    ),
                ))
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}
/// A daemon running on its own thread, stopped when this is dropped.
///
/// Exists for tests and for `keylessd --foreground`, so both drive the same
/// lifecycle rather than one of them having a bespoke loop that the other's
/// tests never exercise.
pub struct Running {
    stop: Arc<AtomicBool>,
    socket: PathBuf,
    resolver: Arc<Resolver>,
    thread: Option<thread::JoinHandle<()>>,
    /// The Proton session renewal loop, when this config asked for one.
    ///
    /// Held here rather than by `main` so its lifetime is the daemon's. See
    /// [`Running::spawn`].
    session: Option<self::session::Keeper>,
    /// The refresh workers that keep recently read names warm. Held here for
    /// the same reason: they are the daemon's, and dropping this stops them.
    refresher: Option<Refresher>,
}

/// Denials, rendered for an operator reading the daemon's own stderr.
///
/// Separate from the wire message on purpose: the wire tells the caller what to
/// do about it, this tells the operator what happened.
#[must_use]
pub fn describe_denial(denial: &Denial) -> String {
    format!("{} ({})", denial, denial.kind())
}
