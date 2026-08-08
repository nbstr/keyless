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

pub mod config;
pub mod resolver;

use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::attest::{Attestation, Denial, Policy, attest};
use crate::audit::{AuditLog, Event, Peer};
use crate::ipc::protocol::{Op, Reply, Request, read_frame, write_frame};
use crate::mask::Masker;
use crate::secret::Secret;
use crate::{NAME, State};

use self::config::DaemonConfig;
use self::resolver::{Outcome, Resolver};

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

/// How many connections may be in flight at once.
///
/// Above this the daemon answers and closes rather than queueing, so a runaway
/// client cannot make the daemon unresponsive to the other nineteen sessions.
const MAX_CONNECTIONS: usize = 64;

/// Longest name a client may ask for. Names go into audit rows, so an unbounded
/// one is a way to push a row over the atomic-write cap.
const MAX_NAME_CHARS: usize = 128;

/// How often the accept loop checks whether it has been told to stop.
const ACCEPT_POLL: Duration = Duration::from_millis(5);

/// A bound, listening daemon.
pub struct Daemon {
    listener: UnixListener,
    socket: PathBuf,
    policy: Arc<Policy>,
    resolver: Arc<Resolver>,
    audit: Arc<AuditLog>,
    names: Arc<Vec<String>>,
    idle: Duration,
    live: Arc<AtomicUsize>,
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

        Ok(Daemon {
            listener,
            socket: config.socket.to_path_buf(),
            policy: Arc::new(policy),
            resolver: Arc::new(Resolver::new(config.registry(), config.ttl())),
            audit: Arc::new(
                AuditLog::new(config.audit.to_path_buf())
                    .with_mode(crate::audit::MODE_GROUP_READABLE),
            ),
            names: Arc::new(config.names.clone()),
            idle: config.idle_timeout(),
            live: Arc::new(AtomicUsize::new(0)),
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

    /// Serve until `stop` is set.
    ///
    /// Non-blocking accept with a short poll rather than a blocking accept plus
    /// a self-pipe: this loop has one job and five milliseconds of latency on
    /// shutdown costs nothing, where a self-pipe would add a second descriptor
    /// and a second failure mode to the most security-sensitive loop in the
    /// program.
    pub fn serve_until(&self, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((stream, _)) => self.dispatch(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    // An accept that fails for any other reason is worth
                    // saying out loud, but is not worth stopping for: the next
                    // one usually works, and a daemon that exits takes the
                    // whole fleet degraded with it.
                    let _ = writeln!(io::stderr(), "{NAME}d: accept failed: {error}");
                    thread::sleep(ACCEPT_POLL);
                }
            }
        }
    }

    fn dispatch(&self, stream: UnixStream) {
        if self.live.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            // Answering is better than dropping: the client learns immediately
            // and degrades, rather than waiting out its whole timeout.
            let _ = write_frame(
                &mut &stream,
                &Reply::Failed("the daemon is at its connection limit".to_owned())
                    .encode()
                    .unwrap_or_default(),
            );
            return;
        }

        let worker = Connection {
            policy: Arc::clone(&self.policy),
            resolver: Arc::clone(&self.resolver),
            audit: Arc::clone(&self.audit),
            names: Arc::clone(&self.names),
            idle: self.idle,
            live: Arc::clone(&self.live),
        };
        self.live.fetch_add(1, Ordering::Relaxed);
        if thread::Builder::new()
            .name(format!("{NAME}d-conn"))
            .spawn(move || worker.serve(stream))
            .is_err()
        {
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
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

struct Connection {
    policy: Arc<Policy>,
    resolver: Arc<Resolver>,
    audit: Arc<AuditLog>,
    names: Arc<Vec<String>>,
    idle: Duration,
    live: Arc<AtomicUsize>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Connection {
    fn serve(self, stream: UnixStream) {
        // The listener is non-blocking so the accept loop can poll its stop
        // flag, and on BSD an accepted socket INHERITS that flag. Left set, the
        // first read that arrives a moment before its data returns EAGAIN, the
        // frame reader calls that a framing error, and the connection is torn
        // down under a client that did nothing wrong. It survives a single
        // request-and-reply — the request is usually already buffered by the
        // time accept returns — and fails the moment a client sends a second
        // one, which is why it has to be cleared here rather than trusted to
        // the timeouts below.
        if let Err(error) = stream.set_nonblocking(false) {
            let _ = writeln!(
                io::stderr(),
                "{NAME}d: cannot make the connection blocking: {error}"
            );
            return;
        }
        let _ = stream.set_read_timeout(Some(self.idle));
        let _ = stream.set_write_timeout(Some(self.idle));

        let mut reader = io::BufReader::new(match stream.try_clone() {
            Ok(clone) => clone,
            Err(_) => return,
        });

        loop {
            let frame = match read_frame(&mut reader) {
                Ok(Some(frame)) => frame,
                // A clean end of stream is the ordinary way a client leaves.
                Ok(None) => return,
                Err(error) => {
                    let _ = write_frame(
                        &mut &stream,
                        &Reply::Failed(error.to_string())
                            .encode()
                            .unwrap_or_default(),
                    );
                    return;
                }
            };

            let reply = self.answer(&stream, &frame);
            let encoded = match reply.encode() {
                Ok(encoded) => encoded,
                Err(_) => return,
            };
            if write_frame(&mut &stream, &encoded).is_err() {
                return;
            }
        }
    }

    /// Attest, then answer.
    ///
    /// Attestation happens here — per request — rather than once when the
    /// connection was accepted. A process can `exec` a different image without
    /// closing its sockets, so a per-connection decision would authorise a
    /// program that is no longer running.
    fn answer(&self, stream: &UnixStream, frame: &[u8]) -> Reply {
        let request = match Request::decode(frame) {
            Ok(request) => request,
            Err(error) => return Reply::Failed(error.to_string()),
        };

        let attestation = attest(stream.as_fd(), &self.policy);

        if let Some(denial) = &attestation.denial {
            self.record(&request, &attestation, denial.kind(), State::Degraded, None);
            return Reply::Denied(denial.to_string());
        }

        match request.op {
            Op::Ping => Reply::Info { names: Vec::new() },
            Op::Names => Reply::Info {
                names: self.names.as_ref().clone(),
            },
            Op::Resolve => self.resolve(&request, &attestation),
        }
    }

    fn resolve(&self, request: &Request, attestation: &Attestation) -> Reply {
        if request.name.is_empty() || request.name.chars().count() > MAX_NAME_CHARS {
            self.record(request, attestation, "bad-name", State::Degraded, None);
            return Reply::Failed(format!(
                "a name must be between 1 and {MAX_NAME_CHARS} characters"
            ));
        }

        match self.resolver.resolve(&request.name) {
            Outcome::Found(secret) => {
                self.record(
                    request,
                    attestation,
                    "allow",
                    State::Injected,
                    Some(secret.as_ref()),
                );
                // One more copy of the plaintext, which the reply owns and
                // zeroizes when it is dropped. The `Arc` in the cache keeps
                // the original.
                Reply::Value(Secret::new(secret.expose().to_owned()))
            }
            Outcome::Absent => {
                self.record(request, attestation, "absent", State::Degraded, None);
                Reply::Absent
            }
            Outcome::Failed(reason) => {
                self.record(request, attestation, "store-failed", State::Degraded, None);
                Reply::Failed(reason)
            }
        }
    }

    /// Write one audit row.
    ///
    /// `secret` is passed so the claimed argv can be masked with it: a caller
    /// that put the value on its own command line — the habit this tool
    /// replaces — must not have it copied into the daemon's log, which is the
    /// one log the caller cannot edit afterwards.
    fn record(
        &self,
        request: &Request,
        attestation: &Attestation,
        decision: &str,
        state: State,
        secret: Option<&Secret>,
    ) {
        let masker = match secret {
            Some(secret) => Masker::from_secrets([(request.name.as_str(), secret)]),
            None => Masker::new(),
        };

        let names = if request.name.is_empty() {
            Vec::new()
        } else {
            vec![request.name.clone()]
        };
        let unresolved = if state == State::Injected {
            Vec::new()
        } else {
            names.clone()
        };

        let mut event = Event::new("resolve", state, names, &request.argv, &masker)
            // The caller's claim, recorded as such. `cwd` on a daemon row is
            // the client's, not the daemon's — the daemon's own working
            // directory is `/` and would say nothing.
            .with_cwd(masker.mask_str(&request.cwd))
            .with_unresolved(unresolved)
            .with_decision(decision);

        if let Some(peer) = &attestation.peer {
            event = event.with_peer(Peer {
                uid: peer.uid,
                pid: peer.pid,
                generation: peer.generation,
                unique_id: peer.unique_id,
                code_hash: peer.code_hash_hex(),
                image: peer.image.display().to_string(),
            });
        }

        if let Err(error) = self.audit.append(&event) {
            // An unwritable audit log is serious and is still not a reason to
            // stop answering: the alternative is that a full disk takes the
            // whole fleet's secrets away.
            let _ = writeln!(io::stderr(), "{NAME}d: audit: {error}");
        }
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
}

impl Running {
    /// Start serving on a background thread.
    pub fn spawn(daemon: Daemon) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let socket = daemon.socket.clone();
        let resolver = Arc::clone(&daemon.resolver);
        let flag = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name(format!("{NAME}d-accept"))
            .spawn(move || daemon.serve_until(&flag))?;
        Ok(Running {
            stop,
            socket,
            resolver,
            thread: Some(thread),
        })
    }

    /// Where it is listening.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// How many times a store has actually been asked.
    #[must_use]
    pub fn upstream_calls(&self) -> u64 {
        self.resolver.upstream_calls()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Denials, rendered for an operator reading the daemon's own stderr.
///
/// Separate from the wire message on purpose: the wire tells the caller what to
/// do about it, this tells the operator what happened.
#[must_use]
pub fn describe_denial(denial: &Denial) -> String {
    format!("{} ({})", denial, denial.kind())
}

#[cfg(test)]
mod tests {
    use super::{Daemon, SOCKET_MODE, remove_stale_socket};
    use crate::attest::Policy;
    use crate::daemon::config::DaemonConfig;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-daemon-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn the_socket_is_group_writable_and_nothing_more() {
        // Connecting needs write, not read. A `0640` socket would be
        // unreachable by the very group it was created for, and a `0666` one
        // would let any user on the machine talk to the daemon.
        let dir = scratch("mode");
        let config = DaemonConfig {
            socket: dir.join("d.sock").into(),
            audit: dir.join("audit.jsonl").into(),
            ..DaemonConfig::default()
        };
        let daemon = Daemon::bind(&config, Policy::new()).expect("bind");
        let mode = std::fs::metadata(daemon.socket())
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, SOCKET_MODE, "mode was {mode:04o}");
        assert_eq!(mode & 0o007, 0, "other must not be able to connect");
        drop(daemon);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_socket_is_replaced() {
        let dir = scratch("stale");
        let config = DaemonConfig {
            socket: dir.join("d.sock").into(),
            audit: dir.join("audit.jsonl").into(),
            ..DaemonConfig::default()
        };
        let first = Daemon::bind(&config, Policy::new()).expect("first bind");
        drop(first);
        // The inode is still there; binding again must work.
        let second = Daemon::bind(&config, Policy::new()).expect("second bind over a stale socket");
        drop(second);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_regular_file_at_the_socket_path_is_refused_rather_than_deleted() {
        // Otherwise a mistyped `socket` field is a delete-any-file primitive
        // running as the daemon's uid.
        let dir = scratch("notasocket");
        let path = dir.join("important.txt");
        std::fs::write(&path, b"not a socket").expect("write");
        assert!(remove_stale_socket(&path).is_err());
        assert!(path.exists(), "the file must still be there");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
