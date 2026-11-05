mod record;

use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::attest::{Attestation, Policy, attest};
use crate::audit::AuditLog;
use crate::ipc::protocol::{Op, Reply, Request, read_frame, write_frame};
use crate::secret::Secret;
use crate::store::catalogue::{Catalogue, Rebuilder, Rebuilt, Route};
use crate::{NAME, State};

use self::record::{Decision, Served};
use super::credential;
use super::heartbeat::Heartbeat;
use super::resolver::{Answer, FailureKind, Outcome, Resolver};

/// Longest name a client may ask for. Names go into audit rows, so an unbounded
/// one is a way to push a row over the atomic-write cap.
const MAX_NAME_CHARS: usize = 128;
pub(super) struct Connection {
    pub(super) policy: Arc<Policy>,
    pub(super) resolver: Arc<Resolver>,
    pub(super) audit: Arc<AuditLog>,
    pub(super) catalogue: Arc<Catalogue>,
    pub(super) rebuilder: Arc<Rebuilder>,
    pub(super) rebuild_within: Duration,
    pub(super) idle: Duration,
    pub(super) live: Arc<AtomicUsize>,
    /// See [`Daemon::token_expires`].
    pub(super) token_expires: Option<String>,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Connection {
    /// `first_attestation` is the peer's identity as read at accept time, by
    /// the caller — see [`Daemon::dispatch`] for why that reading is not
    /// redone here for the connection's first request. Every request after it
    /// re-attests fresh, in the loop below.
    pub(super) fn serve(self, stream: UnixStream, first_attestation: Attestation) {
        // The listener is non-blocking so the accept loop can poll its stop
        // flag, and on BSD an accepted socket INHERITS that flag. Left set, the
        // first read that arrives a moment before its data returns EAGAIN, the
        // frame reader takes that for a read deadline passing, and the
        // connection is torn down under a client that did nothing wrong. It survives a single
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

        let mut attestation = Some(first_attestation);
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

            // The first iteration spends the accept-time reading; every one
            // after it attests fresh. A process can `exec` a different image
            // without closing its sockets, so trusting the first reading for a
            // second request would authorise a program that is no longer
            // running.
            let this_attestation = attestation
                .take()
                .unwrap_or_else(|| attest(stream.as_fd(), &self.policy));

            let request = match Request::decode(&frame) {
                Ok(request) => request,
                Err(error) => {
                    let _ = write_frame(
                        &mut &stream,
                        &Reply::Failed(error.to_string())
                            .encode()
                            .unwrap_or_default(),
                    );
                    continue;
                }
            };

            // Taken here, before anything is decided about the request, and
            // held until the reply exists — see [`Heartbeat`] for why the
            // guard lives on this thread for the whole request rather than
            // around whichever step is slow today.
            let heartbeat = request
                .progress
                .then(|| Heartbeat::start(&stream))
                .flatten();
            let (reply, advisory) = self.answer(&request, &this_attestation);
            let encoded = match reply.encode_with_advisory(advisory.as_deref()) {
                Ok(encoded) => encoded,
                Err(_) => return,
            };
            // The join is the handover between the two writers: the beat
            // thread writes only whole frames, and it has written its last
            // before the reply frame starts, so the bytes never interleave.
            drop(heartbeat);
            if write_frame(&mut &stream, &encoded).is_err() {
                return;
            }
        }
    }

    /// Answer one request against an already-attested peer — see
    /// [`Daemon::dispatch`] and the loop in [`Connection::serve`] for when
    /// that attestation was read.
    ///
    /// The advisory alongside the reply is `Some` only down the [`Op::Resolve`]
    /// path — every `keyless run` request, and no other verb — see
    /// [`credential::run_expiry_advisory`].
    fn answer(&self, request: &Request, attestation: &Attestation) -> (Reply, Option<String>) {
        if let Some(denial) = attestation.denial() {
            let detail = denial.to_string();
            self.record(
                request,
                attestation,
                Decision::with_reason(denial.kind(), &detail),
                State::Refused,
                None,
                None,
            );
            return (Reply::Denied(detail), None);
        }

        match request.op {
            Op::Ping => (Reply::Info { names: Vec::new() }, None),
            Op::Names => {
                // A listing over a daemon that has never enumerated answers the
                // declared set and asks for the rest. The asker gets today's
                // answer immediately rather than waiting on a vault, and the
                // next listing is complete — which is the same demand-driven
                // shape a miss takes, for the same reason: nothing here runs on
                // a clock.
                if self.catalogue.indexed_at().is_none() {
                    self.rebuilder.queue_full();
                }
                (
                    Reply::Info {
                        names: self.catalogue.names(),
                    },
                    None,
                )
            }
            Op::Resolve => self.resolve(request, attestation),
        }
    }

    fn resolve(&self, request: &Request, attestation: &Attestation) -> (Reply, Option<String>) {
        let advisory = credential::run_expiry_advisory(self.token_expires.as_deref());

        if request.name.is_empty() || request.name.chars().count() > MAX_NAME_CHARS {
            self.record(
                request,
                attestation,
                Decision::new("bad-name"),
                State::Refused,
                None,
                None,
            );
            return (
                Reply::Refused(format!(
                    "a name must be between 1 and {MAX_NAME_CHARS} characters"
                )),
                advisory,
            );
        }

        let answer = self.resolve_rebuilding(&request.name);
        let served = Some(Served {
            source: answer.source,
            age: answer.age,
        });

        let (decision, state, reply) = match answer.outcome {
            Outcome::Found(secret) => {
                self.record(
                    request,
                    attestation,
                    Decision::new("allow"),
                    State::Injected,
                    Some(secret.as_ref()),
                    served,
                );
                // One more copy of the plaintext, which the reply owns and
                // zeroizes when it is dropped. The `Arc` in the cache keeps
                // the original.
                return (
                    Reply::Value(Secret::new(secret.expose().to_owned())),
                    advisory,
                );
            }
            Outcome::Absent => (
                Decision::new("absent"),
                State::Refused,
                self.absence(&request.name),
            ),
            Outcome::Failed { reason, kind } => (
                Decision::new(kind.as_str()),
                State::Degraded,
                Reply::Failed(format!("{reason}; {}", self.advice(&request.name))),
            ),
        };
        self.record(request, attestation, decision, state, None, served);
        (reply, advisory)
    }

    fn advice(&self, name: &str) -> String {
        self.catalogue.advice(name, &self.catalogue.route(name))
    }

    fn absence(&self, name: &str) -> Reply {
        match self.catalogue.suggestion(name, &self.catalogue.route(name)) {
            Some(suggestion) => {
                Reply::Refused(format!("its store holds no such name; {suggestion}"))
            }
            None => Reply::Absent,
        }
    }

    /// Resolve `name`, and when its store answered that it does not hold a
    /// name the catalogue does not route, rebuild the catalogue and resolve
    /// once more before answering.
    ///
    /// # Why the catalogue is consulted AFTER the resolve and never before it
    ///
    /// Two reasons, and the second is the one that bites. A resolve that
    /// produces a value must not gain a lock or a lookup it did not have, so
    /// the catalogue is off the happy path entirely.
    ///
    /// And the catalogue must not GATE a request. The keychain store defaults
    /// its account to the name itself and the file store keys on the name, so
    /// both serve names that appear in no `secrets` entry and in no index. A
    /// gate would turn every one of those into a miss — the tool would stop
    /// serving names it serves today, and the index would look correct while
    /// doing it.
    ///
    /// # Why only an absence rebuilds, and a silent rebuild is silence
    ///
    /// A store in silence, or one that failed, said nothing about the name, so
    /// there is nothing for a fresher index to correct. And a rebuild that
    /// gives no verdict leaves the name's existence unknown: answering with
    /// the first resolve's "no such name" would turn a store's silence into a
    /// name it does not hold.
    fn resolve_rebuilding(&self, name: &str) -> Answer {
        let answer = self.resolver.resolve(name);
        if !matches!(answer.outcome, Outcome::Absent)
            || !matches!(self.catalogue.route(name), Route::Unknown { .. })
        {
            return answer;
        }
        match self.rebuilder.rebuild_for(name, self.rebuild_within) {
            Rebuilt::Current if matches!(self.catalogue.route(name), Route::Known(_)) => {
                self.resolver.resolve(name)
            }
            Rebuilt::Current => answer,
            Rebuilt::Silent => Answer {
                outcome: Outcome::Failed {
                    reason: "the store gave no verdict on the catalogue rebuild this name needed"
                        .to_owned(),
                    kind: FailureKind::Silent,
                },
                source: answer.source,
                age: answer.age,
            },
        }
    }
}
