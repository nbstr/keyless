use std::io::{self, Write};
use std::time::Duration;

use crate::attest::Attestation;
use crate::audit::{Event, Peer};
use crate::ipc::protocol::Request;
use crate::mask::Masker;
use crate::secret::Secret;
use crate::{NAME, State};

use super::Connection;
use crate::daemon::resolver::Source;

/// Where a resolved value came from, for [`Daemon::record`] — [`resolver::Answer`]'s
/// `source` and `age` carried together, since neither reaches a row without
/// the other and a call that has one always has both.
pub(super) struct Served {
    pub(super) source: Source,
    pub(super) age: Option<Duration>,
}

/// What was decided about a request, and why — [`Daemon::record`]'s fixed
/// grep-able word and, where one exists, the free-text detail beside it.
pub(super) struct Decision<'a> {
    word: &'a str,
    reason: Option<&'a str>,
}

impl<'a> Decision<'a> {
    pub(super) fn new(word: &'a str) -> Self {
        Decision { word, reason: None }
    }

    pub(super) fn with_reason(word: &'a str, reason: &'a str) -> Self {
        Decision {
            word,
            reason: Some(reason),
        }
    }
}
impl Connection {
    /// Write one audit row.
    ///
    /// `secret` is passed so the claimed argv can be masked with it: a caller
    /// that put the value on its own command line — the habit this tool
    /// replaces — must not have it copied into the daemon's log, which is the
    /// one log the caller cannot edit afterwards.
    ///
    /// `served` is `None` on a row that never asked the resolver at all — an
    /// attestation denial, a malformed name — and `Some` on every row that
    /// did, whatever it decided. A `Some` row naming [`Source::Stale`] is the
    /// fact [`Source::as_str`] exists for: the value this row
    /// served was not read from the vendor a moment ago, and its `age` says
    /// how long ago it was.
    pub(super) fn record(
        &self,
        request: &Request,
        attestation: &Attestation,
        decision: Decision<'_>,
        state: State,
        secret: Option<&Secret>,
        served: Option<Served>,
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
            .with_decision(decision.word);

        if let Some(reason) = decision.reason {
            event = event.with_reason(reason);
        }

        if let Some(served) = served {
            event = event.with_source(served.source.as_str());
            if let Some(age) = served.age {
                event = event.with_age(age);
            }
        }

        if let Some(peer) = attestation.peer() {
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
