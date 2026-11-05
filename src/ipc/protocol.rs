//! The wire between a session and the daemon.
//!
//! One JSON object per line, in each direction. Newline framing rather than a
//! length prefix because the whole conversation is one short request and one
//! short reply — with, for a resolve that asks for them, bare heartbeat lines
//! in between — and a format a person can read with `nc` is a format whose bugs
//! are visible.
//!
//! # What crosses, and what never does
//!
//! **Crosses:** a name, and — on success — the value bound to that name.
//!
//! **Never crosses:** the store credential. The keychain the daemon reads, the
//! token it authenticates to a remote vault with, the file it decrypts — those
//! live on the daemon's side of the uid boundary and have no representation in
//! this protocol. That is the whole point of the boundary: a session that
//! compromises the client learns the values it asked for, and still cannot
//! enumerate the store or read anything it did not name.
//!
//! # The reply type has no `Serialize`
//!
//! [`Reply::Value`] holds a [`Secret`], which deliberately implements neither
//! `Serialize` nor `Display`. So a reply cannot be written anywhere by
//! accident — the only way to put a value on the wire is [`Reply::encode`],
//! which is one function, and which zeroizes its own intermediate buffer.

use std::io::{self, BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

mod reply;
mod request;

#[cfg(test)]
mod advisory_tests;
#[cfg(test)]
mod frame_tests;
#[cfg(test)]
mod reply_tests;
#[cfg(test)]
mod request_tests;

/// Wire version. A daemon and a client that disagree refuse each other rather
/// than guessing, because a guess here is a guess about a credential.
pub const PROTOCOL_VERSION: u32 = 1;

/// Hard cap on one frame in either direction.
///
/// A client that streams megabytes at the daemon must not be able to make it
/// allocate without bound, and a rogue daemon must not be able to do the same
/// to a client. 64 KiB is far above any credential and far below a problem.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// What a client is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    /// Bind one name to its value.
    Resolve,
    /// Liveness and version check. Reads no secret and touches no store.
    Ping,
    /// The declared names. Names only — this is `ls` over the socket, and it
    /// is as incapable of returning a value as `ls` is.
    Names,
}

/// One request.
///
/// `cwd` and `argv` are **claims**. The daemon cannot verify either — a process
/// can rewrite its own argv — so they are recorded in the audit log under names
/// that say so and are never used for a decision. They are there because an
/// audit row that says only "pid 4412 asked for GITHUB_TOKEN" is much less
/// useful during an incident than one that also says what the caller said it
/// was doing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Protocol version.
    pub v: u32,
    /// What to do.
    pub op: Op,
    /// The name, for [`Op::Resolve`].
    #[serde(default)]
    pub name: String,
    /// The caller's claimed working directory.
    #[serde(default)]
    pub cwd: String,
    /// The caller's claimed command line.
    #[serde(default)]
    pub argv: Vec<String>,
    /// Whether this client understands [`Reply::Working`].
    ///
    /// # Why a field rather than the version number
    ///
    /// A daemon and a client are two binaries installed by one script, and
    /// between one run of it and the next they can differ. Bumping
    /// [`PROTOCOL_VERSION`] to introduce a heartbeat would make every such pair
    /// refuse each other outright — a total outage in exchange for a frame that
    /// carries no value and that either side can do without.
    ///
    /// So the capability is negotiated in the one direction that needs it. A
    /// client that says nothing gets no heartbeats and behaves exactly as it
    /// did, because `serde` defaults this to false; a daemon that has never
    /// heard of the field ignores it and answers as it always has. Neither end
    /// has to know the other's build.
    #[serde(default)]
    pub progress: bool,
}

/// What the daemon answers.
///
/// `Debug` is derived and is safe: [`Secret`]'s own `Debug` prints
/// `Secret(<redacted>)`, so a `{:?}` of a reply carrying a value prints the
/// shape and not the value.
#[derive(Debug)]
pub enum Reply {
    /// The name resolved.
    Value(Secret),
    /// Every store was healthy and none had it.
    Absent,
    /// The caller was not authorised. Carries a short, fixed reason.
    Denied(String),
    /// The request names nothing a store could be asked for — an empty or
    /// over-long name. Nothing was looked up, and no lookup would help, so the
    /// caller should not start its child. Carries the rule the name broke.
    Refused(String),
    /// The daemon could not answer. Carries a reason that never contains a
    /// value — it is built from a store's own error text, which this crate
    /// takes from stderr only.
    Failed(String),
    /// Answer to [`Op::Ping`] and [`Op::Names`].
    Info {
        /// Every name the daemon will serve — what an operator declared, and
        /// whatever its enumerable stores mint. Empty for a ping.
        ///
        /// Names, and never the coordinates behind them: a client may learn
        /// what this daemon will SERVE and must never learn what a store
        /// HOLDS. See [`crate::store::catalogue::Catalogue::names`].
        names: Vec<String>,
    },
    /// The daemon has the request and has not finished it yet.
    ///
    /// # What this exists to make decidable
    ///
    /// A client waiting on a socket cannot tell a daemon that is working from
    /// one that is wedged, and both look like silence. Without a signal the only
    /// way to choose between them is a number — how long a lookup "should" take
    /// — held by the side that does not do the work. That number was three
    /// seconds while the daemon was allowed ten per vendor call and spent up to
    /// two calls on a cold lookup, so a name that resolved correctly in 4.4
    /// seconds reached a caller that had already given up and degraded.
    ///
    /// Sent every [`crate::daemon::HEARTBEAT`] while a resolve is in flight, so
    /// the client's deadline can be on SILENCE rather than on completion. That
    /// is HTTP/2's answer too, and gRPC states the same split: its keepalive
    /// timeout is "the timeout in milliseconds for a PING frame to be
    /// acknowledged", never a bound on how long the call may take
    /// (<https://grpc.io/docs/guides/keepalive/>).
    ///
    /// It carries nothing. An elapsed time or a progress fraction would be a
    /// second thing to keep true, and no client decision needs one: the frame's
    /// arrival is the whole message.
    Working,
}

/// The advisory riding alongside a reply frame, if this daemon attached one.
///
/// Split from [`Reply::decode`] rather than folded into it, so every existing
/// reader of a decoded [`Reply`] — which is most of them, and none of which
/// asked for this — keeps matching on the same four or five variants it
/// always has. A frame carrying no `advisory` field, including every one a
/// build that predates this function ever sent, decodes to `None` here the
/// same way [`Request::progress`] decodes to `false` for a client that never
/// heard of it.
#[must_use]
pub fn decode_advisory(frame: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Peek {
        #[serde(default)]
        advisory: Option<String>,
    }
    serde_json::from_slice::<Peek>(frame)
        .ok()
        .and_then(|peek| peek.advisory)
}

/// The wire was not understood.
#[derive(Debug)]
pub enum ProtocolError {
    /// The frame is not a JSON object of the expected shape.
    Malformed(String),
    /// The peer speaks a different version.
    Version(u32),
    /// A frame exceeded [`MAX_FRAME_BYTES`] or the connection ended mid-frame.
    Framing(String),
    /// The read deadline on this socket passed with the peer saying nothing.
    ///
    /// Kept apart from [`ProtocolError::Framing`] because the two send a reader
    /// to opposite places. A framing error means the bytes were wrong and the
    /// bug is in one of the two builds; this means there were no bytes yet, and
    /// the question is whether the peer is slow or gone. Folded together, a
    /// deadline arrived as `framing error: Resource temporarily unavailable` —
    /// the errno for "nothing to read", rendered as a corruption report.
    Silent,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::Malformed(detail) => write!(f, "malformed message: {detail}"),
            ProtocolError::Version(v) => write!(
                f,
                "peer speaks protocol version {v}, this build speaks {PROTOCOL_VERSION}"
            ),
            ProtocolError::Framing(detail) => write!(f, "framing error: {detail}"),
            ProtocolError::Silent => f.write_str("the peer said nothing before the deadline"),
        }
    }
}

/// Whether an io error is a read deadline passing rather than a broken stream.
///
/// Both kinds, because `std` does not promise which one a platform uses:
/// `UnixStream::set_read_timeout` documents that Unix typically answers
/// `WouldBlock` (`EAGAIN`) and that other platforms may answer `TimedOut`.
fn is_deadline(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

impl std::error::Error for ProtocolError {}

/// Read one newline-terminated frame, capped at [`MAX_FRAME_BYTES`].
///
/// Returns `Ok(None)` at a clean end of stream. A frame that reaches the cap
/// without a newline is an error rather than a truncated parse, so an
/// overlong line can never be silently interpreted as a shorter valid one.
pub fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut frame = Vec::with_capacity(256);
    loop {
        let available = match reader.fill_buf() {
            Ok(buf) => buf,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if is_deadline(&error) => return Err(ProtocolError::Silent),
            Err(error) => return Err(ProtocolError::Framing(error.to_string())),
        };
        if available.is_empty() {
            if frame.is_empty() {
                return Ok(None);
            }
            return Err(ProtocolError::Framing(
                "stream ended in the middle of a message".to_owned(),
            ));
        }
        match available.iter().position(|b| *b == b'\n') {
            Some(index) => {
                if frame.len() + index > MAX_FRAME_BYTES {
                    return Err(ProtocolError::Framing(format!(
                        "message exceeds {MAX_FRAME_BYTES} bytes"
                    )));
                }
                frame.extend_from_slice(&available[..index]);
                reader.consume(index + 1);
                return Ok(Some(frame));
            }
            None => {
                let taken = available.len();
                if frame.len() + taken > MAX_FRAME_BYTES {
                    return Err(ProtocolError::Framing(format!(
                        "message exceeds {MAX_FRAME_BYTES} bytes"
                    )));
                }
                frame.extend_from_slice(available);
                reader.consume(taken);
            }
        }
    }
}

/// Write one frame and flush it.
pub fn write_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    writer.write_all(frame)?;
    writer.flush()
}
