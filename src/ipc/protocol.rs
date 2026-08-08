//! The wire between a session and the daemon.
//!
//! One JSON object per line, in each direction. Newline framing rather than a
//! length prefix because the whole conversation is one short request and one
//! short reply, and a format a person can read with `nc` is a format whose bugs
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
use zeroize::Zeroize;

use crate::secret::Secret;

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
}

impl Request {
    /// A resolve request for one name.
    #[must_use]
    pub fn resolve(name: &str) -> Self {
        Request {
            v: PROTOCOL_VERSION,
            op: Op::Resolve,
            name: name.to_owned(),
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            argv: std::env::args().take(MAX_CLAIMED_ARGS).collect(),
        }
    }

    /// A version and liveness check.
    #[must_use]
    pub fn ping() -> Self {
        Request {
            v: PROTOCOL_VERSION,
            op: Op::Ping,
            name: String::new(),
            cwd: String::new(),
            argv: Vec::new(),
        }
    }

    /// Serialize to one frame, newline included.
    ///
    /// Cannot fail in practice — every field is a plain string — but the error
    /// is returned rather than unwrapped, because this crate has no `expect` on
    /// a runtime path.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut line = serde_json::to_vec(self).map_err(io::Error::other)?;
        line.push(b'\n');
        Ok(line)
    }

    /// Parse one frame.
    pub fn decode(frame: &[u8]) -> Result<Self, ProtocolError> {
        let request: Request =
            serde_json::from_slice(frame).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
        if request.v != PROTOCOL_VERSION {
            return Err(ProtocolError::Version(request.v));
        }
        Ok(request)
    }
}

/// How many of the caller's own arguments to claim. A cap here rather than at
/// the daemon keeps a long command line off the wire entirely.
const MAX_CLAIMED_ARGS: usize = 32;

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
    /// The daemon could not answer. Carries a reason that never contains a
    /// value — it is built from a store's own error text, which this crate
    /// takes from stderr only.
    Failed(String),
    /// Answer to [`Op::Ping`] and [`Op::Names`].
    Info {
        /// Declared names. Empty for a ping.
        names: Vec<String>,
    },
}

/// The reply as it appears on the wire, minus the value.
///
/// Split out so the value never passes through a `Serialize` implementation: it
/// is spliced in by [`Reply::encode`], which owns the one buffer that holds it
/// and scrubs that buffer before returning.
#[derive(Serialize, Deserialize)]
struct WireReply {
    v: u32,
    status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    names: Vec<String>,
}

impl Reply {
    /// The wire status word.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        match self {
            Reply::Value(_) => "ok",
            Reply::Absent => "absent",
            Reply::Denied(_) => "denied",
            Reply::Failed(_) => "failed",
            Reply::Info { .. } => "info",
        }
    }

    /// Serialize to one frame, newline included.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut wire = WireReply {
            v: PROTOCOL_VERSION,
            status: self.status().to_owned(),
            value: None,
            reason: None,
            names: Vec::new(),
        };
        match self {
            Reply::Value(secret) => wire.value = Some(secret.expose().to_owned()),
            Reply::Denied(reason) | Reply::Failed(reason) => wire.reason = Some(reason.clone()),
            Reply::Info { names } => wire.names.clone_from(names),
            Reply::Absent => {}
        }
        let result = serde_json::to_vec(&wire).map_err(io::Error::other);
        // The plaintext copy this function made is scrubbed whatever happened,
        // including on the error path.
        if let Some(value) = wire.value.as_mut() {
            value.zeroize();
        }
        let mut line = result?;
        line.push(b'\n');
        Ok(line)
    }

    /// Parse one frame.
    ///
    /// `frame` is the caller's buffer and still holds the plaintext when this
    /// returns; scrubbing it is the caller's job, and every caller in this
    /// crate does it.
    pub fn decode(frame: &[u8]) -> Result<Self, ProtocolError> {
        let mut wire: WireReply =
            serde_json::from_slice(frame).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
        if wire.v != PROTOCOL_VERSION {
            return Err(ProtocolError::Version(wire.v));
        }
        let reply = match wire.status.as_str() {
            "ok" => match wire.value.take() {
                Some(value) => Reply::Value(Secret::new(value)),
                None => {
                    return Err(ProtocolError::Malformed(
                        "status ok carried no value".to_owned(),
                    ));
                }
            },
            "absent" => Reply::Absent,
            "denied" => Reply::Denied(wire.reason.take().unwrap_or_else(|| "refused".to_owned())),
            "failed" => Reply::Failed(wire.reason.take().unwrap_or_else(|| "failed".to_owned())),
            "info" => Reply::Info {
                names: std::mem::take(&mut wire.names),
            },
            other => {
                return Err(ProtocolError::Malformed(format!(
                    "unknown status `{other}`"
                )));
            }
        };
        Ok(reply)
    }
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
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{MAX_FRAME_BYTES, Op, ProtocolError, Reply, Request, read_frame};
    use crate::secret::Secret;
    use std::io::BufReader;

    #[test]
    fn a_request_round_trips() {
        let request = Request::resolve("DECOY_NAME");
        let frame = request.encode().expect("encode");
        assert_eq!(frame.last(), Some(&b'\n'));
        let parsed = Request::decode(&frame[..frame.len() - 1]).expect("decode");
        assert_eq!(parsed.op, Op::Resolve);
        assert_eq!(parsed.name, "DECOY_NAME");
    }

    #[test]
    fn a_value_round_trips_and_survives_json_escaping() {
        // Quotes, backslashes and a newline are exactly what a naive
        // hand-rolled encoder would corrupt or truncate.
        let awkward = "decoy\"with\\quotes\nand-a-newline-\u{e9}";
        let frame = Reply::Value(Secret::new(awkward.to_owned()))
            .encode()
            .expect("encode");
        match Reply::decode(&frame[..frame.len() - 1]).expect("decode") {
            Reply::Value(secret) => assert_eq!(secret.expose(), awkward),
            other => panic!("expected a value, got {other:?}"),
        }
    }

    #[test]
    fn a_reply_debug_never_prints_the_value() {
        let reply = Reply::Value(Secret::new("decoy-must-not-appear-9911".to_owned()));
        let rendered = format!("{reply:?}");
        assert!(
            !rendered.contains("9911"),
            "the value reached a Debug: {rendered}"
        );
    }

    #[test]
    fn a_denial_reason_round_trips() {
        let frame = Reply::Denied("unknown-image".to_owned())
            .encode()
            .expect("encode");
        match Reply::decode(&frame[..frame.len() - 1]).expect("decode") {
            Reply::Denied(reason) => assert_eq!(reason, "unknown-image"),
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn a_version_mismatch_is_refused_rather_than_guessed() {
        let raw = br#"{"v":99,"op":"resolve","name":"X"}"#;
        assert!(matches!(
            Request::decode(raw),
            Err(ProtocolError::Version(99))
        ));
        let raw = br#"{"v":99,"status":"ok","value":"decoy"}"#;
        assert!(matches!(
            Reply::decode(raw),
            Err(ProtocolError::Version(99))
        ));
    }

    #[test]
    fn an_ok_reply_with_no_value_is_malformed_rather_than_empty() {
        let raw = br#"{"v":1,"status":"ok"}"#;
        assert!(matches!(
            Reply::decode(raw),
            Err(ProtocolError::Malformed(_))
        ));
    }

    #[test]
    fn frames_split_at_newlines() {
        let stream: &[u8] = b"{\"a\":1}\n{\"b\":2}\n";
        let mut reader = BufReader::new(stream);
        assert_eq!(
            read_frame(&mut reader).expect("first"),
            Some(b"{\"a\":1}".to_vec())
        );
        assert_eq!(
            read_frame(&mut reader).expect("second"),
            Some(b"{\"b\":2}".to_vec())
        );
        assert_eq!(read_frame(&mut reader).expect("eof"), None);
    }

    #[test]
    fn a_frame_that_never_ends_is_refused_at_the_cap() {
        let huge = vec![b'x'; MAX_FRAME_BYTES + 64];
        let mut reader = BufReader::new(huge.as_slice());
        assert!(matches!(
            read_frame(&mut reader),
            Err(ProtocolError::Framing(_))
        ));
    }

    #[test]
    fn a_stream_that_stops_mid_frame_is_an_error_not_a_short_message() {
        let mut reader = BufReader::new(&b"{\"partial\":"[..]);
        assert!(matches!(
            read_frame(&mut reader),
            Err(ProtocolError::Framing(_))
        ));
    }
}
