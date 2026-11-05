//! Encoding and decoding the daemon's answer, with the value spliced in by hand.

use std::io;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{PROTOCOL_VERSION, ProtocolError, Reply};
use crate::secret::Secret;

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
    /// An operational notice riding alongside this reply, independent of its
    /// own status — see [`Reply::encode_with_advisory`]. Never a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    advisory: Option<String>,
}

impl Reply {
    /// The wire status word.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        match self {
            Reply::Value(_) => "ok",
            Reply::Absent => "absent",
            Reply::Denied(_) => "denied",
            Reply::Refused(_) => "refused",
            Reply::Failed(_) => "failed",
            Reply::Info { .. } => "info",
            Reply::Working => "working",
        }
    }

    /// Serialize to one frame, newline included.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        self.encode_with_advisory(None)
    }

    /// Serialize to one frame, carrying an operational notice alongside it.
    ///
    /// The advisory is not part of the reply's own status — a value can
    /// resolve, or fail to, independently of whether something else about the
    /// daemon is worth saying — so it rides in its own wire field rather than
    /// becoming a fifth thing every `Reply` variant would have to carry.
    /// [`crate::daemon::credential::run_expiry_advisory`] is the one producer
    /// today; a caller with nothing to add passes `None`, which serialises to
    /// nothing on the wire and costs an unread build older than this field
    /// nothing at all.
    pub fn encode_with_advisory(&self, advisory: Option<&str>) -> io::Result<Vec<u8>> {
        let mut wire = WireReply {
            v: PROTOCOL_VERSION,
            status: self.status().to_owned(),
            value: None,
            reason: None,
            names: Vec::new(),
            advisory: advisory.map(str::to_owned),
        };
        match self {
            Reply::Value(secret) => wire.value = Some(secret.expose().to_owned()),
            Reply::Denied(reason) | Reply::Refused(reason) | Reply::Failed(reason) => {
                wire.reason = Some(reason.clone());
            }
            Reply::Info { names } => wire.names.clone_from(names),
            Reply::Absent | Reply::Working => {}
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
            "refused" => Reply::Refused(wire.reason.take().unwrap_or_else(|| "refused".to_owned())),
            "failed" => Reply::Failed(wire.reason.take().unwrap_or_else(|| "failed".to_owned())),
            "info" => Reply::Info {
                names: std::mem::take(&mut wire.names),
            },
            "working" => Reply::Working,
            other => {
                return Err(ProtocolError::Malformed(format!(
                    "unknown status `{other}`"
                )));
            }
        };
        Ok(reply)
    }
}
