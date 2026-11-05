//! Building, encoding and decoding the one frame a client sends.

use std::io;

use super::{Op, PROTOCOL_VERSION, ProtocolError, Request};

impl Request {
    /// A resolve request for one name.
    ///
    /// Asks for heartbeats, which [`crate::ipc::client::Client`] waits out. A
    /// reader that takes exactly one frame per request clears
    /// [`Request::progress`] first, or it reads a heartbeat where it expected
    /// the answer.
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
            progress: true,
        }
    }

    /// A version and liveness check.
    ///
    /// Asks for no heartbeat: this reads no store, so there is nothing it could
    /// be slow about, and a ping that needed one would be measuring the wrong
    /// thing.
    #[must_use]
    pub fn ping() -> Self {
        Request {
            v: PROTOCOL_VERSION,
            op: Op::Ping,
            name: String::new(),
            cwd: String::new(),
            argv: Vec::new(),
            progress: false,
        }
    }

    /// Ask what the daemon will serve.
    ///
    /// Names only — this is `ls` over the socket, and [`Op::Names`] is as
    /// incapable of returning a value as `ls` is.
    ///
    /// # Why this constructor did not exist until now
    ///
    /// The daemon has answered [`Op::Names`] since the verb was added, and
    /// nothing in this crate ever sent one: the handler was reachable only by a
    /// hand-written frame. So `keyless ls` on a machine whose secrets live
    /// behind the daemon printed an EMPTY listing — the one case where the
    /// listing is the only way to find out what is available at all.
    ///
    /// Asks for no heartbeat, for [`Request::ping`]'s reason: this reads no
    /// store and cannot be slow about it.
    #[must_use]
    pub fn names() -> Self {
        Request {
            v: PROTOCOL_VERSION,
            op: Op::Names,
            name: String::new(),
            cwd: String::new(),
            argv: Vec::new(),
            progress: false,
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
