//! Talking to the daemon, with a deadline that cannot be missed.
//!
//! # Why the whole exchange runs on a thread
//!
//! `UnixStream` can be given a read and a write timeout. It cannot be given a
//! **connect** timeout — `std` has no `connect_timeout` for the unix domain —
//! and a connect to a socket whose listener is wedged with a full backlog
//! blocks indefinitely. A tool that must never stop a command from running
//! cannot contain an unbounded wait.
//!
//! So the connect, the write and the read all happen on a worker thread, and
//! the caller waits on a channel with a deadline. When the deadline passes the
//! caller gives up and reports the daemon unavailable; the worker finishes
//! whenever the kernel lets it and drops everything it holds. One orphan thread
//! per timed-out name, each of which ends on its own — the alternative is a
//! non-blocking connect written in `unsafe`, and this boundary already carries
//! all the `unsafe` it needs.
//!
//! # Scrubbing
//!
//! The reply frame holds a plaintext value. It is read into a buffer this
//! module owns and zeroizes, rather than into a `BufReader` whose internal
//! buffer is private and would keep a copy for the life of the read. What
//! cannot be scrubbed is the copy the kernel held in the socket buffer, which
//! belongs to the kernel.

use std::io::{self, BufRead, Read};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use zeroize::Zeroize;

use crate::ipc::protocol::{ProtocolError, Reply, Request, read_frame, write_frame};

/// A configured route to a daemon.
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
    timeout: Duration,
}

/// Why a request did not produce a reply.
///
/// Every variant means the same thing to `run`: no value, so degrade. They are
/// kept apart because `doctor` and the audit log should be able to say whether
/// the daemon is absent, slow, or answering nonsense.
#[derive(Debug)]
pub enum ClientError {
    /// The socket could not be reached: absent, not a socket, wrong
    /// permissions, or nothing listening.
    Unreachable(io::Error),
    /// The deadline passed with no reply.
    Timeout(Duration),
    /// The connection failed mid-exchange.
    Transport(io::Error),
    /// The daemon answered something this build does not understand.
    Protocol(ProtocolError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Unreachable(source) => write!(f, "cannot reach the daemon: {source}"),
            ClientError::Timeout(after) => {
                write!(f, "the daemon did not answer within {after:?}")
            }
            ClientError::Transport(source) => write!(f, "the connection failed: {source}"),
            ClientError::Protocol(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl Client {
    /// Point at a socket, with a deadline for the whole exchange.
    #[must_use]
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Client { socket, timeout }
    }

    /// The socket this client talks to.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Send one request and wait for one reply, or give up.
    pub fn request(&self, request: &Request) -> Result<Reply, ClientError> {
        let frame = request.encode().map_err(ClientError::Transport)?;
        let socket = self.socket.clone();
        let timeout = self.timeout;
        let (sender, receiver) = mpsc::channel();

        thread::Builder::new()
            .name(format!("{}-ipc", crate::NAME))
            .spawn(move || {
                // A send failure means the caller already gave up; the reply is
                // dropped, which zeroizes the value it carried.
                let _ = sender.send(exchange(&socket, &frame, timeout));
            })
            .map_err(ClientError::Transport)?;

        match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ClientError::Timeout(timeout)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ClientError::Transport(
                io::Error::other("the request thread ended without answering"),
            )),
        }
    }
}

fn exchange(socket: &Path, frame: &[u8], timeout: Duration) -> Result<Reply, ClientError> {
    let stream = UnixStream::connect(socket).map_err(ClientError::Unreachable)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(ClientError::Transport)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(ClientError::Transport)?;

    write_frame(&mut &stream, frame).map_err(ClientError::Transport)?;

    let mut reader = ScrubbedReader::new(&stream);
    let raw = read_frame(&mut reader).map_err(ClientError::Protocol)?;
    let Some(mut raw) = raw else {
        return Err(ClientError::Transport(io::Error::other(
            "the daemon closed the connection without answering",
        )));
    };
    let reply = Reply::decode(&raw).map_err(ClientError::Protocol);
    raw.zeroize();
    reply
}

/// A `BufRead` whose buffer is scrubbed when it is dropped.
///
/// `std::io::BufReader` would do the buffering, and would also keep the
/// plaintext in a `Vec` this crate cannot reach. Forty lines is a small price
/// for the difference between "the value is gone" and "the value is somewhere
/// on the heap until the allocator reuses the page".
struct ScrubbedReader<R: Read> {
    inner: R,
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl<R: Read> ScrubbedReader<R> {
    fn new(inner: R) -> Self {
        ScrubbedReader {
            inner,
            buf: vec![0; 8 * 1024],
            start: 0,
            end: 0,
        }
    }
}

impl<R: Read> Read for ScrubbedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let taken = available.len().min(out.len());
        out[..taken].copy_from_slice(&available[..taken]);
        self.consume(taken);
        Ok(taken)
    }
}

impl<R: Read> BufRead for ScrubbedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.start == self.end {
            self.start = 0;
            self.end = self.inner.read(&mut self.buf)?;
        }
        Ok(&self.buf[self.start..self.end])
    }

    fn consume(&mut self, amount: usize) {
        self.start = (self.start + amount).min(self.end);
    }
}

impl<R: Read> Drop for ScrubbedReader<R> {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, ClientError, ScrubbedReader};
    use crate::ipc::protocol::Request;
    use std::io::BufRead;
    use std::time::Duration;

    // Both cases below name a socket, so neither may name one under `TMPDIR`.
    // `connect(2)` refuses an over-long path with the SAME `InvalidInput` these
    // tests expect for their own reasons, so under a long `TMPDIR` they pass
    // without ever reaching the absent socket or the regular file — green, and
    // measuring the length of a directory name. Read the file for the numbers.
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/short_socket.rs"
    ));

    /// The deadline both cases below hand the client.
    ///
    /// # It is a CEILING, and reading it as a subject is what broke
    ///
    /// Neither case asserts anything about elapsed time; both assert the error
    /// VARIANT. That is what makes this number load-bearing, because
    /// [`Client::request`] bounds a THREAD SPAWN and a channel round trip with
    /// the same value it uses for the socket. An absent socket answers
    /// `Unreachable` only if the worker is scheduled and replies before the
    /// deadline — so a machine busy enough to delay the spawn turns the answer
    /// into `Timeout`, and a case named for `Unreachable` goes red having found
    /// nothing whatever wrong with the code.
    ///
    /// That work — spawn, failing connect, channel send — is timed rather than
    /// guessed at: it costs a small fraction of a millisecond on an idle
    /// machine, and stays in the low tens of milliseconds with CPU spinners and
    /// fork-storms saturating every core. Orders of magnitude under any bound
    /// worth writing here. So CPU contention alone does not explain a red; what
    /// does is CRITICAL MEMORY pressure, a regime spinners do not reproduce and
    /// one nobody should reproduce deliberately on a shared machine.
    ///
    /// Twenty seconds is the floor `tests/suite_hygiene.rs` sets for a ceiling on
    /// work that must answer. It is still a bound, which is the half the name
    /// promises: a genuine hang here reds in twenty seconds rather than never.
    ///
    /// **The race is not removed, only made unloseable.** Removing it needs
    /// `request` to report a connect failure that lands after the deadline, and
    /// that is a change to what ships, not to a test.
    const ABSENT_SOCKET_CEILING: Duration = Duration::from_secs(20);

    #[test]
    fn an_absent_socket_is_unreachable_rather_than_a_hang() {
        let client = Client::new(
            short_socket_path(std::path::Path::new("ipc-client-absent")),
            ABSENT_SOCKET_CEILING,
        );
        let error = client
            .request(&Request::ping())
            .expect_err("there is no daemon there");
        assert!(matches!(error, ClientError::Unreachable(_)));
    }

    #[test]
    fn a_path_that_is_a_regular_file_is_unreachable_rather_than_a_panic() {
        let path = short_socket_path(std::path::Path::new("ipc-client-regular-file"));
        std::fs::write(&path, b"not a socket").expect("write");
        let client = Client::new(path.clone(), ABSENT_SOCKET_CEILING);
        assert!(matches!(
            client.request(&Request::ping()),
            Err(ClientError::Unreachable(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_scrubbed_reader_frames_exactly_like_a_bufreader() {
        let data: &[u8] = b"alpha\nbeta\n";
        let mut reader = ScrubbedReader::new(data);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read");
        assert_eq!(line, "alpha\n");
        line.clear();
        reader.read_line(&mut line).expect("read");
        assert_eq!(line, "beta\n");
    }
}
