//! Talking to the daemon, with a deadline that cannot be missed.
//!
//! # The deadline is on SILENCE, not on the answer
//!
//! This is the one thing to hold on to in this file, because the other reading
//! is the natural one and it was wrong.
//!
//! A daemon that has to ask a vendor CLI over the network takes seconds to
//! answer, and it is ALLOWED to: its own store budget says so. A daemon that is
//! wedged takes for ever. Both look identical from here — nothing arrives —
//! and a client that bounds the ANSWER has to guess a number that separates
//! them. That guess lives on the side that does not do the work, so it goes
//! stale the moment the daemon's config changes, and it fails in the direction
//! that reads as an outage: a lookup that was going to succeed in 4.4 seconds
//! is abandoned at 3 and the run degrades.
//!
//! So the daemon says it is still there, every half second, and the deadline
//! below bounds how long it may say NOTHING. A working daemon can take as long
//! as its own budget allows; a wedged one is caught in the same three seconds
//! as before. Nothing here has to know how long a lookup should take.
//! [`crate::ipc::protocol::Reply::Working`] carries the reasoning and the
//! HTTP/2 precedent.
//!
//! [`MAX_EXCHANGE`] is the backstop for the remaining case — a daemon that
//! heartbeats for ever without finishing.
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
//! The worker also reports the connect itself, so the wait above starts being
//! fed as soon as there is anything to feed it. Without that the connect and
//! the answer would share one deadline again, and a slow connect would spend
//! the budget the answer needed.
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
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use crate::ipc::protocol::{self, ProtocolError, Reply, Request, read_frame, write_frame};

/// The longest one exchange may run, however talkative the daemon is.
///
/// The silence deadline cannot bound this on its own: a daemon that heartbeats
/// on schedule and never finishes resets it for ever, which is the wedge this
/// module exists to make impossible expressed as a well-behaved peer.
///
/// # Derived from the daemon's worst case, not chosen beside it
///
/// A ceiling below the work it bounds is the outage the heartbeat exists to
/// end, moved from three seconds to wherever the ceiling sits. The daemon's
/// longest legitimate lookup is [`VENDOR_CALLS_PER_LOOKUP`] vendor calls, and
/// every store clamps one call to [`crate::config::MAX_TIMEOUT_MS`] — so this is
/// their product, read from that constant so the two cannot drift apart.
///
/// What it does not cover: a daemon running `"policy": "ordered"` across
/// several vendor stores tries them in turn, and a chain of slow ones can run
/// past it. That lookup ends as [`ClientError::Overran`], whose message says the
/// daemon was still working — which points at the right place.
const MAX_EXCHANGE: Duration =
    Duration::from_millis(VENDOR_CALLS_PER_LOOKUP * crate::config::MAX_TIMEOUT_MS);

/// A store that resolves a name through a vault listing makes two calls that
/// are each bounded by the per-call ceiling: the listing, then the read.
///
/// A read that FAILS adds a third child — the session-health probe that
/// decides whether the failure was about the session or about the name — but
/// that one carries a ceiling of its own, a few seconds rather than the
/// per-call maximum, precisely so it does not enter this product. Its
/// constant sits beside the probe in `crate::store::proton`; the arithmetic
/// here covers the two calls that can each run to
/// [`crate::config::MAX_TIMEOUT_MS`], and a bounded third is what keeps that
/// true.
const VENDOR_CALLS_PER_LOOKUP: u64 = 2;

/// A configured route to a daemon.
#[derive(Debug)]
pub struct Client {
    socket: PathBuf,
    timeout: Duration,
    /// The advisory carried by the most recent reply, if any — see
    /// [`Client::take_advisory`]. A `Mutex` rather than a `Cell` because
    /// [`crate::store::Store`] requires `Sync`, and a caller like
    /// [`crate::store::daemon::DaemonStore`] may be resolving several names
    /// for one `keyless run` concurrently, each over its own connection.
    last_advisory: Mutex<Option<String>>,
}

/// What the worker thread tells the waiting caller.
///
/// Both signs of life reset the silence deadline. They are kept apart because
/// only one of them says the daemon is WORKING: a connect proves a listener is
/// there and nothing about whether it will ever answer.
enum Event {
    /// The connect returned.
    Connected,
    /// A heartbeat arrived: the daemon has the request and has not finished.
    Working,
    /// The exchange is over, one way or the other. The advisory travels
    /// alongside a successful reply because it is read off the same frame,
    /// never off the reply's own status — see [`protocol::decode_advisory`].
    Done(Result<(Reply, Option<String>), ClientError>),
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
    /// The daemon said nothing at all for this long — no answer and no
    /// heartbeat — so it is not working on this, it is gone or stuck.
    Timeout(Duration),
    /// The daemon kept saying it was working until the whole exchange ran out
    /// of time.
    ///
    /// Distinct from [`ClientError::Timeout`] because it sends a reader
    /// somewhere else: the daemon is alive and answering, and what to look at
    /// is what its lookup is waiting on.
    Overran(Duration),
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
                write!(f, "the daemon went quiet for {after:?} without answering")
            }
            ClientError::Overran(after) => write!(
                f,
                "the daemon was still working on this after {after:?}, so it was given up on"
            ),
            ClientError::Transport(source) => write!(f, "the connection failed: {source}"),
            ClientError::Protocol(source) => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl Client {
    /// Point at a socket, with a deadline for how long it may say nothing.
    #[must_use]
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Client {
            socket,
            timeout,
            last_advisory: Mutex::new(None),
        }
    }

    /// The socket this client talks to.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Send one request and wait for one reply, or give up.
    ///
    /// Waits `timeout` for each sign of life and [`MAX_EXCHANGE`] for the whole
    /// conversation. See the module header for why those are two numbers.
    pub fn request(&self, request: &Request) -> Result<Reply, ClientError> {
        let frame = request.encode().map_err(ClientError::Transport)?;
        let socket = self.socket.clone();
        let silence = self.timeout;
        let (sender, receiver) = mpsc::channel();

        thread::Builder::new()
            .name(format!("{}-ipc", crate::NAME))
            .spawn(move || {
                let progress = sender.clone();
                let result = exchange(&socket, &frame, silence, |event| {
                    progress.send(event).is_ok()
                });
                // The caller may already have gone, and the reply is then
                // dropped here, which zeroizes the value it carried.
                let _ = sender.send(Event::Done(result));
            })
            .map_err(ClientError::Transport)?;

        let (reply, advisory) = self.wait(&receiver, silence)?;
        // Overwritten unconditionally, `None` included: a request that lands
        // outside the daemon's warning window is exactly what retires an
        // advisory a previous request on this client carried, so a stale line
        // does not keep printing once the daemon has stopped sending one.
        if let Ok(mut slot) = self.last_advisory.lock() {
            *slot = advisory;
        }
        Ok(reply)
    }

    /// The advisory carried by the most recent reply this client received, if
    /// any, and clear it.
    ///
    /// Read this once per request, right after issuing it — a caller that
    /// leaves it unread past the next request loses it, and one that reads it
    /// twice for one request gets it once and then `None`.
    #[must_use]
    pub fn take_advisory(&self) -> Option<String> {
        self.last_advisory
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
    }

    /// Wait on the worker, resetting the silence deadline at every sign of life.
    fn wait(
        &self,
        receiver: &mpsc::Receiver<Event>,
        silence: Duration,
    ) -> Result<(Reply, Option<String>), ClientError> {
        let started = Instant::now();
        let mut working = false;
        loop {
            let spent = started.elapsed();
            let Some(left) = MAX_EXCHANGE.checked_sub(spent) else {
                return Err(gave_up(working, true, silence));
            };
            match receiver.recv_timeout(silence.min(left)) {
                Ok(Event::Done(result)) => return result,
                Ok(Event::Connected) => {}
                Ok(Event::Working) => working = true,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(gave_up(working, left <= silence, silence));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ClientError::Transport(io::Error::other(
                        "the request thread ended without answering",
                    )));
                }
            }
        }
    }
}

/// Which deadline ran out, in the words its reader needs.
///
/// Only a heartbeat earns [`ClientError::Overran`]. A daemon that never said it
/// was working went quiet, even when the silence setting is at its maximum and
/// the two deadlines coincide — which is the one configuration where "which
/// timer fired" would otherwise give the wrong answer.
fn gave_up(working: bool, ceiling_reached: bool, silence: Duration) -> ClientError {
    if working && ceiling_reached {
        ClientError::Overran(MAX_EXCHANGE)
    } else {
        ClientError::Timeout(silence.min(MAX_EXCHANGE))
    }
}

/// What the worker ends on once nobody is waiting for it.
///
/// Nobody reads it. It exists so the worker has something to return, which is
/// what ends its thread and closes the socket.
fn abandoned() -> ClientError {
    ClientError::Transport(io::Error::other("the caller stopped waiting"))
}

/// Connect, send, and read until something that is not a heartbeat arrives.
///
/// `report` is called for each sign of life and answers whether anybody is
/// still listening. The exchange ends the moment nobody is.
///
/// # Why it has to be told
///
/// The caller gives up at its ceiling and reports its own error; this worker
/// cannot see that. Left to run, it would keep reading heartbeats on behalf of
/// no one for as long as the daemon kept sending them — holding a thread and a
/// socket open through the whole of the child's run, since `keyless run` waits
/// on its child with this thread still alive.
fn exchange(
    socket: &Path,
    frame: &[u8],
    silence: Duration,
    report: impl Fn(Event) -> bool,
) -> Result<(Reply, Option<String>), ClientError> {
    let stream = UnixStream::connect(socket).map_err(ClientError::Unreachable)?;
    // The connect returning is itself evidence, and it is the only evidence
    // there will be until the daemon has read the request.
    if !report(Event::Connected) {
        return Err(abandoned());
    }
    stream
        .set_read_timeout(Some(silence))
        .map_err(ClientError::Transport)?;
    stream
        .set_write_timeout(Some(silence))
        .map_err(ClientError::Transport)?;

    write_frame(&mut &stream, frame).map_err(ClientError::Transport)?;

    let mut reader = ScrubbedReader::new(&stream);
    loop {
        // A read deadline here and the caller's own silence deadline are the
        // same duration and race each other, so both have to name the same
        // thing or which one fires decides what the operator reads.
        let raw = read_frame(&mut reader).map_err(|error| match error {
            ProtocolError::Silent => ClientError::Timeout(silence),
            other => ClientError::Protocol(other),
        })?;
        let Some(mut raw) = raw else {
            return Err(ClientError::Transport(io::Error::other(
                "the daemon closed the connection without answering",
            )));
        };
        let reply = Reply::decode(&raw).map_err(ClientError::Protocol);
        let advisory = protocol::decode_advisory(&raw);
        raw.zeroize();
        match reply? {
            Reply::Working => {
                if !report(Event::Working) {
                    return Err(abandoned());
                }
            }
            answered => return Ok((answered, advisory)),
        }
    }
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
    fn an_advisory_on_the_reply_is_readable_once_then_gone() {
        let path = short_socket_path(std::path::Path::new("ipc-client-advisory"));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
            let _ = crate::ipc::protocol::read_frame(&mut reader);
            let reply = crate::ipc::protocol::Reply::Absent
                .encode_with_advisory(Some("the token expires soon"))
                .expect("encode");
            let _ = crate::ipc::protocol::write_frame(&mut &stream, &reply);
        });

        let client = Client::new(path.clone(), Duration::from_secs(5));
        client
            .request(&Request::ping())
            .expect("the fixture answers");
        assert_eq!(
            client.take_advisory(),
            Some("the token expires soon".to_owned())
        );
        // Read once, and gone — a caller that asks again for the same request
        // must not see it a second time.
        assert_eq!(client.take_advisory(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_later_request_with_no_advisory_clears_an_earlier_one() {
        let path = short_socket_path(std::path::Path::new("ipc-client-advisory-clears"));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || {
            for advisory in [Some("the token expires soon"), None] {
                let (stream, _) = listener.accept().expect("accept");
                let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
                let _ = crate::ipc::protocol::read_frame(&mut reader);
                let reply = crate::ipc::protocol::Reply::Absent
                    .encode_with_advisory(advisory)
                    .expect("encode");
                let _ = crate::ipc::protocol::write_frame(&mut &stream, &reply);
            }
        });

        let client = Client::new(path.clone(), Duration::from_secs(5));
        client.request(&Request::ping()).expect("first answer");
        client.request(&Request::ping()).expect("second answer");
        assert_eq!(
            client.take_advisory(),
            None,
            "the second, advisory-free reply must retire the first advisory"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn only_a_heartbeat_earns_overran() {
        // With the silence setting at its maximum the two deadlines coincide,
        // and a daemon that never said a word must still read as quiet.
        assert!(matches!(
            super::gave_up(false, true, super::MAX_EXCHANGE),
            ClientError::Timeout(_)
        ));
        assert!(matches!(
            super::gave_up(true, true, Duration::from_secs(3)),
            ClientError::Overran(_)
        ));
        // Heartbeats, then silence well inside the ceiling: it went quiet.
        assert!(matches!(
            super::gave_up(true, false, Duration::from_secs(3)),
            ClientError::Timeout(_)
        ));
    }

    #[test]
    fn a_worker_nobody_is_waiting_for_stops_at_the_next_heartbeat() {
        // The ceiling ends the caller's wait; this is what ends the worker's.
        // A daemon heartbeating past the ceiling would otherwise hold this
        // thread and its socket for as long as it kept talking.
        let path = short_socket_path(std::path::Path::new("ipc-client-abandoned"));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let daemon = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
            let _ = crate::ipc::protocol::read_frame(&mut reader);
            let beat = crate::ipc::protocol::Reply::Working
                .encode()
                .expect("encode");
            // Talks until the client hangs up, and never answers.
            for _ in 0..400 {
                if crate::ipc::protocol::write_frame(&mut &stream, &beat).is_err() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            false
        });

        let (done, finished) = std::sync::mpsc::channel();
        let frame = Request::resolve("DECOY").encode().expect("encode");
        let socket = path.clone();
        std::thread::spawn(move || {
            let heard = std::cell::Cell::new(0_u32);
            // Listening for the connect and the first heartbeat, gone after.
            let result = super::exchange(&socket, &frame, Duration::from_secs(5), |event| {
                if matches!(event, super::Event::Working) {
                    heard.set(heard.get() + 1);
                }
                heard.get() < 2
            });
            let _ = done.send(result.is_err());
        });

        assert_eq!(
            finished.recv_timeout(ABSENT_SOCKET_CEILING),
            Ok(true),
            "the worker kept reading heartbeats for a caller that had gone"
        );
        assert!(
            daemon.join().expect("the daemon thread"),
            "the daemon never saw the client hang up"
        );
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
