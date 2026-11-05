use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::NAME;
use crate::attest::attest;
use crate::ipc::protocol::{Reply, write_frame};

use super::Daemon;
use super::connection::Connection;

/// How many connections may be in flight at once.
///
/// Above this the daemon answers and closes rather than queueing, so a runaway
/// client cannot make the daemon unresponsive to the other nineteen sessions.
const MAX_CONNECTIONS: usize = 64;
/// How often the accept loop checks whether it has been told to stop.
const ACCEPT_POLL: Duration = Duration::from_millis(5);
impl Daemon {
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

        // Attested here, on the accept loop's own thread, rather than left for
        // the connection thread below to do once it exists. A freshly spawned
        // thread's first slice of CPU is scheduled whenever the OS gets to it,
        // and a legitimate peer that is a short-lived process — `keyless run`
        // wrapping a command that finishes fast — can exit before that
        // happens, which turns "identified late" into "unidentifiable" for no
        // reason connected to who the peer was. The accept loop is already
        // running, so there is no second thread's scheduling to wait on: this
        // reads the kernel's facts about the peer as close to connect as any
        // code in this daemon ever will. Every request after the first is
        // still attested fresh, in `Connection::serve`, which is what defends
        // against a peer that `exec`s a different image mid-connection.
        let first_attestation = attest(stream.as_fd(), &self.policy);

        let worker = Connection {
            policy: Arc::clone(&self.policy),
            resolver: Arc::clone(&self.resolver),
            audit: Arc::clone(&self.audit),
            catalogue: Arc::clone(&self.catalogue),
            rebuilder: Arc::clone(&self.rebuilder),
            rebuild_within: self.rebuild_within,
            idle: self.idle,
            live: Arc::clone(&self.live),
            token_expires: self.token_expires.clone(),
        };
        self.live.fetch_add(1, Ordering::Relaxed);
        if thread::Builder::new()
            .name(format!("{NAME}d-conn"))
            .spawn(move || worker.serve(stream, first_attestation))
            .is_err()
        {
            self.live.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
