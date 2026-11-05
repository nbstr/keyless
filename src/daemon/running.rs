use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use crate::NAME;

use super::config::DaemonConfig;
use super::resolver::Resolver;
use super::{Daemon, Running};

impl Running {
    /// Start serving on a background thread, and keep the session alive.
    ///
    /// # Why the renewal loop starts HERE and not in `main`
    ///
    /// It started in the binary, and that was wrong in two ways that only
    /// showed up when something tried to test it.
    ///
    /// A daemon is a thing that serves names and keeps the identity it serves
    /// them with; `main` is argument parsing and a signal wait. Wiring the loop
    /// there made "is this daemon renewing?" a question about which entry point
    /// happened to construct it — so every integration case in this crate, all
    /// of which build a daemon through this function, ran against one that
    /// never renewed. A test asserting the loop's behaviour passed by
    /// describing a loop that was not running.
    ///
    /// It also meant an embedder using this crate as a library got a daemon
    /// whose Proton session lapsed in two hours, with nothing to say so.
    ///
    /// After the socket is bound, so a renewal taking a few seconds does not
    /// delay the sessions waiting to connect.
    ///
    /// # Errors
    ///
    /// The accept thread not starting, or a config that asks for the renewal
    /// loop and cannot support a login — the second carried verbatim from
    /// [`super::session::spawn`], because an operator who wrote `auto_login`
    /// has said the session matters and starting without it is the silent
    /// outage that loop exists to end.
    pub fn spawn(daemon: Daemon, config: &DaemonConfig) -> io::Result<Self> {
        // The same `Generations` the daemon's Proton store reads through: the
        // loop creates and publishes into it, and every store sees a fresh
        // generation the moment this loop makes one current.
        let session = super::session::spawn(config, daemon.generations.as_ref())
            .map_err(|detail| io::Error::new(io::ErrorKind::InvalidInput, detail))?;
        let stop = Arc::new(AtomicBool::new(false));
        let socket = daemon.socket.clone();
        let resolver = Arc::clone(&daemon.resolver);
        let flag = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name(format!("{NAME}d-accept"))
            .spawn(move || daemon.serve_until(&flag))?;
        let refresher = Some(Resolver::start(&resolver));
        Ok(Running {
            stop,
            socket,
            resolver,
            thread: Some(thread),
            session,
            refresher,
        })
    }

    /// Whether this daemon is keeping a Proton session alive.
    #[must_use]
    pub fn renews_its_session(&self) -> bool {
        self.session.is_some()
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
        // The renewal loop first: it spawns vendor children, and stopping the
        // accept loop while one is in flight leaves the process waiting on a
        // join for something nobody is stopping. The refresh workers spawn the
        // same children, so they stop on the same terms and for the same
        // reason.
        drop(self.session.take());
        drop(self.refresher.take());
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}
