//! The masking filters on the child's piped output, and the bounded wait for them.

use std::io::{self, Write};
use std::process::Child;
use std::sync::{Arc, mpsc};
use std::thread;

use super::PUMP_DRAIN_GRACE;
use crate::NAME;
use crate::mask::{Masker, pump};

/// Start one masking filter per piped stream of the child.
///
/// Returns how many started, and the channel each reports its end on.
pub(super) fn start_filters(
    child: &mut Child,
    masker: &Arc<Masker>,
    notes: &mut dyn Write,
) -> (usize, mpsc::Receiver<()>) {
    // One `finished` message per pump. Threads rather than join handles is not
    // the interesting part — a channel is, because `JoinHandle` has no timed
    // join and the drain below has to be bounded. See [`PUMP_DRAIN_GRACE`].
    let (finished, pumps_done) = mpsc::channel::<()>();
    let mut pumps = 0_usize;
    let mut start = |body: Box<dyn FnOnce() + Send>, notes: &mut dyn Write| {
        match thread::Builder::new()
            .name("keyless-mask".to_owned())
            .spawn(body)
        {
            Ok(_) => pumps += 1,
            // The OS refused a thread. The child is already running and its
            // exit code is still owed to the caller, so this costs the
            // masking of one stream and nothing else.
            Err(error) => {
                let _ = writeln!(
                    notes,
                    "{NAME}: warning: cannot start the output filter ({error}); \
                     one stream of the child's output is not redacted"
                );
            }
        }
    };
    // `io::stdout()` and not `io::stdout().lock()`, and that is the second
    // half of the bounded drain rather than a style choice. A held lock is
    // released when its guard drops, and a filter abandoned at the deadline
    // never drops anything — it is still blocked on a read of a pipe a
    // grandchild holds open. Holding the process-wide stdout lock for the
    // pump's whole life therefore moved the hang instead of removing it:
    // `run` returned on time, and `main`'s closing `stdout().flush()`
    // blocked forever on the guard nobody would ever drop.
    //
    // Locking per write costs one uncontended acquisition per 8 KiB read and
    // keeps each `write_all` atomic, which is the only atomicity a stream
    // filter needs.
    if let Some(stream) = child.stdout.take() {
        let masker = Arc::clone(masker);
        let finished = finished.clone();
        start(
            Box::new(move || {
                let _ = pump(stream, io::stdout(), masker);
                let _ = finished.send(());
            }),
            notes,
        );
    }
    if let Some(stream) = child.stderr.take() {
        let masker = Arc::clone(masker);
        let finished = finished.clone();
        start(
            Box::new(move || {
                let _ = pump(stream, io::stderr(), masker);
                let _ = finished.send(());
            }),
            notes,
        );
    }
    // The loop's own clone would otherwise keep the channel open forever.
    drop(finished);
    (pumps, pumps_done)
}

/// The one thing a caller needs to know when a filter is abandoned at the
/// deadline.
///
/// Shared by the pipe path and the pty path, because they abandon for the same
/// reason and the reader's next question is the same either way.
pub(super) fn warn_output_left_open(notes: &mut dyn Write) {
    let _ = writeln!(
        notes,
        "{NAME}: warning: the child exited but something it started still holds its \
         output open; anything written from here on is not shown"
    );
}

/// Wait for the masking filters, but not forever.
pub(super) fn drain_pumps(pumps: usize, done: &mpsc::Receiver<()>, notes: &mut dyn Write) {
    let deadline = std::time::Instant::now() + PUMP_DRAIN_GRACE;
    for _ in 0..pumps {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if done.recv_timeout(left).is_err() {
            warn_output_left_open(notes);
            return;
        }
    }
}
