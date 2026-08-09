// A bound on a test that could hang.
//
// Deliberately written with `//` and not `//!`. An inner doc comment has to be
// the first thing in its module, which would make this file includable only in
// the first position of a `mod tests { … }`. Everything worth reading is on the
// items themselves, so it can be included anywhere.
//
// SHARED ON PURPOSE, and there are two ways in. Integration tests take it
// through `mod support;`:
//
//     mod support;
//     use support::within;
//
// A unit test inside `src/` cannot see `tests/`, so it includes this one file
// rather than growing a second copy of the same idea:
//
//     #[cfg(test)]
//     mod tests {
//         include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/within.rs"));
//     }
//
// That is deliberately the only sharing mechanism offered. Putting this in the
// library itself would ship a test helper inside a crate whose subject is
// credential handling, and a second copy would be free to drift from the first.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// The bound every test in this suite uses unless it has a reason not to.
///
/// Long enough that a loaded parallel run — a dozen test binaries, each
/// spawning shells — never trips it, short enough that a genuine hang is
/// reported in under a minute rather than never.
pub const PATIENCE: Duration = Duration::from_secs(30);

/// Run `body`, and panic if it has not finished within `limit`.
///
/// # Why a test that could hang must be wrapped
///
/// **A hang does not fail a test. It stops the suite and reports nothing.** A
/// hanging test and a passing test are the same empty log, which is exactly how
/// nine broken pty cases sat unnoticed on Linux: `cargo test` never returned, so
/// there was no red line to read. Wrap anything that drives a child process, a
/// terminal, or a descriptor another process can hold open.
///
/// `what` names the work, because the panic message is the entire report a hang
/// produces: "timed out" with no subject sends the reader back to the source to
/// guess which of ten cases stalled.
///
/// # What this does NOT do
///
/// It does not cancel `body`. A thread blocked in `read(2)` cannot be
/// interrupted portably, and any process that thread spawned keeps running. So a
/// timeout leaves the work behind and turns the run red; it does not clean up
/// after it. That trade is the whole point — a red test naming the case beats a
/// suite that never returns, and a leaked child is visible in `ps` where a silent
/// suite is visible nowhere.
///
/// # Panics
///
/// When `body` does not finish within `limit`, and when `body` itself panics —
/// re-raised on the test thread so the failure keeps its own message.
pub fn within<T, F>(limit: Duration, what: &str, body: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (finished, done) = mpsc::channel();
    // NAMED, and it is not decoration. A body that panics does so on this
    // thread, so an unnamed worker makes every assertion failure in a wrapped
    // suite report `thread '<unnamed>' panicked` — which is the one line a
    // reader uses to tell which of nineteen cases blew up. Naming it restores
    // exactly what an unwrapped `#[test]` prints.
    let worker = thread::Builder::new()
        .name(what.to_owned())
        .spawn(move || {
            // The result travels on the channel rather than through
            // `JoinHandle`, because `JoinHandle::join` has no timed form:
            // joining a hung thread is the very hang this is meant to report.
            let _ = finished.send(body());
        })
        // The OS refused a thread. Reported rather than swallowed: running
        // `body` inline instead would silently drop the bound, and a bound
        // nobody can see is worse than none.
        .unwrap_or_else(|error| panic!("`{what}` could not be given a thread to run on: {error}"));
    match done.recv_timeout(limit) {
        Ok(value) => {
            let _ = worker.join();
            value
        }
        // The sender was dropped without sending: `body` panicked. Joining
        // re-raises it, so the original assertion message survives.
        Err(mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
            Ok(()) => unreachable!("the body returned without sending its result"),
            Err(panic) => std::panic::resume_unwind(panic),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => panic!(
            "`{what}` did not finish within {limit:?}; it is HUNG, and it has been \
             abandoned rather than waited on. A hang reports nothing at all when a \
             test is allowed to block, so this is reported as a failure instead."
        ),
    }
}
