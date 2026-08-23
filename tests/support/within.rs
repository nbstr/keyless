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
//
// It also has NO dependencies, and that is a constraint rather than an
// accident: the crate declares no dev-dependencies, so an integration test can
// reach the standard library and this crate and nothing else. Everything below
// is written against `std` for that reason.

use std::hint::black_box;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// The bound every test in this suite uses unless it has a reason not to.
///
/// Read it as *served* time and not as wall time — [`within`] explains the
/// difference and why the difference is the whole point. Long enough that no
/// honest case in this suite comes anywhere near it, short enough that a
/// genuine hang on a machine with cpu to spare is reported in under a minute
/// rather than never. On a machine without, that report is later by however
/// much of itself the machine is withholding, which is the trade the served
/// clock makes and the reason the wall backstop exists.
pub const PATIENCE: Duration = Duration::from_secs(30);

/// Run `body`, and panic if it has not finished within `limit` of *served*
/// time.
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
/// # Why `limit` is not a wall clock
///
/// **A wall clock cannot tell a hung test from a starved one.** A process that
/// is hung burns no cpu while its wall clock runs; a process that is merely
/// being denied the cpu burns it steadily and is making real progress, just
/// slowly. Both read as "took too long", so on a machine with far more runnable
/// work than cores a wall clock fires on healthy tests — and its only defence
/// is a larger constant, which weakens the guard against the hang it exists to
/// catch and still loses, because the wall cost of a busy machine has no
/// ceiling.
///
/// So the clock here is **served time**: wall time divided by how
/// oversubscribed this machine is at that moment, *measured* rather than
/// assumed. A body is charged only for the fraction of the machine it was
/// actually given, so `limit` buys the same amount of PROGRESS on a crushed
/// machine as on an idle one. A hang makes no progress on either, so it spends
/// its budget just as fast on both and is still reported. On a machine that is
/// not oversubscribed the two clocks are the same clock, which is why nothing
/// about the numbers at the call sites had to change.
///
/// [`WALL_CEILING`] is the one wall-clock number left, and it is a backstop
/// rather than a property — see it for what that distinction means.
///
/// # What this bound does and does not classify
///
/// It **catches**: a body blocked forever on a descriptor nothing will write; a
/// body spinning in a loop that will never exit (one spinner barely moves a
/// multi-core machine's contention, so its budget is spent at very nearly the
/// wall rate); a body waiting on a child that will never speak.
///
/// It **stops mis-firing on**: a body whose cost is cpu, on a machine that is
/// not giving it any. That is the entire class this instrument exists to
/// remove, and it is the class a wall clock cannot be tuned out of.
///
/// It **does not** inspect the body. It removes the confound instead of reading
/// through it, and that has two honest consequences, both measurable and
/// neither hidden:
///
/// * A hang on a machine that is itself crushed is reported *late*, in
///   proportion to how crushed the machine is, and never later than
///   [`WALL_CEILING`] times `limit` of wall clock.
/// * A body that merely **overruns** — a sleep, or a wait on a child that is
///   itself only sleeping — is tolerated for as much longer as the machine is
///   loaded, and on an oversubscribed machine will finish before its budget is
///   spent. A bound on served time cannot be a bound on wall time, and a test
///   whose subject IS a wall-clock duration must assert that itself rather than
///   read it out of this. What survives is the property this exists for: a wait
///   with no end still spends the budget and is still reported.
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
/// When `body` has spent `limit` of served time without finishing, when it has
/// run past the wall-clock backstop, and when `body` itself panics — the last
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

    let started = Instant::now();
    let ceiling = limit.saturating_mul(WALL_CEILING);
    let mut served = Duration::ZERO;
    // The first round is a plain wait of `limit`, so a body that finishes in
    // time never costs a reading at all — which is every body, almost always.
    let mut wait = limit;
    loop {
        let round = Instant::now();
        match done.recv_timeout(wait) {
            Ok(value) => {
                let _ = worker.join();
                return value;
            }
            // The sender was dropped without sending: `body` panicked. Joining
            // re-raises it, so the original assertion message survives.
            Err(mpsc::RecvTimeoutError::Disconnected) => match worker.join() {
                Ok(()) => unreachable!("the body returned without sending its result"),
                Err(panic) => std::panic::resume_unwind(panic),
            },
            // Late, which is not yet a verdict. Ask the machine how much of
            // itself it was handing out, and charge the round accordingly.
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }

        // Measured AFTER the wait rather than before it, so the reading
        // describes the machine the body has just been running on. The
        // measurement's own wall time falls inside `round.elapsed()` and is
        // charged at the same rate as the rest of the round.
        let contention = contention();
        served += round.elapsed().div_f64(contention);

        // Asked again before any verdict, because taking that reading TOOK
        // TIME — and on the machine it is there to detect, a lot of it. A body
        // that crossed the line while it was being measured has finished, and
        // reporting it hung would be the same false red this bound exists to
        // stop, arriving through the instrument instead of through the clock.
        match done.try_recv() {
            Ok(value) => {
                let _ = worker.join();
                return value;
            }
            Err(mpsc::TryRecvError::Disconnected) => match worker.join() {
                Ok(()) => unreachable!("the body returned without sending its result"),
                Err(panic) => std::panic::resume_unwind(panic),
            },
            Err(mpsc::TryRecvError::Empty) => {}
        }

        let wall = started.elapsed();
        assert!(
            served < limit,
            "`{what}` has been given {limit:?} of served time and has not finished; it \
             is HUNG, and it has been abandoned rather than waited on. It held {wall:?} \
             of wall clock, of which {served:?} was time this machine actually handed \
             it — the rest went to whatever else was runnable, and a body is not \
             charged for that. A hang reports nothing at all when a test is allowed to \
             block, so this is reported as a failure instead."
        );
        assert!(
            wall < ceiling,
            "`{what}` has held {wall:?} of wall clock without finishing, which is the \
             backstop: {WALL_CEILING} times its {limit:?} budget. It is still inside \
             that budget — only {served:?} of served time has been charged — because \
             this machine reports itself too oversubscribed to be handing out much of \
             anything. That is a machine no test result can be read off, so this is \
             reported as a failure rather than waited on: a suite that never returns \
             reports nothing at all."
        );

        // The next round is sized so that it delivers the rest of the budget on
        // a machine behaving as this reading says it is. That keeps the number
        // of readings small however loaded the machine gets — a fixed round
        // would need one reading per `limit` of WALL time, and each reading
        // costs wall time of its own that grows with the contention it is
        // there to detect. The floor stops the last sliver of a budget being
        // chased in ever-shorter rounds, and caps the readings a single call
        // can take.
        //
        // Trimmed so the WAIT cannot end past the backstop. The ceiling is read
        // between rounds, so without this a single long round would sail
        // through it and report the overshoot rather than the ceiling — a
        // backstop that can be exceeded by an unbounded amount is not one. The
        // reading taken after the wait still adds its own wall time on top,
        // which is why this bounds the overshoot rather than removing it: that
        // reading is `BURST_WORK` of cpu, so its wall cost cannot exceed
        // `BURST_WORK` times the cap `contention` is clamped to.
        wait = (limit.saturating_sub(served))
            .max(limit / ROUNDS_TO_SPEND_A_BUDGET)
            .mul_f64(contention)
            .min(ceiling.saturating_sub(wall));
    }
}

// ---------------------------------------------------------------------------
// The instrument: how much of this machine the process is actually being given
// ---------------------------------------------------------------------------
//
// One reading, self-contained, built out of two numbers taken from the same
// burst of a fixed unit of work.
//
//   * The FLOOR — the shortest that unit took anywhere in this burst. A tick is
//     deliberately small enough to fit inside a single scheduling slice, so
//     even a machine with hundreds of runnable tasks per cpu hands out enough
//     uninterrupted slices for the minimum to converge on the tick's true cost.
//     A minimum over interleaved rounds, never an average: an average is
//     exactly the quantity contention corrupts, and a minimum is the one
//     statistic it cannot inflate.
//
//   * The BURST — every tick in the reading back to back, over what the floor
//     says they should have cost. That ratio IS the oversubscription.
//
// **The floor is taken per reading rather than kept for the process, and that
// is deliberate.** A floor carried between readings is a number one unlucky
// sample can poison for every later one, and on a machine whose cores are not
// all the same speed it is a systematic bias: calibrated on a fast core, every
// later reading on a slow one reports contention that is not there. Taken
// inside the burst, the floor describes the cpu the reading actually ran on, so
// what is left in the ratio is contention and nothing else.
//
// **THE BURST HAS TO BE LONG, and this is the part that is not obvious.** A
// thread waking from a sleep is handed a scheduling credit, so a short burst
// finishes inside that credit and reports an idle machine however loaded the
// machine really is. The thread taking this reading is precisely such a thread
// — it has just come off a timed wait. `BURST_WORK` is therefore sized to
// outlive that credit rather than sized to be cheap, and a reading is taken
// only once a body is already late, so nothing pays for it on a healthy run.
//
// # Why not cpu time
//
// Reading the cpu a body has consumed is the obvious instrument, and it is the
// wrong one here for four reasons that stack.
//
//  1. **The bodies this file wraps split into two extremes.** One of them is
//     almost pure cpu; the rest are almost pure waiting, spending their time in
//     a child process or on a descriptor. A cpu budget large enough for the
//     first is a budget the others can never spend, and a watchdog that never
//     fires is not a watchdog — it is a comment that costs cpu.
//  2. **`getrusage(RUSAGE_CHILDREN)` accrues only when a child is REAPED.** A
//     body waiting on a child that is still running reads exactly zero, which
//     is what a hang reads. The suite's commonest shape would be
//     indistinguishable from the failure this exists to detect.
//  3. **That reading is process-wide**, so a sibling test's work counts as this
//     body's progress — a hang beside a busy neighbour would never be seen.
//  4. **Per-thread cpu is not portable here.** macOS provides no
//     `pthread_getcpuclockid`, so one thread cannot read another's cpu clock
//     without mach calls, and this file has no dependencies to reach them with.
//
// Contention is the confound, so contention is what gets measured.
//
// The harvester strips one `//` prefix before it looks for the word, so this
// paragraph is written with `//` and not `///`: an outer doc comment would
// leave `/ debt:` and match nothing.
//
// debt: a body whose runaway is MEMORY rather than time is bounded here only
//       while the machine is not oversubscribed. Two cases in
//       `tests/hostile.rs` regress by allocating without end rather than by
//       blocking — a config that is a character device, a backend that streams
//       forever — and each one used to be caught by a wall clock set below the
//       point at which the kernel would step in. A served-time budget can be
//       slower than the kernel on a loaded machine, and then the report is an
//       out-of-memory kill rather than a bound naming the case. Still red,
//       less informative.
//       Upgrade trigger: a case in this suite whose regression is a memory
//       runaway reports an out-of-memory kill instead of this bound's own
//       message. The fix is not a shorter budget — it is a second criterion
//       that watches the body's memory, which is a different instrument from
//       the one this file measures.

/// Iterations in one tick.
///
/// A dependent multiply-add chain: register-only, so it reports the machine's
/// *cpu* pressure rather than its memory pressure, and strictly sequential, so
/// no compiler is entitled to collapse it into a closed form. Sized to stay
/// well inside one scheduling slice even in an unoptimized build — that is what
/// makes the floor recoverable on a loaded machine — while staying far above
/// the cost of the two clock reads that bracket it.
const TICK_STEPS: u64 = 16_000;

/// How much floor-equivalent work one reading does.
///
/// Expressed as work rather than as a tick count, so it means the same thing on
/// a fast machine and a slow one. Long enough to outlive the scheduling credit
/// a just-woken thread is handed, which is the requirement that decides it.
const BURST_WORK: Duration = Duration::from_millis(150);

/// Ticks a reading takes before it will believe its own floor.
///
/// The floor is a minimum, so it is only as good as the number of chances it
/// was given to find a slice it was not interrupted in.
const FLOOR_SAMPLES: u64 = 512;

/// The most ticks one reading will ever take, however cheap a tick turns out to
/// be. A guard against a machine where the floor reads as very nearly nothing.
const BURST_CEILING: u64 = 1 << 20;

/// How many rounds one budget is spent over, at most.
///
/// Each round costs a reading, so this caps what a single call can spend on
/// measuring. It is also what stops the last sliver of a budget being chased in
/// ever-shorter rounds.
const ROUNDS_TO_SPEND_A_BUDGET: u32 = 16;

/// The wall-clock backstop, as a multiple of `limit`.
///
/// **This encodes no property, and saying so is the point of stating it apart
/// from everything else here.** Every other bound in this file is a bound on
/// served time and holds whatever the machine is doing. This one exists only so
/// that "a hang is reported eventually" cannot decay into "never" on a machine
/// whose own contention reading has gone through the roof — and past this
/// factor there is no test result to be read off that machine anyway. Being
/// generous here costs nothing but the time to report a hang that has already
/// happened.
const WALL_CEILING: u32 = 128;

/// One fixed unit of work, and how long it took.
#[inline(never)]
fn tick() -> Duration {
    let started = Instant::now();
    let mut state: u64 = black_box(0x9E37_79B9_7F4A_7C15);
    for _ in 0..TICK_STEPS {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
    }
    black_box(state);
    started.elapsed()
}

/// How many times slower than an unloaded machine this one is right now, as a
/// factor of at least one.
fn contention() -> f64 {
    let mut floor = Duration::MAX;
    let mut ticks: u64 = 0;
    // Timed from outside the loop on purpose. At high contention most of the
    // delay lands BETWEEN ticks, in the stretches where this thread is off the
    // cpu entirely; summing the ticks' own durations would miss exactly the
    // thing being measured.
    let started = Instant::now();
    loop {
        let sample = tick();
        ticks += 1;
        floor = floor.min(sample);
        let enough_samples = ticks >= FLOOR_SAMPLES;
        let enough_work =
            floor.saturating_mul(u32::try_from(ticks).unwrap_or(u32::MAX)) >= BURST_WORK;
        if (enough_samples && enough_work) || ticks >= BURST_CEILING {
            break;
        }
    }
    let spent = started.elapsed();

    let factor = spent.as_secs_f64() / (floor.as_secs_f64() * ticks as f64);
    // A floor of zero — a clock too coarse to see a tick at all — makes this a
    // NaN or an infinity rather than a number, and every comparison with a NaN
    // is false, `clamp`'s bounds included. One is what an unloaded machine
    // reads, so it is the safe value to fall back to: it leaves the bound
    // strict rather than permissive.
    if !factor.is_finite() {
        return 1.0;
    }
    // Capped where the wall backstop would refuse to wait any longer anyway, so
    // a reading past that point cannot buy a body time it will not be given —
    // and so no arithmetic downstream of it can overflow.
    factor.clamp(1.0, f64::from(WALL_CEILING))
}
