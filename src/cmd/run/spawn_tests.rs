// -----------------------------------------------------------------------
// The spawn retry, which is a never-block guard rather than an optimisation.
//
// A `fork` refused with `EAGAIN` under `RLIMIT_NPROC` is the machine saying
// "not right now". Giving up on the first one turns a transient limit into a
// dead command — exit 127, no child — which is the single outcome `keyless
// run`'s contract forbids.
//
// The loop, its budget and its jitter now live beside the spawn mutex in
// [`crate::store::exec`], and so do the tests that drive them through a
// seam. What is left here is the WIRING: this module's own spawn path still
// going through that loop, which no test over there can see.
// -----------------------------------------------------------------------

/// The wiring, which the seam tests in `store::exec` cannot see.
///
/// They exercise the retry loop directly, so a `spawn_persistently` that had
/// stopped calling it would leave every one of them green. This runs the
/// shipped path against a real binary.
#[test]
fn the_shipped_spawn_path_produces_a_real_child() {
    let mut command = std::process::Command::new("/usr/bin/true");
    let mut child = super::spawn_persistently(&mut command).expect("`true` must run");
    assert!(child.wait().expect("the child must be reapable").success());
}

// The shared timeout harness, from the file the integration suites use.
// Included rather than copied: a unit test in `src/` cannot see `tests/`,
// and a second copy of a hang-detector is a second copy that can rot.
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/support/within.rs"
));

/// The pty half of the never-block invariant, tested where BOTH platforms
/// can see it fail.
///
/// `tests/pty.rs` covers this end to end, and on Linux it is merciless — but
/// it is BLIND on macOS, because XNU revokes a controlling terminal when the
/// child's session ends and cleans up the leak on this process's behalf.
/// Measured 2026-08-09 against the source with `release_slave` absent: 10 of
/// 11 pty cases fail on Linux and 11 of 11 pass on macOS.
///
/// So this drops to the mechanism, where there is no session and no child
/// and therefore nothing to revoke. A master whose last slave is closed must
/// END the stream — Linux says `EIO`, macOS says end-of-file — and a slave
/// this process is still holding makes both of them block forever instead.
/// That is why the read is inside `within`: without a bound the regression
/// is a hang, and a hang reports nothing.
#[test]
fn releasing_the_pty_slave_lets_the_master_reach_end_of_stream() {
    use super::StdioPlan;
    use std::io::Read;

    // The crate's own opener rather than `openpty`, for the reason stated
    // on it: `openpty` runs its whole body with inheritable descriptors
    // live, and the lib test binary spawns children from other threads
    // while this one runs. A slave that walked into one of them would keep
    // this pty open and turn the read below into the timeout it is here to
    // detect.
    let (master, slave) =
        crate::tty::open_pty(None, None).expect("this platform must provide a pty");
    let mut plan = StdioPlan::Pty(Some(slave));
    plan.release_slave();

    let ended = within(
        PATIENCE,
        "reading a pty master whose only slave has been released",
        move || {
            let mut buf = [0u8; 16];
            match std::fs::File::from(master).read(&mut buf) {
                // macOS: end-of-file. Linux: EIO. Both mean the same thing.
                Ok(0) => true,
                Err(error) => error.raw_os_error() == Some(nix::libc::EIO),
                Ok(_) => false,
            }
        },
    );
    assert!(
        ended,
        "the master neither ended nor errored, so something is still holding \
         the slave"
    );
}
