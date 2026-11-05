#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::time::{Duration, Instant};

use keyless::ipc::client::Client;
use keyless::ipc::protocol::{Reply, Request};
use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::generations::{
    until_a_generation_is_published, until_current_moves_past,
};
use daemon_proton_support::session_verbs::{
    daemon_config_with_generations_loop, daemon_config_with_generations_loop_env,
};
use daemon_proton_support::vendor_store::store_stub;
use daemon_proton_support::{DECLARED, session_dir};
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::scratch;

// ---------------------------------------------------------------------------
// The daemon, against a vendor that behaves the way the real one does.
// ---------------------------------------------------------------------------

#[test]
fn a_generation_the_vendor_destroys_on_a_read_costs_one_degraded_answer_and_is_replaced() {
    // CONTROL — the change that makes this fail: have the renewal loop repair
    // the CURRENT generation in place rather than establishing a new one. The
    // vendor has three ways to delete the directory it is pointed at, two of
    // them decided before the command runs, and a repair in place hands the
    // replacement session back to the same directory a concurrent child may be
    // deleting.
    //
    // The three paths are one case rather than three, because the design
    // survives all of them or none: what the daemon does about a destroyed
    // generation cannot depend on which branch inside the vendor destroyed it.
    let dir = scratch("daemon-proton-vendor-destroys-generation");
    // `key_provider: env`, which is what this daemon ships — the deletions
    // below are the vendor's dispatch and its invalidation callback, and
    // neither reads the key provider at all.
    let vendor = store_stub(&dir, &support::proton_session::VendorStore::INSTANT);
    let config = daemon_config_with_generations_loop_env(&dir, &vendor, 90, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());
    let root = session_dir(&dir);

    let mut current = until_a_generation_is_published(&root, Duration::from_secs(30));
    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { .. } => {}
        other => panic!("the fixture never resolved at all: {}", other.reason()),
    }

    for path in ["revoked", "unauthenticated", "extra-password"] {
        let generation = root.join(&current);
        match path {
            "revoked" => support::proton_session::revoke_vendor_session(&dir, &generation),
            "unauthenticated" => {
                support::proton_session::degrade_vendor_session(
                    &generation,
                    &support::proton_session::VendorSession::NotAuthenticated,
                );
            }
            _ => support::proton_session::degrade_vendor_session(
                &generation,
                &support::proton_session::VendorSession::NeedsExtraPassword,
            ),
        }

        // The read that meets the vendor in that state. It degrades — and on
        // its way to degrading, the vendor deletes the store it was scoped at.
        let degraded = registry.resolve(DECLARED);
        assert!(
            !matches!(degraded, Resolution::Found { .. }),
            "{path}: the vendor refuses this read, so it cannot have resolved"
        );
        assert!(
            !generation.join(".session").join("session.json").exists(),
            "{path}: the vendor deletes the session store on its way out, and this case is \
             about what the daemon does afterwards — if the file is still there the fixture \
             did not reproduce the hazard"
        );

        // The loop's answer: a generation of its own, never a repair of the
        // one the vendor just emptied.
        current = until_current_moves_past(&root, &current, Duration::from_secs(60));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if matches!(registry.resolve(DECLARED), Resolution::Found { .. }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{path}: reads never came back after the generation was replaced"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    // Three destroyed generations, three replacements — read off the vendor's
    // own trace rather than from the daemon's account of itself.
    let outcomes: Vec<String> = support::proton_session::vendor_store_trace(&dir)
        .iter()
        .filter_map(|line| line.split_whitespace().last().map(str::to_owned))
        .collect();
    for expected in [
        "revoked-cleanup",
        "not-authenticated",
        "needs-extra-password",
    ] {
        assert!(
            outcomes.iter().any(|outcome| outcome == expected),
            "the vendor never took the `{expected}` path, so this case proved nothing about \
             it: the trace holds {outcomes:?}"
        );
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

/// How long the concurrent-child case keeps reading while the loop renews.
///
/// Not a deadline on anything: it is how long the hazard is OFFERED. The loop
/// renews on its own interval, and every renewal opens one window in which a
/// reader becomes a deleter, so this is several windows rather than one.
const HAZARD_WINDOW: Duration = Duration::from_secs(35);

#[test]
fn no_read_meets_a_session_store_a_renewal_left_undecryptable() {
    // The case this whole effort exists for, driven by the vendor's own
    // behaviour rather than by a description of it.
    //
    // The vendor's `logout` revokes the session at the account and only then
    // deletes locally, so for the width of that window every other child
    // holding the session is refused — and a refused child runs the
    // invalidation cleanup AND schedules a `session.json` write whose key it
    // resolves at one instant and whose rename lands at a later one. A
    // renewal that logs out the directory readers are using therefore leaves,
    // deterministically, a session file under a key no surviving `local.key`
    // holds. The next child mints a fresh key, cannot decrypt what is there,
    // and every read after that fails the same way: the state is terminal, not
    // transient.
    //
    // The windows below are set so that ordering is arithmetic:
    //
    //   the revoke, then 300 ms before anything local is deleted
    //   a reader landing inside that window resolves the key AT ONCE
    //   its rename lands 600 ms later — after the deletions, before the rmdir
    //   each rmdir is 2 s behind its own listing, so the rename beats both
    //
    // Against a renewal that replaces the directory in place this goes red on
    // the first window it is offered. Against a renewal that establishes each
    // session in a generation of its own it cannot go red at all, because no
    // logout is ever pointed at a directory a reader is holding.
    let dir = scratch("daemon-proton-concurrent-children");
    let vendor = store_stub(
        &dir,
        &support::proton_session::VendorStore {
            logout_delay: Duration::from_millis(300),
            rmdir_window: Duration::from_secs(2),
            persist_key_delay: Duration::ZERO,
            persist_write_delay: Duration::from_millis(600),
            login_delay: Duration::ZERO,
        },
    );
    // `key_provider: fs`, because the key that gets minted, deleted and
    // disagreed about is a FILE under that provider and does not exist at all
    // under the other. `login_after_minutes: 0` makes every tick due, so the
    // window is offered on the loop's own interval rather than once.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());
    let root = session_dir(&dir);
    until_a_generation_is_published(&root, Duration::from_secs(30));

    // Two readers, because one is not concurrency. They read flat out for the
    // whole window and keep every reason they were given.
    let stop = Instant::now() + HAZARD_WINDOW;
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let socket = running.socket().to_path_buf();
            std::thread::spawn(move || {
                let mut reasons: Vec<String> = Vec::new();
                let mut answered = 0_usize;
                while Instant::now() < stop {
                    let client = Client::new(socket.clone(), Duration::from_secs(30));
                    match client.request(&Request::resolve(DECLARED)) {
                        Ok(Reply::Value(_)) => answered += 1,
                        Ok(Reply::Failed(reason)) => reasons.push(reason),
                        Ok(other) => reasons.push(format!("{other:?}")),
                        Err(error) => reasons.push(error.to_string()),
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                (answered, reasons)
            })
        })
        .collect();

    let mut answered = 0_usize;
    let mut reasons: Vec<String> = Vec::new();
    for reader in readers {
        let (ok, said) = reader.join().expect("a reader thread panicked");
        answered += ok;
        reasons.extend(said);
    }

    let trace = support::proton_session::vendor_store_trace(&dir);
    let outcome = |name: &str| {
        trace
            .iter()
            .filter(|line| line.split_whitespace().last() == Some(name))
            .count()
    };

    // The two halves of the fingerprint, in the order the incident produced
    // them: a `remove_dir_all` that lost its own directory, and then a session
    // store nothing can decrypt.
    assert_eq!(
        outcome("logout-enotempty"),
        0,
        "a renewal's `remove_dir_all` raced an entry that appeared after its listing — the \
         `Directory not empty` half of the incident. The vendor's trace: {trace:?}"
    );
    assert_eq!(
        outcome("undecryptable"),
        0,
        "a child met a session store under a key no surviving local key holds — the \
         terminal half. The vendor's trace: {trace:?}"
    );
    let aead: Vec<&String> = reasons
        .iter()
        .filter(|reason| reason.contains("aead::Error"))
        .collect();
    assert!(
        aead.is_empty(),
        "a caller was handed the vendor's undecryptable-session sentence: {aead:?}"
    );

    // Two controls, because every assertion above is satisfied by a run in
    // which nothing happened: the hazard has to have been OFFERED.
    assert!(
        outcome("logged-in") >= 2,
        "the renewal loop logged in {} time(s), so the window this case is about was never \
         opened more than once",
        outcome("logged-in")
    );
    assert!(
        answered > 0,
        "no read ever succeeded, so this run says nothing about what readers met"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
