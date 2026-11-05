#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::path::Path;
use std::time::{Duration, Instant};

use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::{LISTING, TOKEN_DECOY, session_dir, vendor_argv};
use support::backend::Backend;
use support::client::{client_config, write_secrets};
use support::daemon::{policy_allowing_self, start_daemon};
use support::proton::{Listing, stub_pass_cli_listing};
use support::{scratch, short_socket_path};

/// A name the FILE store answers, so the assertion is about another store.
const NEIGHBOUR: &str = "A_NAME_THE_FILE_STORE_HOLDS";
const NEIGHBOUR_VALUE: &str = "file-store-decoy-not-a-credential";

// ---------------------------------------------------------------------------
// One daemon, several stores: a Proton login that keeps failing is Proton's
// problem and nobody else's.
// ---------------------------------------------------------------------------

/// A config with BOTH stores, and a renewal loop that cannot possibly succeed.
///
/// The vendor refuses every login, so `session::attempt` fails on its first
/// tick and on every tick after it. `min_backoff_seconds` is 1 and
/// `probe_interval_seconds` is 1 so the loop is actually spinning through
/// failures while the assertion below runs, rather than asleep on a default
/// five-minute timer and passing for the wrong reason.
fn daemon_config_with_a_failing_renewal(dir: &Path, vendor: &Path) -> DaemonConfig {
    // The audit log is what the daemon's uid is read off — `session::spawn`
    // refuses without it, which is the same refusal the login verb makes.
    std::fs::write(dir.join("audit.jsonl"), b"").expect("audit");
    let secrets = dir.join("secrets.json");
    write_secrets(&secrets, &[(NEIGHBOUR, NEIGHBOUR_VALUE)]);
    let credentials = dir.join("proton.json");
    write_secrets(&credentials, &[("AGENT_TOKEN", TOKEN_DECOY)]);
    // `key_provider: fs` pinned rather than inherited: these cases are about
    // the TOKEN, and under `env` the daemon also names an entry for its own
    // local key, so an unwritten credential file would report the key missing
    // where the case is asking what happens to the token.

    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{
               "file":{{"enabled":true,"path":"{secrets}"}},
               "proton":{{"enabled":true,"binary":"{vendor}",
                          "session_dir":"{session}",
                          "timeout_ms":60000,
                          "key_provider":"fs",
                          "credentials_file":"{credentials}",
                          "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN"}},
                          "session":{{"auto_login":true,"login_after_minutes":1,
                                      "probe_interval_seconds":1,
                                      "min_backoff_seconds":1,"max_backoff_seconds":1}}}}}},
             "secrets":{{"{NEIGHBOUR}":{{"store":"file"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        secrets = secrets.display(),
        credentials = credentials.display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

/// A Proton session that will not come back does not take the file store with it.
///
/// This is the claim the renewal loop was landed on, and it is the reason it
/// carries no counterpart to Vault Agent's `auto_auth.exit_on_err`: Vault Agent
/// brokers ONE identity, so exiting takes away only what was already broken,
/// while this daemon serves several stores and exiting to fix Proton would take
/// the file store, the keychain and Infisical with it.
///
/// Stated in a doc comment, that claim is unfalsifiable. Here it can fail: the
/// vendor refuses every login, the loop is spinning through failures at a
/// one-second backoff, and a name belonging to another store still has to
/// resolve over the same socket.
///
/// # Why the control is waited FOR, and waited for FIRST
///
/// The control below — the vendor was spawned, and spawned for a login — is
/// what stops this case passing against a loop that never started. A loop that
/// died at birth leaves the file store answering too, so without it the two
/// resolve assertions are satisfied by a daemon running no Proton machinery at
/// all.
///
/// It used to be a fixed `sleep(4s)` followed by one read of the argv file, and
/// that is a race rather than a wait: the interval between `start_daemon` and
/// the vendor child's first write is not a duration this crate promises, it is
/// however long the machine takes to get there. **Measured 2026-09-19 over five
/// runs of this file at cargo's default parallelism: +4.913 s, +5.249 s,
/// +7.321 s, +7.410 s, +7.913 s from the scratch directory's creation** — past
/// the 4 s budget in every one, so the read found no file and the case reported
/// that the loop had never reached the vendor. It had; the file arrived
/// seconds later. The same test alone spawns at +0.254 s and passes, which is
/// what made this read as load-sensitive flake rather than as a bound that is
/// simply too short. It is not load: `--test-threads=1` passes on the same
/// busy machine, so the variable is how many of this binary's own tests are
/// spawning children at once, not what else the box is doing.
///
/// So the control waits for its own EVENT and returns the moment it lands —
/// typically a quarter of a second. The 30 s below is a failure bound and
/// never a success-path dependency: nothing waits it out when the loop is
/// healthy, and it matches every other bounded wait in this file. **Its
/// ceiling is roughly four times the worst figure above.** It stops being
/// enough if this file grows enough concurrent daemon fixtures to push the
/// first spawn past 30 s, and the symptom would be this exact assertion firing
/// with an empty `argv` — at which point the number to change is the
/// parallelism, not this bound.
///
/// Waiting for the CONTENT rather than for the file to exist is not
/// fastidiousness: `>` creates the file before `printf` writes into it, so a
/// test that woke on existence alone could read an empty string and fail the
/// `contains` check it had just waited for.
#[test]
fn a_proton_login_that_keeps_failing_leaves_the_other_stores_answering() {
    let dir = scratch("daemon-proton-latches");
    // `Backend::OwnFailure` fails before the probe runs, which is what a
    // refused token, an absent binary and a dead network all look like from
    // here — the loop cannot tell them apart and must not exit for any of them.
    let vendor = stub_pass_cli_listing(&dir, &Backend::OwnFailure, &Listing::Json(LISTING));
    let config = daemon_config_with_a_failing_renewal(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    // The control, established BEFORE the property rather than after it. The
    // old order asserted the property first and only then checked whether the
    // loop had started, so the two resolves below ran against a daemon whose
    // Proton state nothing had pinned down yet.
    //
    // The vendor always refuses, so once the first attempt has failed the loop
    // is latched: `established` is back to `None` and every later tick fails
    // the same way. That is the state the property is about, and reaching it
    // once is what the old "several ticks" sleep was reaching for.
    let argv_path = vendor_argv(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let argv = std::fs::read_to_string(&argv_path).unwrap_or_default();
        if argv.contains("login") || argv.contains("logout") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the renewal loop never reached the vendor, so nothing was latching. \
             {} holds {argv:?}",
            argv_path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    match registry.resolve(NEIGHBOUR) {
        Resolution::Found { secret, store } => {
            assert_eq!(secret.expose(), NEIGHBOUR_VALUE);
            assert_eq!(store, "daemon");
        }
        other => panic!(
            "a failing Proton renewal took another store down with it: {}",
            other.reason()
        ),
    }

    // And the daemon is still there to be asked a second time — a loop that
    // exited would answer the first read from a socket nobody is listening on
    // only by accident of timing.
    assert!(
        matches!(registry.resolve(NEIGHBOUR), Resolution::Found { .. }),
        "the daemon stopped answering while its Proton loop was failing"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A daemon serving other stores runs no Proton machinery at all.
///
/// This is the property an operator on 1Password or Infisical is entitled to:
/// nothing of Proton's runs on their machine, and there is no background job
/// for them to find, understand, or unload. HashiCorp's Vault gives the same
/// guarantee for an optional secrets engine — `vault secrets disable` is one
/// act, after which the engine "stops functioning entirely" and the operator
/// hunts for nothing.
///
/// It rests on three lines in [`session::spawn`], which is exactly the kind of
/// guard that reads as obviously correct and is worth one test: a later change
/// that spawns the thread before consulting the config would leave every case
/// in this suite green.
///
/// Both directions are asserted. The negative alone would also pass against a
/// `renews_its_session` that is always false, which is a daemon that renews
/// nothing for anybody.
#[test]
fn the_renewal_loop_runs_only_where_proton_asked_for_it() {
    let dir = scratch("daemon-proton-off");
    let vendor = stub_pass_cli_listing(&dir, &Backend::OwnFailure, &Listing::Json(LISTING));

    // The control: with the store on and `auto_login` true, there IS a loop.
    let on = daemon_config_with_a_failing_renewal(&dir, &vendor);
    let running = start_daemon(&on, policy_allowing_self());
    assert!(
        running.renews_its_session(),
        "a daemon that asked for the renewal loop is not running one, so the \
         negative cases below prove nothing"
    );
    drop(running);

    // `auto_login` false — the default every config gets by saying nothing.
    let mut off = daemon_config_with_a_failing_renewal(&dir, &vendor);
    off.stores.proton.session.auto_login = false;
    let running = start_daemon(&off, policy_allowing_self());
    assert!(
        !running.renews_its_session(),
        "a daemon that did not ask for the loop started one anyway"
    );
    drop(running);

    // The store disabled outright: the 1Password or Infisical operator's case.
    // `auto_login` stays TRUE here on purpose — a config can carry a leftover
    // session block, and a disabled store must run nothing regardless.
    let mut disabled = daemon_config_with_a_failing_renewal(&dir, &vendor);
    disabled.stores.proton.enabled = false;
    assert!(
        disabled.stores.proton.session.auto_login,
        "this case is only meaningful while auto_login is still true"
    );
    let running = start_daemon(&disabled, policy_allowing_self());
    assert!(
        !running.renews_its_session(),
        "a disabled Proton store still started a renewal loop — an operator who \
         serves no Proton name has a thread spawning vendor processes"
    );
    drop(running);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A daemon whose vendor has stopped answering still shuts down.
///
/// `login::run` is `Command::output()`, deliberately unbounded — the reasoning
/// recorded there is that a deadline killing a login part way is how a session
/// store ends up half-written, which is the one damage this vendor cannot
/// repair. That reasoning is about the LOGIN VERB, where a person is waiting.
///
/// Inside the daemon it collides with shutdown: the renewal thread is stopped
/// by a flag it only reads between ticks, so a thread parked in
/// `Command::output()` against a vendor that never returns cannot see it. Join
/// that thread on the way out and SIGTERM never completes — the socket is not
/// removed, the port is not released, and launchd's own timeout is the only
/// thing that ends it.
///
/// So shutdown waits for the renewal loop and then stops waiting. The child is
/// left to finish rather than killed, which keeps the half-write reasoning
/// intact; what is given up is the join, not the process.
///
/// # Why the hung child is waited FOR
///
/// Everything above is only tested while a vendor child is actually parked. A
/// shutdown measured before the loop's first tick reached the vendor is the
/// shutdown of an idle daemon: fast, green, and a statement about nothing.
///
/// This used to sleep a fixed two seconds for that. Run alone or under
/// `--test-threads=1` the child is there in well under a second and the case
/// is genuine; **at cargo's default parallelism, measured 2026-09-19, the
/// child was spawned at +3.218 s** — a second and a fifth AFTER the daemon had
/// already been dropped. On that run the shutdown clock was started against a
/// loop that had not yet reached the vendor at all, so the case proved nothing
/// and said so nowhere.
///
/// It is the same defect its sibling
/// `a_proton_login_that_keeps_failing_leaves_the_other_stores_answering`
/// carried, in the direction that stays GREEN rather than going red — which is
/// why that one was found the day it started failing and this one was not.
///
/// **A log line is not attribution, and it was nearly read as one here.**
/// `shutting down without it rather than holding the process open` appears
/// once in a parallel run of this file whether or not this case reached the
/// vendor, because a renewal thread that is merely SLOW to spawn is just as
/// unjoinable as one parked on a hung child — shutdown abandons it either way,
/// and the child then turns up afterwards. Only the child's own timestamp
/// separates the two, which is what the wait below replaces it with.
///
/// The argv file is the right signal and not merely a convenient one:
/// `vendor_run_tail` writes it as the stub's first act and `Backend::Hangs`
/// sleeps afterwards, so the file existing means the child exists — and the
/// renewal thread is parked in `exec::capture` on its pipes from that instant,
/// which is exactly the state shutdown has to survive.
#[test]
fn a_vendor_that_stopped_answering_does_not_wedge_shutdown() {
    let dir = scratch("daemon-proton-shutdown");
    // `sleep 60` — a black-holed connection, and 60s is far past any patience a
    // shutdown can have.
    let vendor = stub_pass_cli_listing(&dir, &Backend::Hangs, &Listing::Json(LISTING));
    let config = daemon_config_with_a_failing_renewal(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    // The loop's first tick must be INSIDE the vendor call before the clock
    // below starts. Waited for, never slept past — see this case's own doc.
    let argv_path = vendor_argv(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let argv = std::fs::read_to_string(&argv_path).unwrap_or_default();
        if argv.contains("login") || argv.contains("logout") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the renewal loop never reached the hung vendor, so the shutdown below \
             would have been measured against an idle daemon. {} holds {argv:?}",
            argv_path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let began = std::time::Instant::now();
    drop(running);
    let took = began.elapsed();

    assert!(
        took < std::time::Duration::from_secs(30),
        "shutdown blocked on a hung vendor for {took:?} — a daemon that cannot be \
         stopped is one launchd has to kill, and its socket outlives it"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
