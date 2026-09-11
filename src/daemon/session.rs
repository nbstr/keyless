//! The loop that keeps the daemon's own Proton session alive.
//!
//! # The outage this closes
//!
//! A Proton session opened with a personal access token lasts **two hours**.
//! The vendor publishes no renewal verb — logging in again IS the renewal:
//!
//! > "Sessions established with a personal access token have a lifetime of 2
//! > hours, so you need to log in again once it expires."
//! > — <https://protonpass.github.io/pass-cli/commands/personal-access-token/>
//!
//! and it publishes the loop itself, as a shell line an operator is expected to
//! run on a schedule:
//!
//! > `pass-cli info 2>/dev/null || PROTON_PASS_PERSONAL_ACCESS_TOKEN=… pass-cli login`
//! > — <https://protonpass.github.io/pass-cli/commands/agent/>
//!
//! Before this module, nothing in this crate ran it. The daemon held every
//! piece — the token in a file only it can open, the login verb, `--replace` —
//! and no clock, so every Proton name degraded two hours after the last time a
//! person typed something, on a schedule nobody chose.
//!
//! # Why no other store has one of these
//!
//! Not an omission, and not a thing to generalise at the second vendor. A
//! renewal loop exists here because a Proton Pass identity is a session — a
//! DIRECTORY the vendor's own binary establishes and expires on a clock this
//! crate does not set.
//!
//! An Infisical machine identity and a 1Password service account are
//! credentials and nothing else: writing the value is the whole of their setup,
//! and there is no session to lapse, so there is nothing for a loop to do.
//! [`super::login::refuse_store`] says the same thing to an operator who asks
//! for a login on one of them, and it is the same fact.
//!
//! So the seam this module would need to be generic — a background task each
//! store adapter offers — has exactly one implementer and no second one in
//! sight. It is deliberately not built. The daemon stays general in what it
//! serves, this module stays specific in what it maintains, and a store that
//! never needs maintaining pays nothing for either: [`spawn`] returns `None`
//! the moment `stores.proton.enabled` is false.
//!
//! # Why a thread rather than an external timer
//!
//! Three facts already live in this process and nowhere else, and each one an
//! external job has to reconstruct: which uid may own the session store, where
//! the credential file is, and what the vendor's answer meant. A shell job
//! outside gets the first wrong by running as root, reads the second out of a
//! config it has to parse itself, and judges the third by re-reading the
//! session — which `pass-cli` does not update in time, so successful logins get
//! filed as failures. Every one of those was measured on a real install before
//! this module existed.
//!
//! # Why a failing login does not stop the daemon
//!
//! Vault Agent's `auto_auth` carries `exit_on_err`, and this loop deliberately
//! has no counterpart. Vault Agent brokers one identity, so exiting takes away
//! only what was already broken. This daemon serves several stores, and a
//! Proton login that keeps failing would take the file store, the keychain and
//! Infisical down with it. The loop latches at the maximum backoff instead and
//! keeps trying; every other store keeps answering.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::NAME;
use crate::store::proton_session::Generations;

use super::config::{DaemonConfig, SessionRenewal};
use super::login::{self, Coordinates, Owner};

/// The shortest wake interval the loop will accept.
///
/// A `probe_interval_seconds` of zero would otherwise spin a thread against the
/// vendor binary as fast as it can fork. Clamped rather than refused: a bad
/// number here is worth a warning and a sane floor, not a daemon that will not
/// start and takes four other stores with it.
const MIN_INTERVAL: Duration = Duration::from_secs(5);

/// How finely the sleep between ticks checks whether it has been told to stop.
///
/// The loop sleeps for minutes at a time, and a shutdown must not wait one out.
const STOP_POLL: Duration = Duration::from_millis(100);

/// How long shutdown waits for the renewal loop before it stops waiting.
///
/// # Why waiting for ever is not an option here
///
/// The loop is stopped by a flag it reads BETWEEN ticks. A tick spends most of
/// its time inside [`login::run`], which is `Command::output()` and
/// deliberately unbounded — the reasoning recorded there is that a deadline
/// killing a login part way is how a session store ends up half-written, which
/// is the one damage this vendor cannot repair.
///
/// That reasoning holds, and it is about the login VERB, where a person is
/// waiting. Inside a daemon it collides with shutdown: a thread parked against
/// a vendor that never returns cannot see the flag, so joining it unconditionally
/// means SIGTERM never completes, the socket is never removed, and launchd's
/// `ExitTimeOut` SIGKILL is the only thing that ends the process.
///
/// Measured, not reasoned: with a vendor stubbed as `sleep 60`, dropping a
/// `Running` blocked for the whole sixty seconds.
///
/// So shutdown waits this long and then stops waiting. The child is left to
/// finish rather than killed, which keeps the half-write reasoning intact —
/// what is given up is the join, not the process. Well under any plausible
/// `ExitTimeOut`, whose default the manual page declines to name, so that a
/// daemon which is merely slow still exits on its own terms.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// A running renewal loop. Dropping it stops the thread.
pub struct Keeper {
    stop: Arc<AtomicBool>,
    /// Disconnects when the loop's thread returns. A `Receiver` rather than a
    /// timed join, which `std` does not offer.
    done: std::sync::mpsc::Receiver<Never>,
    handle: Option<JoinHandle<()>>,
}

/// Carried by a channel that only ever closes, never sends.
enum Never {}

impl Drop for Keeper {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        match self.done.recv_timeout(SHUTDOWN_GRACE) {
            // The sender was dropped, so the loop has returned and the join
            // below is immediate.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
            }
            // Still inside a vendor call. Leave the thread detached: it holds
            // no lock this process needs, and the alternative is not exiting.
            _ => report(
                "the Proton renewal loop is still waiting on the vendor; shutting down without \
                 it rather than holding the process open",
            ),
        }
    }
}

/// Start the loop, or say why there is nothing to start.
///
/// `Ok(None)` is the ordinary answer on a daemon that has not asked for this —
/// the store is off, or `stores.proton.session.auto_login` is false.
///
/// # Errors
///
/// A config that asks for the loop and cannot support one, in the same
/// sentences [`login::coordinates`] uses for the interactive verb. Returned
/// rather than warned about: an operator who wrote `auto_login: true` has said
/// the session matters, and starting anyway would leave them with the exact
/// silent outage this module exists to end.
///
/// `generations` being `None` here while the loop was asked for is a wiring
/// bug rather than a config problem — [`login::coordinates`] above already
/// requires `session_dir`, and [`super::config::DaemonConfig::generations`]
/// builds `Some` from the identical precondition, so the two disagreeing means
/// whoever called this built `generations` from a different config.
pub fn spawn(
    config: &DaemonConfig,
    generations: Option<&Arc<Generations>>,
) -> Result<Option<Keeper>, String> {
    let settings = config.stores.proton.session;
    if !config.stores.proton.enabled || !settings.auto_login {
        return Ok(None);
    }

    let coordinates = login::coordinates(config)?;
    let Some(owner) = super::credential::daemon_owner(&config.audit) else {
        return Err(login::no_daemon_uid(&config.audit));
    };
    let Some(generations) = generations else {
        return Err(format!(
            "`stores.{}.session_dir` names a directory to renew, but no `Generations` was \
             built for it",
            login::STORE
        ));
    };
    let generations = Arc::clone(generations);
    let timeout_ms = config.stores.proton.timeout_ms;
    let grace = login::grace(timeout_ms);

    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let (alive, done) = std::sync::mpsc::channel::<Never>();
    let handle = thread::Builder::new()
        .name(format!("{NAME}d-session"))
        .spawn(move || {
            // Moved in so it is dropped when this thread returns, however it
            // returns. That drop is what shutdown waits on.
            let _alive = alive;
            run(
                &coordinates,
                owner,
                settings,
                &generations,
                grace,
                timeout_ms,
                &flag,
            );
        })
        .map_err(|error| format!("cannot start the Proton session loop: {error}"))?;

    Ok(Some(Keeper {
        stop,
        done,
        handle: Some(handle),
    }))
}

/// The loop itself, with its clock and its two waits.
///
/// Two triggers, and both are needed. **Age** replaces a session before the
/// vendor's two-hour cap reaches it. **Liveness** catches the session the
/// vendor dropped early -- which it does without warning, and which age alone
/// would sit out for the whole lifetime. Proton's own published loop is the
/// second one; the first is what keeps it from only ever acting after an
/// outage has started.
///
/// # Why the first tick always logs in
///
/// The daemon has just started and the session directory may hold anything: no
/// session, a fresh one, or one 119 minutes old that a previous daemon
/// established. Nothing on disk says which — `pass-cli` reports whether a
/// session answers, never how long it has left. Adopting an unknown session as
/// though it were new is the one reading that produces an outage, so an unknown
/// age is treated as old and replaced. `--replace` makes that safe against all
/// three states.
fn run(
    coordinates: &Coordinates,
    owner: Owner,
    settings: SessionRenewal,
    generations: &Generations,
    grace: Duration,
    timeout_ms: u64,
    stop: &AtomicBool,
) {
    let interval = Duration::from_secs(settings.probe_interval_seconds).max(MIN_INTERVAL);
    let lifetime = Duration::from_secs(settings.login_after_minutes.saturating_mul(60));
    let min_backoff = Duration::from_secs(settings.min_backoff_seconds).max(MIN_INTERVAL);
    let max_backoff = Duration::from_secs(settings.max_backoff_seconds).max(min_backoff);

    let mut established: Option<Instant> = None;
    let mut failures: u32 = 0;
    // When the loop last actually attempted a login, of any outcome — the
    // floor a session-fault event's early wake is measured against, so a
    // burst of them cannot turn into a burst of attempts. Seeded at "now"
    // rather than left unset: a fault reported before this thread's first
    // tick has even run waits out one `min_backoff` like any other, instead
    // of firing the instant the thread starts.
    let mut last_attempt = Instant::now();

    // Once before the clock below ever runs, so a crash leftover — a
    // generation a previous process created and never published, or one it
    // published and never got to retire — is swept before this process's
    // first attempt rather than waiting out a whole interval for it.
    report_sweep(coordinates, owner, generations, grace, timeout_ms, stop);

    while !stop.load(Ordering::Relaxed) {
        // Three triggers, and the third is not redundant with the second.
        // Liveness re-asks the vendor's own `info` fresh, on THIS tick; a
        // session-fault event is the record that a READ already asked —
        // possibly seconds ago, possibly while this thread was mid-sleep —
        // and got a structural answer this crate itself decided, not the
        // vendor's wording. `take_session_fault` is what turns "the store
        // reported one" into "the loop acted on it", exactly once per
        // report: a fault raised again while an attempt is in flight is
        // caught by the next tick's own read of the flag, not lost.
        // Taken FIRST and unconditionally, never as an arm of the `||`
        // below: `||` short-circuits, and the two conditions ahead of it are
        // true in exactly the states a fault is reported in — an expired
        // session, or one `alive` finds dead. Left in the chain, the flag
        // survives the renewal that fixes it and spends itself on the NEXT
        // tick, buying a second login, a second generation and a second
        // retirement for a session that was just replaced.
        let faulted = generations.take_session_fault();
        let due = faulted
            || established.is_none_or(|at| at.elapsed() >= lifetime)
            || !alive(coordinates, owner, generations);
        if due {
            last_attempt = Instant::now();
            match attempt(coordinates, owner, generations) {
                Ok(name) => {
                    established = Some(Instant::now());
                    if failures > 0 {
                        report(&format!(
                            "established generation {name}, recovered after {failures} failed \
                             attempt(s)"
                        ));
                        failures = 0;
                    } else {
                        report(&format!("established generation {name}"));
                    }
                }
                Err(detail) => {
                    established = None;
                    failures = failures.saturating_add(1);
                    // Every Proton name is degrading while this is true, so it
                    // is said on the first failure rather than after a
                    // threshold. The message carries the vendor's own words:
                    // `login::establish` never puts a value in one.
                    report(&format!(
                        "Proton session renewal failed ({failures} in a row): {detail}"
                    ));
                }
            }
        }

        // After the due-check, on every tick regardless of whether one was
        // due: retirement runs on its own clock (the grace), never the
        // renewal's, so a generation superseded three ticks ago is retired
        // the moment it clears its grace rather than waiting for the next
        // renewal to notice it.
        report_sweep(coordinates, owner, generations, grace, timeout_ms, stop);

        let wait = if failures == 0 {
            interval
        } else {
            backoff(min_backoff, max_backoff, failures)
        };
        // The floor the event path may shorten a sleep to is the wait this
        // loop just computed for ITSELF, not the constant minimum. While
        // logins are succeeding that is `min_backoff`, so a fault still wakes
        // the loop promptly out of a long healthy interval. While they are
        // failing it is the grown backoff, so the event path can no longer
        // shorten a sleep the failure path lengthened.
        let floor = if failures == 0 { min_backoff } else { wait };
        sleep_until_stopped(wait, floor, last_attempt, generations, stop);
    }
}

/// Run [`login::sweep`] and translate its tab-separated rows into the plain
/// stderr sentences this loop's other lines already use.
///
/// `sweep` itself writes the operator-verb's own row shape
/// (`retired\tproton\t<label>`) because [`super::bin::keylessd`]'s `login`
/// verb shares the same function for its own, much rarer call. Rewritten here
/// rather than given a second `sweep` that speaks stderr directly: one
/// retirement procedure, two renderings, is the same relationship
/// `login::perform` and `login::establish` already have.
fn report_sweep(
    coordinates: &Coordinates,
    owner: Owner,
    generations: &Generations,
    grace: Duration,
    timeout_ms: u64,
    stop: &AtomicBool,
) {
    let mut rows: Vec<u8> = Vec::new();
    login::sweep(
        coordinates,
        owner,
        generations,
        grace,
        timeout_ms,
        Some(stop),
        &mut rows,
    );
    for line in rows.split(|&byte| byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let mut fields = text.split('\t');
        match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (Some("retired"), Some("proton"), Some("legacy"), None) => {
                report("retired the legacy session directory");
            }
            (Some("retired"), Some("proton"), Some(label), None) => {
                report(&format!("retired {label}"));
            }
            (Some("retire-failed"), Some("proton"), Some(label), Some(why)) => {
                report(&format!("could not retire {label}: {why}"));
            }
            _ => {}
        }
    }
}

/// What to say when the session directory cannot be made the daemon's.
///
/// Reached almost always for one reason: something ran the vendor as root
/// against this directory and left files behind that this uid cannot take
/// back. `keylessd check` under `sudo` was that something until the adapter
/// began dropping privilege, and a hand-run `pass-cli` still is.
///
/// The remedy is a privileged `chown`, so it is written out rather than
/// described: nothing this daemon can do will fix it, and a message that only
/// reports the errno leaves an operator watching a loop retry for ever.
fn undirectable(coordinates: &Coordinates, owner: Owner, detail: &str) -> String {
    format!(
        "the Proton session directory cannot be made this daemon's, so no login can succeed \
         against it: {detail}\n\
         Only a privileged process may change a file's owner, so this is not something the \
         daemon can repair — it is almost always a `pass-cli` that ran as root against this \
         directory. Give it back:\n\
         \tsudo chown -R {}:{} {}",
        owner.uid,
        owner.gid,
        coordinates.session_dir.display()
    )
}

/// Does a session still answer in the daemon's own directory?
///
/// # Why a failed probe is read as "no session" rather than ignored
///
/// The three ways this comes back false are a dead session, a vendor binary
/// that will not spawn, and a directory the daemon cannot open — and the
/// response to all three is the same: try to log in, and report what that says.
/// A login is safe against every one of them (`--replace` treats "already
/// logged out" as success), and the failure path already carries the vendor's
/// own sentence, which is more specific than anything a probe could add.
///
/// The alternative — treating an unanswerable probe as healthy — is the reading
/// that produces silence over an outage.
///
/// A [`crate::store::proton_session::CurrentFault`] — no generation published
/// yet, a pointer nothing can validate — reads the same as a dead session:
/// `false`, which sends the loop straight to [`attempt`].
fn alive(coordinates: &Coordinates, owner: Owner, generations: &Generations) -> bool {
    let Ok(pass) = generations.enter() else {
        return false;
    };
    login::run(login::info_command(coordinates, pass.dir(), owner))
        .map(|(status, _)| status.success())
        .unwrap_or(false)
}

/// One renewal: read the token the daemon already holds, and use it.
///
/// The token is re-read from the credential file on every attempt rather than
/// captured once at startup. That is what makes a rotation take effect without
/// a restart — `keylessd credential` writes the file, and the next tick logs in
/// with what it now says.
fn attempt(
    coordinates: &Coordinates,
    owner: Owner,
    generations: &Generations,
) -> Result<crate::store::proton_session::GenerationName, String> {
    use crate::store::Store;

    // The directory before the login that writes into it.
    //
    // `pass-cli` creates `.session/` inside it and owns what it creates, so a
    // session directory belonging to anyone but the daemon produces
    // `Permission denied` while creating the local key — a failure that reads
    // nothing like its cause, and that a reader spends the afternoon
    // attributing to the token.
    //
    // What this can and cannot do is worth being exact about, because the
    // difference is a privilege the daemon does not have. It CREATES a missing
    // directory, and it re-asserts the mode, both of which an owner may do. It
    // CANNOT take a file back from root: only a privileged process may change
    // a file's owner, so a `.session/local.key` left behind by something that
    // ran as root is diagnosed here and repaired by nobody. Saying which is the
    // whole value — the alternative is the vendor's own sentence, which names
    // neither the file nor the fix.
    //
    // Here rather than at startup, because a directory can go wrong while the
    // daemon runs, and a check made once cannot see that. It is a `stat` per
    // renewal, not per lookup.
    match login::ensure_session_dir(&coordinates.session_dir, owner)
        .map_err(|detail| undirectable(coordinates, owner, &detail))?
    {
        login::Ensured::Sound => {}
        login::Ensured::Created => report(&format!(
            "created the Proton session directory {}",
            coordinates.session_dir.display()
        )),
        login::Ensured::Repaired(repairs) => {
            for repair in repairs {
                report(&format!("Proton session directory: {repair}"));
            }
        }
    }

    let file = crate::store::file::FileStore::new(coordinates.credentials_file.clone());
    let token = match file.resolve(&coordinates.token_entry) {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Err(format!(
                "{} holds no `{}` entry, so there is nothing to log in with. Write it with \
                 `{} credential --store proton --name {}`",
                coordinates.credentials_file.display(),
                coordinates.token_entry,
                crate::DAEMON_NAME,
                coordinates.token_entry
            ));
        }
        Err(error) => {
            return Err(format!(
                "{} could not be read: {error}",
                coordinates.credentials_file.display()
            ));
        }
    };
    let extra = login::extra_credentials(coordinates)?;

    // `replace = true` unconditionally. An unknown-age generation at startup,
    // a live one past its `login_after_minutes`, and one the vendor already
    // dropped are three different states this loop cannot tell apart from
    // outside — see this function's own doc — and `establish` treats all
    // three the same way under `replace`: build a fresh generation, verify it,
    // publish it, and never open, mutate or delete whatever `current` names
    // right now. There is no gap here for a read to land in: the OLD
    // generation keeps serving, unmodified, for the whole time this call is
    // spawning children against a directory nothing else knows about yet.
    login::establish(
        coordinates,
        owner,
        true,
        &token,
        extra,
        generations,
        &mut io::sink(),
    )
}

/// Exponential, from `min` to `max`, saturating rather than wrapping.
fn backoff(min: Duration, max: Duration, failures: u32) -> Duration {
    let factor = 1u32
        .checked_shl(failures.saturating_sub(1))
        .unwrap_or(u32::MAX);
    min.saturating_mul(factor).min(max)
}

/// Sleep, waking early on a stop request or — no sooner than `floor` after
/// `last_attempt` — a pending session-fault event.
///
/// # Why the event is only peeked here, never consumed
///
/// This function decides only WHEN to look again; `run`'s own
/// `generations.take_session_fault()` at the top of the next iteration is
/// what actually acts on it, once, on the tick that wakes for it — see that
/// call's own doc. Consuming the flag here instead would let a tick this
/// function chose NOT to wake for (because `floor` had not yet elapsed)
/// clear a fault nobody had acted on, and the loop would then sleep out the
/// rest of `total` over a session everyone had already stopped checking.
///
/// # Why the floor is the caller's own computed wait
///
/// A single read discovering a session fault is one event; a daemon under
/// load discovers the same fault on every read against it until the loop
/// replaces the session, which is a stream of them, all re-reporting while
/// this call is asleep. Waking on the very first one would make the interval
/// between attempts exactly the polling granularity below rather than
/// anything this crate chose — a failing store turned into a spawn storm by
/// the one mechanism meant to make it recover faster.
///
/// A floor of `min_backoff` is not enough to stop that, and this is the trap
/// worth naming: while logins are FAILING, `run` has already lengthened its
/// own wait by `backoff`, and a flat `min_backoff` floor lets the event path
/// return after the minimum on every tick regardless. The loop then attempts
/// a login every `min_backoff` for the whole outage — with defaults, one
/// every 5 s against a backoff that had grown to 300 s. Hammering an account
/// endpoint at 60× the intended rate is how a recoverable session fault
/// becomes a rate-limited or locked token, which is an outage no amount of
/// retrying exits. So `run` hands its own `wait` in as the floor whenever it
/// is backing off, and the event path can only ever shorten a sleep the
/// failure path did not lengthen.
fn sleep_until_stopped(
    total: Duration,
    floor: Duration,
    last_attempt: Instant,
    generations: &Generations,
    stop: &AtomicBool,
) {
    let start = Instant::now();
    while start.elapsed() < total {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        if generations.session_fault_pending() && last_attempt.elapsed() >= floor {
            return;
        }
        thread::sleep(STOP_POLL);
    }
}

/// One line on stderr, where the daemon's other operational lines go.
///
/// Not the audit log: that records what a CLIENT asked for, and nothing here
/// was asked for by anybody. A renewal appearing there as a resolve would make
/// the log lie about who read what.
fn report(line: &str) {
    use std::io::Write;
    let _ = writeln!(io::stderr(), "{NAME}d: {line}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::proton_session::GenerationName;

    #[test]
    fn backoff_starts_at_the_minimum() {
        let min = Duration::from_secs(5);
        let max = Duration::from_secs(300);
        assert_eq!(backoff(min, max, 1), min);
    }

    #[test]
    fn backoff_doubles_then_latches_at_the_maximum() {
        let min = Duration::from_secs(5);
        let max = Duration::from_secs(30);
        assert_eq!(backoff(min, max, 2), Duration::from_secs(10));
        assert_eq!(backoff(min, max, 3), Duration::from_secs(20));
        assert_eq!(backoff(min, max, 4), max);
        assert_eq!(backoff(min, max, 99), max);
    }

    #[test]
    fn a_huge_failure_count_saturates_rather_than_wrapping() {
        let min = Duration::from_secs(5);
        let max = Duration::from_secs(300);
        // Shifting by 32 or more is undefined for u32 and would panic in debug;
        // the loop must survive a daemon that has been failing for weeks.
        assert_eq!(backoff(min, max, u32::MAX), max);
    }

    #[test]
    fn a_stopping_daemon_does_not_wait_out_its_interval() {
        let stop = AtomicBool::new(true);
        let generations = Generations::at(scratch_generations_root("stopping"));
        let start = Instant::now();
        sleep_until_stopped(
            Duration::from_secs(600),
            Duration::from_secs(5),
            Instant::now(),
            &generations,
            &stop,
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// A scratch root for a bare `Generations` — this module's tests never
    /// publish anything into it, so it exists only to give the type a path
    /// of its own rather than to be read from.
    fn scratch_generations_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "keyless-daemon-session-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    #[test]
    fn a_pending_session_fault_ends_the_sleep_once_min_backoff_has_elapsed() {
        // CONTROL — the change that makes this fail: `sleep_until_stopped`
        // never consulting `generations` at all, the shape it had before
        // this event existed. The sleep would then run out its full
        // `total` (here, ten seconds — bounded rather than the minutes an
        // interval runs for in production, so a red run still finishes),
        // the assertion on elapsed time would fail, and the renewal loop
        // would keep silently sleeping through a fault a read had already
        // reported.
        let stop = AtomicBool::new(false);
        let generations = Generations::at(scratch_generations_root("wakes"));
        let min_backoff = Duration::from_millis(100);
        generations.report_session_fault(
            &GenerationName::parse("gen-1-1").expect("a well-formed generation name"),
        );

        let start = Instant::now();
        sleep_until_stopped(
            Duration::from_secs(10),
            min_backoff,
            start,
            &generations,
            &stop,
        );
        let elapsed = start.elapsed();

        assert!(
            elapsed >= min_backoff,
            "the sleep ended before its min_backoff floor: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "a pending fault did not end a ten-second sleep early: {elapsed:?}"
        );
    }

    #[test]
    fn a_session_fault_reported_before_min_backoff_does_not_end_the_sleep_early() {
        // The floor's other half: an event that arrives with the previous
        // attempt only moments old must not shorten the wait at all, or the
        // floor is decorative.
        let stop = AtomicBool::new(false);
        let generations = Generations::at(scratch_generations_root("floored"));
        let min_backoff = Duration::from_secs(600);
        generations.report_session_fault(
            &GenerationName::parse("gen-1-1").expect("a well-formed generation name"),
        );

        let start = Instant::now();
        sleep_until_stopped(
            Duration::from_millis(300),
            min_backoff,
            start,
            &generations,
            &stop,
        );
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(300),
            "a fault younger than min_backoff still cut the sleep short: {elapsed:?}"
        );
    }

    #[test]
    fn the_event_path_cannot_shorten_a_sleep_the_failure_path_lengthened() {
        // The expensive failure, and the reason the floor is the caller's own
        // computed wait rather than the constant minimum. While logins are
        // failing, `run` lengthens its wait by `backoff` — and a flat
        // `min_backoff` floor would let a pending fault end that sleep after
        // the minimum on EVERY tick, so the loop attempts a login every
        // `min_backoff` for the whole outage. With production defaults that
        // is one login every 5 s against a backoff that had grown to 300 s:
        // hammering the account endpoint at 60x the intended rate, which is
        // how a recoverable session fault turns into a locked token.
        //
        // Here the loop is "backing off": the wait it computed is 400 ms, and
        // that same value is handed in as the floor. A fault is pending the
        // whole time, and the sleep must still run to completion.
        //
        // CONTROL — the change that makes this fail: passing `min_backoff`
        // as the floor instead of the computed wait. The sleep then returns
        // in roughly one poll interval and the elapsed assertion below fails.
        let stop = AtomicBool::new(false);
        let generations = Generations::at(scratch_generations_root("backing-off"));
        let grown_wait = Duration::from_millis(400);
        generations.report_session_fault(&GenerationName::parse("gen-1-1").expect("a name"));

        let start = Instant::now();
        sleep_until_stopped(grown_wait, grown_wait, start, &generations, &stop);
        let elapsed = start.elapsed();

        assert!(
            elapsed >= grown_wait,
            "a pending fault shortened a sleep the failure path had already \
             lengthened, which is the login storm this floor exists to stop: {elapsed:?}"
        );
    }

    #[test]
    fn no_pending_fault_sleeps_out_the_full_interval_up_to_a_stop() {
        // The control for the two cases above: with nothing reported, the
        // fault check never fires and the function behaves exactly as it
        // did before the event existed.
        let stop = AtomicBool::new(false);
        let generations = Generations::at(scratch_generations_root("quiet"));

        let start = Instant::now();
        sleep_until_stopped(
            Duration::from_millis(250),
            Duration::from_millis(1),
            start,
            &generations,
            &stop,
        );
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "the sleep ended early with no fault ever reported"
        );
    }
}
