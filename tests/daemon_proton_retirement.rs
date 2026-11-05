#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::time::{Duration, Instant};

use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::session_verbs::{
    LogoutAnswer, daemon_config_with_generations_loop, parse_verbs, stub_with_session_verbs,
};
use daemon_proton_support::{DECLARED, LISTING, session_dir};
use support::backend::Backend;
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::generations::{current_generation, generation_dirs, publish_generation};
use support::proton::{Listing, stub_pass_cli_listing};
use support::{PROTON_DECOY, scratch};

// ---------------------------------------------------------------------------
// Generations: the loop establishes each session in a fresh directory, swaps
// the pointer, and retires what it superseded — never touching the one it is
// serving from.
// ---------------------------------------------------------------------------

fn basename(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

#[test]
fn a_renewal_never_logs_out_the_generation_current_names() {
    let dir = scratch("daemon-proton-gen-never-logs-out-current");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    // CONTROL — the change that makes this fail: `timeout_ms: 60_000`
    // (grace 123s, past the 30s this test runs for), the shape this fixture
    // carried before `Generations::candidates` was fixed to anchor a
    // candidate at its own successor's minted time (F3) rather than at
    // `current`'s mtime. `login_after_minutes: 0` keeps every tick due, so
    // under the pre-fix anchor `current`'s mtime was refreshed to "now" on
    // every renewal and no candidate ever cleared the grace — the `for` loop
    // below would iterate an empty set and the `any(logout)` assertion
    // would fail on a run that never logged anything out at all. `3_000`
    // (grace 9s) against a 30s run with a fresh renewal every second is
    // exactly the "sweep lands in the same tick as a publish" case F3
    // fixes, so this is now a real proof of it: logouts DO happen, and none
    // of them ever names the generation `current` held at that instant.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 3_000);
    let running = start_daemon(&config, policy_allowing_self());

    // Comfortably enough ticks (each at least MIN_INTERVAL apart) for the
    // "≥ 2 distinct generations" claim below to be non-trivial.
    std::thread::sleep(Duration::from_secs(30));

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);

    for line in &lines {
        if line.verb != "logout" {
            continue;
        }
        assert_ne!(
            basename(&line.dir),
            line.current,
            "a logout ran against the generation `current` named at that instant: {}",
            line.dir
        );
    }

    // Without this, the loop above proves nothing whenever no candidate ever
    // clears the grace — exactly the state the pre-F3 anchor left this test
    // in, silently, forever.
    assert!(
        lines.iter().any(|line| line.verb == "logout"),
        "no logout ran at all in 30s, so the loop above checked an empty set: {lines:?}"
    );

    let distinct_logins: std::collections::BTreeSet<&str> = lines
        .iter()
        .filter(|line| line.verb == "login")
        .map(|line| line.dir.as_str())
        .collect();
    assert!(
        distinct_logins.len() >= 2,
        "fewer than two distinct generations were logged into in 30s: {distinct_logins:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_generation_the_daemon_retires_is_logged_out_then_removed_and_current_survives() {
    // CONTROL — the change that makes this fail: `retire` treating every
    // candidate as already logged out and never spawning a logout at all.
    // The directory still disappears (`remove` does not depend on the
    // logout outcome), so only the `any(logout && …)` assertion below
    // catches it: "the superseded generation disappeared with no logout
    // line ahead of it."
    //
    // `login_after_minutes: 0` forces the FIRST tick to renew (`established`
    // starts `None`, which is always due); the LARGE `login_after_minutes`
    // here keeps every tick after that one not-due, so exactly one renewal
    // happens and the root's only candidate is the generation this fixture
    // published up front. `Generations::candidates` anchors that candidate
    // at its successor's own minted time — fixed the instant the forced
    // renewal mints it, and untouched by anything published later — so the
    // grace clears on an ordinary later tick that does nothing but sweep,
    // whether or not a further renewal ever runs. A run where every tick
    // renews is exercised on its own, against real retirements, by
    // `a_renewal_never_logs_out_the_generation_current_names`.
    let dir = scratch("daemon-proton-gen-retires");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, true, LogoutAnswer::Ok, None);
    let root = session_dir(&dir);
    let before = publish_generation(&root);
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 1, 3_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root_generation = before
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();

    // Polled rather than a fixed sleep: the forced first renewal and the
    // grace (9s) both complete quickly on an idle machine, but this only
    // widens the WAIT for a loaded one — the grace arithmetic itself is
    // fixed, so a generous ceiling here never turns a genuine non-convergence
    // into a false green.
    //
    // Two phases, not one: `root_generation` itself already satisfies
    // "exactly one directory, and it is current" the instant this fixture
    // publishes it, before the loop's thread has run at all — so convergence
    // is only meaningful once a DIFFERENT generation has actually landed.
    let renewed = Instant::now() + Duration::from_secs(60);
    let current = loop {
        match current_generation(&root) {
            Some(name) if name != root_generation => break name,
            _ => {}
        }
        assert!(
            Instant::now() < renewed,
            "the loop never performed its forced first renewal, so nothing here is under test"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let converged = Instant::now() + Duration::from_secs(60);
    loop {
        let remaining = generation_dirs(&root);
        if remaining == vec![current.clone()] {
            break;
        }
        assert!(
            Instant::now() < converged,
            "the root did not converge to exactly the current generation: {remaining:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    assert!(
        lines
            .iter()
            .any(|line| line.verb == "logout" && basename(&line.dir) == root_generation),
        "the superseded generation disappeared with no logout line ahead of it"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_login_that_succeeds_but_does_not_answer_info_is_discarded_and_current_is_unchanged() {
    // CONTROL — the change that makes this fail: `establish` never
    // discarding on a failed `info` (publishing every login regardless).
    // `generation_dirs` grows past `[g0]` and never converges back, so the
    // first polling loop below runs out its 30s deadline and panics naming
    // every generation that piled up instead of being discarded.
    let dir = scratch("daemon-proton-gen-info-fails");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    // `info` never answers: every login this loop performs succeeds and is
    // then discarded, so `current` must stay exactly where the fixture put it.
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, false, LogoutAnswer::Ok, None);
    let root = session_dir(&dir);
    let published = publish_generation(&root);
    let g0 = published
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();
    // `60_000` — nothing here is about the grace: a discard runs immediately,
    // with no drain and no grace at all (see `discard_unpublished`).
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    // CONTROL — the change that makes this fail: dropping the first phase
    // below and polling `generation_dirs(&root) == vec![g0]` alone, which
    // is already true the INSTANT `publish_generation` writes it above,
    // before the daemon has even started — the `dirs:?}"` message would
    // never print because the loop breaks on its first iteration and the
    // property "a login that could not answer `info` was discarded" would
    // be unexercised. So this waits for evidence the loop actually
    // attempted more than one login FIRST — the same two-phase shape
    // `a_generation_the_daemon_retires_is_logged_out_then_removed_and_
    // current_survives` uses for the identical hazard — and only then
    // checks that nothing any of those attempts produced survived.
    let attempted = Instant::now() + Duration::from_secs(30);
    loop {
        let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
        let logins = parse_verbs(&verbs)
            .iter()
            .filter(|line| line.verb == "login")
            .count();
        if logins >= 2 {
            break;
        }
        assert!(
            Instant::now() < attempted,
            "the loop never attempted two logins, so nothing here is under test"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Polled rather than a single fixed sleep: a discard is a few subprocess
    // spawns this MACHINE'S load decides the speed of, and the property under
    // test is that it removes what it creates, not how fast it runs. A
    // generous ceiling still catches a discard that never happens at all.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let dirs = generation_dirs(&root);
        if dirs == vec![g0.clone()] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a login that could not answer `info` was not discarded: {dirs:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        current_generation(&root).as_deref(),
        Some(g0.as_str()),
        "current changed even though every login could not be verified"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_renewal_whose_old_store_cannot_be_decrypted_still_establishes_a_new_generation_and_reads_succeed()
 {
    // CONTROL — the change that makes this fail: `retire` treating every
    // candidate as already logged out (never spawning the plain logout at
    // all, so the force step it would otherwise trigger never runs either).
    // The old generation is still removed either way, so only the
    // `logout_then_force` pair assertion below catches the missing step.
    let dir = scratch("daemon-proton-gen-old-store-undecryptable");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    // Plain logout answers with the vendor's own aead sentence and fails;
    // `--force` (handled unconditionally by the stub) succeeds — the shape a
    // generation nothing can decrypt produces.
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::Fails(
            "Error decrypting local session(Error decrypting session: aead::Error)",
        ),
        None,
    );
    let root = session_dir(&dir);
    let before = publish_generation(&root);
    // `login_after_minutes: 90` for the reason
    // `a_generation_the_daemon_retires_is_logged_out_then_removed_and_current_survives`
    // gives in full: the forced first tick (`established` starts `None`) is
    // the only renewal this run performs, so the old generation's one and
    // only successor is minted once and its grace clears on a later,
    // sweep-only tick.
    // `10_000` rather than `3_000`: this case performs a READ at the end, and
    // `timeout_ms` is the store's own per-call ceiling as well as the input the
    // grace derives from — so the small value that kept the grace short also
    // gave a stub spawn three seconds to answer on a machine running several
    // suites at once, which it does not always manage. The grace grows to 23s
    // and still clears inside the 60s deadline below.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 1, 10_000);
    let running = start_daemon(&config, policy_allowing_self());

    let old_generation = before
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();

    // Polled rather than a fixed sleep, for the same reason every other
    // generations case in this file polls: the grace (9s) is a fixed
    // arithmetic fact and does not need widening, but the subprocess spawns
    // around it do, on a loaded machine.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if !generation_dirs(&root).contains(&old_generation) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the undecryptable old generation was never removed"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let client = client_config(running.socket(), 10_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { .. } => {}
        other => panic!(
            "a read must succeed once a new generation is established: {}",
            other.reason()
        ),
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    let logout_then_force = lines.windows(2).any(|pair| {
        pair[0].verb == "logout"
            && pair[1].verb == "logout"
            && basename(&pair[0].dir) == old_generation
            && pair[0].dir == pair[1].dir
    });
    assert!(
        logout_then_force,
        "no plain logout of the old generation was immediately followed by a force logout at \
         the same directory"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
