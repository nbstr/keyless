#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::time::{Duration, Instant};

use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::session_verbs::{
    LogoutAnswer, daemon_config_env_with_key, daemon_config_with_generations_loop,
    daemon_config_with_generations_loop_env, parse_verbs, stub_with_session_verbs,
};
use daemon_proton_support::{DECLARED, ENCRYPTION_KEY_DECOY, LISTING, session_dir};
use support::backend::Backend;
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::generations::current_generation;
use support::proton::{Listing, stub_pass_cli_listing};
use support::{PROTON_DECOY, scratch};

#[test]
fn a_fs_daemon_never_sets_the_local_key_variable_at_all() {
    // CONTROL for the case below: under `fs` no credential names
    // `PROTON_PASS_ENCRYPTION_KEY`, so `login::extra_credentials` resolves
    // nothing and the variable never reaches a child at all — not empty,
    // UNSET. Read before the `env` case so a fixture bug that made every
    // spawn's `key_len` read `<unset>` regardless of provider cannot pass
    // both tests by accident: this one is the one that is SUPPOSED to see
    // `<unset>`.
    let dir = scratch("daemon-proton-key-fs");
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
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if current_generation(&root).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    assert!(!lines.is_empty(), "the stand-in recorded nothing");
    for line in &lines {
        assert_eq!(
            line.key_provider, "fs",
            "`{}` at {} did not carry `PROTON_PASS_KEY_PROVIDER=fs`",
            line.verb, line.dir
        );
        assert_eq!(
            line.key_len, "<unset>",
            "`{}` at {} carried a local-key variable under `fs`, which owns no such value",
            line.verb, line.dir
        );
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_proton_spawn_under_env_carries_the_key_provider_and_the_local_keys_length() {
    // The defect this proves closed: `daemon::login::info_command` and
    // `logout_command` used to be built with `&[]`, so the vendor was asked
    // to open a session under `key_provider: env` with nothing to open it
    // WITH — the same shape of bug review already caught once in
    // `ProtonStore::info_probe_command` (`&[]` where every other builder
    // passed the login), just in the sibling module that spawns `login`,
    // `info` and `logout` rather than the one that spawns `run`/`item`/
    // `vault`. Reverting `establish`'s `info_command` call back to `&[]`
    // turns this red: every `info` line reports `key_len=<unset>` while
    // `login` still carries it. The retirement `logout` is the case below.
    let dir = scratch("daemon-proton-key-env");
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
    // The suite's generous ceiling, because this case waits on a READ and not
    // on the grace: `timeout_ms` is the store's own read ceiling as well as
    // the input the retirement grace is derived from, so a value small enough
    // to retire quickly is also a deadline the read has to beat on a machine
    // running four test binaries at once. The retirement half is its own case
    // below, which waits on the grace and reads nothing.
    let config = daemon_config_with_generations_loop_env(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if current_generation(&root).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // A real read too, so the assertion below covers the verbs a LOOKUP
    // spawns and not only the login flow's own three.
    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { .. } => {}
        other => panic!("a declared name must resolve: {}", other.reason()),
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    assert!(!lines.is_empty(), "the stand-in recorded nothing");
    let expected_len = ENCRYPTION_KEY_DECOY.len().to_string();
    let mut verbs_seen = std::collections::BTreeSet::new();
    for line in &lines {
        verbs_seen.insert(line.verb.clone());
        assert_eq!(
            line.key_provider, "env",
            "`{}` at {} did not carry `PROTON_PASS_KEY_PROVIDER=env`",
            line.verb, line.dir
        );
        assert_eq!(
            line.key_len, expected_len,
            "`{}` at {} did not carry the local key — carries no value, only its length",
            line.verb, line.dir
        );
    }
    for verb in ["login", "info"] {
        assert!(
            verbs_seen.contains(verb),
            "`{verb}` never ran, so this run proves nothing about it: {verbs_seen:?}"
        );
    }
    assert!(
        verbs_seen
            .iter()
            .any(|verb| !["login", "info", "logout"].contains(&verb.as_str())),
        "only login-flow verbs ran, so the lookup path is unproven here: {verbs_seen:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_daemon_whose_key_was_never_written_generates_one_and_logs_in_without_a_restart() {
    // The outage of 2026-09-11, end to end. A machine moved to `key_provider:
    // env` whose first start lost the race to generate the key served no
    // Proton name for twenty minutes, because generation happened once at
    // start and nothing tried again — the renewal loop logged the same
    // failure every tick while holding the one thing that could have fixed it.
    //
    // CONTROL, and the reason this case is about the LOOP rather than about
    // the generator: the harness builds the daemon directly, so `serve`'s own
    // start-time generation never runs here. Every key this case sees is one
    // the loop generated. Reverting `report_key_generation` out of the due
    // branch turns it red with the vendor never carrying a key at all.
    let dir = scratch("daemon-proton-key-absent");
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
    let config = daemon_config_env_with_key(&dir, &vendor, 0, 1, 60_000, false);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if current_generation(&root).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published, so the loop never recovered from a missing key"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    assert!(!lines.is_empty(), "the stand-in recorded nothing");
    for line in &lines {
        assert_eq!(
            line.key_provider, "env",
            "`{}` did not carry `PROTON_PASS_KEY_PROVIDER=env`",
            line.verb
        );
        // The generated length, not a decoy's: nothing wrote this value but
        // the daemon, so its length is the generator's own and a literal is
        // the only oracle this case can hold it to.
        assert_eq!(
            line.key_len, "43",
            "`{}` ran without the key the loop was supposed to generate",
            line.verb
        );
    }

    // ONE key, not merely one of the right length. Every key this generator
    // draws is 43 characters, so a length oracle passes a run that generated a
    // key, published a session under it, and then wrote a second one over it —
    // which is precisely the corruption a claim exists to prevent, and the
    // reason the stand-in records a fingerprint.
    let fingerprints: std::collections::BTreeSet<_> =
        lines.iter().map(|line| line.key_fp.clone()).collect();
    assert_eq!(
        fingerprints.len(),
        1,
        "the vendor was handed more than one local key across this run: {fingerprints:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_retirement_logout_under_env_carries_the_key_it_needs_to_end_the_session() {
    // The other half of the case above, split off it because the two want
    // opposite things from `timeout_ms`: this one waits on the retirement
    // GRACE (`2 × timeout_ms + 2s + 1s`), so it wants that number small, and
    // it reads nothing through the daemon, so a small read ceiling costs it
    // nothing.
    //
    // The defect it pins: `retire` built `logout_command` with `&[]`, so
    // under `KeyProvider::Env` the plain logout that ends a superseded
    // session's account side could not open that session at all — it failed
    // on the missing key, fell through to `--force`, and left the account
    // session to expire on the vendor's own clock instead of being ended.
    let dir = scratch("daemon-proton-key-env-retire");
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
    // `3_000` (grace 9s) with `login_after_minutes: 0`: a renewal every tick,
    // so a superseded generation clears the grace inside a run short enough
    // for CI.
    let config = daemon_config_with_generations_loop_env(&dir, &vendor, 0, 1, 3_000);
    let running = start_daemon(&config, policy_allowing_self());

    let deadline = Instant::now() + Duration::from_secs(60);
    let logouts = loop {
        let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
        let lines: Vec<_> = parse_verbs(&verbs)
            .into_iter()
            .filter(|line| line.verb == "logout")
            .collect();
        if !lines.is_empty() {
            break lines;
        }
        assert!(
            Instant::now() < deadline,
            "no retirement logout ran in time, so this case proves nothing"
        );
        std::thread::sleep(Duration::from_millis(200));
    };

    let expected_len = ENCRYPTION_KEY_DECOY.len().to_string();
    for line in &logouts {
        assert_eq!(
            line.key_provider, "env",
            "the retirement logout at {} did not carry `PROTON_PASS_KEY_PROVIDER=env`",
            line.dir
        );
        assert_eq!(
            line.key_len, expected_len,
            "the retirement logout at {} did not carry the local key — carries no value, \
             only its length",
            line.dir
        );
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
