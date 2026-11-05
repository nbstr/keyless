#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::time::{Duration, Instant};

use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::session_verbs::{
    LogoutAnswer, daemon_config_with_generations_loop, parse_verbs, stub_with_session_verbs,
};
use daemon_proton_support::{DECLARED, ITEM, LISTING, VAULT, session_dir};
use support::backend::Backend;
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::generations::{current_generation, generation_dirs};
use support::proton::{Listing, stub_pass_cli_listing};
use support::{PROTON_DECOY, scratch, short_socket_path};

#[test]
fn a_legacy_session_directory_is_retired_and_never_served_from() {
    // CONTROL — this fails four different ways under four different faults.
    // Drop the `is_dir` gate from `Generations::candidates`'s legacy branch,
    // or gate the legacy candidate behind an age check the way an ordinary
    // generation is gated, and `.session` below never disappears before the
    // 30s deadline. Widen `ProtonStore::enter`'s own legacy fallback —
    // narrowly gated on `CurrentFault::Absent` plus the legacy directory
    // existing as a directory, see its own doc — to also answer once a
    // generation is current, or on any other `CurrentFault`, and the final
    // assertion below, which reads back the exact directory the read was
    // scoped at, stops naming a real generation. And widen `candidates` to
    // admit the legacy candidate before any generation has ever published —
    // the ordering check near the end, over every `pass-cli.verbs` line,
    // catches a `logout` scoped at the root ahead of the first `login`.
    let dir = scratch("daemon-proton-gen-legacy-retired");
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
    let root = session_dir(&dir);

    // The pre-existing layout a machine upgrading in place carries into this
    // change: a `.session` directory the OLD, pre-generations code wrote,
    // with a marker standing in for the real session store. Planted before
    // the daemon ever starts, so the very first thing this daemon does with
    // its session directory is decide what to do about a layout it did not
    // create.
    let legacy = root.join(".session");
    std::fs::create_dir_all(&legacy).expect("create the legacy layout");
    std::fs::write(legacy.join("session.json"), b"legacy-marker").expect("plant the legacy marker");

    // `60_000` — this case is not about the grace: `Generations::candidates`
    // makes the legacy candidate eligible the instant a first generation
    // publishes, with no age check of its own, so nothing here is timed
    // against a grace at all.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    // Polled rather than a fixed sleep, the same shape every other
    // generations case in this file uses: this only waits on subprocess
    // spawns this machine's load decides the speed of.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // Whenever `current` names anything at all, it must name a real
        // generation directory and nothing else — never the legacy layout,
        // which no `GenerationName` ever parses — and a read performed at
        // that instant must succeed. A read performed before any generation
        // is current is not attempted here: it is expected to degrade, and
        // asserting success on it would prove nothing about the legacy
        // directory either way.
        if let Some(name) = current_generation(&root) {
            assert!(
                generation_dirs(&root).contains(&name),
                "`current` named {name}, which is not a generation directory under {}",
                root.display()
            );
            match registry.resolve(DECLARED) {
                Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
                other => panic!(
                    "a read failed once a generation was current: {}",
                    other.reason()
                ),
            }
        }
        if !legacy.exists() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the legacy session directory was never retired: {}",
            legacy.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // One last read, after the legacy directory is confirmed gone, checked
    // against the OTHER side of the interface — the directory the stub was
    // actually handed — rather than trusted on its return value alone. A
    // fallback that quietly pointed a read at `root` itself (rather than
    // degrading, or rather than the published generation) would still return
    // the stub's decoy, since `Backend::Injects` answers regardless of scope;
    // this is the assertion that would catch it.
    let current = current_generation(&root).expect("the loop never published a generation");
    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!("the final read must succeed: {}", other.reason()),
    }
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        root.join(&current).display().to_string(),
        "a read was scoped somewhere other than the published current generation"
    );

    // The scope invariant over every line this whole run produced, not the
    // single last-read sample above, plus the ordering S9 names: no `run`
    // or `item` line is ever scoped at the root, and no `logout` at the
    // root — the legacy candidate's own scope — runs before the first
    // `login`, which is what would prove the legacy candidate was retired
    // before any generation existed to make it eligible.
    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    let root_str = root.display().to_string();
    for line in &lines {
        if matches!(line.verb.as_str(), "run" | "item" | "vault") {
            assert_ne!(
                line.dir, root_str,
                "a `{}` was scoped at the root instead of a generation",
                line.verb
            );
        }
    }
    let first_login = lines
        .iter()
        .position(|line| line.verb == "login")
        .expect("the loop never logged in at all");
    assert!(
        lines[..first_login]
            .iter()
            .all(|line| !(line.verb == "logout" && line.dir == root_str)),
        "a legacy logout at the root ran before the first login: {:?}",
        &lines[..first_login]
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_daemon_with_no_renewal_loop_and_only_the_legacy_layout_reads_from_it_instead_of_degrading() {
    // Consumer F1: an install with `session.auto_login` off (the default)
    // runs no renewal loop, so nothing ever writes `<root>/current` — and a
    // pre-upgrade install's real, working session sits at `<root>/.session`,
    // the layout this crate wrote before generations existed. Planted here
    // and never touched by a loop, since this daemon's config carries no
    // `session` block at all.
    let dir = scratch("daemon-proton-legacy-only-no-loop");
    let vendor = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let root = session_dir(&dir);
    let legacy = root.join(".session");
    std::fs::create_dir_all(&legacy).expect("plant the pre-generation layout");
    std::fs::write(legacy.join("session.json"), b"pre-upgrade session")
        .expect("plant the legacy marker");

    let config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(&dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = root.display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config");
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!(
            "a legacy-only root with no renewal loop must still resolve: {}",
            other.reason()
        ),
    }
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        root.display().to_string(),
        "the read was not scoped at the root the legacy layout lives under"
    );
    assert!(
        current_generation(&root).is_none(),
        "no renewal loop ran, so `current` must still name nothing"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
