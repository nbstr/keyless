#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::time::{Duration, Instant, SystemTime};

use keyless::daemon::login;
use keyless::ipc::client::Client;
use keyless::ipc::protocol::{Reply, Request};
use keyless::store::proton_session::Generations;
use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::session_verbs::{
    LogoutAnswer, ReadProbe, daemon_config_with_generations_loop, stub_with_session_verbs,
};
use daemon_proton_support::{DECLARED, LISTING, TOKEN_DECOY, session_dir};
use support::backend::Backend;
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::generations::{current_generation, publish_generation, publish_generation_aged};
use support::proton::{Listing, stub_pass_cli_listing};
use support::{PROTON_DECOY, scratch};

#[test]
fn a_generation_published_by_another_process_is_served_at_the_daemons_next_read() {
    // CONTROL — the change that makes this fail: `Generations::enter`
    // memoizing the first successful read of `current` forever instead of
    // re-reading it on every call. The daemon's OWN first read still
    // resolves; the assertion that catches the staleness is the final one,
    // comparing what the SECOND read (after the out-of-band publish) was
    // actually scoped at against the new generation the other process just
    // published.
    let dir = scratch("daemon-proton-gen-cross-process");
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
    publish_generation(&root);
    // A slow probe interval — the point is that the daemon's OWN loop never
    // ticks during this test, so any change `current` shows must have come
    // from the out-of-band `establish` call below. `60_000` — nothing here is
    // timed against the grace.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 300, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 10_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!(
            "the fixture's own read must succeed first: {}",
            other.reason()
        ),
    }

    // A second process's `keylessd login --replace`, modelled as a direct
    // call against the SAME root — nothing here goes through the running
    // daemon or its loop.
    let coordinates = login::coordinates(&config).expect("valid coordinates");
    let audit = std::fs::metadata(dir.join("audit.jsonl")).expect("audit");
    use std::os::unix::fs::MetadataExt;
    let owner = login::Owner {
        uid: audit.uid(),
        gid: audit.gid(),
    };
    let outside = Generations::at(root.clone());
    let token = keyless::secret::Secret::new(TOKEN_DECOY.to_owned());
    login::establish(
        &coordinates,
        owner,
        true,
        &token,
        Vec::new(),
        &outside,
        &mut std::io::sink(),
    )
    .expect("the out-of-band login must succeed");

    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!("the next read must still resolve: {}", other.reason()),
    }
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        root.join(current_generation(&root).expect("the out-of-band login published a generation"))
            .display()
            .to_string(),
        "the daemon's next read was not scoped at the generation the other process published, \
         with no restart and no tick"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_read_already_in_flight_finishes_against_an_intact_directory_while_its_generation_is_retired() {
    // CONTROL. The property under test is that `Generations::drain` blocks a
    // retirement until every in-process reader of that generation has
    // finished — see `Generations::remove`'s own doc: it is the last guard,
    // and this case is what proves the guard the DRAIN provides is load-
    // bearing rather than redundant with it. Neutering `drain` (returning
    // `Ok(())` without waiting on `self.changed`) makes retirement run the
    // instant the candidate is eligible, deleting `original` while the read
    // below is still asleep inside the stub — its end-of-run check then finds
    // the marker gone and records `missing`. This was run both ways; see the
    // report for both outcomes.
    let dir = scratch("daemon-proton-gen-read-survives-retirement");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );

    let read_witness = dir.join("read.witness");
    let read_marker = "read-in-flight-marker";
    // How long the stand-in vendor holds `original` open before answering the
    // read. `Generations::candidates` anchors a candidate's eligibility at
    // `max(created_at, mtime(current))` (see that method's own doc), and
    // between them `current`'s mtime is the one this test can move without
    // waiting: after `original` is superseded, this file back-dates it
    // directly — the same shortcut `support::generations::publish_generation_aged`'s own
    // doc names ("the shape a retirement fixture needs to make a generation
    // eligible without waiting out a real grace period"), applied to a
    // `current` this daemon wrote rather than one this fixture minted. That
    // makes `original` eligible on the very next tick, at most one
    // `MIN_INTERVAL` (5s, `src/daemon/session.rs`) after it is superseded —
    // so 15s is several times that window, wide enough to absorb scheduling
    // jitter under a loaded machine and still be a small fraction of the 60s
    // `capture` ceiling `timeout_ms` below gives the stand-in vendor to
    // answer in.
    let read_delay = Duration::from_secs(15);
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        // Delays the RENEWAL's own login, not the read: this is what
        // guarantees the client read spawned below reaches `enter()` — and so
        // is scoped at `original` — before the renewal loop's forced first
        // tick can supersede it. Two seconds is generous margin over a socket
        // connect and one dispatch on an idle machine, and it is paid for
        // once, at the very start of the test.
        Duration::from_secs(2),
        true,
        LogoutAnswer::Ok,
        Some(ReadProbe {
            delay: read_delay,
            marker: read_marker,
            witness: read_witness.clone(),
        }),
    );

    let root = session_dir(&dir);
    // `timeout_ms` first, so `original`'s own age can be minted comfortably
    // past the grace it implies — see the loop below, which reuses this same
    // value.
    let timeout_ms: u64 = 60_000;
    let grace = login::grace(timeout_ms);
    // Minted with its OWN embedded creation time already past the grace,
    // because `Generations::candidates` takes the LATER of a candidate's own
    // age and `current`'s mtime — back-dating `current` alone, without also
    // back-dating `original`'s own name, would still read as young the
    // moment a later publish (the renewal below) refreshes `current`'s mtime
    // to now. Both anchors are aged here, by different, generous margins, so
    // neither one alone decides eligibility.
    let original = publish_generation_aged(&root, grace + Duration::from_secs(60));
    std::fs::write(original.join(read_marker), b"still-here")
        .expect("plant the in-flight read's own marker");
    let original_name = original
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();

    // `login_after_minutes: 90` for the reason
    // `a_generation_the_daemon_retires_is_logged_out_then_removed_and_current_survives`
    // gives in full: the forced first tick is the loop's only renewal, and
    // every tick after that finds the new generation `alive` and does
    // nothing but sweep.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 1, timeout_ms);
    let running = start_daemon(&config, policy_allowing_self());

    // The read the invariant is about. Issued the instant the daemon is up,
    // while `current` still names `original` — the renewal loop's own login
    // is asleep for two seconds (above), which is ample margin for this call
    // to reach `enter()`, scoped at `original`, before anything else can move
    // `current`. It blocks inside the stub for `read_delay` before
    // answering, so it runs on its own thread.
    let client = Client::new(running.socket().to_path_buf(), Duration::from_secs(30));
    let read = std::thread::spawn(move || client.request(&Request::resolve(DECLARED)));

    // Wait for the renewal to supersede `original`, then remove the only
    // thing standing between it and immediate eligibility: the freshness of
    // `current`'s own mtime, which the renewal's own publish just refreshed
    // to now. See the comment on `read_delay` above for what this unlocks.
    let superseded = Instant::now() + Duration::from_secs(30);
    let current_path = root.join("current");
    loop {
        match current_generation(&root) {
            Some(name) if name != original_name => break,
            _ => {}
        }
        assert!(
            Instant::now() < superseded,
            "the renewal loop never superseded the original generation"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let ancient = SystemTime::now()
        .checked_sub(grace + Duration::from_secs(30))
        .expect("the clock supports a date this far back");
    std::fs::File::options()
        .write(true)
        .open(&current_path)
        .expect("open current to back-date it")
        .set_modified(ancient)
        .expect("back-date current's mtime");

    // Poll for the retirement this back-dating unlocks: `original`'s
    // directory disappearing. This loop is not the assertion that the read
    // survived it — the witness log below is — it only bounds how long the
    // whole test waits, generously, for the retirement to happen at all.
    let retired = Instant::now() + Duration::from_secs(90);
    while original.exists() {
        assert!(
            Instant::now() < retired,
            "the original generation was never retired: {}",
            original.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    match read.join().expect("the read thread panicked") {
        Ok(Reply::Value(secret)) => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!("the in-flight read must still return its value: {other:?}"),
    }

    // The property itself: the stub's own end-of-run check, read back from
    // the OTHER side of the interface rather than inferred from the read's
    // success — `inner` answers with the decoy regardless of which directory
    // it was scoped at, so a read that succeeds proves nothing here on its
    // own.
    let witness = std::fs::read_to_string(&read_witness).unwrap_or_default();
    assert_eq!(
        witness.trim(),
        "intact",
        "the in-flight read's own directory was not intact when it finished: {witness:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
