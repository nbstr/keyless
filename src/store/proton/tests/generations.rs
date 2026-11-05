use super::{SCOPED, parts_store, scratch};
use crate::error::StoreError;
use crate::store::proton::session_dir::{SESSION_FILE, SESSION_SUBDIR, session_file_present};
use crate::store::proton::store::ProtonStore;
use crate::store::proton_session::Generations;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[test]
fn session_file_present_reads_the_generations_own_session_json() {
    // CONTROL — the change that makes this fail: checking `session_dir`
    // (the daemon's root) instead of the generation directory the caller
    // hands in, which would read `true` here even though nothing was
    // ever planted at the path under test.
    let dir = std::env::temp_dir().join(format!(
        "keyless-tests-session-file-present-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");

    assert!(
        !session_file_present(&dir),
        "an empty generation directory reported a session file"
    );

    let session_subdir = dir.join(SESSION_SUBDIR);
    std::fs::create_dir_all(&session_subdir).expect("session subdir");
    std::fs::write(session_subdir.join(SESSION_FILE), b"{}").expect("plant session.json");

    assert!(
        session_file_present(&dir),
        "a planted session.json was not found"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_store_with_no_generations_reads_its_configured_directory_directly() {
    // The session side has no renewal loop, so it has no `Generations` —
    // and `enter()` still has to answer with somewhere to read, which is
    // the directory the config named, taken verbatim.
    let store = parts_store().in_session_dir(Some(std::path::PathBuf::from(SCOPED)));
    let pass = store.enter().expect("no generations is not a refusal");
    assert_eq!(
        pass.dir(),
        Path::new(SCOPED),
        "the session-side pass did not read the configured directory"
    );
}

#[test]
fn a_read_is_never_made_to_wait_for_a_renewal() {
    // A renewal in progress must never make an ordinary read pause, let
    // alone time out. Proven against a real `Generations` under real,
    // continuous publishing pressure from another thread, rather than
    // against a single replace.
    let dir = scratch("read-never-waits");
    let generations = Arc::new(Generations::at(dir.clone()));
    let (first, _) = generations
        .create(None)
        .expect("create the first generation");
    generations
        .publish(&first, None)
        .expect("publish the first generation");

    let store = parts_store()
        .in_session_dir(Some(dir.clone()))
        .with_generations(Some(Arc::clone(&generations)));

    let stop = Arc::new(AtomicBool::new(false));
    let publisher = {
        let generations = Arc::clone(&generations);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok((name, _)) = generations.create(None) {
                    let _ = generations.publish(&name, None);
                }
            }
        })
    };

    // A read that ever waited on the publisher would show up here: a
    // single `enter()` has nothing to do but read one small file, so any
    // one of two hundred calls taking anywhere near a network-sized delay
    // means a read was made to wait.
    for _ in 0..200 {
        let started = Instant::now();
        let pass = store
            .enter()
            .expect("a read must never be refused by a renewal");
        drop(pass);
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "a read waited on a renewal in progress"
        );
    }

    stop.store(true, Ordering::Relaxed);
    publisher.join().expect("the publishing thread panicked");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_read_with_no_current_generation_degrades_at_once_and_says_no_session_is_established() {
    let dir = scratch("read-no-current");
    let generations = Arc::new(Generations::at(dir.clone()));
    let store = parts_store()
        .in_session_dir(Some(dir.clone()))
        .with_generations(Some(Arc::clone(&generations)))
        .with_timeout(60_000);

    let started = Instant::now();
    let error = store
        .enter()
        .expect_err("a root with no published generation must degrade");
    let took = started.elapsed();

    assert!(
        matches!(error, StoreError::Unavailable { .. }),
        "an unestablished session was reported as a verdict on the item: {error}"
    );
    assert!(
        error.to_string().contains("established"),
        "the refusal does not say no session has been established: {error}"
    );
    assert!(
        took < Duration::from_secs(1),
        "a fresh root made a read wait out something instead of degrading at once: {took:?}"
    );
    assert!(
        generations.session_fault_pending(),
        "an absent `current`, with no legacy directory to fall back to, degraded the \
         read without filing a fault — the renewal loop waits out its next ordinary \
         probe instead of replacing it within the fault backoff"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A store and its `Generations`, over a fresh root whose `current` holds
/// `contents` verbatim — the shape every broken-pointer test below reads
/// `enter()` against.
fn store_over_current(
    tag: &str,
    contents: &str,
) -> (std::path::PathBuf, Arc<Generations>, ProtonStore) {
    let dir = scratch(tag);
    std::fs::write(dir.join("current"), contents).expect("write current");
    let generations = Arc::new(Generations::at(dir.clone()));
    let store = parts_store()
        .in_session_dir(Some(dir.clone()))
        .with_generations(Some(Arc::clone(&generations)))
        .with_timeout(60_000);
    (dir, generations, store)
}

#[test]
fn a_read_against_a_malformed_current_degrades_and_files_a_fault() {
    let (dir, generations, store) =
        store_over_current("read-malformed-current", "not a generation name\nmore\n");

    let error = store
        .enter()
        .expect_err("a malformed current must degrade the read");

    assert!(
        matches!(error, StoreError::Unavailable { .. }),
        "a malformed pointer was reported as a verdict on the item: {error}"
    );
    assert!(
        generations.session_fault_pending(),
        "a malformed `current` degraded the read without filing a fault"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_read_naming_a_generation_that_is_not_there_degrades_and_files_a_fault() {
    let (dir, generations, store) = store_over_current("read-missing-generation", "gen-1-1\n");

    let error = store
        .enter()
        .expect_err("current naming an absent generation must degrade the read");

    assert!(
        matches!(error, StoreError::Unavailable { .. }),
        "a pointer naming an absent generation was reported as a verdict on the item: {error}"
    );
    assert!(
        generations.session_fault_pending(),
        "current naming a missing generation degraded the read without filing a fault"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_retirement_waits_for_the_readers_of_that_generation_alone() {
    // The `ProtonStore::enter` + `Generations::drain` seam: a retirement
    // of one generation must wait for readers of THAT generation, and
    // must not touch readers of the one that replaced it.
    let dir = scratch("retire-waits-for-readers");
    let generations = Arc::new(Generations::at(dir.clone()));
    let (old, _) = generations.create(None).expect("create the old generation");
    generations
        .publish(&old, None)
        .expect("publish the old generation");

    let store = parts_store()
        .in_session_dir(Some(dir.clone()))
        .with_generations(Some(Arc::clone(&generations)));

    let held = store.enter().expect("a pass over the old generation");
    assert_eq!(held.dir(), dir.join(old.as_str()));

    let (new, _) = generations.create(None).expect("create the new generation");
    generations
        .publish(&new, None)
        .expect("publish the new generation");

    // A fresh read now goes to the NEW generation, and is never blocked by
    // the pass still held on the old one.
    let fresh = store.enter().expect("a read must not wait on a retirement");
    assert_eq!(fresh.dir(), dir.join(new.as_str()));
    drop(fresh);

    let waiting = Arc::clone(&generations);
    let old_for_thread = old.clone();
    let drain = std::thread::spawn(move || {
        waiting
            .drain(&old_for_thread, Duration::from_secs(5))
            .is_ok()
    });

    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !drain.is_finished(),
        "the retirement did not wait for the old generation's own reader"
    );

    drop(held);
    assert!(
        drain.join().expect("the drain thread panicked"),
        "the retirement never noticed the reader had gone"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
