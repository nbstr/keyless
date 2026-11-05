use std::path::Path;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Generation fixtures.
//
// Filesystem only — nothing here shapes vendor-shaped behaviour, and nothing
// here spawns a `pass-cli` stand-in. `stub_pass_cli_listing` and its siblings
// already answer `run` / `item list` / `vault list`; what none of them did
// before this fixture existed was PUBLISH a generation for those verbs to be
// scoped at, which every daemon-hosted Proton read now needs before it
// resolves anything at all.
// ---------------------------------------------------------------------------

/// A counter distinguishing generations minted within one test process.
///
/// `GenerationName::mint` alone collides when two are minted in the same
/// process inside one millisecond — see its own doc. A fixture that publishes
/// several generations in a tight loop hits that far more often than
/// production ever does, so the pid half of the name is perturbed by this
/// counter rather than left to the real, constant `process::id()`.
static GENERATION_SEQUENCE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Publish a fresh generation into `root`, as a real `keylessd login` would,
/// and return its directory.
///
/// Every daemon-hosted Proton read now needs a valid `<root>/current` before
/// it resolves anything — see
/// `keyless::store::proton_session::Generations::current` — so a fixture that
/// wants an ordinary read to succeed calls this once before starting the
/// daemon.
pub fn publish_generation(root: &Path) -> PathBuf {
    publish_generation_aged(root, std::time::Duration::ZERO)
}

/// The same, minted `age` in the past with `current`'s own mtime pushed back
/// to match — the shape a retirement fixture needs to make a generation
/// eligible without waiting out a real grace period.
///
/// Also plants `.session/session.json`, the way a real `pass-cli login`
/// leaves the directory it just wrote to — see
/// [`keyless::store::proton::ProtonStore`]'s own structural session-fault
/// check, which reads exactly this path. A fixture whose case is the
/// vendor's own invalidation cleanup having removed it — see
/// `tests/daemon_proton_session_fault.rs`'s `a_missing_session_json_…` case —
/// deletes it after calling this, rather than this function ever omitting it: omitting
/// it by default would make every OTHER fixture here an unrealistic
/// directory the real vendor never produces.
pub fn publish_generation_aged(root: &Path, age: std::time::Duration) -> PathBuf {
    std::fs::create_dir_all(root).expect("create the generation root");
    let minted_at = std::time::SystemTime::now()
        .checked_sub(age)
        .expect("age must not underflow the epoch");
    let sequence = GENERATION_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let millis = minted_at
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock reads after the epoch")
        .as_millis();
    let name = format!("gen-{millis}-{}", std::process::id().wrapping_add(sequence));

    let dir = root.join(&name);
    std::fs::create_dir_all(&dir).expect("create the generation directory");
    let session_subdir = dir.join(".session");
    std::fs::create_dir_all(&session_subdir).expect("create .session");
    std::fs::write(session_subdir.join("session.json"), b"not a real session")
        .expect("plant session.json");

    let current = root.join("current");
    std::fs::write(&current, format!("{name}\n")).expect("write current");
    if age > std::time::Duration::ZERO {
        // Set only when back-dating: leaving `current`'s mtime at "now" is
        // what an ordinary, just-published generation looks like, and forcing
        // a `set_modified` call on every publish would make every fixture pay
        // for a mtime write it does not need.
        let file = std::fs::File::options()
            .write(true)
            .open(&current)
            .expect("open current to back-date it");
        file.set_modified(minted_at).expect("set current's mtime");
    }

    dir
}

/// The generation `<root>/current` names, or `None` when it is absent, empty
/// or unreadable.
///
/// A thin, test-only reader — never the validating one
/// `keyless::store::proton_session::Generations::current` is. A fixture
/// asserting on this is asserting on the bytes a real reader would then
/// validate, not re-deriving that validation itself.
pub fn current_generation(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("current")).ok()?;
    let trimmed = text.strip_suffix('\n').unwrap_or(&text);
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Every `gen-*` directory directly under `root`, by name, sorted.
pub fn generation_dirs(root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("gen-"))
        .collect();
    names.sort();
    names
}
