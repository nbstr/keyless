//! Whether the binary answering you was built from the source beside it.
//!
//! # The failure this exists to catch
//!
//! `keyless` on a developer's `PATH` is a symlink or a copy pointing at a build
//! directory, and nothing rebuilds it. Staleness there is not an accident that
//! befalls an unlucky install; it is what the arrangement produces by default.
//! A build directory changes only when somebody runs `cargo build`, and nothing
//! about invoking `keyless` runs one — so the binary reached through `PATH` is
//! as old as the last build, however many commits ago that was, while the
//! checkout beside it keeps moving. A developer install under a home directory
//! and a system-wide one under `/usr/local/bin` have exactly the same shape,
//! so neither is the safer of the two.
//!
//! Nothing about that looks wrong. The binary runs, answers, and reports its
//! own health as fine — about code nobody is reading. The specific harm is not
//! a crash: it is a fix that has landed in the source and is absent from the
//! program. The commit before this one closed a false green in which a lookup
//! answered from the caller's own environment; a stale binary still has it, and
//! still writes `INJECTED` while doing it.
//!
//! # A symlink is not the problem, and replacing it with a copy is not the fix
//!
//! Pointing `PATH` at a build directory through a symlink is the SHORTER
//! staleness window of the two available: it follows every
//! `cargo build --release`, where a copy is frozen at install time and moves
//! only when somebody re-installs. The check below covers both, because
//! [`std::env::current_exe`] resolves the link and reads the mtime of whatever
//! is really running.
//!
//! # Why an mtime and not a git sha
//!
//! A sha embedded at build time would make `--version` say which COMMIT this
//! binary is, which `0.1.0` never can. It is the wrong instrument for THIS
//! question, for three reasons:
//!
//! - **It answers identification, not staleness.** A sha is only comparable to
//!   `HEAD` where a checkout exists — which is exactly where the comparison
//!   below already works, and where it works better, because an uncommitted
//!   edit moves an mtime and moves no sha.
//! - **It costs a build script**, which is arbitrary code running at build time
//!   in a crate whose auditability is the product and whose entire dependency
//!   list is five crates. That is a real price for a version string.
//! - **The stamp itself goes stale.** A build script that declares
//!   `rerun-if-changed` on `.git/HEAD` does not re-run for an uncommitted edit,
//!   and one that declares nothing re-runs on every touch. Either way a `-dirty`
//!   flag is a claim the mechanism cannot keep.
//!
//! What the binary knows for free is enough: **where it was built**
//! (`CARGO_MANIFEST_DIR`, a compile-time constant) and **when it was built**
//! (its own mtime, through [`std::env::current_exe`]). Those two answer the
//! question exactly.
//!
//! # The rule is cargo's own
//!
//! Cargo decides a target is fresh by comparing mtimes: a source newer than the
//! artefact means a rebuild. This module asks the same question of the
//! artefact you are actually running. So "stale" here means precisely "cargo
//! would rebuild this", and the check cannot drift into a private definition of
//! freshness that disagrees with the tool that produces the binary.
//!
//! # What it cannot see, stated rather than implied
//!
//! - **Whether that source tree is itself current.** This is the big one, and
//!   it is not a corner case: a checkout six commits behind builds a binary
//!   that is `Current` by this rule, because the source WAS the source — and
//!   `keyless doctor` prints `build proven` over it, correctly by its own
//!   logic, while the program is missing every fix in those commits.
//!   [`crate::checkout`] is the other half and it answers only that question — the two are
//!   independent, and neither subsumes the other: an uncommitted edit moves an
//!   mtime and moves no ref.
//! - **A copy whose mtime was reset.** `install -p` preserves the build time;
//!   without `-p` the copy is stamped at install time and a binary built before
//!   an edit can look newer than it. `install/install.sh` passes `-p` and
//!   refuses to install a binary that is already stale, which is why both halves
//!   are there.
//! - **Which commit this is.** It reports that the binary is behind the tree, not
//!   by how much. `git log` answers that and this does not try to.
//! - **A second checkout.** It compares against the tree this binary was BUILT
//!   from, which is the only tree it can name. Where two clones of this
//!   repository sit side by side and only one of them built what is on `PATH`,
//!   work landing in the sibling is invisible here — and would be invisible to
//!   an embedded git sha for exactly the same reason. Nothing inside a binary
//!   can know about a directory it was never compiled in.
//! - **A machine with no source tree.** A binary installed from a release has
//!   nothing to compare against, and this reports nothing at all rather than
//!   inventing a verdict. Absence of a source tree is not a finding.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The directory this binary was compiled in.
///
/// A compile-time constant, so it travels inside the binary to wherever the
/// binary is copied, and it costs no build script. On a machine that is not the
/// one that built it, the path simply does not exist — which is the
/// [`Freshness::NoSourceTree`] case.
const SOURCE_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// The files whose change means the binary is out of date.
///
/// `src/` recursively, plus the two manifests: a dependency bump changes
/// `Cargo.lock` and nothing under `src/`. `tests/` is deliberately absent —
/// a test file cannot change the program.
const SOURCES: [&str; 3] = ["src", "Cargo.toml", "Cargo.lock"];

/// Where cargo keeps the source of every binary target that is not the crate's
/// own `main.rs`.
const BIN_DIR: &str = "bin";

/// How deep the walk goes before it gives up.
///
/// `src/` is two levels deep today. A bound rather than trust, because a
/// symlink loop in a source tree would otherwise hang the one command a person
/// runs when something is already wrong.
const MAX_DEPTH: usize = 16;

/// What a comparison found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// No source tree at the recorded path. Nothing to compare, and nothing to
    /// say: this is the normal state of an installed release.
    NoSourceTree,
    /// Every source file is older than the binary. Cargo would not rebuild.
    Current,
    /// A source file changed after this binary was built, and here it is.
    ///
    /// The path is evidence rather than a claim — a reader can `ls -l` it and
    /// see the same thing this did.
    Stale { newest: PathBuf },
    /// The comparison could not be made: an unreadable mtime, an unreadable
    /// directory, a binary this process cannot locate.
    ///
    /// Never reported as either verdict. An untested claim is not a passing one.
    Unknown { reason: String },
}

/// Compare the running binary against the tree it was built from.
#[must_use]
pub fn check() -> Freshness {
    match std::env::current_exe() {
        Ok(binary) => check_at(Path::new(SOURCE_DIR), &binary),
        Err(error) => Freshness::Unknown {
            reason: format!("cannot locate the running binary: {error}"),
        },
    }
}

/// The same comparison, against a named tree and a named binary.
///
/// Split out from [`check`] so a test can build a tree with mtimes it chose,
/// rather than asserting against whatever this checkout happens to hold. A test
/// that can only observe the real repository can only ever confirm the branch
/// that is true right now.
#[must_use]
pub fn check_at(source_dir: &Path, binary: &Path) -> Freshness {
    if !source_dir.is_dir() {
        return Freshness::NoSourceTree;
    }
    let built = match modified(binary) {
        Ok(time) => time,
        Err(reason) => return Freshness::Unknown { reason },
    };
    // Another binary target's source is not this binary's source. See
    // `newest_source`.
    let running = binary
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned());
    match newest_source(source_dir, running.as_deref()) {
        Err(reason) => Freshness::Unknown { reason },
        // A tree with no readable source file is not a fresh binary; it is a
        // question that was not answered.
        Ok(None) => Freshness::Unknown {
            reason: format!("no source file found under {}", source_dir.display()),
        },
        Ok(Some((path, changed))) => {
            if changed > built {
                Freshness::Stale { newest: path }
            } else {
                Freshness::Current
            }
        }
    }
}

/// The most recently modified source file, and when.
///
/// # Another binary's source is not this binary's source
///
/// `running` is the file stem of the binary being judged, and every file
/// directly under `src/bin/` that does not carry that stem is skipped — the
/// same rule, and the same sentence, as the `tests/` exclusion above: it cannot
/// change this program.
///
/// This crate ships two binaries, and only one of them lives under `src/bin/`.
/// Cargo does not relink `keyless` when `src/bin/keylessd.rs` changes, because
/// that file is in no part of its image — so its mtime does not move, and a
/// walk that counted the daemon's source reported `keyless doctor` as `stale`
/// over a binary cargo would refuse to rebuild. The remedy printed beside it,
/// `cargo build --release`, therefore left the row exactly as it was: a red
/// verdict nobody could clear, on a binary that was not out of date.
///
/// That is the rule at the top of this module read strictly rather than
/// loosened. "Stale" means "cargo would rebuild this", and cargo would not.
///
/// `None` keeps every file, which is the honest answer for a binary whose stem
/// could not be read: the comparison then errs towards reporting a rebuild that
/// is not needed, never towards missing one that is.
fn newest_source(
    source_dir: &Path,
    running: Option<&str>,
) -> Result<Option<(PathBuf, SystemTime)>, String> {
    let mut newest: Option<(PathBuf, SystemTime)> = None;
    let others = source_dir.join("src").join(BIN_DIR);
    for entry in SOURCES {
        let path = source_dir.join(entry);
        // A missing entry is not an error: `Cargo.lock` is absent from a fresh
        // clone until the first build.
        if !path.exists() {
            continue;
        }
        visit(&path, 0, &mut newest, &others, running)?;
    }
    Ok(newest)
}

/// Whether `path` is a binary target belonging to some OTHER binary.
fn another_binarys_source(path: &Path, bin_dir: &Path, running: Option<&str>) -> bool {
    let Some(running) = running else {
        return false;
    };
    path.parent() == Some(bin_dir)
        && path
            .file_stem()
            .is_some_and(|stem| stem.to_string_lossy() != running)
}

/// Walk one path, keeping the newest file seen.
fn visit(
    path: &Path,
    depth: usize,
    newest: &mut Option<(PathBuf, SystemTime)>,
    bin_dir: &Path,
    running: Option<&str>,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "the source tree is deeper than {MAX_DEPTH} levels at {}",
            path.display()
        ));
    }
    if another_binarys_source(path, bin_dir, running) {
        return Ok(());
    }
    // `symlink_metadata`, so a link out of the tree is judged by the link and
    // never followed into somewhere this has no business walking.
    let meta = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;

    if meta.is_dir() {
        let entries = std::fs::read_dir(path)
            .map_err(|error| format!("cannot list {}: {error}", path.display()))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("cannot list {}: {error}", path.display()))?;
            visit(&entry.path(), depth + 1, newest, bin_dir, running)?;
        }
        return Ok(());
    }

    let changed = meta
        .modified()
        .map_err(|error| format!("cannot read the mtime of {}: {error}", path.display()))?;
    if newest.as_ref().is_none_or(|(_, seen)| changed > *seen) {
        *newest = Some((path.to_path_buf(), changed));
    }
    Ok(())
}

/// One file's mtime, or the sentence saying why there is none.
fn modified(path: &Path) -> Result<SystemTime, String> {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .map_err(|error| format!("cannot read the mtime of {}: {error}", path.display()))
}

/// The directory this binary was built in, for a report that names it.
#[must_use]
pub fn source_dir() -> &'static Path {
    Path::new(SOURCE_DIR)
}

#[cfg(test)]
mod tests {
    use super::{Freshness, check_at, source_dir};
    use std::fs::File;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime};

    /// A tree with one source file and one binary, at mtimes this test chose.
    ///
    /// The instants are literals rather than "now" plus an offset: a comparison
    /// against a clock the code under test can also read is a comparison that
    /// can agree with itself for the wrong reason.
    fn tree(tag: &str, binary_secs: u64, source_secs: u64) -> (PathBuf, PathBuf) {
        let mut dir = std::env::temp_dir();
        dir.push(format!("keyless-freshness-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).expect("cannot create the tree");

        let source = dir.join("src").join("thing.rs");
        write_at(&source, source_secs);
        write_at(&dir.join("Cargo.toml"), source_secs.saturating_sub(1000));

        let binary = dir.join("keyless");
        write_at(&binary, binary_secs);
        (dir, binary)
    }

    fn write_at(path: &Path, secs: u64) {
        std::fs::write(path, b"contents").expect("cannot write the fixture");
        let file = File::options()
            .write(true)
            .open(path)
            .expect("cannot open the fixture");
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
            .expect("cannot set the fixture's mtime");
    }

    #[test]
    fn a_source_file_newer_than_the_binary_is_stale_and_is_named() {
        let (dir, binary) = tree("stale", 1_000_000, 1_000_500);
        match check_at(&dir, &binary) {
            Freshness::Stale { newest } => assert!(
                newest.ends_with("src/thing.rs"),
                "the wrong file was named: {}",
                newest.display()
            ),
            other => panic!("a newer source must be stale, got {other:?}"),
        }
    }

    #[test]
    fn a_binary_newer_than_every_source_is_current() {
        let (dir, binary) = tree("current", 1_000_500, 1_000_000);
        assert_eq!(check_at(&dir, &binary), Freshness::Current);
    }

    #[test]
    fn the_same_instant_is_current_because_cargo_treats_it_that_way() {
        // The boundary, pinned deliberately. Cargo rebuilds when a source is
        // NEWER than the artefact, so equal is fresh — and a check that
        // disagreed here would report a rebuild that cargo refuses to perform,
        // which is an instruction nobody can carry out.
        let (dir, binary) = tree("equal", 1_000_000, 1_000_000);
        assert_eq!(check_at(&dir, &binary), Freshness::Current);
    }

    #[test]
    fn a_manifest_newer_than_the_binary_is_stale_too() {
        // A dependency bump changes `Cargo.lock` and nothing under `src/`. A
        // check that watched only `src/` would call that binary current.
        let (dir, binary) = tree("manifest", 1_000_000, 999_000);
        write_at(&dir.join("Cargo.lock"), 1_000_500);
        match check_at(&dir, &binary) {
            Freshness::Stale { newest } => assert!(
                newest.ends_with("Cargo.lock"),
                "the wrong file was named: {}",
                newest.display()
            ),
            other => panic!("a newer manifest must be stale, got {other:?}"),
        }
    }

    #[test]
    fn another_binary_targets_source_is_not_this_binarys_source() {
        // The defect: this crate ships two binaries and cargo does not relink
        // `keyless` when `src/bin/keylessd.rs` changes, because that file is in
        // no part of its image. Its mtime therefore does not move, and a walk
        // that counted the daemon's source called it `stale` — with a remedy,
        // `cargo build --release`, that cargo declines to act on. A red verdict
        // nobody can clear is worse than no row: it is read past, and then the
        // real one is read past with it.
        let (dir, binary) = tree("other-bin", 1_000_000, 999_000);
        std::fs::create_dir_all(dir.join("src").join("bin")).expect("cannot create the tree");
        let daemon = dir.join("src").join("bin").join("keylessd.rs");
        write_at(&daemon, 1_000_500);

        assert_eq!(
            check_at(&dir, &binary),
            Freshness::Current,
            "the daemon's source was counted against the client binary"
        );

        // The control, and the half that must not be lost: the SAME file, newer
        // than the SAME instant, is stale for the binary it does belong to. A
        // rule that skipped `src/bin/` outright would pass the assertion above
        // and silently stop judging the daemon at all.
        let its_own = dir.join("keylessd");
        write_at(&its_own, 1_000_000);
        match check_at(&dir, &its_own) {
            Freshness::Stale { newest } => assert!(
                newest.ends_with("src/bin/keylessd.rs"),
                "the wrong file was named: {}",
                newest.display()
            ),
            other => panic!("a binary's own source must still be judged, got {other:?}"),
        }
    }

    #[test]
    fn a_test_file_newer_than_the_binary_is_not_stale() {
        // The negative control on the source set: a test cannot change the
        // program, and reporting one would send somebody to rebuild for nothing.
        let (dir, binary) = tree("tests", 1_000_000, 999_000);
        std::fs::create_dir_all(dir.join("tests")).expect("cannot create the tree");
        write_at(&dir.join("tests").join("suite.rs"), 1_000_500);
        assert_eq!(check_at(&dir, &binary), Freshness::Current);
    }

    #[test]
    fn no_source_tree_is_not_a_verdict() {
        let missing = Path::new("/nonexistent/keyless-test/source-tree");
        assert_eq!(
            check_at(missing, Path::new("/bin/sh")),
            Freshness::NoSourceTree
        );
    }

    #[test]
    fn an_unreadable_binary_is_unknown_and_never_current() {
        // The direction that matters: a comparison that could not be made must
        // not read as one that passed.
        let (dir, _) = tree("unreadable", 1_000_000, 999_000);
        let absent = dir.join("no-such-binary");
        match check_at(&dir, &absent) {
            Freshness::Unknown { reason } => assert!(reason.contains("no-such-binary"), "{reason}"),
            other => panic!("a missing binary must be unknown, got {other:?}"),
        }
    }

    #[test]
    fn the_recorded_source_directory_is_this_crate() {
        // The constant is the whole mechanism: it is what lets a binary copied
        // elsewhere still find the tree it came from. A build that recorded
        // something else would make every verdict above meaningless.
        assert!(source_dir().join("Cargo.toml").is_file());
        assert!(source_dir().join("src").join("freshness.rs").is_file());
    }
}
