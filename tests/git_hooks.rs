//! Proves the `commit-msg` hook this repository ships actually refuses what it
//! claims to, end to end — through a real `git commit`, in a real clone, with
//! the hook installed exactly the way `scripts/install-hooks.sh` installs it.
//!
//! # Why this is not covered by `hooks/tests/test_publication.py`
//!
//! That suite calls `check_message_file` directly, which proves the grammar.
//! It does not prove that the grammar is reachable from `git commit` at all —
//! and the gap between "the checker is correct" and "the checker runs" is
//! exactly what let 208f29f8 into this history: `install/commit-msg.sh` was
//! never installed in the checkout that authored it, so nothing that already
//! existed would have caught the absence. This test exercises the seam that
//! actually failed: a message reaching git, with the hook `scripts/install-
//! hooks.sh` puts in place standing between it and history.
//!
//! # Why a fresh clone, not this checkout
//!
//! The hook resolves its own checker via `git rev-parse --show-toplevel`, so
//! it needs a real repository whose toplevel actually holds `hooks/tests/
//! test_publication.py` at that relative path. A clone of this repository's own
//! `HEAD` gives it exactly that, self-contained and disposable.

use std::path::{Path, PathBuf};
use std::process::Command;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyless-git-hooks-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("git")
}

fn git_must(repo: &Path, args: &[&str]) {
    let out = git(repo, args);
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A disposable clone of this repository's own `HEAD`, with the `commit-msg`
/// hook installed the way `scripts/install-hooks.sh` installs it: a symlink
/// from the clone's own hooks directory to its tracked `install/commit-msg.sh`.
///
/// Not `scripts/install-hooks.sh` itself, which resolves the hooks directory
/// relative to wherever *this test's own* checkout stands rather than the
/// clone under test — running it here would wire the hook into the outer
/// checkout instead of the scratch one, which is the one thing this test must
/// not do to the repository it is part of.
struct Clone {
    dir: PathBuf,
}

impl Clone {
    fn with_commit_msg_hook(tag: &str) -> Clone {
        let dir = scratch(tag);
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = Command::new("git")
            .args([
                "clone",
                "--local",
                "--no-hardlinks",
                "-q",
                manifest.to_str().expect("utf-8 path"),
                dir.to_str().expect("utf-8 path"),
            ])
            .output()
            .expect("git clone");
        assert!(
            out.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        git_must(&dir, &["config", "user.email", "hook-test@example.invalid"]);
        git_must(&dir, &["config", "user.name", "hook test"]);
        git_must(&dir, &["config", "commit.gpgsign", "false"]);

        // `--git-path` prints relative to the git process's own cwd, which is
        // `dir` here rather than this test binary's — join it back on rather
        // than treating it as usable on its own.
        let relative = String::from_utf8(
            Command::new("git")
                .current_dir(&dir)
                .args(["rev-parse", "--git-path", "hooks"])
                .output()
                .expect("git rev-parse")
                .stdout,
        )
        .expect("utf-8")
        .trim()
        .to_string();
        let hooks_dir = dir.join(relative);
        std::fs::create_dir_all(&hooks_dir).expect("hooks dir");
        let target = hooks_dir.join("commit-msg");
        std::os::unix::fs::symlink("../../install/commit-msg.sh", &target)
            .expect("symlink the commit-msg hook");

        Clone { dir }
    }

    fn commit(&self, message: &str) -> std::process::Output {
        Command::new("git")
            .current_dir(&self.dir)
            .args(["commit", "--allow-empty", "-m", message])
            .output()
            .expect("git commit")
    }
}

impl Drop for Clone {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn the_installed_hook_refuses_a_commit_message_stating_a_census_claim() {
    let repo = Clone::with_commit_msg_hook("refuses");
    let before = git(&repo.dir, &["rev-parse", "HEAD"]);
    let before_sha = String::from_utf8_lossy(&before.stdout).trim().to_string();

    let out = repo.commit("the decision log shows 47 organic denies across 9 sessions");

    assert!(
        !out.status.success(),
        "a commit carrying a measurement of one machine was accepted"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("states a measurement of one machine or account"),
        "refused for the wrong reason, or not through this hook: {stderr}"
    );

    // The control: HEAD must not have moved. A hook that refuses but lets the
    // commit through anyway is worse than none, because it reads as enforced.
    let after = git(&repo.dir, &["rev-parse", "HEAD"]);
    let after_sha = String::from_utf8_lossy(&after.stdout).trim().to_string();
    assert_eq!(before_sha, after_sha, "the refused commit landed anyway");
}

#[test]
fn the_installed_hook_accepts_a_message_carrying_a_legitimate_number() {
    let repo = Clone::with_commit_msg_hook("accepts");
    let before = git(&repo.dir, &["rev-parse", "HEAD"]);
    let before_sha = String::from_utf8_lossy(&before.stdout).trim().to_string();

    let out = repo.commit("the suite is 509 tests and 15 ignored on both platforms");

    assert!(
        out.status.success(),
        "a legitimate count-with-provenance was refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let after = git(&repo.dir, &["rev-parse", "HEAD"]);
    let after_sha = String::from_utf8_lossy(&after.stdout).trim().to_string();
    assert_ne!(before_sha, after_sha, "the commit did not actually land");
}
