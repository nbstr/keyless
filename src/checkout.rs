//! Whether the tree this binary was built from is behind the branch it tracks.
//!
//! # The failure this exists to catch, and why the sibling check is blind to it
//!
//! [`crate::freshness`] compares the running binary against the source beside
//! it. That is a real question and it is not this one. A checkout that is
//! itself old builds a binary that is FRESH by that rule, because the source
//! WAS the source: nothing under `src/` is newer than the artefact, so cargo
//! would not rebuild and the BUILD row is right to say so.
//!
//! That is not a hypothetical, and this module exists because it happened. A
//! checkout sat six commits behind `master`; the binary was built from it, so
//! no source file was newer than the artefact, and `keyless doctor` printed
//! `build proven` with exit code 0 — correctly, by its own logic. That binary
//! contained the
//! `probe_command` defect fixed in `8550644`, in which `doctor --probe`
//! reported names as `proven — read back from infisical` while reading the
//! caller's own exported environment and the store held nothing. A false green
//! certified by a green row.
//!
//! Nothing already in the tool sees it. `--version` reads `0.1.0` on every
//! build. A behaviour probe (`setup --help` resolves) passes on every revision
//! this repository has ever had: it proves the binary RUNS, never that it is
//! CURRENT. The only thing that sees it is the checkout's position against its
//! upstream, which is what this module asks.
//!
//! # It NEVER contacts the remote, and that is the whole design
//!
//! `@{u}` is the ref the LAST FETCH left behind. A checkout that has not
//! fetched in a week reports level while being six commits behind, so a green
//! built on it would be a false green with an extra step. There are three
//! honest responses to that and this module takes the third:
//!
//! 1. **Fetch.** Rejected. A credential broker's health command must not make
//!    an unrequested network call: it is the surface an auditor reads, the
//!    latency lands on the one command a person runs when something is already
//!    wrong, and an SSH remote can prompt for a passphrase — a diagnostic that
//!    hangs behind a question nobody can see is the failure mode
//!    [`crate::store::exec`] exists to prevent, reintroduced at the top of the
//!    report.
//! 2. **Threshold the ref's age.** Rejected. Any window is a private definition
//!    of fresh, which is exactly what the mtime comparison refused to invent.
//! 3. **Report the ref's own age beside every verdict, and never claim a pass
//!    from it.** Taken.
//!
//! The asymmetry is what makes the finding worth having. A stale ref can only
//! cause a MISSED detection; it can never invent one. Commits the last fetch
//! already saw and this checkout does not have are a positive fact, true
//! whatever has happened on the remote since. So:
//!
//! - [`Checkout::Behind`] is a fault, counts, and is a FLOOR rather than a
//!   count.
//! - [`Checkout::NotBehind`] is never a pass. It renders unproven, states when
//!   the ref was last refreshed, and says outright that nothing asked the
//!   remote.
//!
//! # Why it does not cry wolf
//!
//! Only `behind` is a fault. A local commit that is not pushed is `ahead`, not
//! `behind`, and reports nothing — otherwise the row would go red between every
//! commit and its push, and a gate that cries wolf gets removed. The row goes
//! quiet the moment the checkout pulls, and [`crate::freshness`] takes over
//! until the rebuild.
//!
//! # Why `git`, and why it is not on `run`
//!
//! Every store in this crate is already a subprocess, so a spawn is not a new
//! class of thing in a report that already runs `security` and `infisical`.
//! It runs under [`crate::store::exec::capture`]'s deadline for the same
//! reason they do: a diagnostic that hangs is worse than one that abstains.
//!
//! It belongs to `doctor` and to nothing else. `run` is the credential path,
//! and the argument that kept a directory walk out of it holds harder for a
//! process spawn.
//!
//! # Two clones on one machine
//!
//! Two clones of this repository can sit side by side — identical in remote,
//! branch and upstream, unlinked — with only the installed symlink naming which
//! of them built the binary on `PATH`. This asks about
//! [`crate::freshness::source_dir`], the tree that BUILT the running binary,
//! and never about the process's working directory. Work sitting in the
//! sibling clone is invisible here and should be: the sibling did not build
//! what is answering you.
//!
//! # What it cannot see, stated rather than implied
//!
//! - **Anything the last fetch did not already know.** Stated above, printed on
//!   every row, and the reason no verdict here is ever a tick.
//! - **A shallow clone's true distance.** `rev-list` stops at the graft
//!   boundary and would answer a wrong number rather than none, so a shallow
//!   clone is refused a count entirely.
//! - **A remote that is not the upstream.** A branch tracking a fork is
//!   compared against the fork, which is what `@{u}` means and what a rebuild
//!   would be based on.
//! - **Whether the commits you are missing matter.** It counts them. Reading
//!   them is `git log`.
//! - **A machine with no source tree.** Same premise as
//!   [`crate::freshness::Freshness::NoSourceTree`], same answer: nothing is
//!   reported, because absence of a checkout is not a finding.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::store::exec::{self, Captured};

/// How long `git` gets before it is killed.
///
/// Generous for a purely local `rev-list` and still bounded, because the one
/// command a person runs when something is already wrong must not be the reason
/// their terminal is stuck. Nothing here touches a network, so an expiry means
/// the repository or the filesystem is pathological — which is a finding, not a
/// reason to wait.
const DEADLINE: Duration = Duration::from_secs(5);

/// One `git` invocation answering three questions that share a process.
///
/// `--git-path` resolves `FETCH_HEAD` through whatever indirection a linked
/// worktree has, rather than assuming `.git` is a directory.
const PROBE: [&str; 6] = [
    "rev-parse",
    "--is-shallow-repository",
    "--git-path",
    "FETCH_HEAD",
    "--abbrev-ref",
    "@{u}",
];

/// Where the checkout stands against the branch it tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checkout {
    /// No source tree at the recorded path. Nothing to ask, and nothing to say.
    NoSourceTree,
    /// `git` could not answer: not installed, not a repository, refused the
    /// directory, or it timed out. Never a verdict.
    CannotAsk { reason: String },
    /// `HEAD` is not on a branch, so there is no upstream to be behind.
    Detached,
    /// On a branch that tracks nothing.
    NoUpstream { branch: String },
    /// A shallow clone, where a count would be wrong rather than absent.
    Shallow { upstream: String },
    /// Commits exist on the upstream ref that this checkout does not have.
    ///
    /// `behind` is a floor: it is what the last fetch already knew.
    Behind {
        upstream: String,
        behind: u32,
        ahead: u32,
        fetched_ago: Option<Duration>,
    },
    /// No commit on the upstream ref is missing here — **as of the last fetch**.
    ///
    /// Not a pass. `ahead` is carried because a local commit that is not pushed
    /// is the normal reason the two differ, and it is not a fault.
    NotBehind {
        upstream: String,
        ahead: u32,
        fetched_ago: Option<Duration>,
    },
}

/// Ask about the tree this binary was built from.
#[must_use]
pub fn check() -> Checkout {
    check_at(crate::freshness::source_dir())
}

/// The same question, about a named tree.
///
/// Split out from [`check`] for the reason [`crate::freshness::check_at`] is:
/// a test that can only observe this checkout can only ever confirm the branch
/// that happens to be true right now. It also carries the two-clone property —
/// the answer follows the ARGUMENT, never the process's working directory.
#[must_use]
pub fn check_at(source_dir: &Path) -> Checkout {
    if !source_dir.is_dir() {
        return Checkout::NoSourceTree;
    }
    let probe = match git(source_dir, &PROBE) {
        Ok(captured) => captured,
        Err(reason) => return Checkout::CannotAsk { reason },
    };
    if !probe.status.success() {
        return without_upstream(source_dir);
    }

    let text = String::from_utf8_lossy(&probe.stdout).into_owned();
    let mut lines = text.lines();
    let shallow = lines.next().unwrap_or_default().trim() == "true";
    let fetch_head = lines.next().unwrap_or_default().trim().to_owned();
    let upstream = lines.next().unwrap_or_default().trim().to_owned();
    if upstream.is_empty() {
        return Checkout::CannotAsk {
            reason: "git answered without naming an upstream branch".to_owned(),
        };
    }
    if shallow {
        return Checkout::Shallow { upstream };
    }

    let fetched_ago = fetched_ago(source_dir, &fetch_head);
    let counts = match git(
        source_dir,
        &["rev-list", "--count", "--left-right", "HEAD...@{u}"],
    ) {
        Ok(captured) => captured,
        Err(reason) => return Checkout::CannotAsk { reason },
    };
    if !counts.status.success() {
        return Checkout::CannotAsk {
            reason: exec::first_line(&counts.stderr),
        };
    }
    let Some((ahead, behind)) = two_counts(&counts.stdout) else {
        return Checkout::CannotAsk {
            reason: "git did not answer with two commit counts".to_owned(),
        };
    };

    if behind > 0 {
        Checkout::Behind {
            upstream,
            behind,
            ahead,
            fetched_ago,
        }
    } else {
        Checkout::NotBehind {
            upstream,
            ahead,
            fetched_ago,
        }
    }
}

/// Why `@{u}` did not resolve — which is three different repairs.
///
/// Asked only after the probe failed, so the cost is paid by the broken case.
/// A detached `HEAD`, a branch tracking nothing, and a directory `git` will not
/// read send a reader to three different places, and collapsing them into one
/// sentence would name none of them.
fn without_upstream(source_dir: &Path) -> Checkout {
    let head = match git(source_dir, &["rev-parse", "--abbrev-ref", "HEAD"]) {
        Ok(captured) => captured,
        Err(reason) => return Checkout::CannotAsk { reason },
    };
    if !head.status.success() {
        return Checkout::CannotAsk {
            reason: exec::first_line(&head.stderr),
        };
    }
    let branch = String::from_utf8_lossy(&head.stdout).trim().to_owned();
    if branch.is_empty() || branch == "HEAD" {
        Checkout::Detached
    } else {
        Checkout::NoUpstream { branch }
    }
}

/// How long ago this clone last asked the remote anything.
///
/// `FETCH_HEAD` rather than the remote ref's own mtime, because a fetch that
/// found nothing new still rewrites `FETCH_HEAD` and does not touch the ref. So
/// this dates the QUESTION, which is what the verdict's honesty depends on,
/// rather than the last time the answer changed.
///
/// `None` when the file is absent — a clone that has only ever pushed, or a
/// fetch run with `--no-write-fetch-head`. Reported as an unknown time, never
/// as a recent one.
fn fetched_ago(source_dir: &Path, fetch_head: &str) -> Option<Duration> {
    let path = Path::new(fetch_head);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        source_dir.join(path)
    };
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()?
        // A fetch stamped in the future is a clock that disagrees with itself.
        // Reported as unknown rather than as zero seconds ago, which would be
        // the most reassuring possible reading of a broken clock.
        .elapsed()
        .ok()
}

/// `rev-list --count --left-right` writes `<ahead>\t<behind>`.
fn two_counts(stdout: &[u8]) -> Option<(u32, u32)> {
    let text = std::str::from_utf8(stdout).ok()?;
    let mut fields = text.split_whitespace();
    let ahead = fields.next()?.parse().ok()?;
    let behind = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some((ahead, behind))
}

/// Run `git` in `dir`, under a deadline.
///
/// `current_dir` rather than `-C`: the directory is the whole question here, and
/// a spelling that cannot be defeated by an argument-order mistake is worth more
/// than one a reader recognises.
///
/// The two variables are the difference between a diagnostic and a hang.
/// `GIT_TERMINAL_PROMPT=0` refuses a credential prompt outright — nothing here
/// touches a network, so a prompt would mean something is very wrong and
/// waiting for it helps nobody. `GIT_OPTIONAL_LOCKS=0` stops a read from taking
/// a lock or writing an index, which matters because the installer runs this
/// path beside `sudo`.
fn git(dir: &Path, args: &[&str]) -> Result<Captured, String> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(dir)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    exec::capture(command, DEADLINE).map_err(|error| format!("cannot ask git: {error}"))
}

/// An elapsed duration, coarsely, for a sentence.
///
/// Takes the duration rather than reading a clock, so a test states both sides
/// as literals. A helper that called [`std::time::SystemTime::now`] itself could
/// only be checked against the same clock it used.
#[must_use]
pub fn ago(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3_600 {
        format!("{}m ago", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h ago", seconds / 3_600)
    } else {
        format!("{}d ago", seconds / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::{Checkout, ago, check_at, two_counts};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    /// `git`, with every ambient setting that could reach into a fixture turned
    /// off.
    ///
    /// Each flag closes a way this machine's own configuration can decide the
    /// result: a global `init.defaultBranch` renames the branch the assertions
    /// name, a global `commit.gpgsign` makes an empty commit prompt or fail, a
    /// global `core.hooksPath` runs somebody else's hooks inside a temporary
    /// directory. A fixture that inherits those is a fixture that passes on one
    /// machine.
    fn git(dir: &Path, args: &[&str]) -> std::process::Output {
        let output = Command::new("git")
            .args([
                "-c",
                "init.defaultBranch=master",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "user.name=fixture",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/nonexistent/keyless-fixture-hooks",
                "-c",
                "advice.detachedHead=false",
            ])
            .args(args)
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git must be installed to run this suite");
        assert!(
            output.status.success(),
            "fixture command failed: git {args:?}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// A bare remote and a working clone that has pushed `commits` commits.
    ///
    /// A real repository with a real remote rather than a stubbed `git`: the
    /// argument strings, the output format and the tab between the two counts
    /// are exactly the surface that breaks, and a stub would assert that this
    /// module agrees with the author's memory of `rev-list`.
    fn repo(tag: &str, commits: usize) -> PathBuf {
        let mut base = std::env::temp_dir();
        base.push(format!("keyless-checkout-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("cannot create the fixture");

        let remote = base.join("remote.git");
        let work = base.join("work");
        std::fs::create_dir_all(&work).expect("cannot create the fixture");
        git(&base, &["init", "--bare", "--quiet", "remote.git"]);
        git(&work, &["init", "--quiet", "."]);
        for n in 0..commits {
            git(
                &work,
                &["commit", "--quiet", "--allow-empty", "-m", &format!("c{n}")],
            );
        }
        git(
            &work,
            &["remote", "add", "origin", remote.to_str().expect("utf-8")],
        );
        git(&work, &["push", "--quiet", "-u", "origin", "master"]);
        work
    }

    #[test]
    fn a_checkout_behind_its_upstream_is_reported_behind_with_the_count() {
        // The condition this row exists for: the working tree is moved back and
        // the remote is not, so the checkout is old while every file in it looks
        // untouched. Seven commits pushed, then six undone, so the literal below
        // comes from this test's own arithmetic and from no reading the code
        // under test performs.
        let work = repo("behind", 7);
        git(&work, &["reset", "--hard", "--quiet", "HEAD~6"]);
        match check_at(&work) {
            Checkout::Behind {
                upstream,
                behind,
                ahead,
                ..
            } => {
                assert_eq!(behind, 6);
                assert_eq!(ahead, 0);
                assert_eq!(upstream, "origin/master");
            }
            other => panic!("a checkout six commits back must be behind, got {other:?}"),
        }
    }

    #[test]
    fn the_binary_can_match_its_source_while_the_source_is_six_commits_old() {
        // The whole reason this module exists, pinned as one assertion. The
        // freshness check is handed a binary NEWER than every file in the same
        // tree, which is what building from this checkout produces — and it
        // says `Current`, correctly. The tree is six commits behind anyway.
        //
        // If these two ever agree, one of them has stopped answering its own
        // question.
        let work = repo("both", 7);
        git(&work, &["reset", "--hard", "--quiet", "HEAD~6"]);
        std::fs::create_dir_all(work.join("src")).expect("cannot create the tree");
        std::fs::write(work.join("src").join("thing.rs"), b"x").expect("cannot write");
        let binary = work.join("keyless");
        std::fs::write(&binary, b"x").expect("cannot write");
        // Written last, so it is the newest thing in the tree.
        assert_eq!(
            crate::freshness::check_at(&work, &binary),
            crate::freshness::Freshness::Current,
            "the fixture must be one the mtime check calls current"
        );
        assert!(
            matches!(check_at(&work), Checkout::Behind { behind: 6, .. }),
            "and it is six commits behind at the same time"
        );
    }

    #[test]
    fn a_checkout_level_with_its_upstream_is_not_behind() {
        let work = repo("level", 3);
        match check_at(&work) {
            Checkout::NotBehind {
                upstream, ahead, ..
            } => {
                assert_eq!(ahead, 0);
                assert_eq!(upstream, "origin/master");
            }
            other => panic!("a pushed checkout must not be behind, got {other:?}"),
        }
    }

    #[test]
    fn a_commit_that_is_not_pushed_yet_is_never_reported_behind() {
        // The false-alarm control, and the reason only `behind` is a fault. A
        // row that went red between every commit and its push would be removed
        // within a week, and then nothing would watch the real case.
        let work = repo("ahead", 2);
        git(
            &work,
            &["commit", "--quiet", "--allow-empty", "-m", "local"],
        );
        match check_at(&work) {
            Checkout::NotBehind { ahead, .. } => assert_eq!(ahead, 1),
            other => panic!("an unpushed commit is not a fault, got {other:?}"),
        }
    }

    #[test]
    fn a_diverged_checkout_reports_both_directions() {
        // Both counts are load-bearing: with a local commit in the way, a
        // fast-forward pull refuses, so the remedy is not the one the plain
        // behind case prints.
        let work = repo("diverged", 5);
        git(&work, &["reset", "--hard", "--quiet", "HEAD~3"]);
        git(
            &work,
            &["commit", "--quiet", "--allow-empty", "-m", "local"],
        );
        match check_at(&work) {
            Checkout::Behind { behind, ahead, .. } => {
                assert_eq!(behind, 3);
                assert_eq!(ahead, 1);
            }
            other => panic!("a diverged checkout is behind, got {other:?}"),
        }
    }

    #[test]
    fn a_branch_that_tracks_nothing_says_so_rather_than_passing() {
        let mut base = std::env::temp_dir();
        base.push(format!("keyless-checkout-{}-untracked", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("cannot create the fixture");
        git(&base, &["init", "--quiet", "."]);
        git(&base, &["commit", "--quiet", "--allow-empty", "-m", "one"]);
        assert_eq!(
            check_at(&base),
            Checkout::NoUpstream {
                branch: "master".to_owned()
            }
        );
    }

    #[test]
    fn a_detached_head_says_so_rather_than_passing() {
        let work = repo("detached", 2);
        git(&work, &["checkout", "--quiet", "--detach", "HEAD"]);
        assert_eq!(check_at(&work), Checkout::Detached);
    }

    #[test]
    fn a_directory_that_is_not_a_checkout_is_never_a_verdict() {
        let mut plain = std::env::temp_dir();
        plain.push(format!("keyless-checkout-{}-plain", std::process::id()));
        let _ = std::fs::remove_dir_all(&plain);
        std::fs::create_dir_all(&plain).expect("cannot create the fixture");
        match check_at(&plain) {
            Checkout::CannotAsk { reason } => assert!(!reason.is_empty()),
            other => panic!("a plain directory cannot be judged, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_source_tree_is_not_a_verdict() {
        assert_eq!(
            check_at(Path::new("/nonexistent/keyless-test/source-tree")),
            Checkout::NoSourceTree
        );
    }

    #[test]
    fn the_fetch_time_is_unknown_until_something_fetches() {
        // Both halves, because the interesting claim is that an unfetched clone
        // is reported as unknown rather than as recent — the most reassuring
        // reading of the least informed state.
        let work = repo("fetched", 2);
        assert!(
            matches!(
                check_at(&work),
                Checkout::NotBehind {
                    fetched_ago: None,
                    ..
                }
            ),
            "a clone that has only ever pushed has no fetch to date"
        );
        git(&work, &["fetch", "--quiet", "origin"]);
        assert!(
            matches!(
                check_at(&work),
                Checkout::NotBehind {
                    fetched_ago: Some(_),
                    ..
                }
            ),
            "and one that has fetched does"
        );
    }

    #[test]
    fn the_answer_follows_the_directory_it_is_given() {
        // The two-clone property. One machine holds two clones of this
        // repository with the same remote, the same branch and the same
        // upstream, and only a symlink says which one built the binary on
        // PATH. Two trees answered differently in one process is what proves
        // the answer is not read from the process's working directory.
        let behind = repo("two-clone-behind", 4);
        git(&behind, &["reset", "--hard", "--quiet", "HEAD~2"]);
        let level = repo("two-clone-level", 4);
        assert!(matches!(
            check_at(&behind),
            Checkout::Behind { behind: 2, .. }
        ));
        assert!(matches!(check_at(&level), Checkout::NotBehind { .. }));
    }

    #[test]
    fn the_two_counts_are_read_in_gits_order_and_nothing_else_is_accepted() {
        // `--left-right` writes ahead first. Swapping them turns a checkout
        // that is behind into one that is ahead, which is the difference
        // between a fault and a normal working state.
        assert_eq!(two_counts(b"2\t7\n"), Some((2, 7)));
        assert_eq!(two_counts(b"0 0\n"), Some((0, 0)));
        assert_eq!(two_counts(b"3\n"), None);
        assert_eq!(two_counts(b"1\t2\t3\n"), None);
        assert_eq!(two_counts(b"a\tb\n"), None);
    }

    #[test]
    fn an_elapsed_time_reads_in_the_largest_unit_that_fits() {
        assert_eq!(ago(Duration::from_secs(0)), "0s ago");
        assert_eq!(ago(Duration::from_secs(59)), "59s ago");
        assert_eq!(ago(Duration::from_secs(60)), "1m ago");
        assert_eq!(ago(Duration::from_secs(3_599)), "59m ago");
        assert_eq!(ago(Duration::from_secs(3_600)), "1h ago");
        assert_eq!(ago(Duration::from_secs(86_399)), "23h ago");
        assert_eq!(ago(Duration::from_secs(86_400)), "1d ago");
        assert_eq!(ago(Duration::from_secs(604_800)), "7d ago");
    }
}
