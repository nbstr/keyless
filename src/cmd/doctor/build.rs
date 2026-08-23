//! The BUILD section: whether the code answering you is the code anybody is
//! reading.
//!
//! Two links, `upstream → source → binary`, and neither subsumes the other: an
//! uncommitted edit moves an mtime and moves no ref. [`report_build`] holds the
//! reasoning for why both rows are printed above every other section, and why
//! only one of the two can ever be a tick.

use std::io::{self, Write};

use crate::checkout::Checkout;
use crate::cmd::status::{Mark, Style, action, heading, row};
use crate::freshness::{self, Freshness};

/// One row of the BUILD section, before it is printed.
///
/// Built rather than written straight out, so the heading can be printed only
/// when a row exists. A `BUILD` heading over nothing is what a hand-ordered
/// sequence of `writeln!`s produces the first time a verdict goes silent.
struct BuildRow {
    mark: Mark,
    subject: &'static str,
    state: &'static str,
    detail: String,
    next: Option<String>,
}

/// How wide the subject column is here. `checkout` is the longest.
const BUILD_SUBJECT_WIDTH: usize = 8;

/// Whether the code answering you is the code anybody is reading. Returns how
/// many rows are problems.
///
/// **Directly under the header, above every other section, and it counts.** A
/// stale binary does not make one row wrong; it makes the whole report a
/// statement about code nobody is reading — including the rows that say
/// everything is fine. So it is placed where it cannot be reached by scrolling
/// past a wall of green, for the same reason [`super::guards`] is.
///
/// # Two rows, because it is two questions and one of them cannot be answered
///
/// The chain is `upstream → source → binary`, and each link fails on its own:
///
/// - `build` compares the binary against the source tree beside it. It PROVES
///   that link and nothing else, and it says so in the row, because
///   `✔ build proven` at the top of a health report is read as "the code is
///   current" and that is not what it measured. On 2026-08-10 that exact tick
///   certified a binary built from a checkout six commits behind, carrying a
///   false green fixed in one of those six.
/// - `checkout` compares that source tree against the branch it tracks — and it
///   is never a tick, whatever it finds, because [`crate::checkout`] refuses to
///   make a network call and the ref it reads is only as new as the last fetch.
///   [`Checkout::Behind`] is a positive fact a stale ref cannot invent, so it is
///   the one verdict here that is red.
///
/// Both go silent on a machine with no source tree, which is the normal state of
/// an installed release: nothing to compare, no finding, and a row on every
/// invocation would teach people to skip this section. Every other unanswerable
/// case prints as `unproven` and costs no exit code — a comparison that could
/// not be made must never read as one that passed, and must not read as a fault
/// either.
pub(super) fn report_build(
    freshness: &Freshness,
    checkout: &Checkout,
    style: Style,
    out: &mut dyn Write,
) -> io::Result<i32> {
    let rows: Vec<BuildRow> = [build_row(freshness), checkout_row(checkout)]
        .into_iter()
        .flatten()
        .collect();
    if rows.is_empty() {
        return Ok(0);
    }
    heading(out, style, "BUILD")?;
    let mut problems = 0;
    for BuildRow {
        mark,
        subject,
        state,
        detail,
        next,
    } in rows
    {
        row(
            out,
            style,
            mark,
            subject,
            BUILD_SUBJECT_WIDTH,
            state,
            &detail,
        )?;
        if let Some(text) = next {
            action(out, style, &text)?;
        }
        problems += i32::from(mark.is_problem());
    }
    Ok(problems)
}

/// The binary against the source beside it.
fn build_row(freshness: &Freshness) -> Option<BuildRow> {
    let (mark, state, detail, next) = match freshness {
        Freshness::NoSourceTree => return None,
        Freshness::Current => (
            Mark::Proven,
            "proven",
            format!(
                "newer than every source file in {}. That is the whole claim: \
                 whether that checkout is itself current is the row below, and \
                 this one cannot see it",
                freshness::source_dir().display()
            ),
            None,
        ),
        Freshness::Unknown { reason } => (Mark::Unproven, "unproven", reason.clone(), None),
        Freshness::Stale { newest } => (
            Mark::Broken,
            "stale",
            format!(
                "{} changed after this binary was built, so every row here is about \
                 older code",
                newest.display()
            ),
            Some(format!(
                "cargo build --release   (in {})",
                freshness::source_dir().display()
            )),
        ),
    };
    Some(BuildRow {
        mark,
        subject: "build",
        state,
        detail,
        next,
    })
}

/// That source tree against the branch it tracks.
///
/// Every arm names the directory, because the person reading this is not
/// necessarily standing in it — and on a machine with two clones of this
/// repository, "which one" is the entire question.
fn checkout_row(checkout: &Checkout) -> Option<BuildRow> {
    let here = freshness::source_dir().display().to_string();
    let (mark, state, detail, next) = match checkout {
        Checkout::NoSourceTree => return None,
        Checkout::CannotAsk { reason } => (Mark::Unproven, "unproven", reason.clone(), None),
        Checkout::Detached => (
            Mark::Unproven,
            "unproven",
            format!("HEAD in {here} is not on a branch, so there is no upstream to be behind"),
            Some(format!(
                "git -C {here} checkout <branch>   restores the comparison"
            )),
        ),
        Checkout::NoUpstream { branch } => (
            Mark::Unproven,
            "unproven",
            format!(
                "branch {branch} in {here} tracks nothing, so how far behind it is \
                 cannot be asked"
            ),
            Some(format!(
                "git -C {here} branch --set-upstream-to=origin/{branch} {branch}"
            )),
        ),
        Checkout::Shallow { upstream } => (
            Mark::Unproven,
            "unproven",
            format!(
                "{here} is a shallow clone, so a distance from {upstream} would be \
                 WRONG rather than absent. None is given"
            ),
            Some(format!("git -C {here} fetch --unshallow")),
        ),
        Checkout::Behind {
            upstream,
            behind,
            ahead,
            fetched_ago,
        } => (
            Mark::Broken,
            "behind",
            format!(
                "{here} is at least {behind} commit(s) behind {upstream}, {}. This \
                 binary is built from source that old, and the row above cannot see \
                 it",
                as_of(*fetched_ago)
            ),
            Some(if *ahead == 0 {
                format!("git -C {here} pull --ff-only && cargo build --release")
            } else {
                format!(
                    "{ahead} local commit(s) are not on {upstream}, so a \
                     fast-forward refuses. Reconcile, then: cargo build --release \
                     (in {here})"
                )
            }),
        ),
        Checkout::NotBehind {
            upstream,
            ahead,
            fetched_ago,
        } => (
            Mark::Unproven,
            "unproven",
            format!(
                "not behind {upstream}, {}. NOTHING here contacted the remote, so a \
                 commit pushed since then is invisible to this row{}",
                as_of(*fetched_ago),
                if *ahead == 0 {
                    String::new()
                } else {
                    format!("; {ahead} local commit(s) are not pushed, which is not a fault")
                }
            ),
            Some(format!(
                "git -C {here} fetch   asks the remote; this report never does"
            )),
        ),
    };
    Some(BuildRow {
        mark,
        subject: "checkout",
        state,
        detail,
        next,
    })
}

/// When the ref a checkout verdict rests on was last refreshed.
///
/// Printed beside every verdict, red or not. It is the difference between "this
/// checkout is level" and "this checkout is level according to something a week
/// old", and those are not the same sentence.
fn as_of(fetched_ago: Option<std::time::Duration>) -> String {
    fetched_ago.map_or_else(
        || "as of a last fetch this cannot date".to_owned(),
        |elapsed| format!("as of a fetch {}", crate::checkout::ago(elapsed)),
    )
}

#[cfg(test)]
mod tests {
    use super::report_build;
    use crate::checkout::Checkout;
    // The whitespace-collapsing helper is shared with the report these rows are
    // rendered into; it lives beside `doctor` itself.
    use crate::cmd::doctor::tests::flat;
    use crate::cmd::status::Style;
    use crate::freshness::Freshness;
    use std::path::PathBuf;

    /// A checkout verdict that says nothing, so a test about the BUILD row is
    /// about the BUILD row.
    fn quiet() -> Checkout {
        Checkout::NoSourceTree
    }

    /// One BUILD section, rendered plain, with the number of problems it counted.
    fn build_section(freshness: &Freshness, checkout: &Checkout) -> (String, i32) {
        let mut out: Vec<u8> = Vec::new();
        let problems = report_build(freshness, checkout, Style::PLAIN, &mut out).expect("write");
        (String::from_utf8(out).expect("utf-8"), problems)
    }

    /// The one line of a rendered section whose subject column says `subject`.
    ///
    /// The mark is the FIRST character of the row, and `Mark::Proven` renders
    /// `+` in [`Style::PLAIN`] while `Mark::Unproven` renders `~`. Asserting on
    /// the glyph rather than the word matters here: `unproven` contains
    /// `proven`, so a `contains("proven")` check cannot tell the only two states
    /// this section needs to keep apart.
    fn line_for<'a>(text: &'a str, subject: &str) -> &'a str {
        text.lines()
            .find(|line| line.split_whitespace().nth(1) == Some(subject))
            .unwrap_or_else(|| panic!("no {subject} row in:\n{text}"))
    }

    #[test]
    fn a_stale_binary_is_a_problem_and_names_both_the_file_and_the_fix() {
        let (text, problems) = build_section(
            &Freshness::Stale {
                newest: PathBuf::from("/somewhere/src/store/infisical.rs"),
            },
            &quiet(),
        );
        assert_eq!(problems, 1, "{text}");
        assert!(text.contains("stale"), "{text}");
        assert!(
            text.contains("/somewhere/src/store/infisical.rs"),
            "the row must name the evidence a reader can check: {text}"
        );
        assert!(
            text.contains("cargo build --release"),
            "a diagnosis with no next action is the shape this report used to have: {text}"
        );
    }

    #[test]
    fn a_current_binary_costs_no_problem_and_disclaims_the_checkout() {
        // The narrowing is the point. `+ build proven` at the top of a health
        // report is read as "the code is current", and on 2026-08-10 that exact
        // tick certified a binary built from a checkout six commits behind. The
        // row states what it compared and refuses the wider reading in the same
        // breath.
        let (text, problems) = build_section(&Freshness::Current, &quiet());
        assert_eq!(problems, 0, "{text}");
        assert!(
            flat(&text).contains("newer than every source file in"),
            "{text}"
        );
        assert!(
            flat(&text).contains("whether that checkout is itself current is the row below"),
            "the passing row must name what it does NOT prove: {text}"
        );
    }

    #[test]
    fn a_machine_with_no_source_tree_is_told_nothing_at_all() {
        // The control first: the same function does print for a verdict.
        let (present, _) = build_section(&Freshness::Current, &quiet());
        assert!(!present.is_empty());

        let (text, problems) = build_section(&Freshness::NoSourceTree, &Checkout::NoSourceTree);
        assert_eq!(problems, 0);
        assert!(
            text.is_empty(),
            "an installed release has no tree to compare against and no finding \
             to report; a row on every invocation teaches people to skip this \
             section — and the heading must go with the rows: {text}"
        );
    }

    #[test]
    fn a_comparison_that_could_not_be_made_never_reads_as_one_that_passed() {
        let (text, problems) = build_section(
            &Freshness::Unknown {
                reason: "cannot locate the running binary".to_owned(),
            },
            &quiet(),
        );
        assert_eq!(problems, 0, "an unanswered question is not a fault: {text}");
        assert!(text.contains("unproven"), "{text}");
        assert!(text.contains("cannot locate the running binary"), "{text}");
        assert!(
            !text.contains("newer than every source file"),
            "an unknown verdict must not borrow the passing row's words: {text}"
        );
    }

    #[test]
    fn a_checkout_behind_its_upstream_is_a_problem_and_names_the_count_and_the_fix() {
        // The defect this section was extended for: the binary matches its
        // source, the source is six commits old, and the old report said
        // `proven` and exited 0.
        let (text, problems) = build_section(
            &Freshness::Current,
            &Checkout::Behind {
                upstream: "origin/master".to_owned(),
                behind: 6,
                ahead: 0,
                fetched_ago: Some(std::time::Duration::from_secs(7_200)),
            },
        );
        assert_eq!(problems, 1, "{text}");
        assert!(
            flat(&text).contains("at least 6 commit(s) behind origin/master"),
            "{text}"
        );
        assert!(
            flat(&text).contains("as of a fetch 2h ago"),
            "a verdict from a ref must carry that ref's age: {text}"
        );
        assert!(text.contains("pull --ff-only"), "{text}");
    }

    #[test]
    fn a_diverged_checkout_is_not_offered_a_fast_forward() {
        let (text, problems) = build_section(
            &Freshness::Current,
            &Checkout::Behind {
                upstream: "origin/master".to_owned(),
                behind: 3,
                ahead: 2,
                fetched_ago: None,
            },
        );
        assert_eq!(problems, 1, "{text}");
        assert!(
            !text.contains("pull --ff-only"),
            "a fast-forward refuses with a local commit in the way, so printing it \
             sends the reader to a command that cannot work: {text}"
        );
        assert!(
            flat(&text).contains("2 local commit(s) are not on origin/master"),
            "{text}"
        );
        assert!(
            flat(&text).contains("as of a last fetch this cannot date"),
            "an unknown fetch time must not read as a recent one: {text}"
        );
    }

    #[test]
    fn a_checkout_that_is_not_behind_is_never_a_tick() {
        // The whole reason this row has no green: `@{u}` is only as new as the
        // last fetch, and nothing here fetches. A tick would be a false green
        // with an extra step.
        let (text, problems) = build_section(
            &Freshness::Current,
            &Checkout::NotBehind {
                upstream: "origin/master".to_owned(),
                ahead: 0,
                fetched_ago: Some(std::time::Duration::from_secs(604_800)),
            },
        );
        assert_eq!(problems, 0, "not behind is not a fault either: {text}");
        let checkout = line_for(&text, "checkout");
        assert!(
            checkout.trim_start().starts_with('~'),
            "the mark must be Unproven, not Proven: {checkout}"
        );
        assert!(
            line_for(&text, "build").trim_start().starts_with('+'),
            "the control: the build row above IS a tick in the same render:\n{text}"
        );
        assert!(
            flat(checkout).contains("as of a fetch 7d ago"),
            "{checkout}"
        );
        assert!(
            flat(&text).contains("NOTHING here contacted the remote"),
            "the row must say what it did not do: {text}"
        );
        assert!(text.contains("fetch"), "{text}");
    }

    #[test]
    fn an_unpushed_commit_is_reported_without_being_called_a_fault() {
        let (text, problems) = build_section(
            &Freshness::Current,
            &Checkout::NotBehind {
                upstream: "origin/master".to_owned(),
                ahead: 2,
                fetched_ago: Some(std::time::Duration::from_secs(30)),
            },
        );
        assert_eq!(
            problems, 0,
            "a row that went red between every commit and its push would be \
             removed within a week: {text}"
        );
        assert!(
            flat(&text).contains("2 local commit(s) are not pushed"),
            "{text}"
        );
    }

    #[test]
    fn a_checkout_that_cannot_be_asked_says_which_way_it_failed() {
        for (checkout, expected) in [
            (
                Checkout::CannotAsk {
                    reason: "cannot ask git: cannot run it: No such file".to_owned(),
                },
                "cannot ask git",
            ),
            (Checkout::Detached, "not on a branch"),
            (
                Checkout::NoUpstream {
                    branch: "wip".to_owned(),
                },
                "branch wip",
            ),
            (
                Checkout::Shallow {
                    upstream: "origin/master".to_owned(),
                },
                "shallow clone",
            ),
        ] {
            let (text, problems) = build_section(&Freshness::Current, &checkout);
            assert_eq!(problems, 0, "{text}");
            assert!(
                flat(&text).contains(expected),
                "{expected} missing from:\n{text}"
            );
            assert!(
                line_for(&text, "checkout").trim_start().starts_with('~'),
                "an unanswerable question is neither a pass nor a fault:\n{text}"
            );
        }
    }
}
