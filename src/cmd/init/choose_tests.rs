use super::choose::{Choice, choose};
use super::fixtures::{request, scratch};
use super::{EXIT_NEEDS_AN_ANSWER, Finding};
use crate::cmd::status::Mark;
use crate::paths::Paths;
use std::io::Cursor;

#[test]
fn a_non_interactive_run_never_waits_for_an_answer() {
    // Two agents were killed by a stall watchdog today. A setup verb that
    // can block on a prompt in a pipeline is the same defect with a friendly
    // face — so the ambiguous case exits and names the flag rather than
    // reading a stdin nobody is attached to.
    let dir = scratch("no-tty");
    let paths = Paths::under(&dir);
    let usable = [
        Finding {
            store: "keychain",
            mark: Mark::Proven,
            state: "proven",
            detail: String::new(),
            next: None,
        },
        Finding {
            store: "proton",
            mark: Mark::Proven,
            state: "proven",
            detail: String::new(),
            next: None,
        },
    ];
    let refs: Vec<&Finding> = usable.iter().collect();

    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let choice = choose(
        &request(&paths, false),
        &refs,
        &mut Cursor::new(Vec::new()),
        &mut out,
        &mut err,
    )
    .expect("write");
    match choice {
        Choice::Stop(code) => assert_eq!(code, EXIT_NEEDS_AN_ANSWER),
        Choice::Backend(id) => {
            panic!("a non-interactive run guessed `{id}` instead of asking for a flag")
        }
    }
    let text = String::from_utf8(err).expect("utf-8");
    assert!(text.contains("--store"), "{text}");
    assert!(text.contains("--yes"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_terminal_whose_stdin_ends_is_not_a_hang_either() {
    // The second shape of the same hazard: `interactive` is true because
    // both streams are terminals, and the answer never comes. `read_line`
    // returning zero is EOF, and EOF is an answer to act on — not a default
    // to silently take.
    let dir = scratch("eof");
    let paths = Paths::under(&dir);
    let usable = [
        Finding {
            store: "keychain",
            mark: Mark::Proven,
            state: "proven",
            detail: String::new(),
            next: None,
        },
        Finding {
            store: "proton",
            mark: Mark::Proven,
            state: "proven",
            detail: String::new(),
            next: None,
        },
    ];
    let refs: Vec<&Finding> = usable.iter().collect();
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let choice = choose(
        &request(&paths, true),
        &refs,
        &mut Cursor::new(Vec::new()),
        &mut out,
        &mut err,
    )
    .expect("write");
    assert!(matches!(choice, Choice::Stop(EXIT_NEEDS_AN_ANSWER)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn one_usable_backend_is_never_a_question() {
    // The control for the two tests above. Without it they pass on an
    // implementation that refuses to decide anything at all, which would
    // make `init` useless on exactly the machine it is for.
    let dir = scratch("single");
    let paths = Paths::under(&dir);
    let usable = [Finding {
        store: "keychain",
        mark: Mark::Proven,
        state: "proven",
        detail: String::new(),
        next: None,
    }];
    let refs: Vec<&Finding> = usable.iter().collect();
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let choice = choose(
        &request(&paths, false),
        &refs,
        &mut Cursor::new(Vec::new()),
        &mut out,
        &mut err,
    )
    .expect("write");
    assert!(matches!(choice, Choice::Backend("keychain")));
    assert!(String::from_utf8(err).expect("utf-8").is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nothing_usable_writes_nothing_and_says_what_it_is_waiting_for() {
    let dir = scratch("empty");
    let paths = Paths::under(&dir);
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let choice = choose(
        &request(&paths, false),
        &[],
        &mut Cursor::new(Vec::new()),
        &mut out,
        &mut err,
    )
    .expect("write");
    assert!(matches!(choice, Choice::Stop(1)));
    assert!(!paths.config.exists(), "a config was written with no store");
    let text = String::from_utf8(out).expect("utf-8");
    assert!(text.contains("--store"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
