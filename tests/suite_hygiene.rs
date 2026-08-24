//! Properties of the SUITE, asserted by the suite.
//!
//! Everything else in `tests/` checks the tool. This file checks the fixtures,
//! because a fixture can be wrong in a way that no amount of green will show.
//!
//! # The defect this exists for
//!
//! Every store adapter runs its vendor CLI under a deadline, and every fixture
//! that wants a SUCCESS therefore has to name one. That number is a CEILING and
//! never a measurement: a test asserting "the value reached the child" has no
//! opinion about how long the stub took. So the only thing the number decides is
//! **how loaded this machine has to be before a passing test reports a
//! failure.**
//!
//! It was `5000` almost everywhere, which encodes "no fork of `/bin/sh` is ever
//! slower than five seconds". Measured 2026-08-09 on macOS, with a `cargo
//! mutants` campaign running beside the suite at `--jobs 2`: six fixtures in
//! `tests/stores.rs` failed with `no answer within 5000 ms`, and all of them
//! passed the moment the suite ran alone.
//!
//! Both shapes that produces are worse than a plain failure:
//!
//! * A FALSE RED. `the_proton_reason_never_carries_an_argument_value` panics
//!   with `pass-cli.reason was never written` — the stub was killed before its
//!   first line ran, so a runtime artefact is absent and the panic reads like a
//!   missing fixture file. It sent one reader looking for a file to commit; the
//!   file is written by a shell stub into a per-test scratch directory and must
//!   never be in the repository.
//! * A FALSE GREEN, which is the expensive one.
//!   `a_name_with_no_infisical_environment_still_spawns_the_child` says in its
//!   own comment that the answering stub is what stops it being vacuous. A stub
//!   that times out cannot answer, so under load that test asserts a degrade
//!   that would happen anyway — it goes green while measuring nothing.
//!
//! # Why a gate rather than a sweep
//!
//! The sweep was done twice and missed three call sites both times, in two files
//! nobody thought to look at (`tests/cli.rs`, `tests/never_block.rs`). A number
//! that has to be remembered is a number that drifts back.
//!
//! # What this CANNOT see, which is most of the reason to read it
//!
//! * **Only the JSON spelling.** It reads `"timeout_ms":<digits>` out of the
//!   config strings. Deadlines passed as Rust values —
//!   `DaemonStore::new(path, Duration::from_secs(10))`, `client_config(sock,
//!   3_000)` — are invisible here.
//!
//!   **This hole has bitten, and the claim that its margin is wider was wrong.**
//!   `src/ipc/client.rs` handed both of its cases a 200 ms deadline that bounds
//!   a THREAD SPAWN, not a socket: `Client::request` waits on a channel with the
//!   same duration it gives the connection, so an absent socket answers
//!   `Unreachable` only when the worker is scheduled in time and reports
//!   `Timeout` when it is not. It went red on a loaded machine, green on an idle
//!   one, and the code it tests never changed. Both are ceilings now, named and
//!   reasoned about at the constant.
//!
//!   Measured 2026-08-09, the size of what is still unseen: **29 Rust-spelled
//!   deadlines in `src/` test modules, across `store/exec.rs`,
//!   `daemon/resolver.rs`, `ipc/client.rs` and `tty/relay.rs`.** Most are
//!   genuine SUBJECTS — `exec.rs` asserts timeout wording, `resolver.rs` sizes a
//!   coalescing window — so a table of them is not a sweep, it is 29 readings of
//!   code, and a table filled with guesses states them as checked facts. That is
//!   the failure this file exists to prevent, so the hole is measured here
//!   rather than closed badly.
//! * **It cannot tell a ceiling from a measurement.** That is why the table
//!   below is a table and not a threshold: only a human knows whether a number
//!   is the subject of a test or merely a bound on it. A threshold would have
//!   had to call `750` (a value under test in `tests/hostile.rs`) and `5000` (a
//!   ceiling that broke) the same thing.
//! * It scans SOURCE. A fixture that computes a timeout at runtime is not seen.
//!
//! # The other half of this class, which no deadline can classify
//!
//! A deadline reports that a fixture did not finish. It cannot say whether the
//! fixture was merely slow or whether it was waiting on a descriptor a stranger
//! is holding open — and in one process running its cases in parallel, the
//! second happens. A descriptor that is not close-on-exec at the instant
//! another thread forks walks into that child, and into the shell and the
//! backgrounded grandchild it starts. The case that owns it then waits for an
//! end-of-file only a process it has never heard of can send. This suite starts
//! grandchildren that outlive their session by two minutes on purpose, so
//! "until that stranger exits" is longer than every deadline in it.
//!
//! **A number cannot tell those apart, so raising one converts a diagnosable
//! failure into a slower diagnosable failure.** `tests/pty.rs` closed its own
//! instance by creating its terminal's descriptors with the flag already set,
//! which it can do because it opens them itself.
//!
//! The flag is only the worse half of the class, and a descriptor that has it
//! escapes too. `FD_CLOEXEC` is spent by an `exec`, never by a `fork`, so a
//! close-on-exec descriptor still walks into every child forked while it is
//! open and stays there until that child reaches its own `exec`. What it can do
//! from inside that window depends on what it is: a write end of an executable
//! file makes `execve` refuse the file with `ETXTBSY`, which is why
//! `support::install_executable` creates a stub in a process this one's threads
//! cannot fork a copy of rather than opening it here.

// A plain comment and NOT a `//!` one, which is the difference between a marker
// and a marker nobody harvests: the debt ledger strips a language's line-comment
// prefix before it looks for the word, so `//` off `//! debt:` leaves `! debt:`
// and matches nothing. The paragraph below is the ledger's input, not rustdoc's.
//
// debt: the pipe-shaped instance is the one still open. A terminal and an
//       executable are opened by this suite, so each can be created somewhere
//       a `fork` here cannot reach. A pipe cannot: it is created INSIDE
//       `Command::spawn`, so there is no seam to pass a flag through and the
//       fix is a different one — serialise every spawn in a test binary
//       against every other, the way `keyless::store::exec` already serialises
//       the library's own. Under a probe — several threads calling
//       `Command::output` beside several more spawning children — a stray pipe
//       does escape, in a small fraction of the children; the same probe inside
//       `tests/hostile.rs`, which makes four piped children a run, never saw
//       one. So the mechanism is real here and its exposure is not.
//       Upgrade trigger: any descriptor this suite creates turns out to be
//       reachable from a process it was never handed to. The class is a
//       WINDOW, not a fixture shape and not a deadline: a `fork` on any thread
//       copies the whole descriptor table, so the escape is identical whatever
//       the descriptor is and only the symptom differs. Any one of these is
//       this mechanism and is enough on its own: a fixture that waits out its
//       deadline on an end-of-file and passes alone; an `execve` refused
//       `ETXTBSY` on a file this suite has already finished writing; a path, a
//       socket or a lock still held after the case that made it has ended; or
//       any failure that reproduces under parallel cases and never at
//       `--test-threads=1`. That last one is the discriminator the other three
//       are read against, because nothing else in this suite is sensitive to
//       thread count in that direction.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use support::within;

/// Every `"timeout_ms"` a config string in `tests/` is allowed to name, and why.
///
/// Add a row rather than a value: the reason is the whole point of the table.
/// A number with no row turns this test red with the file that introduced it.
const CLASSIFIED: &[(u64, &str)] = &[
    (
        200,
        "tests/daemon_degraded.rs — the deadline IS the subject: the test asserts \
         the message a client prints when a daemon does not answer.",
    ),
    (
        300,
        "tests/stores.rs — the deadline IS the subject: two fixtures assert the \
         wording of `no answer within 300 ms` against a stub that sleeps.",
    ),
    (
        750,
        "tests/hostile.rs — not a deadline at all. It is the negative control for \
         timeout clamping, and the test asserts the parsed value comes back \
         unchanged. Nothing is spawned.",
    ),
    (
        20_000,
        "tests/proton_live.rs — a ceiling on the REAL `pass-cli` against a real \
         Proton account over the network. Every test using it is `#[ignore]`d and \
         needs credentials, so it never runs in CI.",
    ),
    (
        30_000,
        "tests/proton_live.rs — the same, for the discovery and write probes, \
         which make more round trips than a single read.",
    ),
    (
        60_000,
        "The generous ceiling for a stub that MUST answer. Not a measurement: no \
         fixture using it asserts anything about elapsed time. It is set far above \
         any plausible `fork` + `exec` so that a loaded machine cannot turn a \
         passing test red.",
    ),
    (
        86_400_000,
        "tests/hostile.rs — a day, named deliberately by a hostile config to prove \
         `stores.daemon.timeout_ms` is clamped. The number is the attack.",
    ),
];

/// The floor a ceiling has to clear. Below this, a number must be a deliberate
/// measurement with its own row above, or it is the defect this file exists for.
const CEILING_FLOOR_MS: u64 = 20_000;

#[test]
fn every_fixture_deadline_is_classified() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = Vec::new();
    collect_rust_sources(&root, &mut sources);
    assert!(
        sources.len() >= 10,
        "only {} source files were found under {} — the scan collapsed, and a \
         scan that reads nothing passes everything",
        sources.len(),
        root.display()
    );

    let mut found: BTreeSet<(u64, String)> = BTreeSet::new();
    for path in &sources {
        // This file's own prose names every value in the table, so scanning it
        // would just read the table back and prove nothing.
        if path
            .file_name()
            .is_some_and(|name| name == "suite_hygiene.rs")
        {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let name = relative(&root, path);
        for value in timeouts_in(&text) {
            found.insert((value, name.clone()));
        }
    }

    assert!(
        !found.is_empty(),
        "no `\"timeout_ms\":<digits>` was found anywhere under {}. Either every \
         fixture stopped naming a deadline, or the scan below stopped matching \
         the spelling they use — and the second reads exactly like a pass.",
        root.display()
    );

    let known: BTreeSet<u64> = CLASSIFIED.iter().map(|(value, _)| *value).collect();
    let unclassified: Vec<&(u64, String)> = found
        .iter()
        .filter(|(value, _)| !known.contains(value))
        .collect();

    assert!(
        unclassified.is_empty(),
        "unclassified fixture deadline(s): {}\n\n\
         Add a row to CLASSIFIED in tests/suite_hygiene.rs saying which kind of \
         number this is.\n\
         * Is the deadline the SUBJECT of the test — does it assert the timeout \
         message? Then say so, and keep it small.\n\
         * Is it a CEILING on a stub that must answer? Then it belongs at {} or \
         above, and {} is what the rest of the suite uses. A ceiling below {} ms \
         does not measure the tool; it measures how busy this machine is.",
        unclassified
            .iter()
            .map(|(value, file)| format!("{value} in {file}"))
            .collect::<Vec<_>>()
            .join(", "),
        CEILING_FLOOR_MS,
        60_000,
        CEILING_FLOOR_MS
    );
}

/// The two stores whose fixtures spawn a vendor CLI and whose `enabled` default
/// is `false`, so that enabling one has to be spelled out and can be scanned for.
///
/// `keychain` is deliberately absent and that is this gate's largest blind
/// spot: it is enabled by DEFAULT, so a fixture that spawns the `security` stub
/// need write nothing at all, and there is no token here to find. Closing that
/// needs a different mechanism than a source scan.
const SPAWNING_STORES: &[&str] = &["infisical", "proton"];

#[test]
fn a_fixture_that_spawns_a_vendor_cli_names_its_deadline() {
    // # The hole this closes, which is the ABSENCE of a number
    //
    // `every_fixture_deadline_is_classified` above reads the deadlines that
    // were WRITTEN. A store object that names none is invisible to it and
    // inherits `keyless::config::DEFAULT_TIMEOUT_MS` — 10 000 ms, which is half
    // the floor that test sets for a ceiling on a stub that must answer.
    //
    // Measured 2026-08-09: seven store objects across three files named no
    // deadline in source. Only some of those were actually unbounded — the
    // Proton builder in `tests/stores.rs` took one from its callers, so it is
    // flagged here while its fixtures were bounded correctly. The Infisical
    // builder beside it took one from nobody, and the eleven fixtures built
    // from it ran on the 10 000 ms default while reading as green.
    //
    // That difference is why this test asks about the OBJECT rather than the
    // fixture: an object that carries its deadline somewhere a scan cannot see
    // is indistinguishable, here, from one that has none. Both are refused, and
    // spelling the number is the fix for either.
    //
    // So a number that has to be remembered drifts back, AND a number nobody
    // wrote cannot be scanned for at all. This test asks the opposite question
    // to its sibling: not "is this value classified?" but "is there a value?".
    //
    // # What it CANNOT see
    //
    // * A store enabled by default — see [`SPAWNING_STORES`].
    // * A deadline supplied as a Rust value rather than JSON digits. The scan
    //   only asks that `"timeout_ms"` appears inside the object; what follows
    //   it is the sibling test's business.
    // * Whether the number is big enough. That is the table above.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = Vec::new();
    collect_rust_sources(&root, &mut sources);

    let mut spawning = 0usize;
    let mut silent: Vec<String> = Vec::new();
    for path in &sources {
        if path
            .file_name()
            .is_some_and(|name| name == "suite_hygiene.rs")
        {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        for store in SPAWNING_STORES {
            for object in store_objects(&text, store) {
                // A store that is not switched on spawns nothing, and one with
                // no `binary` cannot reach a stub — neither has a deadline to
                // miss.
                if !object.contains(r#""enabled":true"#) || !object.contains(r#""binary""#) {
                    continue;
                }
                spawning += 1;
                if !object.contains(r#""timeout_ms""#) {
                    silent.push(format!("{} — {store}", relative(&root, path)));
                }
            }
        }
    }

    // A scan that matched nothing would report every fixture as compliant.
    assert!(
        spawning >= 5,
        "only {spawning} spawning store fixture(s) were found under {}. The suite \
         has more than that, so the scan below stopped matching the spelling they \
         use — and that reads exactly like a pass.",
        root.display()
    );

    assert!(
        silent.is_empty(),
        "store fixture(s) that spawn a vendor CLI and name no deadline: {}\n\n\
         Each inherits keyless::config::DEFAULT_TIMEOUT_MS, which is below the \
         {CEILING_FLOOR_MS} ms floor a ceiling has to clear, and no scan can see \
         a number nobody wrote. Spell `\"timeout_ms\":60000` in the object, or \
         give the fixture its own config if the deadline is what it tests.",
        silent.join(", ")
    );
}

/// Every `"<store>":{ … }` object in `text`, brace-balanced.
///
/// The config strings are `format!` templates, so their literal braces are
/// doubled. They are halved first, which also turns a `{}` placeholder into a
/// balanced empty pair — harmless here, because only the brace COUNT decides
/// where an object ends.
fn store_objects(text: &str, store: &str) -> Vec<String> {
    let flattened = text.replace("{{", "{").replace("}}", "}");
    let needle = format!("\"{store}\":{{");
    let mut out = Vec::new();
    let bytes: Vec<char> = flattened.chars().collect();
    let mut from = 0;
    while let Some(at) = flattened[from..].find(&needle) {
        let open = from + at + needle.len() - 1;
        let start = flattened[..open].chars().count();
        let mut depth = 0usize;
        let mut end = start;
        for (offset, character) in bytes[start..].iter().enumerate() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(bytes[start..=end].iter().collect());
        from = from + at + needle.len();
    }
    out
}

/// Every `"timeout_ms":<digits>` in `text`.
///
/// A format placeholder (`"timeout_ms":{timeout_ms}` in the daemon helper) has
/// no digits after the colon and is skipped, which is correct: the value comes
/// from the caller and is a Rust expression this scan cannot see.
fn timeouts_in(text: &str) -> Vec<u64> {
    const KEY: &str = "\"timeout_ms\"";
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(KEY) {
        rest = &rest[at + KEY.len()..];
        let after = rest.trim_start();
        let Some(after) = after.strip_prefix(':') else {
            continue;
        };
        let digits: String = after
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(value) = digits.parse::<u64>() {
            out.push(value);
        }
    }
    out
}

/// The bound that wraps most of this suite must still FIRE, and nothing else
/// here proves it.
///
/// Every other test in the repository proves [`support::within`] does not fire
/// when it should not — that is what the rest of the suite going green means.
/// None of them proves the other direction, and a watchdog that has stopped
/// firing is invisible: it looks exactly like a suite with no hangs in it. So
/// this case hands it one.
///
/// It matters more since the bound stopped being a wall clock. `within` charges
/// a body only for the share of the machine it was actually handed, which is
/// what stops a starved test being reported as a stalled one — and the failure
/// mode of that idea is an instrument so forgiving it never reports anything at
/// all. This is the control on exactly that.
///
/// The hang is a receive on a channel whose sender has been leaked: nothing can
/// ever send, and nothing can ever disconnect. It costs no cpu at all while its
/// wall clock runs, which is the whole shape of a real hang and precisely the
/// shape a wall clock cannot tell apart from a machine that is merely busy.
#[test]
#[should_panic(expected = "HUNG")]
fn a_body_that_never_makes_progress_is_reported_as_hung() {
    within(
        // Far below anything a real case uses. The number is not a ceiling on
        // any behaviour: it is how long this test is willing to spend proving
        // that a bound still has teeth.
        Duration::from_millis(250),
        "a deliberate hang",
        || {
            let (sender, receiver) = std::sync::mpsc::channel::<()>();
            std::mem::forget(sender);
            let _ = receiver.recv();
        },
    );
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}
