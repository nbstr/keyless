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
//! # And why a gate needs a control of its own
//!
//! A gate that reads source keys on a SPELLING, and an artefact spelled
//! otherwise produces the same output as one that passed. So the failure this
//! file was written to catch reappears INSIDE the file, one level up: the gate
//! goes green, nobody looks again, and the sweep it replaced would at least
//! have been re-run.
//!
//! Measured 2026-09-12, nbstr/keyless#28: the deadline gate had been green
//! since it was written while TWENTY-ONE store objects inherited the product's
//! 10 000 ms production default. Three spellings, one cause. It walked three
//! stores and not `keychain`; it required `"enabled":true` inside the JSON, so
//! every backend `tests/init.rs` switches on from Rust was skipped; and it
//! searched for `"<store>":{` with no space, so `tests/setup.rs`'s
//! `"infisical": {` had never been read at all.
//!
//! What closes that is not a better predicate. It is a set of planted fixtures
//! carrying the verdict each must get — both directions, since a predicate that
//! flags everything passes the positive half alone — asserted in the same run as
//! the sweep, so a scan that stops matching turns the gate red instead of quiet.
//! `the_deadline_scan_sees_every_spelling_a_fixture_uses` is that control, and a
//! new spelling earns a row in it rather than a fix to the scan alone.
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

use keyless::config::MAX_TIMEOUT_MS;
use support::within;

/// Every `"timeout_ms"` a config string in `tests/` is allowed to name, and why.
///
/// Add a row rather than a value: the reason is the whole point of the table.
/// A number with no row turns this test red with the file that introduced it.
const CLASSIFIED: &[(u64, &str)] = &[
    (
        3_000,
        "tests/daemon_proton.rs — the deadline IS the subject: the generations \
         fixtures derive the retirement grace from it (`2 × timeout_ms + REAP_GRACE \
         + 1s` = 9s), and the tests wait on THAT arithmetic, not on a vendor CLI \
         that might be slow.",
    ),
    (
        200,
        "tests/daemon_degraded.rs — the deadline IS the subject: the test asserts \
         the message a client prints when a daemon does not answer.",
    ),
    (
        300,
        "tests/stores.rs — the deadline IS the subject: three fixtures assert the \
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
        "The ceiling every fixture states rather than inheriting the product's. It \
         is `keyless::config::MAX_TIMEOUT_MS`, the largest bound the tool will \
         honour, which is the nearest a config can be spelled to the `no deadline` \
         a fixture actually wants: not one of these tests asserts anything about \
         elapsed time. Named on every store object carrying a `binary`, including \
         the ones whose fixture never spawns a child — which of them does is \
         decided in Rust, where no scan can see it.",
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

/// Every store whose fixture config can point its adapter at a stub binary.
///
/// All four, and the list exists only so the scan below has something to walk:
/// there is no such thing here as a store that is exempt. It replaced a
/// three-store `SPAWNING_STORES` that left `keychain` out, on the reasoning
/// that `keychain` is enabled by DEFAULT and so writes no `"enabled":true`
/// token for a scan to find. That reasoning is about how a fixture is switched
/// ON, and the gate below no longer asks.
const CONFIGURABLE_STORES: &[&str] = &["keychain", "infisical", "onepassword", "proton"];

/// The ceiling a fixture states instead of inheriting the product's.
///
/// Written as the digits the fixtures write, NOT as `MAX_TIMEOUT_MS` — the two
/// are equal and the gate below asserts that they are. Aliasing the constant
/// would make that assertion a tautology and leave the twenty-one literals in
/// `tests/` answering to nothing.
///
/// It is [`MAX_TIMEOUT_MS`], the largest bound `keyless` will honour, which is
/// the point: a fixture asserting that a stub's value reached a child has no
/// opinion about elapsed time at all, so the honest ceiling is "no deadline",
/// and this is as near to that as a config can be spelled. It is not a bigger
/// timeout chosen over a smaller one — the smaller one was the PRODUCTION
/// default, arriving in a fixture because nobody wrote anything.
const FIXTURE_CEILING_MS: u64 = 60_000;

#[test]
fn a_fixture_that_names_a_store_binary_names_its_deadline() {
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
    // # Why it asks about the BINARY and nothing else
    //
    // 🔴 This gate was green on 2026-09-12 with TWENTY-ONE objects inheriting
    // the production default, and all three reasons were the same reason: the
    // scan keyed on a SPELLING, and an object spelled otherwise reads exactly
    // like an object that passed.
    //
    // * It walked three stores. `keychain` was left out because it is enabled
    //   by default and writes no `"enabled":true`, and `keychain` is the store
    //   the two `tests/cli.rs` cases in nbstr/keyless#28 run through.
    // * It required `"enabled":true` inside the object. `tests/init.rs` says at
    //   its head that `sole_store` turns the flags on and off ITSELF, so every
    //   backend in that file is switched on where no scan can see it — and the
    //   six `tests/init.rs` cases in that issue are those.
    // * It searched for `"<store>":{` with no space. `tests/setup.rs` writes
    //   `"infisical": {"enabled": true, "binary": …}`, which is a store it DID
    //   walk, switched on in JSON, naming a binary and no deadline, and which it
    //   had therefore never read.
    //
    // So the question is now the one property that cannot be spelled two ways
    // and cannot be moved into Rust: does this object name a `binary`? An
    // object that does is an object pointed at a path, and whether that path
    // holds a stub, holds nothing, or is never reached is decided somewhere
    // this scan cannot see. Every one of them states its ceiling; none of them
    // is exempted on a reading of what the fixture around it does, because that
    // reading is exactly what went wrong three times.
    //
    // # What it still CANNOT see
    //
    // * A deadline supplied as a Rust value rather than JSON digits. The scan
    //   only asks that `"timeout_ms"` appears inside the object; what follows
    //   it is the sibling test's business.
    // * Whether the number is big enough. That is the table above.
    // * A config assembled at runtime from pieces, with no store object in
    //   source at all.
    // The ceiling the fixtures spell has to stay the top of the range the
    // product will honour. If the clamp moves, a fixture naming the old number
    // is either clamped down without saying so or is no longer the nearest
    // thing to "no deadline" a config can express — and either way the twenty-one
    // literals in `tests/` need re-deciding rather than silently re-reading.
    assert_eq!(
        FIXTURE_CEILING_MS, MAX_TIMEOUT_MS,
        "`keyless::config::MAX_TIMEOUT_MS` moved; the ceiling every fixture \
         states has to be re-decided with it"
    );

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut sources = Vec::new();
    collect_rust_sources(&root, &mut sources);

    let mut binaries = 0usize;
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
        let characters = flattened(&text);
        for store in CONFIGURABLE_STORES {
            for object in store_objects(&characters, store) {
                if !names_a_binary(&object) {
                    continue;
                }
                binaries += 1;
                if !names_a_deadline(&object) {
                    silent.push(format!("{} — {store}", relative(&root, path)));
                }
            }
        }
    }

    // A scan that matched nothing would report every fixture as compliant.
    assert!(
        binaries >= 15,
        "only {binaries} store object(s) naming a binary were found under {}. The \
         suite has more than that, so the scan below stopped matching the spelling \
         they use — and that reads exactly like a pass.",
        root.display()
    );

    assert!(
        silent.is_empty(),
        "store object(s) naming a binary and no deadline: {}\n\n\
         Each inherits keyless::config::DEFAULT_TIMEOUT_MS, which is below the \
         {CEILING_FLOOR_MS} ms floor a ceiling has to clear, and no scan can see \
         a number nobody wrote. Spell `\"timeout_ms\":{FIXTURE_CEILING_MS}` in the \
         object, or give the fixture its own config if the deadline is what it \
         tests.",
        silent.join(", ")
    );
}

/// The control on the gate above, which is the part that was missing.
///
/// Every one of the three blind spots was a scan that stopped matching and went
/// green, so the sweep's own `binaries >= 15` floor is not enough: it proves the
/// scan matched SOMETHING, never that it matches the shape it just failed to
/// see. So each shape is planted here with the verdict it must get, and a scan
/// that loses one turns this red in the same run.
///
/// Both directions, because a predicate that flags everything passes the
/// positive half on its own and then reports the whole suite as broken.
#[test]
fn the_deadline_scan_sees_every_spelling_a_fixture_uses() {
    // (a fixture's source text, the store, objects the scan must find,
    //  how many of those it must call unbounded)
    let cases: &[(&str, &str, usize, usize)] = &[
        // The plain shape, bounded and unbounded.
        (
            r#"{"stores":{"keychain":{"binary":"S","timeout_ms":60000}}}"#,
            "keychain",
            1,
            0,
        ),
        (
            r#"{"stores":{"keychain":{"binary":"S"}}}"#,
            "keychain",
            1,
            1,
        ),
        // A space between the key and its brace — tests/setup.rs's spelling,
        // which the three-store scan walked straight past.
        (
            r#"{"stores":{"infisical": {"enabled": true, "binary": "S"}}}"#,
            "infisical",
            1,
            1,
        ),
        // Switched on nowhere in the JSON — tests/init.rs's shape, where
        // `sole_store` moves the flag in Rust.
        (
            r#"{"stores":{"onepassword": {"binary": "S", "vault": "company"}}}"#,
            "onepassword",
            1,
            1,
        ),
        // Switched OFF in the JSON and still naming a binary. Flagged too: what
        // a fixture does with that flag afterwards is not readable here.
        (
            r#"{"stores":{"proton":{"enabled":false,"binary":"S"}}}"#,
            "proton",
            1,
            1,
        ),
        // Doubled braces, which is how every one of these really appears inside
        // a `format!` template, placeholder included.
        (
            r#"{{"stores":{{"keychain":{{"binary":"{}"}}}}}}"#,
            "keychain",
            1,
            1,
        ),
        // A nested object inside the store's own — the brace match has to walk
        // out of `manager` before it decides where proton ends.
        (
            r#"{"stores":{"proton":{"manager":{"session_dir":"/s"},"binary":"S"}}}"#,
            "proton",
            1,
            1,
        ),
        // No binary at all: nothing pointed anywhere, and the gate says nothing.
        (
            r#"{"stores":{"keychain":{"enabled":true,"service":"keyless"}}}"#,
            "keychain",
            1,
            0,
        ),
        // A FIELD whose name is a store's, holding a path rather than an object.
        // tests/config_paths.rs writes `"keychain":"…"` inside the keychain
        // store, and a scan that counted it would report an object that is not
        // there and then report it as unbounded.
        (
            r#"{"stores":{"keychain":{"binary":"S","keychain":"K","timeout_ms":60000}}}"#,
            "keychain",
            1,
            0,
        ),
        // Two objects of one store in one file, one bounded and one not.
        (
            r#"a: {"keychain":{"binary":"S","timeout_ms":60000}} b: {"keychain":{"binary":"S"}}"#,
            "keychain",
            2,
            1,
        ),
    ];

    for (source, store, expected_objects, expected_silent) in cases {
        let objects = store_objects(&flattened(source), store);
        assert_eq!(
            objects.len(),
            *expected_objects,
            "the scan found {} `{store}` object(s), not {expected_objects}, in:\n{source}",
            objects.len()
        );
        let silent = objects
            .iter()
            .filter(|object| names_a_binary(object) && !names_a_deadline(object))
            .count();
        assert_eq!(
            silent, *expected_silent,
            "the scan called {silent} `{store}` object(s) unbounded, not \
             {expected_silent}, in:\n{source}"
        );
    }
}

/// Whether a store object points its adapter at a path of its own.
fn names_a_binary(object: &str) -> bool {
    object.contains(r#""binary""#)
}

/// Whether a store object states its own ceiling rather than inheriting one.
fn names_a_deadline(object: &str) -> bool {
    object.contains(r#""timeout_ms""#)
}

/// One test source as the character buffer every scan below walks.
///
/// The config strings are `format!` templates, so their literal braces are
/// doubled. They are halved here, which also turns a `{}` placeholder into a
/// balanced empty pair — harmless, because only the brace COUNT decides where
/// an object ends.
///
/// Characters rather than bytes, in one index space throughout: this file's own
/// prose carries non-ASCII, and the version before this one mixed a byte offset
/// from `str::find` with a character count taken from the same string.
fn flattened(text: &str) -> Vec<char> {
    text.replace("{{", "{").replace("}}", "}").chars().collect()
}

/// Every `"<store>" : { … }` object in `text`, brace-balanced.
///
/// Takes the buffer [`flattened`] produces rather than the source, so a file
/// scanned for four stores is converted once instead of four times.
///
/// Whitespace between the key, its colon and its brace is skipped rather than
/// required to be absent. A fixture written `"infisical": {` is the same fixture
/// as one written `"infisical":{`, and JSON puts neither under a rule — so a
/// scan that could see only the second reported the first as compliant without
/// ever having looked at it.
fn store_objects(characters: &[char], store: &str) -> Vec<String> {
    let key: Vec<char> = format!("\"{store}\"").chars().collect();
    let mut out = Vec::new();

    let mut at = 0;
    while let Some(found) = characters[at..]
        .windows(key.len())
        .position(|window| window == key.as_slice())
    {
        let mut cursor = at + found + key.len();
        // The key is followed by optional space, a colon, optional space, and
        // then either the object this is looking for or something else — a
        // string, a number — which is not one and is skipped.
        skip_whitespace(characters, &mut cursor);
        let colon = characters.get(cursor) == Some(&':');
        cursor += 1;
        skip_whitespace(characters, &mut cursor);
        if !colon || characters.get(cursor) != Some(&'{') {
            at = at + found + key.len();
            continue;
        }

        let start = cursor;
        let mut depth = 0usize;
        let mut end = None;
        for (offset, character) in characters[start..].iter().enumerate() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(start + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        // An unbalanced tail is a template this scan cannot read, not an object
        // with no deadline — it is skipped rather than reported, and the floor
        // on the sweep above is what catches a scan that skips everything.
        match end {
            Some(end) => {
                out.push(characters[start..=end].iter().collect());
                at = end + 1;
            }
            None => break,
        }
    }
    out
}

/// Advance `cursor` past any run of whitespace, in the one index space
/// [`store_objects`] works in.
///
/// One function rather than the two copies this was: the skip rule is one rule,
/// and a rule spelled twice is a rule that disagrees with itself the first time
/// somebody widens it.
fn skip_whitespace(characters: &[char], cursor: &mut usize) {
    while characters.get(*cursor).is_some_and(|c| c.is_whitespace()) {
        *cursor += 1;
    }
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
