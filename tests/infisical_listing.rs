//! `keyless items --store infisical`, under a vendor that is trying to leak.
//!
//! # What this file is for
//!
//! The listing is taken from a child process's ENVIRONMENT rather than from a
//! vendor's text output, and the whole claim of that design is that a value
//! cannot be smuggled out as a name. A claim like that is worth exactly as much
//! as the fixture that attacks it, so this file builds a stand-in `infisical`
//! whose injected values are chosen to break every filter that could be
//! *nearly* right:
//!
//! | The value contains | What it breaks |
//! |---|---|
//! | a newline | a line-based reader: the second line has no `=`, so a stripper passes it through as a key |
//! | a tab | the listing's own column separator |
//! | an `=` | a reader that splits on the LAST `=`, or on every one |
//! | a JSON brace and a `secretKey` key | a reader that treats vendor output as JSON |
//! | an ANSI escape | a reader that trusts a terminal to render what it is handed |
//! | a string shaped like a key name | a reader that recognises names by looking at them |
//!
//! Every one of those values is asserted ABSENT from everything the command
//! writes. The names beside them are asserted PRESENT, which is what stops this
//! file passing because nothing ran.
//!
//! # Why the binary rather than the library
//!
//! The listing probe is `keyless` running itself: the adapter resolves
//! `current_exe()` and spawns it as `keyless __names`. Inside a test binary
//! `current_exe()` is the test harness, which has no such verb — so a library
//! test would exercise a pipeline that cannot exist in production. Every case
//! here drives the real binary.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::{install_executable, scratch};

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// A marker exported into the CHILD's environment by the test itself.
///
/// The adapter clears the environment before the vendor runs, so this must not
/// reach the stand-in. It is the only way to prove the clearing from outside.
const MARKER: &str = "KEYLESS_TEST_MARKER";

/// Values that must never appear in anything the command writes.
///
/// Each is the payload half of one hostile variable in [`hostile_vendor`]. They
/// share no prefix with any name, so a match is a leak and never a coincidence.
const SMUGGLED: [&str; 5] = [
    "SMUGGLEDBYNEWLINE",
    "SMUGGLEDBYEQUALS",
    "SMUGGLEDBYJSON",
    "SMUGGLEDBYANSI",
    "SMUGGLEDBYLOOKALIKE",
];

/// The names those values sit behind. Present is the negative control.
const HOSTILE_NAMES: [&str; 6] = [
    "HOSTILE_NEWLINE",
    "HOSTILE_TAB",
    "HOSTILE_EQUALS",
    "HOSTILE_JSON",
    "HOSTILE_ANSI",
    "HOSTILE_LOOKALIKE",
];

fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    install_executable(&dir.join(name), body)
}

/// The prologue every stand-in shares: record what environment it was handed,
/// then step over the adapter's flags to the child command.
///
/// `${VAR-DEFAULT}` rather than `${VAR:-DEFAULT}`, so a variable that arrived
/// EMPTY is told apart from one that never arrived at all.
fn prologue(dir: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         printf '%s' \"${{{MARKER}-ABSENT}}\" > '{dir}/vendor-marker'\n\
         printf '%s' \"${{HOME-NOHOME}}\" > '{dir}/vendor-home'\n\
         while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         shift\n",
        dir = dir.display()
    )
}

/// A stand-in `infisical` that injects six values built to escape as names.
///
/// The bytes are embedded LITERALLY — a real newline, a real tab, a real escape
/// — rather than written as `printf '\n'` sequences. `/bin/sh` is dash on Debian
/// and bash-in-sh-mode on macOS, and a fixture whose hostility depends on which
/// one expanded a backslash is a fixture that quietly tests nothing on one of
/// the two platforms.
fn hostile_vendor(dir: &Path) -> PathBuf {
    let body = format!(
        "{prologue}\
         exec /usr/bin/env \
         \"HOSTILE_NEWLINE=first line\nSMUGGLEDBYNEWLINE=second line\" \
         \"HOSTILE_TAB=before\tafter\" \
         \"HOSTILE_EQUALS=a=SMUGGLEDBYEQUALS=b\" \
         \"HOSTILE_JSON={{\\\"secretKey\\\":\\\"SMUGGLEDBYJSON\\\"}}\" \
         \"HOSTILE_ANSI=\u{1b}[31mSMUGGLEDBYANSI\u{1b}[0m\" \
         \"HOSTILE_LOOKALIKE=SMUGGLEDBYLOOKALIKE\" \
         \"$@\"\n",
        prologue = prologue(dir)
    );
    write_stub(dir, "infisical-hostile", &body)
}

/// A config wired to a stand-in vendor.
///
/// `timeout_ms` is spelled out rather than inherited. The default deadline is
/// below the floor `tests/suite_hygiene.rs` enforces, and that gate exists
/// because a fixture killed by its own timeout under load fails in a shape that
/// reads as a missing fixture file — or worse, passes while measuring a degrade
/// that would have happened anyway. The number is a CEILING, never a
/// measurement: nothing here has an opinion about how long a `/bin/sh` fork
/// takes.
fn config_for(dir: &Path, vendor: &Path) -> PathBuf {
    let path = dir.join("config.json");
    let body = format!(
        r#"{{"stores":{{"infisical":{{"enabled":true,"binary":"{}","path":"/backend","timeout_ms":60000}}}},
            "secrets":{{"DECLARED":{{"env":"dev"}}}}}}"#,
        vendor.display()
    );
    std::fs::write(&path, body).expect("cannot write the config");
    path
}

/// Run `keyless items` against a stand-in, with the marker exported.
fn items(config: &Path, extra: &[&str]) -> Output {
    let mut command = Command::new(BIN);
    command
        .arg("--config")
        .arg(config)
        .arg("--no-audit")
        .arg("items")
        .arg("infisical")
        .args(extra)
        .env(MARKER, "the-parent-environment-must-not-be-inherited");
    command.output().expect("the binary must run")
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// The property the design rests on.
// ---------------------------------------------------------------------------

#[test]
fn a_vendor_that_injects_hostile_values_yields_names_and_nothing_else() {
    let dir = scratch("infisical-listing-hostile");
    let config = config_for(&dir, &hostile_vendor(&dir));

    let output = items(&config, &["--vault", "dev:/backend"]);
    let (out, err) = text(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the listing must succeed; stderr was: {err}"
    );

    // The negative control FIRST. Everything below would also hold for a
    // command that printed nothing at all.
    for name in HOSTILE_NAMES {
        assert!(
            out.contains(name),
            "`{name}` was injected and is not in the listing, so this case proves nothing: {out}"
        );
    }

    let everything = format!("{out}{err}");
    for value in SMUGGLED {
        assert!(
            !everything.contains(value),
            "a value reached the output: `{value}` in {everything:?}"
        );
    }
    // The pieces of a value that are not words: the escape byte itself, the
    // JSON key a structural reader would have trusted, and the tail of the
    // value whose name is legitimate.
    for fragment in ["\u{1b}", "secretKey", "second line", "before\tafter"] {
        assert!(
            !everything.contains(fragment),
            "a fragment of a value reached the output: {fragment:?} in {everything:?}"
        );
    }

    // Shape, not just content: a smuggled newline or tab would show up as a row
    // with the wrong number of columns long before anybody read the words.
    for line in out.lines() {
        assert_eq!(
            line.split('\t').count(),
            4,
            "a row has the wrong column count, which is what a smuggled separator \
             looks like: {line:?}"
        );
    }
}

#[test]
fn the_vendor_is_handed_a_cleared_environment_and_still_gets_its_login() {
    // Proved by a side effect the parent cannot fake: the stand-in writes down
    // what it was given, and the test reads that file rather than the adapter's
    // own account of itself.
    let dir = scratch("infisical-listing-cleared");
    let config = config_for(&dir, &hostile_vendor(&dir));
    let output = items(&config, &["--vault", "dev"]);
    assert_eq!(output.status.code(), Some(0));

    let marker = std::fs::read_to_string(dir.join("vendor-marker")).expect("the stand-in ran");
    assert_eq!(
        marker, "ABSENT",
        "the parent's environment reached the vendor, so every variable this \
         process carries would be listed as though the store held it"
    );

    // The other half, and the reason the clearing is a filter rather than a
    // wipe: without HOME the vendor cannot find its login, and a listing that
    // authenticates as nobody is not a safer listing.
    let home = std::fs::read_to_string(dir.join("vendor-home")).expect("the stand-in ran");
    assert_ne!(home, "NOHOME", "HOME must still reach the vendor");
    assert!(!home.is_empty());
}

#[test]
fn a_forwarded_variable_is_not_listed_as_though_the_store_held_it() {
    let dir = scratch("infisical-listing-forwarded");
    let config = config_for(&dir, &hostile_vendor(&dir));
    let (out, _) = text(&items(&config, &["--vault", "dev"]));

    // HOME and PATH reach the child because the vendor needs them, so they are
    // in the child's environment and are filtered back out. This is the
    // documented blind spot stated as a test: a secret really named `PATH`
    // would be missing from this listing too, and `doctor --probe` is the check
    // that answers for one name.
    for forwarded in ["HOME", "PATH"] {
        assert!(
            !out.lines().any(|line| line.ends_with(forwarded)),
            "`{forwarded}` was forwarded to the vendor and must not be reported \
             as something the store holds: {out}"
        );
    }
}

// ---------------------------------------------------------------------------
// What the vendor does to the stream it shares with the child.
// ---------------------------------------------------------------------------

#[test]
fn vendor_noise_on_the_childs_stream_does_not_become_a_row() {
    // `infisical run` does not exec the child; it forks and waits, so it writes
    // to the same stdout before and after. Unframed, the banner below would fuse
    // with the first name and every listing's first row would be wrong.
    let dir = scratch("infisical-listing-noise");
    let body = format!(
        "{prologue}\
         printf 'Injecting 172 Infisical secrets\\n'\n\
         /usr/bin/env \"REAL_KEY=irrelevant\" \"$@\"\n\
         printf 'a trailing tip nobody asked for\\n'\n",
        prologue = prologue(&dir)
    );
    let config = config_for(&dir, &write_stub(&dir, "infisical-noisy", &body));

    let output = items(&config, &["--vault", "dev"]);
    let (out, err) = text(&output);
    assert_eq!(output.status.code(), Some(0), "stderr: {err}");

    // The secret the stand-in injected is listed, and neither thing it printed
    // around the child is.
    assert!(
        out.lines().any(|line| line.ends_with("\tREAL_KEY")),
        "the injected secret is missing, so this case proves nothing: {out}"
    );
    assert!(!out.contains("Injecting"), "{out}");
    assert!(!out.contains("trailing tip"), "{out}");

    // NOT a row count. `/bin/sh` sets `PWD`, `SHLVL` and `_` in the stand-in
    // itself, downstream of the clearing, so an exact count would be an
    // assertion about this fixture's shell rather than about the code. The real
    // CLI spawns the child directly and adds none of them — measured against
    // 0.43.114, where a live listing matched a name-set taken independently.
    // Filtering them in the adapter would be the wrong repair anyway: it would
    // hide a secret genuinely named `PWD`.
    for line in out.lines() {
        assert_eq!(
            line.split('\t').count(),
            4,
            "a row has the wrong column count: {line:?}"
        );
    }
}

#[test]
fn a_probe_that_never_ran_is_an_error_and_never_an_empty_store() {
    // The two answers call for opposite actions — fix your install, or write a
    // secret — so a build that reported both as zero rows would send somebody
    // to the Infisical UI to look for keys that are right there.
    let dir = scratch("infisical-listing-silent");
    let body = format!("{prologue}exit 0\n", prologue = prologue(&dir));
    let config = config_for(&dir, &write_stub(&dir, "infisical-silent", &body));

    let output = items(&config, &["--vault", "dev"]);
    let (out, err) = text(&output);
    assert_eq!(output.status.code(), Some(1), "stdout was: {out}");
    assert!(out.is_empty(), "a broken probe printed a listing: {out}");
    assert!(err.contains("did not run"), "{err}");
    assert!(
        !err.contains("no items"),
        "an absent probe must not be reported as an empty coordinate: {err}"
    );
}

#[test]
fn a_failing_vendor_reports_its_first_line_and_no_more_of_its_stderr() {
    // A subprocess's stderr is not ours to forward whole. Measured against
    // 0.43.114, a failed fetch answers with one sentence naming the coordinate
    // and an empty stdout — but the cap is what makes that a property of this
    // code rather than a habit of that release.
    let dir = scratch("infisical-listing-failing");
    let body = format!(
        "{prologue}\
         echo 'error: failed to fetch secrets for path \"/backend\": status-code=404' >&2\n\
         echo 'SMUGGLEDBYSECONDLINE' >&2\n\
         exit 1\n",
        prologue = prologue(&dir)
    );
    let config = config_for(&dir, &write_stub(&dir, "infisical-failing", &body));

    let output = items(&config, &["--vault", "dev"]);
    let (out, err) = text(&output);
    assert_eq!(output.status.code(), Some(1));
    assert!(out.is_empty(), "a failure printed a listing: {out}");
    assert!(err.contains("failed to fetch secrets"), "{err}");
    assert!(
        err.contains("dev:/backend"),
        "the message must name the coordinate that failed: {err}"
    );
    assert!(
        !err.contains("SMUGGLEDBYSECONDLINE"),
        "the whole of the vendor's stderr was forwarded: {err}"
    );
}

// ---------------------------------------------------------------------------
// What it refuses to guess.
// ---------------------------------------------------------------------------

#[test]
fn with_no_location_it_lists_the_declared_coordinate_and_no_other() {
    let dir = scratch("infisical-listing-declared");
    let config = config_for(&dir, &hostile_vendor(&dir));
    let (out, err) = text(&items(&config, &[]));

    // The config declares exactly one Infisical coordinate, so a bare `items`
    // lists that one. It is an allowlist, and the default is to honour it.
    assert!(!out.is_empty(), "stderr: {err}");
    for line in out.lines() {
        assert!(
            line.starts_with("dev:/backend\t"),
            "a coordinate nobody declared was listed: {line}"
        );
    }
}

#[test]
fn a_location_with_no_environment_is_refused_by_the_binary() {
    let dir = scratch("infisical-listing-noenv");
    let config = config_for(&dir, &hostile_vendor(&dir));
    let output = items(&config, &["--vault", ":/backend"]);
    let (out, err) = text(&output);
    assert_ne!(output.status.code(), Some(0));
    assert!(out.is_empty());
    assert!(err.contains("names no Infisical environment"), "{err}");
}

#[test]
fn the_environment_alias_is_the_same_flag() {
    // `--env` is what somebody types after reading `keyless run --env staging`,
    // and answering it with `unexpected argument` would send them to the manual
    // for a flag that is right there under another name.
    let dir = scratch("infisical-listing-alias");
    let config = config_for(&dir, &hostile_vendor(&dir));
    let (by_env, _) = text(&items(&config, &["--env", "dev:/backend"]));
    let (by_vault, _) = text(&items(&config, &["--vault", "dev:/backend"]));
    assert!(!by_env.is_empty());
    assert_eq!(by_env, by_vault);
}
