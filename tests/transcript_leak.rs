//! The spawn an agent is pointed at never surfaces a value — measured on the
//! exact shape that leaked.
//!
//! On 2026-09-26 an agent refused a vault print verb ran the store's own runner
//! instead, as a presence check: `sh -c '…${VAR:+set}${VAR:-ABSENT}…'`. The
//! expansion substitutes the VALUE whenever it is set, and the runner passed the
//! child's output straight to the transcript. The hook pack now refuses that
//! runner and names `keyless run` as the only spawn, so the claim that matters is
//! this file's: the same shape under `keyless run` prints no value, on either
//! stream, however the child splits its writes.
//!
//! Every assertion is an EQUALITY on the whole stream, one per test. A substring
//! check for "the value is absent" also passes when the value was never injected
//! — the expansion then prints `ABSENT` and nothing leaks because nothing was
//! there. The exact expected text carries the mask token, so it is false both
//! when the value leaks and when it never arrived.
//!
//! The `known_limit_` tests pin what masking does NOT cover. Each is a ceiling
//! written down in `src/mask/mod.rs` as a `debt:` marker, and each goes red the
//! day the ceiling moves, so the marker and the behaviour cannot drift apart.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use support::{DECOY_VALUE, Stub, install_executable, keychain_stub_config, scratch};

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// A second decoy, distinct from [`DECOY_VALUE`], for the comparison that must
/// say `different`. Served by [`two_value_config`] under the name `OTHER`.
const OTHER_VALUE: &str = "decoy-Qw55-another-coined-value-0077";

/// The mask token `keyless run` substitutes for the secret named `DECOY`.
const MASKED: &str = "[keyless:DECOY]";

fn one_value_config(dir: &Path) -> PathBuf {
    keychain_stub_config(dir, &Stub::Returns(DECOY_VALUE), r#"{"DECOY":{}}"#)
}

/// A keychain stand-in serving two DIFFERENT values: `OTHER` gets
/// [`OTHER_VALUE`], every other name gets [`DECOY_VALUE`].
fn two_value_config(dir: &Path) -> PathBuf {
    let stub = install_executable(
        &dir.join("security-stub"),
        &format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
             \x20 find-generic-password)\n\
             \x20   case \"$*\" in\n\
             \x20     *OTHER*) printf '%s\\n' '{OTHER_VALUE}' ;;\n\
             \x20     *) printf '%s\\n' '{DECOY_VALUE}' ;;\n\
             \x20   esac\n\
             \x20   exit 0 ;;\n\
             esac\n\
             exit 1\n"
        ),
    );
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{}","timeout_ms":60000}}}},
                "secrets":{{"DECOY":{{}},"SAME":{{}},"OTHER":{{}}}}}}"#,
            stub.display()
        ),
    )
    .expect("write config");
    path
}

/// `keyless run --config <config> <specs…> -- sh -c <script>`, stdio piped.
fn run_script(config: &Path, audit: &Path, specs: &[&str], script: &str) -> Output {
    let mut command = Command::new(BIN);
    command
        .arg("run")
        .arg("--config")
        .arg(config)
        .arg("--audit")
        .arg(audit);
    for spec in specs {
        command.arg("-s").arg(spec);
    }
    command
        .args(["--", "/bin/sh", "-c", script])
        .stdin(Stdio::null())
        .output()
        .expect("the binary must run")
}

fn leak_run(tag: &str, script: &str) -> Output {
    let dir = scratch(tag);
    let config = one_value_config(&dir);
    run_script(&config, &dir.join("audit.jsonl"), &["DECOY"], script)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The leaking shape, with the stdout write and the stderr write it carried.
const LEAKING_SHAPE: &str = r#"echo "[${DECOY:+set}${DECOY:-ABSENT}]"; echo "${DECOY}" >&2"#;

/// Writes the value in two pieces with a pause between them, so the two
/// halves reach `keyless` as separate reads.
fn split_script(redirect: &str) -> String {
    format!(
        r#"printf '%s' "$(printf '%s' "$DECOY" | cut -c1-10)" {redirect}; sleep 0.2; printf '%s\n' "$(printf '%s' "$DECOY" | cut -c11-)" {redirect}"#
    )
}

#[test]
fn the_leaking_presence_check_prints_no_value_on_stdout() {
    let output = leak_run("leak-stdout", LEAKING_SHAPE);
    assert_eq!(text(&output.stdout), format!("[set{MASKED}]\n"));
}

#[test]
fn the_leaking_presence_check_prints_no_value_on_stderr() {
    let output = leak_run("leak-stderr", LEAKING_SHAPE);
    assert_eq!(text(&output.stderr), format!("{MASKED}\n"));
}

#[test]
fn a_value_split_across_two_writes_to_stdout_is_masked() {
    let output = leak_run("split-stdout", &split_script(""));
    assert_eq!(text(&output.stdout), format!("{MASKED}\n"));
}

#[test]
fn a_value_split_across_two_writes_to_stderr_is_masked() {
    let output = leak_run("split-stderr", &split_script(">&2"));
    assert_eq!(text(&output.stderr), format!("{MASKED}\n"));
}

/// A ceiling, not a guarantee: each stream has its own masking writer, so
/// half of the value on stdout and half on stderr is two unmatched fragments.
/// Whoever merges the two streams — a terminal, a Bash tool — reassembles it.
#[test]
fn known_limit_a_value_split_across_the_two_streams_is_not_masked() {
    let output = leak_run(
        "split-across",
        r#"printf '%s' "$(printf '%s' "$DECOY" | cut -c1-17)"; printf '%s\n' "$(printf '%s' "$DECOY" | cut -c18-)" >&2"#,
    );
    assert_eq!(
        (text(&output.stdout), text(&output.stderr)),
        (
            DECOY_VALUE[..17].to_owned(),
            format!("{}\n", &DECOY_VALUE[17..])
        ),
        "if this now masks, the cross-stream ceiling in src/mask/mod.rs has moved \
         and its debt marker must change with it"
    );
}

/// A ceiling, not a guarantee: a needle is a WHOLE value or a whole encoding
/// of one, so a proper fragment of the value passes unmasked.
#[test]
fn known_limit_a_fragment_of_a_value_is_not_masked() {
    let output = leak_run(
        "fragment",
        r#"printf '%s\n' "$(printf '%s' "$DECOY" | cut -c1-20)""#,
    );
    assert_eq!(
        text(&output.stdout),
        format!("{}\n", &DECOY_VALUE[..20]),
        "if this now masks, the fragment ceiling in src/mask/mod.rs has moved \
         and its debt marker must change with it"
    );
}

/// The comparison the refusals recommend: one `keyless run` inside another,
/// each binding its own variable, so the child compares two values and only
/// its verdict reaches the output. The recipe is copied here verbatim in shape,
/// three-way on purpose: a bare `[ "$A" = "$B" ]` says `identical` when NEITHER
/// name resolved, and that was measured — breaking `ENV=NAME` left both
/// variables unset and the two-way recipe reported a match.
fn compare(tag: &str, second: &str) -> Output {
    let dir = scratch(tag);
    let config = two_value_config(&dir);
    let audit = dir.join("audit.jsonl");
    let inner = format!(
        r#"'{BIN}' run --config '{}' --audit '{}' -s B={second} -- /bin/sh -c 'if [ -z "$A" ] || [ -z "$B" ]; then echo "unset: A=${{A:+set}} B=${{B:+set}}"; elif [ "$A" = "$B" ]; then echo identical; else echo different; fi'"#,
        config.display(),
        audit.display(),
    );
    run_script(&config, &audit, &["A=DECOY"], &inner)
}

#[test]
fn nested_runs_report_identical_values_without_printing_either() {
    let output = compare("compare-same", "SAME");
    assert_eq!(text(&output.stdout), "identical\n");
}

#[test]
fn nested_runs_report_different_values_without_printing_either() {
    let output = compare("compare-other", "OTHER");
    assert_eq!(text(&output.stdout), "different\n");
}
