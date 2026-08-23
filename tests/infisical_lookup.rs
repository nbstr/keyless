//! What an Infisical LOOKUP is allowed to answer from.
//!
//! # The defect this file exists to hold shut
//!
//! The listing (`tests/infisical_listing.rs`) runs the vendor with a cleared
//! environment, so nothing this process carries can be reported as something
//! the store holds. The lookup did not, and the lookup's child is
//! `printenv KEY` — which cannot tell a variable the vendor injected from one
//! the caller already exported. So the probe answered from the caller's own
//! environment and the adapter reported it as a credential:
//!
//! ```text
//! NAMES
//!   ✔ X  proven     read back from infisical      <- store holds NOTHING
//! ```
//!
//! Measured against a stand-in vendor that injects nothing at all, with `X`
//! exported in the calling shell. It was not confined to the nine forwarded
//! names; it applied to every name, and `keyless run` on the same evidence
//! wrote an `INJECTED` audit row naming that store — a durable wrong answer,
//! not just a printed one.
//!
//! # What is asserted, and what is deliberately not
//!
//! Every case here fixes the vendor's behaviour and asks what `keyless` does
//! with it. **Nothing here asserts what the real Infisical CLI does when a
//! secret's name collides with a variable it was handed** — whether its
//! injection wins is the vendor's own business, and settling it would need a
//! real secret in a real project. The adapter compares the value it reads back
//! against the bytes it forwarded, so it is correct under either precedence,
//! and both branches are covered below.
//!
//! # Why the binary rather than the library
//!
//! `doctor --probe` and `run` are the two surfaces that reported the false
//! green, and a library test would exercise neither. Every case drives the real
//! binary.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::scratch;

const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// The declared name most cases use. Not credential-shaped, so the fixture can
/// be read without anybody wondering whether it is real.
const NAME: &str = "FIXTURE_MARKER";

/// What the CALLER exports. If this ever reaches the child, the lookup answered
/// from this process's environment.
const FROM_THE_CALLER: &str = "fixture-value-from-the-calling-shell-A1";

/// What the STAND-IN VENDOR injects. Distinct from the value above, so "which
/// side answered?" is a question every assertion here can ask.
const FROM_THE_STORE: &str = "fixture-value-from-the-stand-in-store-B2";

/// Appended to `PATH` for the collision cases.
///
/// `PATH` has to keep working — the vendor and the probe are found through it —
/// so the forwarded value cannot be replaced with a marker. A suffix naming a
/// directory that does not exist changes nothing about resolution and makes the
/// forwarded value greppable.
const PATH_SUFFIX: &str = "/keyless-fixture-no-such-directory-C3";

/// What a stand-in injects for `PATH` when it is standing in for a store that
/// really holds one. Absolute-looking and unique; nothing ever executes through
/// it, because the probe binary is `/usr/bin/printenv` by absolute path.
const PATH_FROM_THE_STORE: &str = "/keyless-fixture-the-store-said-this-D4";

fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("cannot write the stand-in");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("cannot chmod the stand-in");
    }
    path
}

/// The prologue every stand-in shares.
///
/// It records what environment it was handed — the only way to prove the
/// clearing from outside — then steps over the adapter's flags to the child.
///
/// `${VAR-DEFAULT}` rather than `${VAR:-DEFAULT}`, so a variable that arrived
/// EMPTY is told apart from one that never arrived at all.
fn prologue(dir: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         printf '%s' \"${{{NAME}-ABSENT}}\" > '{dir}/vendor-saw'\n\
         printf '%s' \"${{HOME-NOHOME}}\" > '{dir}/vendor-home'\n\
         while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         shift\n",
        dir = dir.display()
    )
}

/// The epilogue of a faithful stand-in: report the CHILD's exit status the way
/// the vendor does.
///
/// Measured against 0.43.114 and recorded in the adapter: an unset variable
/// makes `printenv` exit 1 and the CLI answers
/// `failed to wait for command termination: exit status 1`. That sentence is
/// what tells "the store does not hold it" apart from "Infisical broke", so a
/// stand-in that omitted it would exercise the wrong branch.
const CHILD_STATUS: &str = "\"$@\" || { \
     echo \"failed to wait for command termination: exit status $?\" >&2; exit 1; }\n";

/// A stand-in for a store that holds nothing at the coordinate.
fn vendor_holding_nothing(dir: &Path) -> PathBuf {
    let body = format!("{}{CHILD_STATUS}", prologue(dir));
    write_stub(dir, "infisical-empty", &body)
}

/// A stand-in for a store that holds one secret, injected the way the vendor
/// injects: into the child's environment, overriding whatever was there.
fn vendor_holding(dir: &Path, key: &str, value: &str) -> PathBuf {
    let body = format!(
        "{prologue}/usr/bin/env \"{key}={value}\" {CHILD_STATUS}",
        prologue = prologue(dir)
    );
    write_stub(dir, &format!("infisical-holds-{key}"), &body)
}

/// A config wired to a stand-in, declaring exactly one name against Infisical.
///
/// The store is pinned on the name so the keychain on the developer's own
/// machine cannot answer instead and make a case pass for the wrong reason.
/// `timeout_ms` is spelled out for the reason `tests/suite_hygiene.rs` enforces:
/// a fixture killed by its own deadline fails in a shape that reads as a
/// missing fixture.
fn config_for(dir: &Path, vendor: &Path, name: &str) -> PathBuf {
    // Named after the VENDOR as well as the name: two configs in one case
    // differ only in which stand-in they point at, and a shared filename would
    // silently make the second overwrite the first.
    let path = dir.join(format!(
        "config-{name}-{}.json",
        vendor.file_name().unwrap_or_default().to_string_lossy()
    ));
    let body = format!(
        r#"{{"stores":{{"infisical":{{"enabled":true,"binary":"{}","path":"/backend","timeout_ms":60000}}}},
            "secrets":{{"{name}":{{"env":"dev","store":"infisical"}}}}}}"#,
        vendor.display()
    );
    std::fs::write(&path, body).expect("cannot write the config");
    path
}

/// Run the binary with the caller's environment carrying `NAME`.
///
/// That export is the whole experiment: it is the value a non-hermetic probe
/// reads back and reports as the store's.
fn keyless(config: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(BIN);
    command
        .arg("--config")
        .arg(config)
        .arg("--no-audit")
        .args(args)
        .env(NAME, FROM_THE_CALLER);
    command.output().expect("the binary must run")
}

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The one `NAMES` row, so an assertion cannot be satisfied by another section.
/// The state column of a rendered row: `<mark> <subject> <state> <detail>`.
///
/// Read as a whole column, because `unproven` CONTAINS `proven` — so
/// `contains("proven")` passes on the one state it exists to exclude. Measured
/// over this tree: every `proven` in the crate can be rewritten to `unproven`,
/// leaving a green mark beside the word that denies it, and the suite stays
/// green.
fn state_of(row: &str) -> &str {
    row.split_whitespace().nth(2).unwrap_or_default()
}

fn names_row(out: &str, name: &str) -> String {
    out.lines()
        .skip_while(|line| !line.starts_with("NAMES"))
        .find(|line| line.contains(name))
        .unwrap_or_else(|| panic!("no NAMES row for `{name}`, so this case proves nothing:\n{out}"))
        .to_owned()
}

// ---------------------------------------------------------------------------
// The defect itself.
// ---------------------------------------------------------------------------

#[test]
fn a_value_this_process_carries_is_never_reported_as_read_back_from_the_store() {
    let dir = scratch("infisical-lookup-shadow");

    // The negative control FIRST, and it is not decoration: it is what makes
    // the assertion below a statement about provenance rather than about a
    // lookup that never happened. Same name, same caller environment, same
    // command — the ONLY difference is that this vendor holds the secret.
    let holding = config_for(&dir, &vendor_holding(&dir, NAME, FROM_THE_STORE), NAME);
    let (control, control_err) = text(&keyless(&holding, &["doctor", "--probe"]));
    assert_eq!(
        state_of(&names_row(&control, NAME)),
        "proven",
        "a store that HOLDS the name must resolve it, or every assertion below \
         is satisfied by a lookup that cannot work at all: {control}{control_err}"
    );

    // And now the same command against a store that holds nothing.
    let empty = config_for(&dir, &vendor_holding_nothing(&dir), NAME);
    let (out, err) = text(&keyless(&empty, &["doctor", "--probe"]));
    let row = names_row(&out, NAME);
    assert!(
        !row.contains("proven"),
        "the caller's own environment was reported as read back from the store: {row}"
    );
    assert!(
        row.contains("absent"),
        "a store holding nothing must say so: {row}"
    );
    assert!(
        !format!("{out}{err}").contains(FROM_THE_CALLER),
        "the caller's value reached the output: {out}{err}"
    );
}

#[test]
fn the_vendor_is_handed_a_cleared_environment_on_a_lookup_too() {
    // Proved by a side effect the parent cannot fake: the stand-in writes down
    // what it was handed, and the test reads that file rather than the
    // adapter's own account of itself.
    let dir = scratch("infisical-lookup-cleared");
    let config = config_for(&dir, &vendor_holding_nothing(&dir), NAME);
    let _ = keyless(&config, &["doctor", "--probe"]);

    let saw = std::fs::read_to_string(dir.join("vendor-saw")).expect("the stand-in ran");
    assert_eq!(
        saw, "ABSENT",
        "the caller's environment reached the vendor, so `printenv` answers from it"
    );

    // The other half, and the reason the clearing is a filter rather than a
    // wipe: without HOME the vendor cannot find its login, and a lookup that
    // authenticates as nobody is not a safer lookup.
    let home = std::fs::read_to_string(dir.join("vendor-home")).expect("the stand-in ran");
    assert_ne!(home, "NOHOME", "HOME must still reach the vendor");
    assert!(!home.is_empty());
}

#[test]
fn a_run_degrades_rather_than_injecting_the_callers_own_environment() {
    // `doctor --probe` is a report; `run` is the surface that hands a value to
    // a program, and a successful run says NOTHING — so this case reads what
    // the child was actually given rather than what the tool said about it.
    // The child writes to a FILE: masking rewrites the stream keyless relays,
    // which would make a stdout assertion here a test of the masker.
    let dir = scratch("infisical-lookup-run");
    let seen = dir.join("child-saw");
    let script = format!("printf '%s' \"${{{NAME}-UNSET}}\" > '{}'", seen.display());
    let child: [&str; 4] = ["--", "/bin/sh", "-c", script.as_str()];

    let holding = config_for(&dir, &vendor_holding(&dir, NAME, FROM_THE_STORE), NAME);
    let mut control = vec!["run", "-s", NAME];
    control.extend_from_slice(&child);
    let output = keyless(&holding, &control);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", text(&output).1);
    assert_eq!(
        std::fs::read_to_string(&seen).expect("the child ran"),
        FROM_THE_STORE,
        "a store that HOLDS the name must deliver ITS value, or every assertion \
         below is satisfied by a lookup that cannot work at all"
    );

    // Same command, same caller environment; only the store changes.
    let empty = config_for(&dir, &vendor_holding_nothing(&dir), NAME);
    let mut degraded = vec!["run", "-s", NAME];
    degraded.extend_from_slice(&child);
    let output = keyless(&empty, &degraded);
    let (out, err) = text(&output);
    assert!(err.contains("DEGRADED"), "{err}");
    assert!(
        err.contains(NAME),
        "the degrade must name what did not resolve: {err}"
    );
    assert!(
        !format!("{out}{err}").contains(FROM_THE_CALLER),
        "the caller's value reached the output: {out}{err}"
    );
    // What the child sees is the caller's own untouched environment, which is
    // exactly right — and is why the report above matters. The defect was never
    // that the child got the wrong bytes; it was that `keyless` claimed to have
    // fetched them.
    assert_eq!(
        std::fs::read_to_string(&seen).expect("the child ran"),
        FROM_THE_CALLER
    );
    // Never blocks. A lookup that could not answer degrades the run and
    // forwards the child's own exit code, which is this tool's whole contract.
    assert_eq!(output.status.code(), Some(0), "stderr: {err}");
}

// ---------------------------------------------------------------------------
// The one collision the clearing cannot remove: a key the vendor itself needs.
// ---------------------------------------------------------------------------

/// `PATH`, with a marker appended, and the store's own answer if there is one.
fn keyless_with_marked_path(config: &Path, args: &[&str]) -> Output {
    let inherited = std::env::var("PATH").expect("the test runner has a PATH");
    let mut command = Command::new(BIN);
    command
        .arg("--config")
        .arg(config)
        .arg("--no-audit")
        .args(args)
        .env("PATH", format!("{inherited}:{PATH_SUFFIX}"));
    command.output().expect("the binary must run")
}

#[test]
fn a_forwarded_name_the_store_does_not_hold_is_named_rather_than_returned() {
    // `PATH` must be handed to the vendor for it to run at all, so clearing
    // cannot make this lookup exact. The adapter compares instead: what came
    // back is what went in, so it says so and returns nothing.
    let dir = scratch("infisical-lookup-forwarded-absent");
    let config = config_for(&dir, &vendor_holding_nothing(&dir), "PATH");
    let (out, err) = text(&keyless_with_marked_path(&config, &["doctor", "--probe"]));

    let row = names_row(&out, "PATH");
    assert!(
        !row.contains("proven"),
        "this machine's own PATH was reported as a credential: {row}"
    );
    assert!(
        out.contains("byte-for-byte the one that was handed in"),
        "the collision must be named, not merely reported as a failure: {out}"
    );
    assert!(
        !format!("{out}{err}").contains(PATH_SUFFIX),
        "the forwarded value reached the output: {out}{err}"
    );
}

#[test]
fn a_forwarded_name_the_store_does_hold_still_resolves() {
    // The other branch, and the one the module docs claim: a lookup consults
    // the coordinate directly and never the listing, so a name the listing
    // cannot show is still resolvable. It holds only when the vendor's
    // injection outranks the forwarded variable — which is why the adapter
    // compares rather than assumes, and why the case above exists beside this
    // one.
    let dir = scratch("infisical-lookup-forwarded-held");
    let vendor = vendor_holding(&dir, "PATH", PATH_FROM_THE_STORE);
    let config = config_for(&dir, &vendor, "PATH");
    let (out, err) = text(&keyless_with_marked_path(&config, &["doctor", "--probe"]));

    let row = names_row(&out, "PATH");
    assert_eq!(
        state_of(&row),
        "proven",
        "a store that holds a forwarded name must still resolve it: {out}{err}"
    );
    assert!(
        !format!("{out}{err}").contains(PATH_FROM_THE_STORE),
        "the value reached the output: {out}{err}"
    );
}

#[test]
fn a_forwarded_name_this_machine_does_not_set_is_an_ordinary_secret() {
    // The asymmetry the whole forwarding rule rests on: `HTTPS_PROXY` is on the
    // forwarded LIST, but on a machine that sets no proxy nothing forwards it,
    // so a secret of that name collides with nothing and resolves like any
    // other. Removed explicitly rather than assumed absent — a developer with a
    // proxy configured would otherwise get a different test.
    let dir = scratch("infisical-lookup-forwarded-unset");
    let vendor = vendor_holding(&dir, "HTTPS_PROXY", FROM_THE_STORE);
    let config = config_for(&dir, &vendor, "HTTPS_PROXY");
    let output = Command::new(BIN)
        .arg("--config")
        .arg(&config)
        .arg("--no-audit")
        .args(["doctor", "--probe"])
        .env_remove("HTTPS_PROXY")
        .output()
        .expect("the binary must run");
    let (out, err) = text(&output);

    let row = names_row(&out, "HTTPS_PROXY");
    assert_eq!(
        state_of(&row),
        "proven",
        "an unset forwarded name collides with nothing and must resolve: {out}{err}"
    );
    assert!(
        !out.contains("byte-for-byte"),
        "nothing was forwarded, so there is no collision to report: {out}"
    );
}
