//! The vendor's own output masking, measured against a real account.
//!
//! Live, `#[ignore]`d and run by hand: how to run them, which fixtures they
//! need and what they must never do is the header of `tests/proton_live.rs`.

mod proton_live_support;
mod support;

use std::path::Path;

use proton_live_support::required;
use support::scratch;

/// 3. The two maskers do not collide, because only one is ever in the pipe.
///
/// `keyless` spawns the user's command **itself** — `pass-cli` is in the pipe
/// for the probe and nowhere else — so the vendor's masking never sees the real
/// child's output and this crate's masker never sees the vendor's placeholder.
/// The one place they could collide is the probe, which reads its child's
/// stdout: leave the vendor's masking on there and the adapter injects the
/// placeholder as though it were the credential.
///
/// So this measures the vendor directly, in both settings, and proves
/// `--no-masking` is load-bearing rather than decorative. Nothing here goes
/// through `keyless`, on purpose: the adapter always passes the flag, so the
/// unflagged behaviour is unreachable from inside it.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn the_vendor_conceals_the_probes_own_output_unless_masking_is_switched_off() {
    let dir = scratch("proton-live-masking");
    let reference = required("KEYLESS_LIVE_REFERENCE");
    let env_file = dir.join("probe.dotenv");
    std::fs::write(&env_file, format!("KEYLESS_PROBE={reference}\n")).expect("write the env file");

    let unmasked = probe_directly(&env_file, true);
    let masked = probe_directly(&env_file, false);

    assert!(
        !unmasked.contains("concealed"),
        "`--no-masking` did not switch the vendor's masking off"
    );
    assert!(
        masked.to_ascii_lowercase().contains("concealed"),
        "the vendor did not conceal without the flag, so the guard in `proton.rs` \
         is protecting against nothing — re-read what it substitutes now"
    );
    assert_ne!(
        masked.len(),
        unmasked.len(),
        "both settings produced the same number of bytes"
    );
}

/// Run the vendor's `run` verb directly and return its child's stdout.
///
/// Returns the raw bytes as a string — which for `no_masking` is the decoy
/// value — so every caller must assert on it without printing it.
fn probe_directly(env_file: &Path, no_masking: bool) -> String {
    let mut command = std::process::Command::new("pass-cli");
    command.arg("run").arg("--env-file").arg(env_file);
    if no_masking {
        command.arg("--no-masking");
    }
    // This test drives the vendor directly, so it does not get the adapter's
    // ambient-reference filter for free. The runner's own inputs hold `pass://`
    // strings, and `pass-cli run` resolves every one it finds in the inherited
    // environment — which would fail this probe for a reason that has nothing
    // to do with masking.
    for key in ["KEYLESS_LIVE_REFERENCE", "KEYLESS_LIVE_FOREIGN"] {
        command.env_remove(key);
    }
    command
        .arg("--")
        .arg("/usr/bin/printenv")
        .arg("KEYLESS_PROBE")
        .env(
            "PROTON_PASS_SESSION_DIR",
            required("KEYLESS_LIVE_SESSION_DIR"),
        )
        .env(
            "PROTON_PASS_AGENT_REASON",
            "keyless test suite: measuring the vendor's masking default",
        );
    let output = command.output().expect("`pass-cli` must be on PATH");
    assert!(
        output.status.success(),
        "the vendor CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned()
}
