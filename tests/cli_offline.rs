mod cli_support;
mod support;

use cli_support::BIN;

// ---------------------------------------------------------------------------
// Nothing leaves the machine.
// ---------------------------------------------------------------------------

/// Every offset in `haystack` at which `needle` appears, case-insensitively.
fn occurrences(haystack: &[u8], needle: &str) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| window.eq_ignore_ascii_case(needle.as_bytes()))
        .map(|(at, _)| at)
        .collect()
}

/// Every occurrence of `word` in `haystack`, classified against the literals
/// in `allowed` by the bytes around it — never by a second scan of `haystack`
/// per literal.
///
/// Returns which of `allowed` each classified hit matched, and the offsets of
/// every hit that matched none of them. `haystack` is a built binary, tens of
/// megabytes, so this runs the one scan for `word` and then, per hit, a cheap
/// bounds check against each literal — not a full re-scan for each.
fn classify<'a>(haystack: &[u8], word: &str, allowed: &[&'a str]) -> (Vec<&'a str>, Vec<usize>) {
    let mut matched = Vec::new();
    let mut unmatched = Vec::new();
    'hits: for at in occurrences(haystack, word) {
        for literal in allowed {
            // The offset of `word` within `literal`, so the literal's own
            // start can be found from where `word` was found.
            let offset = literal
                .to_ascii_lowercase()
                .find(&word.to_ascii_lowercase())
                .unwrap_or_else(|| {
                    panic!("`{word}` does not appear in the allowed literal `{literal}`")
                });
            if at < offset {
                continue;
            }
            let start = at - offset;
            let end = start + literal.len();
            if haystack
                .get(start..end)
                .is_some_and(|window| window.eq_ignore_ascii_case(literal.as_bytes()))
            {
                matched.push(*literal);
                continue 'hits;
            }
        }
        unmatched.push(at);
    }
    (matched, unmatched)
}

#[test]
fn the_binary_contains_no_network_endpoint() {
    // The reference implementation posted the user's email to a hard-coded
    // endpoint with no opt-out, while its docs claimed it collected nothing.
    // This test reads the built binary and fails if a URL scheme appears in it
    // outside of the strings this project deliberately ships.
    scan_for_endpoints(BIN);
}

#[test]
fn the_daemon_binary_contains_no_network_endpoint_either() {
    // The daemon is the process that holds every credential and runs
    // unattended for weeks. It is the last thing that should be able to reach
    // the network, and it is the one a reader is least likely to check.
    let daemon = std::path::Path::new(BIN)
        .parent()
        .map(|dir| dir.join("keylessd"))
        .expect("the test binary has a parent directory");
    assert!(
        daemon.is_file(),
        "keylessd was not built; expected it at {}",
        daemon.display()
    );
    scan_for_endpoints(&daemon.display().to_string());
}

fn scan_for_endpoints(path: &str) {
    let binary = std::fs::read(path).expect("read the built binary");
    for needle in [
        "https://api.",
        "http://",
        "vercel.app",
        "analytics",
        "sentry.io",
        "amplitude",
        "posthog",
    ] {
        assert!(
            occurrences(&binary, needle).is_empty(),
            "{path} contains `{needle}`"
        );
    }
}

/// `pass-cli`'s own telemetry switch-off, in the shape it is set — see
/// `store::proton::DISABLE_TELEMETRY_VAR`. Written out here rather than
/// imported from the crate, for the same reason as `ONLY_ALLOWED` in each
/// test below: a test that reads the same constant the implementation uses
/// would keep passing if that constant were renamed away from the word it
/// exists to allow.
const PROTON_DISABLE_TELEMETRY: &str = "PROTON_PASS_DISABLE_TELEMETRY";

/// `pass-cli`'s own update-check switch-off — see
/// `store::proton::NO_UPDATE_CHECK_VAR`. Written out here for the same reason
/// as `PROTON_DISABLE_TELEMETRY` above: it contains no `telemetry`, so a hit
/// on it is never found by the scan for that word and is checked on its own.
const PROTON_NO_UPDATE_CHECK: &str = "PROTON_PASS_NO_UPDATE_CHECK";

#[test]
fn the_only_telemetry_string_in_the_binary_is_the_one_that_switches_it_off() {
    // The Infisical CLI's telemetry defaults to ON, so the adapter passes
    // `--telemetry=false` on every invocation it makes — otherwise `keyless`
    // would be the reason a report left the machine, which is exactly what the
    // blanket ban above exists to prevent.
    //
    // So the word is allowed, and only in that one shape. Written out here
    // rather than imported from the crate: a test that reads the same constant
    // the implementation uses would keep passing if that constant were edited
    // to `--telemetry=true`.
    const ONLY_ALLOWED: &str = "--telemetry=false";

    let binary = std::fs::read(BIN).expect("read the built binary");
    let (matched, unmatched) = classify(
        &binary,
        "telemetry",
        &[ONLY_ALLOWED, PROTON_DISABLE_TELEMETRY],
    );
    assert!(
        unmatched.is_empty(),
        "the binary contains a `telemetry` string that is not `{ONLY_ALLOWED}` or \
         `{PROTON_DISABLE_TELEMETRY}`: at {unmatched:?}"
    );
    assert!(
        matched.contains(&ONLY_ALLOWED),
        "`{ONLY_ALLOWED}` is absent; the vendor CLI's telemetry is no longer being disabled"
    );
    assert!(
        matched.contains(&PROTON_DISABLE_TELEMETRY),
        "`{PROTON_DISABLE_TELEMETRY}` is absent; the Proton Pass CLI's telemetry is no longer \
         being disabled"
    );
    assert!(
        !occurrences(&binary, PROTON_NO_UPDATE_CHECK).is_empty(),
        "`{PROTON_NO_UPDATE_CHECK}` is absent; the Proton Pass CLI's update check is no longer \
         being disabled"
    );
}

#[test]
fn the_daemon_carries_no_telemetry_string_of_its_own() {
    // `scan_for_endpoints` deliberately stopped banning the word outright, so
    // without this the daemon is the one binary nothing checks for it. It links
    // the same library, so `--telemetry=false` may legitimately appear; what
    // must not appear is any OTHER telemetry string.
    //
    // Presence is not asserted for `--telemetry=false` here, unlike for the
    // client: the daemon does not construct the Infisical adapter, so whether
    // that literal survives is a linker decision and not a property worth
    // pinning. `PROTON_PASS_DISABLE_TELEMETRY` and `PROTON_PASS_NO_UPDATE_CHECK`
    // are different: the daemon's own login verb is built to set both on every
    // `pass-cli login` / `info` / `logout` it spawns. A hit here only proves
    // the literal survived linking, never that a call site reaches it — that
    // is a property of the source, and the scan that proves it reads the
    // source rather than this binary.
    const ONLY_ALLOWED: &str = "--telemetry=false";
    let daemon = std::path::Path::new(BIN)
        .parent()
        .map(|dir| dir.join("keylessd"))
        .expect("the test binary has a parent directory");
    let binary = std::fs::read(&daemon).expect("read the built daemon");

    let (matched, unmatched) = classify(
        &binary,
        "telemetry",
        &[ONLY_ALLOWED, PROTON_DISABLE_TELEMETRY],
    );
    assert!(
        unmatched.is_empty(),
        "keylessd contains a `telemetry` string that is not `{ONLY_ALLOWED}` or \
         `{PROTON_DISABLE_TELEMETRY}`: at {unmatched:?}"
    );
    assert!(
        matched.contains(&PROTON_DISABLE_TELEMETRY),
        "`{PROTON_DISABLE_TELEMETRY}` is absent from keylessd; the Proton Pass CLI's telemetry \
         is no longer being disabled there"
    );
    assert!(
        !occurrences(&binary, PROTON_NO_UPDATE_CHECK).is_empty(),
        "`{PROTON_NO_UPDATE_CHECK}` is absent from keylessd; the Proton Pass CLI's update check \
         is no longer being disabled there"
    );
}
