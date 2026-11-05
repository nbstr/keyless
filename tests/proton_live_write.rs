//! A write through a viewer-role token, against a real account.
//!
//! Live, `#[ignore]`d and run by hand: how to run them, which fixtures they
//! need and what they must never do is the header of `tests/proton_live.rs`.

mod proton_live_support;

use keyless::config::Config;
use keyless::store::proton::Reason;

use proton_live_support::required;

/// 14. A viewer-role token cannot write, and the failure names the role.
///
/// **This is the one write assertion this account can make.** Measured
/// 2026-08-08: `--role` on `pass-cli agent access grant` defaults to `viewer`, so
/// a token minted without thinking about the role is read-only and `item create`
/// answers `NotAllowed`. A bare `NotAllowed` sends the reader hunting through
/// vault permissions, which are not the problem.
///
/// It deliberately points the MANAGER session at the reader's session directory:
/// that is the only editor-shaped configuration this account can express, and the
/// point is that even so the vendor refuses. **Nothing is created by this test**
/// — the refusal is the assertion. Once a real editor token exists, this test
/// needs `KEYLESS_LIVE_MANAGER_SESSION_DIR` pointed at it and inverting.
#[test]
#[ignore = "needs a live Proton Pass account and an agent token"]
fn a_live_viewer_role_token_cannot_create_and_the_failure_names_the_role() {
    let session = required("KEYLESS_LIVE_SESSION_DIR");
    let vault = required("KEYLESS_LIVE_VAULT");
    let config: Config = serde_json::from_str(&format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"session_dir":"{session}","timeout_ms":30000,
                        "manager":{{"session_dir":"{session}","timeout_ms":30000}}}}}},
            "secrets":{{"DECOY":{{"vault":"{vault}",
                                  "item":"keyless-live-write-probe-do-not-create",
                                  "field":"password"}}}}}}"#
    ))
    .expect("valid config");

    let manager = keyless::store::manage::manager(&config, "proton", &Reason::for_verb("new"))
        .expect(
            "a manager block is configured, so a writer must be constructible even if it cannot \
             write",
        );
    assert_eq!(manager.identity(), "proton (manager)");

    let message = manager
        .store(
            "DECOY",
            &config.route("DECOY"),
            &keyless::secret::Secret::new("decoy-live-write-probe-value".to_owned()),
        )
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());

    assert!(
        message.contains("ROLE") || message.contains("role"),
        "the refusal must attach the fix to the failure: {message}"
    );
    assert!(
        message.contains("--role editor"),
        "the refusal must name the flag: {message}"
    );
    assert!(
        !message.contains("decoy-live-write-probe-value"),
        "the refusal carried the value"
    );
}
