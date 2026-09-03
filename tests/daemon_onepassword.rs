//! What a daemon-hosted 1Password lookup is allowed to reach, and where its
//! login may and may not go.
//!
//! # The property this file holds shut
//!
//! Behind the daemon the vault allowlist becomes a boundary: the daemon's `op`
//! is handed a service account the vendor minted for named vaults, and that
//! token lives in a mode-`0600` file only the daemon's uid can read. Two things
//! have to be true for that arrangement to be worth anything — the token has
//! to REACH the vendor, and it has to reach NOTHING ELSE: not the vendor's
//! argv, not the audit log, not a client that asks for it by name over the
//! socket. Every case here reads the file the stand-in vendor writes when it
//! runs, so the facts come from the vendor's side of the interface rather than
//! from the adapter's own account of what it set.
//!
//! The vault pin is asserted from the same side: a name whose entry says a
//! different vault must reach no vendor process at all, which is a listing
//! that never happened and a file that is not there.

// The daemon is macOS-only (`src/lib.rs`), so this whole file is. On any other
// platform it compiles to nothing and reports 0 tests — absent rather than
// ignored, which leaves the suite's exact ignored count alone.
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::path::Path;

use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Invocation, Resolution};

use support::{
    Backend, ONEPASSWORD_DECOY, client_config, policy_allowing_self, scratch, short_socket_path,
    start_daemon, stub_op, write_secrets,
};

/// The one name the daemon's config declares, by title.
const DECLARED: &str = "FIXTURE_DECLARED";

/// A name whose entry names a vault the store is not pinned to.
const ELSEWHERE: &str = "FIXTURE_IN_ANOTHER_VAULT";

/// The entry, in the daemon's own credential file, that holds the token.
const TOKEN_ENTRY: &str = "FIXTURE_SERVICE_ACCOUNT";

/// The stand-in service-account token. Distinct from every other decoy here,
/// and long enough that a grep for it in any output means a real leak.
const TOKEN_DECOY: &str = "decoy-Sa11-service-account-never-real-0606";

/// A daemon config carrying the 1Password store and nothing else, with a
/// service account read out of its own `0600` file.
///
/// From JSON rather than a struct literal, so the coordinates travel through a
/// file the way an operator's do, and `timeout_ms` is spelled for the reason
/// `tests/suite_hygiene.rs` enforces.
///
/// Each name carries its own `field` and the store carries no store-wide one,
/// deliberately: a store-wide `field` supplies the last coordinate an
/// UNDECLARED name is missing, which makes the pinned vault itself the
/// allowlist for every attested client. The daemon warns about that at startup,
/// so putting it back here would trade a silent fixture for a noisy one — and
/// this file's `warnings().is_empty()` is what would catch it.
fn daemon_config_with_onepassword(dir: &Path, vendor: &Path) -> DaemonConfig {
    let credentials = dir.join("onepassword-credentials.json");
    write_secrets(&credentials, &[(TOKEN_ENTRY, TOKEN_DECOY)]);
    // The `peer` block is what the config's own startup warnings read; the
    // daemon below is started with `policy_allowing_self` regardless. It is
    // here so the fixture can be asserted well-formed, which is what makes the
    // absence of a vault-pin warning a fact rather than noise.
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "peer":{{"allow_uids":[501],
                      "allow_images":["00112233445566778899aabbccddeeff00112233"]}},
             "stores":{{"onepassword":{{"enabled":true,"binary":"{vendor}","timeout_ms":60000,
                                        "vault":"company",
                                        "credentials_file":"{credentials}",
                                        "credentials":{{"OP_SERVICE_ACCOUNT_TOKEN":"{TOKEN_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"onepassword","item":"DECOY","field":"password"}},
                         "{ELSEWHERE}":{{"store":"onepassword","vault":"personal","item":"DECOY",
                                         "field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config")
}

#[test]
fn the_service_account_reaches_the_vendor_and_no_other_surface() {
    let dir = scratch("daemon-onepassword-token");
    let vendor = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let config = daemon_config_with_onepassword(&dir, &vendor);
    assert!(config.warnings().is_empty(), "{:?}", config.warnings());
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), ONEPASSWORD_DECOY),
        other => panic!(
            "the lookup must work, or nothing below is tested: {}",
            other.reason()
        ),
    }

    // It arrived, read from the child's environment by the vendor itself.
    assert_eq!(
        support::recorded(&dir.join("op.token")),
        TOKEN_DECOY,
        "the service account did not reach the vendor"
    );
    // And the reference the vendor was asked to resolve names the PINNED
    // vault and the item's id — never its title, never another vault.
    assert_eq!(
        support::recorded(&dir.join("op.probe")),
        "op://company/It3mL1v3/password"
    );

    // Nowhere else: not argv, not the audit log.
    let spawned = support::recorded_lines(&dir.join("op.argv"));
    assert!(
        !spawned.iter().any(|arg| arg.contains(TOKEN_DECOY)),
        "the credential was put on the vendor's command line: {spawned:?}"
    );
    let audit = std::fs::read_to_string(dir.join("audit.jsonl")).expect("the daemon wrote a row");
    assert!(
        !audit.contains(TOKEN_DECOY),
        "the credential reached the audit log"
    );

    // And not a name the daemon serves: asked for by its entry name over the
    // socket, it is not there.
    match registry.resolve(TOKEN_ENTRY) {
        Resolution::Found { secret, .. } => assert_ne!(
            secret.expose(),
            TOKEN_DECOY,
            "the service account was served to a client that asked for it by name"
        ),
        other => assert!(
            !other.reason().contains(TOKEN_DECOY),
            "the credential leaked through a refusal: {}",
            other.reason()
        ),
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_name_pinned_to_another_vault_reaches_no_vendor_process() {
    // The boundary, from the vendor's side. A wrong entry in the daemon's own
    // config must fail closed: no listing, no run, no file written by the
    // stand-in — and a message that names the pin.
    let dir = scratch("daemon-onepassword-other-vault");
    let vendor = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let config = daemon_config_with_onepassword(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let reason = registry.resolve(ELSEWHERE).reason();
    assert!(reason.contains("pinned to `company`"), "{reason}");
    assert!(
        !dir.join("op.argv").exists(),
        "a vendor process was spawned for a name pinned to another vault"
    );

    // The control: the declared name in the pinned vault DOES spawn one.
    assert!(registry.resolve(DECLARED).is_found());
    assert!(dir.join("op.argv").exists());

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
