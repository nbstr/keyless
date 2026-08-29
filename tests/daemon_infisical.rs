//! What a daemon-hosted Infisical lookup is allowed to reach.
//!
//! # The hazard this file exists to hold shut
//!
//! The Infisical adapter turns a name into a key lookup at a folder of an
//! environment. Given an environment, an **invented** name — one declared in no
//! config at all — becomes a real query against a real vault: measured against a
//! stand-in vendor, `A_NAME_NOBODY_EVER_DECLARED` spawned it as
//! `run --env=<slug> --path=/ … -- printenv A_NAME_NOBODY_EVER_DECLARED`. On a
//! session an environment can come from the caller's own
//! `keyless run --env <slug>`, and that is the hole.
//!
//! A daemon has no such input. [`keyless::ipc::protocol::Request`] carries
//! `v`, `op`, `name`, `cwd` and `argv` and nothing else, and
//! `DaemonConfig::infisical_routing` supplies no environment of its own — so an
//! undeclared name has no environment, and a lookup with no environment is a
//! lookup that never happens.
//!
//! # Why the assertion is the ABSENCE of a spawn
//!
//! A case that only read the returned status would pass just as happily against
//! a daemon that queried the vendor, got nothing back, and reported an absence.
//! That is a network call and a vendor-side audit entry for a name nobody
//! declared, which is most of the harm. So every case here reads the file the
//! stand-in vendor writes when it runs, and the property is that the file is not
//! there at all.

// The daemon is macOS-only (`src/lib.rs`), so this whole file is. On any other
// platform it compiles to nothing and reports 0 tests — absent rather than
// ignored, which leaves the suite's exact ignored count alone.
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::path::Path;

use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Invocation, Resolution};

use support::{
    Backend, INFISICAL_DECOY, client_config, policy_allowing_self, scratch, short_socket_path,
    start_daemon, stub_infisical,
};

/// The one name the daemon's config declares, with an environment.
const DECLARED: &str = "FIXTURE_DECLARED";

/// A name that appears in no config anywhere. The historical hazard, by name.
const INVENTED: &str = "A_NAME_NOBODY_EVER_DECLARED";

/// A name the daemon's config declares but gives no environment.
const NO_ENV: &str = "FIXTURE_WITHOUT_AN_ENVIRONMENT";

/// The environment the one declared name states. Not a real slug anywhere.
const SLUG: &str = "fixture-env";

/// Where the stand-in vendor records the argv it was spawned with.
///
/// Its EXISTENCE is the whole signal: `stub_infisical` writes it as its first
/// act, so a missing file means no vendor process was ever created.
fn vendor_argv(dir: &Path) -> std::path::PathBuf {
    dir.join("infisical.argv")
}

/// A daemon config carrying the Infisical store and nothing else.
///
/// From JSON rather than a struct literal, deliberately: a key the daemon does
/// not read is dropped in silence, and a struct literal cannot show that the
/// coordinates below travelled through a file. `timeout_ms` is spelled out for
/// the reason `tests/suite_hygiene.rs` enforces — a fixture killed by its own
/// deadline fails in a shape that reads as a missing fixture.
///
/// One store, so nothing is ambiguous. With the file store also enabled, an
/// unpinned name would be reported ambiguous with **nothing asked**, and every
/// case below would pass without proving anything about the environment.
fn daemon_config_with_infisical(dir: &Path, vendor: &Path) -> DaemonConfig {
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"infisical":{{"enabled":true,"binary":"{vendor}",
                                      "timeout_ms":60000}}}},
             "secrets":{{"{DECLARED}":{{"store":"infisical","env":"{SLUG}"}},
                         "{NO_ENV}":{{"store":"infisical"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

#[test]
fn a_name_the_daemons_config_never_declared_reaches_no_vendor_process() {
    let dir = scratch("daemon-infisical-undeclared");
    let vendor = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let config = daemon_config_with_infisical(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    // The control FIRST, and it is not decoration: without it every assertion
    // below is satisfied by a daemon whose Infisical store cannot look anything
    // up at all — which is not the property being claimed. Same daemon, same
    // socket, same stand-in; the only difference is that this name was declared
    // with an environment.
    match registry.resolve(DECLARED) {
        Resolution::Found { secret, store } => {
            assert_eq!(store, "daemon");
            assert_eq!(secret.expose(), INFISICAL_DECOY);
        }
        other => panic!(
            "a declared name must resolve through the daemon, or nothing below \
             proves a lookup was withheld: {}",
            other.reason()
        ),
    }
    let spawned = support::recorded_lines(&vendor_argv(&dir));
    assert!(
        spawned.iter().any(|arg| arg == &format!("--env={SLUG}")),
        "the control did not reach the vendor at the declared coordinate: {spawned:?}"
    );

    // Delete the record before the case that must not write one. A stale file
    // from the control above would make a run that never happened report a
    // spawn, and this assertion would then be the only thing standing between
    // an invented name and a real vault.
    std::fs::remove_file(vendor_argv(&dir)).expect("the control wrote an argv record");

    let reason = registry.resolve(INVENTED).reason();
    assert!(
        !vendor_argv(&dir).exists(),
        "a name nobody declared reached the vendor: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(reason.contains("was not asked"), "{reason}");
    assert!(reason.contains(INVENTED), "{reason}");
    assert!(
        !reason.contains(INFISICAL_DECOY),
        "the refusal carried a value: {reason}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_declared_name_with_no_environment_reaches_no_vendor_process_either() {
    // The other half. An operator who writes a name into `keylessd.json` and
    // forgets its `env` must get a refusal, not a lookup at whatever
    // environment the daemon might have defaulted to — there is none to
    // default, and this is what says so out loud.
    let dir = scratch("daemon-infisical-no-env");
    let vendor = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let config = daemon_config_with_infisical(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    // Nothing has run yet in this scratch directory, so an argv record here
    // could only have been written by the lookup below.
    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );

    let reason = registry.resolve(NO_ENV).reason();
    assert!(
        !vendor_argv(&dir).exists(),
        "a name with no environment reached the vendor: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(reason.contains("was not asked"), "{reason}");
    assert!(reason.contains(NO_ENV), "{reason}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_client_cannot_name_an_environment_because_the_wire_has_no_field_for_one() {
    // `keyless run --env <slug>` is the session-side input that makes an
    // invented name resolvable. This asserts it cannot cross the socket: the
    // same invocation that would supply one locally supplies nothing here, and
    // the invented name is still refused with no spawn.
    //
    // Asserted through the real client rather than by reading the protocol
    // struct, because "the type has no field" is a statement about the source
    // and this is a statement about what a caller can achieve.
    let dir = scratch("daemon-infisical-env-flag");
    let vendor = stub_infisical(&dir, &Backend::Injects(INFISICAL_DECOY));
    let config = daemon_config_with_infisical(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let invocation = Invocation::default().with_infisical_env(Some(SLUG.to_owned()));
    let registry = store::build(&client, &invocation).registry;

    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    let reason = registry.resolve(INVENTED).reason();
    assert!(
        !vendor_argv(&dir).exists(),
        "`--env` crossed the socket and made an invented name resolvable: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(reason.contains("was not asked"), "{reason}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
