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
    Backend, INFISICAL_DECOY, client_config, install_executable, policy_allowing_self, scratch,
    short_socket_path, start_daemon, stub_infisical, write_secrets,
};

/// The one name the daemon's config declares, with an environment.
const DECLARED: &str = "FIXTURE_DECLARED";

/// A name that appears in no config anywhere. The historical hazard, by name.
const INVENTED: &str = "A_NAME_NOBODY_EVER_DECLARED";

/// A name the daemon's config declares but gives no environment.
const NO_ENV: &str = "FIXTURE_WITHOUT_AN_ENVIRONMENT";

/// The environment the one declared name states. Not a real slug anywhere.
const SLUG: &str = "fixture-env";

/// The entry, in the daemon's own credential file, that holds the vendor login.
const IDENTITY_ENTRY: &str = "FIXTURE_MACHINE_IDENTITY";

/// The stand-in machine identity. Distinct from every other decoy here, so
/// "which value is this?" is a question every assertion below can ask, and long
/// enough that a grep for it in any output means a real leak.
const IDENTITY_DECOY: &str = "decoy-Mid5-machine-identity-never-real-0404";

/// Where a credential-carrying stand-in records the login it was handed.
fn vendor_token(dir: &Path) -> std::path::PathBuf {
    dir.join("vendor-token")
}

/// A stand-in vendor that records the login it was given, then injects.
///
/// `stub_infisical` records argv only, and argv is exactly where a credential
/// must never be. This one reads it from the place it is supposed to arrive —
/// the child environment — and writes it to a file, so the test can ask whether
/// it got there without the adapter being the one that says so.
///
/// `${VAR-ABSENT}` rather than `${VAR:-ABSENT}`, so a variable that arrived
/// EMPTY is told apart from one that never arrived at all.
fn stub_infisical_recording_login(dir: &Path) -> std::path::PathBuf {
    let body = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         printf '%s' \"${{INFISICAL_TOKEN-ABSENT}}\" > '{token}'\n\
         while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         shift\n\
         exec /usr/bin/env \"$2={INFISICAL_DECOY}\" \"$1\" \"$2\"\n",
        argv = vendor_argv(dir).display(),
        token = vendor_token(dir).display(),
    );
    install_executable(&dir.join("infisical-records-login"), &body)
}

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

/// The same daemon, plus a machine identity read out of its own `0600` file.
///
/// The credential file is a file of its OWN, which is the arrangement being
/// asserted: anything in the file the `file` store serves is a name an attested
/// client can ask for, so a login kept there would be handed to any session that
/// guessed its label.
fn daemon_config_with_credential(dir: &Path, vendor: &Path) -> DaemonConfig {
    let credentials = dir.join("infisical-credentials.json");
    write_secrets(&credentials, &[(IDENTITY_ENTRY, IDENTITY_DECOY)]);
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"infisical":{{"enabled":true,"binary":"{vendor}",
                                      "timeout_ms":60000,
                                      "credentials_file":"{credentials}",
                                      "credentials":{{"INFISICAL_TOKEN":"{IDENTITY_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"infisical","env":"{SLUG}"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config")
}

// ---------------------------------------------------------------------------
// The vendor's own login: where it comes from, and everywhere it must not go.
// ---------------------------------------------------------------------------

#[test]
fn the_machine_identity_reaches_the_vendor_and_no_other_surface() {
    // A daemon cannot inherit a login the way a session does — a login keychain
    // belongs to the uid that unlocked it. So the credential is read from the
    // daemon's own mode-0600 file at lookup time and set on the vendor's child.
    // This asserts both halves: that it arrives, and that it appears in nothing
    // else the daemon writes or says.
    let dir = scratch("daemon-infisical-identity");
    let vendor = stub_infisical_recording_login(&dir);
    let config = daemon_config_with_credential(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let reason = match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => {
            assert_eq!(secret.expose(), INFISICAL_DECOY);
            "resolved".to_owned()
        }
        other => panic!(
            "the lookup must work, or nothing below is tested: {}",
            other.reason()
        ),
    };

    // It arrived, read from the child's environment by the vendor itself rather
    // than from the adapter's own account of what it set.
    assert_eq!(
        support::recorded(&vendor_token(&dir)),
        IDENTITY_DECOY,
        "the machine identity did not reach the vendor"
    );

    // And nowhere else. argv is the one this project exists to keep clean, and
    // the audit log is the one the caller cannot edit afterwards.
    let spawned = support::recorded_lines(&vendor_argv(&dir));
    assert!(
        !spawned.iter().any(|arg| arg.contains(IDENTITY_DECOY)),
        "the credential was put on the vendor's command line: {spawned:?}"
    );
    let audit = std::fs::read_to_string(dir.join("audit.jsonl")).expect("the daemon wrote a row");
    assert!(
        !audit.contains(IDENTITY_DECOY),
        "the credential reached the audit log"
    );
    assert!(!reason.contains(IDENTITY_DECOY), "{reason}");

    // The point of a file of its own: the credential is not a name the daemon
    // serves. Asked for by its own entry name over the socket, it is not there.
    match registry.resolve(IDENTITY_ENTRY) {
        Resolution::Found { secret, .. } => {
            assert_ne!(
                secret.expose(),
                IDENTITY_DECOY,
                "the machine identity was served to a client that asked for it by name"
            );
        }
        other => assert!(
            !other.reason().contains(IDENTITY_DECOY),
            "the credential leaked through a refusal: {}",
            other.reason()
        ),
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_credential_the_daemons_file_does_not_hold_degrades_without_a_spawn() {
    // The operator wrote down where the login lives and it is not there. That
    // is a misconfiguration, not an absence: every Infisical name degrades, the
    // message names the entry to write, and no vendor process is created — so
    // an unauthenticated lookup is never attempted against a real vault.
    let dir = scratch("daemon-infisical-identity-missing");
    let vendor = stub_infisical_recording_login(&dir);
    let config = daemon_config_with_credential(&dir, &vendor);
    // Same config, same file, with the one entry it names removed. Rewritten
    // rather than deleted, so the failure is a missing ENTRY and not a missing
    // file — the two have different messages and this is the one that is easy
    // to report as the other.
    write_secrets(
        &dir.join("infisical-credentials.json"),
        &[("FIXTURE_SOMETHING_ELSE", IDENTITY_DECOY)],
    );
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    let reason = registry.resolve(DECLARED).reason();
    assert!(
        !vendor_argv(&dir).exists(),
        "the vendor was spawned with no login: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(reason.contains(IDENTITY_ENTRY), "{reason}");
    assert!(reason.contains("INFISICAL_TOKEN"), "{reason}");
    assert!(
        !reason.contains(IDENTITY_DECOY),
        "the refusal carried the value it could not attribute: {reason}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_credential_variable_that_is_not_the_vendors_own_is_refused() {
    // Without the `INFISICAL_*` bound this field is a general "set any variable
    // on a child process, as the daemon's uid" primitive: `PATH` would choose
    // which binary the vendor is and `HOME` would choose which login it finds.
    // Neither is a thing a credential mapping needs to say.
    let dir = scratch("daemon-infisical-identity-refused");
    let vendor = stub_infisical_recording_login(&dir);
    let credentials = dir.join("infisical-credentials.json");
    write_secrets(&credentials, &[(IDENTITY_ENTRY, IDENTITY_DECOY)]);
    let config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"infisical":{{"enabled":true,"binary":"{vendor}",
                                      "timeout_ms":60000,
                                      "credentials_file":"{credentials}",
                                      "credentials":{{"PATH":"{IDENTITY_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"infisical","env":"{SLUG}"}}}}}}"#,
        socket = short_socket_path(&dir).display(),
        audit = dir.join("audit.jsonl").display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config");

    // Said at startup, so an operator finds out while reading the daemon's own
    // output rather than while reading a degraded run a week later.
    let said = config.warnings().join(" ");
    assert!(said.contains("not `INFISICAL_*`"), "{said}");
    assert!(said.contains("PATH"), "{said}");

    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    let reason = registry.resolve(DECLARED).reason();
    assert!(
        !vendor_argv(&dir).exists(),
        "a refused credential variable still reached a spawn: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(reason.contains("PATH"), "{reason}");
    assert!(
        !reason.contains(IDENTITY_DECOY),
        "the refusal carried a value: {reason}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
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
    // The remedy has to name the file that can actually settle it. A reader who
    // applies a session's remedy changes nothing — `--env` cannot cross this
    // socket and `store::build` dropped their own `secrets` pins on purpose —
    // and is then holding a config that looks correct beside a run that still
    // degrades. Asserted over the socket rather than on the routing, because
    // this is a statement about what a degraded session actually reads.
    assert!(reason.contains("keylessd's own config file"), "{reason}");
    assert!(
        !reason.contains("--env"),
        "the degrade offered a flag this client cannot send: {reason}"
    );

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

// ---------------------------------------------------------------------------
// The login the vendor's `run` verb actually accepts.
//
// Measured against `infisical` 0.43.124: `run` authenticates with
// `INFISICAL_TOKEN` and with nothing else. Handed a universal-auth client id
// and client secret in its environment, with no terminal and no keyring, it
// ignores both and tries to open a browser login — so a daemon that stored a
// client secret and stopped there would have stored a credential no lookup can
// use. What works with neither a home directory nor a keyring is
// `infisical login --method=universal-auth --plain --silent`, which prints an
// access token and stores nothing; the adapter runs it per lookup and hands the
// token on.
//
// Every case below therefore asserts on TWO spawns, and the interesting half is
// what the second one did NOT receive.
// ---------------------------------------------------------------------------

/// The credential-file entries holding a machine identity.
const CLIENT_ID_ENTRY: &str = "FIXTURE_CLIENT_ID";
const CLIENT_SECRET_ENTRY: &str = "FIXTURE_CLIENT_SECRET";

/// The stand-in identity. Distinct decoys, so "which value is this?" is always
/// answerable, and long enough that a grep for one means a real leak.
const CLIENT_ID_DECOY: &str = "decoy-Cid6-universal-auth-client-id-0505";
const CLIENT_SECRET_DECOY: &str = "decoy-Cse7-universal-auth-client-secret-0606";

/// What the stand-in vendor's login hands back.
const MINTED_TOKEN: &str = "decoy-Tok8-minted-access-token-0707";

/// Where the stand-in vendor records the argv of its `login` invocation.
fn login_argv(dir: &Path) -> std::path::PathBuf {
    dir.join("infisical-login.argv")
}

/// Where it records the identity that reached the login child.
fn login_identity(dir: &Path) -> std::path::PathBuf {
    dir.join("login-client-secret")
}

/// Where it records the client secret that reached the `run` child.
///
/// The assertion this file cares about most: after minting, the long-lived
/// credential must reach the login and nothing else.
fn run_client_secret(dir: &Path) -> std::path::PathBuf {
    dir.join("run-client-secret")
}

/// A stand-in vendor with two verbs, each recording what it was handed.
///
/// `${VAR-ABSENT}` rather than `${VAR:-ABSENT}`, so a variable that arrived
/// EMPTY is told apart from one that never arrived at all.
fn stub_infisical_with_login(dir: &Path, login: &str, run: &str) -> std::path::PathBuf {
    let body = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = login ]; then\n\
         \x20 printf '%s\\n' \"$@\" > '{login_argv}'\n\
         \x20 printf '%s' \"${{INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET-ABSENT}}\" > '{identity}'\n\
         {login}\n\
         fi\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         printf '%s' \"${{INFISICAL_TOKEN-ABSENT}}\" > '{token}'\n\
         printf '%s' \"${{INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET-ABSENT}}\" > '{secret}'\n\
         while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         shift\n\
         {run}\n",
        login_argv = login_argv(dir).display(),
        identity = login_identity(dir).display(),
        argv = vendor_argv(dir).display(),
        token = vendor_token(dir).display(),
        secret = run_client_secret(dir).display(),
    );
    install_executable(&dir.join("infisical-with-login"), &body)
}

/// The login half that mints a token, as the real one does.
const LOGIN_MINTS: &str = "  printf '%s\\n' 'decoy-Tok8-minted-access-token-0707'\n  exit 0";

/// The login half Infisical refuses.
const LOGIN_REFUSED: &str = "  echo 'error: CallUniversalAuthLogin unsuccessful response \
                             [status-code=401] [message=\"Unauthorized.\"]' >&2\n  exit 1";

/// The `run` half that injects, as `stub_infisical` does.
const RUN_INJECTS: &str =
    "exec /usr/bin/env \"$2=decoy-Inf7-company-vault-value-0101\" \"$1\" \"$2\"";

/// The `run` half Infisical refuses because the login it was given is dead.
const RUN_REFUSED: &str = "echo 'error: failed to fetch secrets for path \"/\": \
                           CallGetRawSecretsV3 Unsuccessful response [status-code=401] \
                           [message=\"Unauthorized. Access token expired.\"]' >&2\nexit 1";

/// The `run` half where the probe ran and the variable was unset. The control
/// that separates "Infisical said no" from "the name is not there".
const RUN_UNSET: &str = "\"$1\" \"$2\"\n\
                         status=$?\n\
                         if [ $status -ne 0 ]; then\n\
                         \x20 echo \"failed to wait for command termination: exit status \
                         $status\" >&2\n\
                         fi\n\
                         exit $status";

/// A daemon carrying a universal-auth machine identity in its own `0600` file.
fn daemon_config_with_identity(dir: &Path, vendor: &Path) -> DaemonConfig {
    let credentials = dir.join("infisical-credentials.json");
    write_secrets(
        &credentials,
        &[
            (CLIENT_ID_ENTRY, CLIENT_ID_DECOY),
            (CLIENT_SECRET_ENTRY, CLIENT_SECRET_DECOY),
        ],
    );
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"infisical":{{"enabled":true,"binary":"{vendor}",
                                      "timeout_ms":60000,
                                      "credentials_file":"{credentials}",
                                      "credentials":{{
                          "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":"{CLIENT_ID_ENTRY}",
                          "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET":"{CLIENT_SECRET_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"infisical","env":"{SLUG}"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config")
}

#[test]
fn a_machine_identity_is_exchanged_for_a_token_and_only_the_token_reaches_the_lookup() {
    let dir = scratch("daemon-infisical-mint");
    let vendor = stub_infisical_with_login(&dir, LOGIN_MINTS, RUN_INJECTS);
    let config = daemon_config_with_identity(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 5_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), INFISICAL_DECOY),
        other => panic!(
            "the lookup must work, or nothing below is tested: {}",
            other.reason()
        ),
    }

    // The login happened, with the identity in its ENVIRONMENT.
    let login = support::recorded_lines(&login_argv(&dir));
    assert!(
        login.iter().any(|arg| arg == "--method=universal-auth"),
        "the adapter did not run the vendor's universal-auth login: {login:?}"
    );
    assert!(
        login.iter().any(|arg| arg == "--plain"),
        "without --plain the vendor's stdout is not a bare token: {login:?}"
    );
    assert_eq!(
        support::recorded(&login_identity(&dir)),
        CLIENT_SECRET_DECOY,
        "the client secret did not reach the login"
    );
    assert!(
        !login.iter().any(|arg| arg.contains(CLIENT_SECRET_DECOY)),
        "the client secret was put on the vendor's command line: {login:?}"
    );

    // And the lookup got the MINTED token — not the identity.
    assert_eq!(
        support::recorded(&vendor_token(&dir)),
        MINTED_TOKEN,
        "the minted access token did not reach the lookup"
    );
    assert_eq!(
        support::recorded(&run_client_secret(&dir)),
        "ABSENT",
        "the long-lived client secret reached the lookup child as well as the login"
    );

    let spawned = support::recorded_lines(&vendor_argv(&dir));
    assert!(
        !spawned.iter().any(|arg| arg.contains(CLIENT_SECRET_DECOY)),
        "the client secret reached the lookup's command line: {spawned:?}"
    );
    let audit = std::fs::read_to_string(dir.join("audit.jsonl")).expect("the daemon wrote a row");
    assert!(
        !audit.contains(CLIENT_SECRET_DECOY),
        "the identity was audited"
    );
    assert!(
        !audit.contains(MINTED_TOKEN),
        "the minted token was audited"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_login_says_so_and_never_reads_as_a_missing_name() {
    // The confusion this whole file exists to prevent, in its sharpest form: a
    // credential that no longer works must not look like a secret that was
    // never there. One spawns nothing further and names the credential; the
    // other is an answer about the vault.
    let dir = scratch("daemon-infisical-login-refused");
    let vendor = stub_infisical_with_login(&dir, LOGIN_REFUSED, RUN_INJECTS);
    let config = daemon_config_with_identity(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 5_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    let outcome = registry.resolve(DECLARED);
    let reason = outcome.reason();

    // The login was tried and the LOOKUP was not: a daemon that could not
    // authenticate has made no statement about what is in the vault.
    assert!(
        login_argv(&dir).exists(),
        "the login was never attempted: {reason}"
    );
    assert!(
        !vendor_argv(&dir).exists(),
        "an unauthenticated lookup was attempted anyway: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );

    assert!(reason.contains("did not authenticate"), "{reason}");
    assert!(reason.contains("not a missing secret"), "{reason}");
    assert!(reason.contains("credential"), "{reason}");
    assert!(
        !reason.contains(CLIENT_SECRET_DECOY),
        "the refusal carried the credential it could not use: {reason}"
    );

    // The negative control, in the same test: the same daemon, the same stand-in
    // vendor, a login that works and a probe that reports the variable unset.
    // THAT is what an absence reads like, and the two sentences must not be the
    // same sentence.
    let ok_dir = scratch("daemon-infisical-login-refused-control");
    let ok_vendor = stub_infisical_with_login(&ok_dir, LOGIN_MINTS, RUN_UNSET);
    let ok_config = daemon_config_with_identity(&ok_dir, &ok_vendor);
    let ok_running = start_daemon(&ok_config, policy_allowing_self());
    let ok_client = client_config(ok_running.socket(), 5_000);
    let ok_registry = store::build(&ok_client, &Invocation::default()).registry;
    // Both sides asserted against LITERALS rather than against each other: an
    // `assert_ne!` between two strings the same code renders holds whatever
    // that code says, including when it says the same thing twice.
    let absent = ok_registry.resolve(DECLARED).reason();
    assert_eq!(absent, "not found in any store", "{absent}");
    assert!(
        !absent.contains("did not authenticate"),
        "an absence was reported as a login failure: {absent}"
    );

    drop(ok_running);
    let _ = std::fs::remove_dir_all(&ok_dir);
    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_access_token_that_infisical_refuses_is_reported_as_an_expiry_with_its_remedy() {
    // The other arrangement: a bare `INFISICAL_TOKEN` in the credential file,
    // which is what a human's own login flow produces and what expires. The
    // vendor's own line says "Unauthorized" and stops; the daemon has to say
    // which credential that is and what replaces it.
    let dir = scratch("daemon-infisical-token-expired");
    let vendor = stub_infisical_with_login(&dir, LOGIN_MINTS, RUN_REFUSED);
    let config = daemon_config_with_credential(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 5_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    let reason = registry.resolve(DECLARED).reason();

    // No login was minted: a token was configured, so there was nothing to
    // exchange. This is the path where an expiry is possible at all.
    assert!(
        !login_argv(&dir).exists(),
        "a configured access token was exchanged for another one"
    );
    assert!(reason.contains("expired or been revoked"), "{reason}");
    assert!(reason.contains("not a missing secret"), "{reason}");
    assert!(
        reason.contains("machine identity"),
        "the remedy that ends the expiry is not offered: {reason}"
    );
    assert!(
        !reason.contains(IDENTITY_DECOY),
        "the refusal carried the token it could not use: {reason}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn half_a_machine_identity_is_refused_at_startup_and_reaches_no_vendor_process() {
    // One half of the pair is not a weaker identity, it is an unusable one:
    // `infisical run` authenticates with neither half on its own, so a config
    // that names only the client id would spawn a vendor that opens a browser
    // login it cannot complete and reports something about a login flow.
    let dir = scratch("daemon-infisical-half-identity");
    let vendor = stub_infisical_with_login(&dir, LOGIN_MINTS, RUN_INJECTS);
    let credentials = dir.join("infisical-credentials.json");
    write_secrets(&credentials, &[(CLIENT_ID_ENTRY, CLIENT_ID_DECOY)]);
    let config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"infisical":{{"enabled":true,"binary":"{vendor}",
                                      "timeout_ms":60000,
                                      "credentials_file":"{credentials}",
                                      "credentials":{{
                          "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":"{CLIENT_ID_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"infisical","env":"{SLUG}"}}}}}}"#,
        socket = short_socket_path(&dir).display(),
        audit = dir.join("audit.jsonl").display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config");

    let said = config.warnings().join(" ");
    assert!(said.contains("half declared"), "{said}");
    assert!(
        said.contains("INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET"),
        "the warning does not name the half that is missing: {said}"
    );

    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 5_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    let reason = registry.resolve(DECLARED).reason();
    assert!(
        !login_argv(&dir).exists() && !vendor_argv(&dir).exists(),
        "half an identity still reached a vendor process: {reason}"
    );
    assert!(reason.contains("half declared"), "{reason}");
    assert!(
        !reason.contains(CLIENT_ID_DECOY),
        "the refusal carried a value: {reason}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
