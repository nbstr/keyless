//! What a daemon-hosted Proton Pass lookup is allowed to reach.
//!
//! # The property this file pins
//!
//! A Proton name is a vault, an item and a field, and **none of the three is
//! inferable**. Guessing any of them would send a read — and a permanent
//! off-machine audit entry — to an item nobody asked for. So a name that
//! appears in no config has no address at all, and `ProtonStore::resolve`
//! turns that into an error before a temporary file is written or a child is
//! created.
//!
//! That is a stronger starting position than the Infisical adapter had. An
//! Infisical name is a key at a folder of an environment, and two of those
//! three have defaults, so an undeclared name is still a well-formed query
//! somebody's real vault will answer. The daemon had to be built to close
//! that. Here it is closed by construction — which is exactly why it needs a
//! test: a property nothing had to be written to obtain is a property nothing
//! stops a later change from removing.
//!
//! # Why the assertion is the ABSENCE of a spawn
//!
//! A case reading only the returned status would pass just as happily against
//! a daemon that listed a real vault, found no such item, and reported an
//! absence. That is a network call and a vendor-side audit entry for a name
//! nobody declared, which is most of the harm. So the cases below read the
//! file the stand-in vendor writes when it runs, and the property is that the
//! file is not there at all.

// The daemon is macOS-only (`src/lib.rs`), so this whole file is. On any other
// platform it compiles to nothing and reports 0 tests — absent rather than
// ignored, which leaves the suite's exact ignored count alone.
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::path::Path;

use keyless::daemon::config::DaemonConfig;
use keyless::store::{self, Invocation, Resolution};

use support::{
    Backend, Listing, PROTON_DECOY, client_config, policy_allowing_self, scratch,
    short_socket_path, start_daemon, stub_pass_cli_listing, write_secrets,
};

/// The one name the daemon's config declares, with all three coordinates.
const DECLARED: &str = "FIXTURE_DECLARED";

/// A name that appears in no config anywhere. The hazard, by name.
const INVENTED: &str = "A_NAME_NOBODY_EVER_DECLARED";

/// A name the daemon's config declares and gives only part of an address.
const HALF_WRITTEN: &str = "FIXTURE_WITHOUT_AN_ITEM";

/// The vault the one declared name lives in. Not a real vault anywhere.
const VAULT: &str = "company";

/// The item title the one declared name lives under.
const ITEM: &str = "decoy";

/// The session directory the daemon's config points at.
///
/// Never touched by a stub — the fixtures below record what they were handed
/// rather than reading anything out of it — but it must be an absolute path,
/// because a relative one degrades every lookup for a different reason and
/// every case here would pass without asking anything.
fn session_dir(dir: &Path) -> std::path::PathBuf {
    dir.join("session")
}

/// A listing holding exactly the one item the declared name addresses.
///
/// Written out by hand rather than built from the adapter's own idea of the
/// shape: a fixture generated from that would agree with it whatever it became.
const LISTING: &str = concat!(
    r#"{"items":[{"id":"It3mOne","share_id":"ShAr3","state":"Active","#,
    r#""title":"decoy","item_type":"login"}]}"#
);

/// Where the stand-in vendor records the argv it was spawned with.
///
/// Its EXISTENCE is the whole signal for the `run` path: `stub_pass_cli_listing`
/// writes it as its first act after the listing branch, so a missing file means
/// no `run` was ever created.
fn vendor_argv(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.argv")
}

/// Where the same stand-in records an `item list` invocation.
///
/// Separate from the one above because they are separate claims. `run` is the
/// verb that reads a value; `item list` is the verb that turns a vault and a
/// title into ids, and it is a real read against a real vault with a real
/// audit entry. An undeclared name must cost neither.
fn vendor_list_argv(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.list.argv")
}

/// The entry, in the daemon's own credential file, that holds the agent token.
const TOKEN_ENTRY: &str = "FIXTURE_AGENT_TOKEN";

/// The stand-in agent token. Distinct from every other decoy here, and long
/// enough that a grep for it in any output means a real leak.
const TOKEN_DECOY: &str = "decoy-Pat8-agent-token-never-real-0606";

/// Where a credential-carrying stand-in records the login it was handed.
fn vendor_token(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.token")
}

/// Where it records the key provider it was handed, or `<unset>`.
///
/// `${VAR-<unset>}` rather than `${VAR:-<unset>}`, so a variable that arrived
/// EMPTY is told apart from one that never arrived at all.
fn vendor_key_provider(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.key-provider")
}

/// A `pass-cli` stand-in that also records the key provider it was given.
///
/// `stub_pass_cli_listing` records the session directory and the reason, which
/// is everything the session-side cases need. The daemon needs one more: which
/// key provider reached the child. That is not cosmetic — see
/// `keyless::store::proton::KeyProvider` — so it is read from the place it is
/// supposed to arrive rather than from the adapter's own account of what it set.
fn stub_recording_key_provider(
    dir: &Path,
    behaviour: &Backend,
    listing: &Listing,
) -> std::path::PathBuf {
    let inner = stub_pass_cli_listing(dir, behaviour, listing);
    let wrapper = dir.join("pass-cli-wrapper");
    let body = format!(
        "#!/bin/sh\n\
         printf '%s' \"${{PROTON_PASS_KEY_PROVIDER-<unset>}}\" > '{provider}'\n\
         printf '%s' \"${{PROTON_PASS_PERSONAL_ACCESS_TOKEN-<unset>}}\" > '{token}'\n\
         exec '{inner}' \"$@\"\n",
        provider = vendor_key_provider(dir).display(),
        token = vendor_token(dir).display(),
        inner = inner.display(),
    );
    std::fs::write(&wrapper, body).expect("write the wrapper");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    wrapper
}

/// A daemon config carrying the Proton store and nothing else.
///
/// From JSON rather than a struct literal, deliberately: a key the daemon does
/// not read is dropped in silence, and a struct literal cannot show that the
/// coordinates below travelled through a file. `timeout_ms` is spelled out for
/// the reason `tests/suite_hygiene.rs` enforces — a fixture killed by its own
/// deadline fails in a shape that reads as a missing fixture.
///
/// One store, so nothing is ambiguous. With the file store also enabled, an
/// unpinned name would be reported ambiguous with **nothing asked**, and every
/// case below would pass without proving anything.
fn daemon_config_with_proton(dir: &Path, vendor: &Path) -> DaemonConfig {
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}},
                         "{HALF_WRITTEN}":{{"store":"proton","vault":"{VAULT}"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

// ---------------------------------------------------------------------------
// The control that matters: a declared name resolves, so the ones below are
// statements about the name and not about a fixture that never worked.
// ---------------------------------------------------------------------------

#[test]
fn a_declared_name_resolves_through_the_daemon_and_names_the_provider_it_ran_under() {
    let dir = scratch("daemon-proton-declared");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_proton(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    match registry.resolve(DECLARED) {
        Resolution::Found { secret, store } => {
            assert_eq!(secret.expose(), PROTON_DECOY);
            // `daemon`, not `proton`: this is the CLIENT's registry, which has
            // exactly one backend — the socket. Which store answered on the
            // far side is the daemon's own audit row's business, and a client
            // that could read it back would be reading the daemon's config.
            assert_eq!(store, "daemon");
        }
        other => panic!(
            "a declared name must resolve, or nothing else here is tested: {}",
            other.reason()
        ),
    }

    // The daemon reached the vault the config named, and it did so under the
    // session directory the config named — not an ambient one.
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        session_dir(&dir).display().to_string(),
        "the daemon read some other identity's session"
    );

    // And it named a key provider. Left unset under a uid with no keyring,
    // `pass-cli` finds no local key beside an existing session store and
    // reinitialises it — so an absent variable here is this adapter destroying
    // its own login on every lookup, silently.
    assert_eq!(
        support::recorded(&vendor_key_provider(&dir)),
        "fs",
        "the key provider did not reach the vendor"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// A name nobody declared: no process, of either verb.
// ---------------------------------------------------------------------------

#[test]
fn an_undeclared_name_creates_no_vendor_process_at_all() {
    let dir = scratch("daemon-proton-invented");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_proton(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    // The scratch directory starts clean, so the absence below is a fact about
    // this lookup rather than about a directory that never had the file.
    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    assert!(
        !vendor_list_argv(&dir).exists(),
        "the scratch directory is dirty"
    );

    let reason = registry.resolve(INVENTED).reason();

    assert!(
        !vendor_argv(&dir).exists(),
        "an undeclared name spawned `run`: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(
        !vendor_list_argv(&dir).exists(),
        "an undeclared name listed a real vault: {:?}",
        support::recorded_lines(&vendor_list_argv(&dir))
    );
    assert!(
        !vendor_key_provider(&dir).exists(),
        "a vendor process ran for an undeclared name"
    );
    assert!(
        !reason.contains(PROTON_DECOY),
        "the refusal carried a value: {reason}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_half_written_address_is_refused_before_anything_is_spawned() {
    // The other config that reaches the same absence of a spawn, and it is a
    // different mistake with a different fix: the entry EXISTS and states one
    // of the three coordinates. Reported as "declared nowhere" it would send
    // the reader to add an entry that is already there.
    let dir = scratch("daemon-proton-half-written");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_proton(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    assert!(
        !vendor_argv(&dir).exists(),
        "the scratch directory is dirty"
    );
    let reason = registry.resolve(HALF_WRITTEN).reason();

    assert!(
        !vendor_list_argv(&dir).exists(),
        "a half-written address listed a real vault: {:?}",
        support::recorded_lines(&vendor_list_argv(&dir))
    );
    assert!(
        !vendor_argv(&dir).exists(),
        "a half-written address spawned `run`: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    // Names the two parts that are missing, so the reader edits the entry in
    // front of them rather than hunting for one that was never written.
    assert!(reason.contains("item"), "{reason}");
    assert!(reason.contains("field"), "{reason}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The daemon's own login: where it comes from, and everywhere it must not go.
// ---------------------------------------------------------------------------

/// The same daemon, plus an agent token read out of its own `0600` file.
///
/// The credential file is a file of its OWN, which is the arrangement being
/// asserted: anything in the file the `file` store serves is a name an attested
/// client can ask for, so the token that unlocks the vault would be handed to
/// any session that guessed its label.
fn daemon_config_with_token(dir: &Path, vendor: &Path) -> DaemonConfig {
    let credentials = dir.join("proton-credentials.json");
    write_secrets(&credentials, &[(TOKEN_ENTRY, TOKEN_DECOY)]);
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000,
                                   "credentials_file":"{credentials}",
                                   "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"{TOKEN_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config")
}

#[test]
fn the_agent_token_reaches_the_vendor_and_no_other_surface() {
    // A daemon cannot inherit a Proton login the way a session does. So the
    // token is read from the daemon's own mode-0600 file at lookup time and
    // set on the vendor's child. This asserts both halves: that it arrives,
    // and that it appears in nothing else the daemon writes or says.
    let dir = scratch("daemon-proton-token");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_token(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let reason = match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => {
            assert_eq!(secret.expose(), PROTON_DECOY);
            "resolved".to_owned()
        }
        other => panic!(
            "the lookup must work, or nothing below is tested: {}",
            other.reason()
        ),
    };

    // It arrived, read from the child's environment by the vendor itself
    // rather than from the adapter's own account of what it set.
    assert_eq!(
        support::recorded(&vendor_token(&dir)),
        TOKEN_DECOY,
        "the agent token did not reach the vendor"
    );

    // And nowhere else. argv is the one this project exists to keep clean, and
    // the audit log is the one the caller cannot edit afterwards.
    let spawned = support::recorded_lines(&vendor_argv(&dir));
    assert!(
        !spawned.iter().any(|arg| arg.contains(TOKEN_DECOY)),
        "the token was put on the vendor's command line: {spawned:?}"
    );
    let listed = support::recorded_lines(&vendor_list_argv(&dir));
    assert!(
        !listed.iter().any(|arg| arg.contains(TOKEN_DECOY)),
        "the token was put on the listing's command line: {listed:?}"
    );
    let audit = std::fs::read_to_string(dir.join("audit.jsonl")).expect("the daemon wrote a row");
    assert!(
        !audit.contains(TOKEN_DECOY),
        "the token reached the audit log"
    );
    // The reason travels to Proton's own audit trail, permanently.
    assert!(
        !support::recorded(&dir.join("pass-cli.reason")).contains(TOKEN_DECOY),
        "the token reached the reason the vendor records"
    );
    assert!(!reason.contains(TOKEN_DECOY), "{reason}");

    // The point of a file of its own: the token is not a name the daemon
    // serves. Asked for by its own entry name over the socket, it is not there.
    match registry.resolve(TOKEN_ENTRY) {
        Resolution::Found { secret, .. } => assert_ne!(
            secret.expose(),
            TOKEN_DECOY,
            "the agent token was served to a client that asked for it by name"
        ),
        other => assert!(
            !other.reason().contains(TOKEN_DECOY),
            "the token leaked through a refusal: {}",
            other.reason()
        ),
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_credential_variable_this_adapter_sets_itself_is_refused() {
    // The narrow allowlist, and the reason it is narrower than the
    // `INFISICAL_*` prefix rule next door. `PROTON_PASS_SESSION_DIR` is a
    // `PROTON_PASS_*` variable, so a prefix rule would accept it here — and it
    // chooses which identity answers, which is the difference between reading
    // one vault and reading a whole account. A credential entry must not be
    // able to say it.
    let dir = scratch("daemon-proton-credential-refused");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let credentials = dir.join("proton-credentials.json");
    write_secrets(&credentials, &[(TOKEN_ENTRY, TOKEN_DECOY)]);
    let config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000,
                                   "credentials_file":"{credentials}",
                                   "credentials":{{"PROTON_PASS_SESSION_DIR":"{TOKEN_ENTRY}"}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(&dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(&dir).display(),
        vendor = vendor.display(),
        credentials = credentials.display(),
    ))
    .expect("valid daemon config");

    // Said at startup, so an operator finds out while reading the daemon's own
    // output rather than while reading a degraded run a week later.
    let said = config.warnings().join(" ");
    assert!(said.contains("PROTON_PASS_SESSION_DIR"), "{said}");

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
        "a refused credential still spawned the vendor: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(
        !vendor_list_argv(&dir).exists(),
        "a refused credential still listed a vault: {:?}",
        support::recorded_lines(&vendor_list_argv(&dir))
    );
    assert!(reason.contains("PROTON_PASS_SESSION_DIR"), "{reason}");
    assert!(!reason.contains(TOKEN_DECOY), "{reason}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_token_the_daemons_file_does_not_hold_degrades_without_a_spawn() {
    // The operator wrote down where the token lives and it is not there. That
    // is a misconfiguration, not an absence: every Proton name degrades, the
    // message names the entry to write, and no vendor process is created — so
    // an unauthenticated lookup is never attempted against a real vault.
    let dir = scratch("daemon-proton-token-missing");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_token(&dir, &vendor);
    // Same config, same file, with the one entry it names removed. Rewritten
    // rather than deleted, so the failure is a missing ENTRY and not a missing
    // file — the two have different messages and this is the one that is easy
    // to report as the other.
    write_secrets(
        &dir.join("proton-credentials.json"),
        &[("FIXTURE_SOMETHING_ELSE", TOKEN_DECOY)],
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
        !vendor_list_argv(&dir).exists(),
        "the vendor listed a vault with no login: {:?}",
        support::recorded_lines(&vendor_list_argv(&dir))
    );
    assert!(
        !vendor_argv(&dir).exists(),
        "the vendor was spawned with no login: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(reason.contains(TOKEN_ENTRY), "{reason}");
    assert!(
        !reason.contains(TOKEN_DECOY),
        "the refusal carried the value it could not attribute: {reason}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The wire has no field that could widen any of this.
// ---------------------------------------------------------------------------

#[test]
fn no_client_can_name_a_vault_the_daemons_config_did_not() {
    // The Infisical hazard's shape, asked of this adapter. There, a caller
    // could supply an environment with `keyless run --env` and turn an
    // invented name into a real query. Here there is no coordinate a caller
    // could supply at all — the request carries `v`, `op`, `name`, `cwd` and
    // `argv` — and a session's own per-name pins are dropped by `store::build`
    // the moment the daemon is enabled.
    //
    // Asserted through a CLIENT config that states a full, different address
    // for the same name: if any of it survived the crossing, the daemon would
    // read the vault this config names rather than its own.
    let dir = scratch("daemon-proton-client-cannot-steer");
    let vendor = stub_recording_key_provider(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let config = daemon_config_with_proton(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    let mut client = client_config(running.socket(), 3_000);
    client.secrets.insert(
        INVENTED.to_owned(),
        serde_json::from_str(
            r#"{"store":"proton","vault":"Personal","item":"decoy","field":"password"}"#,
        )
        .expect("a valid route"),
    );
    let registry = store::build(&client, &Invocation::default()).registry;

    let reason = registry.resolve(INVENTED).reason();
    assert!(
        !vendor_list_argv(&dir).exists(),
        "a client-supplied vault reached the vendor: {:?}",
        support::recorded_lines(&vendor_list_argv(&dir))
    );
    assert!(
        !vendor_argv(&dir).exists(),
        "a client-supplied address resolved: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(!reason.contains(PROTON_DECOY), "{reason}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
