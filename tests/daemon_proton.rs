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
use std::time::{Duration, Instant, SystemTime};

use keyless::daemon::config::DaemonConfig;
use keyless::daemon::login;
use keyless::ipc::client::{Client, ClientError};
use keyless::ipc::protocol::{Reply, Request};
use keyless::store::proton_session::Generations;
use keyless::store::{self, Invocation, Resolution};

use support::{
    Backend, Listing, NextCall, PROTON_DECOY, client_config, current_generation, generation_dirs,
    install_executable, policy_allowing_self, publish_generation, publish_generation_aged, scratch,
    set_next_call, short_socket_path, start_daemon, stub_pass_cli_listing, vendor_call_count,
    vendor_decoy, write_secrets,
};

/// A name the FILE store answers, so the assertion is about another store.
const NEIGHBOUR: &str = "A_NAME_THE_FILE_STORE_HOLDS";
const NEIGHBOUR_VALUE: &str = "file-store-decoy-not-a-credential";

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

/// The generation directory `daemon_config_with_proton` (or any fixture that
/// calls [`support::publish_generation`] against this root) actually
/// published, read back off `<root>/current` rather than re-derived.
///
/// A vendor child is scoped at THIS directory, never at `session_dir(dir)`
/// itself — that path is the root of generations under this change, and a
/// test asserting a spawn's scope has to compare against the generation a
/// real reader would resolve to, which is exactly what `current` names.
fn published_generation(dir: &Path) -> std::path::PathBuf {
    let root = session_dir(dir);
    let name = support::current_generation(&root)
        .expect("the fixture must have published a generation before starting the daemon");
    root.join(name)
}

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

/// The stand-in local encryption key, for `key_provider: env` fixtures.
/// Distinct from [`TOKEN_DECOY`] and long enough that a grep for it in any
/// output means a real leak. Its LENGTH, never its text, is what any
/// assertion here may compare against.
const ENCRYPTION_KEY_DECOY: &str = "decoy-Lk4l-local-encryption-key-never-real-0911";

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

/// Where it records the uid and gid it actually ran as, as `uid:gid`.
fn vendor_identity(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.identity")
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
         printf '%s:%s' \"$(id -u)\" \"$(id -g)\" > '{identity}'\n\
         exec '{inner}' \"$@\"\n",
        provider = vendor_key_provider(dir).display(),
        token = vendor_token(dir).display(),
        identity = vendor_identity(dir).display(),
        inner = inner.display(),
    );
    std::fs::write(&wrapper, body).expect("write the wrapper");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    wrapper
}

/// A daemon config carrying the Proton store and nothing else, with a
/// generation already published into its session root.
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
///
/// # Why every case here needs a published generation
///
/// Under generations, `<session_dir>` is the ROOT — a read resolves against
/// whatever `<root>/current` names, and a fresh root names nothing. None of
/// the cases in this file are about the renewal loop establishing that first
/// generation (`daemon_proton_generations.rs` is), so each one publishes its
/// own before the daemon that will read it ever starts, the same way an
/// operator's first `keylessd login` would have to before any of this file's
/// cases could observe a resolve at all.
fn daemon_config_with_proton(dir: &Path, vendor: &Path) -> DaemonConfig {
    support::publish_generation(&session_dir(dir));
    // A credential file with both entries written, because this fixture takes
    // the crate's own `key_provider` default: under `env` a config declaring
    // no key is one a real `pass-cli` refuses at provider construction, so a
    // control running that way would be modelling an arrangement that cannot
    // work anywhere but against a stand-in.
    let credentials = dir.join("proton.json");
    write_secrets(
        &credentials,
        &[
            ("AGENT_TOKEN", TOKEN_DECOY),
            ("LOCAL_KEY", ENCRYPTION_KEY_DECOY),
        ],
    );
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "credentials_file":"{credentials}",
                                   "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN",
                                                   "PROTON_PASS_ENCRYPTION_KEY":"LOCAL_KEY"}},
                                   "timeout_ms":60000}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}},
                         "{HALF_WRITTEN}":{{"store":"proton","vault":"{VAULT}"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(dir).display(),
        credentials = credentials.display(),
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
    // GENERATION directory the config's own `current` pointer names — never
    // the root, and never an ambient identity.
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        published_generation(&dir).display().to_string(),
        "the daemon read some other identity's session"
    );

    // And it named a key provider — the literal `"env"`, not
    // `KeyProvider::default().as_str()`: the fixture declares none of its own
    // on purpose, so this pins the crate's ACTUAL default rather than
    // comparing that default against itself, which would hold whatever the
    // default became. Left unset under a uid with no keyring, `pass-cli`
    // finds no local key beside an existing session store and reinitialises
    // it — so an absent variable here is this adapter destroying its own
    // login on every lookup, silently. A future default change is meant to
    // edit this literal, not to be absorbed by it — see `KeyProvider`'s own
    // doc for why `env` is that default now.
    assert_eq!(
        support::recorded(&vendor_key_provider(&dir)),
        "env",
        "the key provider did not reach the vendor"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// One daemon, several stores: a Proton login that keeps failing is Proton's
// problem and nobody else's.
// ---------------------------------------------------------------------------

/// A config with BOTH stores, and a renewal loop that cannot possibly succeed.
///
/// The vendor refuses every login, so `session::attempt` fails on its first
/// tick and on every tick after it. `min_backoff_seconds` is 1 and
/// `probe_interval_seconds` is 1 so the loop is actually spinning through
/// failures while the assertion below runs, rather than asleep on a default
/// five-minute timer and passing for the wrong reason.
fn daemon_config_with_a_failing_renewal(dir: &Path, vendor: &Path) -> DaemonConfig {
    // The audit log is what the daemon's uid is read off — `session::spawn`
    // refuses without it, which is the same refusal the login verb makes.
    std::fs::write(dir.join("audit.jsonl"), b"").expect("audit");
    let secrets = dir.join("secrets.json");
    write_secrets(&secrets, &[(NEIGHBOUR, NEIGHBOUR_VALUE)]);
    let credentials = dir.join("proton.json");
    write_secrets(&credentials, &[("AGENT_TOKEN", TOKEN_DECOY)]);
    // `key_provider: fs` pinned rather than inherited: these cases are about
    // the TOKEN, and under `env` the daemon also names an entry for its own
    // local key, so an unwritten credential file would report the key missing
    // where the case is asking what happens to the token.

    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{
               "file":{{"enabled":true,"path":"{secrets}"}},
               "proton":{{"enabled":true,"binary":"{vendor}",
                          "session_dir":"{session}",
                          "timeout_ms":60000,
                          "key_provider":"fs",
                          "credentials_file":"{credentials}",
                          "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN"}},
                          "session":{{"auto_login":true,"login_after_minutes":1,
                                      "probe_interval_seconds":1,
                                      "min_backoff_seconds":1,"max_backoff_seconds":1}}}}}},
             "secrets":{{"{NEIGHBOUR}":{{"store":"file"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        secrets = secrets.display(),
        credentials = credentials.display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

/// A Proton session that will not come back does not take the file store with it.
///
/// This is the claim the renewal loop was landed on, and it is the reason it
/// carries no counterpart to Vault Agent's `auto_auth.exit_on_err`: Vault Agent
/// brokers ONE identity, so exiting takes away only what was already broken,
/// while this daemon serves several stores and exiting to fix Proton would take
/// the file store, the keychain and Infisical with it.
///
/// Stated in a doc comment, that claim is unfalsifiable. Here it can fail: the
/// vendor refuses every login, the loop is spinning through failures at a
/// one-second backoff, and a name belonging to another store still has to
/// resolve over the same socket.
#[test]
fn a_proton_login_that_keeps_failing_leaves_the_other_stores_answering() {
    let dir = scratch("daemon-proton-latches");
    // `Backend::OwnFailure` fails before the probe runs, which is what a
    // refused token, an absent binary and a dead network all look like from
    // here — the loop cannot tell them apart and must not exit for any of them.
    let vendor = stub_pass_cli_listing(&dir, &Backend::OwnFailure, &Listing::Json(LISTING));
    let config = daemon_config_with_a_failing_renewal(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    // Long enough for several ticks at a one-second interval, so the assertion
    // is made against a loop that has already failed repeatedly rather than one
    // that has not started.
    std::thread::sleep(std::time::Duration::from_secs(4));

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    match registry.resolve(NEIGHBOUR) {
        Resolution::Found { secret, store } => {
            assert_eq!(secret.expose(), NEIGHBOUR_VALUE);
            assert_eq!(store, "daemon");
        }
        other => panic!(
            "a failing Proton renewal took another store down with it: {}",
            other.reason()
        ),
    }

    // And the daemon is still there to be asked a second time — a loop that
    // exited would answer the first read from a socket nobody is listening on
    // only by accident of timing.
    assert!(
        matches!(registry.resolve(NEIGHBOUR), Resolution::Found { .. }),
        "the daemon stopped answering while its Proton loop was failing"
    );

    // The control, and without it this case passes for the wrong reason. A
    // loop that never STARTED — a config the spawn declined, a thread that
    // died at birth — leaves the file store answering too, and the assertions
    // above cannot tell that apart from a loop that is failing and latching.
    // So the vendor must have been spawned, and spawned for a login.
    let argv = support::recorded(&dir.join("pass-cli.argv"));
    assert!(
        argv.contains("login") || argv.contains("logout"),
        "the renewal loop never reached the vendor, so nothing was latching: {argv:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A daemon serving other stores runs no Proton machinery at all.
///
/// This is the property an operator on 1Password or Infisical is entitled to:
/// nothing of Proton's runs on their machine, and there is no background job
/// for them to find, understand, or unload. HashiCorp's Vault gives the same
/// guarantee for an optional secrets engine — `vault secrets disable` is one
/// act, after which the engine "stops functioning entirely" and the operator
/// hunts for nothing.
///
/// It rests on three lines in [`session::spawn`], which is exactly the kind of
/// guard that reads as obviously correct and is worth one test: a later change
/// that spawns the thread before consulting the config would leave every case
/// in this suite green.
///
/// Both directions are asserted. The negative alone would also pass against a
/// `renews_its_session` that is always false, which is a daemon that renews
/// nothing for anybody.
#[test]
fn the_renewal_loop_runs_only_where_proton_asked_for_it() {
    let dir = scratch("daemon-proton-off");
    let vendor = stub_pass_cli_listing(&dir, &Backend::OwnFailure, &Listing::Json(LISTING));

    // The control: with the store on and `auto_login` true, there IS a loop.
    let on = daemon_config_with_a_failing_renewal(&dir, &vendor);
    let running = start_daemon(&on, policy_allowing_self());
    assert!(
        running.renews_its_session(),
        "a daemon that asked for the renewal loop is not running one, so the \
         negative cases below prove nothing"
    );
    drop(running);

    // `auto_login` false — the default every config gets by saying nothing.
    let mut off = daemon_config_with_a_failing_renewal(&dir, &vendor);
    off.stores.proton.session.auto_login = false;
    let running = start_daemon(&off, policy_allowing_self());
    assert!(
        !running.renews_its_session(),
        "a daemon that did not ask for the loop started one anyway"
    );
    drop(running);

    // The store disabled outright: the 1Password or Infisical operator's case.
    // `auto_login` stays TRUE here on purpose — a config can carry a leftover
    // session block, and a disabled store must run nothing regardless.
    let mut disabled = daemon_config_with_a_failing_renewal(&dir, &vendor);
    disabled.stores.proton.enabled = false;
    assert!(
        disabled.stores.proton.session.auto_login,
        "this case is only meaningful while auto_login is still true"
    );
    let running = start_daemon(&disabled, policy_allowing_self());
    assert!(
        !running.renews_its_session(),
        "a disabled Proton store still started a renewal loop — an operator who \
         serves no Proton name has a thread spawning vendor processes"
    );
    drop(running);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A daemon whose vendor has stopped answering still shuts down.
///
/// `login::run` is `Command::output()`, deliberately unbounded — the reasoning
/// recorded there is that a deadline killing a login part way is how a session
/// store ends up half-written, which is the one damage this vendor cannot
/// repair. That reasoning is about the LOGIN VERB, where a person is waiting.
///
/// Inside the daemon it collides with shutdown: the renewal thread is stopped
/// by a flag it only reads between ticks, so a thread parked in
/// `Command::output()` against a vendor that never returns cannot see it. Join
/// that thread on the way out and SIGTERM never completes — the socket is not
/// removed, the port is not released, and launchd's own timeout is the only
/// thing that ends it.
///
/// So shutdown waits for the renewal loop and then stops waiting. The child is
/// left to finish rather than killed, which keeps the half-write reasoning
/// intact; what is given up is the join, not the process.
#[test]
fn a_vendor_that_stopped_answering_does_not_wedge_shutdown() {
    let dir = scratch("daemon-proton-shutdown");
    // `sleep 60` — a black-holed connection, and 60s is far past any patience a
    // shutdown can have.
    let vendor = stub_pass_cli_listing(&dir, &Backend::Hangs, &Listing::Json(LISTING));
    let config = daemon_config_with_a_failing_renewal(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());

    // Long enough for the loop's first tick to be inside the vendor call.
    std::thread::sleep(std::time::Duration::from_secs(2));

    let began = std::time::Instant::now();
    drop(running);
    let took = began.elapsed();

    assert!(
        took < std::time::Duration::from_secs(30),
        "shutdown blocked on a hung vendor for {took:?} — a daemon that cannot be \
         stopped is one launchd has to kill, and its socket outlives it"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Whoever runs the vendor owns what it writes, and it writes on reads.
// ---------------------------------------------------------------------------

/// The vendor runs as the uid the audit log names, not as whoever invoked us.
///
/// `pass-cli` WRITES to the session directory on invocations that only read:
/// against a directory holding no identity it creates `.session/pass-cli.db`
/// and `.session/local.key`, owned by whoever ran it. Inside the daemon that is
/// the daemon. Under `keylessd check`, which runs beneath `sudo` and resolves
/// every store to fill in its rows, it was ROOT — so the diagnostic left two
/// root-owned files in the daemon's own session directory, and every later
/// access answered `Error creating local key file: Permission denied`. That
/// reads like a broken token and is a directory the check broke.
///
/// Measured on a real install: a session cleared for repair, one
/// `sudo keylessd check`, and the renewal loop could not recover it.
///
/// This asserts the drop happens AND that dropping to the uid already in force
/// still succeeds — the case that runs inside the daemon itself, on every
/// lookup, where a wrong call here would break every read rather than one.
#[test]
fn the_vendor_runs_as_the_uid_the_audit_log_names() {
    let dir = scratch("daemon-proton-runs-as");
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
        matches!(registry.resolve(DECLARED), Resolution::Found { .. }),
        "the lookup failed, so nothing below is a statement about its uid"
    );

    // The audit log is what the login verbs read the daemon's identity off, so
    // it is what this has to agree with. Comparing against the test process
    // instead would pass on a daemon that never dropped at all.
    use std::os::unix::fs::MetadataExt;
    let audit = std::fs::metadata(dir.join("audit.jsonl")).expect("the audit log");
    assert_eq!(
        support::recorded(&vendor_identity(&dir)),
        format!("{}:{}", audit.uid(), audit.gid()),
        "the vendor ran as somebody other than the uid that owns the daemon's files"
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
    support::publish_generation(&session_dir(dir));
    let credentials = dir.join("proton-credentials.json");
    write_secrets(&credentials, &[(TOKEN_ENTRY, TOKEN_DECOY)]);
    // `key_provider: fs` pinned rather than inherited: these cases are about
    // the TOKEN, and under `env` the daemon also names an entry for its own
    // local key, so an unwritten credential file would report the key missing
    // where the case is asking what happens to the token.
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000,
                                   "key_provider":"fs",
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
    support::publish_generation(&session_dir(&dir));
    let credentials = dir.join("proton-credentials.json");
    write_secrets(&credentials, &[(TOKEN_ENTRY, TOKEN_DECOY)]);
    // `key_provider: fs` pinned rather than inherited: these cases are about
    // the TOKEN, and under `env` the daemon also names an entry for its own
    // local key, so an unwritten credential file would report the key missing
    // where the case is asking what happens to the token.
    let config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000,
                                   "key_provider":"fs",
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

// ---------------------------------------------------------------------------
// The warm cache: what a slow, silent or disowning vendor does to a value the
// daemon is already holding.
//
// # Why these are here rather than beside the resolver
//
// `src/daemon/resolver.rs` already drives every one of these transitions
// against a scripted `Store`, and that store returns whichever `StoreError`
// variant the case asked for. So the resolver's cases assume the classification
// they are testing the consequences of: they say what a `Backend` error does
// and what an `Unavailable` error does, and nothing there fails if the Proton
// adapter starts producing the other one.
//
// That classification is `reached_no_service` plus `vendor_failed` in
// `src/store/proton.rs`, and its input is a SENTENCE a vendor process printed
// on stderr. The cases below are the only ones that hand it a real sentence
// from a real child of a real daemon and read the result at the client's own
// seam — which is where the cost lands: a verdict read as transport keeps
// serving a credential the account has disowned.
//
// # Why nothing below is timed
//
// The stand-in hands out a different decoy on every call, so "which value came
// back" answers "was the store asked" outright. Where a delay is unavoidable it
// is several times the window it has to lose to, and it is a SLEEP — which can
// only ever overshoot, so a loaded machine pushes every one of these further
// into the case being true rather than out of it.
// ---------------------------------------------------------------------------

/// A second name at the same address as [`DECLARED`].
///
/// For the one case that needs two lookups running at once: single-flight
/// coalesces per name, so two reads of one name would be one vendor call and
/// the second read would prove nothing about a cold one.
const DECLARED_AGAIN: &str = "FIXTURE_DECLARED_TOO";

/// The freshness window for the cases that have to go PAST it.
///
/// One second, which is the smallest there is — `cache_ttl_seconds` is whole
/// seconds. Everything below sleeps [`PAST_FRESHNESS`] rather than 1 001 ms so
/// that a loaded machine lands further past the window rather than short of it.
const FRESHNESS_SECONDS: u64 = 1;

/// The freshness window for the case that has to stay INSIDE it.
///
/// A minute, and generous on purpose: the case asserts that a second read costs
/// no vendor call, so the window has to be wide enough that no amount of load
/// can push the second read out of it and turn a correct daemon red.
const GENEROUS_FRESHNESS_SECONDS: u64 = 60;

/// How long a value may still be served once it is past freshness.
///
/// A minute, so no case below reaches the far edge of it and none of them is
/// accidentally measuring the sweep.
const STALE_SECONDS: u64 = 60;

/// Comfortably past [`FRESHNESS_SECONDS`].
const PAST_FRESHNESS: Duration = Duration::from_millis(1_200);

/// How long a vendor takes when it has to lose a race against the resolver's
/// one-second refresh grace.
///
/// Five times that grace. The margin is not politeness: the reader's grace
/// expires on a timed wait, and a machine loaded enough to wake that thread
/// four seconds late would be the only way this stand-in answers in time. A
/// sleep cannot finish early, so nothing can shrink the gap from the other end.
const SLOWER_THAN_THE_GRACE: Duration = Duration::from_secs(5);

/// How long a vendor takes when it has to outlast the CLIENT's silence
/// deadline.
///
/// Three times [`SILENCE_MS`], for the same reason and in the same direction.
const SLOWER_THAN_THE_SILENCE: Duration = Duration::from_secs(3);

/// How long the client will hear nothing at all before it gives up.
///
/// The SUBJECT of the cold-read case rather than a ceiling on it, which is why
/// it is small where the rest of this suite is generous: the case is about a
/// lookup that outlives it.
const SILENCE_MS: u64 = 1_000;

/// The longest any poll below waits before reporting what never happened.
///
/// It bounds a FAILURE and nothing else — every case here converges in seconds
/// — so being generous costs a passing run nothing and buys a loaded machine
/// all the room it needs.
const NEVER_HAPPENED: Duration = Duration::from_secs(20);

/// What `pass-cli` printed while the network was gone.
///
/// Verbatim, measured 2026-09-09 in the daemon's own log and quoted in the
/// adapter's `UNREACHABLE` list. Quoted here rather than approximated: the
/// adapter matches on these words, so a fixture that paraphrased them would be
/// proving the match against a sentence no release has ever printed.
const TRANSPORT_FAILURE: &str =
    "failed to connect to host: error resolving destination: unknown error errno=None";

/// Enough of it to recognise in a degraded run's reason.
const TRANSPORT_FRAGMENT: &str = "failed to connect to host";

/// The vendor answering about the ITEM rather than about its own reach.
///
/// What makes this a verdict is that it is OUTSIDE the adapter's allowlist, not
/// its wording — the allowlist holds the measured transport phrases and every
/// other sentence is the account speaking about the name. The wording of the
/// allowlist itself is pinned by that adapter's own unit tests; all a fixture
/// here has to be is outside it.
const ITEM_VERDICT: &str = "no item titled decoy is readable in vault company";

/// The same daemon as [`daemon_config_with_proton`], with its cache turned on.
///
/// The fixture next door pins `cache_ttl_seconds` at zero because every case
/// above it is about a vendor process that must not be created, and a cache
/// would answer some of those reads without asking anything. These cases are
/// about the cache itself, so they say what they want.
///
/// Set on the parsed struct rather than in the JSON: both keys are read from
/// JSON by the daemon's own config tests, and what these cases need is the
/// window the daemon runs with, not a second proof that the key is spelled
/// right.
fn daemon_config_with_a_warm_cache(
    dir: &Path,
    vendor: &Path,
    freshness_seconds: u64,
    stale_seconds: u64,
) -> DaemonConfig {
    let mut config = daemon_config_with_proton(dir, vendor);
    config.cache_ttl_seconds = freshness_seconds;
    config.cache_stale_seconds = stale_seconds;
    config
}

/// The value a name resolved to, or a panic naming why there was none.
///
/// The reason is safe to print: every refusal this daemon produces is built
/// from a store's own error text, and the cases above this section are what
/// hold that down.
fn value_from(registry: &store::Registry, name: &str) -> String {
    match registry.resolve(name) {
        Resolution::Found { secret, store } => {
            assert_eq!(
                store, "daemon",
                "the value came from the session's own side"
            );
            secret.expose().to_owned()
        }
        other => panic!("`{name}` did not resolve: {}", other.reason()),
    }
}

/// Wait until the stand-in vendor has been asked for a value `times` over.
///
/// The tally is appended when a call STARTS, so this waits for a spawn rather
/// than for an answer — which is what a case wants before it changes what the
/// next call will do.
fn until_the_vendor_has_been_asked(dir: &Path, times: usize) {
    let deadline = Instant::now() + NEVER_HAPPENED;
    while Instant::now() < deadline {
        if vendor_call_count(dir) >= times {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "the vendor was asked {} time(s), never {times}",
        vendor_call_count(dir)
    );
}

/// Read `name` until the answer stops being `held`, and hand back the new one.
///
/// A poll rather than a sleep of the right length: what it is waiting for is a
/// vendor child finishing and a worker thread publishing what it fetched, and
/// the only sleep long enough for that on every machine is one far longer than
/// it takes on this one. A daemon that never refreshes fails this just as
/// surely, at [`NEVER_HAPPENED`].
fn until_the_value_stops_being(registry: &store::Registry, name: &str, held: &str) -> String {
    let deadline = Instant::now() + NEVER_HAPPENED;
    while Instant::now() < deadline {
        let answer = value_from(registry, name);
        if answer != held {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("`{name}` was still being answered from the value it started with");
}

/// Read `name` until it degrades, and hand back the reason it gave.
fn until_the_read_degrades(registry: &store::Registry, name: &str) -> String {
    let deadline = Instant::now() + NEVER_HAPPENED;
    while Instant::now() < deadline {
        match registry.resolve(name) {
            Resolution::Found { .. } => std::thread::sleep(Duration::from_millis(50)),
            other => return other.reason(),
        }
    }
    panic!("`{name}` never stopped resolving, so nothing was ever evicted");
}

#[test]
fn two_reads_inside_the_freshness_window_cost_one_vendor_probe() {
    // CONTROL — the change that makes this fail: `cache_ttl_seconds: 0`, which
    // is what the fixture next door uses. The second read then reaches the
    // vendor, comes back as the SECOND decoy, and both assertions below break.
    //
    // Nothing here is timed. The stand-in hands out a different value on every
    // call, so a second read answered by a vendor process is visible in the
    // string it returned and does not have to be inferred from how long it
    // took.
    let dir = scratch("daemon-proton-warm-twice");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    // No stale window: this case is about freshness, and a stale window would
    // give a second read a second route to an answer.
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, GENEROUS_FRESHNESS_SECONDS, 0);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    // What the stand-in answers with on its first call, by the FIXTURE's own
    // definition. Both reads are compared against this rather than against each
    // other: two answers from one daemon agree whatever that daemon does, which
    // is the shape `tests/oracle_independence.rs` refuses.
    let first_answer = vendor_decoy(1);

    assert_eq!(
        value_from(&registry, DECLARED),
        first_answer,
        "the cold read did not come from the vendor, so nothing below it is about a cache"
    );
    assert_eq!(
        value_from(&registry, DECLARED),
        first_answer,
        "the second read was answered by a vendor process"
    );
    assert_eq!(
        vendor_call_count(&dir),
        1,
        "a name read twice inside its freshness window cost more than one vendor process"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_vendor_slower_than_the_grace_leaves_the_held_value_in_front_of_the_caller() {
    // The property the whole mechanism exists for, asked of a real vendor
    // process: past freshness, against a store that takes longer than a caller
    // should wait, the caller gets the value the daemon already had.
    //
    // CONTROL — the change that makes this fail: a daemon that waits for the
    // refresh instead of serving what it holds. It would hand back the SECOND
    // decoy, five seconds later, and the assertion on `served` breaks. A daemon
    // that serves the held value and never refreshes fails the second half at
    // `NEVER_HAPPENED`.
    let dir = scratch("daemon-proton-warm-slow");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Slow(SLOWER_THAN_THE_GRACE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "the caller waited on the vendor instead of being handed the value the daemon held"
    );

    // The refresh was started, off this caller's request. Without this the case
    // above would also pass against a daemon that serves a stale value for ever
    // and asks nobody.
    until_the_vendor_has_been_asked(&dir, 2);

    // From here the stand-in answers at once, so the poll below converges as
    // fast as the machine allows. The call already sleeping read its
    // instruction when it started and still sleeps out its five seconds.
    set_next_call(&dir, &NextCall::Answers);
    let refreshed = until_the_value_stops_being(&registry, DECLARED, &held);

    // Which call's decoy this is, is deliberately not asserted: a poll that
    // lands in the wrong second starts a third call, and a third refresh is the
    // same daemon behaving the same way. What is pinned is that the held value
    // stopped being the answer, which no daemon without a refresh can produce.
    assert_ne!(refreshed, vendor_decoy(1));
    assert!(
        vendor_call_count(&dir) >= 2,
        "the value changed without a vendor process being asked for it"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_vendor_that_could_not_reach_the_service_leaves_the_value_being_served() {
    // The expensive half of the classification. A transport failure says
    // nothing about the item, so the value stands — and the discriminator is
    // that while the vendor is refusing every call, the first decoy can only
    // have come from the daemon's memory.
    //
    // CONTROL — three changes, each making this fail: dropping the phrase from
    // the adapter's `UNREACHABLE` list, so the sentence is read as the account
    // disowning the item; the adapter reporting a `Backend` error where it
    // reports `Unavailable`; and the resolver evicting on a store that could
    // not answer. Under any of them the reads below degrade instead of
    // answering, because the vendor cannot supply a value any more.
    let dir = scratch("daemon-proton-warm-unreachable");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(TRANSPORT_FAILURE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "a vendor that never reached its service took the value with it"
    );
    until_the_vendor_has_been_asked(&dir, 2);

    // And it is still there afterwards, which is the half a single read cannot
    // show: the refresh has now failed, and the entry it failed on is what
    // answers the next reader.
    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "the value survived the failing refresh and then did not survive the read after it"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_vendor_that_answers_about_the_item_evicts_the_value_and_the_next_read_degrades() {
    // The other half, and the one that costs a credential if it is wrong: the
    // account has spoken about this name, so what the daemon holds is worthless
    // and serving it would hand out a credential its owner has disowned.
    //
    // The vendor is turned SILENT after the verdict, and that is what makes the
    // eviction observable rather than assumed. A transport failure is the one
    // shape that keeps a value alive — the case above this one is exactly that
    // — so if the verdict had left the entry in place, every read below would
    // be answered from it for the whole stale window. Degrading is therefore
    // only possible if the entry is gone.
    //
    // CONTROL — the change that makes this fail: the resolver keeping a value
    // when a store answers about it, or the adapter reporting this sentence as
    // a transport failure. Either way the poll below never degrades and fails
    // at `NEVER_HAPPENED`.
    //
    // Wrapped in `stub_with_session_verbs` with `info_answers: true` since
    // the session-fault slice landed: this test's whole point is a HEALTHY
    // session that the account still refuses an item over, and the plain
    // `Backend::Controlled` stub answers every verb — `info` included —
    // out of the same `NextCall`, which would misread this exact case as a
    // dead session.
    let dir = scratch("daemon-proton-warm-verdict");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, true, LogoutAnswer::Ok, None);
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(ITEM_VERDICT));
    std::thread::sleep(PAST_FRESHNESS);
    let _ = registry.resolve(DECLARED);
    until_the_vendor_has_been_asked(&dir, 2);

    set_next_call(&dir, &NextCall::Fails(TRANSPORT_FAILURE));
    let reason = until_the_read_degrades(&registry, DECLARED);

    // Which failure the degraded read carried, and it is load-bearing. A read
    // that degraded on the VERDICT itself proves nothing about eviction: it
    // would be the vendor's answer travelling to the caller with the entry
    // still in place behind it. Only a read that reached the store and found it
    // unreachable — the shape that keeps a value — says the entry was gone.
    assert!(
        reason.contains(TRANSPORT_FRAGMENT),
        "the read degraded before the value's absence was what caused it: {reason}"
    );
    assert!(
        !reason.contains(&held),
        "the refusal carried the value it had just disowned"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_cold_read_slower_than_the_clients_own_deadline_still_reaches_the_caller() {
    // The Proton adapter's own version of the outage the heartbeat closed. It
    // is worth asking here as well as at `tests/daemon.rs`'s keychain stub,
    // because a cold Proton lookup is TWO vendor children — the vault listing,
    // then the read — so the latency a caller waits out is their sum, and that
    // sum is what was measured overrunning a session's deadline.
    //
    // Both halves go to one daemon over one store and differ in one field, the
    // way that case does. That pairing is the control: if the value arrives
    // either way the deadline was never the thing under test, and if it arrives
    // neither way the heartbeat is not what carries it.
    //
    // Two DIFFERENT names, because single-flight coalesces per name: one name
    // read twice would be one vendor call, and the second read would be handed
    // the first one's answer without ever having been slow.
    let dir = scratch("daemon-proton-cold-and-slow");
    let vendor = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    set_next_call(&dir, &NextCall::Slow(SLOWER_THAN_THE_SILENCE));
    // The fixture's own `cache_ttl_seconds: 0`, deliberately: with nothing
    // cached the second lookup pays the vendor's whole cost too, and cannot be
    // answered out of the first one's success.
    let mut config = daemon_config_with_proton(&dir, &vendor);
    config.secrets.insert(
        DECLARED_AGAIN.to_owned(),
        serde_json::from_str(&format!(
            r#"{{"store":"proton","vault":"{VAULT}","item":"{ITEM}","field":"password"}}"#
        ))
        .expect("a valid route"),
    );
    let running = start_daemon(&config, policy_allowing_self());

    // ONE client for both requests, so the deadline in force is provably this
    // one. Built through the two halves' shared object rather than through a
    // config on each: a loud read that outran a deadline nobody in the case can
    // see would pass just as well against a client that had quietly been given
    // a longer one.
    let silence = Duration::from_millis(SILENCE_MS);
    let client = Client::new(running.socket().to_path_buf(), silence);

    let mut asks_for_no_heartbeat = Request::resolve(DECLARED_AGAIN);
    asks_for_no_heartbeat.progress = false;
    match client.request(&asks_for_no_heartbeat) {
        Err(ClientError::Timeout(after)) => assert_eq!(after, silence),
        other => panic!("a daemon that says nothing must time out, got {other:?}"),
    }

    let began = Instant::now();
    let answered = client.request(&Request::resolve(DECLARED));
    let took = began.elapsed();

    match answered {
        // The SECOND decoy, so this read reached a vendor process of its own
        // rather than being handed whatever the mute lookup left behind. The
        // ordinal is settled: the mute lookup's child has been sleeping for a
        // second by the time this request is made.
        Ok(Reply::Value(secret)) => assert_eq!(
            secret.expose(),
            vendor_decoy(2),
            "the value did not come from this lookup's own vendor process"
        ),
        other => panic!("a daemon that says it is working must be waited for, got {other:?}"),
    }
    assert!(
        took > silence,
        "the value came back inside the silence deadline, so nothing outran it and this \
         proves nothing: {took:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Generations: the loop establishes each session in a fresh directory, swaps
// the pointer, and retires what it superseded — never touching the one it is
// serving from.
// ---------------------------------------------------------------------------

/// What the stand-in's plain `logout` (never `--force`) does.
///
/// `--force` is not a variant here: every case below answers it the vendor's
/// own way — it deletes local data and succeeds — because no case in this
/// file needs it to do anything else, and the retirement procedure's own
/// fallback shape is what `a_renewal_whose_old_store_cannot_be_decrypted…`
/// exercises through the PLAIN answer failing.
enum LogoutAnswer {
    /// The account had a session; it is ended.
    Ok,
    /// `pass-cli`'s own wording for a directory with nothing to end.
    AlreadyLoggedOut,
    /// Fails with `said` on stderr, exit 1 — the shape a corrupt local store
    /// produces: the vendor's own words, verbatim.
    Fails(&'static str),
}

impl LogoutAnswer {
    fn shell(&self) -> (i32, String) {
        match self {
            LogoutAnswer::Ok => (0, "echo 'Session logged out'".to_owned()),
            LogoutAnswer::AlreadyLoggedOut => (
                0,
                "echo 'There was not an active session, you are already logged out'".to_owned(),
            ),
            LogoutAnswer::Fails(said) => (1, format!("echo '{said}' >&2")),
        }
    }
}

/// What the stand-in's `run` verb — the read path — does before letting
/// `inner` actually answer it: hold the scoped directory open for `delay`,
/// then check whether `marker` (a file the fixture planted inside that
/// directory ahead of time) is still there, and append `intact` or `missing`
/// to `witness`.
///
/// Every other fixture in this file passes `None` to
/// [`stub_with_session_verbs`] and gets the pre-existing shape back exactly:
/// `run` answers at once, nothing is held open, nothing is recorded. This is
/// the minimal extension the in-flight-read case needed — a single new `run)`
/// arm in that stub's `case`, gated on this being `Some`.
struct ReadProbe {
    delay: Duration,
    marker: &'static str,
    witness: std::path::PathBuf,
}

/// A `pass-cli` stand-in that answers `login`, `info` and `logout` itself,
/// and execs `inner` for every other verb — `run`, `item list`, `vault list`,
/// `item view`, whatever `inner` already knows how to answer.
///
/// Every call, of any verb, appends one line to `<dir>/pass-cli.verbs`:
/// `<verb> <PROTON_PASS_SESSION_DIR> current=<contents of the root's
/// current>` — the root being `PROTON_PASS_SESSION_DIR`'s own parent, true
/// for every verb this file scopes at a GENERATION. That line is what proves,
/// after the fact, which directory a verb ran against and what `current` held
/// at that instant — never inferred from timing.
///
/// `read_probe`, when `Some`, additionally intercepts `run` — see
/// [`ReadProbe`] — before the same `exec '{inner}' "$@"` fallthrough every
/// other verb already uses answers it.
fn stub_with_session_verbs(
    dir: &Path,
    inner: &Path,
    login_delay: Duration,
    info_answers: bool,
    logout_answer: LogoutAnswer,
    read_probe: Option<ReadProbe>,
) -> std::path::PathBuf {
    let verbs_log = dir.join("pass-cli.verbs");
    let (info_body, info_exit) = if info_answers {
        ("echo 'ok'".to_owned(), 0)
    } else {
        (
            "echo 'Error: This operation requires an authenticated client' >&2".to_owned(),
            1,
        )
    };
    let (logout_exit, logout_body) = logout_answer.shell();
    let run_case = match &read_probe {
        Some(probe) => format!(
            "\x20 run)\n\
             \x20   sleep {delay}\n\
             \x20   if [ -e \"$scoped/{marker}\" ]; then\n\
             \x20     echo intact >> '{witness}'\n\
             \x20   else\n\
             \x20     echo missing >> '{witness}'\n\
             \x20   fi\n\
             \x20   ;;\n",
            delay = probe.delay.as_secs_f64(),
            marker = probe.marker,
            witness = probe.witness.display(),
        ),
        None => String::new(),
    };

    let body = format!(
        "#!/bin/sh\n\
         scoped=\"$PROTON_PASS_SESSION_DIR\"\n\
         root=\"$(dirname \"$scoped\")\"\n\
         now_current=\"$(cat \"$root/current\" 2>/dev/null | tr -d '\\n')\"\n\
         if [ -n \"${{PROTON_PASS_ENCRYPTION_KEY+x}}\" ]; then\n\
         \x20 key_len=${{#PROTON_PASS_ENCRYPTION_KEY}}\n\
         else\n\
         \x20 key_len=\"<unset>\"\n\
         fi\n\
         printf '%s %s current=%s key_provider=%s key_len=%s\\n' \"$1\" \"$scoped\" \
         \"$now_current\" \"${{PROTON_PASS_KEY_PROVIDER-<unset>}}\" \"$key_len\" >> '{verbs}'\n\
         case \"$1\" in\n\
         \x20 login)\n\
         \x20   sleep {login_delay}\n\
         \x20   echo 'Personal access token session created successfully'\n\
         \x20   exit 0 ;;\n\
         \x20 info)\n\
         \x20   {info_body}\n\
         \x20   exit {info_exit} ;;\n\
         \x20 logout)\n\
         \x20   case \"$2\" in\n\
         \x20     --force) echo 'Session logged out'; exit 0 ;;\n\
         \x20   esac\n\
         \x20   {logout_body}\n\
         \x20   exit {logout_exit} ;;\n\
         {run_case}\
         esac\n\
         exec '{inner}' \"$@\"\n",
        verbs = verbs_log.display(),
        login_delay = login_delay.as_secs_f64(),
        inner = inner.display(),
    );
    install_executable(&dir.join("pass-cli-session-verbs-stub"), &body)
}

/// A daemon config with the renewal loop switched on against a real
/// session-verbs stand-in, tuned for a short test run.
///
/// `timeout_ms` is BOTH the store's own read ceiling and the input the
/// retirement grace is derived from (`2 × timeout_ms + REAP_GRACE(2s) + 1s`)
/// — the same field serves both roles in production, so a test choosing it
/// small to keep grace fast for a RETIREMENT case is choosing the same small
/// number as the ceiling every vendor spawn in that test gets. Pass `3_000`
/// (grace 9s) only for a case that is actually waiting on the grace; every
/// other case should pass `60_000`, the suite's own generous ceiling, so a
/// loaded machine cannot turn it red for a reason that has nothing to do with
/// what it is testing.
fn daemon_config_with_generations_loop(
    dir: &Path,
    vendor: &Path,
    login_after_minutes: u64,
    probe_interval_seconds: u64,
    timeout_ms: u64,
) -> DaemonConfig {
    std::fs::write(dir.join("audit.jsonl"), b"").expect("audit");
    let credentials = dir.join("proton.json");
    write_secrets(&credentials, &[("AGENT_TOKEN", TOKEN_DECOY)]);
    // `key_provider` is pinned to `fs` explicitly, rather than left to the
    // type's own default, so the generation-timing cases below stay about
    // generation timing when that default moves — see
    // `daemon_config_with_generations_loop_env` for the cases that are
    // actually about the key provider.
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                        "session_dir":"{session}",
                        "timeout_ms":{timeout_ms},
                        "key_provider":"fs",
                        "credentials_file":"{credentials}",
                        "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN"}},
                        "session":{{"auto_login":true,"login_after_minutes":{login_after_minutes},
                                    "probe_interval_seconds":{probe_interval_seconds},
                                    "min_backoff_seconds":1,"max_backoff_seconds":5}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        credentials = credentials.display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

/// The same fixture as [`daemon_config_with_generations_loop`], scoped at
/// `key_provider: env` with [`ENCRYPTION_KEY_DECOY`] already written under
/// its declared entry — the state a real install reaches once
/// `credential::ensure_proton_local_key` has run once, which this fixture
/// stands in for rather than re-exercising: that generation step is proven
/// at the unit level in `daemon::credential`'s own tests.
fn daemon_config_with_generations_loop_env(
    dir: &Path,
    vendor: &Path,
    login_after_minutes: u64,
    probe_interval_seconds: u64,
    timeout_ms: u64,
) -> DaemonConfig {
    std::fs::write(dir.join("audit.jsonl"), b"").expect("audit");
    let credentials = dir.join("proton.json");
    write_secrets(
        &credentials,
        &[
            ("AGENT_TOKEN", TOKEN_DECOY),
            ("LOCAL_KEY", ENCRYPTION_KEY_DECOY),
        ],
    );
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                        "session_dir":"{session}",
                        "timeout_ms":{timeout_ms},
                        "key_provider":"env",
                        "credentials_file":"{credentials}",
                        "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN",
                                        "PROTON_PASS_ENCRYPTION_KEY":"LOCAL_KEY"}},
                        "session":{{"auto_login":true,"login_after_minutes":{login_after_minutes},
                                    "probe_interval_seconds":{probe_interval_seconds},
                                    "min_backoff_seconds":1,"max_backoff_seconds":5}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        credentials = credentials.display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

/// One recorded line of `pass-cli.verbs`, parsed.
///
/// `key_provider` and `key_len` read `<unset>` for a stub predating this
/// pair — every stand-in built through [`stub_with_session_verbs`] carries
/// both, so the only way to see the sentinel is a variable the vendor child
/// genuinely never received. `key_len` is a character COUNT, never the
/// value: see `stub_with_session_verbs`'s own script for why.
#[derive(Debug)]
struct VerbLine {
    verb: String,
    dir: String,
    current: String,
    key_provider: String,
    key_len: String,
}

fn parse_verbs(text: &str) -> Vec<VerbLine> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let verb = fields.next()?.to_owned();
            let dir = fields.next()?.to_owned();
            let current = fields
                .next()?
                .strip_prefix("current=")
                .unwrap_or_default()
                .to_owned();
            let key_provider = fields
                .next()
                .and_then(|field| field.strip_prefix("key_provider="))
                .unwrap_or("<unset>")
                .to_owned();
            let key_len = fields
                .next()
                .and_then(|field| field.strip_prefix("key_len="))
                .unwrap_or("<unset>")
                .to_owned();
            Some(VerbLine {
                verb,
                dir,
                current,
                key_provider,
                key_len,
            })
        })
        .collect()
}

fn basename(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

#[test]
fn the_renewal_loop_establishes_each_session_in_a_fresh_generation_and_makes_it_current() {
    // CONTROL — the change that makes this fail: scope `establish`'s login
    // at `coordinates.session_dir` (the root) instead of the fresh
    // generation directory it just created. `info` still runs at the
    // generation, so `followed_by_info` below breaks — the login and the
    // info that verifies it are no longer at the same directory.
    let dir = scratch("daemon-proton-gen-establishes");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    // `login_after_minutes: 0` makes every tick due, so the loop renews on
    // every one-second probe interval rather than waiting out an age nobody
    // has time to reach in a short test run. `60_000` — this case is not
    // about the grace, so it gets the suite's generous ceiling rather than
    // the small one a loaded machine could turn red for the wrong reason.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    // Polled rather than a fixed sleep: this only waits on a subprocess spawn
    // this MACHINE'S load decides the speed of, not on anything the retirement
    // grace governs.
    let deadline = Instant::now() + Duration::from_secs(30);
    let current = loop {
        if let Some(name) = current_generation(&root) {
            break name;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published"
        );
        std::thread::sleep(Duration::from_millis(200));
    };

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    let first_login = lines
        .iter()
        .position(|line| line.verb == "login")
        .expect("the loop never logged in");
    let login_dir = lines[first_login].dir.clone();
    let followed_by_info = lines[first_login + 1..]
        .iter()
        .take_while(|line| line.verb != "login")
        .any(|line| line.verb == "info" && line.dir == login_dir);
    assert!(
        followed_by_info,
        "the first login was not followed by an info at the same directory"
    );

    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { .. } => {}
        other => panic!("a declared name must resolve: {}", other.reason()),
    }
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        root.join(current).display().to_string(),
        "a read was scoped somewhere other than the published current generation"
    );

    // The scope invariant over every line, not the single sample above: a
    // real vault read (`run`, `item`, `vault`) is never scoped at the root —
    // re-read fresh so the resolve just performed is included.
    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let root_str = root.display().to_string();
    for line in parse_verbs(&verbs) {
        if matches!(line.verb.as_str(), "run" | "item" | "vault") {
            assert_ne!(
                line.dir, root_str,
                "a `{}` was scoped at the root instead of a generation",
                line.verb
            );
        }
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_fs_daemon_never_sets_the_local_key_variable_at_all() {
    // CONTROL for the case below: under `fs` no credential names
    // `PROTON_PASS_ENCRYPTION_KEY`, so `login::extra_credentials` resolves
    // nothing and the variable never reaches a child at all — not empty,
    // UNSET. Read before the `env` case so a fixture bug that made every
    // spawn's `key_len` read `<unset>` regardless of provider cannot pass
    // both tests by accident: this one is the one that is SUPPOSED to see
    // `<unset>`.
    let dir = scratch("daemon-proton-key-fs");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if current_generation(&root).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    assert!(!lines.is_empty(), "the stand-in recorded nothing");
    for line in &lines {
        assert_eq!(
            line.key_provider, "fs",
            "`{}` at {} did not carry `PROTON_PASS_KEY_PROVIDER=fs`",
            line.verb, line.dir
        );
        assert_eq!(
            line.key_len, "<unset>",
            "`{}` at {} carried a local-key variable under `fs`, which owns no such value",
            line.verb, line.dir
        );
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_proton_spawn_under_env_carries_the_key_provider_and_the_local_keys_length() {
    // The defect this proves closed: `daemon::login::info_command` and
    // `logout_command` used to be built with `&[]`, so the vendor was asked
    // to open a session under `key_provider: env` with nothing to open it
    // WITH — the same shape of bug review already caught once in
    // `ProtonStore::info_probe_command` (`&[]` where every other builder
    // passed the login), just in the sibling module that spawns `login`,
    // `info` and `logout` rather than the one that spawns `run`/`item`/
    // `vault`. Reverting `establish`'s `info_command` call back to `&[]`
    // turns this red: every `info` line reports `key_len=<unset>` while
    // `login` still carries it. The retirement `logout` is the case below.
    let dir = scratch("daemon-proton-key-env");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    // The suite's generous ceiling, because this case waits on a READ and not
    // on the grace: `timeout_ms` is the store's own read ceiling as well as
    // the input the retirement grace is derived from, so a value small enough
    // to retire quickly is also a deadline the read has to beat on a machine
    // running four test binaries at once. The retirement half is its own case
    // below, which waits on the grace and reads nothing.
    let config = daemon_config_with_generations_loop_env(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if current_generation(&root).is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // A real read too, so the assertion below covers the verbs a LOOKUP
    // spawns and not only the login flow's own three.
    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { .. } => {}
        other => panic!("a declared name must resolve: {}", other.reason()),
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    assert!(!lines.is_empty(), "the stand-in recorded nothing");
    let expected_len = ENCRYPTION_KEY_DECOY.len().to_string();
    let mut verbs_seen = std::collections::BTreeSet::new();
    for line in &lines {
        verbs_seen.insert(line.verb.clone());
        assert_eq!(
            line.key_provider, "env",
            "`{}` at {} did not carry `PROTON_PASS_KEY_PROVIDER=env`",
            line.verb, line.dir
        );
        assert_eq!(
            line.key_len, expected_len,
            "`{}` at {} did not carry the local key — carries no value, only its length",
            line.verb, line.dir
        );
    }
    for verb in ["login", "info"] {
        assert!(
            verbs_seen.contains(verb),
            "`{verb}` never ran, so this run proves nothing about it: {verbs_seen:?}"
        );
    }
    assert!(
        verbs_seen
            .iter()
            .any(|verb| !["login", "info", "logout"].contains(&verb.as_str())),
        "only login-flow verbs ran, so the lookup path is unproven here: {verbs_seen:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_retirement_logout_under_env_carries_the_key_it_needs_to_end_the_session() {
    // The other half of the case above, split off it because the two want
    // opposite things from `timeout_ms`: this one waits on the retirement
    // GRACE (`2 × timeout_ms + 2s + 1s`), so it wants that number small, and
    // it reads nothing through the daemon, so a small read ceiling costs it
    // nothing.
    //
    // The defect it pins: `retire` built `logout_command` with `&[]`, so
    // under `KeyProvider::Env` the plain logout that ends a superseded
    // session's account side could not open that session at all — it failed
    // on the missing key, fell through to `--force`, and left the account
    // session to expire on the vendor's own clock instead of being ended.
    let dir = scratch("daemon-proton-key-env-retire");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    // `3_000` (grace 9s) with `login_after_minutes: 0`: a renewal every tick,
    // so a superseded generation clears the grace inside a run short enough
    // for CI.
    let config = daemon_config_with_generations_loop_env(&dir, &vendor, 0, 1, 3_000);
    let running = start_daemon(&config, policy_allowing_self());

    let deadline = Instant::now() + Duration::from_secs(60);
    let logouts = loop {
        let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
        let lines: Vec<_> = parse_verbs(&verbs)
            .into_iter()
            .filter(|line| line.verb == "logout")
            .collect();
        if !lines.is_empty() {
            break lines;
        }
        assert!(
            Instant::now() < deadline,
            "no retirement logout ran in time, so this case proves nothing"
        );
        std::thread::sleep(Duration::from_millis(200));
    };

    let expected_len = ENCRYPTION_KEY_DECOY.len().to_string();
    for line in &logouts {
        assert_eq!(
            line.key_provider, "env",
            "the retirement logout at {} did not carry `PROTON_PASS_KEY_PROVIDER=env`",
            line.dir
        );
        assert_eq!(
            line.key_len, expected_len,
            "the retirement logout at {} did not carry the local key — carries no value, \
             only its length",
            line.dir
        );
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_renewal_never_logs_out_the_generation_current_names() {
    let dir = scratch("daemon-proton-gen-never-logs-out-current");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    // CONTROL — the change that makes this fail: `timeout_ms: 60_000`
    // (grace 123s, past the 30s this test runs for), the shape this fixture
    // carried before `Generations::candidates` was fixed to anchor a
    // candidate at its own successor's minted time (F3) rather than at
    // `current`'s mtime. `login_after_minutes: 0` keeps every tick due, so
    // under the pre-fix anchor `current`'s mtime was refreshed to "now" on
    // every renewal and no candidate ever cleared the grace — the `for` loop
    // below would iterate an empty set and the `any(logout)` assertion
    // would fail on a run that never logged anything out at all. `3_000`
    // (grace 9s) against a 30s run with a fresh renewal every second is
    // exactly the "sweep lands in the same tick as a publish" case F3
    // fixes, so this is now a real proof of it: logouts DO happen, and none
    // of them ever names the generation `current` held at that instant.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 3_000);
    let running = start_daemon(&config, policy_allowing_self());

    // Comfortably enough ticks (each at least MIN_INTERVAL apart) for the
    // "≥ 2 distinct generations" claim below to be non-trivial.
    std::thread::sleep(Duration::from_secs(30));

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);

    for line in &lines {
        if line.verb != "logout" {
            continue;
        }
        assert_ne!(
            basename(&line.dir),
            line.current,
            "a logout ran against the generation `current` named at that instant: {}",
            line.dir
        );
    }

    // Without this, the loop above proves nothing whenever no candidate ever
    // clears the grace — exactly the state the pre-F3 anchor left this test
    // in, silently, forever.
    assert!(
        lines.iter().any(|line| line.verb == "logout"),
        "no logout ran at all in 30s, so the loop above checked an empty set: {lines:?}"
    );

    let distinct_logins: std::collections::BTreeSet<&str> = lines
        .iter()
        .filter(|line| line.verb == "login")
        .map(|line| line.dir.as_str())
        .collect();
    assert!(
        distinct_logins.len() >= 2,
        "fewer than two distinct generations were logged into in 30s: {distinct_logins:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_generation_the_daemon_retires_is_logged_out_then_removed_and_current_survives() {
    // CONTROL — the change that makes this fail: `retire` treating every
    // candidate as already logged out and never spawning a logout at all.
    // The directory still disappears (`remove` does not depend on the
    // logout outcome), so only the `any(logout && …)` assertion below
    // catches it: "the superseded generation disappeared with no logout
    // line ahead of it."
    //
    // `login_after_minutes: 0` forces the FIRST tick to renew (`established`
    // starts `None`, which is always due); the LARGE `login_after_minutes`
    // here keeps every tick after that one not-due, so exactly one renewal
    // happens and the root's only candidate is the generation this fixture
    // published up front. `Generations::candidates` anchors that candidate
    // at its successor's own minted time — fixed the instant the forced
    // renewal mints it, and untouched by anything published later — so the
    // grace clears on an ordinary later tick that does nothing but sweep,
    // whether or not a further renewal ever runs. A run where every tick
    // renews is exercised on its own, against real retirements, by
    // `a_renewal_never_logs_out_the_generation_current_names`.
    let dir = scratch("daemon-proton-gen-retires");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, true, LogoutAnswer::Ok, None);
    let root = session_dir(&dir);
    let before = publish_generation(&root);
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 1, 3_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root_generation = before
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();

    // Polled rather than a fixed sleep: the forced first renewal and the
    // grace (9s) both complete quickly on an idle machine, but this only
    // widens the WAIT for a loaded one — the grace arithmetic itself is
    // fixed, so a generous ceiling here never turns a genuine non-convergence
    // into a false green.
    //
    // Two phases, not one: `root_generation` itself already satisfies
    // "exactly one directory, and it is current" the instant this fixture
    // publishes it, before the loop's thread has run at all — so convergence
    // is only meaningful once a DIFFERENT generation has actually landed.
    let renewed = Instant::now() + Duration::from_secs(60);
    let current = loop {
        match current_generation(&root) {
            Some(name) if name != root_generation => break name,
            _ => {}
        }
        assert!(
            Instant::now() < renewed,
            "the loop never performed its forced first renewal, so nothing here is under test"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let converged = Instant::now() + Duration::from_secs(60);
    loop {
        let remaining = generation_dirs(&root);
        if remaining == vec![current.clone()] {
            break;
        }
        assert!(
            Instant::now() < converged,
            "the root did not converge to exactly the current generation: {remaining:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    assert!(
        lines
            .iter()
            .any(|line| line.verb == "logout" && basename(&line.dir) == root_generation),
        "the superseded generation disappeared with no logout line ahead of it"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_login_that_succeeds_but_does_not_answer_info_is_discarded_and_current_is_unchanged() {
    // CONTROL — the change that makes this fail: `establish` never
    // discarding on a failed `info` (publishing every login regardless).
    // `generation_dirs` grows past `[g0]` and never converges back, so the
    // first polling loop below runs out its 30s deadline and panics naming
    // every generation that piled up instead of being discarded.
    let dir = scratch("daemon-proton-gen-info-fails");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    // `info` never answers: every login this loop performs succeeds and is
    // then discarded, so `current` must stay exactly where the fixture put it.
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, false, LogoutAnswer::Ok, None);
    let root = session_dir(&dir);
    let published = publish_generation(&root);
    let g0 = published
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();
    // `60_000` — nothing here is about the grace: a discard runs immediately,
    // with no drain and no grace at all (see `discard_unpublished`).
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    // CONTROL — the change that makes this fail: dropping the first phase
    // below and polling `generation_dirs(&root) == vec![g0]` alone, which
    // is already true the INSTANT `publish_generation` writes it above,
    // before the daemon has even started — the `dirs:?}"` message would
    // never print because the loop breaks on its first iteration and the
    // property "a login that could not answer `info` was discarded" would
    // be unexercised. So this waits for evidence the loop actually
    // attempted more than one login FIRST — the same two-phase shape
    // `a_generation_the_daemon_retires_is_logged_out_then_removed_and_
    // current_survives` uses for the identical hazard — and only then
    // checks that nothing any of those attempts produced survived.
    let attempted = Instant::now() + Duration::from_secs(30);
    loop {
        let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
        let logins = parse_verbs(&verbs)
            .iter()
            .filter(|line| line.verb == "login")
            .count();
        if logins >= 2 {
            break;
        }
        assert!(
            Instant::now() < attempted,
            "the loop never attempted two logins, so nothing here is under test"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Polled rather than a single fixed sleep: a discard is a few subprocess
    // spawns this MACHINE'S load decides the speed of, and the property under
    // test is that it removes what it creates, not how fast it runs. A
    // generous ceiling still catches a discard that never happens at all.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let dirs = generation_dirs(&root);
        if dirs == vec![g0.clone()] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "a login that could not answer `info` was not discarded: {dirs:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(
        current_generation(&root).as_deref(),
        Some(g0.as_str()),
        "current changed even though every login could not be verified"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_renewal_whose_old_store_cannot_be_decrypted_still_establishes_a_new_generation_and_reads_succeed()
 {
    // CONTROL — the change that makes this fail: `retire` treating every
    // candidate as already logged out (never spawning the plain logout at
    // all, so the force step it would otherwise trigger never runs either).
    // The old generation is still removed either way, so only the
    // `logout_then_force` pair assertion below catches the missing step.
    let dir = scratch("daemon-proton-gen-old-store-undecryptable");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    // Plain logout answers with the vendor's own aead sentence and fails;
    // `--force` (handled unconditionally by the stub) succeeds — the shape a
    // generation nothing can decrypt produces.
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::Fails(
            "Error decrypting local session(Error decrypting session: aead::Error)",
        ),
        None,
    );
    let root = session_dir(&dir);
    let before = publish_generation(&root);
    // `login_after_minutes: 90` for the reason
    // `a_generation_the_daemon_retires_is_logged_out_then_removed_and_current_survives`
    // gives in full: the forced first tick (`established` starts `None`) is
    // the only renewal this run performs, so the old generation's one and
    // only successor is minted once and its grace clears on a later,
    // sweep-only tick.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 1, 3_000);
    let running = start_daemon(&config, policy_allowing_self());

    let old_generation = before
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();

    // Polled rather than a fixed sleep, for the same reason every other
    // generations case in this file polls: the grace (9s) is a fixed
    // arithmetic fact and does not need widening, but the subprocess spawns
    // around it do, on a loaded machine.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if !generation_dirs(&root).contains(&old_generation) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the undecryptable old generation was never removed"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    let client = client_config(running.socket(), 10_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { .. } => {}
        other => panic!(
            "a read must succeed once a new generation is established: {}",
            other.reason()
        ),
    }

    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    let logout_then_force = lines.windows(2).any(|pair| {
        pair[0].verb == "logout"
            && pair[1].verb == "logout"
            && basename(&pair[0].dir) == old_generation
            && pair[0].dir == pair[1].dir
    });
    assert!(
        logout_then_force,
        "no plain logout of the old generation was immediately followed by a force logout at \
         the same directory"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_generation_published_by_another_process_is_served_at_the_daemons_next_read() {
    // CONTROL — the change that makes this fail: `Generations::enter`
    // memoizing the first successful read of `current` forever instead of
    // re-reading it on every call. The daemon's OWN first read still
    // resolves; the assertion that catches the staleness is the final one,
    // comparing what the SECOND read (after the out-of-band publish) was
    // actually scoped at against the new generation the other process just
    // published.
    let dir = scratch("daemon-proton-gen-cross-process");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    let root = session_dir(&dir);
    publish_generation(&root);
    // A slow probe interval — the point is that the daemon's OWN loop never
    // ticks during this test, so any change `current` shows must have come
    // from the out-of-band `establish` call below. `60_000` — nothing here is
    // timed against the grace.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 300, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 10_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!(
            "the fixture's own read must succeed first: {}",
            other.reason()
        ),
    }

    // A second process's `keylessd login --replace`, modelled as a direct
    // call against the SAME root — nothing here goes through the running
    // daemon or its loop.
    let coordinates = login::coordinates(&config).expect("valid coordinates");
    let audit = std::fs::metadata(dir.join("audit.jsonl")).expect("audit");
    use std::os::unix::fs::MetadataExt;
    let owner = login::Owner {
        uid: audit.uid(),
        gid: audit.gid(),
    };
    let outside = Generations::at(root.clone());
    let token = keyless::secret::Secret::new(TOKEN_DECOY.to_owned());
    login::establish(
        &coordinates,
        owner,
        true,
        &token,
        Vec::new(),
        &outside,
        &mut std::io::sink(),
    )
    .expect("the out-of-band login must succeed");

    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!("the next read must still resolve: {}", other.reason()),
    }
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        root.join(current_generation(&root).expect("the out-of-band login published a generation"))
            .display()
            .to_string(),
        "the daemon's next read was not scoped at the generation the other process published, \
         with no restart and no tick"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_legacy_session_directory_is_retired_and_never_served_from() {
    // CONTROL — this fails four different ways under four different faults.
    // Drop the `is_dir` gate from `Generations::candidates`'s legacy branch,
    // or gate the legacy candidate behind an age check the way an ordinary
    // generation is gated, and `.session` below never disappears before the
    // 30s deadline. Widen `ProtonStore::enter`'s own legacy fallback —
    // narrowly gated on `CurrentFault::Absent` plus the legacy directory
    // existing as a directory, see its own doc — to also answer once a
    // generation is current, or on any other `CurrentFault`, and the final
    // assertion below, which reads back the exact directory the read was
    // scoped at, stops naming a real generation. And widen `candidates` to
    // admit the legacy candidate before any generation has ever published —
    // the ordering check near the end, over every `pass-cli.verbs` line,
    // catches a `logout` scoped at the root ahead of the first `login`.
    let dir = scratch("daemon-proton-gen-legacy-retired");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true,
        LogoutAnswer::AlreadyLoggedOut,
        None,
    );
    let root = session_dir(&dir);

    // The pre-existing layout a machine upgrading in place carries into this
    // change: a `.session` directory the OLD, pre-generations code wrote,
    // with a marker standing in for the real session store. Planted before
    // the daemon ever starts, so the very first thing this daemon does with
    // its session directory is decide what to do about a layout it did not
    // create.
    let legacy = root.join(".session");
    std::fs::create_dir_all(&legacy).expect("create the legacy layout");
    std::fs::write(legacy.join("session.json"), b"legacy-marker").expect("plant the legacy marker");

    // `60_000` — this case is not about the grace: `Generations::candidates`
    // makes the legacy candidate eligible the instant a first generation
    // publishes, with no age check of its own, so nothing here is timed
    // against a grace at all.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    // Polled rather than a fixed sleep, the same shape every other
    // generations case in this file uses: this only waits on subprocess
    // spawns this machine's load decides the speed of.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        // Whenever `current` names anything at all, it must name a real
        // generation directory and nothing else — never the legacy layout,
        // which no `GenerationName` ever parses — and a read performed at
        // that instant must succeed. A read performed before any generation
        // is current is not attempted here: it is expected to degrade, and
        // asserting success on it would prove nothing about the legacy
        // directory either way.
        if let Some(name) = current_generation(&root) {
            assert!(
                generation_dirs(&root).contains(&name),
                "`current` named {name}, which is not a generation directory under {}",
                root.display()
            );
            match registry.resolve(DECLARED) {
                Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
                other => panic!(
                    "a read failed once a generation was current: {}",
                    other.reason()
                ),
            }
        }
        if !legacy.exists() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the legacy session directory was never retired: {}",
            legacy.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // One last read, after the legacy directory is confirmed gone, checked
    // against the OTHER side of the interface — the directory the stub was
    // actually handed — rather than trusted on its return value alone. A
    // fallback that quietly pointed a read at `root` itself (rather than
    // degrading, or rather than the published generation) would still return
    // the stub's decoy, since `Backend::Injects` answers regardless of scope;
    // this is the assertion that would catch it.
    let current = current_generation(&root).expect("the loop never published a generation");
    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!("the final read must succeed: {}", other.reason()),
    }
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        root.join(&current).display().to_string(),
        "a read was scoped somewhere other than the published current generation"
    );

    // The scope invariant over every line this whole run produced, not the
    // single last-read sample above, plus the ordering S9 names: no `run`
    // or `item` line is ever scoped at the root, and no `logout` at the
    // root — the legacy candidate's own scope — runs before the first
    // `login`, which is what would prove the legacy candidate was retired
    // before any generation existed to make it eligible.
    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    let lines = parse_verbs(&verbs);
    let root_str = root.display().to_string();
    for line in &lines {
        if matches!(line.verb.as_str(), "run" | "item" | "vault") {
            assert_ne!(
                line.dir, root_str,
                "a `{}` was scoped at the root instead of a generation",
                line.verb
            );
        }
    }
    let first_login = lines
        .iter()
        .position(|line| line.verb == "login")
        .expect("the loop never logged in at all");
    assert!(
        lines[..first_login]
            .iter()
            .all(|line| !(line.verb == "logout" && line.dir == root_str)),
        "a legacy logout at the root ran before the first login: {:?}",
        &lines[..first_login]
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_daemon_with_no_renewal_loop_and_only_the_legacy_layout_reads_from_it_instead_of_degrading() {
    // Consumer F1: an install with `session.auto_login` off (the default)
    // runs no renewal loop, so nothing ever writes `<root>/current` — and a
    // pre-upgrade install's real, working session sits at `<root>/.session`,
    // the layout this crate wrote before generations existed. Planted here
    // and never touched by a loop, since this daemon's config carries no
    // `session` block at all.
    let dir = scratch("daemon-proton-legacy-only-no-loop");
    let vendor = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    let root = session_dir(&dir);
    let legacy = root.join(".session");
    std::fs::create_dir_all(&legacy).expect("plant the pre-generation layout");
    std::fs::write(legacy.join("session.json"), b"pre-upgrade session")
        .expect("plant the legacy marker");

    let config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(&dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = root.display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config");
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    match registry.resolve(DECLARED) {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!(
            "a legacy-only root with no renewal loop must still resolve: {}",
            other.reason()
        ),
    }
    assert_eq!(
        support::recorded(&dir.join("pass-cli.session")),
        root.display().to_string(),
        "the read was not scoped at the root the legacy layout lives under"
    );
    assert!(
        current_generation(&root).is_none(),
        "no renewal loop ran, so `current` must still name nothing"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_read_already_in_flight_finishes_against_an_intact_directory_while_its_generation_is_retired() {
    // CONTROL. The property under test is that `Generations::drain` blocks a
    // retirement until every in-process reader of that generation has
    // finished — see `Generations::remove`'s own doc: it is the last guard,
    // and this case is what proves the guard the DRAIN provides is load-
    // bearing rather than redundant with it. Neutering `drain` (returning
    // `Ok(())` without waiting on `self.changed`) makes retirement run the
    // instant the candidate is eligible, deleting `original` while the read
    // below is still asleep inside the stub — its end-of-run check then finds
    // the marker gone and records `missing`. This was run both ways; see the
    // report for both outcomes.
    let dir = scratch("daemon-proton-gen-read-survives-retirement");
    let inner = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );

    let read_witness = dir.join("read.witness");
    let read_marker = "read-in-flight-marker";
    // How long the stand-in vendor holds `original` open before answering the
    // read. `Generations::candidates` anchors a candidate's eligibility at
    // `max(created_at, mtime(current))` (see that method's own doc), and
    // between them `current`'s mtime is the one this test can move without
    // waiting: after `original` is superseded, this file back-dates it
    // directly — the same shortcut `support::publish_generation_aged`'s own
    // doc names ("the shape a retirement fixture needs to make a generation
    // eligible without waiting out a real grace period"), applied to a
    // `current` this daemon wrote rather than one this fixture minted. That
    // makes `original` eligible on the very next tick, at most one
    // `MIN_INTERVAL` (5s, `src/daemon/session.rs`) after it is superseded —
    // so 15s is several times that window, wide enough to absorb scheduling
    // jitter under a loaded machine and still be a small fraction of the 60s
    // `capture` ceiling `timeout_ms` below gives the stand-in vendor to
    // answer in.
    let read_delay = Duration::from_secs(15);
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        // Delays the RENEWAL's own login, not the read: this is what
        // guarantees the client read spawned below reaches `enter()` — and so
        // is scoped at `original` — before the renewal loop's forced first
        // tick can supersede it. Two seconds is generous margin over a socket
        // connect and one dispatch on an idle machine, and it is paid for
        // once, at the very start of the test.
        Duration::from_secs(2),
        true,
        LogoutAnswer::Ok,
        Some(ReadProbe {
            delay: read_delay,
            marker: read_marker,
            witness: read_witness.clone(),
        }),
    );

    let root = session_dir(&dir);
    // `timeout_ms` first, so `original`'s own age can be minted comfortably
    // past the grace it implies — see the loop below, which reuses this same
    // value.
    let timeout_ms: u64 = 60_000;
    let grace = login::grace(timeout_ms);
    // Minted with its OWN embedded creation time already past the grace,
    // because `Generations::candidates` takes the LATER of a candidate's own
    // age and `current`'s mtime — back-dating `current` alone, without also
    // back-dating `original`'s own name, would still read as young the
    // moment a later publish (the renewal below) refreshes `current`'s mtime
    // to now. Both anchors are aged here, by different, generous margins, so
    // neither one alone decides eligibility.
    let original = publish_generation_aged(&root, grace + Duration::from_secs(60));
    std::fs::write(original.join(read_marker), b"still-here")
        .expect("plant the in-flight read's own marker");
    let original_name = original
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();

    // `login_after_minutes: 90` for the reason
    // `a_generation_the_daemon_retires_is_logged_out_then_removed_and_current_survives`
    // gives in full: the forced first tick is the loop's only renewal, and
    // every tick after that finds the new generation `alive` and does
    // nothing but sweep.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 1, timeout_ms);
    let running = start_daemon(&config, policy_allowing_self());

    // The read the invariant is about. Issued the instant the daemon is up,
    // while `current` still names `original` — the renewal loop's own login
    // is asleep for two seconds (above), which is ample margin for this call
    // to reach `enter()`, scoped at `original`, before anything else can move
    // `current`. It blocks inside the stub for `read_delay` before
    // answering, so it runs on its own thread.
    let client = Client::new(running.socket().to_path_buf(), Duration::from_secs(30));
    let read = std::thread::spawn(move || client.request(&Request::resolve(DECLARED)));

    // Wait for the renewal to supersede `original`, then remove the only
    // thing standing between it and immediate eligibility: the freshness of
    // `current`'s own mtime, which the renewal's own publish just refreshed
    // to now. See the comment on `read_delay` above for what this unlocks.
    let superseded = Instant::now() + Duration::from_secs(30);
    let current_path = root.join("current");
    loop {
        match current_generation(&root) {
            Some(name) if name != original_name => break,
            _ => {}
        }
        assert!(
            Instant::now() < superseded,
            "the renewal loop never superseded the original generation"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let ancient = SystemTime::now()
        .checked_sub(grace + Duration::from_secs(30))
        .expect("the clock supports a date this far back");
    std::fs::File::options()
        .write(true)
        .open(&current_path)
        .expect("open current to back-date it")
        .set_modified(ancient)
        .expect("back-date current's mtime");

    // Poll for the retirement this back-dating unlocks: `original`'s
    // directory disappearing. This loop is not the assertion that the read
    // survived it — the witness log below is — it only bounds how long the
    // whole test waits, generously, for the retirement to happen at all.
    let retired = Instant::now() + Duration::from_secs(90);
    while original.exists() {
        assert!(
            Instant::now() < retired,
            "the original generation was never retired: {}",
            original.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    match read.join().expect("the read thread panicked") {
        Ok(Reply::Value(secret)) => assert_eq!(secret.expose(), PROTON_DECOY),
        other => panic!("the in-flight read must still return its value: {other:?}"),
    }

    // The property itself: the stub's own end-of-run check, read back from
    // the OTHER side of the interface rather than inferred from the read's
    // success — `inner` answers with the decoy regardless of which directory
    // it was scoped at, so a read that succeeds proves nothing here on its
    // own.
    let witness = std::fs::read_to_string(&read_witness).unwrap_or_default();
    assert_eq!(
        witness.trim(),
        "intact",
        "the in-flight read's own directory was not intact when it finished: {witness:?}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// A session fault is not a verdict about a name: a vendor failure that is
// about the daemon's OWN session — never established by matching the
// vendor's wording — keeps the cache warm, is reported as `Unavailable`, and
// wakes the renewal loop; the same failure over a healthy session is still a
// verdict about the item and still evicts.
// ---------------------------------------------------------------------------

/// A vendor sentence that means nothing to the transport allowlist and
/// matches no phrase measured anywhere in this crate — the shape "the
/// account said something about this read" takes when nobody has a more
/// specific idea what. Used identically across every case below, so what
/// changes between them is only whether the session answers, never the
/// words — which is the property this whole slice exists to prove.
const SESSION_FAULT_SENTENCE: &str =
    "some arbitrary Proton failure text this build has never measured before";

/// Remove `.session/session.json` from an already-published generation
/// directory — [`support::publish_generation`] plants one by default, the
/// way a real `pass-cli login` would have left it, so THIS is the explicit
/// step a case takes to model the other half of the structural check: the
/// vendor's own invalidation cleanup having removed it from inside a read.
fn remove_session_file(generation_dir: &Path) {
    let path = generation_dir.join(".session").join("session.json");
    std::fs::remove_file(&path)
        .unwrap_or_else(|error| panic!("remove the planted session.json at {path:?}: {error}"));
}

/// How many times `pass-cli info` ran, read out of
/// [`stub_with_session_verbs`]'s own verb log — the coalesced probe's own
/// tally, kept separate from [`vendor_call_count`] (the value-reading `run`
/// verb) and [`listing_count`] (`item list`) for the same reason those two
/// are kept apart from each other: each is a different claim about a
/// different verb.
fn info_call_count(dir: &Path) -> usize {
    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    parse_verbs(&verbs)
        .into_iter()
        .filter(|line| line.verb == "info")
        .count()
}

/// A second declared name, addressing the exact same vault, item and field
/// as [`DECLARED`] — a burst across the two still shares one listing and one
/// session either way, and reusing the coordinate keeps this fixture inside
/// the decoy field names `tests/publication.rs` already allowlists rather
/// than inventing a new one. That is what
/// [`a_burst_of_failing_names_costs_one_probe_not_one_per_name`] needs: two
/// failures that can only share a coalesced probe because they share a
/// GENERATION, never because they share a vault entry.
const DECLARED_2: &str = "FIXTURE_DECLARED_2";

/// [`daemon_config_with_a_warm_cache`], with [`DECLARED_2`] added beside
/// [`DECLARED`].
fn daemon_config_with_two_names(
    dir: &Path,
    vendor: &Path,
    freshness_seconds: u64,
    stale_seconds: u64,
) -> DaemonConfig {
    support::publish_generation(&session_dir(dir));
    let mut config: DaemonConfig = serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "timeout_ms":60000}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}},
                         "{DECLARED_2}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config");
    config.cache_ttl_seconds = freshness_seconds;
    config.cache_stale_seconds = stale_seconds;
    config
}

#[test]
fn a_vendor_failure_whose_info_also_fails_keeps_the_value_and_reports_the_store_unavailable() {
    // CONTROL — the change that makes this fail: `vendor_failed` still
    // classifying every non-transport failure as `StoreError::Backend`, the
    // shape it had before this slice. The value would be evicted instead of
    // kept, and the second `value_from` below would panic rather than read
    // `held` back.
    let dir = scratch("daemon-proton-session-fault-info-fails");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        false, // `info` fails too: the session itself cannot answer
        LogoutAnswer::Ok,
        None,
    );
    // `daemon_config_with_a_warm_cache` publishes the generation this reads
    // through, with a `.session/session.json` already inside it — see
    // `support::publish_generation_aged` — so the structural check's `stat`
    // finds a present, ordinary session and falls through to the coalesced
    // probe below.
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "a session fault must keep the value the daemon already held"
    );
    until_the_vendor_has_been_asked(&dir, 2);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "the value survived the failing refresh and then did not survive the read after it"
    );
    assert!(
        info_call_count(&dir) >= 1,
        "a non-transport failure never asked the session whether it was still alive"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_vendor_failure_whose_info_answers_evicts_the_value_as_a_verdict_about_the_name() {
    // CONTROL — the change that makes this fail: reading a non-transport
    // failure as a session fault unconditionally, without ever asking `info`
    // — the eviction below would never happen and the poll would fail at
    // `NEVER_HAPPENED`.
    let dir = scratch("daemon-proton-session-fault-info-answers");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true, // `info` answers: the session is healthy
        LogoutAnswer::Ok,
        None,
    );
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);
    let _ = registry.resolve(DECLARED);
    until_the_vendor_has_been_asked(&dir, 2);

    set_next_call(&dir, &NextCall::Fails(TRANSPORT_FAILURE));
    let reason = until_the_read_degrades(&registry, DECLARED);

    assert!(
        reason.contains(TRANSPORT_FRAGMENT),
        "the read degraded before the value's absence was what caused it: {reason}"
    );
    assert!(
        !reason.contains(&held),
        "the refusal carried the value it had just disowned"
    );
    assert!(
        info_call_count(&dir) >= 1,
        "a non-transport failure never asked the session whether it was still alive"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_session_json_is_a_session_fault_decided_without_spawning_anything() {
    // CONTROL — the change that makes this fail: `session_is_at_fault`
    // skipping the `stat` and going straight to the coalesced probe. The
    // read below would still keep the value (the probe reads the session as
    // dead too, since `info` fails here as well) but `info_call_count`
    // would come back nonzero — the absence was never enough on its own.
    let dir = scratch("daemon-proton-session-fault-missing-file");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, false, LogoutAnswer::Ok, None);
    let config = daemon_config_with_a_warm_cache(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    // `daemon_config_with_a_warm_cache` plants a `.session/session.json` by
    // default (see `support::publish_generation_aged`) — removed here so the
    // generation directory holds none at all, the vendor's own invalidation
    // cleanup's signature, per the parent RCA's §3.
    remove_session_file(&published_generation(&dir));
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry, DECLARED),
        held,
        "a missing session.json must keep the value, exactly as a failing probe does"
    );
    until_the_vendor_has_been_asked(&dir, 2);

    assert_eq!(
        info_call_count(&dir),
        0,
        "a missing session.json still spawned a probe to confirm what the stat already knew"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_burst_of_failing_names_costs_one_probe_not_one_per_name() {
    // CONTROL — the change that makes this fail: `session_is_at_fault`
    // calling the vendor's `info` directly instead of routing it through
    // `Generations::session_fault`'s coalescing. Two names failing together
    // would then spawn two `info` calls, and the count below would read 2,
    // never 1.
    let dir = scratch("daemon-proton-session-fault-burst");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, false, LogoutAnswer::Ok, None);
    let config = daemon_config_with_two_names(&dir, &vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = std::sync::Arc::new(store::build(&client, &Invocation::default()).registry);

    // Warm both names first: each is its own read against the same vault, so
    // the vendor is asked once per field before either failure below.
    let held_1 = value_from(&registry, DECLARED);
    let held_2 = value_from(&registry, DECLARED_2);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);

    // Both names fail at the same instant, on their own threads — a
    // sequential pair of reads would still coalesce inside the probe's
    // window, but only a genuine burst exercises the lock held across the
    // spawn, which is the mechanism under test.
    use std::sync::{Arc, Barrier};
    let barrier = Arc::new(Barrier::new(2));
    let (registry_a, barrier_a) = (Arc::clone(&registry), Arc::clone(&barrier));
    let first = std::thread::spawn(move || {
        barrier_a.wait();
        value_from(&registry_a, DECLARED)
    });
    let (registry_b, barrier_b) = (Arc::clone(&registry), barrier);
    let second = std::thread::spawn(move || {
        barrier_b.wait();
        value_from(&registry_b, DECLARED_2)
    });
    let answer_1 = first.join().expect("the first reader panicked");
    let answer_2 = second.join().expect("the second reader panicked");

    assert_eq!(
        answer_1, held_1,
        "the first name's value did not survive the burst"
    );
    assert_eq!(
        answer_2, held_2,
        "the second name's value did not survive the burst"
    );

    // Pin that BOTH reads actually reached the vendor and failed there,
    // before the probe count is read. Without this the case is green in a run
    // where one name's refresh is still queued or is answered inside
    // `REFRESH_GRACE` from the older value: one vendor failure, one probe,
    // and a passing count over a burst that never happened. The value
    // assertions above cannot close that hole — they read the same `held_N`
    // whether or not that name's refresh ever ran.
    assert!(
        vendor_call_count(&dir) >= 4,
        "the two warm-up reads and the two failing ones did not all reach the vendor, so \
         the probe count below is not measuring a burst: {}",
        vendor_call_count(&dir)
    );
    assert_eq!(
        info_call_count(&dir),
        1,
        "two names failing over one session cost more than one probe"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_session_fault_wakes_the_renewal_loop_inside_min_backoff() {
    // CONTROL — the change that makes this fail: dropping
    // `generations.take_session_fault()` from `run`'s own `due` calculation.
    // The loop would then only ever renew on its age or its own `alive()`
    // check, and neither is due here — `info` answers healthy throughout,
    // and `login_after_minutes` / `probe_interval_seconds` both sit far
    // outside this test's own window — so the poll below would time out
    // with no second login ever recorded.
    let dir = scratch("daemon-proton-session-fault-wakes-loop");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let vendor = stub_with_session_verbs(
        &dir,
        &inner,
        Duration::ZERO,
        true, // `info` always answers: nothing here is due on liveness
        LogoutAnswer::Ok,
        None,
    );
    // `login_after_minutes: 90` and `probe_interval_seconds: 120` put both
    // ordinary triggers far outside this test's run, so a second login
    // inside the poll below can only be the session-fault event.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 90, 120, 60_000);
    let running = start_daemon(&config, policy_allowing_self());

    let root = session_dir(&dir);
    let deadline = Instant::now() + Duration::from_secs(30);
    let original_name = loop {
        if let Some(name) = current_generation(&root) {
            break name;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was ever published"
        );
        std::thread::sleep(Duration::from_millis(100));
    };

    // No `.session/session.json` is ever planted under the generation the
    // fake `login` verb "established" — this stand-in never writes one — so
    // the read below is classified a session fault by the cheaper of the
    // two checks, the `stat`, independent of `info_answers` above.
    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    let _ = registry.resolve(DECLARED);

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(name) = current_generation(&root)
            && name != original_name
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no second login happened within 30s of the session-fault event, though the \
             configured interval is 120s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_same_vendor_sentence_evicts_with_a_healthy_session_and_keeps_the_value_without_one() {
    // CONTROL — the change this whole slice exists to rule out: classifying
    // by matching `SESSION_FAULT_SENTENCE`, or any fixed wording, into the
    // transport allowlist. That would make both halves below evict, or both
    // keep, regardless of the session's own health — the two assertions
    // could never disagree, which is exactly what this test exists to catch.
    let dir = scratch("daemon-proton-session-fault-control");
    let inner = stub_pass_cli_listing(&dir, &Backend::Controlled, &Listing::Json(LISTING));
    let healthy_vendor =
        stub_with_session_verbs(&dir, &inner, Duration::ZERO, true, LogoutAnswer::Ok, None);
    let config =
        daemon_config_with_a_warm_cache(&dir, &healthy_vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running = start_daemon(&config, policy_allowing_self());

    let client = client_config(running.socket(), 3_000);
    let registry = store::build(&client, &Invocation::default()).registry;

    let held = vendor_decoy(1);
    assert_eq!(value_from(&registry, DECLARED), held);

    set_next_call(&dir, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);
    let _ = registry.resolve(DECLARED);
    until_the_vendor_has_been_asked(&dir, 2);

    set_next_call(&dir, &NextCall::Fails(TRANSPORT_FAILURE));
    let reason = until_the_read_degrades(&registry, DECLARED);
    assert!(
        reason.contains(TRANSPORT_FRAGMENT),
        "the healthy-session half degraded before the value's absence was the cause: {reason}"
    );

    drop(running);

    // Second half: the identical sentence, a fresh daemon, a dead session —
    // the only thing that changed.
    let dir2 = scratch("daemon-proton-session-fault-control-2");
    let inner2 = stub_pass_cli_listing(&dir2, &Backend::Controlled, &Listing::Json(LISTING));
    let dead_vendor = stub_with_session_verbs(
        &dir2,
        &inner2,
        Duration::ZERO,
        false,
        LogoutAnswer::Ok,
        None,
    );
    let config2 =
        daemon_config_with_a_warm_cache(&dir2, &dead_vendor, FRESHNESS_SECONDS, STALE_SECONDS);
    let running2 = start_daemon(&config2, policy_allowing_self());

    let client2 = client_config(running2.socket(), 3_000);
    let registry2 = store::build(&client2, &Invocation::default()).registry;

    assert_eq!(value_from(&registry2, DECLARED), held);
    set_next_call(&dir2, &NextCall::Fails(SESSION_FAULT_SENTENCE));
    std::thread::sleep(PAST_FRESHNESS);

    assert_eq!(
        value_from(&registry2, DECLARED),
        held,
        "the SAME sentence, over a dead session, must keep the value rather than evict it"
    );

    drop(running2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

// ---------------------------------------------------------------------------
// The vendor's own store semantics, pinned.
//
// Everything above this line is a claim about the DAEMON. The cases below are
// claims about `pass-cli` — read out of its source at the version installed on
// this machine and written down so a release that changes one of them arrives
// as a red test rather than as an undecryptable session store.
//
// They drive `support::stub_pass_cli_store` directly, with no daemon anywhere:
// the stand-in is the subject, and a case that reached it through the daemon
// could not say whether a wrong answer came from the model or from the adapter.
// `support::stub_pass_cli_store`'s own doc carries the source citation for each
// behaviour, and the sentences asserted here are quoted from the vendor.
// ---------------------------------------------------------------------------

/// One directory a vendor child is pointed at, holding nothing yet.
fn vendor_scope(dir: &Path, tag: &str) -> std::path::PathBuf {
    let scope = dir.join(tag);
    std::fs::create_dir_all(&scope).expect("create the directory the variable names");
    scope
}

/// What `PROTON_PASS_KEY_PROVIDER` and `PROTON_PASS_ENCRYPTION_KEY` are set to
/// for one invocation — or deliberately not set, which is a third answer the
/// vendor reads differently from either.
enum Keying {
    /// `key_provider: fs`, the arrangement that keeps the key in a file.
    Fs,
    /// `key_provider: env` with a key, the arrangement this daemon ships.
    Env(&'static str),
    /// `key_provider: env` with the key variable left off entirely.
    EnvWithoutKey,
    /// `key_provider: env` with the key variable present and EMPTY.
    EnvWithEmptyKey,
    /// Neither variable set at all — what a call site that forgot the scope
    /// hands the vendor.
    Unset,
    /// The provider variable present and empty, which is not the same
    /// omission and, per the vendor, not a different one either.
    Empty,
}

/// Run the store stand-in once, exactly as a child of the daemon would be run.
///
/// The environment is CLEARED rather than inherited, so a variable the
/// developer happens to export cannot decide which arm the stand-in takes —
/// which is the whole subject of several cases below.
fn run_vendor(vendor: &Path, scope: &Path, keying: &Keying, args: &[&str]) -> std::process::Output {
    let mut command = std::process::Command::new(vendor);
    command.args(args);
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    command.env("PROTON_PASS_SESSION_DIR", scope);
    match keying {
        Keying::Fs => {
            command.env("PROTON_PASS_KEY_PROVIDER", "fs");
        }
        Keying::Env(key) => {
            command.env("PROTON_PASS_KEY_PROVIDER", "env");
            command.env("PROTON_PASS_ENCRYPTION_KEY", key);
        }
        Keying::EnvWithoutKey => {
            command.env("PROTON_PASS_KEY_PROVIDER", "env");
        }
        Keying::EnvWithEmptyKey => {
            command.env("PROTON_PASS_KEY_PROVIDER", "env");
            command.env("PROTON_PASS_ENCRYPTION_KEY", "");
        }
        Keying::Unset => {}
        Keying::Empty => {
            command.env("PROTON_PASS_KEY_PROVIDER", "");
        }
    }
    command
        .output()
        .unwrap_or_else(|error| panic!("cannot run the vendor stand-in: {error}"))
}

fn said(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The permission bits on `path`, as the three octal digits a person writes.
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("cannot stat {}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

fn store_stub(dir: &Path, behaviour: &support::VendorStore) -> std::path::PathBuf {
    let inner = stub_pass_cli_listing(
        dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    support::stub_pass_cli_store(dir, &inner, behaviour)
}

#[test]
fn an_fs_child_pointed_at_an_empty_directory_creates_the_store_the_vendor_creates() {
    // Two vendor facts in one invocation, because they happen in one stretch of
    // its startup and a case that separated them would need two fixtures to say
    // one thing: `get_base_dir` creates `.session` under the variable, mode
    // 0700, on EVERY verb before dispatch; and the `fs` key provider MINTS
    // `local.key` at 0600 when it finds none — also on every verb, a read
    // included.
    //
    // That pair is why an operator's mistyped command leaves a whole
    // old-style layout behind for something else to find later.
    let dir = scratch("vendor-store-fs-creates");
    let vendor = store_stub(&dir, &support::VendorStore::INSTANT);
    let scope = vendor_scope(&dir, "scope");

    let output = run_vendor(&vendor, &scope, &Keying::Fs, &["info"]);

    let base = scope.join(".session");
    assert!(
        base.is_dir(),
        "the vendor creates `.session` under the directory the variable names, on every verb"
    );
    assert_eq!(mode_of(&base), 0o700, "`.session` is created owner-only");
    let key = base.join("local.key");
    assert!(
        key.is_file(),
        "an `fs` child that finds no local key mints one — on a read, not only on a login"
    );
    assert_eq!(mode_of(&key), 0o600, "the minted key is created owner-only");
    // The verb itself still fails: there is no session in this directory. That
    // is the shape of the hazard — the failure is ordinary and the directory
    // has been written to anyway.
    assert!(!output.status.success());
    assert!(
        said(&output).contains("This operation requires an authenticated client"),
        "a verb against a directory with no session is refused in the vendor's own words: {}",
        said(&output)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_env_child_pointed_at_an_empty_directory_mints_no_key_at_all() {
    // The counterpart to the case above, and the reason this daemon moved to
    // `env`: the environment provider derives its key from the variable and
    // stores nothing, so no file appears beside the session store for a
    // concurrent child to delete, mint or disagree about.
    let dir = scratch("vendor-store-env-mints-nothing");
    let vendor = store_stub(&dir, &support::VendorStore::INSTANT);
    let scope = vendor_scope(&dir, "scope");

    run_vendor(
        &vendor,
        &scope,
        &Keying::Env(ENCRYPTION_KEY_DECOY),
        &["info"],
    );

    assert!(
        scope.join(".session").is_dir(),
        "`.session` is still created: that half is the provider's business"
    );
    assert!(
        !scope.join(".session").join("local.key").exists(),
        "an `env` child must never write a local key"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_child_that_cannot_create_the_local_key_fails_with_the_vendors_own_sentence() {
    // In production this is a RACE: `create_new(true)` is `O_EXCL`, so two
    // children that both find `local.key` missing both try to create it and the
    // loser fails outright rather than reading what the winner wrote.
    //
    // The case reaches that branch without running a race, through the vendor's
    // own guard: it reads the key only when the path exists AND is a file, so a
    // path that exists and is not one falls through to the same `create_new`,
    // which fails for the same reason with the same sentence. A test built on
    // two concurrent children would prove this only on the runs where they
    // actually collided, and would read as a pass on every run where they did
    // not.
    let dir = scratch("vendor-store-key-race-loser");
    let vendor = store_stub(&dir, &support::VendorStore::INSTANT);
    let scope = vendor_scope(&dir, "scope");
    std::fs::create_dir_all(scope.join(".session").join("local.key"))
        .expect("occupy the key's own path");

    let output = run_vendor(&vendor, &scope, &Keying::Fs, &["info"]);

    assert!(!output.status.success());
    assert!(
        said(&output).contains("Error creating local key file"),
        "the loser of the mint must fail in the vendor's own words: {}",
        said(&output)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_env_child_with_no_key_is_refused_before_it_can_delete_anything() {
    // The fact that settles what a probe naming `env` with no key DOES: the
    // provider's constructor returns an error, the caller propagates it with
    // `?`, and no client is ever built — so no dispatch runs and no cleanup
    // path is reached. A probe like that MISCLASSIFIES; it does not destroy
    // the session.
    //
    // An EMPTY value is refused exactly as hard as a missing one, which is the
    // half a reader assumes rather than checks.
    let dir = scratch("vendor-store-env-no-key");
    let vendor = store_stub(&dir, &support::VendorStore::INSTANT);
    let scope = vendor_scope(&dir, "scope");
    run_vendor(
        &vendor,
        &scope,
        &Keying::Env(ENCRYPTION_KEY_DECOY),
        &["login"],
    );
    let session = scope.join(".session").join("session.json");
    assert!(session.is_file(), "the fixture must start from a session");

    for keying in [Keying::EnvWithoutKey, Keying::EnvWithEmptyKey] {
        let output = run_vendor(&vendor, &scope, &keying, &["run", "--", "true"]);
        assert!(!output.status.success());
        assert_eq!(
            said(&output).trim(),
            "Error: PROTON_PASS_ENCRYPTION_KEY environment variable must be set and non-empty \
             when using env key provider",
            "the refusal is the vendor's own sentence, verbatim"
        );
        assert!(
            session.is_file(),
            "a read refused at provider construction must leave the session store untouched"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_child_handed_no_key_provider_lands_on_neither_the_file_nor_the_environment() {
    // The default when `PROTON_PASS_KEY_PROVIDER` is unset OR EMPTY is
    // `keyring` — a third provider, not `fs`. A daemon's own uid has an empty
    // login keyring, and that provider's answer to "no key beside local data"
    // is to FORCE A LOGOUT, which the `fs` provider has no equivalent of.
    //
    // So a call site that forgot to set the provider does not merely read the
    // wrong key: it destroys the session it was pointed at.
    let dir = scratch("vendor-store-unset-provider");
    let vendor = store_stub(&dir, &support::VendorStore::INSTANT);

    for (tag, keying) in [("unset", Keying::Unset), ("empty", Keying::Empty)] {
        let scope = vendor_scope(&dir, tag);
        run_vendor(&vendor, &scope, &Keying::Fs, &["login"]);
        let base = scope.join(".session");
        assert!(base.join("session.json").is_file(), "{tag}: fixture");

        let output = run_vendor(&vendor, &scope, &keying, &["run", "--", "true"]);

        assert!(!output.status.success(), "{tag}");
        assert!(
            said(&output).contains("Forcing logout for security"),
            "{tag}: the keyring provider's own guard must be what answered: {}",
            said(&output)
        );
        assert!(
            !base.exists(),
            "{tag}: that guard force-logs-out, so the whole store is gone"
        );
        assert!(
            scope.is_dir(),
            "{tag}: the directory the variable names is never what goes"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_session_written_under_one_key_cannot_be_read_under_another_and_logout_cannot_repair_it() {
    // The terminal state this whole effort is about, reached deliberately: a
    // `session.json` on disk under a key no surviving `local.key` holds. The
    // next child mints a fresh key and every verb fails with the same
    // sentence.
    //
    // And the part that makes it terminal rather than transient: the client is
    // built — which means the store is decrypted — BEFORE dispatch, for every
    // command except `logout --force` and `completions`. So the obvious repair,
    // a plain `logout`, fails for the same reason everything else does.
    let dir = scratch("vendor-store-undecryptable");
    let vendor = store_stub(&dir, &support::VendorStore::INSTANT);
    let scope = vendor_scope(&dir, "scope");

    run_vendor(&vendor, &scope, &Keying::Fs, &["login"]);
    let base = scope.join(".session");
    assert!(base.join("session.json").is_file(), "fixture");
    // Exactly what the concurrent-child class leaves behind: the session file
    // survives, the key it was written under does not.
    std::fs::remove_file(base.join("local.key")).expect("take the key away");

    for verb in [
        vec!["run", "--", "true"],
        vec!["info"],
        vec!["item", "list"],
        vec!["logout"],
    ] {
        let output = run_vendor(&vendor, &scope, &Keying::Fs, &verb);
        assert!(!output.status.success(), "{verb:?} must fail");
        assert_eq!(
            said(&output).trim(),
            "Error: Error decrypting local session(Error decrypting session: aead::Error)",
            "{verb:?}: the vendor has one sentence for this and every verb gets it"
        );
    }

    // `logout --force` is the one command that never opens the store, so it is
    // the only thing that clears this by hand.
    let forced = run_vendor(&vendor, &scope, &Keying::Fs, &["logout", "--force"]);
    assert!(
        forced.status.success(),
        "`logout --force` must work where plain `logout` cannot: {}",
        said(&forced)
    );
    assert!(!base.exists(), "the force logout takes the whole store");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_read_whose_session_the_account_revoked_deletes_the_whole_store_on_its_way_out() {
    // The first of the vendor's three paths to `remove_dir_all`, and the one
    // that is hardest to believe from the outside: a plain read — no logout
    // anywhere near it — deletes the session store it was pointed at, and then
    // reports an ordinary error.
    //
    // The other two are asserted beside it, because they fire even EARLIER:
    // before the command runs at all, off the persisted session's own fields.
    // Slice by slice this crate survives all three identically or none of them,
    // so they are one case.
    let dir = scratch("vendor-store-destructive-reads");
    // The callback's cleanup is not the only thing an invalidated read does:
    // the store schedules its own `session.json` write, and with both instant
    // the two race — which is the vendor, and is the subject of the
    // concurrent-child case rather than of this one. Starting the write after
    // the cleanup has finished takes it out of contention, so what this case
    // observes is the cleanup alone.
    let vendor = store_stub(
        &dir,
        &support::VendorStore {
            persist_key_delay: Duration::from_millis(300),
            ..support::VendorStore::INSTANT
        },
    );

    let revoked = vendor_scope(&dir, "revoked");
    run_vendor(&vendor, &revoked, &Keying::Fs, &["login"]);
    support::revoke_vendor_session(&dir, &revoked);
    let output = run_vendor(&vendor, &revoked, &Keying::Fs, &["run", "--", "true"]);
    assert!(!output.status.success());
    assert!(
        said(&output).contains("Your session has been invalidated"),
        "the callback path reports in the vendor's own words: {}",
        said(&output)
    );
    assert!(
        !revoked.join(".session").exists(),
        "a READ deleted nothing — the callback's cleanup is a `remove_dir_all`"
    );
    assert!(
        revoked.is_dir(),
        "the directory the variable names survives"
    );

    for (tag, state) in [
        ("unauthenticated", support::VendorSession::NotAuthenticated),
        ("extra-password", support::VendorSession::NeedsExtraPassword),
    ] {
        let scope = vendor_scope(&dir, tag);
        run_vendor(&vendor, &scope, &Keying::Fs, &["login"]);
        support::degrade_vendor_session(&scope, &state);

        let output = run_vendor(&vendor, &scope, &Keying::Fs, &["run", "--", "true"]);

        assert!(!output.status.success(), "{tag}");
        assert!(
            said(&output).contains("This operation requires an authenticated client"),
            "{tag}: {}",
            said(&output)
        );
        assert!(
            !scope.join(".session").exists(),
            "{tag}: the dispatch deletes the store before the command runs"
        );
        assert!(scope.is_dir(), "{tag}: the named directory survives");
    }

    // Which branch each call took, read off the stand-in's own trace rather
    // than inferred from an exit status all three share.
    let outcomes: Vec<String> = support::vendor_store_trace(&dir)
        .iter()
        .filter_map(|line| line.split_whitespace().last().map(str::to_owned))
        .collect();
    for expected in [
        "revoked-cleanup",
        "not-authenticated",
        "needs-extra-password",
    ] {
        assert!(
            outcomes.iter().any(|outcome| outcome == expected),
            "no call took the `{expected}` path; the trace holds {outcomes:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_logout_under_fs_takes_the_key_with_it_and_one_under_env_has_no_key_to_take() {
    // `logout` calls `remove_key()` unconditionally, BEFORE it deletes the
    // directory. Under `fs` that unlinks a file a concurrent reader's session
    // still needs; under `env` the vendor documents it as a no-op, because the
    // key only ever lived in process memory.
    //
    // That difference is the whole of why this daemon moved to `env`, so it is
    // worth a case that would notice the vendor giving `env` a key file.
    let dir = scratch("vendor-store-logout-keys");
    let vendor = store_stub(&dir, &support::VendorStore::INSTANT);

    let on_fs = vendor_scope(&dir, "fs");
    run_vendor(&vendor, &on_fs, &Keying::Fs, &["login"]);
    assert!(
        on_fs.join(".session").join("local.key").is_file(),
        "an `fs` login leaves a key file behind"
    );
    let out = run_vendor(&vendor, &on_fs, &Keying::Fs, &["logout"]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(!on_fs.join(".session").exists(), "the store goes too");

    let on_env = vendor_scope(&dir, "env");
    run_vendor(
        &vendor,
        &on_env,
        &Keying::Env(ENCRYPTION_KEY_DECOY),
        &["login"],
    );
    assert!(
        !on_env.join(".session").join("local.key").exists(),
        "an `env` login writes no key file, so a logout has none to unlink"
    );
    let out = run_vendor(
        &vendor,
        &on_env,
        &Keying::Env(ENCRYPTION_KEY_DECOY),
        &["logout"],
    );
    assert!(out.status.success(), "{}", said(&out));
    assert!(!on_env.join(".session").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_stand_ins_info_answers_while_a_read_against_the_same_session_fails() {
    // `info` is answered by the stand-in itself rather than handed to the
    // fixture underneath it, and that separation is load-bearing: this crate
    // classifies a failing read by asking `info` about the same session, so a
    // stand-in whose `info` shared the read's fate could not tell a verdict
    // about a NAME from a fault in the SESSION, and every case built on that
    // distinction would pass for the wrong reason.
    let dir = scratch("vendor-store-info-independent");
    // A listing holding no item at all, so a read for the declared name fails
    // as a verdict about the name while the session behind it is sound.
    let inner = stub_pass_cli_listing(&dir, &Backend::Injects(PROTON_DECOY), &Listing::EMPTY);
    let vendor = support::stub_pass_cli_store(&dir, &inner, &support::VendorStore::INSTANT);
    let scope = vendor_scope(&dir, "scope");
    run_vendor(&vendor, &scope, &Keying::Fs, &["login"]);

    let listed = run_vendor(
        &vendor,
        &scope,
        &Keying::Fs,
        &["item", "list", "--vault-name", VAULT, "--output", "json"],
    );
    assert_eq!(
        String::from_utf8_lossy(&listed.stdout).trim(),
        r#"{"items":[]}"#,
        "the read reached the fixture underneath and found nothing"
    );

    let info = run_vendor(&vendor, &scope, &Keying::Fs, &["info"]);
    assert!(
        info.status.success(),
        "`info` must answer from the session's own state: {}",
        said(&info)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The daemon, against a vendor that behaves the way the real one does.
// ---------------------------------------------------------------------------

/// Wait until `<root>/current` names something other than `held`, and hand back
/// what it names instead.
fn until_current_moves_past(root: &Path, held: &str, patience: Duration) -> String {
    let deadline = Instant::now() + patience;
    loop {
        if let Some(name) = current_generation(root)
            && name != held
        {
            return name;
        }
        assert!(
            Instant::now() < deadline,
            "`current` still names {held} after {patience:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for the renewal loop's first generation and hand back its name.
fn until_a_generation_is_published(root: &Path, patience: Duration) -> String {
    let deadline = Instant::now() + patience;
    loop {
        if let Some(name) = current_generation(root) {
            return name;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was published within {patience:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn a_generation_the_vendor_destroys_on_a_read_costs_one_degraded_answer_and_is_replaced() {
    // CONTROL — the change that makes this fail: have the renewal loop repair
    // the CURRENT generation in place rather than establishing a new one. The
    // vendor has three ways to delete the directory it is pointed at, two of
    // them decided before the command runs, and a repair in place hands the
    // replacement session back to the same directory a concurrent child may be
    // deleting.
    //
    // The three paths are one case rather than three, because the design
    // survives all of them or none: what the daemon does about a destroyed
    // generation cannot depend on which branch inside the vendor destroyed it.
    let dir = scratch("daemon-proton-vendor-destroys-generation");
    // `key_provider: env`, which is what this daemon ships — the deletions
    // below are the vendor's dispatch and its invalidation callback, and
    // neither reads the key provider at all.
    let vendor = store_stub(&dir, &support::VendorStore::INSTANT);
    let config = daemon_config_with_generations_loop_env(&dir, &vendor, 90, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());
    let root = session_dir(&dir);

    let mut current = until_a_generation_is_published(&root, Duration::from_secs(30));
    let client = client_config(running.socket(), 60_000);
    let registry = store::build(&client, &Invocation::default()).registry;
    match registry.resolve(DECLARED) {
        Resolution::Found { .. } => {}
        other => panic!("the fixture never resolved at all: {}", other.reason()),
    }

    for path in ["revoked", "unauthenticated", "extra-password"] {
        let generation = root.join(&current);
        match path {
            "revoked" => support::revoke_vendor_session(&dir, &generation),
            "unauthenticated" => {
                support::degrade_vendor_session(
                    &generation,
                    &support::VendorSession::NotAuthenticated,
                );
            }
            _ => support::degrade_vendor_session(
                &generation,
                &support::VendorSession::NeedsExtraPassword,
            ),
        }

        // The read that meets the vendor in that state. It degrades — and on
        // its way to degrading, the vendor deletes the store it was scoped at.
        let degraded = registry.resolve(DECLARED);
        assert!(
            !matches!(degraded, Resolution::Found { .. }),
            "{path}: the vendor refuses this read, so it cannot have resolved"
        );
        assert!(
            !generation.join(".session").join("session.json").exists(),
            "{path}: the vendor deletes the session store on its way out, and this case is \
             about what the daemon does afterwards — if the file is still there the fixture \
             did not reproduce the hazard"
        );

        // The loop's answer: a generation of its own, never a repair of the
        // one the vendor just emptied.
        current = until_current_moves_past(&root, &current, Duration::from_secs(60));
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if matches!(registry.resolve(DECLARED), Resolution::Found { .. }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{path}: reads never came back after the generation was replaced"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    // Three destroyed generations, three replacements — read off the vendor's
    // own trace rather than from the daemon's account of itself.
    let outcomes: Vec<String> = support::vendor_store_trace(&dir)
        .iter()
        .filter_map(|line| line.split_whitespace().last().map(str::to_owned))
        .collect();
    for expected in [
        "revoked-cleanup",
        "not-authenticated",
        "needs-extra-password",
    ] {
        assert!(
            outcomes.iter().any(|outcome| outcome == expected),
            "the vendor never took the `{expected}` path, so this case proved nothing about \
             it: the trace holds {outcomes:?}"
        );
    }

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

/// How long the concurrent-child case keeps reading while the loop renews.
///
/// Not a deadline on anything: it is how long the hazard is OFFERED. The loop
/// renews on its own interval, and every renewal opens one window in which a
/// reader becomes a deleter, so this is several windows rather than one.
const HAZARD_WINDOW: Duration = Duration::from_secs(35);

#[test]
fn no_read_meets_a_session_store_a_renewal_left_undecryptable() {
    // The case this whole effort exists for, driven by the vendor's own
    // behaviour rather than by a description of it.
    //
    // The vendor's `logout` revokes the session at the account and only then
    // deletes locally, so for the width of that window every other child
    // holding the session is refused — and a refused child runs the
    // invalidation cleanup AND schedules a `session.json` write whose key it
    // resolves at one instant and whose rename lands at a later one. A
    // renewal that logs out the directory readers are using therefore leaves,
    // deterministically, a session file under a key no surviving `local.key`
    // holds. The next child mints a fresh key, cannot decrypt what is there,
    // and every read after that fails the same way: the state is terminal, not
    // transient.
    //
    // The windows below are set so that ordering is arithmetic:
    //
    //   the revoke, then 300 ms before anything local is deleted
    //   a reader landing inside that window resolves the key AT ONCE
    //   its rename lands 600 ms later — after the deletions, before the rmdir
    //   each rmdir is 2 s behind its own listing, so the rename beats both
    //
    // Against a renewal that replaces the directory in place this goes red on
    // the first window it is offered. Against a renewal that establishes each
    // session in a generation of its own it cannot go red at all, because no
    // logout is ever pointed at a directory a reader is holding.
    let dir = scratch("daemon-proton-concurrent-children");
    let vendor = store_stub(
        &dir,
        &support::VendorStore {
            logout_delay: Duration::from_millis(300),
            rmdir_window: Duration::from_secs(2),
            persist_key_delay: Duration::ZERO,
            persist_write_delay: Duration::from_millis(600),
            login_delay: Duration::ZERO,
        },
    );
    // `key_provider: fs`, because the key that gets minted, deleted and
    // disagreed about is a FILE under that provider and does not exist at all
    // under the other. `login_after_minutes: 0` makes every tick due, so the
    // window is offered on the loop's own interval rather than once.
    let config = daemon_config_with_generations_loop(&dir, &vendor, 0, 1, 60_000);
    let running = start_daemon(&config, policy_allowing_self());
    let root = session_dir(&dir);
    until_a_generation_is_published(&root, Duration::from_secs(30));

    // Two readers, because one is not concurrency. They read flat out for the
    // whole window and keep every reason they were given.
    let stop = Instant::now() + HAZARD_WINDOW;
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let socket = running.socket().to_path_buf();
            std::thread::spawn(move || {
                let mut reasons: Vec<String> = Vec::new();
                let mut answered = 0_usize;
                while Instant::now() < stop {
                    let client = Client::new(socket.clone(), Duration::from_secs(30));
                    match client.request(&Request::resolve(DECLARED)) {
                        Ok(Reply::Value(_)) => answered += 1,
                        Ok(Reply::Failed(reason)) => reasons.push(reason),
                        Ok(other) => reasons.push(format!("{other:?}")),
                        Err(error) => reasons.push(error.to_string()),
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                (answered, reasons)
            })
        })
        .collect();

    let mut answered = 0_usize;
    let mut reasons: Vec<String> = Vec::new();
    for reader in readers {
        let (ok, said) = reader.join().expect("a reader thread panicked");
        answered += ok;
        reasons.extend(said);
    }

    let trace = support::vendor_store_trace(&dir);
    let outcome = |name: &str| {
        trace
            .iter()
            .filter(|line| line.split_whitespace().last() == Some(name))
            .count()
    };

    // The two halves of the fingerprint, in the order the incident produced
    // them: a `remove_dir_all` that lost its own directory, and then a session
    // store nothing can decrypt.
    assert_eq!(
        outcome("logout-enotempty"),
        0,
        "a renewal's `remove_dir_all` raced an entry that appeared after its listing — the \
         `Directory not empty` half of the incident. The vendor's trace: {trace:?}"
    );
    assert_eq!(
        outcome("undecryptable"),
        0,
        "a child met a session store under a key no surviving local key holds — the \
         terminal half. The vendor's trace: {trace:?}"
    );
    let aead: Vec<&String> = reasons
        .iter()
        .filter(|reason| reason.contains("aead::Error"))
        .collect();
    assert!(
        aead.is_empty(),
        "a caller was handed the vendor's undecryptable-session sentence: {aead:?}"
    );

    // Two controls, because every assertion above is satisfied by a run in
    // which nothing happened: the hazard has to have been OFFERED.
    assert!(
        outcome("logged-in") >= 2,
        "the renewal loop logged in {} time(s), so the window this case is about was never \
         opened more than once",
        outcome("logged-in")
    );
    assert!(
        answered > 0,
        "no read ever succeeded, so this run says nothing about what readers met"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
