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

mod daemon_proton_support;
mod support;

use keyless::store::{self, Invocation, Resolution};

use daemon_proton_support::{
    DECLARED, HALF_WRITTEN, LISTING, daemon_config_with_proton, published_generation,
    stub_recording_key_provider, vendor_argv, vendor_key_provider, vendor_list_argv,
    vendor_reference,
};
use support::backend::Backend;
use support::client::client_config;
use support::daemon::{policy_allowing_self, start_daemon};
use support::proton::Listing;
use support::{PROTON_DECOY, scratch};

/// A name that appears in no config anywhere. The hazard, by name.
const INVENTED: &str = "A_NAME_NOBODY_EVER_DECLARED";

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
// A name nobody declared: no value read, and no vault the name chose.
// ---------------------------------------------------------------------------

#[test]
fn an_undeclared_name_reads_no_value_and_lists_no_vault_of_its_own() {
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
        !vendor_reference(&dir).exists(),
        "an undeclared name spawned `run`: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(
        !vendor_list_argv(&dir).exists(),
        "an undeclared name listed a real vault: {:?}",
        support::recorded_lines(&vendor_list_argv(&dir))
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
        !vendor_reference(&dir).exists(),
        "a client-supplied address resolved: {:?}",
        support::recorded_lines(&vendor_argv(&dir))
    );
    assert!(!reason.contains(PROTON_DECOY), "{reason}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
