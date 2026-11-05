#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::path::Path;

use daemon_proton_support::ENCRYPTION_KEY_DECOY;
use daemon_proton_support::vendor_store::{Keying, run_vendor, said, store_stub, vendor_scope};
use support::scratch;

// ---------------------------------------------------------------------------
// The vendor's own store semantics, pinned.
//
// Everything above this line is a claim about the DAEMON. The cases below are
// claims about `pass-cli` — read out of its source at the version installed on
// this machine and written down so a release that changes one of them arrives
// as a red test rather than as an undecryptable session store.
//
// They drive `support::proton_store::stub_pass_cli_store` directly, with no daemon anywhere:
// the stand-in is the subject, and a case that reached it through the daemon
// could not say whether a wrong answer came from the model or from the adapter.
// `support::proton_store::stub_pass_cli_store`'s own doc carries the source citation for each
// behaviour, and the sentences asserted here are quoted from the vendor.
// ---------------------------------------------------------------------------

/// The permission bits on `path`, as the three octal digits a person writes.
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("cannot stat {}: {error}", path.display()))
        .permissions()
        .mode()
        & 0o777
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
    let vendor = store_stub(&dir, &support::proton_session::VendorStore::INSTANT);
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
    let vendor = store_stub(&dir, &support::proton_session::VendorStore::INSTANT);
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
    let vendor = store_stub(&dir, &support::proton_session::VendorStore::INSTANT);
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
    let vendor = store_stub(&dir, &support::proton_session::VendorStore::INSTANT);
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
    let vendor = store_stub(&dir, &support::proton_session::VendorStore::INSTANT);

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
