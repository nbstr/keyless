#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod daemon_proton_support;
mod support;

use std::time::Duration;

use daemon_proton_support::vendor_store::{Keying, run_vendor, said, store_stub, vendor_scope};
use daemon_proton_support::{ENCRYPTION_KEY_DECOY, VAULT};
use support::backend::Backend;
use support::proton::{Listing, stub_pass_cli_listing};
use support::{PROTON_DECOY, scratch};

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
    let vendor = store_stub(&dir, &support::proton_session::VendorStore::INSTANT);
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
        &support::proton_session::VendorStore {
            persist_key_delay: Duration::from_millis(300),
            ..support::proton_session::VendorStore::INSTANT
        },
    );

    let revoked = vendor_scope(&dir, "revoked");
    run_vendor(&vendor, &revoked, &Keying::Fs, &["login"]);
    support::proton_session::revoke_vendor_session(&dir, &revoked);
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
        (
            "unauthenticated",
            support::proton_session::VendorSession::NotAuthenticated,
        ),
        (
            "extra-password",
            support::proton_session::VendorSession::NeedsExtraPassword,
        ),
    ] {
        let scope = vendor_scope(&dir, tag);
        run_vendor(&vendor, &scope, &Keying::Fs, &["login"]);
        support::proton_session::degrade_vendor_session(&scope, &state);

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
    let outcomes: Vec<String> = support::proton_session::vendor_store_trace(&dir)
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
    let vendor = store_stub(&dir, &support::proton_session::VendorStore::INSTANT);

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
    let vendor = support::proton_store::stub_pass_cli_store(
        &dir,
        &inner,
        &support::proton_session::VendorStore::INSTANT,
    );
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
