//! What the installer places, what the uninstaller takes away, and the one
//! file neither of them may ever put a credential in.
//!
//! # Why a test reads shell scripts
//!
//! Three things name the daemon's credential file: a default in
//! [`keyless::daemon::config`], a line in `install/install.sh` that creates it,
//! and a line in `install/uninstall.sh` that removes it. Nothing makes them
//! agree. A rename in the Rust default leaves the installer creating a file the
//! daemon never opens and the uninstaller deleting a file nobody wrote — and
//! every one of those states compiles, installs and reports success.
//!
//! The failure is worse in one direction than the other. An installer that
//! creates the wrong path produces a daemon that degrades, which is loud. An
//! uninstaller that deletes the wrong path leaves a long-lived machine identity
//! on a machine that no longer has a daemon to use it, and nothing anywhere
//! says so. That is the case this file exists for.
//!
//! # Why the scripts are not executed
//!
//! They create users, load launchd jobs and write under `/usr/local`. There is
//! no scratch prefix that makes those reversible, and a test suite that runs
//! them is a test suite that changes the machine it is checked on. So what is
//! asserted is the TEXT of the command each script will run, which is exactly
//! what the dry run prints and exactly what `--commit` executes — the two are
//! the same list by construction of `step`.

// `DaemonConfig` is macOS-only, like the daemon it configures. Off macOS this
// file compiles to nothing and reports no tests — absent rather than ignored,
// which leaves the suite's exact ignored count alone.
#![cfg(any(target_os = "macos", keyless_force_xnu))]

use keyless::daemon::config::DaemonConfig;

/// The installer, as text.
fn installer() -> String {
    read("install/install.sh")
}

/// The uninstaller, as text.
fn uninstaller() -> String {
    read("install/uninstall.sh")
}

/// The launchd job, as text.
fn plist() -> String {
    read("install/sh.keyless.keylessd.plist")
}

fn read(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// The path the daemon will actually open, read from the config's own default.
fn credential_path() -> String {
    let config: DaemonConfig = serde_json::from_str("{}").expect("an empty config is a valid one");
    config
        .stores
        .infisical
        .credentials_file
        .to_path_buf()
        .display()
        .to_string()
}

#[test]
fn the_installer_creates_the_file_the_daemon_will_open_and_shuts_it_to_everyone_else() {
    let path = credential_path();
    let script = installer();

    // The whole command, not the path alone: `0600` and the daemon's ownership
    // are the boundary this credential has, and a line that created the right
    // path at the wrong mode would satisfy a path-only assertion.
    let expected = format!(
        r#"step install -m 0600 -o "$DAEMON_USER" -g "$ACCESS_GROUP" /dev/null "$LIB_DIR/{}""#,
        file_name(&path)
    );
    assert!(
        script.contains(&expected),
        "install/install.sh does not create the daemon's credential file at {path} \
         with mode 0600 owned by the daemon. Expected this line:\n  {expected}"
    );
    // And its own `LIB_DIR` is the directory the config names, or the line
    // above creates a path that agrees with nothing.
    assert!(
        script.contains(&format!(
            r#"LIB_DIR="{}""#,
            path.rsplit_once('/').expect("an absolute path").0
        )),
        "install/install.sh's LIB_DIR is not the directory {path} is in"
    );
}

#[test]
fn the_uninstaller_removes_it() {
    // The asymmetry with the secrets store beside it is deliberate and is
    // argued in the script: the store may be somebody's only copy, this file
    // never is, and a long-lived credential left on a machine with no daemon
    // to use it is a landmine with no upside.
    let path = credential_path();
    let script = uninstaller();
    let expected = format!(r#"step rm -f "$LIB_DIR/{}""#, file_name(&path));
    assert!(
        script.contains(&expected),
        "install/uninstall.sh does not remove the daemon's credential file at {path}. \
         Expected this line:\n  {expected}"
    );
    // And the directory the script's own variable stands for is the one the
    // config names, or the line above deletes a path that agrees with nothing.
    assert!(
        script.contains(&format!(
            r#"LIB_DIR="{}""#,
            path.rsplit_once('/').expect("an absolute path").0
        )),
        "install/uninstall.sh's LIB_DIR is not the directory {path} is in"
    );
}

#[test]
fn the_uninstaller_says_that_deleting_the_file_is_not_revoking_the_credential() {
    // The half no script can do. Without this sentence the uninstaller reads as
    // a complete removal, and a machine identity that is still valid at the
    // vendor is exactly the thing somebody would then forget about.
    let script = uninstaller();
    assert!(
        script.to_uppercase().contains("REVOKE"),
        "install/uninstall.sh removes the credential file without telling anybody to \
         revoke the identity it held"
    );
}

#[test]
fn the_launchd_job_carries_no_environment_at_all() {
    // The plist is installed 0644 root:wheel — world-readable. An
    // `EnvironmentVariables` entry holding a token would put the credential
    // that unlocks the whole vault in a file every user on the machine can
    // read: this project's own hole, re-opened by its own installer.
    //
    // The whole key is refused rather than its contents inspected. A test that
    // allowed the key and checked the values inside it would pass on the day
    // somebody adds one more.
    let plist = plist();
    assert!(
        !plist.contains("EnvironmentVariables"),
        "the launchd job declares EnvironmentVariables, and it is installed world-readable"
    );

    // The control: the scanner has to be reading the file it thinks it is.
    // Without this, a renamed plist makes every assertion above vacuously true.
    assert!(
        plist.contains("<key>UserName</key>"),
        "the plist being read is not the daemon's launchd job"
    );

    // And the installer must still be installing it at that mode, because the
    // paragraph above is only a hazard while the file is world-readable — and
    // only worth this test while it stays one.
    assert!(
        installer().contains(r#"step install -m 0644 -o root -g wheel "$HERE/"#),
        "the plist is no longer installed 0644 root:wheel; the reasoning above needs \
         re-checking rather than this assertion relaxing"
    );
}

#[test]
fn neither_script_can_carry_a_credential_of_its_own() {
    // The structural half of the rule: there is no assignment in either script
    // whose value is a login. Both name entry names and paths, and the value
    // arrives through `keylessd credential` from stdin — so a credential is in
    // no shell history, no process table and no file an operator opens.
    for (name, script) in [("install.sh", installer()), ("uninstall.sh", uninstaller())] {
        for forbidden in [
            "INFISICAL_TOKEN=",
            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET=",
            "--client-secret",
            "--token=",
        ] {
            assert!(
                !script.contains(forbidden),
                "install/{name} spells `{forbidden}`, which is a value reaching a command \
                 line or an environment assignment in a script somebody reads"
            );
        }
    }
}

/// The last component of a path, for building the uninstaller's own spelling.
fn file_name(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, name)| name)
}
