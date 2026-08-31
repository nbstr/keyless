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
//! # Why most of this reads text, and one part does not
//!
//! The scripts create users, load launchd jobs and write under `/usr/local`.
//! There is no scratch prefix that makes those reversible, and a test suite
//! that runs them is a test suite that changes the machine it is checked on. So
//! for those, what is asserted is the TEXT of the command each script will run,
//! which is exactly what the dry run prints and exactly what `--commit`
//! executes — the two are the same list by construction of `step`.
//!
//! Text is not enough for one question, and it is the question that decides
//! whether an operator loses data. `install -m 0600 /dev/null <dest>` reads as
//! "create the file" and is a copy, which over an existing file truncates it;
//! `printf ... > <dest>` reads as "write the config" and over an existing
//! config deletes the blocks somebody hand-added. Both are indistinguishable
//! from their safe forms by reading. Those two blocks are therefore LIFTED OUT
//! OF THE SCRIPT VERBATIM and executed against a scratch directory, with `step`
//! and `chown` stubbed and nothing else changed — see [`block`].

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

/// The paths the daemon will actually open, read from the config's own
/// defaults — one per vendor it carries a login for.
///
/// Both, rather than one: a second vendor's file added to the config and to
/// neither script is exactly the drift the module header describes, arriving
/// through a file this test used to know nothing about.
fn credential_paths() -> Vec<String> {
    let config: DaemonConfig = serde_json::from_str("{}").expect("an empty config is a valid one");
    vec![
        config
            .stores
            .infisical
            .credentials_file
            .to_path_buf()
            .display()
            .to_string(),
        config
            .stores
            .onepassword
            .credentials_file
            .to_path_buf()
            .display()
            .to_string(),
    ]
}

#[test]
fn the_installer_creates_the_files_the_daemon_will_open_and_shuts_them_to_everyone_else() {
    let script = installer();
    for path in credential_paths() {
        // The whole command, not the path alone: `0600` and the daemon's
        // ownership are the boundary this credential has, and a line that
        // created the right path at the wrong mode would satisfy a path-only
        // assertion. The mode travels with the call rather than with the
        // `install` line, because the call is what a reader has to check; that
        // the helper honours it is asserted by executing the helper, below.
        let expected = format!(r#"place_state_file 0600 "$LIB_DIR/{}""#, file_name(&path));
        assert!(
            script.contains(&expected),
            "install/install.sh does not create the daemon's credential file at {path} \
             with mode 0600 owned by the daemon. Expected this line:
  {expected}"
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
}

#[test]
fn the_uninstaller_removes_them() {
    // The asymmetry with the secrets store beside it is deliberate and is
    // argued in the script: the store may be somebody's only copy, these files
    // never are, and a long-lived credential left on a machine with no daemon
    // to use it is a landmine with no upside.
    let script = uninstaller();
    for path in credential_paths() {
        let expected = format!(r#"step rm -f "$LIB_DIR/{}""#, file_name(&path));
        assert!(
            script.contains(&expected),
            "install/uninstall.sh does not remove the daemon's credential file at {path}. \
             Expected this line:\n  {expected}"
        );
        // And the directory the script's own variable stands for is the one
        // the config names, or the line above deletes a path that agrees with
        // nothing.
        assert!(
            script.contains(&format!(
                r#"LIB_DIR="{}""#,
                path.rsplit_once('/').expect("an absolute path").0
            )),
            "install/uninstall.sh's LIB_DIR is not the directory {path} is in"
        );
    }
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
            "OP_SERVICE_ACCOUNT_TOKEN=",
            "OP_CONNECT_TOKEN=",
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

// ---------------------------------------------------------------------------
// The half that cannot be read off the text: what the commands actually DO
// ---------------------------------------------------------------------------
//
// `install -m 0600 /dev/null <dest>` reads as "create the file". It is a COPY,
// and a copy over an existing file truncates it — silently, exit 0. No
// assertion over the script's text can tell those two apart, because the text
// is identical either way. So the two pieces of the installer that decide
// whether an operator's data survives a second run are LIFTED OUT AND RUN, in
// a scratch directory, with `step` and `chown` stubbed and nothing else
// changed. What executes is the script's own bytes.
//
// This is not the whole commit path and cannot be: the rest of it creates a
// user, edits a group and loads a launchd job, none of which has a scratch
// form. What is covered is exactly the part that can destroy something.

/// One block of the installer, lifted out verbatim so it can be executed.
///
/// `opens` is matched against the whole line, and everything up to and
/// including the first line equal to `closes` comes with it. Both markers are
/// at column zero in the script, which is what makes the match unambiguous
/// while the block's own nested `fi`s and `}`s are indented.
fn block(script: &str, opens: &str, closes: &str) -> String {
    let mut lines = script.lines().skip_while(|line| *line != opens).peekable();
    assert!(
        lines.peek().is_some(),
        "install/install.sh no longer has a line reading `{opens}`, so the test below is \
         executing nothing. Re-point it rather than deleting it."
    );
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push('\n');
        if line == closes {
            return out;
        }
    }
    panic!("the block opened by `{opens}` is never closed by a line reading `{closes}`");
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyless-install-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// Run a shell program and return its stdout, insisting it exited 0.
fn bash(program: &str) -> String {
    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(program)
        .output()
        .expect("bash");
    assert!(
        out.status.success(),
        "the lifted block failed: {}\n--- program ---\n{program}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
}

/// The preamble every lifted block needs: `step` runs the command it is given,
/// which is what `--commit` does, and the daemon's account is this one so the
/// ownership calls are real rather than skipped.
fn preamble(dir: &std::path::Path) -> String {
    format!(
        "set -euo pipefail\n\
         DAEMON_USER=\"$(id -un)\"\n\
         ACCESS_GROUP=\"$(id -gn)\"\n\
         COMMIT=1\n\
         CONF_DIR={dir:?}\n\
         step() {{ \"$@\"; }}\n\
         chown() {{ command chown \"$@\" || true; }}\n"
    )
}

#[test]
fn a_second_install_does_not_empty_the_files_the_first_one_left_behind() {
    // The measured defect: 23 bytes in, 0 bytes out, exit 0, nothing printed.
    // Every path here holds something that has no other copy — the migrated
    // store, the append-only record, and a credential whose only other home is
    // the vendor.
    let dir = scratch("survive");
    let helper = block(&installer(), "place_state_file() {", "}");

    let placed = [
        (
            "secrets.json",
            0o600,
            r#"{"DECOY":"decoy-survives-a-rerun-0031"}"#,
        ),
        ("audit.jsonl", 0o640, "{\"row\":1}\n{\"row\":2}\n"),
        (
            "infisical.json",
            0o600,
            r#"{"MACHINE_IDENTITY":"decoy-identity-0031"}"#,
        ),
        (
            "onepassword.json",
            0o600,
            r#"{"SERVICE_ACCOUNT":"decoy-service-account-0031"}"#,
        ),
    ];
    for (name, _, body) in placed {
        std::fs::write(dir.join(name), body).expect("seed");
    }
    // Widened on purpose. A re-run must repair the boundary while leaving the
    // contents alone; those are two different operations and only one of them
    // is destructive.
    std::fs::set_permissions(
        dir.join("secrets.json"),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o644),
    )
    .expect("widen");

    bash(&format!(
        "{}{helper}\n\
         place_state_file 0600 {dir:?}/secrets.json\n\
         place_state_file 0640 {dir:?}/audit.jsonl\n\
         place_state_file 0600 {dir:?}/infisical.json\n\
         place_state_file 0600 {dir:?}/onepassword.json\n",
        preamble(&dir)
    ));

    for (name, mode, body) in placed {
        let path = dir.join(name);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            body,
            "the installer emptied {name} on a second run"
        );
        assert_eq!(
            mode_of(&path),
            mode,
            "{name} is not shut back to {mode:04o}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_first_install_still_creates_each_file_empty_and_shut() {
    // The other half, and the reason the fix is not simply "never touch it":
    // on a machine with nothing there, these files still have to appear, at the
    // mode that is the whole boundary.
    let dir = scratch("create");
    let helper = block(&installer(), "place_state_file() {", "}");

    bash(&format!(
        "{}{helper}\n\
         place_state_file 0600 {dir:?}/secrets.json\n\
         place_state_file 0640 {dir:?}/audit.jsonl\n\
         place_state_file 0600 {dir:?}/onepassword.json\n",
        preamble(&dir)
    ));

    for (name, mode) in [
        ("secrets.json", 0o600),
        ("audit.jsonl", 0o640),
        ("onepassword.json", 0o600),
    ] {
        let path = dir.join(name);
        assert_eq!(std::fs::read(&path).expect("read").len(), 0, "{name}");
        assert_eq!(mode_of(&path), mode, "{name}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_existing_config_is_left_alone_and_the_new_pin_is_printed_instead() {
    // The template this script renders has no `infisical` block and no
    // `secrets` block, and the script's own closing instructions are what tell
    // an operator to add them. Writing the template over a config that has them
    // deletes the Infisical store entirely, and the daemon that comes back up
    // reports no fault at all.
    let dir = scratch("config");
    let conf = dir.join("keylessd.json");
    let kept = r#"{"stores":{"infisical":{"enabled":true}},"peer":{"allow_images":["aa11"]}}"#;
    std::fs::write(&conf, kept).expect("seed");

    let region = block(&installer(), r#"CONF_FILE="$CONF_DIR/keylessd.json""#, "fi");
    let program = format!(
        "{}CLIENT_HASH=bb22\nCONFIG_JSON='{{\"template\":true}}'\n{region}",
        preamble(&dir)
    );
    let said = bash(&program);

    assert_eq!(
        std::fs::read_to_string(&conf).expect("read"),
        kept,
        "the installer overwrote a config it did not write"
    );
    assert!(
        said.contains("ACTION REQUIRED") && said.contains("bb22"),
        "a config that does not pin the client just installed was left stale in \
         silence: {said}"
    );

    // And when the existing config already pins that client there is nothing to
    // do, which must not read the same as the case above.
    std::fs::write(&conf, r#"{"peer":{"allow_images":["bb22"]}}"#).expect("seed");
    let said = bash(&program);
    assert!(!said.contains("ACTION REQUIRED"), "{said}");

    // With nothing there, the template is still written. Without this the
    // assertions above are satisfied by a script that writes no config ever.
    std::fs::remove_file(&conf).expect("remove");
    bash(&program);
    assert_eq!(
        std::fs::read_to_string(&conf).expect("read").trim(),
        r#"{"template":true}"#
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The last component of a path, for building the uninstaller's own spelling.
fn file_name(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, name)| name)
}
