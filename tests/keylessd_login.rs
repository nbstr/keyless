//! `keylessd login --store proton`, driven as a binary against a stand-in vendor.
//!
//! # What only a driven test can see here
//!
//! The unit tests in `src/daemon/login.rs` read a built `Command` and the
//! vendor's own sentences. Neither can see the two properties this verb exists
//! to hold, because both are about what actually reached a spawned process and
//! what is on disk afterwards:
//!
//! - **The token is in the child's environment and nowhere in its argument
//!   vector.** The stand-in vendor writes down its own `"$@"`, so the assertion
//!   reads what the child received rather than what this crate believes it
//!   sent. `ps` is world-readable, and an argument is in it for as long as the
//!   process lives.
//! - **A second run does not destroy a working session.** The vendor refuses to
//!   replace an identity it already holds, and the whole value of that refusal
//!   is what this verb does NEXT: nothing to the directory, nothing to the
//!   credential file, and a message naming the flag that would.
//!
//! # Nothing here touches a real account
//!
//! `pass-cli` is a stand-in shell script written per case. No case runs the
//! real binary, names a real session directory, or holds a real token: every
//! token in this file is a decoy shaped like the vendor's format.

// Like the daemon it drives: off macOS this file compiles to nothing and
// reports no tests, which leaves the suite's exact ignored count alone.
#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use support::{current_generation, install_executable, publish_generation};

/// A decoy shaped the way a real agent token is: `pst_<token>::<key>`, with a
/// base64url key. Invented, and distinctive enough that finding it in an
/// argument vector means the leak this verb exists to close.
const TOKEN_DECOY: &str = "pst_decoy0Verb0never0real0Aa1::ZGVjb3ktdmVyYi0wOTAz";

/// A second decoy, for the case that must prove a value was NOT written.
const OTHER_DECOY: &str = "pst_decoy0Prior0never0real0Bb2::ZGVjb3ktcHJpb3ItMDkwMw==";

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyless-login-verb-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// How the stand-in vendor answers `login`.
enum Vendor {
    /// The session is created. The vendor's own success line, 2.3.2.
    Accepts,
    /// One is already there. The vendor's own refusal, 2.3.2.
    AlreadyAuthenticated,
    /// The account will not take the token. The vendor's own sentence, 2.3.2.
    Refuses,
}

impl Vendor {
    fn body(&self) -> &'static str {
        match self {
            Vendor::Accepts => {
                "echo 'Personal access token session created successfully'\nexit 0\n"
            }
            Vendor::AlreadyAuthenticated => {
                "echo 'Client is already authenticated. Log out if you want to log in again' >&2\n\
                 exit 1\n"
            }
            Vendor::Refuses => {
                "echo 'This personal access token is invalid, expired or has been deleted.' >&2\n\
                 exit 1\n"
            }
        }
    }
}

/// Write a stand-in `pass-cli` that records what it was handed.
///
/// `<dir>/pass-cli.argv` holds its argument vector, one per line;
/// `<dir>/pass-cli.env` holds the three variables that decide whether this
/// login is the right one — read from the ENVIRONMENT it was given, which is
/// the only place a token may be.
///
/// The argv log is written by every verb including `logout`, so a case can tell
/// a login that ran from one that never did by whether the file exists at all.
fn stub_vendor(dir: &Path, behaviour: &Vendor) -> PathBuf {
    let argv = dir.join("pass-cli.argv");
    let environment = dir.join("pass-cli.env");
    let body = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" >> '{argv}'\n\
         {{\n\
         \x20 printf 'PROTON_PASS_SESSION_DIR=%s\\n' \"${{PROTON_PASS_SESSION_DIR-<unset>}}\"\n\
         \x20 printf 'PROTON_PASS_KEY_PROVIDER=%s\\n' \"${{PROTON_PASS_KEY_PROVIDER-<unset>}}\"\n\
         \x20 printf 'PROTON_PASS_PERSONAL_ACCESS_TOKEN=%s\\n' \
         \"${{PROTON_PASS_PERSONAL_ACCESS_TOKEN-<unset>}}\"\n\
         }} >> '{environment}'\n\
         if [ \"$1\" = 'logout' ]; then echo 'Successfully logged out'; exit 0; fi\n\
         {answer}",
        argv = argv.display(),
        environment = environment.display(),
        answer = behaviour.body()
    );
    install_executable(&dir.join("pass-cli-stub"), &body)
}

/// Write a daemon config whose Proton block points at the stand-in.
///
/// `session_dir` is a path under the scratch directory and never a real one.
/// The audit log is created here because it is what the daemon's uid is read
/// off — owned by this process, which is what lets the login run without root.
///
/// `timeout_ms` is the LOOKUP deadline and `login` does not consult it: a
/// deadline that killed a login part way is how a session store ends up
/// half-written, which is the one damage this vendor cannot repair. It is
/// spelled here because this is a whole daemon config and `suite_hygiene.rs`
/// requires every spawning store fixture to state one, not because anything
/// below is bounded by it.
fn config_at(dir: &Path, vendor: &Path, session_dir: &Path, expires: &str) -> PathBuf {
    std::fs::write(dir.join("audit.jsonl"), b"").expect("audit");
    let credentials = dir.join("proton.json");
    std::fs::write(&credentials, b"").expect("credential file");
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let path = dir.join("keylessd.json");
    std::fs::write(
        &path,
        format!(
            r#"{{
                 "socket": "{dir}/keylessd.sock",
                 "audit": "{dir}/audit.jsonl",
                 "stores": {{
                   "proton": {{
                     "enabled":true,
                     "binary": "{vendor}",
                     "session_dir": "{session}",
                     "key_provider": "fs",
                     "timeout_ms": 60000,
                     "credentials_file": "{credentials}",
                     "credentials": {{ "PROTON_PASS_PERSONAL_ACCESS_TOKEN": "AGENT_TOKEN" }}
                     {expires}
                   }}
                 }}
               }}"#,
            dir = dir.display(),
            vendor = vendor.display(),
            session = session_dir.display(),
            credentials = credentials.display(),
        ),
    )
    .expect("config");
    path
}

/// Run `keylessd login`, feeding `token` on stdin.
///
/// A pipe rather than a terminal, which is the shape `read_value` handles
/// without echo control — and the shape that makes this assertable at all. The
/// terminal path is `credential`'s own and is exercised where that verb is.
fn login(config: &Path, token: &str, extra: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_keylessd"))
        .arg("login")
        .arg("--store")
        .arg("proton")
        .arg("--config")
        .arg(config)
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keylessd login");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(token.as_bytes())
        .expect("write the token");
    child.wait_with_output().expect("keylessd login")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn the_token_reaches_the_vendor_in_the_environment_and_never_in_its_argument_vector() {
    // The first of the two properties this verb exists for, and the one an
    // assertion on the returned status cannot see: a login that succeeded with
    // the token in `--pat` would pass every status check and put a
    // vault-unlocking credential in the process table.
    let dir = scratch("argv");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);
    let config = config_at(&dir, &vendor, &session, "");

    let output = login(&config, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(output.status.success(), "{rendered}");

    // `login`, then this crate's own verification of the fresh generation —
    // see `establish`. `session` is now the ROOT of generations, so the
    // directory actually scoped is `<session>/<current>`, read back rather
    // than assumed.
    let argv: Vec<String> = read(&dir.join("pass-cli.argv"))
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        argv,
        vec!["login".to_owned(), "info".to_owned()],
        "argv: {argv:?}"
    );
    assert!(
        !argv.iter().any(|arg| arg.contains("pst_")),
        "the token reached the argument vector: {argv:?}"
    );

    let generation = current_generation(&session).expect("the login must publish a generation");
    let scoped = session.join(&generation).display().to_string();

    let environment = read(&dir.join("pass-cli.env"));
    assert!(
        environment
            .lines()
            .any(|line| line == format!("PROTON_PASS_PERSONAL_ACCESS_TOKEN={TOKEN_DECOY}")),
        "the token did not reach the environment: {environment}"
    );
    // Both of the other two, read whole rather than as substrings. A key
    // provider left unset is what reinitialises a session store, and a
    // generation directory left unset logs in whichever identity the caller's
    // home holds.
    assert!(
        environment
            .lines()
            .any(|line| line == format!("PROTON_PASS_SESSION_DIR={scoped}")),
        "environment: {environment}"
    );
    assert!(
        environment
            .lines()
            .any(|line| line == "PROTON_PASS_KEY_PROVIDER=fs"),
        "environment: {environment}"
    );

    // Nothing this verb printed carries the value.
    assert!(
        !rendered.contains(TOKEN_DECOY),
        "the verb printed it: {rendered}"
    );

    // And the token landed in the credential file, at 0600.
    let credentials = dir.join("proton.json");
    let mode = std::fs::metadata(&credentials)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o600, "written at {mode:04o}");
    assert!(
        read(&credentials).contains(TOKEN_DECOY),
        "the token was not recorded"
    );

    // The session directory was created shut.
    let mode = std::fs::metadata(&session)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o700, "session directory at {mode:04o}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The double-paste this verb used to demand, and no longer does.
///
/// `credential` writes the token and `login` uses it — two verbs, one value.
/// Until the file answered first, wiring a machine meant typing the same token
/// into both. Vault Agent's AppRole auto-auth reads `secret_id_file_path` and
/// has no prompt at all; this is the same order.
#[test]
fn a_login_with_nothing_on_stdin_uses_the_token_the_daemon_already_holds() {
    let dir = scratch("held");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);
    let config = config_at(&dir, &vendor, &session, r#","token_expires":"2099-01-01""#);

    let credentials = dir.join("proton.json");
    std::fs::write(
        &credentials,
        format!(r#"{{"AGENT_TOKEN":"{TOKEN_DECOY}"}}"#),
    )
    .expect("seed");
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let before = read(&credentials);

    // Nothing on stdin at all: the shape a script takes once the credential is
    // already written.
    let output = login(&config, "", &[]);
    let rendered = said(&output);
    assert!(
        output.status.success(),
        "a login with a token already on disk failed: {rendered}"
    );
    assert!(
        rendered.contains("token\theld\t"),
        "the verb did not say which token it used: {rendered}"
    );
    // The vendor was reached with the held value, so the file WAS the source.
    assert!(
        read(&dir.join("pass-cli.env")).contains(TOKEN_DECOY),
        "the held token never reached the vendor: {rendered}"
    );
    // And it was not written back: the value is identical, and the write is the
    // one step that can fail over a session that is in fact alive.
    assert_eq!(
        read(&credentials),
        before,
        "the held token was rewritten into its own file"
    );
    assert!(
        !rendered.contains(TOKEN_DECOY),
        "the verb printed it: {rendered}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The rotation path, which must not silently reuse the old token.
#[test]
fn a_piped_token_wins_over_the_one_on_disk_and_is_recorded() {
    let dir = scratch("piped-wins");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);
    let config = config_at(&dir, &vendor, &session, r#","token_expires":"2099-01-01""#);

    let credentials = dir.join("proton.json");
    std::fs::write(
        &credentials,
        format!(r#"{{"AGENT_TOKEN":"{OTHER_DECOY}"}}"#),
    )
    .expect("seed");
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let output = login(&config, TOKEN_DECOY, &["--replace"]);
    let rendered = said(&output);
    assert!(output.status.success(), "the rotation failed: {rendered}");
    assert!(
        !rendered.contains("token\theld\t"),
        "the piped token lost to the one on disk: {rendered}"
    );
    assert!(
        read(&dir.join("pass-cli.env")).contains(TOKEN_DECOY),
        "the piped token never reached the vendor: {rendered}"
    );
    // Recorded, because this is the value the vendor has just accepted and the
    // file did not have.
    assert!(
        read(&credentials).contains(TOKEN_DECOY),
        "the accepted token was not recorded"
    );
    assert!(
        !read(&credentials).contains(OTHER_DECOY),
        "the superseded token is still on disk"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_second_run_leaves_a_working_session_and_the_credential_file_untouched() {
    // The second of the two properties, and the one with the worst failure: a
    // session store this vendor reinitialises cannot be got back, and the
    // remedy for a token that is merely unwritten is to type it again.
    let dir = scratch("second");
    let session = dir.join("session");
    // A session directory as a working install has one: created, shut, holding
    // the vendor's own files.
    std::fs::create_dir_all(session.join(".session")).expect("session");
    std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let landed = session.join(".session/session.json");
    std::fs::write(&landed, b"decoy-session-not-a-real-identity").expect("plant");

    let vendor = stub_vendor(&dir, &Vendor::AlreadyAuthenticated);
    let config = config_at(&dir, &vendor, &session, "");
    // A credential file that already holds a value, so "unchanged" is a real
    // claim rather than one an empty file satisfies for free.
    let credentials = dir.join("proton.json");
    std::fs::write(
        &credentials,
        format!(r#"{{"AGENT_TOKEN":"{OTHER_DECOY}"}}"#),
    )
    .expect("seed");
    std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let before = read(&credentials);

    let output = login(&config, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(
        !output.status.success(),
        "a login the vendor refused reported success: {rendered}"
    );

    // The session survived, byte for byte.
    assert_eq!(
        read(&landed),
        "decoy-session-not-a-real-identity",
        "the session store was rewritten"
    );
    // And the credential file was not touched — neither replaced by the new
    // token nor emptied.
    assert_eq!(read(&credentials), before, "the credential file changed");
    assert!(
        !read(&credentials).contains(TOKEN_DECOY),
        "an unproven token was written"
    );

    // The message names the flag that WOULD replace it, so the rotation path is
    // discoverable without a hand-typed vendor command.
    assert!(
        rendered.contains("--replace"),
        "the refusal does not name the rotation path: {rendered}"
    );
    assert!(
        !rendered.contains(TOKEN_DECOY),
        "the verb printed it: {rendered}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_token_the_account_refuses_is_not_left_on_disk() {
    // A well-formed token the vendor rejects passes every structural rule the
    // `token` row of `check` has, so writing it first would put a false green
    // over a credential that unlocks nothing.
    let dir = scratch("refused");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Refuses);
    let config = config_at(&dir, &vendor, &session, "");

    let output = login(&config, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(!output.status.success(), "{rendered}");
    assert!(
        !read(&dir.join("proton.json")).contains(TOKEN_DECOY),
        "a refused token was written to the credential file"
    );
    assert!(
        rendered.contains("invalid, expired or has been deleted"),
        "the vendor's own sentence is not in the report: {rendered}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_default_refuses_a_live_session_by_asking_and_replace_never_asks_at_all() {
    // The control for the case above and the rotation path itself: the same
    // fixture, differing only in the flag, must reach the vendor differently.
    //
    // Under generations a fresh directory is never refused by the vendor — see
    // `establish`'s own doc — so the property this used to prove (`--replace`
    // logs the old session out first, the default does not) is now proven the
    // other way round: the DEFAULT asks this crate's own question (`info`
    // against the current generation) and refuses without ever calling
    // `login` when it answers; `--replace` skips that question entirely and
    // goes straight to a fresh generation, never touching the old one.
    let dir = scratch("replace");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);
    let config = config_at(&dir, &vendor, &session, "");
    let existing = publish_generation(&session);
    let existing_name = existing
        .file_name()
        .and_then(|name| name.to_str())
        .expect("a generation name")
        .to_owned();

    // The default: `Vendor::Accepts` answers ANY verb with exit 0, so the
    // `info` probe reads as a live session and the verb refuses without
    // creating anything.
    let output = login(&config, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(
        !output.status.success(),
        "a live session was not refused: {rendered}"
    );
    let argv: Vec<String> = read(&dir.join("pass-cli.argv"))
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        argv,
        vec!["info".to_owned()],
        "the default asked something other than this crate's own liveness check: {argv:?}"
    );
    assert_eq!(
        current_generation(&session).as_deref(),
        Some(existing_name.as_str()),
        "current changed even though the default never logs in"
    );

    // `--replace`: no question is asked, a fresh generation is created,
    // logged into and verified — and the OLD one is never touched, because
    // retirement runs on its own grace and this run is far too quick for it.
    std::fs::remove_file(dir.join("pass-cli.argv")).expect("clear the argv log");
    let output = login(&config, TOKEN_DECOY, &["--replace"]);
    let rendered = said(&output);
    assert!(output.status.success(), "{rendered}");
    let argv: Vec<String> = read(&dir.join("pass-cli.argv"))
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        argv,
        vec!["login".to_owned(), "info".to_owned()],
        "`--replace` asked the already-authenticated question or skipped its own \
         verification: {argv:?}"
    );
    let replaced_name = current_generation(&session).expect("a generation is current");
    assert_ne!(
        replaced_name, existing_name,
        "`--replace` republished the same generation rather than a fresh one"
    );
    assert!(
        session.join(&existing_name).is_dir(),
        "the superseded generation was deleted immediately, with no grace"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn everything_that_can_refuse_this_config_refuses_before_a_token_is_asked_for() {
    // Nobody should type a credential into a setup that was never going to use
    // it — and a value typed at a prompt that then refuses is a value the
    // person now has to decide whether to trust.
    let dir = scratch("early");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);

    // 1. The store is off. There is nothing to log in.
    let off = dir.join("off.json");
    std::fs::write(
        &off,
        format!(
            r#"{{"audit":"{dir}/audit.jsonl","stores":{{"proton":{{"enabled":false}}}}}}"#,
            dir = dir.display()
        ),
    )
    .expect("config");
    let output = login(&off, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(!output.status.success(), "{rendered}");
    assert!(rendered.contains("enabled"), "{rendered}");

    // 2. No session directory. The one field that is never defaulted.
    let bare = dir.join("bare.json");
    std::fs::write(
        &bare,
        format!(
            r#"{{"audit":"{dir}/audit.jsonl","stores":{{"proton":{{"enabled":true,
                 "binary":"{vendor}",
                 "timeout_ms":60000,
                 "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN"}}}}}}}}"#,
            dir = dir.display(),
            vendor = vendor.display()
        ),
    )
    .expect("config");
    let output = login(&bare, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(!output.status.success(), "{rendered}");
    assert!(rendered.contains("session_dir"), "{rendered}");

    // 3. A store with no session at all.
    let config = config_at(&dir, &vendor, &session, "");
    let output = Command::new(env!("CARGO_BIN_EXE_keylessd"))
        .args(["login", "--store", "infisical", "--config"])
        .arg(&config)
        .output()
        .expect("keylessd login");
    let rendered = said(&output);
    assert!(!output.status.success(), "{rendered}");
    assert!(
        rendered.contains("credential --store infisical"),
        "{rendered}"
    );

    // Not one of the three reached the vendor. The control for all of them:
    // the same fixture with a sound config spawns it, which the case above
    // proves.
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a refused config still spawned the vendor"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_value_that_is_not_a_token_is_refused_before_the_vendor_is_spawned() {
    // The most plausible paste of all is the token's NAME, and the vendor's
    // answer to it is the same sentence it gives an expired token — which
    // sends the reader to a dashboard to look for something that was never
    // wrong.
    let dir = scratch("shape");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);
    let config = config_at(&dir, &vendor, &session, "");

    let output = login(&config, "keyless-agents", &[]);
    let rendered = said(&output);
    assert!(!output.status.success(), "{rendered}");
    assert!(rendered.contains("pst_"), "{rendered}");
    assert!(
        !rendered.contains("keyless-agents"),
        "the value was printed back: {rendered}"
    );
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a malformed value was sent to the vendor"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_session_directory_left_wide_open_is_shut_rather_than_reported() {
    // What a hand-typed login without `sudo -u` leaves: a directory whose mode
    // the daemon's own store would refuse. Repaired in the same pass, and said
    // out loud, because the operator who did it needs to know it was the
    // problem.
    let dir = scratch("repair");
    let session = dir.join("session");
    std::fs::create_dir_all(&session).expect("session");
    std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o755)).expect("widen");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);
    let config = config_at(&dir, &vendor, &session, "");

    let output = login(&config, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(output.status.success(), "{rendered}");
    let mode = std::fs::metadata(&session)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o700, "left at {mode:04o}");
    assert!(
        rendered
            .lines()
            .any(|line| line.split('\t').next() == Some("session")
                && line.split('\t').nth(1) == Some("repaired")),
        "the repair went unreported: {rendered}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_undeclared_expiry_is_said_out_loud_and_a_declared_one_is_not() {
    // The one setting whose failure arrives on a schedule nobody chose with
    // nobody awake to read it — and the moment somebody has the vendor's own
    // output in front of them is this one.
    let dir = scratch("expiry");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);

    let silent = config_at(&dir, &vendor, &session, r#","token_expires":"2099-01-01""#);
    let output = login(&silent, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(output.status.success(), "{rendered}");
    assert!(
        !rendered.contains("token_expires"),
        "a declared expiry was nagged about: {rendered}"
    );

    // Same fixture, one field away.
    let dir = scratch("expiry-absent");
    let session = dir.join("session");
    let vendor = stub_vendor(&dir, &Vendor::Accepts);
    let loud = config_at(&dir, &vendor, &session, "");
    let output = login(&loud, TOKEN_DECOY, &[]);
    let rendered = said(&output);
    assert!(output.status.success(), "{rendered}");
    assert!(rendered.contains("token_expires"), "{rendered}");

    let _ = std::fs::remove_dir_all(&dir);
}
