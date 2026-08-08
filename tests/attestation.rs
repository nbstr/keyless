//! The attacks, built and run rather than reasoned about.
//!
//! Every test here is an adversary. Where an attack is expected to fail, there
//! is a positive control alongside it showing the same machinery succeeding —
//! otherwise "the attack was refused" and "nothing worked at all" look
//! identical, and the second one passes just as green.
//!
//! What is **not** covered, stated here rather than left to be inferred:
//!
//! - Every test runs the daemon and the peer under **one uid**. The privilege
//!   separation itself — the store file the session cannot open, the audit log
//!   the session cannot write — is enforced by file modes that only mean
//!   something across two uids, and creating a second user needs `sudo`. Those
//!   modes are asserted; the boundary they create is not exercised.
//! - Genuine pid **reuse** is not forced. The anchor is exercised against a
//!   process that has exited, and against a process that changes its own image
//!   mid-connection, which is the same class and is forcible. Wrapping the pid
//!   space to recycle a specific number is not.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use keyless::audit::AuditLog;
use keyless::ipc::ffi::{live_code_hash, live_process};
use keyless::ipc::peer::code_hash_of_file;

use support::{
    DECOY_VALUE, daemon_config, example_binary, own_identity, policy_allowing_self, scratch,
    start_daemon, write_secrets,
};

/// The SHA-256 of the decoy, which is what an authorised peer reports instead
/// of the value itself.
fn decoy_digest() -> String {
    keyless::mask::encodings::hex_lower(&keyless::audit::sha256::digest(DECOY_VALUE.as_bytes()))
}

/// Copy a binary, preserving the mode so it stays executable.
fn install(from: &Path, to: &Path) {
    std::fs::copy(from, to).expect("copy the peer");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
}

/// Run a peer to completion and return its stdout line.
fn run_peer(binary: &Path, socket: &Path, extra: &[(&str, &str)]) -> String {
    let mut command = Command::new(binary);
    command
        .env("KLP_SOCKET", socket)
        .env("KLP_NAME", "DECOY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in extra {
        command.env(key, value);
    }
    let output = command.output().expect("the peer must run");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

// ---------------------------------------------------------------------------
// Attack 1 — swap the binary between connect and attestation
// ---------------------------------------------------------------------------

/// Drive the swap attack, returning what the peer was told.
///
/// The swap is a `rename`, not an overwrite, and that is the real attack
/// rather than a convenience: renaming leaves the running process mapped to
/// the original inode while everything that resolves the *path* sees the
/// replacement. An implementation that hashes the file at the peer's path
/// therefore reads the attacker's chosen binary while the peer keeps running
/// the original — which is exactly the hole this design exists to avoid.
fn swap_attack(tag: &str, pinned: &str) -> String {
    let dir = scratch(tag);
    let alpha = example_binary("keyless_peer_alpha");
    let beta = example_binary("keyless_peer_beta");

    let victim = dir.join("victim");
    let staged = dir.join("staged");
    install(&alpha, &victim);
    install(&beta, &staged);

    let pinned_hash = match pinned {
        "alpha" => code_hash_of_file(&victim).expect("alpha is signed"),
        _ => code_hash_of_file(&staged).expect("beta is signed"),
    };

    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);

    let me = own_identity();
    let policy = keyless::attest::Policy::new()
        .allow_uid(me.uid)
        .allow_image(pinned_hash);
    let running = start_daemon(&config, policy);

    let child = Command::new(&victim)
        .env("KLP_SOCKET", running.socket())
        .env("KLP_NAME", "DECOY")
        .env("KLP_MODE", "delay")
        .env("KLP_DELAY_MS", "600")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the victim");

    // Let it connect, then replace the file at its path while it is still
    // running and still connected.
    std::thread::sleep(Duration::from_millis(200));
    std::fs::rename(&staged, &victim).expect("rename the replacement over the victim");

    // The file at the path is now beta. Prove it, so a failed rename cannot
    // make this test pass by never performing the attack.
    let on_disk = code_hash_of_file(&victim).expect("the replacement is signed");
    let beta_hash = code_hash_of_file(&example_binary("keyless_peer_beta")).expect("beta");
    assert_eq!(
        on_disk, beta_hash,
        "{tag}: the swap did not land, so no attack was performed"
    );

    let output = child.wait_with_output().expect("the victim must finish");
    let line = String::from_utf8_lossy(&output.stdout).trim().to_owned();

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
    line
}

#[test]
fn swapping_the_binary_on_disk_does_not_grant_the_replacements_identity() {
    // Pin BETA. The peer running is alpha. The attacker renames beta over
    // alpha's path mid-connection, so a path-hashing daemon would see the
    // pinned hash and let it through.
    let line = swap_attack("toctou-attack", "beta");
    assert!(
        line.contains("status=denied"),
        "the swap attack succeeded: {line}"
    );
    assert!(
        line.contains("unknown-image") || line.contains("not a pinned client"),
        "refused for the wrong reason: {line}"
    );
}

#[test]
fn swapping_the_binary_on_disk_does_not_revoke_the_running_images_identity() {
    // The positive control, and the sharper half of the claim. Pin ALPHA, run
    // alpha, and perform the identical swap. The daemon must still recognise
    // the peer — because it is reading the loaded image, which did not change
    // — rather than being confused by a file it never looks at.
    let line = swap_attack("toctou-control", "alpha");
    assert!(
        line.contains("status=ok"),
        "the running image stopped being recognised after an unrelated file swap: {line}"
    );
    assert!(
        line.contains(&decoy_digest()),
        "the wrong value came back: {line}"
    );
}

// ---------------------------------------------------------------------------
// Attack 2 — attest as an interpreter
// ---------------------------------------------------------------------------

/// A perl client that speaks the protocol.
///
/// `perl` ships with macOS and `IO::Socket::UNIX` is in its core distribution,
/// so this is a genuine interpreted caller and not a simulation of one. Its
/// loaded image is `/usr/bin/perl`, which is the whole point: nothing about
/// this process's code identity says which script it is running.
const PERL_CLIENT: &str = r#"
use strict; use warnings; use IO::Socket::UNIX;
my $sock = IO::Socket::UNIX->new(Peer => $ENV{KLP_SOCKET}, Type => SOCK_STREAM)
    or die "connect: $!";
print $sock qq({"v":1,"op":"resolve","name":"DECOY","cwd":"/","argv":[]}\n);
my $reply = <$sock>;
print $reply;
"#;

fn run_perl_peer(socket: &Path) -> String {
    let output = Command::new("/usr/bin/perl")
        .arg("-e")
        .arg(PERL_CLIENT)
        .env("KLP_SOCKET", socket)
        .stdin(Stdio::null())
        .output()
        .expect("perl must run");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn an_interpreter_cannot_inherit_trust_even_when_its_own_hash_is_pinned() {
    let dir = scratch("interpreter");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);

    // The operator's mistake, made deliberately: pin the interpreter itself.
    // This is what "allowlisting Claude Code" would actually mean, and it is
    // what makes an interpreter allowlist authorise every program on the
    // machine that interpreter can run.
    let perl_hash = code_hash_of_file(Path::new("/usr/bin/perl")).expect("perl is signed");
    let me = own_identity();
    let policy = keyless::attest::Policy::new()
        .allow_uid(me.uid)
        .allow_image(perl_hash);
    let running = start_daemon(&config, policy);

    let reply = run_perl_peer(running.socket());
    assert!(
        reply.contains("\"status\":\"denied\""),
        "an interpreted caller was served: {reply}"
    );
    assert!(
        reply.contains("interpreter"),
        "refused, but not as an interpreter: {reply}"
    );
    assert!(
        reply.contains("keyless run"),
        "the refusal must say what to do instead: {reply}"
    );
    assert!(
        !reply.contains(DECOY_VALUE),
        "the value reached an interpreted caller: {reply}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_interpreter_refusal_is_what_refused_it() {
    // Negative control. With the rule off and perl's hash pinned, the same
    // perl process is served — so the test above is about the interpreter
    // rule and not about the allowlist happening to miss.
    let dir = scratch("interpreter-control");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);

    let perl_hash = code_hash_of_file(Path::new("/usr/bin/perl")).expect("perl is signed");
    let me = own_identity();
    let policy = keyless::attest::Policy::new()
        .allow_uid(me.uid)
        .allow_image(perl_hash)
        .permitting_interpreters();
    let running = start_daemon(&config, policy);

    let reply = run_perl_peer(running.socket());
    assert!(
        reply.contains("\"status\":\"ok\""),
        "with the rule off the same caller must pass, or the rule is not what refused it: {reply}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Attack 3 — the pid anchor
// ---------------------------------------------------------------------------

#[test]
fn a_process_that_has_exited_cannot_be_attested() {
    // The pid of a dead process is a number that will be handed to somebody
    // else. Both primitives the attestation rests on must refuse it rather
    // than returning a default, which is how a zero hash would end up matching
    // a zero pin.
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .spawn()
        .expect("spawn");
    let pid = child.id().cast_signed();
    let _ = child.wait().expect("reap");

    assert!(
        live_code_hash(pid).is_err(),
        "a reaped pid still produced a code hash"
    );
    assert!(
        live_process(pid).is_err(),
        "a reaped pid still produced a live identity"
    );
}

#[test]
fn every_process_carries_a_distinct_generation() {
    // The anchor is only worth anything if the generation actually varies. If
    // the kernel handed out a constant, the recycled-pid check would compare
    // equal every time and the whole guard would be decorative.
    let mut generations = Vec::new();
    for _ in 0..8 {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 0.4")
            .spawn()
            .expect("spawn");
        let pid = child.id().cast_signed();
        let live = live_process(pid).expect("a running child is in the pid table");
        generations.push((live.generation, live.unique_id));
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
    }

    let mut seen_generations: Vec<i32> = generations.iter().map(|(g, _)| *g).collect();
    seen_generations.sort_unstable();
    seen_generations.dedup();
    assert_eq!(
        seen_generations.len(),
        generations.len(),
        "two different processes reported the same generation"
    );

    let mut seen_ids: Vec<u64> = generations.iter().map(|(_, id)| *id).collect();
    seen_ids.sort_unstable();
    seen_ids.dedup();
    assert_eq!(seen_ids.len(), generations.len());
}

#[test]
fn changing_image_mid_connection_loses_the_authorisation() {
    // The forcible member of the pid-reuse family, and the reason attestation
    // runs per request. The peer connects as a pinned program, is served, then
    // `exec`s a program that is not pinned — same pid, same generation, same
    // open socket — and asks again on the connection it already had.
    //
    // A daemon that attested once per connection would serve the second
    // request to a program it never authorised.
    let dir = scratch("exec-swap");
    let alpha = example_binary("keyless_peer_alpha");
    let beta = example_binary("keyless_peer_beta");

    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);

    let alpha_hash = code_hash_of_file(&alpha).expect("alpha is signed");
    let me = own_identity();
    let policy = keyless::attest::Policy::new()
        .allow_uid(me.uid)
        .allow_image(alpha_hash);
    let running = start_daemon(&config, policy);

    let output = Command::new(&alpha)
        .env("KLP_SOCKET", running.socket())
        .env("KLP_NAME", "DECOY")
        .env("KLP_MODE", "exec")
        .env("KLP_EXEC", &beta)
        .stdin(Stdio::null())
        .output()
        .expect("the peer must run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    assert_eq!(
        lines.len(),
        2,
        "expected one line before the exec and one after: {stdout}"
    );
    assert!(
        lines[0].starts_with("alpha") && lines[0].contains("status=ok"),
        "the pinned program was not served: {}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("beta"),
        "the successor did not run: {}",
        lines[1]
    );
    assert!(
        lines[1].contains("status=denied"),
        "an unpinned program inherited an authorised connection: {}",
        lines[1]
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Attack 4 — an unauthorised peer
// ---------------------------------------------------------------------------

#[test]
fn a_program_that_is_not_pinned_is_refused() {
    let dir = scratch("unauthorised");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);

    let alpha = example_binary("keyless_peer_alpha");
    let beta = example_binary("keyless_peer_beta");
    let me = own_identity();
    let policy = keyless::attest::Policy::new()
        .allow_uid(me.uid)
        .allow_image(code_hash_of_file(&alpha).expect("alpha is signed"));
    let running = start_daemon(&config, policy);

    let refused = run_peer(&beta, running.socket(), &[]);
    assert!(
        refused.contains("status=denied"),
        "an unpinned program was served: {refused}"
    );
    assert!(
        !refused.contains(&decoy_digest()),
        "a value reached an unpinned program: {refused}"
    );

    // The positive control: the pinned twin, same socket, same moment.
    let served = run_peer(&alpha, running.socket(), &[]);
    assert!(
        served.contains("status=ok") && served.contains(&decoy_digest()),
        "the pinned program was not served, so the refusal above proves nothing: {served}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_allowlist_serves_nobody() {
    let dir = scratch("nothing-pinned");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);

    let me = own_identity();
    let running = start_daemon(&config, keyless::attest::Policy::new().allow_uid(me.uid));

    let line = run_peer(&example_binary("keyless_peer_alpha"), running.socket(), &[]);
    assert!(
        line.contains("status=denied") && line.contains("no client image is pinned"),
        "an unconfigured daemon must refuse rather than allow: {line}"
    );

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Attack 5 — forge the audit log
// ---------------------------------------------------------------------------

#[test]
fn rewriting_a_row_breaks_the_chain() {
    let dir = scratch("audit-forge");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);
    let running = start_daemon(&config, policy_allowing_self());

    let alpha = example_binary("keyless_peer_alpha");
    let alpha_hash = code_hash_of_file(&alpha).expect("alpha is signed");
    // The peer is this test process, which is what `policy_allowing_self`
    // pinned; drive three requests through the client so there are rows.
    let store = keyless::store::daemon::DaemonStore::new(
        running.socket().to_path_buf(),
        Duration::from_secs(5),
    );
    for _ in 0..3 {
        let _ = keyless::store::Store::resolve(&store, "DECOY");
    }
    drop(running);

    let log = AuditLog::new(config.audit.to_path_buf());
    let rows = log.verify().expect("a fresh log must verify");
    assert!(rows >= 3, "expected the daemon's rows, got {rows}");

    // The forgery. As the calling user, edit a row to say a different program
    // asked for the secret.
    let raw = std::fs::read_to_string(&config.audit).expect("read");
    let forged = raw.replace("\"decision\":\"allow\"", "\"decision\":\"deny\"");
    assert_ne!(
        forged, raw,
        "the substitution did not land, so nothing was forged"
    );
    std::fs::write(&config.audit, &forged).expect("write");

    let error = log.verify().expect_err("an edited row must not verify");
    assert!(error.to_string().contains("chain broken"), "{error}");

    // And the other forgery: recompute nothing, just delete a row.
    std::fs::write(&config.audit, &raw).expect("restore");
    assert!(log.verify().is_ok(), "the restore must put it back");
    let without_middle: String = raw
        .lines()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, line)| format!("{line}\n"))
        .collect();
    std::fs::write(&config.audit, without_middle).expect("write");
    assert!(log.verify().is_err(), "a deleted row must break the chain");

    // The hash is not the boundary — the file mode is. Assert the mode the
    // daemon creates, because the chain detects an edit only where the editor
    // cannot also recompute every hash after it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&config.audit)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "mode was {mode:04o}");
    }

    let _ = alpha_hash;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wholesale_rewrite_is_not_detected_by_the_chain_alone() {
    // The honest half. A writer who can rewrite the whole file can recompute
    // every hash and produce a log that verifies perfectly. This test exists
    // so that fact is a checked property rather than a caveat somebody might
    // quietly drop from the README.
    //
    // What stops it in production is that the file belongs to the daemon's
    // uid and the session's uid cannot write it — which this suite cannot
    // exercise, because it runs everything under one uid.
    let dir = scratch("audit-rewrite");
    let path = dir.join("audit.jsonl");
    let log = AuditLog::new(path.clone());
    let masker = keyless::mask::Masker::new();
    for i in 0..4 {
        log.append(&keyless::audit::Event::new(
            "resolve",
            keyless::State::Injected,
            vec![format!("NAME{i}")],
            &[] as &[String],
            &masker,
        ))
        .expect("append");
    }
    assert_eq!(log.verify().expect("verify"), 4);

    // Rewrite from scratch, as an attacker with write access would.
    std::fs::remove_file(&path).expect("remove");
    let forged = AuditLog::new(path.clone());
    forged
        .append(&keyless::audit::Event::new(
            "resolve",
            keyless::State::Injected,
            vec!["NOTHING_HAPPENED".to_owned()],
            &[] as &[String],
            &masker,
        ))
        .expect("append");

    assert_eq!(
        forged.verify().expect("a rewritten log verifies"),
        1,
        "a from-scratch rewrite produces a chain that verifies; only the file \
         mode stops it, and only across two uids"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// The happy path, so every refusal above means something
// ---------------------------------------------------------------------------

#[test]
fn an_authorised_peer_is_served_and_the_row_names_it() {
    let dir = scratch("authorised");
    let mut config = daemon_config(&dir);
    config.cache_ttl_seconds = 0;
    write_secrets(&config.stores.file.path, &[("DECOY", DECOY_VALUE)]);

    let alpha = example_binary("keyless_peer_alpha");
    let alpha_hash = code_hash_of_file(&alpha).expect("alpha is signed");
    let me = own_identity();
    let running = start_daemon(
        &config,
        keyless::attest::Policy::new()
            .allow_uid(me.uid)
            .allow_image(alpha_hash),
    );

    let line = run_peer(&alpha, running.socket(), &[]);
    assert!(line.contains("status=ok"), "{line}");
    assert!(line.contains(&decoy_digest()), "wrong value: {line}");
    drop(running);

    let raw = std::fs::read_to_string(&config.audit).expect("read the audit log");
    let hex = keyless::mask::encodings::hex_lower(&alpha_hash);
    assert!(
        raw.contains(&hex),
        "the row does not name the program that asked"
    );
    assert!(raw.contains("\"decision\":\"allow\""));
    assert!(raw.contains("keyless_peer_alpha"));
    assert!(
        !raw.contains(DECOY_VALUE),
        "the daemon's audit log carries a value"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Sanity: the two peers really are different programs.
///
/// If a compiler ever folded them into one binary, every test above that
/// distinguishes them would pass for the wrong reason.
#[test]
fn the_two_test_peers_have_different_identities() {
    let alpha: PathBuf = example_binary("keyless_peer_alpha");
    let beta: PathBuf = example_binary("keyless_peer_beta");
    let a = code_hash_of_file(&alpha).expect("alpha is signed");
    let b = code_hash_of_file(&beta).expect("beta is signed");
    assert_ne!(
        a, b,
        "the two peers share a code hash, so nothing here tests identity"
    );
}

// ---------------------------------------------------------------------------
// The cross-uid measurement, made repeatable
// ---------------------------------------------------------------------------

/// The daemon runs as a uid its callers are not, so every primitive it uses to
/// identify a caller has to work when the reader does **not** own the target
/// process. That is not obvious and it is not uniform: one of the flavours
/// commonly recommended for this job is refused across a uid boundary, which is
/// why the anchor in `ipc::peer` is the pid generation rather than a start time.
///
/// pid 1 is `launchd`, owned by root, and this test is not root. So it is a
/// genuine cross-uid read, on any machine, without creating a user — which
/// makes it the one part of the privilege boundary CI can actually check.
#[test]
fn the_attestation_primitives_read_across_a_uid_boundary() {
    let me = own_identity();
    assert_ne!(
        me.uid, 0,
        "run this as an ordinary user; as root it proves nothing"
    );

    // `launchd`: pid 1, uid 0, and emphatically not ours.
    let hash = live_code_hash(1).expect(
        "csops(CS_OPS_CDHASH) must read the live image of a process owned by another uid; \
         without it the daemon cannot identify any caller",
    );
    assert!(hash.iter().any(|b| *b != 0));

    let live = live_process(1).expect(
        "PROC_PIDUNIQIDENTIFIERINFO must be readable across a uid boundary; it carries the \
         pid generation the recycled-pid check compares against",
    );
    assert!(live.generation > 0);
    assert!(live.unique_id > 0);

    let image = keyless::ipc::ffi::image_path(1).expect("proc_pidpath works across uids");
    assert_eq!(
        image,
        std::path::Path::new("/sbin/launchd"),
        "pid 1 should be launchd"
    );

    // And the identity really is per-process rather than a constant: a second,
    // different foreign process must not report pid 1's hash.
    let child = Command::new("/bin/sleep")
        .arg("2")
        .spawn()
        .expect("spawn a process of our own");
    let ours = live_code_hash(child.id().cast_signed()).expect("our own child attests");
    assert_ne!(
        ours, hash,
        "two different images reported the same code hash, so the hash is not an identity"
    );
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
}
