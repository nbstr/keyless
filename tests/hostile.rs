//! The never-block invariant under attack, rather than under failure.
//!
//! [`never_block`](../never_block.rs) covers the failures a store is *expected*
//! to have: absent, unhealthy, empty-handed, slow. Every one of them is
//! something the world does to `keyless`.
//!
//! This file covers what an ATTACKER does to it, and every property here was
//! found by falsifying the README's Rule 1 — *"there is no code path in which
//! `keyless run` exits without spawning the child"* — rather than by reading
//! the code. Each one ended in the same place: **no child process, and nothing
//! on screen saying why.**
//!
//! # How each of these is proved
//!
//! By a side effect the parent cannot fake. A test that asserts on `run`'s
//! return value is asserting on the thing under test; a file that only the
//! CHILD could have written is not. So every test here spawns a child whose
//! whole job is to write a marker, and reads the marker.
//!
//! # Two shapes of failure, and only one of them is an exit code
//!
//! A refusal exits. A **hang** does not — it produces no output, no exit code
//! and no evidence, and under `cargo test` it stops the whole suite rather than
//! failing one case. Four of the properties below are hangs, so they are written
//! to FAIL rather than to hang: the call under test runs on its own thread and
//! the assertion is on a `recv_timeout`. A regression then reports a named
//! failing test instead of a suite that never finishes.
//!
//! # Platform
//!
//! macOS. The whole crate is, and `cargo test` does not run at all on Linux —
//! every test binary links the lib and the lib references four XNU symbols. The
//! FIFO, `/dev/zero` and `ARG_MAX` properties below are POSIX rather than
//! Darwin-specific, but they are only *measured* here.

mod support;

use std::ffi::OsString;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use keyless::State;
use keyless::cmd::run::{Binding, TtyPolicy};
use keyless::config::{Config, MAX_TIMEOUT_MS};
use keyless::error::StoreError;
use keyless::secret::Secret;
use keyless::store::keychain::KeychainStore;
use keyless::store::{Registry, Store};

use support::{DECOY_VALUE, Stub, run_with, scratch, stub_security, witness, witnessed};

/// Run `body` on its own thread and fail if it has not finished by `limit`.
///
/// The difference between a test that reports a hang and a test that IS one.
/// The worker is left running on a timeout — the process is about to end.
fn within<T: Send + 'static>(
    limit: Duration,
    label: &str,
    body: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (done, waiting) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(body());
    });
    match waiting.recv_timeout(limit) {
        Ok(value) => value,
        Err(_) => panic!("{label} did not finish within {limit:?}; it hangs"),
    }
}

/// A `security` stand-in that behaves badly in one specific way.
fn hostile_security(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write the hostile stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    path
}

/// A backend that hands back exactly the value it was built with.
struct Hands(&'static str, String);

impl Store for Hands {
    fn id(&self) -> &str {
        self.0
    }
    fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
        Ok(Some(Secret::new(self.1.clone())))
    }
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 1. The config file is not a file.
// ---------------------------------------------------------------------------

#[test]
fn a_config_that_is_a_fifo_with_no_writer_does_not_hang_the_load() {
    // `fs::read_to_string` on a writerless FIFO blocks in `open`, forever. The
    // config is read before anything else, so this is a `keyless run` that never
    // reaches its spawn and never prints a word. Measured: killed at 20 s.
    let dir = scratch("config-fifo");
    let fifo = dir.join("config.json");
    let made = std::process::Command::new("/usr/bin/mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must run");
    assert!(made.success(), "the fixture needs a FIFO");

    let load = within(
        Duration::from_secs(10),
        "Config::load on a FIFO",
        move || Config::load(&fifo),
    );

    assert!(load.problem.is_some(), "a FIFO must be reported, not read");
    assert!(!load.loaded);
    // The defaults, so the run continues with a usable config.
    assert!(load.config.secrets.is_empty());
}

#[test]
fn a_config_that_is_a_character_device_is_refused_rather_than_read() {
    // `/dev/zero` reads successfully and never ends. With no bound this is not
    // a hang that looks like a hang: memory climbs until the kernel intervenes.
    // Measured: 19.9 s to an out-of-memory kill, no child.
    let load = within(Duration::from_secs(10), "Config::load on /dev/zero", || {
        Config::load(Path::new("/dev/zero"))
    });
    let problem = load.problem.expect("a character device must be refused");
    assert!(
        problem.to_string().contains("not a regular file"),
        "the reason must name the cause: {problem}"
    );
    assert!(load.config.secrets.is_empty());
}

#[test]
fn a_config_over_the_cap_is_refused_and_the_defaults_still_load() {
    let dir = scratch("config-too-big");
    let path = dir.join("config.json");
    std::fs::write(&path, vec![b'x'; 2 * 1024 * 1024]).expect("write a big file");
    let load = Config::load(&path);
    let problem = load.problem.expect("over the cap must be refused");
    assert!(problem.to_string().contains("cap"), "{problem}");
}

#[test]
fn the_ordinary_config_still_loads_unchanged() {
    // The negative control for the three above. Without it, a `read_config_file`
    // that refused everything would pass all of them.
    let dir = scratch("config-ordinary");
    let path = dir.join("config.json");
    std::fs::write(&path, br#"{"secrets":{"DECOY":{}}}"#).expect("write config");
    let load = Config::load(&path);
    assert!(load.problem.is_none(), "{:?}", load.problem);
    assert!(load.loaded);
    assert!(load.config.secrets.contains_key("DECOY"));
}

// ---------------------------------------------------------------------------
// 2. The keychain backend, which is the one enabled by default.
// ---------------------------------------------------------------------------

#[test]
fn a_keychain_binary_that_never_answers_still_spawns_the_child() {
    // The adapter called `Command::output`, which has no deadline. A `security`
    // that sleeps therefore hung `keyless run` with no child, no stderr and no
    // exit code — measured, killed at 45 s. The two network backends already
    // routed through a deadline and degraded at 10 s under the same attack.
    let dir = scratch("keychain-hangs");
    let marker = dir.join("witness");
    let stub = hostile_security(&dir, "security-sleeps", "sleep 120\n");

    let registry = Registry::new(vec![Box::new(
        KeychainStore::new(stub, "keyless".to_owned()).with_timeout(Duration::from_millis(400)),
    )]);

    let argv = witness(&marker, "DECOY", 42);
    let started = Instant::now();
    let (outcome, notes) = within(
        Duration::from_secs(30),
        "a hanging keychain lookup",
        move || run_with(&registry, &["DECOY"], &argv, &[]),
    );

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "the child must run with an unmodified environment"
    );
    assert_eq!(
        outcome.exit_code, 42,
        "the child's exit code must come back"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert!(notes.contains("DEGRADED"), "no banner: {notes}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the deadline was not enforced: {:?}",
        started.elapsed()
    );
}

#[test]
fn a_keychain_binary_that_streams_forever_is_bounded_in_memory_not_just_in_time() {
    // The same absent deadline, in its expensive form: a `security` that copies
    // `/dev/zero` to its stdout reached 2.7 GB resident in 12 s and was still
    // climbing at 40 s. `Command::output` reads to end of stream, and there is
    // no end.
    //
    // **A deadline alone does not fix this, and the first version of this test
    // proved it.** With the read still unbounded, a 500 ms deadline against
    // `dd if=/dev/zero` allocated and scrubbed enough that this test
    // intermittently blew past a THIRTY-SECOND wall clock on a loaded machine —
    // a green suite that failed once in several runs, for the exact defect it
    // was written to close. How long a flood runs and how much arrives in that
    // time are two different bounds, and only the second one is about memory.
    //
    // So the read is capped, and the giveaway that the cap is what is working
    // is the deadline below: **60 seconds**, far longer than the 500 ms lookup
    // deadline. If this test ever fails on time again, the cap is gone.
    let dir = scratch("keychain-floods");
    let marker = dir.join("witness");
    let stub = hostile_security(
        &dir,
        "security-floods",
        "case \"$1\" in\n\
         \x20 find-generic-password) exec /bin/dd if=/dev/zero bs=65536 ;;\n\
         esac\n\
         exit 1\n",
    );

    let registry = Registry::new(vec![Box::new(
        KeychainStore::new(stub, "keyless".to_owned()).with_timeout(Duration::from_millis(500)),
    )]);

    let argv = witness(&marker, "DECOY", 7);
    let started = Instant::now();
    let (outcome, _) = within(
        Duration::from_secs(60),
        "a flooding keychain lookup",
        move || run_with(&registry, &["DECOY"], &argv, &[]),
    );

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 7);
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the flood was not bounded: {:?}",
        started.elapsed()
    );
}

#[test]
fn a_backend_that_produces_more_than_the_cap_is_an_error_not_a_truncated_value() {
    // The cap must not hand back a PREFIX. A truncated credential is a silently
    // wrong one: it injects, the child runs, and the remote end rejects it for
    // a reason nothing on this machine can explain.
    //
    // 12 MB, over the 8 MiB cap, from a stub that EXITS — so nothing here is a
    // timeout, and the error can only come from the cap itself.
    let dir = scratch("cap-not-truncation");
    let marker = dir.join("witness");
    let stub = hostile_security(
        &dir,
        "security-oversized",
        "case \"$1\" in\n\
         \x20 find-generic-password) exec /bin/dd if=/dev/zero bs=1048576 count=12 ;;\n\
         esac\n\
         exit 1\n",
    );

    let registry = Registry::new(vec![Box::new(
        KeychainStore::new(stub, "keyless".to_owned()).with_timeout(Duration::from_secs(30)),
    )]);

    let argv = witness(&marker, "DECOY", 5);
    let (outcome, notes) = within(
        Duration::from_secs(60),
        "an oversized keychain value",
        move || run_with(&registry, &["DECOY"], &argv, &[]),
    );

    assert_eq!(witnessed(&marker), "<unset>", "nothing may be injected");
    assert_eq!(outcome.exit_code, 5, "the child's exit code must come back");
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("more than"),
        "the reason must name the cap rather than a timeout: {notes}"
    );

    // The negative control: a value just UNDER the cap still resolves, so the
    // assertion above is about the cap and not about `dd` output being rejected
    // on some other ground.
    let under = hostile_security(
        &dir,
        "security-large-but-legal",
        "case \"$1\" in\n\
         \x20 find-generic-password) exec /usr/bin/head -c 1048576 /dev/zero ;;\n\
         esac\n\
         exit 1\n",
    );
    let store =
        KeychainStore::new(under, "keyless".to_owned()).with_timeout(Duration::from_secs(30));
    // NUL bytes are valid UTF-8, so a megabyte of them is a legal `Secret`.
    assert!(
        store.resolve("DECOY").is_ok(),
        "a 1 MB value is under the cap and must still resolve"
    );
}

#[test]
fn a_healthy_keychain_lookup_still_resolves_under_the_new_deadline() {
    // The negative control for the two above: a deadline that refused every
    // lookup would pass both of them and break the product.
    let dir = scratch("keychain-still-works");
    let marker = dir.join("witness");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    let registry = Registry::new(vec![Box::new(KeychainStore::new(
        stub,
        "keyless".to_owned(),
    ))]);

    let (outcome, _) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(witnessed(&marker), DECOY_VALUE);
    assert_eq!(outcome.state, State::Injected);
}

// ---------------------------------------------------------------------------
// 3. The injected environment is what the kernel refuses.
// ---------------------------------------------------------------------------

#[test]
fn a_value_with_a_nul_byte_degrades_instead_of_killing_the_run() {
    // std refuses a NUL in an environment value before `execve`, and the
    // resulting message names the COMMAND: `cannot execute /bin/sh: nul byte
    // found`, exit 127, no child. The command was never the problem.
    let dir = scratch("nul-in-value");
    let marker = dir.join("witness");
    let registry = Registry::new(vec![Box::new(Hands(
        "hands",
        format!("decoy-{}NUL-inside-0042", '\0'),
    ))]);

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 42), &[]);

    assert_eq!(
        witnessed(&marker),
        "<unset>",
        "the child must run with an unmodified environment"
    );
    assert_eq!(
        outcome.exit_code, 42,
        "the child's exit code must come back"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("NUL"),
        "the reason must name the value, not the command: {notes}"
    );
    assert!(
        !notes.contains("cannot execute"),
        "the command must not be blamed: {notes}"
    );
}

#[test]
fn a_value_too_large_for_arg_max_degrades_instead_of_killing_the_run() {
    // `E2BIG`, `Argument list too long`, exit 127, no child. Measured on macOS:
    // 1.0 MB runs, 1.5 MB does not. Deliberately NOT pre-checked — the true
    // limit counts argv, the inherited environment and the pointer array
    // together, so the kernel is allowed to be the judge and its refusal is
    // turned into the documented degrade.
    let dir = scratch("value-too-large");
    let marker = dir.join("witness");
    let registry = Registry::new(vec![Box::new(Hands("hands", "z".repeat(2 * 1024 * 1024)))]);

    let argv = witness(&marker, "DECOY", 42);
    let (outcome, notes) = within(
        Duration::from_secs(90),
        "a 2 MB injected value",
        move || run_with(&registry, &["DECOY"], &argv, &[]),
    );

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(
        outcome.exit_code, 42,
        "the child's exit code must come back"
    );
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("unmodified"),
        "the caller must be told the environment was dropped: {notes}"
    );
}

// ---------------------------------------------------------------------------
// 4. A store VALUE choosing which program runs.
// ---------------------------------------------------------------------------

#[test]
fn a_secret_cannot_be_bound_to_a_variable_that_chooses_the_program() {
    for spec in [
        "PATH=DECOY",
        "IFS=DECOY",
        "ENV=DECOY",
        "BASH_ENV=DECOY",
        "SHELLOPTS=DECOY",
        "ZDOTDIR=DECOY",
        "CDPATH=DECOY",
        "LD_PRELOAD=DECOY",
        "LD_LIBRARY_PATH=DECOY",
        "LD_AUDIT=DECOY",
        "DYLD_INSERT_LIBRARIES=DECOY",
        "DYLD_LIBRARY_PATH=DECOY",
        // The bare form binds the name to itself, so it is the same hazard.
        "PATH",
        "LD_PRELOAD",
    ] {
        let refused = Binding::parse(spec)
            .err()
            .unwrap_or_else(|| panic!("`{spec}` must be refused"));
        assert!(
            refused.contains("cannot be bound"),
            "`{spec}` was refused for the wrong reason: {refused}"
        );
    }
}

#[test]
fn an_ordinary_variable_is_still_bindable() {
    // The negative control. A denylist that refused everything would pass the
    // test above and delete the product.
    for spec in [
        "GITHUB_TOKEN",
        "GH_TOKEN=work-pat",
        "DATABASE_URL",
        "STRIPE_KEY",
        // Near misses that must NOT be caught: a prefix rule that matched these
        // would refuse real names.
        "LDAP_PASSWORD",
        "PATHOLOGY_KEY",
        "MY_LD_PRELOAD",
    ] {
        assert!(
            Binding::parse(spec).is_ok(),
            "`{spec}` must remain bindable"
        );
    }
}

#[test]
fn a_refused_binding_costs_a_degrade_and_never_the_command() {
    // Refusing at parse time only helps if the refusal is a degrade. The child
    // must still run, with the REAL program — proved by the marker the real
    // `/bin/sh` writes, which a decoy on an injected `PATH` could not.
    let dir = scratch("path-binding-degrades");
    let marker = dir.join("witness");
    let registry = Registry::new(Vec::new());

    let mut notes: Vec<u8> = Vec::new();
    let unusable = vec!["PATH=DECOY".to_owned()];
    let outcome = keyless::cmd::run::run(
        keyless::cmd::run::RunRequest {
            bindings: &[],
            unusable: &unusable,
            argv: &witness(&marker, "PATH", 31),
            registry: &registry,
            audit: None,
            warnings: &["`PATH` cannot be bound to a secret".to_owned()],
            tty: TtyPolicy::Pipes,
        },
        &mut notes,
    )
    .expect("a refused binding must not stop the command");

    assert_ne!(
        witnessed(&marker),
        "<unset>",
        "the child must inherit the real PATH"
    );
    assert_eq!(outcome.exit_code, 31);
    assert_eq!(outcome.state, State::Degraded);
}

// ---------------------------------------------------------------------------
// 6. An argument clap refuses before `keyless` has any say.
// ---------------------------------------------------------------------------

#[test]
fn a_secret_flag_that_is_not_utf8_degrades_instead_of_exiting_2() {
    // `-s` was a `Vec<String>`, so clap rejected non-UTF-8 bytes and exited 2 —
    // a third way out with no child, decided before `dispatch` ran, while a
    // perfectly runnable command sat after the `--`.
    use std::os::unix::ffi::OsStringExt as _;

    let dir = scratch("secret-not-utf8");
    let marker = dir.join("witness");
    let config = dir.join("config.json");
    std::fs::write(&config, br#"{"stores":{"keychain":{"enabled":false}}}"#).expect("write config");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_keyless"))
        .arg("--config")
        .arg(&config)
        .arg("--no-audit")
        .arg("run")
        .arg("-s")
        .arg(OsString::from_vec(vec![0x41, 0xff, 0xfe, 0x42]))
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg("printf ran > \"$1\"; exit 33")
        .arg("sh")
        .arg(&marker)
        .output()
        .expect("the binary must run");

    assert_eq!(
        std::fs::read_to_string(&marker).ok().as_deref(),
        Some("ran"),
        "the child never ran; stderr was {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(33),
        "the child's exit code must come back, not clap's 2"
    );
}

// ---------------------------------------------------------------------------
// 7. Hangs where the child DID run and `keyless` never returned.
// ---------------------------------------------------------------------------

#[test]
fn a_backgrounded_grandchild_does_not_hold_the_process_open() {
    // The masked-pipes path. `sh` exits at once; the `sleep` it backgrounded
    // inherits the pipes and keeps them open, so the masking filters never see
    // end-of-file. Measured: 300 s. No secret: 0.20 s. A real pty: 0.01 s — so
    // the hang belongs to masking plus pipes, which is what every non-tty
    // caller gets: a CI job, a script, an agent's shell call.
    //
    // **Through the real binary, and that is load-bearing.** Bounding the drain
    // inside `run` is only half of it: a filter abandoned at the deadline is
    // still holding whatever it locked, so the first version of this fix moved
    // the hang from `run` into `main`'s closing `stdout().flush()` and a
    // library-level test saw nothing. Only the process can prove the process
    // exits.
    //
    // stdout goes to a FILE rather than a pipe for the same reason: `Command`'s
    // own `output()` waits for the pipe to reach end-of-file, so the harness
    // would inherit exactly the hang under test and report it as its own.
    let dir = scratch("backgrounded-grandchild");
    let marker = dir.join("witness");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{}"}}}},
                "secrets":{{"DECOY":{{}}}}}}"#,
            stub.display()
        ),
    )
    .expect("write config");
    let sink = std::fs::File::create(dir.join("out")).expect("create the sink");

    let started = Instant::now();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_keyless"))
        .args([
            "--config",
            &config.display().to_string(),
            "--no-audit",
            "run",
        ])
        .args(["-s", "DECOY", "--"])
        .args([
            "/bin/sh",
            "-c",
            &format!("printf ran > '{}'; sleep 45 &", marker.display()),
        ])
        .stdout(std::process::Stdio::from(sink))
        .status()
        .expect("the binary must run");
    let elapsed = started.elapsed();

    assert_eq!(
        std::fs::read_to_string(&marker).ok().as_deref(),
        Some("ran"),
        "the child did not run"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "the child's exit code must come back"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "the process did not exit until its grandchild did: {elapsed:?}"
    );
}

#[test]
fn the_output_of_a_child_that_exits_normally_is_not_truncated() {
    // That the bounded drain does not eat ordinary output — 100,000 lines,
    // ~1.2 MB, through the masking filters and out the other side intact.
    //
    // **This is NOT a control on the grace length, and saying so is the point.**
    // It was written as one, and the mutation refuted it: cutting
    // `PUMP_DRAIN_GRACE` from two seconds to one NANOSECOND leaves this test
    // green, at 4,000 lines and at 100,000 alike. Raising the volume cannot fix
    // that, because volume is not what is at stake.
    //
    // A pipe holds one buffer. A child writing more than that BLOCKS until the
    // filter drains it, so by the time the child exits — which is the only
    // thing `child.wait()` is waiting for — at most one buffer is still in
    // flight, whatever the total. The filters flush that in far less time than
    // `run` spends writing an audit row and returning.
    //
    // So the two-second grace is generous rather than load-bearing: what
    // protects a normal run's output is backpressure, and the grace exists only
    // for the abnormal case where a grandchild holds the pipe open forever.
    // Both facts are worth knowing, and neither is what a green tick here says.
    // Through the real binary, because a library-level test writes to this
    // process's own stdout and cannot count what arrived.
    let dir = scratch("drain-keeps-output");
    let stub = stub_security(&dir, &Stub::Returns(DECOY_VALUE));
    let sink = dir.join("out");
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{}"}}}},
                "secrets":{{"DECOY":{{}}}}}}"#,
            stub.display()
        ),
    )
    .expect("write config");

    let out = std::fs::File::create(&sink).expect("create the sink");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_keyless"))
        .args([
            "--config",
            &config.display().to_string(),
            "--no-audit",
            "run",
        ])
        .args(["-s", "DECOY", "--"])
        .args([
            "/bin/sh",
            "-c",
            "i=0; while [ $i -lt 100000 ]; do echo line-$i; i=$((i+1)); done",
        ])
        .stdout(std::process::Stdio::from(out))
        .status()
        .expect("the binary must run");

    assert!(status.success());
    let lines = std::fs::read_to_string(&sink)
        .expect("read the sink")
        .lines()
        .count();
    assert_eq!(lines, 100_000, "output was truncated by the drain");
}

#[test]
fn names_that_all_time_out_cost_one_deadline_and_not_one_each() {
    // Sequential resolution made N unresolvable names cost N × the deadline.
    // Measured: three names, 36.03 s before the child ran. Thirty is five
    // minutes. The command does still run at the end of it, which is worse than
    // failing — nothing on screen says that waiting is the correct thing to do.
    let dir = scratch("sequential-resolution");
    let marker = dir.join("witness");
    let stub = hostile_security(&dir, "security-slow", "sleep 120\n");

    let registry = Registry::new(vec![Box::new(
        KeychainStore::new(stub, "keyless".to_owned()).with_timeout(Duration::from_millis(1_500)),
    )]);

    let argv = witness(&marker, "A", 12);
    let started = Instant::now();
    let (outcome, _) = within(
        Duration::from_secs(60),
        "six names against a store that never answers",
        move || run_with(&registry, &["A", "B", "C", "D", "E", "F"], &argv, &[]),
    );
    let elapsed = started.elapsed();

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 12);
    assert_eq!(outcome.unresolved.len(), 6);
    // Six × 1.5 s is 9 s sequentially. Concurrently it is one deadline plus
    // change. 5 s separates them by a wide margin in both directions.
    assert!(
        elapsed < Duration::from_secs(5),
        "resolution is still sequential: six 1.5 s deadlines took {elapsed:?}"
    );
}

#[test]
fn a_daemon_timeout_from_config_is_clamped() {
    // `stores.daemon.timeout_ms` had no upper bound, so a config could name a
    // day. A config is not a trusted input — `--config` and `KEYLESS_CONFIG`
    // both name one — and an unbounded deadline is a wedged terminal written as
    // a number.
    let parsed: Config = serde_json::from_str(
        r#"{"stores":{"daemon":{"enabled":true,"socket":"/tmp/d.sock","timeout_ms":86400000}}}"#,
    )
    .expect("valid config");
    assert_eq!(
        parsed.stores.daemon.timeout(),
        Duration::from_millis(MAX_TIMEOUT_MS)
    );

    // The negative control: a sane value is untouched.
    let sane: Config = serde_json::from_str(
        r#"{"stores":{"daemon":{"enabled":true,"socket":"/tmp/d.sock","timeout_ms":750}}}"#,
    )
    .expect("valid config");
    assert_eq!(sane.stores.daemon.timeout(), Duration::from_millis(750));
}
