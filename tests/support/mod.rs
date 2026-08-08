//! Test fixtures.
//!
//! Every secret value used anywhere in this suite is a decoy invented here.
//! Nothing reads a real `.env`, a real credential file, or a real keychain
//! item: the `security` backend is exercised against a shell stub, which is why
//! [`crate::support::stub_security`] exists at all.

// Each integration test file is its own crate and uses a different subset.
#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// A decoy long enough to survive the minimum-needle filter and distinctive
/// enough that a grep for it in test output means a real leak.
pub const DECOY_VALUE: &str = "decoy-Zx91-nEVEr-a-REAL-secret-0042";

/// A decoy that only the fake Infisical CLI hands out.
///
/// Distinct from [`PROTON_DECOY`] on purpose: "which store answered?" is a
/// question the resolution-policy tests have to be able to ask, and two stores
/// returning the same string would make a wrong answer invisible.
pub const INFISICAL_DECOY: &str = "decoy-Inf7-company-vault-value-0101";

/// A decoy that only the fake Proton Pass CLI hands out.
pub const PROTON_DECOY: &str = "decoy-Pro9-personal-vault-value-0202";

/// What the vendor CLIs' output masking substitutes for a value.
pub const CONCEALED: &str = "<concealed by Proton Pass>";

/// A fresh, empty directory for one test.
pub fn scratch(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("keyless-tests-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("cannot create the scratch directory");
    path
}

/// How the `security` stub should behave.
pub enum Stub {
    /// Return a value, like a keychain item that exists.
    Returns(&'static str),
    /// Exit 44, which is how `security` reports `errSecItemNotFound`.
    NotFound,
    /// Fail in some other way, like a locked keychain.
    Errors,
    /// Report unhealthy for `list-keychains` as well as failing lookups.
    Dead,
}

/// Write an executable stand-in for `/usr/bin/security`.
///
/// The real binary is never invoked by this suite. A stub means the tests can
/// exercise every branch of the adapter — found, absent, backend error — with
/// no dependency on what is or is not in the developer's keychain.
pub fn stub_security(dir: &Path, behaviour: &Stub) -> PathBuf {
    // `add-generic-password` is answered by every stub that is not `Dead`, and it
    // records what arrived on stdin at `<dir>/security.stdin`. Whether a *read*
    // finds an item is orthogonal to whether a *write* is accepted, so the two are
    // separate branches rather than one shared exit status.
    //
    // The real binary reads the password from stdin twice; `cat` here is what lets
    // a test check that both copies arrived, and draining stdin is also what stops
    // the writer thread blocking on a full pipe.
    let write = format!(
        "\x20 add-generic-password) cat > '{}'; exit 0 ;;\n",
        dir.join("security.stdin").display()
    );
    let body = match behaviour {
        Stub::Returns(value) => format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
             \x20 find-generic-password) printf '%s\\n' '{value}'; exit 0 ;;\n\
             {write}\
             esac\n\
             exit 1\n"
        ),
        Stub::NotFound => format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
             \x20 find-generic-password) exit 44 ;;\n\
             {write}\
             esac\n\
             exit 1\n"
        ),
        Stub::Errors => format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
             {write}\
             esac\n\
             echo 'security: SecKeychainSearchCopyNext: User interaction is not allowed.' >&2\n\
             exit 51\n"
        ),
        Stub::Dead => {
            "#!/bin/sh\necho 'security: keychain is unavailable' >&2\nexit 1\n".to_owned()
        }
    };

    let path = dir.join("security-stub");
    std::fs::write(&path, body).expect("cannot write the security stub");
    make_executable(&path);
    path
}

/// How a fake network-backed CLI should behave.
///
/// The Infisical fake reproduces behaviour **measured** against `infisical`
/// 0.43.114 on 2026-08-06, including the exact stderr wording the adapter reads
/// to tell "the variable is unset" from "the CLI itself failed". The Proton
/// fake reproduces the shapes measured against `pass-cli` 2.2.5 on 2026-08-08
/// and recorded in `src/store/proton.rs` — the record keys, the reference
/// format and the coloured stderr — and, where nothing was measured, the
/// vendor's documented contract. A disagreement between this fake and the real
/// CLI is a bug in this fake, never a finding about the adapter.
pub enum Backend {
    /// Inject the value and exec the probe, as a working `run` does.
    Injects(&'static str),
    /// Exec the probe with nothing injected, then report the child's status the
    /// way the CLI does.
    Unset,
    /// Inject an empty value.
    Empty,
    /// Fail before the probe ever runs — no project, bad token, no network.
    OwnFailure,
    /// Never answer. Stands in for a black-holed connection.
    Hangs,
    /// Honour neither `--no-masking` nor the value: hand back the concealment
    /// placeholder. Only reachable on the Proton path.
    Concealed,
}

impl Backend {
    /// The shell fragment that runs, or declines to run, the probe.
    ///
    /// `$child` and `$key` are already set by the caller's preamble.
    fn body(&self) -> String {
        match self {
            Backend::Injects(value) => {
                format!("exec /usr/bin/env \"$key={value}\" \"$child\" \"$key\"\n")
            }
            Backend::Concealed => {
                format!("exec /usr/bin/env \"$key={CONCEALED}\" \"$child\" \"$key\"\n")
            }
            Backend::Empty => "exec /usr/bin/env \"$key=\" \"$child\" \"$key\"\n".to_owned(),
            // The wording is the vendor's, quoted because the adapter reads it.
            Backend::Unset => "\"$child\" \"$key\"\n\
                 status=$?\n\
                 if [ $status -ne 0 ]; then\n\
                 \x20 echo \"failed to wait for command termination: exit status $status\" >&2\n\
                 fi\n\
                 exit $status\n"
                .to_owned(),
            Backend::OwnFailure => "echo 'Please either run infisical init to connect to a \
                 project or pass in project id with --projectId flag' >&2\nexit 1\n"
                .to_owned(),
            Backend::Hangs => "sleep 60\n".to_owned(),
        }
    }
}

/// Write a stand-in for the `infisical` binary.
///
/// It records its own argv, one element per line, at `<dir>/infisical.argv`, so
/// a test can assert on the invocation the adapter built rather than on a copy
/// of the adapter's own list of flags.
pub fn stub_infisical(dir: &Path, behaviour: &Backend) -> PathBuf {
    let argv_log = dir.join("infisical.argv");
    let body = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         # Everything after `--` is the child command the adapter chose.\n\
         while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         shift\n\
         child=\"$1\"\n\
         key=\"$2\"\n\
         {body}",
        argv = argv_log.display(),
        body = behaviour.body()
    );
    write_stub(dir, "infisical-stub", &body)
}

/// The session directory the Proton fixtures pretend an agent token lives in.
///
/// The real CLI keeps one logged-in identity per session directory, so this is
/// the fixture's stand-in for "the scoped agent, not the full account".
pub const SCOPED_SESSION_DIR: &str = "/tmp/keyless-tests-scoped-agent-session";

/// How the `pass-cli` stub answers `item list`.
///
/// The name form of a Proton address turns a vault name and an item title into
/// this session's share id and item id, so every rule about which item answers —
/// one live match, several, none, a trashed one — is a rule about what comes
/// back here.
pub enum Listing {
    /// The vendor's JSON, verbatim. Written out by hand in each test rather
    /// than built by a helper: a fixture generated from the adapter's own idea
    /// of the shape would agree with it no matter what that shape became.
    Json(&'static str),
    /// The verb fails, the way it does for a vault the token cannot see:
    /// measured 2026-08-08, exit 1 and `Could not find vault <name>`.
    NoSuchVault,
}

impl Listing {
    /// An empty vault. The default for fixtures that use the reference form and
    /// never list anything.
    pub const EMPTY: Listing = Listing::Json(r#"{"items":[]}"#);

    fn body(&self) -> String {
        match self {
            Listing::Json(json) => format!("printf '%s' '{json}'\n exit 0\n"),
            Listing::NoSuchVault => "echo 'Error: Error finding vault' >&2\n exit 1\n".to_owned(),
        }
    }
}

/// Write a stand-in for the `pass-cli` binary that lists nothing.
pub fn stub_pass_cli(dir: &Path, behaviour: &Backend) -> PathBuf {
    stub_pass_cli_listing(dir, behaviour, &Listing::EMPTY)
}

/// Write a stand-in for the `pass-cli` binary.
///
/// Records its argv at `<dir>/pass-cli.argv`, the reason it was given at
/// `<dir>/pass-cli.reason` and the session directory it was pointed at
/// (`<dir>/pass-cli.session`, holding the literal `<unset>` when the adapter
/// exported nothing), and resolves the reference out of the `--env-file` the
/// adapter wrote — so a test can check each of those from the other side of the
/// interface rather than from a copy of the adapter's own list.
///
/// `item list` is answered from `listing`, and records its own argv at
/// `<dir>/pass-cli.list.argv` plus a tally at `<dir>/pass-cli.list.count` —
/// one line appended per invocation, which is how "the listing was memoised"
/// is checked by counting spawns rather than by reading the cache.
pub fn stub_pass_cli_listing(dir: &Path, behaviour: &Backend, listing: &Listing) -> PathBuf {
    let list_argv_log = dir.join("pass-cli.list.argv");
    let list_count_log = dir.join("pass-cli.list.count");
    let argv_log = dir.join("pass-cli.argv");
    let reason_log = dir.join("pass-cli.reason");
    let reference_log = dir.join("pass-cli.reference");
    let session_log = dir.join("pass-cli.session");
    let body = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'list' ]; then\n\
         \x20 printf '%s\\n' \"$@\" > '{list_argv}'\n\
         \x20 printf '%s' \"$PROTON_PASS_AGENT_REASON\" > '{reason}'\n\
         \x20 printf '%s' \"${{PROTON_PASS_SESSION_DIR-<unset>}}\" > '{session}'\n\
         \x20 echo one >> '{list_count}'\n\
         \x20 {listing}\
         fi\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         printf '%s' \"$PROTON_PASS_AGENT_REASON\" > '{reason}'\n\
         printf '%s' \"${{PROTON_PASS_SESSION_DIR-<unset>}}\" > '{session}'\n\
         # Resolve the reference the way the real CLI would: out of the env file.\n\
         env_file=''\n\
         for arg in \"$@\"; do\n\
         \x20 if [ \"$prev\" = '--env-file' ]; then env_file=\"$arg\"; fi\n\
         \x20 prev=\"$arg\"\n\
         done\n\
         if [ -n \"$env_file\" ]; then\n\
         \x20 sed -e 's/^[^=]*=//' \"$env_file\" > '{reference}'\n\
         fi\n\
         while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         shift\n\
         child=\"$1\"\n\
         key=\"$2\"\n\
         {body}",
        argv = argv_log.display(),
        list_argv = list_argv_log.display(),
        list_count = list_count_log.display(),
        listing = listing.body(),
        reason = reason_log.display(),
        session = session_log.display(),
        reference = reference_log.display(),
        body = behaviour.body()
    );
    write_stub(dir, "pass-cli-stub", &body)
}

/// A `pass-cli` stand-in that answers the three read-only discovery verbs.
///
/// `vault list`, `item list` and `item view`, and nothing else — a `run` against
/// this stub fails, which is deliberate: a discovery test that accidentally
/// resolved a value would be testing the wrong thing and would look fine.
///
/// `view` is the JSON `item view --output json` returns. It is written out by hand
/// at each call site so a fixture can hold a value in every value position, which
/// is what makes "no value reached the field list" a real assertion rather than a
/// restatement of the parser.
pub fn stub_pass_cli_discovery(dir: &Path, vaults: &str, listing: &str, view: &str) -> PathBuf {
    let vaults_file = dir.join("vaults.json");
    let listing_file = dir.join("listing.json");
    let view_file = dir.join("view.json");
    // Through files rather than inlined into the script: these fixtures hold
    // JSON with quotes and backslashes in them, and a single-quoted shell string
    // cannot carry an apostrophe. Inlining one made a stub fail to parse, and the
    // adapter then reported the shell's syntax error as though it were the
    // vendor's refusal.
    std::fs::write(&vaults_file, vaults).expect("write the vault fixture");
    std::fs::write(&listing_file, listing).expect("write the listing fixture");
    std::fs::write(&view_file, view).expect("write the view fixture");

    let body = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         printf '%s' \"$PROTON_PASS_AGENT_REASON\" > '{reason}'\n\
         printf '%s' \"${{PROTON_PASS_SESSION_DIR-<unset>}}\" > '{session}'\n\
         if [ \"$1\" = 'vault' ] && [ \"$2\" = 'list' ]; then cat '{vaults}'; exit 0; fi\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'list' ]; then cat '{listing}'; exit 0; fi\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'view' ]; then cat '{view}'; exit 0; fi\n\
         echo 'stub: this fixture answers discovery verbs only' >&2\n\
         exit 1\n",
        argv = dir.join("pass-cli.argv").display(),
        reason = dir.join("pass-cli.reason").display(),
        session = dir.join("pass-cli.session").display(),
        vaults = vaults_file.display(),
        listing = listing_file.display(),
        view = view_file.display(),
    );
    write_stub(dir, "pass-cli-discovery-stub", &body)
}

/// How many times the stub's `item list` ran. Zero when it never did.
pub fn listing_count(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("pass-cli.list.count"))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

/// What a stub recorded, one element per line, with the trailing blank dropped.
pub fn recorded_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} was never written ({error})", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

/// What a stub recorded as a single string.
pub fn recorded(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} was never written ({error})", path.display()))
}

fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap_or_else(|error| panic!("cannot write {name}: {error}"));
    make_executable(&path);
    path
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .expect("cannot stat the stub")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("cannot chmod the stub");
    }
}

/// A child command that proves it ran.
///
/// It writes the value of `$var` — or the literal `<unset>` when the variable
/// is absent — into `marker`, then exits with `code`. That single file answers
/// both questions a never-block test must ask: did the child run at all, and
/// did it see an environment we did or did not modify.
pub fn witness(marker: &Path, var: &str, code: i32) -> Vec<OsString> {
    vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(format!(
            "printf '%s' \"${{{var}-<unset>}}\" > \"$1\"; exit {code}"
        )),
        OsString::from("sh"),
        OsString::from(marker),
    ]
}

/// A child command that prints `text` to stdout and exits 0.
pub fn echoes(text: &str) -> Vec<OsString> {
    vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from("printf '%s' \"$1\""),
        OsString::from("sh"),
        OsString::from(text),
    ]
}

/// Run one command through the library and return what happened, plus what the
/// caller would have seen on stderr.
///
/// Shared rather than copied into each test crate: every never-block property
/// asks the same three questions of the same call, and two copies of the setup
/// would eventually answer them differently.
pub fn run_with(
    registry: &keyless::store::Registry,
    specs: &[&str],
    argv: &[OsString],
    warnings: &[String],
) -> (keyless::cmd::run::Outcome, String) {
    run_with_tty(
        registry,
        specs,
        argv,
        warnings,
        keyless::cmd::run::TtyPolicy::Pipes,
    )
}

/// The same, choosing how the child's terminal is arranged.
///
/// The policy is named rather than left to `Auto` on purpose. `Auto` reads the
/// *test harness's* stdio, which is a pipe under `cargo test` and a terminal
/// under `cargo test -- --nocapture` from a shell — so an `Auto` here would make
/// these tests take a different code path depending on how they were invoked.
pub fn run_with_tty(
    registry: &keyless::store::Registry,
    specs: &[&str],
    argv: &[OsString],
    warnings: &[String],
    tty: keyless::cmd::run::TtyPolicy,
) -> (keyless::cmd::run::Outcome, String) {
    use keyless::cmd::run::{Binding, RunRequest, run};

    let bindings: Vec<Binding> = specs
        .iter()
        .map(|spec| Binding::parse(spec).expect("test specs are well formed"))
        .collect();
    let mut notes: Vec<u8> = Vec::new();
    let outcome = run(
        RunRequest {
            bindings: &bindings,
            unusable: &[],
            argv,
            registry,
            audit: None,
            warnings,
            tty,
        },
        &mut notes,
    )
    .expect("run must not fail when a command was given");
    (outcome, String::from_utf8_lossy(&notes).into_owned())
}

/// What the witness child recorded.
pub fn witnessed(marker: &Path) -> String {
    std::fs::read_to_string(marker).unwrap_or_else(|error| {
        panic!(
            "the child did not run: {} is unreadable ({error})",
            marker.display()
        )
    })
}

// ---------------------------------------------------------------------------
// Daemon fixtures
// ---------------------------------------------------------------------------

use keyless::attest::Policy;
use keyless::daemon::config::{DaemonConfig, DaemonStores, FileStoreConfig, PeerConfig};
use keyless::daemon::{Daemon, Running};
use keyless::ipc::peer;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

/// This process's own verified identity.
///
/// Both ends of a socketpair belong to us, so attesting one end is attesting
/// ourselves — which is how a test pins the test binary as an authorised
/// client without shelling out to anything.
pub fn own_identity() -> peer::PeerIdentity {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    peer::identify(a.as_fd()).expect("this process must be able to attest itself")
}

/// A policy that authorises this test process and nothing else.
pub fn policy_allowing_self() -> Policy {
    let me = own_identity();
    Policy::new().allow_uid(me.uid).allow_image(me.code_hash)
}

/// A policy that authorises this process's uid but no image at all.
pub fn policy_allowing_nobody() -> Policy {
    Policy::new().allow_uid(own_identity().uid)
}

/// Write a daemon-side secrets file at mode 0600.
pub fn write_secrets(path: &Path, entries: &[(&str, &str)]) {
    let body: std::collections::BTreeMap<&str, &str> = entries.iter().copied().collect();
    std::fs::write(path, serde_json::to_vec(&body).expect("encode")).expect("write secrets");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

/// A short, unique socket path for a scratch directory.
///
/// `sockaddr_un.sun_path` is 104 bytes on macOS, and the platform temp
/// directory is already about half of that. A socket named inside a scratch
/// directory therefore binds fine for a short test name and fails with
/// `path must be shorter than SUN_LEN` for a long one — a limit that shows up
/// as a test-naming problem rather than as the platform constraint it is.
///
/// So the socket goes somewhere short and is named by a hash of the directory
/// it belongs to. The daemon removes it on shutdown.
pub fn short_socket_path(dir: &Path) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dir.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    PathBuf::from("/tmp").join(format!("kl{:x}.sock", hasher.finish()))
}

/// A daemon config rooted in `dir`, backed by a file store.
pub fn daemon_config(dir: &Path) -> DaemonConfig {
    DaemonConfig {
        socket: short_socket_path(dir),
        audit: dir.join("audit.jsonl"),
        cache_ttl_seconds: 60,
        idle_timeout_seconds: 5,
        peer: PeerConfig::default(),
        stores: DaemonStores {
            file: FileStoreConfig {
                enabled: true,
                path: dir.join("secrets.json"),
            },
            ..DaemonStores::default()
        },
        names: Vec::new(),
    }
}

/// Bind and start serving.
pub fn start_daemon(config: &DaemonConfig, policy: Policy) -> Running {
    let daemon = Daemon::bind(config, policy).expect("bind the daemon");
    Running::spawn(daemon).expect("start the accept loop")
}

/// A session config that routes through `socket` and has no local fallback.
pub fn client_config(socket: &Path, timeout_ms: u64) -> keyless::config::Config {
    serde_json::from_str(&format!(
        r#"{{"stores":{{"daemon":{{"enabled":true,"socket":"{}","timeout_ms":{timeout_ms}}}}}}}"#,
        socket.display()
    ))
    .expect("valid client config")
}

/// Locate one of the `examples/` binaries that `cargo test` has built.
///
/// The test binary lives at `target/<profile>/deps/<name>-<hash>`, so the
/// examples are two directories up and one across. Asserted rather than
/// assumed: a silently missing peer would make an adversarial test pass by
/// never running the attack.
pub fn example_binary(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile>/deps/<test>");
    let path = profile_dir.join("examples").join(name);
    assert!(
        path.is_file(),
        "example `{name}` was not built; expected it at {}",
        path.display()
    );
    assert_not_stale(&path);
    path
}

/// Refuse to run an attack against a peer built from older source.
///
/// `cargo test --test <name>` does **not** rebuild examples. So editing a peer
/// and re-running one test file exercises the previous binary, and every
/// adversarial test passes or fails for reasons that have nothing to do with
/// the change being made. That is not hypothetical — it cost two debugging
/// cycles on this suite, during which two correct fixes read as no-ops.
///
/// The whole run is aborted rather than the test skipped: a skipped security
/// test is a green one.
fn assert_not_stale(binary: &Path) {
    let built = match std::fs::metadata(binary).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(_) => return,
    };
    let sources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    let newest = newest_mtime(&sources);
    if let Some(newest) = newest
        && newest > built
    {
        panic!(
            "{} is older than the sources in {}. `cargo test --test <name>` does not \
             rebuild examples — run `cargo build --examples` first, or `cargo test` \
             with no --test filter.",
            binary.display(),
            sources.display()
        );
    }
}

fn newest_mtime(dir: &Path) -> Option<std::time::SystemTime> {
    let mut newest = None;
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let candidate = if path.is_dir() {
            newest_mtime(&path)
        } else {
            entry.metadata().and_then(|m| m.modified()).ok()
        };
        if let Some(candidate) = candidate
            && newest.is_none_or(|current| candidate > current)
        {
            newest = Some(candidate);
        }
    }
    newest
}

/// A `security` stand-in that takes `millis` to answer.
///
/// Coalescing is only observable while a request is in flight, so a test that
/// wants to see it needs a backend slow enough to have an in-flight window.
/// This is that backend: a real subprocess on the real adapter path, just a
/// slow one.
pub fn slow_store_stub(dir: &Path, value: &str, millis: u64) -> PathBuf {
    let seconds = millis as f64 / 1000.0;
    let body = format!(
        "#!/bin/sh\n\
         case \"$1\" in\n\
         \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
         \x20 find-generic-password) sleep {seconds}; printf '%s\\n' '{value}'; exit 0 ;;\n\
         esac\n\
         exit 1\n"
    );
    let path = dir.join("security-slow");
    std::fs::write(&path, body).expect("cannot write the slow stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    path
}
