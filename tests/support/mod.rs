//! Test fixtures.
//!
//! Every secret value used anywhere in this suite is a decoy invented here.
//! Nothing reads a real `.env`, a real credential file, or a real keychain
//! item: the `security` backend is exercised against a shell stub, which is why
//! [`crate::support::stub_security`] exists at all.

// Each integration test file is its own crate and uses a different subset.
#![allow(dead_code)]

/// The bound that turns a hang into a red test. Its own file so a unit test in
/// `src/` can `include!` the same source rather than keep a second copy.
mod within;
// Only the suites that drive a child or a terminal need the bound, and each
// integration test file is its own crate — same reason as the `dead_code` allow
// above, which does not cover a re-export.
#[allow(unused_imports)]
pub use within::{PATIENCE, within};

/// A socket path that fits in `sockaddr_un`. Its own file for the same reason
/// as `within` above: the unit tests in `src/` bind sockets too, they cannot
/// see `tests/`, and a second copy of this would be free to drift from this one
/// — which is how three of them ended up depending on `TMPDIR` being short.
mod short_socket;
#[allow(unused_imports)]
pub use short_socket::short_socket_path;

/// Creating a file a case is going to execute. Its own file for the same reason
/// as the two above: `tests/` builds executables in several binaries, and the
/// shape it replaces — write it, then `chmod` it — is the one anybody writes
/// from memory, so a second copy would drift straight back into it.
mod executable;
#[allow(unused_imports)]
pub use executable::{install_executable, install_executable_copy};

/// A real pty for a test that must confirm a prompt at a terminal. Its own
/// file for the same reason as the three above: only the suites that drive a
/// verb asking a person need it.
pub mod terminal;

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

/// A decoy that only the fake 1Password CLI hands out.
pub const ONEPASSWORD_DECOY: &str = "decoy-1Pw3-company-vault-value-0505";

/// What the 1Password CLI's output masking substitutes for a value.
///
/// Measured: the literal is in the `op` 2.39.0 binary.
pub const ONEPASSWORD_CONCEALED: &str = "<concealed by 1Password>";

/// The name of a second secret sitting at the same Infisical path as `DECOY`.
///
/// Nothing ever asks for it. It exists so that "only the names that were asked
/// for reach the child" has something to be FALSE about: against a vault
/// holding one name, a tool that narrows and a tool that does not look
/// identical.
pub const NEIGHBOUR_KEY: &str = "NEIGHBOUR";

/// The value behind [`NEIGHBOUR_KEY`]. Distinct from every other decoy here, so
/// an assertion that names it cannot be satisfied by another store's answer.
pub const NEIGHBOUR_DECOY: &str = "decoy-Nb42-the-name-nobody-asked-for-0303";

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

/// Write a config at `<dir>/config.json` whose keychain store is a stub, with
/// `secrets` as its declarations.
///
/// `secrets` is the caller's because it is the only half that differs between
/// the four sites this replaced — one of them declares a second name to prove
/// the narrowing, the rest declare `DECOY` alone. The store half is identical
/// at all four and now has one home.
///
/// # Why the deadline is written here at all
///
/// `timeout_ms` is a CEILING, never a measurement: not one case using this
/// config asserts anything about how long the stub took. Left out, the store
/// inherits `keyless::config::DEFAULT_TIMEOUT_MS` — the PRODUCTION default, ten
/// seconds — and the only thing that number then decides is how loaded the
/// machine has to be before a passing test reports a failure. So the value is
/// `keyless::config::MAX_TIMEOUT_MS`, the top of the range the tool will
/// honour, which is the nearest a config can be spelled to the "no deadline"
/// these cases actually want.
///
/// It was written into four copies of this literal before this function
/// existed, and `tests/suite_hygiene.rs`'s deadline gate is what refuses a
/// fifth that leaves it out.
pub fn keychain_stub_config(dir: &Path, behaviour: &Stub, secrets: &str) -> PathBuf {
    let stub = stub_security(dir, behaviour);
    let path = dir.join("config.json");
    let body = format!(
        r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{binary}","timeout_ms":60000}}}},
            "secrets":{secrets}}}"#,
        binary = stub.display(),
    );
    std::fs::write(&path, body).expect("write config");
    path
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

    install_executable(&dir.join("security-stub"), &body)
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
    /// Inject the WHOLE path's worth of secrets — [`INFISICAL_DECOY`] under
    /// `DECOY` and [`NEIGHBOUR_DECOY`] under [`NEIGHBOUR_KEY`], which nobody
    /// asks for — and then run whatever follows `--`, verbatim.
    ///
    /// That is what `infisical run` does, and [`Backend::Injects`] does not
    /// model it: it sets exactly the one name the probe named, so a tool that
    /// handed its child an entire vault would look identical against it.
    InjectsWholeVault,
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
    /// Read what to do from a control file beside the stub, on every call, and
    /// hand out a value that is different on each one.
    ///
    /// # Why the other variants cannot stand in
    ///
    /// Every arm above is fixed when the stub is written, so one test gets one
    /// behaviour for its whole run. The daemon's cache is only observable
    /// ACROSS calls — a value held while the vendor is slow, a value kept while
    /// it cannot connect, a value evicted when it answers about the item — so a
    /// case about it needs the vendor to answer one way and then another,
    /// against a daemon that keeps running in between. The two timings on offer
    /// are also instant and [`Backend::Hangs`]'s sixty seconds, and neither is a
    /// vendor that is merely slower than a window.
    ///
    /// So this arm reads [`set_next_call`]'s file each time it runs, and
    /// [`vendor_call_count`] is the tally it appends to. Which value came back
    /// then answers "was the store asked?" on its own — see [`vendor_decoy`].
    Controlled,
}

impl Backend {
    /// The shell fragment that runs, or declines to run, the probe.
    ///
    /// `$child` and `$key` are already set by the caller's preamble. `dir` is
    /// the stub's own directory, which only [`Backend::Controlled`] reads —
    /// every other arm decides everything when the stub is written.
    fn body(&self, dir: &Path) -> String {
        match self {
            Backend::Injects(value) => {
                format!("exec /usr/bin/env \"$key={value}\" \"$child\" \"$key\"\n")
            }
            // Two deliberate differences from the arm above, and both are the
            // point. Both names are LITERAL, because what a vault holds does
            // not depend on what was asked for — `"$key"` would make the
            // fixture's contents follow the request, which is the coupling the
            // case using this exists to deny. And `"$@"` rather than `"$child"
            // "$key"`, because the vendor runs whatever it was handed after
            // `--`: a fixture that re-spells the probe's two arguments could
            // not show a longer command nested under it. For the two-argument
            // probe the two spellings are identical.
            Backend::InjectsWholeVault => format!(
                "exec /usr/bin/env \"DECOY={INFISICAL_DECOY}\" \
                 \"{NEIGHBOUR_KEY}={NEIGHBOUR_DECOY}\" \"$@\"\n"
            ),
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
            // The tally is appended BEFORE anything else this call does, so a
            // vendor that is sleeping or about to fail is still counted as
            // having been asked. A test that waits for the count to move is
            // therefore waiting for the spawn, never for the answer.
            //
            // `wc -l` is left-padded on this platform, hence the `tr`.
            Backend::Controlled => format!(
                "echo one >> '{calls}'\n\
                 call=$(wc -l < '{calls}' | tr -d ' ')\n\
                 next=$(cat '{next}' 2>/dev/null || echo answers)\n\
                 case \"$next\" in\n\
                 \x20 slow:*) sleep \"${{next#slow:}}\" ;;\n\
                 \x20 fails:*) printf '%s\\n' \"${{next#fails:}}\" >&2; exit 1 ;;\n\
                 esac\n\
                 value=$(printf '%s%03d' '{stem}' \"$call\")\n\
                 exec /usr/bin/env \"$key=$value\" \"$child\" \"$key\"\n",
                calls = vendor_calls_path(dir).display(),
                next = next_call_path(dir).display(),
                stem = CONTROLLED_STEM,
            ),
        }
    }
}

/// What the controlled stand-in does on its next call.
///
/// A separate type from [`Backend`], because it names a MOMENT rather than a
/// fixture: one stub meets several of these while one daemon keeps running.
pub enum NextCall {
    /// Answer at once, with this call's own decoy.
    Answers,
    /// Sleep this long, then answer. For a vendor that has to lose a race
    /// against one of the daemon's windows.
    Slow(std::time::Duration),
    /// Print this on stderr and exit 1, having run no child. The adapter reads
    /// the sentence to decide whether the vendor answered ABOUT the item or
    /// never reached the service, so the wording is the input under test.
    Fails(&'static str),
}

/// The stem every controlled decoy is built on.
///
/// Long and distinctive for the reason every other decoy here is: a grep for it
/// in output that should hold no value means a real leak.
const CONTROLLED_STEM: &str = "decoy-Wrm4-controlled-vendor-answer-";

/// The decoy [`Backend::Controlled`] hands out on its `call`th call.
///
/// Different on every call, which is what lets a case assert "the store was not
/// asked" by comparing a string rather than by timing anything: a value from
/// call 1 coming back a second time cannot have been fetched.
///
/// Two calls in flight at once may read the same tally and hand out the same
/// decoy. A case that overlaps two calls asserts on [`vendor_call_count`]
/// instead.
#[must_use]
pub fn vendor_decoy(call: usize) -> String {
    format!("{CONTROLLED_STEM}{call:03}")
}

/// Tell the controlled stand-in what to do from now on.
///
/// Takes effect on the next call to START. A call already running has read the
/// file already, so a test that needs the change to bite waits for the running
/// one first — [`vendor_call_count`] is how.
pub fn set_next_call(dir: &Path, next: &NextCall) {
    let encoded = match next {
        NextCall::Answers => "answers".to_owned(),
        NextCall::Slow(delay) => format!("slow:{}", delay.as_secs_f64()),
        NextCall::Fails(said) => {
            assert!(
                !said.contains('\n'),
                "a refusal is one line: the stub reads this file with `cat` and matches on \
                 its prefix, so a second line would arrive as part of the sentence"
            );
            format!("fails:{said}")
        }
    };
    std::fs::write(next_call_path(dir), encoded).expect("write the vendor's next call");
}

/// How many times the controlled stand-in has been asked for a value.
///
/// Counts the value-reading verb only. `item list` has its own tally — see
/// [`listing_count`] — because a listing is memoised for its own window and a
/// combined count could not say which verb moved.
#[must_use]
pub fn vendor_call_count(dir: &Path) -> usize {
    std::fs::read_to_string(vendor_calls_path(dir))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

fn vendor_calls_path(dir: &Path) -> PathBuf {
    dir.join("vendor.calls")
}

fn next_call_path(dir: &Path) -> PathBuf {
    dir.join("vendor.next")
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
        body = behaviour.body(dir)
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

/// The argument walk every `pass-cli` stand-in starts with.
///
/// # Why it is factored out rather than copied
///
/// It is not boilerplate: it is the vendor's own parse, measured against
/// `pass-cli` 2.2.5 and documented at [`stub_pass_cli_discovery`] — clap reads
/// any standalone argument beginning with a single `-` as a short-flag cluster
/// and refuses the command with exit 2, whatever option came before it. In two
/// copies, a correction measured against a new vendor release lands in one and
/// leaves the other green against a stub that no longer imitates the vendor.
///
/// Sets `env_file` from either spelling of `--env-file`, and stops at `--` the
/// way clap does, because everything after it belongs to the child.
fn vendor_arg_walk() -> &'static str {
    "# Parse like the vendor up to `--`: both spellings of an option value,\n\
     # and a refusal for anything the vendor reads as a short-flag cluster.\n\
     # Ahead of every verb, because clap parses before it dispatches.\n\
     env_file=''\n\
     for arg in \"$@\"; do\n\
     \x20 if [ \"$arg\" = '--' ]; then break; fi\n\
     \x20 case \"$arg\" in\n\
     \x20   --env-file=*) env_file=\"${arg#--env-file=}\" ;;\n\
     \x20   --*|-) ;;\n\
     \x20   -*) echo \"error: unexpected argument '$arg' found\" >&2; exit 2 ;;\n\
     \x20 esac\n\
     \x20 if [ \"$prev\" = '--env-file' ]; then env_file=\"$arg\"; fi\n\
     \x20 prev=\"$arg\"\n\
     done\n"
}

/// What a `pass-cli` stand-in does once every listing verb has declined: record
/// the invocation, resolve the reference out of the env file the way the real
/// CLI would, and hand `$child` and `$key` to a [`Backend`].
///
/// Factored for [`vendor_arg_walk`]'s reason. The env-file resolution is the
/// half a test reads back to assert which item was addressed, so two copies of
/// it is two ways for that assertion to stop meaning the same thing.
fn vendor_run_tail(dir: &Path, behaviour: &Backend) -> String {
    format!(
        "printf '%s\\n' \"$@\" > '{argv}'\n\
         printf '%s' \"$PROTON_PASS_AGENT_REASON\" > '{reason}'\n\
         printf '%s' \"${{PROTON_PASS_SESSION_DIR-<unset>}}\" > '{session}'\n\
         # Resolve the reference the way the real CLI would: out of the env file.\n\
         if [ -n \"$env_file\" ]; then\n\
         \x20 sed -e 's/^[^=]*=//' \"$env_file\" > '{reference}'\n\
         fi\n\
         while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         shift\n\
         child=\"$1\"\n\
         key=\"$2\"\n\
         {body}",
        argv = dir.join("pass-cli.argv").display(),
        reason = dir.join("pass-cli.reason").display(),
        session = dir.join("pass-cli.session").display(),
        reference = dir.join("pass-cli.reference").display(),
        body = behaviour.body(dir),
    )
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
    let body = format!(
        "#!/bin/sh\n\
         {walk}\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'list' ]; then\n\
         \x20 printf '%s\\n' \"$@\" > '{list_argv}'\n\
         \x20 printf '%s' \"$PROTON_PASS_AGENT_REASON\" > '{reason}'\n\
         \x20 printf '%s' \"${{PROTON_PASS_SESSION_DIR-<unset>}}\" > '{session}'\n\
         \x20 echo one >> '{list_count}'\n\
         \x20 {listing}\
         fi\n\
         {tail}",
        walk = vendor_arg_walk(),
        list_argv = dir.join("pass-cli.list.argv").display(),
        list_count = dir.join("pass-cli.list.count").display(),
        listing = listing.body(),
        reason = dir.join("pass-cli.reason").display(),
        session = dir.join("pass-cli.session").display(),
        tail = vendor_run_tail(dir, behaviour),
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
///
/// # It parses arguments the way the vendor does, and refuses the same ones
///
/// A stub that answers on `$1` and `$2` and ignores the rest cannot fail on a
/// malformed invocation, so every test using it is blind to the one thing an
/// argument vector can get wrong. The real binary parses with clap, which reads
/// ANY standalone argument beginning with a single `-` as a short-flag cluster —
/// whatever option came before it. Measured against `pass-cli` 2.2.5 on
/// 2026-08-08:
///
/// ```text
/// $ pass-cli item list --vault-name -dashvault --output json
/// error: unexpected argument '-d' found
/// exit 2
/// ```
///
/// Proton ids are base64url, so about one in 64 begins with `-`. That is not a
/// hypothetical: it was found on a real item, whose leading `-` meant `keyless
/// fields` could not inspect it at all. The check below reproduces the refusal — exit 2, the vendor's
/// wording — so an adapter that hands a bare `-…` to this fixture fails here
/// rather than passing and failing in front of a user.
///
/// A lone `-` is left alone: it is the vendor's own spelling for stdin, and clap
/// treats it as a value rather than as flags.
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
         for arg in \"$@\"; do\n\
         \x20 case \"$arg\" in\n\
         \x20   --*|-) ;;\n\
         \x20   -*) echo \"error: unexpected argument '$arg' found\" >&2; exit 2 ;;\n\
         \x20 esac\n\
         done\n\
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

/// A `pass-cli` stand-in that answers all four verbs a catalogue exercises.
///
/// `vault list`, `item list`, `item view` AND `run`, which no other fixture
/// does: a catalogue test needs the daemon to enumerate and then to resolve
/// what it enumerated, and a stub that answers only the discovery verbs turns
/// "the retry resolved" into "the retry could never have resolved".
///
/// Each fixture is read from a FILE on every call, so a test can change what
/// the vault holds while the daemon keeps running — which is the whole point:
/// the claim under test is that a new item becomes usable with no restart, and
/// a fixture baked into the script at write time cannot express that.
///
/// Tallies one line per verb into `pass-cli.vault.count`,
/// `pass-cli.list.count` and `pass-cli.view.count`, so a test asserts what was
/// NOT spawned by counting rather than by reading the adapter's cache.
pub fn stub_pass_cli_catalogue(
    dir: &Path,
    behaviour: &Backend,
    vaults: &str,
    listing: &str,
    view: &str,
) -> PathBuf {
    std::fs::write(dir.join("vaults.json"), vaults).expect("write the vault fixture");
    set_catalogue_listing(dir, listing);
    std::fs::write(dir.join("view.json"), view).expect("write the view fixture");

    let body = format!(
        "#!/bin/sh\n\
         {walk}\
         if [ \"$1\" = 'vault' ] && [ \"$2\" = 'list' ]; then\n\
         \x20 echo one >> '{vault_count}'; cat '{vaults}'; exit 0; fi\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'list' ]; then\n\
         \x20 echo one >> '{list_count}'; cat '{listing}'; exit 0; fi\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'view' ]; then\n\
         \x20 echo one >> '{view_count}'; cat '{view}'; exit 0; fi\n\
         {tail}",
        walk = vendor_arg_walk(),
        vaults = dir.join("vaults.json").display(),
        listing = dir.join("listing.json").display(),
        view = dir.join("view.json").display(),
        vault_count = dir.join("pass-cli.vault.count").display(),
        list_count = dir.join("pass-cli.list.count").display(),
        view_count = dir.join("pass-cli.view.count").display(),
        tail = vendor_run_tail(dir, behaviour),
    );
    write_stub(dir, "pass-cli-catalogue-stub", &body)
}

/// Change what `item list` answers, while the daemon keeps running.
pub fn set_catalogue_listing(dir: &Path, listing: &str) {
    std::fs::write(dir.join("listing.json"), listing).expect("write the listing fixture");
}

/// How many times the stub's `vault list` ran.
pub fn vault_list_count(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("pass-cli.vault.count"))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

/// How many times the stub's `item view` ran.
pub fn view_count(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("pass-cli.view.count"))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

/// A `pass-cli` stand-in whose session is dead: every verb is refused.
///
/// The two stderr lines are the vendor's own, measured against `pass-cli` 2.2.5
/// on 2026-08-08 by pointing `PROTON_PASS_SESSION_DIR` at an empty scratch
/// directory. Quoted rather than invented, because the adapter's health message
/// is built from them and an approximation would let the wording drift.
///
/// This is what an expired agent token looks like from the outside: the binary is
/// on `PATH`, the session directory exists, and nothing at all can be read. Both
/// local preconditions pass, which is why a health check that stops at them
/// reports `ok`.
pub fn stub_pass_cli_dead_session(dir: &Path) -> PathBuf {
    let body = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         echo 'ERROR pass-cli/src/main.rs:332: Command is not logout there is no session' >&2\n\
         echo 'Error: This operation requires an authenticated client' >&2\n\
         exit 1\n",
        argv = dir.join("pass-cli.argv").display(),
    );
    write_stub(dir, "pass-cli-dead-session-stub", &body)
}

/// How many times the stub's `item list` ran. Zero when it never did.
pub fn listing_count(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("pass-cli.list.count"))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The vendor's store semantics, as a stand-in.
//
// Every fixture above answers a VERB. This one models what `pass-cli` does to
// the session directory around the verb — which key it resolves, what it
// deletes, and which of those deletions happen on a plain read. Those are the
// facts this crate's session design is correct BECAUSE of, and until this
// fixture existed the suite held none of them: a vendor release that changed
// one broke the daemon in production with every test still green.
//
// # Where each behaviour was read from
//
// `pass-cli` 2.3.3. Three sources were available and they agree here:
//
// - the public repository `protonpass/pass-cli` at tag `2.3.3`, which resolves
//   to commit `51a4c9b`. Every line number below is that commit's.
// - the installed binary, `/usr/local/libexec/pass-cli --version` reporting
//   `2.3.3 (0d7235d)`. That second hash is a build id and resolves to no
//   commit in the public repository, so the TAG is what ties the two together.
// - a local clone, whose `HEAD` was confirmed to be the commit `2.3.3` points
//   at rather than trusted to be current.
//
// A behaviour that could not be read is modelled anyway and SAYS SO at the
// line that models it, so a reader never has to assume a citation was checked.
// The one place that bites: the SDK crate the CLI depends on is not in that
// repository, so anything happening inside a `client.*` call is inferred from
// the CLI's own handling of what comes back.
//
// # A disagreement between this fixture and the real binary is a finding
//
// The other Proton fixtures carry the opposite rule — a disagreement there is a
// bug in the fixture. Here it is the point: this file is the written-down half
// of the vendor's contract, so a case going red against a new `pass-cli` means
// the contract moved, and the diff that makes it green again is the record of
// what moved.
// ---------------------------------------------------------------------------

/// How long each of the vendor's own spans lasts, in the stand-in.
///
/// Every field is a real span in `pass-cli` with a real duration — a server
/// round trip, an `unlink` sweep, an encrypt-and-rename — and every one of them
/// is a window another process can act inside. Production hits them at whatever
/// width the machine gives them; a case that needs a particular interleaving
/// sets them so the ordering is arithmetic rather than luck.
///
/// All zero by default, which is a vendor with no windows at all: the fixture
/// that does not care about concurrency pays nothing for these.
pub struct VendorStore {
    /// `login` holds the directory open this long before writing
    /// `session.json` — the server round trip.
    pub login_delay: std::time::Duration,

    /// `logout` waits this long between revoking the session AT THE ACCOUNT and
    /// deleting anything locally.
    ///
    /// Those are two separate acts in `commands/logout.rs:46-67`: `client
    /// .logout()` first, then `remove_key()`, then `remove_local_data()`. From
    /// the instant the first returns, every other child holding that session is
    /// answered "logged out" by the server — so this is the window in which a
    /// concurrent reader turns into a deleter.
    pub logout_delay: std::time::Duration,

    /// How long `remove_dir_all` takes between listing the directory and the
    /// final `rmdir`.
    ///
    /// `tokio::fs::remove_dir_all` (`commands/logout.rs:34`) lists once and
    /// unlinks by name, so an entry created after the listing survives and the
    /// final `rmdir` fails with `ENOTEMPTY`. That failure is the fingerprint
    /// this crate's own incident began with, and it is only reachable because
    /// the two steps are not one atomic act.
    pub rmdir_window: std::time::Duration,

    /// How long the invalidation-time `session.json` write waits before it
    /// resolves the key.
    ///
    /// A read whose session the account revoked does two things and they are
    /// not ordered with respect to each other: the SDK's callback deletes the
    /// store, and the store schedules its own `session.json` write on a
    /// background task. This is when that task starts.
    pub persist_key_delay: std::time::Duration,

    /// How long that write takes between resolving the key and the rename
    /// landing — the encrypt.
    ///
    /// This is the span that makes a mismatch possible at all: the key is read
    /// at one instant and the file it encrypts is renamed into place at a
    /// later one, and a deleter working in between leaves a `session.json` on
    /// disk under a key no surviving `local.key` holds. That state is terminal
    /// — the next child mints a fresh key and cannot decrypt it.
    pub persist_write_delay: std::time::Duration,
}

impl VendorStore {
    /// A vendor with no windows: every span above is instant.
    pub const INSTANT: VendorStore = VendorStore {
        login_delay: std::time::Duration::ZERO,
        logout_delay: std::time::Duration::ZERO,
        rmdir_window: std::time::Duration::ZERO,
        persist_key_delay: std::time::Duration::ZERO,
        persist_write_delay: std::time::Duration::ZERO,
    };
}

/// The state a fixture puts the vendor's own session record into.
///
/// Two of `pass-cli`'s three paths to `remove_dir_all` are decided from the
/// PERSISTED session before the command runs, so a case that wants one of them
/// sets the session's own fields rather than arranging a server answer — which
/// is also what the vendor reads: `main.rs:337` and `main.rs:354` both ask the
/// session it just loaded.
pub enum VendorSession {
    /// `!session.is_authenticated()` — `main.rs:337-341`.
    NotAuthenticated,
    /// `store.needs_extra_password()` — `main.rs:354-358`.
    NeedsExtraPassword,
}

/// Put the session the stand-in wrote into a state its dispatch refuses.
///
/// `generation` is the directory `PROTON_PASS_SESSION_DIR` names — the
/// vendor's own `.session` subdirectory is appended here, the way
/// `utils.rs:53-85` appends it.
pub fn degrade_vendor_session(generation: &Path, state: &VendorSession) {
    let session = generation.join(".session").join("session.json");
    let text = std::fs::read_to_string(&session)
        .unwrap_or_else(|error| panic!("no session at {}: {error}", session.display()));
    let (field, was) = match state {
        VendorSession::NotAuthenticated => ("auth", "auth=yes"),
        VendorSession::NeedsExtraPassword => ("extra", "extra=no"),
    };
    assert!(
        text.contains(was),
        "the session at {} does not carry `{was}`, so this fixture would be degrading nothing: \
         {text:?}",
        session.display()
    );
    let degraded = match state {
        VendorSession::NotAuthenticated => text.replace("auth=yes", "auth=no"),
        VendorSession::NeedsExtraPassword => text.replace("extra=no", "extra=yes"),
    };
    std::fs::write(&session, degraded)
        .unwrap_or_else(|error| panic!("cannot rewrite {} ({field}): {error}", session.display()));
}

/// Revoke, at the account, the session the stand-in wrote into `generation`.
///
/// `client.logout()` is one act and the local deletion is another
/// (`commands/logout.rs:46-67`), and the window between them is where a
/// concurrent reader turns into a deleter. A case that wants a reader in that
/// state can wait out the window, or it can say so directly — which is what
/// this does, so the case is arithmetic rather than a race it has to win.
///
/// `dir` is the stand-in's own directory, `generation` the one
/// `PROTON_PASS_SESSION_DIR` names.
pub fn revoke_vendor_session(dir: &Path, generation: &Path) {
    let session = generation.join(".session").join("session.json");
    let text = std::fs::read_to_string(&session)
        .unwrap_or_else(|error| panic!("no session at {}: {error}", session.display()));
    let id = text
        .lines()
        .find_map(|line| line.strip_prefix("session="))
        .unwrap_or_else(|| panic!("no session id in {}: {text:?}", session.display()));
    let account = dir.join("pass-cli.store.revoked");
    let mut held = std::fs::read_to_string(&account).unwrap_or_default();
    held.push_str(id);
    held.push('\n');
    std::fs::write(&account, held).expect("record the revocation at the account");
}

/// Every call the store stand-in has answered, one line each, oldest first.
///
/// The line is `<verb> <session directory> <outcome>`, where the outcome is one
/// of the stand-in's own words for which branch of the vendor it took —
/// `minted-key`, `revoked-cleanup`, `not-authenticated`, `undecryptable` and
/// the rest. That is what lets a case assert WHICH vendor path ran, rather
/// than inferring it from an exit status three paths share.
///
/// It carries no key, no token and no value: the two credentials in play here
/// are the agent token and the local key, and neither the id the stand-in mints
/// nor the fingerprint it derives is ever written to this file.
pub fn vendor_store_trace(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(vendor_store_trace_path(dir))
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn vendor_store_trace_path(dir: &Path) -> PathBuf {
    dir.join("pass-cli.store.trace")
}

/// Write a `pass-cli` stand-in that models the vendor's store semantics and
/// hands everything else to `inner`.
///
/// It answers `login`, `logout`, `info` and `completions` itself and `exec`s
/// `inner` for the value-reading verbs, which is the same division
/// `tests/daemon_proton.rs`'s session-verbs stand-in already draws. What it
/// adds is everything the vendor does BEFORE it dispatches — and two of the
/// three ways it destroys a session live in exactly that stretch.
///
/// # The three paths to `remove_dir_all`, and why two of them are reads
///
/// | Path | Source | When |
/// | --- | --- | --- |
/// | the SDK's `on_session_invalidated` callback | `features/mod.rs:266-268` | the account revoked this session, from inside ANY command |
/// | dispatch: the session is not authenticated | `main.rs:337-341` | before the command runs, on every verb |
/// | dispatch: the session needs an extra password | `main.rs:354-358` | same |
///
/// All three land in `remove_local_data` (`commands/logout.rs:26-44`), which is
/// one `remove_dir_all` over `<PROTON_PASS_SESSION_DIR>/.session`. So a plain
/// `pass-cli run` — a read — deletes the whole store on its way to reporting an
/// ordinary error, and it does so on the two dispatch paths before it has run
/// the command at all.
///
/// # What survives, and what a verb creates
///
/// `get_base_dir` (`utils.rs:53-85`) joins `.session` onto the variable and
/// CREATES it, mode `0700`, on every verb before dispatch. So the directory the
/// variable names survives every deletion above, and a verb pointed at a
/// directory holding no session leaves an empty `.session` behind it.
///
/// # The key
///
/// `get_key_provider` (`features/mod.rs:63-84`) reads
/// `PROTON_PASS_KEY_PROVIDER` off the environment, so the arm is the caller's
/// choice and never this fixture's. Unset **or empty** is `keyring`, a third
/// provider — not `fs`, which is the reading a missing scope call invites.
///
/// # What it deliberately does not model
///
/// That exactly one process writes the local key. That is this crate's own
/// claim, proven by `daemon::credential`'s own tests, and a stand-in asserting
/// it would be a stand-in for us.
pub fn stub_pass_cli_store(dir: &Path, inner: &Path, behaviour: &VendorStore) -> PathBuf {
    let trace = vendor_store_trace_path(dir);
    // The account, which is the one piece of state that is NOT inside the
    // session directory — `client.logout()` revokes at the server, and every
    // deletion below then runs against a directory that no longer holds a
    // session the account will honour. Keeping it here rather than in
    // `.session` is what makes a revocation survive the `remove_dir_all` that
    // follows it, exactly as the account's own record does.
    let revoked = dir.join("pass-cli.store.revoked");
    let body = format!(
        r#"#!/bin/sh
verb="$1"
root="${{PROTON_PASS_SESSION_DIR-}}"
trace='{trace}'
revoked='{revoked}'

# One line per call, written once, at the point the branch is decided.
note() {{ printf '%s %s %s\n' "${{verb:-<none>}}" "${{root:-<unset>}}" "$1" >> "$trace"; }}

# `completions` is the one verb that returns before the base directory is
# touched at all.  main.rs:250-254
if [ "$verb" = 'completions' ]; then note completions; exit 0; fi

if [ -z "$root" ]; then
  note no-session-dir
  printf '%s\n' 'Error: Error getting base dir' >&2
  exit 1
fi

# get_base_dir(): `.session` is joined onto the variable and CREATED, mode
# 0700, on every verb before dispatch.  utils.rs:53-85
#
# `mkdir -p` then `chmod` rather than one call: the vendor uses DirBuilder's
# own mode on every level it creates, and the shell has no spelling for that.
# The leaf is the one this fixture's cases read.
base="$root/.session"
mkdir -p "$base" 2>/dev/null
chmod 700 "$base" 2>/dev/null
session="$base/session.json"
key_file="$base/local.key"
database="$base/pass-cli.db"

# remove_dir_all, with its listing and its final rmdir as the two separate acts
# they are.  commands/logout.rs:26-44
remove_local_data() {{
  if [ ! -d "$base" ]; then
    printf '%s\n' 'There was no data to be removed'
    return 0
  fi
  # The glob IS the listing, expanded once. An entry created after this line
  # is not in it, survives the unlinks, and fails the rmdir below.
  for entry in "$base"/* "$base"/.[!.]*; do
    [ -e "$entry" ] || continue
    rm -rf "$entry"
  done
  sleep {rmdir_window}
  if rmdir "$base" 2>/dev/null; then return 0; fi
  # The wording of the anyhow chain a failing `remove_dir_all` renders was NOT
  # read from a run of the real binary; `Error deleting base dir` is the
  # context string at logout.rs:36 and `Directory not empty` is what this
  # crate's own incident log recorded beside it. The two-line shape between
  # them is modelled.
  printf '%s\n' 'Error: Error deleting base dir' >&2
  printf '%s\n' 'Caused by:' >&2
  printf '%s\n' '    Directory not empty (os error 66)' >&2
  return 1
}}

# get_key(), per provider.  Prints the key's IDENTITY, never a key: under `fs`
# that is the id this fixture minted, and under `env` a checksum of the
# variable — the same shape the vendor logs, which prints a fingerprint and
# never the key.
resolve_key() {{
  case "$provider" in
    fs)
      # FsLocalKeyProvider::get_local_key: read it when it is there, MINT one
      # when it is not — on any verb.  features/mod.rs:177-211
      if [ -f "$key_file" ]; then cat "$key_file"; return 0; fi
      minted="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
      # `create_new(true).mode(0o600)` at features/mod.rs:196-199 is O_EXCL, so
      # two children that both find the key missing race and the loser gets
      # nothing. `set -C` is the shell's own O_EXCL and refuses identically.
      if (set -C; printf '%s' "$minted" > "$key_file") 2>/dev/null; then
        chmod 600 "$key_file"
        printf '%s' "$minted"
        return 0
      fi
      return 1
      ;;
    env)
      # EnvLocalKeyProvider derives the key from the variable's bytes and
      # stores nothing.  env_key_provider.rs:43-45
      printf 'env:%s' "$(printf '%s' "${{PROTON_PASS_ENCRYPTION_KEY-}}" | cksum | tr -d ' ')"
      return 0
      ;;
  esac
  return 1
}}

# get_key_provider(): the arm is the variable's, and unset OR EMPTY is
# `keyring`.  features/mod.rs:63-84
provider="${{PROTON_PASS_KEY_PROVIDER-}}"
case "$provider" in
  fs) ;;
  env)
    # EnvLocalKeyProvider::new refuses an unset or empty variable with this
    # exact sentence, and features/mod.rs:78 propagates it with `?` — so no
    # client is built, no dispatch is reached, and NOTHING is deleted. That is
    # what separates a misconfigured probe from a destructive one.
    # env_key_provider.rs:33-41
    if [ -z "${{PROTON_PASS_ENCRYPTION_KEY-}}" ]; then
      note env-key-missing
      printf '%s\n' 'Error: PROTON_PASS_ENCRYPTION_KEY environment variable must be set and non-empty when using env key provider' >&2
      exit 1
    fi
    ;;
  keyring|'')
    # The daemon's own uid has an empty login keyring, so KeyringKeyProvider
    # takes its NoEntry arm. With local data beside it that arm FORCE-LOGS-OUT
    # — the guard the `fs` provider has no equivalent of.
    # features/keyring.rs:258-268, local_data_exists at :141-143
    if [ -f "$session" ] || [ -f "$database" ]; then
      printf '%s\n' 'Error: Local encryption key not found but local data exists. Forcing logout for security.' >&2
      rm -f "$key_file"
      remove_local_data > /dev/null 2>&1
      printf '%s\n' "Run 'pass-cli login' to authenticate again." >&2
      note keyring-forced-logout
      exit 1
    fi
    # The other half of that arm mints a key INTO the keyring and carries on.
    # A shell stand-in has no keyring to mint into, so it refuses in words that
    # are plainly its own rather than putting the vendor's name on a guess.
    note keyring-no-local-data
    printf '%s\n' 'stub: the keyring provider has no keyring to reach' >&2
    exit 1
    ;;
  *)
    note invalid-provider
    printf '%s\n' "Error: Invalid PROTON_PASS_KEY_PROVIDER value: '$provider'. Valid values are 'fs', 'keyring', or 'env'" >&2
    exit 1
    ;;
esac

# `logout --force` and `completions` are the only commands that never build the
# client, which is why they are the only two that work against a store nothing
# can decrypt.  main.rs:267-274, commands/logout.rs:69-79
if [ "$verb" = 'logout' ] && [ "$2" = '--force' ]; then
  printf '%s\n' 'Executing force logout'
  # try_cleanup_all_key_providers, then cleanup().  features/mod.rs:45-61
  rm -f "$key_file"
  remove_local_data
  status=$?
  if [ $status -eq 0 ]; then
    note force-logged-out
    printf '%s\n' 'Successfully performed force logout'
  else
    note force-logout-enotempty
  fi
  exit $status
fi

key="$(resolve_key)" || {{
  note key-race-lost
  printf '%s\n' 'Error: Error creating local key file' >&2
  exit 1
}}

# Building the client opens the store, so a session.json the resolved key
# cannot decrypt fails EVERY remaining verb — a plain `logout` included, which
# is why a store in this state cannot be repaired by the obvious command.
# main.rs:267-274
if [ -f "$session" ]; then
  stored="$(sed -n 's/^key=//p' "$session" | head -1)"
  if [ "$stored" != "$key" ]; then
    note undecryptable
    printf '%s\n' 'Error: Error decrypting local session(Error decrypting session: aead::Error)' >&2
    exit 1
  fi
fi

# login is dispatched at main.rs:275-309, ahead of every session check below.
if [ "$verb" = 'login' ]; then
  sleep {login_delay}
  : > "$database"
  # persist_now writes session.json under whatever get_key() answered AT THAT
  # MOMENT, by rename.
  printf 'session=%s\nkey=%s\nauth=yes\nextra=no\n' \
    "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" "$key" > "$session.tmp"
  mv "$session.tmp" "$session"
  note logged-in
  printf '%s\n' 'Personal access token session created successfully'
  exit 0
fi

# get_session() answers None.  main.rs:325-335
if [ ! -f "$session" ]; then
  if [ "$verb" = 'logout' ]; then
    note already-logged-out
    printf '%s\n' 'There was not an active session, you are already logged out' >&2
    exit 0
  fi
  note no-session
  printf '%s\n' 'ERROR pass-cli/src/main.rs:332: Command is not logout there is no session' >&2
  printf '%s\n' 'Error: This operation requires an authenticated client' >&2
  exit 1
fi

sid="$(sed -n 's/^session=//p' "$session" | head -1)"
auth="$(sed -n 's/^auth=//p' "$session" | head -1)"
extra="$(sed -n 's/^extra=//p' "$session" | head -1)"

# DELETION PATH 2 — dispatch, session present and not authenticated. The
# cleanup runs BEFORE the command, on every verb.  main.rs:336-341
if [ "$auth" != 'yes' ]; then
  remove_local_data > /dev/null 2>&1
  note not-authenticated
  printf '%s\n' 'ERROR pass-cli/src/main.rs:338: Session is some but is not logged in' >&2
  printf '%s\n' 'Error: This operation requires an authenticated client' >&2
  exit 1
fi

# DELETION PATH 3 — dispatch, the session needs an extra password. Same
# cleanup, same place.  main.rs:342-358
if [ "$extra" = 'yes' ]; then
  remove_local_data > /dev/null 2>&1
  note needs-extra-password
  printf '%s\n' 'ERROR pass-cli/src/main.rs:355: Session is some but needs extra password' >&2
  printf '%s\n' 'Error: This operation requires an authenticated client' >&2
  exit 1
fi

is_revoked() {{ grep -qx "$1" "$revoked" 2>/dev/null; }}

if [ "$verb" = 'logout' ]; then
  if is_revoked "$sid"; then
    # A logout whose server call fails exits BEFORE remove_key and
    # remove_local_data, so it touches nothing on disk.  logout.rs:48-54
    note logout-refused
    printf '%s\n' 'Error logging out: This operation requires an authenticated client' >&2
    printf '%s\n' "There has been an error during the logout process. If it persists, you may run 'pass-cli logout --force'" >&2
    exit 1
  fi
  # client.logout() revokes AT THE ACCOUNT. From here every other child holding
  # this session is answered "logged out", whatever it was asked for, and the
  # local deletion has not started.  logout.rs:48
  printf '%s\n' "$sid" >> "$revoked"
  sleep {logout_delay}
  # remove_key() is unconditional and runs before remove_local_data. Under
  # `fs` it unlinks local.key while a concurrent reader's session file still
  # needs it; under `env` it is a documented no-op, so there is nothing to
  # unlink and nothing to race.
  # logout.rs:56-64, features/mod.rs:229-237, env_key_provider.rs:65-68
  case "$provider" in fs) rm -f "$key_file" ;; esac
  remove_local_data
  status=$?
  if [ $status -eq 0 ]; then
    note logged-out
    printf '%s\n' 'Successfully logged out'
  else
    note logout-enotempty
  fi
  exit $status
fi

# DELETION PATH 1 — the SDK's own callback. The account revoked this session,
# so the command's first request is refused and the SDK calls
# on_session_invalidated() from inside whatever command that was — a read
# included.  features/mod.rs:266-268 -> logout.rs:81-84
#
# The store ALSO schedules its own session.json write on a background task
# which re-reads, and mints when absent, the key at write time. The two are not
# ordered against each other, and the terminal state is the one where that
# write survives and the key it was written under does not: the next child
# mints a fresh key and cannot decrypt what is on disk.
#
# That the SDK behaves this way is inferred from the CLI's handling of it — the
# SDK crate is not in the vendor's public repository, so `schedule_persist`'s
# own source was not read.
if is_revoked "$sid"; then
  (
    sleep {persist_key_delay}
    # local_key_path() canonicalizes the base directory, so a write arriving
    # after the directory is gone ERRORS rather than minting a key into a
    # store nothing is serving from.  features/mod.rs:214-220
    [ -d "$base" ] || exit 0
    persisted="$(resolve_key)" || exit 0
    sleep {persist_write_delay}
    [ -d "$base" ] || exit 0
    printf 'session=%s\nkey=%s\nauth=yes\nextra=no\n' "$sid" "$persisted" \
      > "$session.tmp" 2>/dev/null && mv "$session.tmp" "$session" 2>/dev/null
  ) &
  remove_local_data > /dev/null 2>&1
  # The background write is bounded by the process that scheduled it: the
  # vendor's runtime goes down with the command, so a write that has not landed
  # by the time the command returns never lands at all.
  wait
  note revoked-cleanup
  # main.rs:229-235, which is where an invalidated session is turned into words.
  printf '%s\n' 'Your session has been invalidated and you have been logged out automatically.' >&2
  printf '%s\n' 'Please log in again with: pass login' >&2
  exit 1
fi

# `info` is answered HERE rather than handed to `inner`, and that is the whole
# point of it: this crate classifies a failing read by asking `info` about the
# same session, so a fixture whose `info` shared the read's fate could not tell
# a verdict about a NAME from a fault in the SESSION. Every session check above
# has already run, so this answers exactly when the session is sound.
if [ "$verb" = 'info' ]; then
  note info-answered
  printf '%s\n' 'ok'
  exit 0
fi

note dispatched
exec '{inner}' "$@"
"#,
        trace = trace.display(),
        revoked = revoked.display(),
        inner = inner.display(),
        login_delay = behaviour.login_delay.as_secs_f64(),
        logout_delay = behaviour.logout_delay.as_secs_f64(),
        rmdir_window = behaviour.rmdir_window.as_secs_f64(),
        persist_key_delay = behaviour.persist_key_delay.as_secs_f64(),
        persist_write_delay = behaviour.persist_write_delay.as_secs_f64(),
    );

    install_executable(&dir.join("pass-cli-store-stub"), &body)
}

// ---------------------------------------------------------------------------
// 1Password fixtures
// ---------------------------------------------------------------------------

/// How the `op` stub answers the verbs that need a login.
///
/// The shapes are the vendor's DOCUMENTED ones — see `src/store/onepassword.rs`
/// for what was measured against `op` 2.39.0 and what was not. The two error
/// spellings are measured: `account is not signed in` and the `[ERROR] <date>
/// <time> <message>` log prefix are what the real binary printed.
pub enum OnePasswordListing {
    /// `item list` prints this JSON; `vault get` answers with the vault.
    Json(&'static str),
    /// Every authenticated verb fails as the real CLI does with no sign-in.
    NotSignedIn,
    /// `vault get` and `item list` fail as they do for a vault the login
    /// cannot see. Wording documented, not measured.
    NoSuchVault,
    /// `vault get` ANSWERS and `item list` is refused.
    ///
    /// The split a health check must not read as health. It is what the
    /// vendor's own grant syntax produces — `--vault <name>:read_items` is an
    /// **item** permission, and the vault RECORD is a different object — so a
    /// login can see the vault it cannot list. Wording documented, not
    /// measured.
    ItemsRefused,
}

impl OnePasswordListing {
    /// One live Password item titled `DECOY`, in the pinned vault. The
    /// default for fixtures that are about the lookup rather than the listing.
    pub const ONE_ITEM: OnePasswordListing = OnePasswordListing::Json(
        r#"[{"id":"It3mL1v3","title":"DECOY","category":"PASSWORD",
             "vault":{"id":"V1","name":"company"}}]"#,
    );

    /// What `vault get` does.
    fn vault_body(&self) -> String {
        match self {
            // `ItemsRefused` answers here on purpose: the vault record is
            // readable and the items are not, which is the whole case.
            OnePasswordListing::Json(_) | OnePasswordListing::ItemsRefused => {
                r#"printf '%s' '{"id":"V1","name":"company","items":1}'; exit 0"#.to_owned()
            }
            OnePasswordListing::NotSignedIn => NOT_SIGNED_IN.to_owned(),
            OnePasswordListing::NoSuchVault => NO_SUCH_VAULT.to_owned(),
        }
    }

    /// What `item list` does. The JSON goes through a file rather than a
    /// single-quoted shell string, for the reason `stub_pass_cli_discovery`
    /// gives.
    fn list_body(&self, listing_file: &Path) -> String {
        match self {
            OnePasswordListing::Json(_) => format!("cat '{}'; exit 0", listing_file.display()),
            OnePasswordListing::NotSignedIn => NOT_SIGNED_IN.to_owned(),
            OnePasswordListing::NoSuchVault => NO_SUCH_VAULT.to_owned(),
            OnePasswordListing::ItemsRefused => NO_ITEM_PERMISSION.to_owned(),
        }
    }
}

/// The measured refusal, in the measured log format. The date is a fixture.
const NOT_SIGNED_IN: &str =
    "printf '%s\\n' '[ERROR] 2001/01/01 00:00:00 account is not signed in' >&2; exit 1";

/// A vault the login cannot see. No apostrophe, so it survives single quotes.
const NO_SUCH_VAULT: &str = "printf '%s\\n' '[ERROR] 2001/01/01 00:00:00 no vault named that is \
     visible to this account' >&2; exit 1";

/// A vault the login can SEE and may not LIST. No apostrophe, same reason.
const NO_ITEM_PERMISSION: &str = "printf '%s\\n' '[ERROR] 2001/01/01 00:00:00 you do not have \
     permission to list items in this vault' >&2; exit 1";

/// The shell fragment that runs, or declines to run, the probe under `op run`.
///
/// `$child` and `$key` are set by the stub's preamble. The real CLI replaces
/// the variable that HELD the reference, so the injection is into
/// `KEYLESS_PROBE` rather than into a variable named after the key.
fn op_run_body(behaviour: &Backend) -> String {
    match behaviour {
        Backend::Injects(value) => {
            format!("exec /usr/bin/env \"KEYLESS_PROBE={value}\" \"$child\" \"$key\"\n")
        }
        Backend::InjectsWholeVault => "exec \"$@\"\n".to_owned(),
        Backend::Concealed => format!(
            "exec /usr/bin/env \"KEYLESS_PROBE={ONEPASSWORD_CONCEALED}\" \"$child\" \"$key\"\n"
        ),
        Backend::Empty => "exec /usr/bin/env \"KEYLESS_PROBE=\" \"$child\" \"$key\"\n".to_owned(),
        // The reference passes through unresolved: what `printenv` prints is
        // the `op://` string the adapter set. Measured, this is what the real
        // CLI does with a child when it has nothing to resolve.
        Backend::Unset => "exec \"$child\" \"$key\"\n".to_owned(),
        Backend::OwnFailure => format!("{NOT_SIGNED_IN}\n"),
        Backend::Hangs => "sleep 60\n".to_owned(),
        // Declined out loud rather than answered. `op run` injects into
        // `KEYLESS_PROBE` rather than into a variable named after the key, so
        // the controlled body above is not the body this vendor would need —
        // and no case drives a 1Password vendor across several calls. A second
        // cursor written for nobody would be a fixture whose first user finds
        // it already wrong.
        Backend::Controlled => {
            "echo 'stub: this fixture answers no per-call script' >&2\nexit 1\n".to_owned()
        }
    }
}

/// Write a stand-in for the `op` binary, backed by one live item.
pub fn stub_op(dir: &Path, behaviour: &Backend) -> PathBuf {
    stub_op_listing(dir, behaviour, &OnePasswordListing::ONE_ITEM, "{}")
}

/// Write a stand-in for the `op` binary.
///
/// Records its argv at `<dir>/op.argv` (every invocation, overwritten), the
/// NAMES of the environment it was handed at `<dir>/op.env`, the reference it
/// found in `KEYLESS_PROBE` at `<dir>/op.probe` (the literal `<unset>` when
/// none arrived), and the service-account token at `<dir>/op.token` (again
/// `<unset>` when absent). `item list` records its own argv at
/// `<dir>/op.list.argv` and appends one line per invocation to
/// `<dir>/op.list.count`. `item get` prints `view`.
///
/// So every fact a test asserts is read from the OTHER side of the interface —
/// what the vendor received — rather than from the adapter's own account of
/// what it sent.
pub fn stub_op_listing(
    dir: &Path,
    behaviour: &Backend,
    listing: &OnePasswordListing,
    view: &str,
) -> PathBuf {
    let listing_file = dir.join("op-listing.json");
    let view_file = dir.join("op-view.json");
    if let OnePasswordListing::Json(json) = listing {
        std::fs::write(&listing_file, json).expect("write the listing fixture");
    }
    std::fs::write(&view_file, view).expect("write the view fixture");

    let body = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         /usr/bin/env | sed 's/=.*//' | sort > '{env}'\n\
         printf '%s' \"${{KEYLESS_PROBE-<unset>}}\" > '{probe}'\n\
         printf '%s' \"${{OP_SERVICE_ACCOUNT_TOKEN-<unset>}}\" > '{token}'\n\
         if [ \"$1\" = 'vault' ] && [ \"$2\" = 'get' ]; then {vault}; fi\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'list' ]; then\n\
         \x20 printf '%s\\n' \"$@\" > '{list_argv}'\n\
         \x20 echo one >> '{list_count}'\n\
         \x20 {list}\n\
         fi\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'get' ]; then cat '{view}'; exit 0; fi\n\
         if [ \"$1\" = 'run' ]; then\n\
         \x20 while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         \x20 shift\n\
         \x20 child=\"$1\"\n\
         \x20 key=\"$2\"\n\
         \x20 {run}\
         fi\n\
         echo 'stub: this fixture does not answer that verb' >&2\n\
         exit 1\n",
        argv = dir.join("op.argv").display(),
        env = dir.join("op.env").display(),
        probe = dir.join("op.probe").display(),
        token = dir.join("op.token").display(),
        vault = listing.vault_body(),
        list_argv = dir.join("op.list.argv").display(),
        list_count = dir.join("op.list.count").display(),
        list = listing.list_body(&listing_file),
        view = view_file.display(),
        run = op_run_body(behaviour),
    );
    write_stub(dir, "op-stub", &body)
}

/// How many times the `op` stub's `item list` ran. Zero when it never did.
pub fn op_listing_count(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("op.list.count"))
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
    install_executable(&dir.join(name), body)
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

/// A child command that reports SEVERAL names out of one environment.
///
/// It writes one `NAME=value` line per name — the literal `<unset>` where the
/// variable is absent — then exits 0.
///
/// One child rather than one per name, because "did exactly the asked-for set
/// arrive?" is a question about a single environment. Two children are two
/// environments, and a name could be present in one and absent in the other
/// with neither run able to notice.
pub fn witness_env(marker: &Path, vars: &[&str]) -> Vec<OsString> {
    let mut script = String::from(": > \"$1\"");
    for var in vars {
        // The format string is fixed and the value arrives as an argument, so a
        // value holding a `%` is reported rather than interpreted.
        script.push_str(&format!(
            "; printf '%s=%s\\n' '{var}' \"${{{var}-<unset>}}\" >> \"$1\""
        ));
    }
    script.push_str("; exit 0");
    vec![
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(script),
        OsString::from("sh"),
        OsString::from(marker),
    ]
}

/// What a [`witness_env`] child recorded, as a map from name to value.
///
/// # Panics
///
/// When a line is not `NAME=value`. A record this cannot read is a fixture
/// failure, and skipping the line instead would report the name as absent —
/// which is exactly the answer several callers assert on.
pub fn witnessed_env(marker: &Path) -> std::collections::BTreeMap<String, String> {
    witnessed(marker)
        .lines()
        .map(|line| {
            let (name, value) = line.split_once('=').unwrap_or_else(|| {
                panic!("the witness wrote a line that is not NAME=value: {line}")
            });
            (name.to_owned(), value.to_owned())
        })
        .collect()
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

// The daemon is macOS-only (see `src/lib.rs`), so every fixture that binds
// one, or that asks the kernel who this process is, is gated with it. The
// portable fixtures below it are NOT gated: `write_secrets`, `client_config`
// and `example_binary` describe a session's side of the socket, which is what
// `daemon_degraded.rs` exercises without a daemon anywhere.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
use keyless::attest::Policy;
#[cfg(any(target_os = "macos", keyless_force_xnu))]
use keyless::daemon::config::{DaemonConfig, DaemonStores, FileStoreConfig, PeerConfig};
#[cfg(any(target_os = "macos", keyless_force_xnu))]
use keyless::daemon::{Daemon, Running};
#[cfg(any(target_os = "macos", keyless_force_xnu))]
use keyless::ipc::peer;
#[cfg(any(target_os = "macos", keyless_force_xnu))]
use std::os::fd::AsFd;
#[cfg(any(target_os = "macos", keyless_force_xnu))]
use std::os::unix::net::UnixStream;

/// This process's own verified identity.
///
/// Both ends of a socketpair belong to us, so attesting one end is attesting
/// ourselves — which is how a test pins the test binary as an authorised
/// client without shelling out to anything.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub fn own_identity() -> peer::PeerIdentity {
    let (a, _b) = UnixStream::pair().expect("socketpair");
    peer::identify(a.as_fd()).expect("this process must be able to attest itself")
}

/// A policy that authorises this test process and nothing else.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub fn policy_allowing_self() -> Policy {
    let me = own_identity();
    Policy::new().allow_uid(me.uid).allow_image(me.code_hash)
}

/// A policy that authorises this process's uid but no image at all.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
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

/// A daemon config rooted in `dir`, backed by a file store.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub fn daemon_config(dir: &Path) -> DaemonConfig {
    DaemonConfig {
        socket: short_socket_path(dir).into(),
        audit: dir.join("audit.jsonl").into(),
        cache_ttl_seconds: 60,
        // No stale window in the fixtures: a test that wants one says so, and
        // one that does not gets the pre-existing behaviour — a value is
        // served for its freshness window and then fetched again.
        cache_stale_seconds: 0,
        idle_timeout_seconds: 5,
        peer: PeerConfig::default(),
        stores: DaemonStores {
            file: FileStoreConfig {
                enabled: true,
                path: dir.join("secrets.json").into(),
            },
            ..DaemonStores::default()
        },
        // One store, so nothing needs routing. The fixtures that DO run two
        // stores build their config from JSON instead, because an unread key
        // is dropped in silence and a struct literal cannot show that.
        secrets: std::collections::BTreeMap::new(),
    }
}

/// Bind and start serving.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub fn start_daemon(config: &DaemonConfig, policy: Policy) -> Running {
    let daemon = Daemon::bind(config, policy).expect("bind the daemon");
    Running::spawn(daemon, config).expect("start the accept loop")
}

// ---------------------------------------------------------------------------
// Generation fixtures.
//
// Filesystem only — nothing here shapes vendor-shaped behaviour, and nothing
// here spawns a `pass-cli` stand-in. `stub_pass_cli_listing` and its siblings
// already answer `run` / `item list` / `vault list`; what none of them did
// before this fixture existed was PUBLISH a generation for those verbs to be
// scoped at, which every daemon-hosted Proton read now needs before it
// resolves anything at all.
// ---------------------------------------------------------------------------

/// A counter distinguishing generations minted within one test process.
///
/// `GenerationName::mint` alone collides when two are minted in the same
/// process inside one millisecond — see its own doc. A fixture that publishes
/// several generations in a tight loop hits that far more often than
/// production ever does, so the pid half of the name is perturbed by this
/// counter rather than left to the real, constant `process::id()`.
static GENERATION_SEQUENCE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Publish a fresh generation into `root`, as a real `keylessd login` would,
/// and return its directory.
///
/// Every daemon-hosted Proton read now needs a valid `<root>/current` before
/// it resolves anything — see
/// `keyless::store::proton_session::Generations::current` — so a fixture that
/// wants an ordinary read to succeed calls this once before starting the
/// daemon.
pub fn publish_generation(root: &Path) -> PathBuf {
    publish_generation_aged(root, std::time::Duration::ZERO)
}

/// The same, minted `age` in the past with `current`'s own mtime pushed back
/// to match — the shape a retirement fixture needs to make a generation
/// eligible without waiting out a real grace period.
///
/// Also plants `.session/session.json`, the way a real `pass-cli login`
/// leaves the directory it just wrote to — see
/// [`keyless::store::proton::ProtonStore`]'s own structural session-fault
/// check, which reads exactly this path. A fixture whose case is the
/// vendor's own invalidation cleanup having removed it — see
/// `tests/daemon_proton.rs`'s `a_missing_session_json_…` case — deletes it
/// after calling this, rather than this function ever omitting it: omitting
/// it by default would make every OTHER fixture here an unrealistic
/// directory the real vendor never produces.
pub fn publish_generation_aged(root: &Path, age: std::time::Duration) -> PathBuf {
    std::fs::create_dir_all(root).expect("create the generation root");
    let minted_at = std::time::SystemTime::now()
        .checked_sub(age)
        .expect("age must not underflow the epoch");
    let sequence = GENERATION_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let millis = minted_at
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock reads after the epoch")
        .as_millis();
    let name = format!("gen-{millis}-{}", std::process::id().wrapping_add(sequence));

    let dir = root.join(&name);
    std::fs::create_dir_all(&dir).expect("create the generation directory");
    let session_subdir = dir.join(".session");
    std::fs::create_dir_all(&session_subdir).expect("create .session");
    std::fs::write(session_subdir.join("session.json"), b"not a real session")
        .expect("plant session.json");

    let current = root.join("current");
    std::fs::write(&current, format!("{name}\n")).expect("write current");
    if age > std::time::Duration::ZERO {
        // Set only when back-dating: leaving `current`'s mtime at "now" is
        // what an ordinary, just-published generation looks like, and forcing
        // a `set_modified` call on every publish would make every fixture pay
        // for a mtime write it does not need.
        let file = std::fs::File::options()
            .write(true)
            .open(&current)
            .expect("open current to back-date it");
        file.set_modified(minted_at).expect("set current's mtime");
    }

    dir
}

/// The generation `<root>/current` names, or `None` when it is absent, empty
/// or unreadable.
///
/// A thin, test-only reader — never the validating one
/// `keyless::store::proton_session::Generations::current` is. A fixture
/// asserting on this is asserting on the bytes a real reader would then
/// validate, not re-deriving that validation itself.
pub fn current_generation(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("current")).ok()?;
    let trimmed = text.strip_suffix('\n').unwrap_or(&text);
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Every `gen-*` directory directly under `root`, by name, sorted.
pub fn generation_dirs(root: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("gen-"))
        .collect();
    names.sort();
    names
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
    install_executable(&dir.join("security-slow"), &body)
}
