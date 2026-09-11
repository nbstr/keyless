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
         # Parse like the vendor up to `--`: both spellings of an option value,\n\
         # and a refusal for anything the vendor reads as a short-flag cluster.\n\
         # Ahead of every verb, because clap parses before it dispatches.\n\
         env_file=''\n\
         for arg in \"$@\"; do\n\
         \x20 if [ \"$arg\" = '--' ]; then break; fi\n\
         \x20 case \"$arg\" in\n\
         \x20   --env-file=*) env_file=\"${{arg#--env-file=}}\" ;;\n\
         \x20   --*|-) ;;\n\
         \x20   -*) echo \"error: unexpected argument '$arg' found\" >&2; exit 2 ;;\n\
         \x20 esac\n\
         \x20 if [ \"$prev\" = '--env-file' ]; then env_file=\"$arg\"; fi\n\
         \x20 prev=\"$arg\"\n\
         done\n\
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
        body = behaviour.body(dir)
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
        names: Vec::new(),
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
