use std::path::Path;
use std::path::PathBuf;

use super::backend::Backend;
use super::write_stub;

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
         \x20 echo one >> '{list_count}'\n\
         \x20 if [ -e '{pause}' ]; then sleep \"$(cat '{pause}')\"; fi\n\
         \x20 cat '{listing}'; exit 0; fi\n\
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
        pause = dir.join("listing.pause").display(),
        tail = vendor_run_tail(dir, behaviour),
    );
    write_stub(dir, "pass-cli-catalogue-stub", &body)
}

/// Make every later `item list` sleep `seconds` before it answers.
pub fn pause_catalogue_listing(dir: &Path, seconds: u64) {
    std::fs::write(dir.join("listing.pause"), seconds.to_string())
        .expect("write the listing pause");
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
