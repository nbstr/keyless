use std::fs;
use std::path::Path;
use std::time::Duration;

use super::environment::SESSION_DIR_VAR;
use super::token::login_into;

/// What to tell an operator whose config names no session directory.
///
/// Written once because [`ProtonStore::resolve`] and [`ProtonStore::health`]
/// must give the same answer: `doctor` exists to say in advance what a run
/// would say, and two copies of a sentence eventually stop matching.
pub(super) const NO_SESSION_DIR: &str = "`stores.proton.session_dir` is not set, so which Proton \
     identity answers would be whatever `pass-cli` was last logged into — on a machine with a \
     full-account login that is every vault, not the scoped one. Set it to the session \
     directory of the agent token you minted, e.g. \"session_dir\": \"~/.keyless-pass-session\" \
     — a leading `~` is expanded against your home directory";

/// What to tell an operator whose session directory is a RELATIVE path.
///
/// # Why this is checked here rather than at parse time
///
/// [`crate::paths::ConfigPath`] refuses a `~` it cannot resolve, so a path
/// reaching this point is exactly what the file said. It cannot go further and
/// refuse every relative path, because most path fields in the same config are
/// legitimately relative: `binary` is `pass-cli`, `probe_binary` resolves
/// through `PATH`. Relative is wrong for a session DIRECTORY specifically, so
/// the rule belongs to the field, not to the type.
///
/// # Why a degraded name rather than a refused command
///
/// This is the same defect the tilde bug was — one config, a different session
/// per working directory — and it is just as invisible, so it must not be
/// silent. It must also not block: `keyless run` never blocks on a store's or
/// the daemon's failure, and refuses only a name its store does not hold, an
/// empty name, or a caller that fails attestation. A config typo is none of
/// those, so a lookup fails as
/// [`StoreError::Unavailable`], `run` names the name it could not resolve and
/// still spawns the child, and `doctor` — which calls the same function from
/// [`ProtonStore::health`] — reports `store proton PROBLEM …` instead of `ok`.
/// `doctor` has no power to block anything and its own report says so, so
/// "refuse it in `doctor`" can only mean "never call it ok", which is what this
/// does.
///
/// The write verbs are the documented exception and refuse outright; see
/// [`crate::store::manage`] and [`crate::store::proton_manager`].
pub(crate) fn relative_session_dir(field: &str, dir: &Path) -> String {
    format!(
        "`{field}` is `{}`, which is a relative path. `pass-cli` resolves it against the \
         working directory, so one config would mint a FRESH, EMPTY session in every directory \
         a command is run from — and every one of them resolves nothing while looking \
         configured. Write an absolute path, or `~/…`, which is expanded against your home \
         directory",
        dir.display()
    )
}

/// The subdirectory `pass-cli` keeps one identity's session in.
///
/// Under `PROTON_PASS_SESSION_DIR`, not beside it: measured 2026-08-11, a
/// directory this crate handed the vendor came back holding
/// `<dir>/.session/{pass-cli.db,pat_key,session.json}`.
pub(crate) const SESSION_SUBDIR: &str = ".session";

/// The prefix on the file `pass-cli` writes a session into before renaming it.
///
/// `session.tmp.<pid>.<seq>`. The literal `session.tmp.` is in the vendor's
/// binary (`pass-cli` 2.2.5), beside `session.json` — so the write-temp-then-
/// rename is the VENDOR's, and one of those files left behind is its rename
/// having never happened.
const SESSION_TEMP_PREFIX: &str = "session.tmp.";

/// How long an unfinished write must sit still before this crate calls it dead.
///
/// A zero-byte temp file being written right now and one abandoned by a killed
/// process are byte-for-byte the same file. The only thing that separates them
/// without inspecting open file descriptors is that one of them stops moving,
/// so this is the whole discriminator and it is deliberately generous: calling
/// a live write dead is the error that costs a session.
const STALE_TEMP_AFTER: Duration = Duration::from_secs(10);

/// An unfinished `session.json` write, found beside the session it belongs to.
///
/// Metadata only. Nothing in this crate opens `session.json` or any temp file —
/// a session file holds an authenticated identity, and a broker that reads one
/// is a `get` verb with extra steps.
pub(super) struct InterruptedWrite {
    /// The temp file's own name, e.g. `session.tmp.28182.0`.
    name: String,
    /// How long it has sat unmodified, or `None` when the clock could not say.
    ///
    /// `None` on a file whose modification time is in the FUTURE as well: a
    /// skewed clock is a reason to make no claim, never a reason to make the
    /// confident one.
    idle: Option<Duration>,
}

impl InterruptedWrite {
    /// Whether it has been still long enough to be finished-or-dead for certain.
    fn stale(&self) -> bool {
        self.idle.is_some_and(|idle| idle >= STALE_TEMP_AFTER)
    }
}

/// The name of the file the temp files are renamed over.
pub(super) const SESSION_FILE: &str = "session.json";

/// Whether `<dir>/.session/session.json` is there at all.
///
/// Metadata only — the same read [`interrupted_write`] already makes of this
/// directory, and for the same reason: nothing in this crate opens a session
/// file. A symlink counts as present; this is a presence check, not a
/// trust check, and [`ProtonStore::info_probe_answers`] is what actually asks
/// whether the thing it names still works.
pub(super) fn session_file_present(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(SESSION_SUBDIR).join(SESSION_FILE)).is_ok()
}

/// How long a coalesced session-health probe's verdict is trusted before a
/// later failure asks the vendor again.
///
/// A few seconds: long enough that a burst of names failing over one broken
/// session inside a single renewal interval costs one `pass-cli info`, short
/// enough that a session an operator repairs by hand is not still read as
/// faulted seconds after it started answering again.
pub(super) const SESSION_PROBE_WINDOW: Duration = Duration::from_secs(3);

/// The longest a session-health probe may run before it is read as having no
/// answer.
///
/// Deliberately far below the per-call ceiling every other vendor child gets.
/// Two reasons, and the first is the one that bites: this probe runs on the
/// caller's own thread, after a read that has ALREADY spent its own budget
/// failing, so borrowing the full ceiling doubles the latency of exactly the
/// lookup that is already going wrong — and `crate::ipc::client`'s own
/// exchange ceiling is derived from how many vendor calls one lookup may
/// make. The second: the question is only whether a local session store
/// answers at all, which is not vault work, so a probe still silent after
/// this long is a session fault on any reading.
pub(super) const SESSION_PROBE_CEILING: Duration = Duration::from_secs(3);

/// The message a session-fault classification reports, wrapping the vendor's
/// own words with what decided this was about the session rather than the
/// name.
pub(super) fn session_fault_detail(detail: &str, dir: &Path) -> String {
    format!(
        "{detail} — the daemon's own session at {} is not answering, so nothing was decided \
         about this name; every value already cached stays, and the session is due to be \
         replaced",
        dir.display()
    )
}

/// The oldest unfinished session write that is still the LAST thing to happen.
///
/// Reads the directory listing and each entry's modification time, and nothing
/// else — never a byte of any file in it.
///
/// # A temp file older than `session.json` is debris, and saying otherwise
/// # would make this check wrong forever
///
/// `rename` carries the source file's modification time with it, so after a
/// write that COMPLETED, `session.json` is exactly as new as the temp file that
/// became it — and strictly newer than any temp left over from an earlier,
/// failed attempt. So `session.json` being newer proves a later write landed,
/// and the leftover is then a scar rather than a cause.
///
/// Measured on the incident's own directory, 2026-08-11: the abandoned
/// `session.tmp.28182.0` from 17:47:30 the previous day was still on disk beside
/// a `session.json` rewritten at 06:35:14 that morning — the personal-access-
/// token session had re-established itself, exactly as
/// [`remove_ambient_references`] documents it can. Without this comparison every
/// unrelated Proton failure from that day onward — an expired token, a revoked
/// one — would have been reported as a half-written session, on the strength of
/// a file that stopped mattering months earlier.
///
/// The OLDEST of several rather than the newest, because the one that has sat
/// longest is the one whose writer is least likely to still exist.
pub(super) fn interrupted_write(session_dir: &Path) -> Option<InterruptedWrite> {
    let session = session_dir.join(SESSION_SUBDIR);
    // `None` when there is no session file at all, which is not a reason to stay
    // quiet: a rename that never happened leaves precisely that.
    let landed = fs::symlink_metadata(session.join(SESSION_FILE))
        .and_then(|meta| meta.modified())
        .ok();
    let entries = fs::read_dir(&session).ok()?;
    let now = std::time::SystemTime::now();

    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with(SESSION_TEMP_PREFIX) {
                return None;
            }
            let modified = entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())?;
            if landed.is_some_and(|landed| landed > modified) {
                return None;
            }
            Some(InterruptedWrite {
                name,
                idle: now.duration_since(modified).ok(),
            })
        })
        // An entry whose age is unknown sorts last, so a readable clock always
        // decides the answer when there is one.
        .max_by_key(|write| write.idle.unwrap_or_default())
}

/// Render a path as ONE shell word, so a remedy can be pasted as printed.
///
/// A session directory with a space in it would otherwise produce advice that
/// silently logs into a DIFFERENT directory — which is the exact failure this
/// whole report exists to name.
pub(super) fn shell_word(path: &Path) -> String {
    let text = path.display().to_string();
    let safe = !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/:@%+=,".contains(&byte));
    if safe {
        text
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

/// Every `pass-cli` verb whose answer depends on which session directory it runs in.
///
/// Taken from `pass-cli --help` on 2.2.5. The list is the vendor's whole verb
/// set MINUS `help`, `update` and `support` — the three that reach no vault — so
/// it is written as an exception list rather than as a judgement made verb by
/// verb. Two of them were measured rather than assumed: `settings view` and
/// `item list` both answer `This operation requires an authenticated client`
/// against a session directory with no identity in it.
///
/// It exists to be READ BY A TEST. `tests/session_coordinate.rs` scans every
/// published file for a `pass-cli` command line written without the variable
/// that decides which identity runs it, and this is the list of verbs that makes
/// such a line wrong. See that file for what the scan cannot see.
pub const SESSION_SCOPED_VERBS: &[&str] = &[
    "agent",
    "info",
    "inject",
    "invite",
    "item",
    "login",
    "logout",
    "password",
    "personal-access-token",
    "run",
    "session",
    "settings",
    "share",
    "ssh-agent",
    "totp",
    "user",
    "vault",
];

/// One `pass-cli` command line, with the session it runs in on the front.
///
/// # Why the variable is on the front, every time
///
/// `pass-cli login` with nothing in front of it logs into the DEFAULT session —
/// `~/Library/Application Support/proton-pass-cli/.session` on macOS — which on
/// a machine that has ever had a full-account login answers `Already
/// authenticated` and changes nothing about the directory `keyless` reads. That
/// answer is true, and it is about a different session; it cost a day, twice, on
/// two machines.
///
/// `PROTON_PASS_SESSION_DIR` is the variable this adapter puts on every child it
/// spawns, so it is by construction the variable that decides which identity
/// answers `keyless`. Advice that omits it cannot be followed.
///
/// # Why this is a function rather than a habit
///
/// Every wrong spelling of this that reached an operator was a hand-written
/// string. There is no other way to build one now: this is the only place the
/// prefix is assembled, [`shell_word`] is the only place the directory is
/// quoted, and a test asserts that no published file writes a `pass-cli`
/// command line the variable is absent from. A sentence nobody is required to
/// write correctly is not a mechanism.
#[must_use]
pub fn scoped_command(session_dir: &Path, arguments: &str) -> String {
    format!(
        "{SESSION_DIR_VAR}={} pass-cli {arguments}",
        shell_word(session_dir)
    )
}

/// What stands in for the directory in advice written before there is one.
///
/// `keyless init` and `keyless setup` run BEFORE `stores.proton.session_dir`
/// exists, so their advice cannot name a real path. It can still name the
/// variable, which is the half that was missing: an operator who is told to
/// "log in to a session directory" has no way to discover that the directory
/// travels in an environment variable, and every other spelling they will reach
/// for is a documented failure — `pass-cli login` hits the default session,
/// `HOME=<dir> pass-cli login` moves the macOS keychain out from under the
/// vendor and dies at `-25307`, and `pass-cli --session-dir <dir>` is not a flag
/// that exists.
pub const SESSION_DIR_PLACEHOLDER: &str = "<the session directory you chose>";

/// The same command line, before the directory is known. See
/// [`SESSION_DIR_PLACEHOLDER`].
#[must_use]
pub fn scoped_command_template(arguments: &str) -> String {
    format!("{SESSION_DIR_VAR}={SESSION_DIR_PLACEHOLDER} pass-cli {arguments}")
}

/// What to tell an operator whose session directory holds an unfinished write.
///
/// Two states, because they call for opposite actions: a write that stopped
/// moving is damage, and a write from two seconds ago may be a sibling process
/// doing its job.
pub(super) fn interrupted_write_detail(
    session_dir: &Path,
    write: &InterruptedWrite,
    vendor: &str,
) -> String {
    let dir = session_dir.display();
    let name = &write.name;

    if !write.stale() {
        return format!(
            "the session at {dir} did not answer, and `{SESSION_SUBDIR}/{name}` was written \
             moments ago — a `pass-cli` may be writing this session right now. Run `keyless \
             doctor` again before concluding anything: a temp file that is still there and no \
             longer changing is an interrupted write, and this one is too fresh to call. \
             `pass-cli` says: {vendor}"
        );
    }

    format!(
        "the session at {dir} is HALF-WRITTEN, and that is WHY there is no identity here: \
         `{SESSION_SUBDIR}/{name}` is an unfinished write that stopped moving, and it is the \
         last thing that happened in that directory. `pass-cli` writes a session to a temp file \
         and renames it over `{SESSION_FILE}`, so a `pass-cli` killed between the two leaves \
         exactly this pair. keyless writes NOTHING in this directory — the whole write is the \
         vendor's — so it cannot make that rename atomic and cannot repair the result. Log in \
         again with the directory NAMED, because a plain `pass-cli login` answers about the \
         default session and reports `Already authenticated` while this one stays broken: `{}`. \
         keyless leaves `{name}` where it is: a temp file held by a live writer and one \
         abandoned by a dead one are the same zero bytes, and deleting a live session would be \
         worse than reporting this one — once a login has landed, a leftover older than \
         `{SESSION_FILE}` is ignored by this check anyway. `pass-cli` says: {vendor}",
        login_into(session_dir)
    )
}
