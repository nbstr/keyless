//! One verb for the whole of a vendor login: the directory, the child, the file.
//!
//! # What this replaces, and why it was ever four steps
//!
//! Logging the daemon into Proton Pass used to be a command an operator typed
//! by hand, and every clause of it was load-bearing in a way that is invisible
//! to whoever is pasting it:
//!
//! ```text
//! sudo -u <daemon> env \
//!     PROTON_PASS_SESSION_DIR=<dir> \
//!     PROTON_PASS_KEY_PROVIDER=fs \
//!     PROTON_PASS_PERSONAL_ACCESS_TOKEN=<the token> \
//!     pass-cli login
//! ```
//!
//! - **The uid** decides who owns the files the vendor creates. `pass-cli`
//!   writes its session store on invocations that only read, so a store the
//!   daemon cannot write is not a safer arrangement, it is a broken one — and
//!   it fails in a way that reads exactly like a wrong token.
//! - **The session directory** decides WHICH logged-in identity answers. With
//!   none, the vendor derives one from the caller's home, which for a daemon
//!   uid is either nothing or something nobody meant to be a credential store.
//! - **The key provider** decides whether that identity survives being read.
//!   The vendor's default keeps the local key in a login keyring, and a keyring
//!   belongs to the uid that unlocked one; asked for a key it cannot find
//!   beside a session store that exists, `pass-cli` forces a logout and
//!   reinitialises the store. See [`crate::store::proton::KeyProvider`].
//! - **The token in the environment** rather than in `--pat`, because an
//!   argument is in the process table for as long as the process lives.
//!
//! Four facts, no one of which announces itself when it is missing. Every one
//! of them is already written down in `keylessd.json`, which is why this verb
//! takes none of them as a flag: a flag that disagreed with the config would
//! log a session into a directory the daemon never looks at, and that failure
//! is indistinguishable from a wrong token.
//!
//! # What is deliberately NOT here
//!
//! **A second copy of the credential writer.** The value lands through
//! [`super::credential::store_entry`] — the same atomic `0600` rename, into the
//! same file [`super::credential::inspect`] reports on. Two writers of one
//! credential file would be free to disagree about its mode.
//!
//! **`env_clear`.** A stripped environment is one of the ways the key-provider
//! failure above is reached. This module ADDS three variables and removes
//! nothing.
//!
//! # Every vendor child this module spawns runs under a deadline
//!
//! `stores.proton.timeout_ms` bounds every one of them — `login`, `info` and
//! `logout` alike — through [`run`], which is built on
//! [`crate::store::exec::capture`]: past the deadline the child is killed and
//! reaped, and the caller reads that exactly like an ordinary vendor
//! refusal, on the same backoff a refusal already drives.
//!
//! What a killed verb can damage differs by which directory it was scoped
//! at, which is what makes killing every one of them safe. `login` and the
//! `info` that verifies it, in [`establish`], are always scoped at a FRESH
//! generation nothing is reading yet — a kill there only ever costs a
//! directory the failure path was already about to discard whole, never a
//! store anything depends on. `info` against the CURRENT, live generation —
//! [`already_authenticated_now`] here, and the renewal loop's own liveness
//! probe — is the same verb against the same directory the read path already
//! kills at a deadline in
//! [`crate::store::proton::ProtonStore::info_probe_answers`], so bounding it
//! here adds no exposure that directory does not already carry. `retire`'s
//! two logouts run against a directory nothing is writing to any more, so a
//! kill there is pure loss with no half-written store to protect.
//!
//! [`login_deadline`] allows `login` twice [`probe_deadline`]'s budget — a
//! network login is a heavier round trip than a local liveness probe — and
//! [`grace`] is built wide enough to absorb a killed login plus the time
//! `capture` waits for it to be reaped, so a sweep can never retire a fresh
//! generation a killed login is still writing into.
//!
//! **Any judgement about whether a session already exists, made without
//! asking.** The vendor no longer gets to answer that for a generation this
//! crate is about to create — a fresh generation is never refused, so a
//! `pass-cli login` reporting `LoggedIn` there proves nothing about whether an
//! identity was already live. What makes a second run of `keylessd login`
//! safe now is this crate's own `info` probe of the CURRENT generation, run
//! before anything is created — see [`establish`] — which supplies the
//! refusal the vendor's own `Client is already authenticated` used to.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::config::bounded_timeout;
use crate::secret::Secret;
use crate::store::exec::{self, REAP_GRACE};
use crate::store::proton::{self, KeyProvider};
use crate::store::proton_session::{Candidate, GenerationName, Generations};

/// The only mode the session directory may have.
///
/// The store, the local key and the timestamp file all live in here, and the
/// key is the whole of what stands between anybody on this machine and the
/// vault. The installer creates it at exactly this; so does this verb.
pub const SESSION_DIR_MODE: u32 = 0o700;

/// The store id this verb serves. There is exactly one, and it is named rather
/// than defaulted — see [`refuse_store`].
pub const STORE: &str = proton::STORE_ID;

/// A file's owning uid and gid, which for the daemon's own files are one fact.
///
/// # The gid is the access group, not the daemon's primary group
///
/// Both numbers come from one `stat` of the audit log, and the installer
/// creates every state file as `<daemon>:<access group>` — including the
/// session directory this login writes into. So a login run this way produces
/// files with the same ownership pair as everything else the install made,
/// which `sudo -u <daemon>` would not: that takes the daemon's PRIMARY group
/// instead, and the two are not the same on this install or on any other.
///
/// Nothing depends on which one it is — the directory is `0700` and the files
/// in it `0600`, so no group can read either — but a pair read from one file is
/// a pair that cannot disagree with itself, and that is the property worth
/// having when the alternative is two lookups that can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

/// Everything the login needs, read out of the config and nowhere else.
#[derive(Debug, Clone)]
pub struct Coordinates {
    /// The vendor binary to spawn.
    pub binary: PathBuf,
    /// The ROOT of the daemon's generations — `<root>/current` names which
    /// one is live, and `<root>/gen-<millis>-<pid>/` is what a login actually
    /// scopes a vendor child at. Never handed to a vendor child directly: see
    /// [`establish`], which always spawns against a specific generation
    /// directory, never against this path.
    pub session_dir: PathBuf,
    /// Where the key encrypting that identity is kept.
    pub key_provider: KeyProvider,
    /// The `0600` file the token is recorded in afterwards.
    pub credentials_file: PathBuf,
    /// The entry name inside that file the token goes under.
    pub token_entry: String,
    /// Every OTHER declared credential — vendor variable to entry name.
    ///
    /// Empty under [`KeyProvider::Fs`], where the key rides inside the token.
    /// Under [`KeyProvider::Env`] it holds
    /// [`proton::ENCRYPTION_KEY_VAR`], which the login itself needs and which
    /// this verb does not prompt for: it is a second credential, written by
    /// `keylessd credential`, and asking for two values at one prompt is how
    /// one of them ends up in the wrong file.
    pub extra: BTreeMap<String, String>,
    /// `stores.proton.timeout_ms`, the one source every deadline this module
    /// bounds a vendor child by is derived from — see [`login_deadline`] and
    /// [`probe_deadline`].
    pub timeout_ms: u64,
}

/// Why a store other than Proton has no login verb.
///
/// Not a generic "unknown store": the other two are real, configured, working
/// stores whose setup this verb genuinely does not perform, and a reader who is
/// told "no such store" goes looking for a typo.
#[must_use]
pub fn refuse_store(named: &str) -> String {
    let remedy = if named == "infisical" || named == "onepassword" {
        format!(
            "An Infisical machine identity and a 1Password service account are credentials and \
             nothing else, so writing the value IS the whole of their setup: `{} credential \
             --store {named} --name <entry>`. Only `--store {STORE}` has a session to \
             establish",
            crate::DAEMON_NAME
        )
    } else {
        format!("This build logs in exactly one store: `--store {STORE}`")
    };
    format!(
        "`--store {named}` has no vendor session to log in. A Proton Pass identity lives in a \
         session DIRECTORY that only the vendor's own binary can establish, which is what this \
         verb runs. {remedy}"
    )
}

/// Read the login's coordinates out of a parsed daemon config.
///
/// # Errors
///
/// The one arrangement that stops this verb, named specifically enough to fix.
/// Every check here is made BEFORE anything is typed, so a config that cannot
/// support a login never gets as far as asking for a credential.
pub fn coordinates(config: &super::config::DaemonConfig) -> Result<Coordinates, String> {
    let settings = &config.stores.proton;

    if !settings.enabled {
        return Err(format!(
            "`stores.{STORE}.enabled` is false, so this daemon serves no Proton name and has \
             nothing to log in. Enable the store and give it coordinates first — there is no \
             flag here that could stand in for them, because a session logged into a directory \
             this config does not name is one the daemon will never look in"
        ));
    }

    let Some(session_dir) = settings.session_dir.as_deref() else {
        return Err(format!(
            "`stores.{STORE}.session_dir` is not set, and it is never defaulted. It names the \
             directory holding the daemon's own logged-in identity; with none, `pass-cli` \
             derives one from the CALLER's home, which for a daemon uid is either nothing or \
             something nobody meant to be a credential store. Set it to the directory the \
             installer created, then run this again"
        ));
    };
    if !session_dir.is_absolute() {
        return Err(proton::relative_session_dir(
            &format!("stores.{STORE}.session_dir"),
            session_dir,
        ));
    }

    if let Some(variable) = proton::AgentToken::refused(&settings.credentials).first() {
        return Err(format!(
            "`{variable}` is named under `stores.{STORE}.credentials` and is neither \
             `{}` nor `{}`. Only those two may be named there: every other `PROTON_PASS_*` \
             variable is one this daemon SETS itself, and one named as a credential would \
             choose which identity this login establishes or where its key is looked for",
            proton::TOKEN_VAR,
            proton::ENCRYPTION_KEY_VAR
        ));
    }

    let Some(token_entry) = settings.credentials.get(proton::TOKEN_VAR).cloned() else {
        return Err(format!(
            "`stores.{STORE}.credentials` names no `{}`, so there is no entry for the token to \
             be recorded under. Add `\"{}\": \"<entry name>\"` there first: the login below \
             establishes a session, and that entry is what re-establishes it when the vendor \
             drops one, which it does without warning",
            proton::TOKEN_VAR,
            proton::TOKEN_VAR
        ));
    };

    let credentials_file = settings.credentials_file.to_path_buf();
    // The same refusal `credential` makes, for the same reason: everything in
    // the file the `file` store serves is a name an attested client can ask
    // for, so a vault-unlocking token kept there is handed to any session that
    // guesses its label.
    if config.stores.file.enabled && credentials_file == config.stores.file.path.to_path_buf() {
        return Err(format!(
            "{} is the file the `file` store serves, so anything written there is a name any \
             attested client can ask for over the socket. Point \
             `stores.{STORE}.credentials_file` at a file of its own first",
            credentials_file.display()
        ));
    }

    // `credential_entries`, not `credentials`: under `env` the local key's own
    // entry is one this daemon names when the operator did not, and every
    // reader of that map has to agree about the name — the generator writes
    // the value under it, and this is where the same name is read back.
    let extra = settings
        .credential_entries()
        .into_iter()
        .filter(|(variable, _)| variable.as_str() != proton::TOKEN_VAR)
        .collect();

    Ok(Coordinates {
        binary: settings.binary.to_path_buf(),
        session_dir: session_dir.to_path_buf(),
        key_provider: settings.key_provider,
        credentials_file,
        token_entry,
        extra,
        timeout_ms: settings.timeout_ms,
    })
}

/// What [`ensure_session_dir`] had to do to the session directory.
#[derive(Debug, PartialEq, Eq)]
pub enum Ensured {
    /// It was not there. Created at [`SESSION_DIR_MODE`], owned by the daemon.
    Created,
    /// It was there and already correct. Nothing was written.
    Sound,
    /// It was there and wrong. One line per repair, in the order they happened.
    ///
    /// Reported rather than done quietly: a session directory owned by root is
    /// exactly what a hand-typed `pass-cli login` without `sudo -u` leaves, and
    /// the operator who did that needs to know it was the problem.
    Repaired(Vec<String>),
}

/// Make the session directory one the daemon can write, without touching what
/// is inside it.
///
/// # Why the contents are re-owned and not merely reported
///
/// A directory owned by the daemon can still hold a session store owned by
/// whoever typed `sudo`, and that store is the thing `pass-cli` rewrites on
/// every read. Re-asserting the owner is the same repair `install/install.sh`
/// makes on every re-run, for the same reason: `chown` changes neither the
/// contents nor the inode, so it is safe on a directory with a working session
/// in it, and it is the only thing that turns a hand-run login into a usable
/// one.
///
/// Symlinks are re-owned with `lchown` and never followed. A symlink out of
/// this directory is not something the vendor creates, and following one would
/// let whatever planted it choose a file for root to hand away.
///
/// # Errors
///
/// The step that failed. `EPERM` here is the ordinary answer to running this
/// without `sudo`, and the caller says so rather than reporting the errno.
pub fn ensure_session_dir(dir: &Path, owner: Owner) -> Result<Ensured, String> {
    let existing = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(SESSION_DIR_MODE)
                .create(dir)
                .map_err(|error| format!("{} cannot be created: {error}", dir.display()))?;
            // `.mode()` applies to every component `recursive` had to make, and
            // only the last one is this directory. Re-asserted unconditionally
            // so a reused path cannot keep a wider mode.
            chmod(dir)?;
            chown(dir, owner)?;
            return Ok(Ensured::Created);
        }
        Err(error) => return Err(format!("{} cannot be examined: {error}", dir.display())),
    };

    if !existing.is_dir() {
        return Err(format!(
            "{} is not a directory. Proton Pass keeps a logged-in identity in a directory — the \
             session store, the local key and a timestamp file — so there is nothing this verb \
             can do with a file of that name",
            dir.display()
        ));
    }

    let mut repairs = Vec::new();
    if existing.permissions().mode() & 0o7777 != SESSION_DIR_MODE {
        chmod(dir)?;
        repairs.push(format!(
            "mode {SESSION_DIR_MODE:04o} re-asserted on {}",
            dir.display()
        ));
    }
    let mut reowned = 0_usize;
    reown(dir, owner, &mut reowned)?;
    if reowned > 0 {
        repairs.push(format!(
            "{reowned} path(s) given back to uid {}, which is what a login run without \
             `sudo -u` leaves behind",
            owner.uid
        ));
    }

    if repairs.is_empty() {
        Ok(Ensured::Sound)
    } else {
        Ok(Ensured::Repaired(repairs))
    }
}

fn chmod(dir: &Path) -> Result<(), String> {
    fs::set_permissions(dir, fs::Permissions::from_mode(SESSION_DIR_MODE)).map_err(|error| {
        format!(
            "{} cannot be set to mode {SESSION_DIR_MODE:04o}: {error}",
            dir.display()
        )
    })
}

fn chown(path: &Path, owner: Owner) -> Result<(), String> {
    std::os::unix::fs::lchown(path, Some(owner.uid), Some(owner.gid)).map_err(|error| {
        format!(
            "{} cannot be given to uid {}: {error}",
            path.display(),
            owner.uid
        )
    })
}

/// Give `path` and everything under it to `owner`, counting what changed.
///
/// Only what is already wrong is written, so a correct directory needs no
/// privilege at all and this verb can be run unprivileged far enough to be
/// refused for a reason that is about the login rather than about a `chown`.
fn reown(path: &Path, owner: Owner, changed: &mut usize) -> Result<(), String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|error| format!("{} cannot be examined: {error}", path.display()))?;
    if meta.uid() != owner.uid || meta.gid() != owner.gid {
        chown(path, owner)?;
        *changed += 1;
    }
    // Symlinks are re-owned above and never descended into.
    if !meta.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(path)
        .map_err(|error| format!("{} cannot be listed: {error}", path.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("{} cannot be listed: {error}", path.display()))?;
        reown(&entry.path(), owner, changed)?;
    }
    Ok(())
}

/// One `pass-cli login` invocation, scoped at `dir` and not yet spawned.
///
/// Split out so a test can read the argument vector and the environment from
/// the outside. The property being defended is not that the login works — it is
/// that the TOKEN is in the environment and the argument vector is the two
/// words `pass-cli login`, and an assertion on the returned status could not
/// tell those apart.
///
/// `dir` is a specific GENERATION directory, never
/// [`Coordinates::session_dir`] — see that field's own doc. Every builder in
/// this file takes the directory explicitly for the same reason: a generation
/// changes on every attempt, so nothing here may read it off `coordinates`.
#[must_use]
pub fn login_command(
    coordinates: &Coordinates,
    dir: &Path,
    login: &[(String, Secret)],
    owner: Owner,
) -> Command {
    let mut command = Command::new(&coordinates.binary);
    command.arg("login");
    scope(&mut command, coordinates, dir, login, owner);
    command
}

/// One `pass-cli info` invocation, scoped at `dir` — does a session answer
/// there?
///
/// The liveness half of the loop Proton publishes: `pass-cli info 2>/dev/null
/// || … pass-cli login`. It carries no TOKEN, because the question is about
/// the session store rather than about the account: a directory with a live
/// identity answers, and one whose identity has gone answers `This operation
/// requires an authenticated client`.
///
/// # Why `login` is a parameter here too
///
/// `info`, like every verb here, builds a client before it does anything
/// else — and under [`KeyProvider::Env`] building a client means
/// `EnvLocalKeyProvider::new()` reads [`proton::ENCRYPTION_KEY_VAR`] out of
/// the environment BEFORE the vendor ever looks at the session directory. A
/// caller that named the `env` provider and passed no key would fail on
/// every call for that reason alone — not because the session died, but
/// because nothing here gave the vendor anything to decrypt it with. So
/// `login` carries [`extra_credentials`]' output: never the token (this verb
/// asks nothing that needs one), and under `fs` an empty slice, matching the
/// vendor's own file-backed key which needs no variable at all.
///
/// Scoped exactly as the two verbs beside it. `info` is on
/// [`crate::store::proton::SESSION_SCOPED_VERBS`], so run without
/// `PROTON_PASS_SESSION_DIR` it reports on the DEFAULT session — a different
/// identity, usually a healthy one, which is the answer that makes a dead
/// daemon session read as fine.
#[must_use]
pub fn info_command(
    coordinates: &Coordinates,
    dir: &Path,
    login: &[(String, Secret)],
    owner: Owner,
) -> Command {
    let mut command = Command::new(&coordinates.binary);
    command.arg("info");
    scope(&mut command, coordinates, dir, login, owner);
    command
}

/// One `pass-cli logout` invocation, scoped at `dir`, for the retirement path
/// only — never against the directory an ordinary, generation-named
/// [`Coordinates::session_dir`] names as current. The one deliberate
/// exception is the legacy retirement candidate: it carries no name of its
/// own (see [`crate::store::proton_session::Candidate::name`]), so `dir` IS
/// `Coordinates::session_dir` there — the vendor appends its own `.session`
/// subdirectory to whatever root it is given, which is exactly what that
/// candidate needs.
///
/// `force` appends `--force`, measured against the real vendor binary as
/// deleting the directory's contents rather than ending the session at the
/// account — its own `--help` says only "Force logout even if remote logout
/// fails" and claims nothing about what happens on disk. See [`retire`], the
/// only caller that ever passes `true`, and only after a plain logout has
/// already failed.
///
/// `login` is [`info_command`]'s own parameter, for the same reason: a PLAIN
/// logout (`force: false`) builds a client exactly like `info` does, so it
/// needs the same key under [`KeyProvider::Env`] to reach the vendor at all.
/// `pass-cli logout --force` is the one exception — `main.rs`'s own dispatch
/// answers `is_force_logout()` before any client is built, so a forced logout
/// never constructs a key provider and never fails on a missing one. `login`
/// is threaded through unconditionally even there: a builder that carries it
/// only sometimes is a builder a later change forgets to carry it through in
/// the case that still needs it, which is exactly how this bug shipped once
/// already — see [`scope`]'s own doc on the five daemon-side builders in
/// [`crate::store::proton::ProtonStore`] for the sibling argument.
#[must_use]
pub fn logout_command(
    coordinates: &Coordinates,
    dir: &Path,
    force: bool,
    login: &[(String, Secret)],
    owner: Owner,
) -> Command {
    let mut command = Command::new(&coordinates.binary);
    command.arg("logout");
    if force {
        command.arg("--force");
    }
    scope(&mut command, coordinates, dir, login, owner);
    command
}

/// Everything every verb below needs, applied in one place so none can lack
/// one.
///
/// Deliberately not [`Command::env_clear`]: a stripped environment is one of
/// the ways the vendor loses its local key and force-logs-out. This ADDS.
fn scope(
    command: &mut Command,
    coordinates: &Coordinates,
    dir: &Path,
    login: &[(String, Secret)],
    owner: Owner,
) {
    use std::os::unix::process::CommandExt;

    command.env(proton::SESSION_DIR_VAR, dir);
    command.env(proton::KEY_PROVIDER_VAR, coordinates.key_provider.as_str());
    for (variable, secret) in login {
        command.env(variable, secret.expose());
    }
    // The daemon's login, info and logout are `pass-cli` invocations like any
    // other this crate spawns: no telemetry row, no update check. See
    // `proton::set_vendor_switch_offs`.
    proton::set_vendor_switch_offs(command);
    // Whoever runs this owns what the vendor creates. Set unconditionally: from
    // root it is the privilege drop, and from the daemon's own uid it is a
    // no-op that still succeeds, so there is no branch here that could be right
    // on one machine and wrong on another. Dropping from root also clears the
    // supplementary groups, which `std` does as part of `uid`.
    command.gid(owner.gid);
    command.uid(owner.uid);
    // Nothing on this child's stdin. `pass-cli login` with no token in the
    // environment falls back to an interactive web login, and one inheriting a
    // terminal would sit there waiting rather than failing.
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
}

/// What the vendor did, read out of what it said.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A session now exists in the directory.
    LoggedIn,
    /// One was already there and the vendor refused to replace it.
    ///
    /// # Why this is the shape that makes a second run safe
    ///
    /// `pass-cli` 2.3.2 answers `Client is already authenticated. Log out if
    /// you want to log in again`. So a re-run of this verb cannot overwrite a
    /// working session even by accident — the vendor stops it before anything
    /// in that directory is touched. That is a stronger guarantee than a check
    /// made here could be, because it is made by the only program that knows.
    ///
    /// It also means a token ROTATION needs a logout first, which is what
    /// `--replace` is and why it is a flag rather than the default.
    AlreadyAuthenticated,
    /// The vendor could not find the local key beside a store that exists, and
    /// has reinitialised the store. The single worst outcome, and the one the
    /// key provider exists to prevent.
    KeyLost(String),
    /// The account will not accept the token. One sentence for three causes —
    /// invalid, expired, deleted — and the vendor cannot be asked which.
    TokenRefused(String),
    /// The login never reached the vendor's service, so nothing was decided
    /// about the token at all.
    Unreachable(String),
    /// Anything else, in the vendor's own words.
    Failed(String),
}

/// The vendor's own sentence for a session that is already there.
const ALREADY: &str = "already authenticated";

/// The vendor's own sentence for the key-provider failure.
const KEY_LOST: &str = "local encryption key not found";

/// The vendor's own noun for a token it will not take.
const REFUSED: &str = "personal access token";

/// Read the vendor's answer.
///
/// # Why the TEXT decides before the exit code does
///
/// Two of these outcomes are catastrophic and two are ordinary, and an exit
/// code separates none of them. `Already authenticated` is a refusal on 2.3.2,
/// but a release that made it a warning and exited zero would silently turn
/// "your session was left alone" into "logged in", which is the one claim this
/// verb must never make wrongly — it is what decides whether a token gets
/// written. So the words are read first, in both streams, and the status only
/// decides between success and a failure nothing else recognised.
///
/// # Why a network failure is checked before a refused token
///
/// The vendor names its whole login flow after the token, so every line of a
/// failure it reports carries [`REFUSED`] — including one that never left the
/// machine: `Error in personal access token login flow … failed to connect to
/// host: error resolving destination`. Tested for the noun alone, a laptop
/// waking without a network was filed as an account that had refused its
/// token, and the message sent its reader to the vendor's dashboard to inspect
/// a token nobody had checked.
#[must_use]
pub fn classify(status: ExitStatus, said: &str) -> Outcome {
    let lowered = said.to_ascii_lowercase();
    if lowered.contains(ALREADY) {
        return Outcome::AlreadyAuthenticated;
    }
    if lowered.contains(KEY_LOST) {
        return Outcome::KeyLost(said.trim().to_owned());
    }
    if status.success() {
        return Outcome::LoggedIn;
    }
    if proton::reached_no_service(&lowered) {
        return Outcome::Unreachable(said.trim().to_owned());
    }
    if lowered.contains(REFUSED) {
        return Outcome::TokenRefused(said.trim().to_owned());
    }
    Outcome::Failed(said.trim().to_owned())
}

/// Spawn a built command, run it to completion or kill it at `deadline`, and
/// return its status with both streams joined.
///
/// Every vendor child this module spawns runs under a deadline: [`establish`]
/// scopes `login` at [`login_deadline`] and `info` at [`probe_deadline`], and
/// [`discard_unpublished`]'s plain logout is a probe too. A killed child is
/// reaped by [`exec::capture`] itself, within [`REAP_GRACE`] of the deadline
/// — so a hung `pass-cli` is never left running and never leaves this
/// function waiting on it.
///
/// # Errors
///
/// [`exec::CaptureError`]. [`exec::CaptureError::Spawn`] is the ordinary
/// answer to running this without `sudo`, because the child asks to become
/// the daemon's uid before it execs; the caller turns that into a sentence
/// about privilege rather than an errno. Every other variant, above all
/// [`exec::CaptureError::TimedOut`], is the vendor child having been killed
/// at `deadline` — the caller reports that a verb was killed and that
/// nothing was made current, and takes the same discard path an ordinary
/// vendor refusal takes.
pub fn run(
    command: Command,
    deadline: Duration,
) -> Result<(ExitStatus, String), exec::CaptureError> {
    let captured = exec::capture(command, deadline)?;
    let mut said = String::from_utf8_lossy(&captured.stderr).into_owned();
    said.push('\n');
    said.push_str(&String::from_utf8_lossy(&captured.stdout));
    Ok((captured.status, said))
}

/// What to tell an operator on a machine where the daemon's uid is unknown.
///
/// Refused rather than guessed, and the reasoning is
/// [`super::credential`]'s: nothing in `keylessd.json` says which uid the
/// daemon runs as, so the only evidence is a file the daemon owns. A login run
/// as the wrong uid produces a session store the daemon cannot open, and that
/// failure reads exactly like a wrong token — which is the single most
/// expensive way for this verb to be wrong.
#[must_use]
pub fn no_daemon_uid(audit: &Path) -> String {
    format!(
        "{} is not there, so nothing here knows which uid the daemon runs as — and this login \
         has to run as that uid, because whoever runs it owns the session store `pass-cli` \
         creates. The plist says the uid and this process does not read it; the audit log is \
         what the installer creates owned by the daemon. Run `install/install.sh --commit`, or \
         start the daemon once, and try again. Guessing would produce a session directory the \
         daemon cannot open, which fails in a way that reads exactly like a wrong token",
        audit.display()
    )
}

/// Read every declared credential the login needs BESIDES the token.
///
/// Empty under [`KeyProvider::Fs`]. Under [`KeyProvider::Env`] the local key is
/// a second credential that `keylessd credential` writes, and the login cannot
/// establish a session without it — so it is read here, before anything is
/// prompted for, and a missing one refuses with the command that writes it.
///
/// # Errors
///
/// The entry that could not be read, named. No value appears in the message.
pub fn extra_credentials(coordinates: &Coordinates) -> Result<Vec<(String, Secret)>, String> {
    use crate::store::Store;

    if coordinates.extra.is_empty() {
        return Ok(Vec::new());
    }
    let file = crate::store::file::FileStore::new(coordinates.credentials_file.clone());
    let mut resolved = Vec::with_capacity(coordinates.extra.len());
    for (variable, entry) in &coordinates.extra {
        match file.resolve(entry) {
            Ok(Some(secret)) => resolved.push((variable.clone(), secret)),
            Ok(None) => {
                // Two remedies, and naming the wrong one sends an operator at
                // a verb this daemon refuses. The local key is a value this
                // daemon GENERATES — `credential` declines to write it,
                // precisely because a typed value there makes every published
                // generation unreadable — so what is owed is a restart, or
                // simply the next tick of a renewal loop that generates before
                // it logs in. Every other entry is a value a person holds, and
                // for those `credential` is exactly right.
                let remedy = if variable == proton::ENCRYPTION_KEY_VAR {
                    format!(
                        "this is a value `{}` writes itself at its first start and reuses on \
                         every later one — nothing has to be typed. Restart it, or wait for \
                         the renewal loop's next attempt, which generates it before it logs in",
                        crate::DAEMON_NAME
                    )
                } else {
                    format!(
                        "write it first, without the value passing through a command line: \
                         `{} credential --store {STORE} --name {entry}`",
                        crate::DAEMON_NAME
                    )
                };
                return Err(format!(
                    "`{variable}` is declared to live in `{entry}` of {}, which holds no such \
                     entry — and the login cannot establish a session without it. {remedy}",
                    coordinates.credentials_file.display(),
                ));
            }
            Err(error) => {
                return Err(format!(
                    "`{variable}` is declared to live in `{entry}` of {}, which could not be \
                     read: {error}",
                    coordinates.credentials_file.display()
                ));
            }
        }
    }
    Ok(resolved)
}

/// Where a login's token comes from, decided before anything is read.
///
/// # Why this is a value and not four lines inside the verb
///
/// The rule has four inputs — a terminal or a pipe, `--prompt`, `--replace`,
/// and whether the daemon already holds a token — and one of the sixteen
/// combinations is a silent wrong-credential rotation. Written inline it can
/// only be exercised by running the binary under a pseudo-terminal, which is
/// why the branch that mattered went untested: a piped test never reaches the
/// terminal arm at all, and passes while proving nothing about it.
///
/// As a value the whole matrix is decidable in a unit test.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TokenSource {
    /// Read it from whoever is on the other end — a pipe, or a person.
    Read,
    /// Use the entry the credential file already holds, and do not rewrite it.
    Held,
}

impl TokenSource {
    /// Decide, from the four things that bear on it.
    ///
    /// # The case this exists for
    ///
    /// `--replace` is this verb's rotation flag — "the token-rotation path, and
    /// deliberately not the default". At a terminal it says a person is here
    /// and means to install a NEW value. Letting the credential file answer
    /// there produces the worst outcome this verb has: the daemon logs back in
    /// with the OLD token, the command reports success, and an operator walks
    /// away believing a rotation happened. The old credential keeps working
    /// until the day it stops, and nothing anywhere says why.
    ///
    /// So a terminal plus `--replace` asks, even with a token on disk.
    ///
    /// Unattended repair is untouched, and it is the reason the rule reads the
    /// terminal rather than `--replace` alone: `keylessd login --replace`
    /// with no terminal — from a script, or `< /dev/null` — still uses what the
    /// daemon holds, because there is nobody to ask and re-establishing a
    /// session from the stored token is exactly what it wants.
    #[must_use]
    pub fn decide(interactive: bool, prompt: bool, replace: bool, holds_one: bool) -> Self {
        if prompt || !holds_one {
            return TokenSource::Read;
        }
        if interactive && replace {
            return TokenSource::Read;
        }
        TokenSource::Held
    }
}

/// The token this daemon already holds, if it holds one.
///
/// # Why a login reads the file it would otherwise write
///
/// The credential file is the source of truth for this daemon's identity, and
/// two verbs used to demand the same value on stdin — `credential` to write it
/// and `login` to use it — so a bootstrap that ran both asked the operator to
/// paste the same token twice. HashiCorp's Vault Agent draws the line the other
/// way and is right: its AppRole auto-auth takes the bootstrap credential from
/// `secret_id_file_path` and offers no prompt at all, and rotation is writing
/// the file again — "new files or values written at the expected locations will
/// be used on next authentication".
///
/// So the file answers first here too, and the prompt is what happens when it
/// cannot. [`super::session`] already worked this way; this is `login` catching
/// up with the loop.
///
/// # Errors
///
/// A file that exists and could not be read. A file with no such entry is
/// `Ok(None)` — that is the ordinary first-run state, not a fault.
pub fn stored_token(coordinates: &Coordinates) -> Result<Option<Secret>, String> {
    use crate::store::Store;

    let file = crate::store::file::FileStore::new(coordinates.credentials_file.clone());
    match file.resolve(&coordinates.token_entry) {
        Ok(found) => Ok(found),
        // An unreadable file is the same absence as an empty one for this
        // verb's purposes: there is nothing to log in with, and the prompt is
        // the remedy either way. The `identity` row of `check` is where an
        // operator is told the file itself is wrong.
        Err(_) => Ok(None),
    }
}

/// Log in, and record the token only once the vendor has taken it.
///
/// # Why the login happens BEFORE the file is written
///
/// The two halves can each fail, and the order decides which half-finished
/// state an operator is left in.
///
/// Written first, a token the account has just refused sits in a `0600` file
/// that `keylessd check` reports as SOUND — its `token` row judges shape, and a
/// well-formed token the vendor rejects passes every structural rule there is.
/// That is a false green over a long-lived credential doing nothing.
///
/// Logged in first, the only half-finished state is a working session whose
/// token was not recorded, which `check` reports in the `identity` row as an
/// empty credential file — true, red, and with the right remedy. See
/// [`logged_in_but_unwritten`].
///
/// So the login is also the only proof this crate can obtain that the token is
/// real, and nothing is written until it has been obtained.
///
/// # Errors
///
/// The sentence to print. `Ok` means both halves happened.
pub fn perform(
    coordinates: &Coordinates,
    owner: Owner,
    replace: bool,
    token: &Secret,
    extra: Vec<(String, Secret)>,
    generations: &Generations,
    out: &mut dyn std::io::Write,
) -> Result<(), String> {
    let name = establish(coordinates, owner, replace, token, extra, generations, out)?;

    super::credential::store_entry(
        &coordinates.credentials_file,
        &coordinates.token_entry,
        token,
        Some((owner.uid, owner.gid)),
    )
    .map_err(|error| {
        logged_in_but_unwritten(
            coordinates,
            &generations.root().join(name.as_str()),
            &error.to_string(),
        )
    })?;

    writeln!(
        out,
        "stored\t{}\t{}",
        coordinates.token_entry,
        coordinates.credentials_file.display()
    )
    .map_err(|error| format!("the report could not be written: {error}"))
}

/// Establish a session in a FRESH generation directory, and record nothing.
///
/// The half of [`perform`] that talks to the vendor, split out so the renewal
/// loop in [`super::session`] can reuse it without rewriting a token the file
/// already holds.
///
/// # The flow, and why each step is safe
///
/// 1. Unless `replace` is set, probe the CURRENT generation with `info`; if
///    one answers, refuse with [`already_authenticated`] — this crate's own
///    refusal, since a fresh generation is never refused by the vendor and so
///    cannot supply one on its own (see the module header).
/// 2. [`Generations::create`] a fresh, empty, `0700` directory. Nothing reads
///    it yet.
/// 3. `pass-cli login`, scoped at that directory alone and killed if it is
///    still running at [`login_deadline`]. Anything but [`Outcome::LoggedIn`]
///    — a kill included — discards the directory directly — no grace, no
///    sweep, because its only possible reader is this call and `run` has
///    already returned.
/// 4. Verify with `pass-cli info` at the same directory, killed if it is
///    still running at [`probe_deadline`]. A non-zero answer or a kill means
///    the vendor reported success and then could not be asked anything —
///    discarded the same way as step 3, after a plain logout first, since
///    the account-side session this time genuinely exists.
/// 5. [`Generations::publish`]. From this instant every new pass reads the
///    new generation. A failure here discards the same way as step 4 — the
///    directory is fully logged in and unpublished, which is exactly the
///    state step 4's discard already handles.
///
/// The OLD generation, if any, is never opened, mutated or deleted by this
/// function. Retiring it is [`sweep`]'s job, on its own grace.
///
/// # Why the renewal must NOT write the token back
///
/// It is the same value, so the write looks free — and it is the one step in
/// [`perform`] that can fail on a healthy renewal. A full disk, a read-only
/// filesystem or a credential file an operator has just chmod'd turns a
/// successful login into [`logged_in_but_unwritten`], which backs the loop off
/// and eventually notifies, over a session that is in fact alive. Writing the
/// token belongs to the verb that has just been HANDED one; a loop that read
/// it out of the file has nothing new to record.
///
/// # Errors
///
/// The sentence to print. `Ok` carries the generation that is now current.
pub fn establish(
    coordinates: &Coordinates,
    owner: Owner,
    replace: bool,
    token: &Secret,
    extra: Vec<(String, Secret)>,
    generations: &Generations,
    out: &mut dyn std::io::Write,
) -> Result<GenerationName, String> {
    if !replace && already_authenticated_now(coordinates, owner, generations, &extra) {
        let current = generations
            .current()
            .expect("already_authenticated_now only answers true when current() is Ok");
        return Err(already_authenticated(
            &generations.root().join(current.as_str()),
            "the vendor's own liveness probe answered there, which is this crate's own check \
             standing in for the vendor's login refusal — a freshly created generation is \
             never refused",
        ));
    }

    let (name, dir) = generations
        .create(Some((owner.uid, owner.gid)))
        .map_err(|error| {
            format!(
                "a fresh Proton session directory could not be created under {}: {error}",
                generations.root().display()
            )
        })?;

    let mut login = extra;
    // A second [`Secret`] rather than a borrow of the caller's, so the token is
    // still here to be written once the vendor has taken it.
    //
    // Pushed LAST and popped on the line after the spawn returns, which is the
    // last moment anything here needs it: the pop drops that `Secret`, and
    // [`Secret`]'s own `Drop` zeroizes it. Popping rather than slicing is what
    // keeps this function from carrying a live copy of the token through the
    // `info` call, the publish and their three failure paths, all of which
    // spawn children of their own. What is left in `login` afterwards is
    // exactly the extra credentials this function was handed — which is what
    // those later spawns carry, `info` taking no token by design (see its own
    // doc) — reused rather than resolved a second time, so the local key never
    // exists twice in this process either.
    login.push((
        proton::TOKEN_VAR.to_owned(),
        Secret::new(token.expose().to_owned()),
    ));

    let spawned = run(
        login_command(coordinates, &dir, &login, owner),
        login_deadline(coordinates.timeout_ms),
    );
    drop(login.pop());
    let extra_only = &login;

    let (status, said) = spawned.map_err(|error| {
        let _ = fs::remove_dir_all(&dir);
        not_run(coordinates, owner, &dir, "login", &error)
    })?;

    let outcome = classify(status, &said);
    if outcome != Outcome::LoggedIn {
        let _ = fs::remove_dir_all(&dir);
        return Err(match outcome {
            Outcome::AlreadyAuthenticated => already_authenticated(&dir, said.trim()),
            Outcome::KeyLost(said) => key_lost(coordinates, &dir, &said),
            Outcome::TokenRefused(said) => token_refused(coordinates, &said),
            Outcome::Unreachable(said) => unreachable(coordinates, &said),
            Outcome::Failed(said) => format!(
                "the login into {} failed for a reason nothing here recognises, and nothing \
                 was written to {}: {said}",
                dir.display(),
                coordinates.credentials_file.display()
            ),
            Outcome::LoggedIn => unreachable!("handled above"),
        });
    }
    writeln!(out, "login\t{STORE}\t{}", dir.display())
        .map_err(|error| format!("the report could not be written: {error}"))?;

    let (status, said) = run(
        info_command(coordinates, &dir, extra_only, owner),
        probe_deadline(coordinates.timeout_ms),
    )
    .map_err(|error| {
        discard_unpublished(coordinates, &dir, extra_only, owner);
        not_run(coordinates, owner, &dir, "info", &error)
    })?;
    if !status.success() {
        discard_unpublished(coordinates, &dir, extra_only, owner);
        return Err(format!(
            "the login into {} succeeded but the session did not answer `info`, so nothing was \
             made current: {}",
            dir.display(),
            said.trim()
        ));
    }

    generations
        .publish(&name, Some((owner.uid, owner.gid)))
        .map_err(|error| {
            discard_unpublished(coordinates, &dir, extra_only, owner);
            format!(
                "{} logged in but could not be made current: {error}",
                dir.display()
            )
        })?;

    writeln!(out, "established generation {name}")
        .map_err(|error| format!("the report could not be written: {error}"))?;
    Ok(name)
}

/// Does a session already answer in the CURRENT generation?
///
/// This crate's own replacement for the vendor's `Client is already
/// authenticated` refusal, which a fresh generation can never trigger — see
/// the module header. `false` covers both "no" and "could not be asked",
/// because either one means [`establish`] should proceed to create a fresh
/// generation rather than refuse.
///
/// `login` is the same extra-credentials slice [`establish`] was handed —
/// under [`KeyProvider::Env`] this probe needs the local key exactly as
/// every other `info` call does, or it reads as "could not be asked" on
/// every attempt and `establish` always proceeds to create a fresh
/// generation, never refusing a genuine double-run.
fn already_authenticated_now(
    coordinates: &Coordinates,
    owner: Owner,
    generations: &Generations,
    login: &[(String, Secret)],
) -> bool {
    let Ok(pass) = generations.enter() else {
        return false;
    };
    run(
        info_command(coordinates, pass.dir(), login, owner),
        probe_deadline(coordinates.timeout_ms),
    )
    .map(|(status, _)| status.success())
    .unwrap_or(false)
}

/// Log out (best-effort) and delete a generation this call created but will
/// never publish.
///
/// The one exception to the grace-and-drain retirement [`sweep`] performs: a
/// generation nobody but THIS call could ever have read, whose `run` has
/// already returned, needs neither a grace nor a drain — there is no reader
/// left to wait for. The logout is attempted unconditionally, bounded by
/// [`probe_deadline`] like every other logout this module spawns; whether the
/// account had anything to end, or the child had to be killed to find out, is
/// the vendor's business and not decisive here.
///
/// `login` carries the same extra credentials [`establish`] holds — a plain
/// logout builds a client exactly like `info` does, so under
/// [`KeyProvider::Env`] it needs the same key to even ATTEMPT the account-side
/// end before this falls back to discarding the directory.
fn discard_unpublished(
    coordinates: &Coordinates,
    dir: &Path,
    login: &[(String, Secret)],
    owner: Owner,
) {
    let _ = run(
        logout_command(coordinates, dir, false, login, owner),
        probe_deadline(coordinates.timeout_ms),
    );
    let _ = fs::remove_dir_all(dir);
}

/// What to tell an operator whose child could not even be started.
///
/// Two causes and they are nothing alike: the binary is not there, or this
/// process is not allowed to become the daemon. The second is what running
/// this without `sudo` looks like, and an errno alone sends the reader to the
/// wrong one.
fn cannot_spawn(coordinates: &Coordinates, owner: Owner, error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        return format!(
            "this process cannot become uid {} / gid {} to run the login, so nothing has \
             happened: {error}. Whoever runs the login owns the session store `pass-cli` \
             creates, and a store the daemon cannot open fails in a way that reads exactly \
             like a wrong token — so this verb will not run it as anybody else. Run it with \
             `sudo`. Both numbers are read off the audit log named in this config, and either \
             one of the two can be the half that was refused",
            owner.uid, owner.gid
        );
    }
    format!(
        "{} could not be started, so nothing has happened: {error}. That is \
         `stores.{STORE}.binary` in the config, and it is worth an absolute path — this runs \
         as the daemon, whose `PATH` is not yours",
        coordinates.binary.display()
    )
}

/// What to tell an operator whose vendor child produced no answer to read —
/// it never started, or [`run`] ended it at its deadline.
///
/// A spawn failure is [`cannot_spawn`]'s sentence. Every other
/// [`exec::CaptureError`] is the deadline, rather than the vendor, ending the
/// child: its own [`std::fmt::Display`] already says `no answer within N ms`,
/// so this adds only what that error cannot — which verb, against which
/// directory, and that nothing was made current because of it.
fn not_run(
    coordinates: &Coordinates,
    owner: Owner,
    dir: &Path,
    verb: &str,
    error: &exec::CaptureError,
) -> String {
    if let exec::CaptureError::Spawn(error) = error {
        return cannot_spawn(coordinates, owner, error);
    }
    format!(
        "`pass-cli {verb}` at {} was stopped: {error}. The child is gone and nothing there was \
         made current; the next attempt establishes another fresh generation. Nothing was \
         written to {}",
        dir.display(),
        coordinates.credentials_file.display()
    )
}

/// What to tell an operator whose current generation already holds an
/// identity.
///
/// `said` names WHY this call believes that — either the vendor's own refusal
/// of a login into a directory that, in the ordinary case, was never fresh
/// (`Outcome::AlreadyAuthenticated`, now reachable only if something else
/// logged into a generation this call had just created), or this crate's own
/// `info` probe of the current generation, which is the refusal
/// [`establish`] actually relies on — see the module header.
#[must_use]
pub fn already_authenticated(dir: &Path, said: &str) -> String {
    format!(
        "{} already holds a logged-in identity: {said}\n\
         \n\
         NOTHING was changed — not the session, not the credential file — and the token you \
         typed was discarded. If that identity is the one you want, there is nothing to do; run \
         `{daemon} check` to see whether the daemon accepts it. If you are ROTATING the token, \
         re-run with `--replace`, which establishes a fresh generation and makes it current \
         without touching this one until it has proven itself.\n\
         \n\
         To record a token in the credential file WITHOUT touching the session: \
         `{daemon} credential --store {STORE} --name <entry>`",
        dir.display(),
        daemon = crate::DAEMON_NAME
    )
}

/// What to tell an operator whose fresh generation the vendor reinitialised.
#[must_use]
pub fn key_lost(coordinates: &Coordinates, dir: &Path, said: &str) -> String {
    format!(
        "`pass-cli` could not find the local key for {}, found a session store beside it, and \
         FORCED A LOGOUT to reinitialise the store: {said}\n\
         \n\
         That directory has been discarded — it was a fresh generation this attempt created and \
         never published, so nothing was reading it. This daemon set `{}={}`, so the key was \
         looked for in the directory itself; a key-provider mismatch is the ordinary way this \
         happens. Nothing was written to {}. The next attempt establishes another fresh \
         generation",
        dir.display(),
        proton::KEY_PROVIDER_VAR,
        coordinates.key_provider.as_str(),
        coordinates.credentials_file.display()
    )
}

/// What to tell an operator whose token the account will not take.
#[must_use]
pub fn token_refused(coordinates: &Coordinates, said: &str) -> String {
    format!(
        "Proton Pass refused the token: {said}\n\
         \n\
         That one sentence covers a token that is invalid, one that has expired and one that \
         has been deleted, and the vendor offers nothing that tells them apart — so check the \
         agent at the vendor rather than the file here. NOTHING was written to {}: a token the \
         account has just refused is a long-lived credential on disk that does nothing, and \
         `{} check` would report its SHAPE as sound while every Proton name degraded",
        coordinates.credentials_file.display(),
        crate::DAEMON_NAME
    )
}

/// What to tell an operator whose login never reached the vendor.
///
/// Says what was NOT learned as plainly as what failed: the token was never
/// presented, so this is no evidence about it either way, and the fix is a
/// connection rather than a new token.
#[must_use]
pub fn unreachable(coordinates: &Coordinates, said: &str) -> String {
    format!(
        "Proton Pass could not be reached from this machine, so the token was never checked: \
         {said}\n\
         \n\
         This is the network — DNS, a VPN, a captive portal, a machine that has just woken — \
         and says nothing about the token. Nothing was written to {}. A daemon with \
         `session.auto_login` on keeps retrying on its own backoff, and a login typed by hand \
         succeeds once the connection is back",
        coordinates.credentials_file.display()
    )
}

/// What to tell an operator whose login landed but whose file write did not.
///
/// The one half-finished state this verb can leave, said in full rather than as
/// an errno, because what `check` will report next is the opposite of alarming:
/// the session works, so every name resolves, and the row that is red is about
/// a file nobody is looking at.
#[must_use]
pub fn logged_in_but_unwritten(coordinates: &Coordinates, dir: &Path, detail: &str) -> String {
    format!(
        "the session at {} is established and current, and every Proton name will resolve — \
         but the token could not be recorded in {}: {detail}\n\
         \n\
         So nothing can re-establish that session when the vendor drops it, which it does \
         without warning, and the failure would arrive at an hour nobody chose. `{} check` says \
         so in the `identity` row. Fix the file and run `{} credential --store {STORE} --name \
         {}` with the same token",
        dir.display(),
        coordinates.credentials_file.display(),
        crate::DAEMON_NAME,
        crate::DAEMON_NAME,
        coordinates.token_entry
    )
}

/// The deadline a `pass-cli info` or a `pass-cli logout` child is killed at.
///
/// The plain `bounded_timeout(timeout_ms)` every other lookup in this crate is
/// bounded by — the same read-path budget `stores.proton.timeout_ms`
/// configures for everything else this daemon spawns against Proton.
#[must_use]
pub fn probe_deadline(timeout_ms: u64) -> Duration {
    bounded_timeout(timeout_ms)
}

/// The deadline a `pass-cli login` child is killed at.
///
/// Twice [`probe_deadline`]: a network login is a heavier round trip than a
/// local liveness probe, so it is allowed twice the budget rather than being
/// killed at the same bound a probe is. And twice is the most this may ever
/// be, because [`grace`] is built to absorb it — see that function's own
/// `2 × bounded_timeout(timeout_ms)` term, which exists so that a login this
/// crate has just killed can never still be writing into a directory once a
/// sweep has decided that directory's grace has cleared. A login allowed
/// three times the probe would need `grace` widened to match, and nothing
/// here enforces that the two stay in step except the unit test beside this
/// function.
#[must_use]
pub fn login_deadline(timeout_ms: u64) -> Duration {
    2 * bounded_timeout(timeout_ms)
}

/// The grace a retirement candidate must clear before [`sweep`] logs it out.
///
/// `2 × bounded_timeout(timeout_ms) + REAP_GRACE + 1s`. Two `capture`-bounded
/// children can outlive one attempt's own `timeout_ms` — a `resolve` spawns
/// the listing and the read as two children, each bounded separately — so the
/// grace covers two full budgets rather than one. [`REAP_GRACE`] is the extra
/// `capture` itself waits for a killed child's pipes to drain, and the final
/// second covers the gap between a token being read and its child actually
/// spawning. Never configurable, and never allowed below one `capture`
/// timeout plus [`REAP_GRACE`] — see [`Generations::drain`]'s own contract,
/// which this exists to satisfy: no other process's child can still be
/// reading a candidate once its age clears this bound.
#[must_use]
pub fn grace(timeout_ms: u64) -> Duration {
    2 * bounded_timeout(timeout_ms) + REAP_GRACE + Duration::from_secs(1)
}

/// Run the ordered retirement procedure against one candidate.
///
/// Never touches [`Generations::current`] — every step is guarded by
/// [`Generations`] itself refusing to hand out or delete the current name, so
/// this function's own logic never has to re-derive that guard.
///
/// 1. [`Generations::drain`] — wait for this process's own readers of the
///    candidate to finish, for at most `bound`.
/// 2. A plain `pass-cli logout`, scoped at the candidate and bounded by
///    [`probe_deadline`] like every other logout this module spawns — see
///    the module header. Success, or the vendor's own "already logged out",
///    both mean the account-side session this candidate held is gone; a
///    killed child is read the same as a refusal.
/// 3. On any other outcome — a refusal, a spawn failure, or a kill alike —
///    `pass-cli logout --force`, bounded the same way. The vendor's own
///    words describe this as deleting the directory's contents rather than
///    ending the session at the account, which is exactly what step 4 is
///    about to do anyway, so nothing here relies on it reaching the
///    account, and no outcome of step 2 skips this step: whatever went
///    wrong there is read the same way as an ordinary refusal.
/// 4. [`Generations::remove`] — `remove_dir_all`, refused if `current` has,
///    in the meantime, come to name this candidate.
///
/// # Errors
///
/// The sentence to print, naming which step failed. The candidate is left in
/// place either way, for [`sweep`] to retry on its next pass.
pub fn retire(
    coordinates: &Coordinates,
    owner: Owner,
    generations: &Generations,
    candidate: &Candidate,
    bound: Duration,
    out: &mut dyn std::io::Write,
) -> Result<(), String> {
    let drain_key = candidate.drain_key();
    if generations.drain(&drain_key, bound).is_err() {
        return Err(format!(
            "{drain_key} is still being read by this process; retried next sweep"
        ));
    }

    // Resolved once, per candidate, the same way every other lookup in this
    // crate reads its login — not held across retirements. A failure here
    // (an entry named in the config but not yet written) is read the same
    // way a spawn failure below is: `unwrap_or_default` falls through to the
    // plain logout failing for that reason, then to step 3, never to this
    // function refusing outright — a scheduled sweep running unattended must
    // not wedge over one entry's own misconfiguration.
    let login = extra_credentials(coordinates).unwrap_or_default();

    let timeout = probe_deadline(coordinates.timeout_ms);
    let already_gone = match run(
        logout_command(coordinates, candidate.scope(), false, &login, owner),
        timeout,
    ) {
        Ok((status, said)) => {
            status.success() || said.to_ascii_lowercase().contains("already logged out")
        }
        // A spawn failure or a kill is read exactly like a refusal: step 3
        // runs whatever step 2 did or did not manage to say. See this
        // function's own doc — dropping the vendor's own `?` here is what
        // makes that ordering hold for every kind of failure, not only the
        // ones with an exit status to read.
        Err(_) => false,
    };
    if !already_gone {
        // Outcome deliberately not decisive here — see this function's own
        // doc. `remove` below is what actually clears the directory. `--force`
        // never needs `login` — see `logout_command`'s own doc — and carries
        // it anyway, for the same reason that doc gives.
        let _ = run(
            logout_command(coordinates, candidate.scope(), true, &login, owner),
            timeout,
        );
    }

    generations
        .remove(candidate)
        .map_err(|error| format!("{} could not be removed: {error}", candidate.label()))?;

    writeln!(out, "retired\tproton\t{}", candidate.label())
        .map_err(|error| format!("the report could not be written: {error}"))
}

/// Retire every eligible candidate, oldest first, honouring `stop` between
/// candidates.
///
/// Called on the renewal loop's own thread at every tick — after the due
/// check, and once more before the first attempt — and by `keylessd login`
/// once, after a successful publish. Never drains on the operator verb's
/// behalf: a candidate whose readers have not finished by the time `keylessd
/// login` gets to it is left for the loop's own next tick, or for the next
/// invocation of this verb.
///
/// A failure retiring one candidate does not stop the sweep — every other
/// eligible candidate still gets its turn — and is reported through `out` at
/// most once per candidate per process, via
/// [`Generations::mark_failure_reported`].
///
/// `coordinates.timeout_ms` bounds every vendor child [`retire`] spawns for
/// each candidate, through [`probe_deadline`] — the same value the store's
/// own reads are bounded by.
///
/// # Returns
///
/// How many candidates this call retired.
/// The label [`Generations::legacy_layout_obstruction`] is reported under —
/// distinct from [`Candidate::label`]'s `"legacy"`, so a root that once had a
/// real legacy DIRECTORY fail to retire, and later has that directory
/// replaced by a symlink, reports the new obstruction on its own rather than
/// finding the label already spent.
const LEGACY_OBSTRUCTION_LABEL: &str = "legacy-not-a-directory";

pub fn sweep(
    coordinates: &Coordinates,
    owner: Owner,
    generations: &Generations,
    grace: Duration,
    stop: Option<&AtomicBool>,
    out: &mut dyn std::io::Write,
) -> usize {
    // Reported once per process, the same mechanism a stuck retirement uses
    // below — a `.session` that is a symlink or a plain file is never a
    // `Candidate` (`Generations::candidates` excludes it), so without this it
    // would never surface anywhere and would be skipped in silence forever.
    if let Some(detail) = generations.legacy_layout_obstruction()
        && generations.mark_failure_reported(LEGACY_OBSTRUCTION_LABEL)
    {
        let _ = writeln!(out, "retire-failed\tproton\tlegacy\t{detail}");
    }

    let mut retired = 0;
    for candidate in generations.candidates(std::time::SystemTime::now(), grace) {
        if stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            break;
        }
        match retire(coordinates, owner, generations, &candidate, grace, out) {
            Ok(()) => retired += 1,
            Err(detail) => {
                if generations.mark_failure_reported(&candidate.label()) {
                    let _ = writeln!(
                        out,
                        "retire-failed\tproton\t{}\t{detail}",
                        candidate.label()
                    );
                }
            }
        }
    }
    retired
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property [`grace`]'s own doc relies on: a login this crate killed
    /// can never still be writing into a fresh generation once a sweep has
    /// decided that generation's grace has cleared.
    ///
    /// `0` and a value above [`crate::config::MAX_TIMEOUT_MS`] are included
    /// because both are values a real config can hold — `bounded_timeout`
    /// clamps the second down and leaves the first alone — and the ordering
    /// this test pins must survive both.
    #[test]
    fn a_login_is_allowed_twice_a_probe_and_grace_absorbs_it_plus_the_reap() {
        for timeout_ms in [0, 1, 100, 10_000, crate::config::MAX_TIMEOUT_MS, 999_999] {
            let probe = probe_deadline(timeout_ms);
            let login = login_deadline(timeout_ms);
            assert!(
                login > probe || (probe.is_zero() && login.is_zero()),
                "timeout_ms={timeout_ms}: login_deadline ({login:?}) must exceed \
                 probe_deadline ({probe:?})"
            );
            assert_eq!(
                login,
                2 * probe,
                "timeout_ms={timeout_ms}: login_deadline must be exactly twice probe_deadline"
            );
            assert!(
                login + REAP_GRACE < grace(timeout_ms),
                "timeout_ms={timeout_ms}: login_deadline + REAP_GRACE ({:?}) must stay inside \
                 grace ({:?}), or a sweep can retire a generation a killed login is still \
                 writing into",
                login + REAP_GRACE,
                grace(timeout_ms)
            );
        }
    }

    /// Every combination of the four inputs, and the one that used to be wrong.
    ///
    /// Sixteen cases, written out rather than generated, because the value of
    /// this table is that a reader can see the rotation case sitting among the
    /// others and check it by eye.
    #[test]
    fn the_token_source_matrix_holds_and_replace_at_a_terminal_asks() {
        use TokenSource::{Held, Read};
        // interactive, --prompt, --replace, holds one  ->  source
        let matrix = [
            // Nothing held: there is nothing to use, so every row reads.
            (false, false, false, false, Read),
            (false, false, true, false, Read),
            (false, true, false, false, Read),
            (false, true, true, false, Read),
            (true, false, false, false, Read),
            (true, false, true, false, Read),
            (true, true, false, false, Read),
            (true, true, true, false, Read),
            // Piped, holding one: the file answers, and `--replace` changes
            // nothing — an unattended repair has nobody to ask.
            (false, false, false, true, Held),
            (false, false, true, true, Held),
            // `--prompt` always asks, whoever is listening.
            (false, true, false, true, Read),
            (false, true, true, true, Read),
            // A terminal, holding one: the file answers an ordinary login.
            (true, false, false, true, Held),
            // THE ROW THIS EXISTS FOR. A person typed the rotation flag, so
            // the file must not answer: reusing the old token here logs the
            // daemon back in with a credential the operator believes they
            // just replaced, and reports success.
            (true, false, true, true, Read),
            (true, true, false, true, Read),
            (true, true, true, true, Read),
        ];
        for (interactive, prompt, replace, holds_one, expected) in matrix {
            assert_eq!(
                TokenSource::decide(interactive, prompt, replace, holds_one),
                expected,
                "interactive={interactive} prompt={prompt} replace={replace} \
                 holds_one={holds_one}"
            );
        }
    }

    /// The regression, stated on its own so a failure names it.
    #[test]
    fn a_rotation_typed_at_a_terminal_is_never_served_from_disk() {
        assert_eq!(
            TokenSource::decide(true, false, true, true),
            TokenSource::Read,
            "`--replace` at a terminal reused the token on disk — a rotation that \
             reports success and installs nothing"
        );
    }

    /// The probe carries no token — it is not a place a credential belongs,
    /// and one here would be a token in a child spawned every tick — but
    /// DOES carry the local key it was handed, which under
    /// [`KeyProvider::Env`] is what lets the vendor open the session at all.
    ///
    /// CONTROL for the bug this pins: `info_command` used to be built with
    /// `&[]` unconditionally, the same defect review had already caught once
    /// in `ProtonStore::info_probe_command`. Reverting the `login` parameter
    /// back to `&[]` at this call site turns the key assertion below red
    /// while leaving the token assertion green — which is why both are
    /// checked, rather than only the invariant that never moved.
    ///
    /// Which directory the probe names is `every_login_verb_is_scoped_at_the_
    /// directory_it_is_given_and_never_at_the_root`'s claim, not this one's.
    #[test]
    fn the_liveness_probe_names_the_session_it_is_asking_about_carries_the_key_and_no_token() {
        let coordinates = Coordinates {
            binary: PathBuf::from("/nonexistent/pass-cli"),
            session_dir: PathBuf::from("/var/lib/keyless/proton-session"),
            key_provider: KeyProvider::Env,
            credentials_file: PathBuf::from("/var/lib/keyless/proton.json"),
            token_entry: "AGENT_TOKEN".to_owned(),
            extra: BTreeMap::new(),
            timeout_ms: crate::config::DEFAULT_TIMEOUT_MS,
        };
        let generation = coordinates.session_dir.join("gen-1789012345678-4242");
        let login = key_vector();
        let command = info_command(&coordinates, &generation, &login, Owner { uid: 1, gid: 1 });

        let environment: Vec<_> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(
            environment
                .iter()
                .any(|(key, _)| key == proton::KEY_PROVIDER_VAR),
            "the probe does not name the key provider: {environment:?}"
        );
        assert_eq!(
            environment
                .iter()
                .find(|(key, _)| key == proton::ENCRYPTION_KEY_VAR)
                .and_then(|(_, value)| value.as_deref()),
            Some(KEY_DECOY),
            "the probe does not carry the local key it was handed: {environment:?}"
        );
        assert!(
            !environment.iter().any(|(key, _)| key == proton::TOKEN_VAR),
            "the probe carries the token: {environment:?}"
        );

        let argv: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(argv, vec!["info".to_owned()]);
    }

    /// The one caller of [`info_command`] `establish`'s own doc does not
    /// cover: the double-run guard, reachable only from `keylessd login`
    /// WITHOUT `--replace` — the renewal loop always passes `replace: true`
    /// and never reaches this probe at all (see `session.rs::spawn`'s own
    /// `!replace && …` short circuit having no analogue here — this guard
    /// IS that check, on the operator verb's side).
    ///
    /// CONTROL — the change that makes this fail: `already_authenticated_now`
    /// spawning `info_command` with `&[]` again. Under `KeyProvider::Env` the
    /// stand-in then reports `absent` on every call, so this assertion is
    /// exactly what turns red; the `assert!(answered, …)` line above it does
    /// not, because the stand-in answers success regardless of what it saw.
    #[test]
    fn the_double_run_guard_probes_the_current_generation_with_the_key_it_needs_to_open_it() {
        let dir = scratch("already-authenticated");
        let stub = dir.join("pass-cli-stub");
        let record = dir.join("key.seen");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\n\
                 if [ -n \"${{PROTON_PASS_ENCRYPTION_KEY+x}}\" ]; then\n\
                 \x20 printf '%s' \"${{#PROTON_PASS_ENCRYPTION_KEY}}\" > '{record}'\n\
                 else\n\
                 \x20 printf absent > '{record}'\n\
                 fi\n\
                 exit 0\n",
                record = record.display()
            ),
        )
        .expect("write stub");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).expect("chmod");

        let root = dir.join("session");
        fs::create_dir_all(&root).expect("root");
        let generations = Generations::at(root.clone());
        let owner = own(&dir);
        let (name, _generation_dir) = generations
            .create(Some((owner.uid, owner.gid)))
            .expect("create");
        generations
            .publish(&name, Some((owner.uid, owner.gid)))
            .expect("publish");

        let coordinates = Coordinates {
            binary: stub,
            session_dir: root,
            key_provider: KeyProvider::Env,
            credentials_file: dir.join("proton.json"),
            token_entry: "AGENT_TOKEN".to_owned(),
            extra: BTreeMap::new(),
            timeout_ms: crate::config::DEFAULT_TIMEOUT_MS,
        };

        let answered = already_authenticated_now(&coordinates, owner, &generations, &key_vector());
        assert!(
            answered,
            "the stand-in always exits 0; the probe must have run"
        );

        let seen = fs::read_to_string(&record).expect("the stub must have run and recorded");
        assert_eq!(
            seen,
            KEY_DECOY.len().to_string(),
            "the double-run guard did not carry the local key it was handed: saw {seen:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn login_info_and_logout_all_switch_off_the_vendors_telemetry_and_update_check() {
        let coordinates = coordinates_at(Path::new("/nonexistent/keyless-login-switch-off"));
        let owner = Owner { uid: 1, gid: 1 };
        let login = login_vector();
        let generation = coordinates.session_dir.join("gen-1-1");

        // Every verb's own argv, alongside the switch-off check below: setting
        // an environment variable cannot append an argument, so this is the
        // same argv each verb has always produced.
        let cases: [(Command, &[&str]); 3] = [
            (
                login_command(&coordinates, &generation, &login, owner),
                &["login"],
            ),
            (
                info_command(&coordinates, &generation, &[], owner),
                &["info"],
            ),
            (
                logout_command(&coordinates, &generation, false, &[], owner),
                &["logout"],
            ),
        ];

        for (command, expected_argv) in cases {
            let argv: Vec<String> = command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            assert_eq!(argv, expected_argv, "{argv:?}");
            proton::assert_vendor_switch_offs(&command);
        }
    }

    #[test]
    fn every_login_verb_is_scoped_at_the_directory_it_is_given_and_never_at_the_root() {
        // The property generations exist for: whichever directory a caller
        // names is the one the vendor sees, and `Coordinates::session_dir` —
        // the ROOT of every generation — is never that directory on its own.
        //
        // The deliberate exception, NOT exercised here: the legacy
        // retirement candidate has no generation name of its own, so
        // `Generations::candidates` scopes it at the root directly (see
        // `logout_command`'s own doc) — proved end to end, against a real
        // daemon, by `a_legacy_session_directory_is_retired_and_never_served_from`
        // in `tests/daemon_proton.rs`.
        let coordinates = coordinates_at(Path::new("/nonexistent/keyless-login-scoped"));
        let owner = Owner { uid: 1, gid: 1 };
        let generation = coordinates.session_dir.join("gen-1-1");
        assert_ne!(
            generation, coordinates.session_dir,
            "the fixture's own generation must differ from the root"
        );

        let commands = [
            login_command(&coordinates, &generation, &login_vector(), owner),
            info_command(&coordinates, &generation, &key_vector(), owner),
            logout_command(&coordinates, &generation, false, &key_vector(), owner),
            logout_command(&coordinates, &generation, true, &key_vector(), owner),
        ];

        for command in &commands {
            let scoped = env_value(command, proton::SESSION_DIR_VAR);
            assert_eq!(
                scoped.as_deref(),
                Some(generation.display().to_string().as_str()),
                "scoped at {scoped:?}, not the generation it was given: {command:?}"
            );
            assert_ne!(
                scoped.as_deref(),
                Some(coordinates.session_dir.display().to_string().as_str()),
                "a login verb was scoped at the root of generations"
            );
        }
    }

    #[test]
    fn a_retirement_logout_carries_force_only_when_asked() {
        let coordinates = coordinates_at(Path::new("/nonexistent/keyless-login-force"));
        let owner = Owner { uid: 1, gid: 1 };
        let generation = coordinates.session_dir.join("gen-1-1");

        let argv_of = |command: &Command| -> Vec<String> {
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect()
        };

        assert_eq!(
            argv_of(&logout_command(
                &coordinates,
                &generation,
                false,
                &[],
                owner
            )),
            vec!["logout".to_owned()]
        );
        assert_eq!(
            argv_of(&logout_command(&coordinates, &generation, true, &[], owner)),
            vec!["logout".to_owned(), "--force".to_owned()]
        );
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-login-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// The value a built [`Command`] would export for `key`, read off it
    /// directly rather than off the process's own environment.
    fn env_value(command: &Command, key: &str) -> Option<String> {
        command
            .get_envs()
            .find(|(k, _)| *k == std::ffi::OsStr::new(key))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
    }

    fn own(dir: &Path) -> Owner {
        let meta = fs::metadata(dir).expect("stat");
        Owner {
            uid: meta.uid(),
            gid: meta.gid(),
        }
    }

    fn coordinates_at(dir: &Path) -> Coordinates {
        Coordinates {
            binary: PathBuf::from("/nonexistent/pass-cli"),
            session_dir: dir.join("session"),
            key_provider: KeyProvider::Fs,
            credentials_file: dir.join("proton.json"),
            token_entry: "AGENT_TOKEN".to_owned(),
            extra: BTreeMap::new(),
            timeout_ms: crate::config::DEFAULT_TIMEOUT_MS,
        }
    }

    /// A decoy shaped like a personal access token. Invented; a grep for it in
    /// any output would mean a real leak.
    const TOKEN_DECOY: &str = "pst_decoy0Login0never0real0Aa1::ZGVjb3ktbG9naW4tMDkwMw==";

    /// The `login` argument every test below passes, wrapping [`TOKEN_DECOY`].
    fn login_vector() -> Vec<(String, Secret)> {
        vec![(
            proton::TOKEN_VAR.to_owned(),
            Secret::new(TOKEN_DECOY.to_owned()),
        )]
    }

    /// A decoy shaped like a base64url local key. Distinct from
    /// [`TOKEN_DECOY`], and long enough that a grep for it in any output
    /// would mean a real leak.
    const KEY_DECOY: &str = "decoy0Lk4l0never0real0Aa1-ZGVjb3kta2V5LTA5MTE";

    /// The extra-credentials `login` slice under [`KeyProvider::Env`] —
    /// [`ENCRYPTION_KEY_VAR`](proton::ENCRYPTION_KEY_VAR), never the token.
    fn key_vector() -> Vec<(String, Secret)> {
        vec![(
            proton::ENCRYPTION_KEY_VAR.to_owned(),
            Secret::new(KEY_DECOY.to_owned()),
        )]
    }

    #[test]
    fn the_token_is_in_the_environment_and_the_argument_vector_is_two_words() {
        // The whole reason this file builds a `Command` rather than spawning
        // one inline: an assertion on a returned status cannot see the argv,
        // and the argv is what `ps` shows every user on the machine.
        let dir = scratch("argv");
        let coordinates = coordinates_at(&dir);
        let login = login_vector();
        let generation = coordinates.session_dir.join("gen-1-1");
        let command = login_command(&coordinates, &generation, &login, own(&dir));

        let argv: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(argv, vec!["login".to_owned()], "argv: {argv:?}");
        assert!(
            !argv.iter().any(|arg| arg.contains("pst_")),
            "the token reached the argument vector: {argv:?}"
        );

        let environment: BTreeMap<String, String> = command
            .get_envs()
            .filter_map(|(key, value)| {
                value.map(|value| {
                    (
                        key.to_string_lossy().into_owned(),
                        value.to_string_lossy().into_owned(),
                    )
                })
            })
            .collect();
        assert_eq!(
            environment.get(proton::TOKEN_VAR).map(String::as_str),
            Some(TOKEN_DECOY),
            "the token did not reach the environment"
        );
        assert_eq!(
            environment
                .get(proton::KEY_PROVIDER_VAR)
                .map(String::as_str),
            Some("fs"),
            "the key provider was not set, which is what reinitialises a store"
        );
        assert_eq!(
            environment.get(proton::SESSION_DIR_VAR).map(String::as_str),
            Some(generation.display().to_string().as_str()),
            "the generation directory was not set"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_session_directory_is_created_shut_and_a_present_one_is_left_alone() {
        let dir = scratch("ensure");
        let session = dir.join("session");
        let owner = own(&dir);

        assert_eq!(
            ensure_session_dir(&session, owner).expect("created"),
            Ensured::Created
        );
        let mode = fs::metadata(&session).expect("stat").permissions().mode() & 0o7777;
        assert_eq!(mode, SESSION_DIR_MODE, "created at {mode:04o}");

        // The control for the case below: a sound directory reports that
        // nothing was done, so `Repaired` cannot be satisfied by every run.
        fs::write(session.join("session.json"), b"decoy").expect("plant");
        fs::set_permissions(
            session.join("session.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("chmod");
        assert_eq!(
            ensure_session_dir(&session, owner).expect("sound"),
            Ensured::Sound
        );
        assert_eq!(
            fs::read(session.join("session.json")).expect("read"),
            b"decoy",
            "a working session was rewritten"
        );

        // Widened by hand, the way an editor or a `cp` leaves it.
        fs::set_permissions(&session, fs::Permissions::from_mode(0o755)).expect("widen");
        let Ensured::Repaired(repairs) = ensure_session_dir(&session, owner).expect("repaired")
        else {
            panic!("a mode 0755 session directory was reported sound");
        };
        assert!(
            repairs.iter().any(|line| line.contains("0700")),
            "repairs: {repairs:?}"
        );
        let mode = fs::metadata(&session).expect("stat").permissions().mode() & 0o7777;
        assert_eq!(mode, SESSION_DIR_MODE, "left at {mode:04o}");
        assert_eq!(
            fs::read(session.join("session.json")).expect("read"),
            b"decoy",
            "repairing the directory destroyed the session in it"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_vendors_four_answers_are_told_apart_by_what_it_said() {
        // Every one of these decides something different about whether a token
        // is written, and an exit code separates none of them.
        let failed = std::process::Command::new("/usr/bin/false")
            .status()
            .expect("false");
        let ok = std::process::Command::new("/usr/bin/true")
            .status()
            .expect("true");

        assert_eq!(
            classify(
                failed,
                "Client is already authenticated. Log out if you want to log in again"
            ),
            Outcome::AlreadyAuthenticated
        );
        // The same sentence on a zero exit must still not read as a login: the
        // status is deliberately the last thing consulted.
        assert_eq!(
            classify(ok, "Already authenticated"),
            Outcome::AlreadyAuthenticated
        );
        assert!(matches!(
            classify(
                failed,
                "Error: Local encryption key not found but local data exists. Forcing logout for \
                 security."
            ),
            Outcome::KeyLost(_)
        ));
        assert!(matches!(
            classify(
                failed,
                "This personal access token is invalid, expired or has been deleted."
            ),
            Outcome::TokenRefused(_)
        ));
        assert!(matches!(
            classify(failed, "connection refused"),
            Outcome::Unreachable(_)
        ));
        // Verbatim from the daemon's log during an outage. Every line names the
        // token, and none of it is about the token.
        assert!(matches!(
            classify(
                failed,
                "Error: Error in personal access token login flow\n\nCaused by:\n    0: Error \
                 creating personal access token session\n    1: Error requesting personal access \
                 token session\n    2: failed to connect to host: error resolving destination: \
                 unknown error errno=None\n    3: error resolving destination: unknown error \
                 errno=None"
            ),
            Outcome::Unreachable(_)
        ));
        // A connection lost after the token was sent: still no answer, so
        // still nothing learned about the token, although the flow's own
        // lines name it throughout.
        assert!(matches!(
            classify(
                failed,
                "Error: Error in personal access token login flow\n\nCaused by:\n    0: Error \
                 requesting personal access token session\n    1: Operation timed out (os \
                 error 60)"
            ),
            Outcome::Unreachable(_)
        ));
        assert!(matches!(
            classify(failed, "the login flow hit an error nothing names"),
            Outcome::Failed(_)
        ));
        assert_eq!(
            classify(ok, "Personal access token session created successfully"),
            Outcome::LoggedIn
        );
    }
}
