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
//! **A deadline.** `stores.proton.timeout_ms` bounds a LOOKUP, where a hung
//! vendor would hold a session's command open with nobody watching. This runs
//! with a person at a terminal who can stop it, and killing a login part way is
//! how a session store ends up half-written — the one damage in this directory
//! that nothing here can repair. See
//! [`crate::store::proton`]'s note on interrupted writes.
//!
//! **Any judgement about whether a session already exists.** The vendor answers
//! that, in its own words, and it is the only thing on the machine that knows —
//! see [`Outcome::AlreadyAuthenticated`], which is what makes a second run safe
//! rather than merely unlikely to be harmful.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::secret::Secret;
use crate::store::proton::{self, KeyProvider};

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
    /// Which logged-in identity the login establishes.
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

    let extra = settings
        .credentials
        .iter()
        .filter(|(variable, _)| variable.as_str() != proton::TOKEN_VAR)
        .map(|(variable, entry)| (variable.clone(), entry.clone()))
        .collect();

    Ok(Coordinates {
        binary: settings.binary.to_path_buf(),
        session_dir: session_dir.to_path_buf(),
        key_provider: settings.key_provider,
        credentials_file,
        token_entry,
        extra,
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

/// One `pass-cli login` invocation, built and not yet spawned.
///
/// Split out so a test can read the argument vector and the environment from
/// the outside. The property being defended is not that the login works — it is
/// that the TOKEN is in the environment and the argument vector is the two
/// words `pass-cli login`, and an assertion on the returned status could not
/// tell those apart.
#[must_use]
pub fn login_command(
    coordinates: &Coordinates,
    login: &[(String, Secret)],
    owner: Owner,
) -> Command {
    let mut command = Command::new(&coordinates.binary);
    command.arg("login");
    scope(&mut command, coordinates, login, owner);
    command
}

/// One `pass-cli logout` invocation, for the rotation path only.
#[must_use]
pub fn logout_command(coordinates: &Coordinates, owner: Owner) -> Command {
    let mut command = Command::new(&coordinates.binary);
    command.arg("logout");
    scope(&mut command, coordinates, &[], owner);
    command
}

/// Everything both verbs need, applied in one place so neither can lack one.
///
/// Deliberately not [`Command::env_clear`]: a stripped environment is one of
/// the ways the vendor loses its local key and force-logs-out. This ADDS.
fn scope(
    command: &mut Command,
    coordinates: &Coordinates,
    login: &[(String, Secret)],
    owner: Owner,
) {
    use std::os::unix::process::CommandExt;

    command.env(proton::SESSION_DIR_VAR, &coordinates.session_dir);
    command.env(proton::KEY_PROVIDER_VAR, coordinates.key_provider.as_str());
    for (variable, secret) in login {
        command.env(variable, secret.expose());
    }
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
    if lowered.contains(REFUSED) {
        return Outcome::TokenRefused(said.trim().to_owned());
    }
    Outcome::Failed(said.trim().to_owned())
}

/// Spawn a built command and return its status with both streams joined.
///
/// # Errors
///
/// The spawn itself. `EPERM` is the ordinary answer to running this without
/// `sudo`, because the child asks to become the daemon's uid before it execs;
/// the caller turns that into a sentence about privilege rather than an errno.
pub fn run(mut command: Command) -> Result<(ExitStatus, String), std::io::Error> {
    let output = command.output()?;
    let mut said = String::from_utf8_lossy(&output.stderr).into_owned();
    said.push('\n');
    said.push_str(&String::from_utf8_lossy(&output.stdout));
    Ok((output.status, said))
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
                return Err(format!(
                    "`{variable}` is declared to live in `{entry}` of {}, which holds no such \
                     entry — and the login cannot establish a session without it. Write it \
                     first, without the value passing through a command line: `{} credential \
                     --store {STORE} --name {entry}`",
                    coordinates.credentials_file.display(),
                    crate::DAEMON_NAME
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
    out: &mut dyn std::io::Write,
) -> Result<(), String> {
    if replace {
        let (status, said) = run(logout_command(coordinates, owner))
            .map_err(|error| cannot_spawn(coordinates, owner, &error))?;
        // `There was not an active session, you are already logged out` is a
        // success for this verb's purposes: the directory is empty, which is
        // the state the login below needs.
        if !status.success() && !said.to_ascii_lowercase().contains("already logged out") {
            return Err(format!(
                "the existing session at {} could not be logged out, so nothing was replaced \
                 and the session is as it was: {}\n\nThe vendor's own next step DELETES that \
                 directory's contents rather than ending the session at the account, so it is \
                 not a step this verb takes for anybody. Run it deliberately, as the daemon: \
                 `sudo -u '#{}' env {}` — or take the directory away and log in fresh",
                coordinates.session_dir.display(),
                said.trim(),
                owner.uid,
                proton::scoped_command(&coordinates.session_dir, "logout --force")
            ));
        }
        writeln!(
            out,
            "logout\t{STORE}\t{}",
            coordinates.session_dir.display()
        )
        .map_err(|error| format!("the report could not be written: {error}"))?;
    }

    let mut login = extra;
    // A second [`Secret`] rather than a borrow of the caller's, so the token is
    // still here to be written once the vendor has taken it. It is zeroized
    // with the vector, on the line below the spawn.
    login.push((
        proton::TOKEN_VAR.to_owned(),
        Secret::new(token.expose().to_owned()),
    ));
    let (status, said) = run(login_command(coordinates, &login, owner))
        .map_err(|error| cannot_spawn(coordinates, owner, &error))?;
    drop(login);

    match classify(status, &said) {
        Outcome::LoggedIn => {}
        Outcome::AlreadyAuthenticated => {
            return Err(already_authenticated(&coordinates.session_dir, said.trim()));
        }
        Outcome::KeyLost(said) => return Err(key_lost(coordinates, &said)),
        Outcome::TokenRefused(said) => return Err(token_refused(coordinates, &said)),
        Outcome::Failed(said) => {
            return Err(format!(
                "the login into {} failed for a reason nothing here recognises, and nothing \
                 was written to {}: {said}",
                coordinates.session_dir.display(),
                coordinates.credentials_file.display()
            ));
        }
    }

    writeln!(out, "login\t{STORE}\t{}", coordinates.session_dir.display())
        .map_err(|error| format!("the report could not be written: {error}"))?;

    super::credential::store_entry(
        &coordinates.credentials_file,
        &coordinates.token_entry,
        token,
    )
    .map_err(|error| logged_in_but_unwritten(coordinates, &error.to_string()))?;

    writeln!(
        out,
        "stored\t{}\t{}",
        coordinates.token_entry,
        coordinates.credentials_file.display()
    )
    .map_err(|error| format!("the report could not be written: {error}"))
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
            "this process cannot become uid {} to run the login, so nothing has happened: \
             {error}. Whoever runs the login owns the session store `pass-cli` creates, and a \
             store the daemon cannot open fails in a way that reads exactly like a wrong \
             token — so this verb will not run it as anybody else. Run it with `sudo`",
            owner.uid
        );
    }
    format!(
        "{} could not be started, so nothing has happened: {error}. That is \
         `stores.{STORE}.binary` in the config, and it is worth an absolute path — this runs \
         as the daemon, whose `PATH` is not yours",
        coordinates.binary.display()
    )
}

/// What to tell an operator whose session directory already holds an identity.
#[must_use]
pub fn already_authenticated(session_dir: &Path, said: &str) -> String {
    format!(
        "{} already holds a logged-in identity, and `pass-cli` refuses to replace one: {said}\n\
         \n\
         NOTHING was changed — not the session, not the credential file — and the token you \
         typed was discarded. If that identity is the one you want, there is nothing to do; run \
         `{daemon} check` to see whether the daemon accepts it. If you are ROTATING the token, \
         re-run with `--replace`, which logs the existing session out first. That is deliberate \
         and not the default: a logout followed by a login the vendor refuses leaves the \
         directory with no identity at all, so it is a step somebody chooses.\n\
         \n\
         To record a token in the credential file WITHOUT touching the session: \
         `{daemon} credential --store {STORE} --name <entry>`",
        session_dir.display(),
        daemon = crate::DAEMON_NAME
    )
}

/// What to tell an operator whose store was just reinitialised.
#[must_use]
pub fn key_lost(coordinates: &Coordinates, said: &str) -> String {
    format!(
        "`pass-cli` could not find the local key for {}, found a session store beside it, and \
         FORCED A LOGOUT to reinitialise the store: {said}\n\
         \n\
         That directory now holds no identity. This daemon set `{}={}`, so the key was looked \
         for in the directory itself — if the session in there was established under a \
         different provider, this is what that mismatch does, and it is why `keyring` is not a \
         value `keylessd.json` will accept. Nothing was written to {}. Log in again with this \
         verb, which will find an empty directory and establish a fresh session",
        coordinates.session_dir.display(),
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

/// What to tell an operator whose login landed but whose file write did not.
///
/// The one half-finished state this verb can leave, said in full rather than as
/// an errno, because what `check` will report next is the opposite of alarming:
/// the session works, so every name resolves, and the row that is red is about
/// a file nobody is looking at.
#[must_use]
pub fn logged_in_but_unwritten(coordinates: &Coordinates, detail: &str) -> String {
    format!(
        "the session at {} is established and every Proton name will resolve — but the token \
         could not be recorded in {}: {detail}\n\
         \n\
         So nothing can re-establish that session when the vendor drops it, which it does \
         without warning, and the failure would arrive at an hour nobody chose. `{} check` says \
         so in the `identity` row. Fix the file and run `{} credential --store {STORE} --name \
         {}` with the same token",
        coordinates.session_dir.display(),
        coordinates.credentials_file.display(),
        crate::DAEMON_NAME,
        crate::DAEMON_NAME,
        coordinates.token_entry
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        }
    }

    /// A decoy shaped like a personal access token. Invented; a grep for it in
    /// any output would mean a real leak.
    const TOKEN_DECOY: &str = "pst_decoy0Login0never0real0Aa1::ZGVjb3ktbG9naW4tMDkwMw==";

    #[test]
    fn the_token_is_in_the_environment_and_the_argument_vector_is_two_words() {
        // The whole reason this file builds a `Command` rather than spawning
        // one inline: an assertion on a returned status cannot see the argv,
        // and the argv is what `ps` shows every user on the machine.
        let dir = scratch("argv");
        let coordinates = coordinates_at(&dir);
        let login = vec![(
            proton::TOKEN_VAR.to_owned(),
            Secret::new(TOKEN_DECOY.to_owned()),
        )];
        let command = login_command(&coordinates, &login, own(&dir));

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
            Some(coordinates.session_dir.display().to_string().as_str()),
            "the session directory was not set"
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
            Outcome::Failed(_)
        ));
        assert_eq!(
            classify(ok, "Personal access token session created successfully"),
            Outcome::LoggedIn
        );
    }
}
