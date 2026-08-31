//! Proton Pass, via `pass-cli run`.
//!
//! Personal credentials, kept in a different vault from the company's — which
//! is the whole reason the resolution policy in [`super`] refuses to guess which
//! store a name belongs to.
//!
//! # Status: observed against `pass-cli` 2.2.5, 2026-08-08
//!
//! The argv this adapter builds, the reference format it passes through, the
//! session scoping below and the vendor's masking were all exercised against
//! the real CLI on macOS (Homebrew, `pass-cli` 2.2.5) against a live account,
//! using disposable decoy items. `run --env-file <FILE> --no-masking --
//! <COMMAND>` exists with exactly that spelling, and `agent create` exists too.
//!
//! One requirement the code cannot check and a user must plan for: **an agent
//! token needs Pass Plus or higher.** The free tier is excluded, so a free
//! account fails authentication — which reaches `keyless` as a degraded run
//! rather than as an explanation.
//!
//! # Scoping: which login answers is a config field, never an inheritance
//!
//! `pass-cli` keeps one logged-in identity per **session directory**, chosen by
//! `PROTON_PASS_SESSION_DIR` and falling back to a shared per-user location.
//! Two identities therefore coexist on one machine with no visible difference
//! at the call site: a vault-scoped agent token in its own directory, and
//! whatever a plain `pass-cli login` left in the default one.
//!
//! Measured 2026-08-08: the default session was the full account and saw two
//! vaults; the agent session saw one. An adapter that sets nothing inherits the
//! default — so the scoping a user deliberately set up is bypassed, and it is
//! bypassed **in the direction that looks correct**, because a session holding
//! every vault resolves every name successfully. Nothing in the output would
//! say the wrong identity answered.
//!
//! So the session directory is [`crate::config::ProtonConfig::session_dir`],
//! it is passed to every child explicitly, and when it is absent this adapter
//! **degrades the lookup** rather than falling back to the ambient session.
//! See [`ProtonStore::session_dir`] for why that is the right one of the three
//! available answers.
//!
//! # Addressing: names in the config, ids resolved fresh
//!
//! **A share id is minted per session, so it is not a coordinate you can store.**
//! Measured 2026-08-08: the same vault `personal` answered with two different share ids
//! to two live sessions of one account. A `pass://SHARE_ID/ITEM_ID/FIELD`
//! reference is therefore relative to the session that resolves it, and a
//! reference written into a config file dies the next time the token is renewed
//! or a session recovers — as a **degraded run**, which is quiet.
//!
//! So the recommended form addresses an item the way a person does: vault name,
//! item title, field. Those are stable. The volatile half is looked up at every
//! lookup, from `pass-cli item list --vault-name <VAULT> --output json`, whose
//! records carry `share_id`, `id`, `state` and `title` — everything needed to
//! build a fresh reference in memory. Note the item id is the key **`id`**;
//! there is no `item_id` key, and reading one yields `None`.
//!
//! Three decisions that path forced, each made rather than guessed:
//!
//! - **Two live items with the same title are refused, never picked.** Same rule
//!   as [`crate::config::Policy::Explicit`] for two backends answering one name:
//!   guessing is a wrong credential delivered silently. The error names every
//!   candidate id, so the `reference` form is the way to pin one.
//! - **A trashed item never resolves.** `item list` still returns it, with
//!   `state: "Trashed"`. Resolving one would hand a child a value its owner
//!   believes they deleted. The filter is an **allowlist** on `Active` rather
//!   than a denylist on `Trashed`: a state this build has never heard of must
//!   fail closed.
//! - **The listing is memoised, in memory only, and it expires.** One `keyless
//!   run` resolves several names, usually from one vault, so the cache turns N
//!   spawns into one. It is reused only while it is younger than
//!   [`crate::config::ProtonConfig::listing_ttl_ms`], because the listing is
//!   also what carries the trash rule below: an entry kept indefinitely goes on
//!   resolving an item somebody trashed an hour ago, and does it silently. A
//!   run cannot outlive the default, so the memoisation costs nothing there;
//!   the bound is what makes the adapter safe to hold open across commands.
//!   There is deliberately no on-disk cache: a cache the client can read is a
//!   `get` verb with extra steps.
//!
//! The `reference` form still resolves, unchanged. It is the escape hatch for an
//! ambiguous title, and the wrong choice for everything else — it is fragile
//! across sessions, and it is **not** covered by the trash rule above.
//!
//! **Measured 2026-08-08: `pass-cli run` resolves a reference to a TRASHED item
//! and returns its value, exit 0, with nothing on stderr.** The vendor applies
//! no trash filter of its own, so the only thing standing between a deleted item
//! and a child's environment is the listing check in this adapter — which the
//! reference form skips by construction, because it never lists anything. That
//! is the strongest reason to prefer the name form, and the reason the ambiguity
//! escape hatch is a narrow recommendation rather than a general one.
//!
//! # The mechanism
//!
//! Same shape as the Infisical adapter, for the same reason: `pass-cli item
//! view --field` prints plaintext to stdout and is therefore unusable, while
//! `pass-cli run [--env-file FILE] -- CMD` puts secrets in a child's
//! environment and prints nothing. So a lookup is a `run` whose child is
//! `printenv`, and the env file is written for that one lookup and deleted
//! after it.
//!
//! Two details of the vendor's contract shape the code:
//!
//! - **`--no-masking` is required for the probe.** Proton's own output masking
//!   is on by default and replaces a value in the child's output with
//!   `<concealed by Proton Pass>`. The probe reads the child's output, so with
//!   masking left on it would read the mask token and inject *that* as the
//!   credential. Disabling it here costs nothing: `keyless` masks the real
//!   child's output itself, over more encodings, and the probe's own output
//!   never leaves this process.
//! - **Every read needs a reason.** `PROTON_PASS_AGENT_REASON` must be present
//!   and non-empty, is capped at 300 characters, and is stored end-to-end
//!   encrypted beside the audit entry. See [`Reason`] for what goes in it and
//!   what deliberately does not.
//!
//! # What this adapter never touches
//!
//! No token file, no keyring entry, no account credential. The login belongs to
//! `pass-cli` and is inherited by spawning it, and there is no config field in
//! which a token would fit.
//!
//! # Why there is no `keyless login proton`, and no `keyless proton -- …`
//!
//! The obvious close for the lost-session-directory class is a `keyless` verb
//! that runs the vendor for you with the variable already set. Attacked before
//! being built, it is not the answer:
//!
//! - **The general form is a `get` verb wearing a hyphen.** `keyless proton --
//!   <args>` reaches `item view --field password`, `totp generate`, `inject` and
//!   `personal-access-token create`, and every one of those prints a credential
//!   to stdout. The whole claim of this tool is that no verb prints a value, and
//!   the most reachable verb in it must not be the exception. An allowlist of
//!   harmless vendor verbs would narrow that and would still be a list this
//!   crate has to keep correct against somebody else's release schedule.
//! - **A narrow `keyless login proton` closes one verb out of seventeen.** See
//!   [`SESSION_SCOPED_VERBS`]: an operator reaches for `info`, `logout`, `agent
//!   create` and `agent renew` in the same sitting, and each one silently
//!   answers about the DEFAULT session when the variable is missing. Closing the
//!   one that was noticed leaves the class open.
//! - **Neither reaches the person who typed the command.** Both incidents began
//!   with a command line that had been WRITTEN DOWN without the variable — in
//!   this crate's own messages, in its README, and in the vendor's own `agent
//!   instructions`, which tells its reader to recover from an authentication
//!   error by logging out. A new verb adds a second correct spelling; it removes
//!   no wrong one.
//! - **Every wrapper is one more place to destroy a session.** See
//!   [`remove_ambient_references`]: handed an environment somebody sanitised,
//!   `pass-cli` reinitialises the session database at that path, and a web-login
//!   session does not come back.
//!
//! So the coordinate is attached where a command line is WRITTEN instead.
//! [`scoped_command`] is the only place the prefix is assembled, and
//! `tests/session_coordinate.rs` fails the suite when a published file writes a
//! command line the variable is absent from.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;
use zeroize::Zeroize;

use crate::config::{Config, SecretRoute};
use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;
use crate::store::discover::{Discover, FieldKind, FieldSummary, ItemSummary};
use crate::store::exec::{self, CaptureError, capture, strip_one_newline, summarise};

/// This adapter's id, as a config route and an error message spell it.
pub const STORE_ID: &str = "proton";

/// The environment variable a read's justification travels in.
pub(crate) const REASON_VAR: &str = "PROTON_PASS_AGENT_REASON";

/// The environment variable that chooses which logged-in identity answers.
pub(crate) const SESSION_DIR_VAR: &str = "PROTON_PASS_SESSION_DIR";

/// The environment variable that chooses where the local encryption key lives.
///
/// See [`KeyProvider`], which is the whole story.
pub const KEY_PROVIDER_VAR: &str = "PROTON_PASS_KEY_PROVIDER";

/// The environment variable [`KeyProvider::Env`] reads that key out of.
pub const ENCRYPTION_KEY_VAR: &str = "PROTON_PASS_ENCRYPTION_KEY";

/// Where `pass-cli` keeps the key its local session store is encrypted with.
///
/// # This is the field that decides whether a login survives
///
/// `pass-cli` encrypts its session database with a **local key**, and where
/// that key is kept is chosen by [`KEY_PROVIDER_VAR`]. Read out of the 2.3.2
/// binary, it accepts exactly three words: `fs`, `keyring` and `env`, and it
/// says so — `Invalid PROTON_PASS_KEY_PROVIDER value: '<what you wrote>'. Valid
/// values are 'fs', 'keyring', or 'env'`.
///
/// Two of those three are representable here. `keyring` is not, and that is
/// this type's entire reason to exist.
///
/// **The default is `keyring`, and a keyring belongs to the uid that unlocked
/// it.** So a process with no login keychain — a daemon's uid, a build agent,
/// anything started without a user session — asks the keyring for the local
/// key and is told there is none. The binary's own words for what happens
/// next: `Local encryption key not found but local data exists. Forcing logout
/// for security.` It then reinitialises the session store at that path.
///
/// That is the mechanism behind this adapter's oldest and worst hazard, the
/// one [`remove_ambient_references`] documents: a `pass-cli` invoked with a
/// stripped environment **destroys a web-login session**, unrecoverably. The
/// stripping was never the cause; it was one way of reaching the cause, by
/// taking away what the keyring provider needed to answer. A daemon reaches
/// the same cause by simply not having a login keychain in the first place.
///
/// Naming a provider that keeps the key somewhere a daemon can reach is
/// therefore not a convenience — it is the difference between an adapter that
/// works behind a uid boundary and one that empties a session store every time
/// it runs. So the field is not optional, its default is the safe value, and
/// the unsafe value cannot be written into a config at all: a `keyring` there
/// is a parse error, which on a daemon means it refuses to start, which is
/// visible. See [`crate::daemon::config`] on why that is the right direction
/// for a daemon to fail in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KeyProvider {
    /// The key is a file inside the session directory. Whoever owns that
    /// directory can read it, and nobody else, which is the same boundary the
    /// session store itself has.
    #[default]
    Fs,
    /// The key arrives in [`ENCRYPTION_KEY_VAR`], base64url-encoded. Nothing
    /// is written beside the session store, at the cost of the daemon having
    /// to hold one more value in its own credential file.
    Env,
}

impl KeyProvider {
    /// The word the vendor accepts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyProvider::Fs => "fs",
            KeyProvider::Env => "env",
        }
    }
}

impl fmt::Display for KeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for KeyProvider {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for KeyProvider {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let word = String::deserialize(deserializer)?;
        match word.as_str() {
            "fs" => Ok(KeyProvider::Fs),
            "env" => Ok(KeyProvider::Env),
            // Refused by name, with the reason, rather than by serde's
            // "unknown variant" — an operator reading that would reasonably
            // conclude this build is out of date, and set out to find one that
            // accepts the vendor's own documented value.
            "keyring" => Err(serde::de::Error::custom(format!(
                "`{KEY_PROVIDER_VAR}` may not be `keyring` here. A keyring belongs to the \
                 uid that unlocked it, so a daemon's uid finds no local key in one — and \
                 `pass-cli` answers a missing local key beside an existing session store by \
                 FORCING A LOGOUT and reinitialising the store. Use `fs`, which keeps the \
                 key in the session directory, or `env`, which takes it from \
                 `{ENCRYPTION_KEY_VAR}`"
            ))),
            other => Err(serde::de::Error::custom(format!(
                "`{other}` is not a key provider; this build accepts `fs` and `env`"
            ))),
        }
    }
}

/// The vendor's cap on that justification.
const REASON_MAX: usize = 300;

/// What the vendor's masking substitutes for a value.
///
/// Taken from the documentation rather than observed. If the real text differs,
/// the guard that uses it does not fire — so the guard is a second line of
/// defence behind `--no-masking`, never the only one.
const CONCEALED_MARKER: &str = "concealed by proton pass";

/// The variable the probe reads out of the child environment.
///
/// Fixed rather than derived from the secret's name: the name is `keyless`'s,
/// while this is an implementation detail of one probe that lives for one
/// process. Fixing it also keeps a name with awkward characters from having to
/// be a valid environment variable on the way through.
const PROBE_VAR: &str = "KEYLESS_PROBE";

/// The scheme `pass-cli` treats as a secret reference wherever it finds one.
pub(crate) const REFERENCE_SCHEME: &str = "pass://";

/// Distinguishes concurrent probes within one process.
static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Environment variables the probe must not inherit, and why there are any.
///
/// **Measured 2026-08-08, `pass-cli` 2.2.5:** `run` resolves every `pass://`
/// reference it finds in the **whole inherited environment**, not only the ones
/// in `--env-file`. A single unrelated `UNRELATED=pass://…` exported in the
/// caller's shell is enough to make
/// `pass-cli run -- printenv HOME` exit 1 with `Failed to resolve secret … in
/// variable UNRELATED`.
///
/// That costs `keyless` two things at once, and both are exactly the kind of
/// over-reach the rest of this adapter is written to avoid:
///
/// - **Reads nobody asked for.** Each extra reference is fetched from the
///   vault and recorded, permanently and off-machine, against an audit trail
///   the user reads to answer "what did this tool touch?". `keyless` asked for
///   one name; a stale shell variable would make it read a second item and
///   leave a receipt saying it did.
/// - **A denial with a misleading cause.** One unresolvable reference anywhere
///   in the environment fails the *whole* probe, so every Proton-backed name in
///   the config degrades and the message is about a variable that has nothing
///   to do with any of them.
///
/// So the probe's environment is filtered rather than cleared.
///
/// # Never clear it — clearing DESTROYS the user's login
///
/// Clearing was tried, on 2026-08-08, and it did more than fail. Run under
/// `env -i` with `PROTON_PASS_SESSION_DIR` set and little else, `pass-cli`
/// 2.2.5 reports `This operation requires an authenticated client` **and
/// reinitialises the session database at that path**, replacing a logged-in
/// session with an empty one.
///
/// How bad that is depends on how the session was created, and the difference
/// is worth knowing before anyone experiments here:
///
/// - A **personal-access-token** session recovers by itself. The token is held
///   outside the session database, so the next command re-establishes the
///   session — with a **new share id for the same vault**, which is why a
///   reference is written against the session that will resolve it and not
///   copied from anywhere else.
/// - A **web-login** session does not. It is gone, the only way back is
///   `pass-cli login`, and nothing on disk restores it. That is not a
///   hypothetical: stripping the environment of a probe is enough to destroy a
///   web-login session that took a browser round trip to create.
///
/// The rule that follows is unconditional and applies to any future change
/// here: **`pass-cli` may rewrite its session store on any invocation, so never
/// invoke it with an environment you have stripped.** Remove exactly the
/// variables that are known to cause a problem and leave the rest alone.
///
/// The caller's own environment is untouched: this filters the argument list of
/// one short-lived probe, not the environment `keyless` hands the real child.
///
/// `environment` is a parameter rather than a call to [`std::env::vars_os`] so
/// the rule can be tested against a hand-written list. Mutating this process's
/// environment to test it would be `unsafe` in a suite that runs its tests on
/// several threads, and the wiring to the real environment is covered live in
/// `tests/proton_live.rs`.
pub(crate) fn remove_ambient_references<I>(command: &mut Command, environment: I)
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    for (key, value) in environment {
        if value.to_string_lossy().contains(REFERENCE_SCHEME) {
            command.env_remove(&key);
        }
    }
}

/// Attach `--flag=value` as ONE argument, because a value may begin with `-`.
///
/// # The failure this exists to stop
///
/// `pass-cli` parses with clap, and clap reads any standalone argument starting
/// with a single `-` as a short-flag cluster — whatever option preceded it.
/// Measured against `pass-cli` 2.2.5 on 2026-08-08:
///
/// ```text
/// $ pass-cli item list --vault-name -dashvault --output json
/// error: unexpected argument '-d' found
///   tip: to pass '-d' as a value, use '-- -d'
/// exit 2
/// ```
///
/// That is not a corner case here. Proton item and share ids are **base64url**,
/// whose alphabet includes `-`, so roughly one id in 64 begins with one. This
/// was found on a real item, not reasoned about: an id beginning `-` meant
/// `keyless fields` could not inspect that item at all.
///
/// # Why the `=` form and not the alternatives
///
/// - **A `--` separator** ends option parsing, so it protects a POSITIONAL. Every
///   coordinate here is an option VALUE, which is on the wrong side of that
///   separator. It fixes nothing.
/// - **The vendor's by-name flags** (`--item-title`, `--vault-name`) address by
///   title, which is exactly what this adapter refuses to do: the ids come from a
///   listing it just read, so `fields` and `run` see the same item even when two
///   share a title.
/// - **Shell quoting** does not enter into it — [`Command`] passes an argument
///   vector to `execvp` and no shell is involved. The receiving parser is what
///   rejects the value, so the fix has to be in the argument it receives.
///
/// `--flag=value` is accepted by clap for every long option, verified against the
/// same binary and the same value that fails above. It carries no ambiguity: clap
/// splits on the FIRST `=`, so a value containing one arrives whole.
///
/// This is the only way this adapter and [`crate::store::proton_manager`] pass a
/// value that a vault, an item, a share or a path decides. There is deliberately
/// no second idiom.
pub(crate) fn flag_value(command: &mut Command, flag: &str, value: impl AsRef<std::ffi::OsStr>) {
    let mut joined = std::ffi::OsString::from(flag);
    joined.push("=");
    joined.push(value);
    command.arg(joined);
}

/// The justification recorded, end-to-end encrypted, against every read.
///
/// # Why this is not the command line
///
/// The obvious reason to record is "what the user ran". It is also the one
/// thing that must not be recorded. An argument vector is where every shape
/// this tool exists to remove ends up — a credential in a URL, in a `--token=`
/// flag, in a header. A reason is assembled *before* any name has
/// resolved, so `keyless` has nothing to redact those with yet, and it is then
/// sent to a vendor and kept. Putting argv in it would take the exact class of
/// leak this tool exists to prevent and forward it to a third party under a
/// field labelled "reason".
///
/// So the reason carries the verb, the program's base name, how many arguments
/// it had, and the name being resolved — enough to answer "which run was this,
/// and what did it want?" while carrying no argument value at all. The base
/// name of a program is not a credential; an argument routinely is.
#[derive(Debug, Clone)]
pub struct Reason {
    prefix: String,
}

impl Reason {
    /// The reason for a `keyless run` of `argv`.
    ///
    /// Only `argv[0]`'s final path component is used, and only the *count* of
    /// the rest.
    #[must_use]
    pub fn for_run(argv: &[std::ffi::OsString]) -> Self {
        let program = argv
            .first()
            .map(Path::new)
            .and_then(Path::file_name)
            .map_or_else(
                || "?".to_owned(),
                |name| name.to_string_lossy().into_owned(),
            );
        let arguments = argv.len().saturating_sub(1);
        Reason {
            prefix: format!("{} run {program} ({arguments} args)", crate::NAME),
        }
    }

    /// The reason for a command that has no child, such as `doctor --probe`.
    #[must_use]
    pub fn for_verb(verb: &str) -> Self {
        Reason {
            prefix: format!("{} {verb}", crate::NAME),
        }
    }

    /// The value of `PROTON_PASS_AGENT_REASON` for one lookup.
    #[must_use]
    pub fn for_name(&self, name: &str) -> String {
        self.for_action("resolving", name)
    }

    /// The same sentence for something other than a read.
    ///
    /// `action` is a verb this crate chooses — `resolving`, `listing`,
    /// `inspecting`, `creating` — and `subject` is a coordinate: a secret's name,
    /// a vault name, an item title. **Neither may ever be an argument value**,
    /// which is the rule the whole type exists for; see the type documentation.
    ///
    /// Truncated on a character boundary so a multi-byte subject cannot produce a
    /// string the vendor rejects, and never empty — an empty reason is refused
    /// by the API, which would turn every read into a failure.
    #[must_use]
    pub fn for_action(&self, action: &str, subject: &str) -> String {
        let mut reason = format!("{}: {action} {subject}", self.prefix);
        if reason.len() > REASON_MAX {
            let mut cut = REASON_MAX;
            while cut > 0 && !reason.is_char_boundary(cut) {
                cut -= 1;
            }
            reason.truncate(cut);
        }
        if reason.trim().is_empty() {
            reason = crate::NAME.to_owned();
        }
        reason
    }
}

impl Default for Reason {
    fn default() -> Self {
        Reason {
            prefix: crate::NAME.to_owned(),
        }
    }
}

/// Deletes the env file it names, on every exit path including a panic.
struct TempEnvFile {
    path: PathBuf,
}

impl TempEnvFile {
    /// Write `KEYLESS_PROBE=<reference>` to a fresh 0600 file.
    ///
    /// The contents are a reference — vault, item and field names — never a
    /// value. It is still written 0600, because those names describe where a
    /// credential lives and a directory shared with every other process on the
    /// machine is no place to publish that.
    fn create(directory: &Path, reference: &str) -> io::Result<Self> {
        let unique = format!(
            "{}-probe-{}-{}.env",
            crate::NAME,
            std::process::id(),
            PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let path = directory.join(unique);
        let body = format!("{PROBE_VAR}={reference}\n");

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            // Created with the mode rather than chmod'd after: between a create
            // and a chmod there is a window in which the file is world-readable.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(body.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&path, body)?;
        }

        Ok(TempEnvFile { path })
    }
}

impl Drop for TempEnvFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// What to tell an operator whose config names no session directory.
///
/// Written once because [`ProtonStore::resolve`] and [`ProtonStore::health`]
/// must give the same answer: `doctor` exists to say in advance what a run
/// would say, and two copies of a sentence eventually stop matching.
const NO_SESSION_DIR: &str = "`stores.proton.session_dir` is not set, so which Proton \
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
/// silent. It must also not block: `keyless run` never refuses, and a config
/// typo is a poor place to acquire the first exception. So a lookup fails as
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
const SESSION_SUBDIR: &str = ".session";

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
struct InterruptedWrite {
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
const SESSION_FILE: &str = "session.json";

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
fn interrupted_write(session_dir: &Path) -> Option<InterruptedWrite> {
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
fn shell_word(path: &Path) -> String {
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

/// The environment variable an agent token travels in, at login.
///
/// Read out of `pass-cli agent instructions` on 2026-08-11 — the vendor's own
/// text, printed by the vendor's own binary, which is the only reason this crate
/// states it. The alternative spelling `pass-cli login --pat <TOKEN>` exists and
/// is **not** what this crate ever recommends: an argument is readable from the
/// process table for as long as the process lives, which is the exact leak
/// `keyless` exists to remove, and this crate does not get to make an exception
/// for its own setup instructions.
pub const TOKEN_VAR: &str = "PROTON_PASS_PERSONAL_ACCESS_TOKEN";

/// How a minted agent token becomes the identity in ONE session directory.
///
/// # The step that was missing entirely, not merely under-specified
///
/// `agent create` prints a token and writes nothing to any session directory.
/// Until that token is logged in somewhere, the directory named in the config is
/// empty — so an operator who follows a recipe ending at `agent access grant`
/// has a token, a config pointing at nothing, and a store that fails
/// authentication. That was true of this crate's own manager-token recipe and of
/// its README.
///
/// The token is a value, so it goes in the child's environment and never in an
/// argument. It does land in shell history, which is the vendor's design and not
/// something `keyless` can route around: say so rather than pretend the line is
/// free.
/// `None` when the directory is the one the operator is being told to invent —
/// [`SESSION_DIR_PLACEHOLDER`] stands in for it, because a path that does not
/// exist yet cannot be quoted as a shell word and a tilde that got quoted would
/// stop expanding.
#[must_use]
pub fn login_with_token(session_dir: Option<&Path>) -> String {
    let dir = session_dir.map_or_else(|| SESSION_DIR_PLACEHOLDER.to_owned(), shell_word);
    format!("{SESSION_DIR_VAR}={dir} {TOKEN_VAR}=<the token `agent create` printed> pass-cli login")
}

/// The login command for ONE session directory, ready to paste.
#[must_use]
pub fn login_into(session_dir: &Path) -> String {
    scoped_command(session_dir, "login")
}

/// The daemon's own Proton login, read out of a file only the daemon can open.
///
/// # Why the daemon needs one at all, when a session does not
///
/// A session spawns `pass-cli` and inherits whatever login the caller already
/// established — a session store the caller owns, encrypted with a key in the
/// caller's keyring. A daemon inherits neither half. It is given a session
/// directory of its own, and it must be able to put that session back when the
/// vendor drops it: measured behaviour recorded in [`remove_ambient_references`]
/// is that a personal-access-token session **re-establishes itself** on the next
/// command, because the token lives outside the session database. Without the
/// token in the environment there is nothing to re-establish it from, and the
/// first time anything disturbs that directory every Proton name stops
/// resolving until somebody notices and logs it back in by hand.
///
/// Under [`KeyProvider::Env`] it carries the local encryption key too, which is
/// the other half of the session and is a secret in exactly the same sense.
///
/// # Where it comes from, and everywhere it must not be
///
/// **Not the launchd plist**, whose `EnvironmentVariables` are readable by
/// every user on the machine. **Not `keylessd.json`**, which names coordinates
/// and has no field a value fits in. **Not the file the `file` store serves**,
/// because everything in that file is a name an attested client can ask for
/// over the socket — a vault-unlocking token kept there is handed to any
/// session that guesses its label, which is the hole this project exists to
/// close, reopened by its own installer.
///
/// So it comes from a [`Store`] the daemon reads under its own uid: a
/// mode-`0600` file [`crate::store::file::FileStore`] refuses to read if
/// anybody else could. The config names the variable and the entry; the value
/// never appears in anything an operator opens.
///
/// # One token, and it is a viewer
///
/// [`crate::config::ProtonConfig`] carries a second, editor-role identity for
/// the write verbs. The daemon deliberately has no counterpart: with
/// `daemon.enabled`, [`crate::store::manage`] refuses every write for every
/// store, so an editor token here would be a strictly larger prize with no
/// ability whatsoever to be used.
///
/// The vendor enforces the rest in its crypto layer rather than by policy —
/// `Personal access tokens and agent sessions cannot perform user key
/// operations`, read out of the 2.3.2 binary — so a viewer-role token scoped to
/// one vault is narrower than anything a login could be talked into.
///
/// # Read per lookup, not held
///
/// Resolved when a lookup is about to spawn the vendor, and dropped with the
/// [`Secret`]s that carry it. A rotated token therefore takes effect without
/// restarting the daemon, and nothing keeps a plaintext copy between calls. The
/// same residency as the forwarded variables beside it: one copy lives as long
/// as the [`Command`] holding it.
pub struct AgentToken {
    source: Box<dyn Store>,
    names: BTreeMap<String, String>,
}

impl AgentToken {
    /// Read the values for `names` — vendor variable to entry name — out of
    /// `source`.
    #[must_use]
    pub fn new(source: Box<dyn Store>, names: BTreeMap<String, String>) -> Self {
        AgentToken { source, names }
    }

    /// The named variables this adapter will not set, in the order it reads them.
    ///
    /// An **allowlist of exactly two**, and deliberately narrower than the
    /// `INFISICAL_*` prefix rule the sibling adapter uses. A prefix rule works
    /// there because every `INFISICAL_*` variable is a credential. It does not
    /// work here: the two variables that decide whether this adapter is safe
    /// are both `PROTON_PASS_*`. [`SESSION_DIR_VAR`] chooses which identity
    /// answers — the difference between reading one vault and reading a whole
    /// account — and [`KEY_PROVIDER_VAR`] chooses whether the session store
    /// survives being read. A credential entry able to set either would
    /// silently overrule the two settings this store's own config exists to
    /// state.
    ///
    /// An associated function on the map rather than a method, so a config can
    /// be checked before a store is built from it.
    #[must_use]
    pub fn refused(names: &BTreeMap<String, String>) -> Vec<String> {
        names
            .keys()
            .filter(|variable| {
                variable.as_str() != TOKEN_VAR && variable.as_str() != ENCRYPTION_KEY_VAR
            })
            .cloned()
            .collect()
    }

    /// Every named value, or the sentence saying which one could not be read.
    fn resolve(&self) -> Result<Vec<(String, Secret)>, StoreError> {
        if let Some(variable) = Self::refused(&self.names).first() {
            return Err(StoreError::Misconfigured {
                store: STORE_ID.to_owned(),
                detail: format!(
                    "`{variable}` is named as a Proton credential and is neither \
                     `{TOKEN_VAR}` nor `{ENCRYPTION_KEY_VAR}`. Only those two may be set \
                     this way: every other `PROTON_PASS_*` variable is one this adapter \
                     sets itself, and one named here would choose which identity answers \
                     or where its encryption key is looked for"
                ),
            });
        }

        let mut resolved = Vec::with_capacity(self.names.len());
        for (variable, name) in &self.names {
            match self.source.resolve(name) {
                Ok(Some(secret)) => resolved.push((variable.clone(), secret)),
                // Named and missing is a misconfiguration, not an absence: the
                // operator wrote down where the token lives and it is not
                // there, so every Proton name degrades and the message says
                // which entry to write rather than which vault to search.
                Ok(None) => {
                    return Err(StoreError::Misconfigured {
                        store: STORE_ID.to_owned(),
                        detail: format!(
                            "the Proton credential `{variable}` is declared to live in \
                             `{name}` of the `{}` store, which holds no such entry",
                            self.source.id()
                        ),
                    });
                }
                Err(error) => {
                    return Err(StoreError::Misconfigured {
                        store: STORE_ID.to_owned(),
                        detail: format!(
                            "the Proton credential `{variable}` could not be read: {error}"
                        ),
                    });
                }
            }
        }
        Ok(resolved)
    }
}

/// What to tell an operator whose session directory holds an unfinished write.
///
/// Two states, because they call for opposite actions: a write that stopped
/// moving is damage, and a write from two seconds ago may be a sibling process
/// doing its job.
fn interrupted_write_detail(session_dir: &Path, write: &InterruptedWrite, vendor: &str) -> String {
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

/// Where one name lives, in the stable form: vault name, item title, field.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ItemAddress {
    vault: String,
    item: String,
    field: String,
}

/// How a declared name says where its value is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Address {
    /// `pass://SHARE_ID/ITEM_ID/FIELD`, taken verbatim. Pins one item, and dies
    /// when the session that minted the share id is replaced.
    Reference(String),
    /// Vault name, item title and field. The ids are resolved at lookup time.
    Named(ItemAddress),
    /// The config names a Proton backend in a way that cannot be an address.
    /// Carries the sentence an operator needs; see [`Address::from_route`].
    Unusable(String),
}

impl Address {
    /// Read one config entry, or say precisely why it is not an address.
    ///
    /// Returns `None` when the entry says nothing about Proton at all, which is
    /// a different fault with a different message — see [`ProtonStore::resolve`].
    ///
    /// Every rejection here is decided **before** anything is spawned, so a
    /// malformed entry costs no vault read and leaves no audit entry.
    fn from_route(route: &SecretRoute) -> Option<Self> {
        let named = [&route.vault, &route.item, &route.field];
        let any_named = named.iter().any(|part| part.is_some());

        match (&route.reference, any_named) {
            (None, false) => None,
            // Refusing rather than ranking them: a config that states an
            // address twice has two answers to one question, and picking the
            // one this build happens to prefer is how the wrong item gets read
            // silently. Same rule as two backends answering one name.
            (Some(_), true) => Some(Address::Unusable(
                "both `reference` and the `vault`/`item`/`field` form are declared; \
                 keep one — the name form survives a new session, the reference does not"
                    .to_owned(),
            )),
            (Some(reference), false) => Some(Address::Reference(reference.clone())),
            (None, true) => Some(Self::named(route)),
        }
    }

    /// The name form, once at least one of its three parts is present.
    fn named(route: &SecretRoute) -> Self {
        let missing: Vec<&str> = [
            ("vault", &route.vault),
            ("item", &route.item),
            ("field", &route.field),
        ]
        .into_iter()
        .filter(|(_, part)| part.as_deref().is_none_or(str::is_empty))
        .map(|(label, _)| label)
        .collect();

        if !missing.is_empty() {
            // None of the three is inferable. A vault or a field guessed from
            // the secret's name would send a read, and a permanent off-machine
            // audit entry, to an item nobody asked for.
            return Address::Unusable(format!(
                "the `vault`/`item`/`field` form needs all three, and {} {} missing or empty",
                missing.join(", "),
                if missing.len() == 1 { "is" } else { "are" }
            ));
        }

        let address = ItemAddress {
            vault: route.vault.clone().unwrap_or_default(),
            item: route.item.clone().unwrap_or_default(),
            field: route.field.clone().unwrap_or_default(),
        };

        // A `/` in the field would move the boundary inside the reference this
        // builds, so the CLI would be handed a different address than the one
        // written down — silently, and with a plausible-looking result.
        if address.field.contains('/') {
            return Address::Unusable(format!(
                "`field` may not contain `/`: `{}` would address a different item once \
                 it is written into a pass:// reference",
                address.field
            ));
        }

        Address::Named(address)
    }
}

/// One record of `pass-cli item list --output json`.
///
/// Only the four keys this adapter acts on are named. That is forward
/// compatibility and a safety property at once: a key added by a later CLI
/// cannot fail the parse, and — since `--show-secrets` is never passed and is
/// refused for agent sessions anyway — content this adapter did not ask for is
/// not merely unused, it is never held. Every field here is a coordinate, which
/// is why naming one in an error message is safe.
///
/// **`id`, not `item_id`** — there is no `item_id` key, and asking for one
/// yields nothing.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ItemRecord {
    pub(crate) id: String,
    pub(crate) share_id: String,
    pub(crate) state: String,
    pub(crate) title: String,
    /// `login`, `custom`, `note`, … Defaulted rather than required so a listing
    /// from a CLI that stops sending it degrades one column of `items` instead of
    /// failing every lookup in `run`.
    #[serde(default)]
    pub(crate) item_type: String,
}

impl ItemRecord {
    /// Whether this item is live, as an allowlist rather than a denylist.
    ///
    /// A trashed item is still listed, and resolving one would hand a child a
    /// value its owner believes they deleted. Anything that is not plainly
    /// `Active` — a state added by a later CLI, a spelling this build has never
    /// seen — is therefore treated as not resolvable, which degrades the name
    /// instead of reading something unexpected.
    pub(crate) fn is_active(&self) -> bool {
        self.state.eq_ignore_ascii_case("active")
    }
}

/// What `pass-cli item list --output json` prints.
#[derive(Debug, Deserialize)]
pub(crate) struct ItemListing {
    pub(crate) items: Vec<ItemRecord>,
}

/// One record of `pass-cli vault list --output json`.
///
/// Only the name is read. A vault's share id is minted per session — see this
/// module's header — so storing one would be storing something that expires, and
/// every command below addresses a vault by `--vault-name` anyway.
#[derive(Debug, Clone, Deserialize)]
struct VaultRecord {
    name: String,
}

/// What `pass-cli vault list --output json` prints.
#[derive(Debug, Deserialize)]
struct VaultListing {
    vaults: Vec<VaultRecord>,
}

/// Which title matched, in the three shapes a caller has to be told apart.
pub(crate) enum Matched<'a> {
    /// Exactly one live item carries the title.
    One(&'a ItemRecord),
    /// Nothing carries it at all.
    None,
    /// Only trashed items carry it. Resolving one would hand out a value its
    /// owner believes is deleted, so this is never silently promoted to `One`.
    OnlyTrashed,
    /// Several live items carry it. Refused, never ranked: guessing here is a
    /// wrong credential delivered with nothing said.
    Several(Vec<&'a ItemRecord>),
}

/// Find the one live item with `title`, or say which of the other three it is.
///
/// Shared by the resolver and by `fields` so the two cannot disagree about which
/// item a title names. Each caller writes its own message, because the fix
/// differs: a resolver points at the `reference` escape hatch, `fields` points at
/// the trash.
pub(crate) fn match_title<'a>(items: &'a [ItemRecord], title: &str) -> Matched<'a> {
    // Exact and case-sensitive: a looser match is a second way to reach an item
    // nobody named.
    let (live, dead): (Vec<&ItemRecord>, Vec<&ItemRecord>) = items
        .iter()
        .filter(|record| record.title == title)
        .partition(|record| record.is_active());

    match live.as_slice() {
        [only] => Matched::One(only),
        [] if dead.is_empty() => Matched::None,
        [] => Matched::OnlyTrashed,
        _ => Matched::Several(live),
    }
}

/// Keys whose **value** is a field's label rather than a field's content.
///
/// This and [`VALUE_KEYS`] together are the only place in this crate where a
/// string from a value position may reach stdout, and the pair is deliberately
/// tiny. Measured against `pass-cli` 2.2.5, the two shapes are not the same:
///
/// | Where | Label key | Value key |
/// |---|---|---|
/// | `item view --output json`, on a custom item | `item.content.extra_fields[N].name` | `…[N].content` |
/// | `item create custom --get-template` | `sections[].fields[].field_name` | `…value` |
///
/// **The template's shape is NOT the view's shape**, which is worth stating
/// because the template is the only one of the two that can be read without
/// printing a credential — so it is the tempting thing to build against, and it is
/// wrong. Both are handled: the write path builds a template, the read path parses
/// a view.
const LABEL_KEYS: &[&str] = &["field_name", "name"];

/// Keys whose value is a field's CONTENT. Never printed, in any form.
///
/// Their presence is what identifies the object around them as a field
/// descriptor, so they are read as structure and never as data. On the view shape
/// `content` is itself an object — `{"Hidden": "<the credential>"}` — whose single
/// key is the field's type, which is why [`FieldSummary::value_type`] can report a
/// type without going anywhere near the value.
const VALUE_KEYS: &[&str] = &["content", "value"];

/// Keys that are never a usable field name, so their key is not printed either.
///
/// Two groups. The first is item metadata — ids, states, timestamps — which is
/// not addressable in a `pass://` reference and would be noise in a listing. The
/// second is the structural keys of a custom field: `value` above all, whose
/// **key** is safe to print but whose presence in the output would invite exactly
/// the wrong conclusion, and `field_name` / `field_type`, whose names are handled
/// by [`NAME_KEYS`] or ignored.
const NEVER_A_FIELD: &[&str] = &[
    "value",
    "content",
    "field_name",
    "field_type",
    "section_name",
    "id",
    "item_id",
    "item_uuid",
    "share_id",
    "vault_id",
    "state",
    "flags",
    "revision",
    "create_time",
    "modify_time",
    "content_format_version",
    "item_type",
    "type",
];

/// The vendor's rendering of ONE item, which **contains that item's values**.
///
/// The only radioactive object in this crate outside [`Secret`] itself, and it
/// exists because of an unavoidable fact: the sole `pass-cli` verb that reveals
/// an item's field NAMES is `item view`, which also prints their values. So the
/// values enter this process whether anyone wants them or not, and the whole
/// question is what happens between arrival and the first byte of output.
///
/// Four properties, each closing one way this has leaked in other tools:
///
/// - **No `Display` and a hand-written `Debug`.** `{:?}` prints
///   `ItemView(<redacted>)`, so an `assert!` message, an `expect`, a stray
///   `dbg!` or a derived `Debug` on any struct holding one cannot print an item.
/// - **`Drop` scrubs every string in the tree**, so the plaintext does not sit
///   in freed heap for the rest of the process. That covers the early-return and
///   panic paths as well, which is the reason it is a `Drop` and not a call at
///   the end of a function.
/// - **The only accessor is [`ItemView::field_names`]**, which returns names
///   built from key positions and from [`NAME_KEYS`]. There is no method that
///   returns a value, and no method that returns a value's length.
/// - **It is never serialized.** It has no `Serialize`, so it cannot reach the
///   audit log by someone adding a field to a row.
struct ItemView(serde_json::Value);

impl ItemView {
    /// Parse the vendor's JSON, or say it did not parse without quoting it.
    ///
    /// The error deliberately does not include serde's own message beyond its
    /// position: serde_json reports unexpected input by quoting it, and the input
    /// here is an item's contents.
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .map(ItemView)
            .map_err(|error| {
                format!(
                    "`item view` did not return JSON this build understands (at line {}, column {})",
                    error.line(),
                    error.column()
                )
            })
    }

    /// Every field name on the item, with where it was found.
    ///
    /// Document order rather than sorted: it is the order the item shows in
    /// Proton's own UI, which is what somebody comparing the two expects.
    /// Duplicates are dropped, because a name and a path together are unique and
    /// repeating them says nothing.
    fn field_names(&self) -> Vec<FieldSummary> {
        let mut found = Vec::new();
        collect_fields(&self.0, "", false, &mut found);
        found.dedup();
        found
    }
}

impl fmt::Debug for ItemView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ItemView(<redacted>)")
    }
}

impl Drop for ItemView {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

/// Zeroize every string in a JSON tree, in place.
///
/// Object *keys* are left alone: they are field names, which is the thing being
/// reported, and `serde_json`'s map gives no mutable access to them anyway.
pub(crate) fn scrub(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => {
            for item in items {
                scrub(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, child) in map.iter_mut() {
                scrub(child);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// Walk `value`, emitting field names and nothing else.
///
/// Two rules, and there is no third:
///
/// 1. **An array element that is a field descriptor** — an object carrying a key
///    from [`LABEL_KEYS`] beside one from [`VALUE_KEYS`] — contributes its label as
///    a custom field's name, and is **not** recursed into. That is the only rule by
///    which a string from a value position reaches the output.
/// 2. **An entry whose value is a JSON scalar** contributes its KEY as a built-in
///    field's name, unless the key is in [`NEVER_A_FIELD`].
///
/// Everything else is recursed into.
///
/// # Why rule 1 requires being inside an array
///
/// Both vendor shapes keep field descriptors in a list — `extra_fields[]` on the
/// view, `sections[].fields[]` on the template — and nothing else in either shape
/// is one. Without that condition the rule is much looser than it looks: the
/// view's own top-level `item` object carries a `content` key, so an `item` that
/// ever gained a `name` would be read as a single field descriptor and the whole
/// item's fields would silently vanish from the listing. Requiring an array
/// element makes the rule structural rather than a guess about key names.
///
/// A shape that puts a descriptor outside an array falls back to rule 2, which
/// emits keys. That is a **worse listing, never a leak** — which is the direction
/// this has to fail in.
fn collect_fields(
    value: &serde_json::Value,
    path: &str,
    in_array: bool,
    out: &mut Vec<FieldSummary>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if in_array && let Some((label, value_type)) = field_descriptor(map) {
                out.push(FieldSummary {
                    name: label,
                    kind: FieldKind::Custom,
                    value_type,
                    path: path.to_owned(),
                });
                // Deliberately no recursion: everything below here is the value.
                return;
            }

            for (key, child) in map {
                let here = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if is_scalar(child) {
                    if !NEVER_A_FIELD.contains(&key.as_str()) {
                        out.push(FieldSummary {
                            name: key.clone(),
                            kind: FieldKind::Builtin,
                            value_type: None,
                            path: path.to_owned(),
                        });
                    }
                    continue;
                }
                collect_fields(child, &here, false, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_fields(item, &format!("{path}[{index}]"), true, out);
            }
        }
        _ => {}
    }
}

/// A field descriptor's label and, when the shape carries one, its type.
///
/// Returns `None` unless the object holds both a label and a value container:
/// a label alone is just a string somewhere, and a container alone has no name to
/// report.
///
/// The type comes from the container's own single key on the view shape —
/// `{"Hidden": …}` — or from a sibling `field_type` on the template shape. Reading
/// a key is not reading a value, so this stays on the safe side of the line.
fn field_descriptor(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Option<(String, Option<String>)> {
    let container = VALUE_KEYS
        .iter()
        .find_map(|key| map.get(*key).map(|value| (*key, value)))?;

    let label = LABEL_KEYS.iter().find_map(|key| match map.get(*key) {
        Some(serde_json::Value::String(label)) if !label.is_empty() => Some(label.clone()),
        _ => None,
    })?;

    let value_type = match map.get("field_type") {
        Some(serde_json::Value::String(named)) if !named.is_empty() => Some(named.clone()),
        // The view shape wraps the value in a single-key object whose key is the
        // type. More than one key means this build does not understand the shape,
        // and inventing a type would be worse than reporting none.
        _ => match container.1 {
            serde_json::Value::Object(inner) if inner.len() == 1 => inner.keys().next().cloned(),
            _ => None,
        },
    };

    Some((label, value_type))
}

/// Whether a JSON value is a leaf rather than a container.
fn is_scalar(value: &serde_json::Value) -> bool {
    !matches!(
        value,
        serde_json::Value::Object(_) | serde_json::Value::Array(_)
    )
}

/// Where every declared name lives inside Proton Pass.
///
/// # Why the projection is a type and not a map built at each call site
///
/// Two hosts build this adapter now — a session, from
/// [`crate::config::Config`], and a daemon, from its own `secrets` block — and
/// the one property that must hold in both is the one this file's whole safety
/// argument rests on: **a name that appears in no config has no address, and a
/// lookup with no address is a lookup that never spawns anything.** Two walks
/// of two maps would be free to disagree about which entries are addresses, and
/// the disagreement would be invisible: the daemon would simply resolve a name
/// the session refuses, or refuse one the session resolves.
///
/// So both hosts project through [`Routing::from_secrets`], and the session's
/// [`Routing::from_config`] is a thin wrapper over it rather than a second
/// implementation. What a daemon has that a session does not is a config file
/// the calling user cannot write — which is what turns "declared" into a
/// boundary rather than a convention.
pub struct Routing {
    /// name -> where its value lives. An entry that says nothing about Proton
    /// is absent, exactly as it is absent from a session's own projection.
    addresses: BTreeMap<String, Address>,
}

impl Routing {
    /// The projection a session builds, from its own parsed config.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self::from_secrets(&config.secrets)
    }

    /// The projection either host builds, from a `secrets` map.
    #[must_use]
    pub fn from_secrets(secrets: &BTreeMap<String, SecretRoute>) -> Self {
        Routing {
            addresses: secrets
                .iter()
                .filter_map(|(name, route)| {
                    Address::from_route(route).map(|address| (name.clone(), address))
                })
                .collect(),
        }
    }

    /// How many names carry a Proton address of any kind, usable or not.
    ///
    /// Counted rather than tested for emptiness so an operator-facing warning
    /// can say how many names it is talking about. An [`Address::Unusable`]
    /// counts: it is a name somebody meant to declare, and reporting "no name
    /// declares an address" over a config full of typos would send the reader
    /// to the wrong file.
    #[must_use]
    pub fn declared(&self) -> usize {
        self.addresses.len()
    }

    /// Where one name lives, or `None` when nothing declares it.
    ///
    /// `None` is the property `tests/daemon_proton.rs` asserts as the absence
    /// of a vendor process: see [`ProtonStore::resolve`], which turns it into
    /// an error before a temporary file is written or a child is created.
    fn route(&self, name: &str) -> Option<&Address> {
        self.addresses.get(name)
    }
}

/// Reads one Proton Pass item at a time through `pass-cli run`.
pub struct ProtonStore {
    binary: PathBuf,
    probe_binary: PathBuf,
    /// Value of `PROTON_PASS_SESSION_DIR` for every child. See
    /// [`ProtonStore::session_dir`].
    session_dir: Option<PathBuf>,
    /// Where the local key encrypting that session lives, or `None` to leave
    /// the choice to the vendor. See [`ProtonStore::key_provider`].
    key_provider: Option<KeyProvider>,
    /// The daemon's own login, or `None` on a session, which inherits one.
    /// See [`AgentToken`].
    credentials: Option<AgentToken>,
    timeout: Duration,
    reason: Reason,
    /// name -> where its value lives.
    routing: Routing,
    /// How long a listing may be reused. See [`ProtonStore::cached_items`].
    listing_ttl: Duration,
    /// vault name -> that vault's items, until they expire.
    ///
    /// In memory and nowhere else. A cache on disk that the client can read is
    /// a `get` verb with extra steps, which is the one thing this tool does not
    /// offer.
    listings: Mutex<BTreeMap<String, VaultSlot>>,
}

/// One vault's cache entry, and the gate that makes it fill exactly once.
///
/// The inner `Mutex` is the whole point: it is held across the vendor CLI spawn,
/// so several names resolving from one vault at the same time produce one
/// listing rather than one each. See [`ProtonStore::cached_items`].
type VaultSlot = Arc<Mutex<Option<Listed>>>;

/// One vault's items, and when they were fetched.
///
/// The timestamp is what makes the cache expire. Without it the entry is a
/// statement about the vault that was true once and is never checked again —
/// and the check it silently drops is the trash rule, since a trashed item is
/// still listed and is refused only because a listing says `Trashed`.
struct Listed {
    items: Arc<Vec<ItemRecord>>,
    at: Instant,
}

/// The longest a listing may be reused, whatever the config asks for.
///
/// A config is not a trusted input — it can arrive by `--config` or
/// `KEYLESS_CONFIG` from whatever wrote the file — so `listing_ttl_ms` is
/// clamped for the same reason `timeout_ms` is: without a ceiling it is the
/// knob that turns the expiry off again, and an expiry that a number can
/// disable is not a bound. Fifteen minutes is far above the default and far
/// below "until somebody restarts it".
pub const MAX_LISTING_TTL_MS: u64 = 900_000;

/// A configured `listing_ttl_ms` as a duration, clamped to
/// [`MAX_LISTING_TTL_MS`].
#[must_use]
pub const fn bounded_listing_ttl(milliseconds: u64) -> Duration {
    let bounded = if milliseconds > MAX_LISTING_TTL_MS {
        MAX_LISTING_TTL_MS
    } else {
        milliseconds
    };
    Duration::from_millis(bounded)
}

impl ProtonStore {
    /// Construct from a parsed config and the reason reads will be recorded under.
    #[must_use]
    pub fn from_config(config: &Config, reason: Reason) -> Self {
        let settings = &config.stores.proton;
        Self::new(
            settings.binary.to_path_buf(),
            settings.probe_binary.to_path_buf(),
            Routing::from_config(config),
            reason,
        )
        .in_session_dir(
            settings
                .session_dir
                .as_deref()
                .map(|path| path.to_path_buf()),
        )
        .with_timeout(settings.timeout_ms)
        .with_listing_ttl(settings.listing_ttl_ms)
    }

    /// Construct from the parts, with no session config anywhere behind it.
    ///
    /// The constructor a daemon uses. It takes a [`Routing`] rather than a
    /// `Config` for the reason [`Routing`] exists: the daemon's `secrets` block
    /// is not a [`crate::config::Config`] and must not have to become one for
    /// this adapter to be hosted behind the socket.
    ///
    /// The session directory is deliberately **not** a parameter here and is
    /// set by [`ProtonStore::in_session_dir`] instead, so that a store built
    /// and never pointed at one degrades every lookup rather than inheriting
    /// the ambient session. See [`ProtonStore::session_dir`] for why that is
    /// the only acceptable default.
    #[must_use]
    pub fn new(binary: PathBuf, probe_binary: PathBuf, routing: Routing, reason: Reason) -> Self {
        ProtonStore {
            binary,
            probe_binary,
            session_dir: None,
            key_provider: None,
            credentials: None,
            timeout: crate::config::bounded_timeout(crate::config::DEFAULT_TIMEOUT_MS),
            reason,
            routing,
            listing_ttl: bounded_listing_ttl(crate::config::default_listing_ttl_ms()),
            listings: Mutex::new(BTreeMap::new()),
        }
    }

    /// Which logged-in identity answers every child this store spawns.
    #[must_use]
    pub fn in_session_dir(mut self, session_dir: Option<PathBuf>) -> Self {
        self.session_dir = session_dir;
        self
    }

    /// The login this daemon presents, read out of its own file at lookup time.
    ///
    /// `None` on a session, which inherits one by spawning the vendor. See
    /// [`AgentToken`] for why a daemon cannot.
    #[must_use]
    pub fn with_agent_token(mut self, credentials: Option<AgentToken>) -> Self {
        self.credentials = credentials;
        self
    }

    /// Where the local key encrypting that session is kept.
    ///
    /// # Why a session sets none and a daemon must
    ///
    /// `None` leaves [`KEY_PROVIDER_VAR`] off the child entirely, so the vendor
    /// uses whatever the caller's own environment says — which for a person at
    /// a terminal is the keyring their `pass-cli login` already put the key in.
    /// Setting one there would be this adapter deciding, on a user's behalf,
    /// where a key it did not create should be looked for, and getting it wrong
    /// costs that user their login. So the session side stays out of it.
    ///
    /// A daemon has no such inheritance and no such default worth keeping: its
    /// uid's keyring is empty, and [`KeyProvider`] documents what `pass-cli`
    /// does about an empty one. So the daemon always names a provider, and it
    /// is a config field there rather than a constant here.
    #[must_use]
    pub fn with_key_provider(mut self, key_provider: Option<KeyProvider>) -> Self {
        self.key_provider = key_provider;
        self
    }

    /// Bound one lookup, in milliseconds. Clamped by
    /// [`crate::config::bounded_timeout`], so a config cannot switch the
    /// deadline off by naming a large enough number.
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout = crate::config::bounded_timeout(timeout_ms);
        self
    }

    /// How long one vault listing may be reused, in milliseconds. Clamped by
    /// [`bounded_listing_ttl`], for the reason that function documents.
    #[must_use]
    pub fn with_listing_ttl(mut self, listing_ttl_ms: u64) -> Self {
        self.listing_ttl = bounded_listing_ttl(listing_ttl_ms);
        self
    }

    /// The configured session directory, or the reason there will be no lookup.
    ///
    /// # Why an unset `session_dir` degrades rather than inheriting
    ///
    /// Three answers were available and two of them are worse.
    ///
    /// **Inherit the ambient session** is how the bug this replaces existed at
    /// all. It resolves every name, exactly as a correct configuration does,
    /// while reading an identity nobody chose — so the failure is invisible by
    /// construction and shows up as a full-account credential in a child that
    /// asked for a scoped one. A default whose failure mode is "everything
    /// works" cannot be audited.
    ///
    /// **Inherit and warn** keeps that leak and adds a line to every single
    /// run. This crate already holds the position that a warning printed on
    /// every invocation of a working setup is how a reader learns to skip
    /// stderr — see [`crate::store::Built`]. It would buy nothing: the wrong
    /// vault is still read, the remote audit entry is still written, and the
    /// value still reaches the child. A warning is not a control.
    ///
    /// **Refuse to register the backend** removes the store from the registry,
    /// which turns a `"store": "proton"` pin into `routed store is not
    /// configured` — a message pointing at a backend the user's own config
    /// plainly enables. Same objection as the daemon's dropped pins in
    /// [`crate::store::build`], and it also hides the store from `doctor`,
    /// which is the one place someone has come to ask.
    ///
    /// So the store registers, `doctor` reports it unhealthy with the fix in
    /// the message, and each lookup fails as [`StoreError::Unavailable`]. That
    /// is a **degraded name, never a refused command**: `run` treats an
    /// unavailable store exactly as it treats an unreachable one — it names the
    /// name it could not resolve and spawns the child anyway. The never-block
    /// invariant has no exception here and does not acquire one.
    fn session_dir(&self) -> Result<&Path, StoreError> {
        let dir = self
            .session_dir
            .as_deref()
            .ok_or_else(|| self.unavailable(NO_SESSION_DIR))?;
        if !dir.is_absolute() {
            // A relative session directory is the tilde defect wearing different
            // clothes — see `relative_session_dir` for why it degrades here and
            // refuses in the write verbs.
            return Err(self.unavailable(relative_session_dir("stores.proton.session_dir", dir)));
        }
        Ok(dir)
    }

    /// Put the three things every child of this adapter needs on one command.
    ///
    /// Written once and called from all four builders, because the set is not
    /// obviously complete and a builder that quietly lacked one of them would
    /// fail in a way nobody reads as a missing variable:
    ///
    /// - **The session directory** decides which logged-in identity answers. A
    ///   verb that inherited the ambient one would enumerate a different set of
    ///   vaults than the verb beside it, which reads as a missing item.
    /// - **The key provider** decides whether that identity survives being
    ///   read. A verb that left it unset under a uid with no keyring would
    ///   reinitialise the session store — see [`KeyProvider`] — so the next
    ///   verb, correctly written, would find nothing. One missing call here is
    ///   enough to make this adapter destroy its own login.
    /// - **The reason** is required by the vendor and is what the remote audit
    ///   entry is filed under.
    ///
    /// Deliberately NOT `env_clear` followed by a rebuild: `pass-cli` may
    /// rewrite its session store on any invocation and must never be handed an
    /// environment somebody stripped. See [`remove_ambient_references`], which
    /// removes exactly what is known to cause a problem and leaves the rest.
    fn scope(
        &self,
        command: &mut Command,
        session_dir: &Path,
        login: &[(String, Secret)],
        reason: String,
    ) {
        command.env(SESSION_DIR_VAR, session_dir);
        if let Some(provider) = self.key_provider {
            command.env(KEY_PROVIDER_VAR, provider.as_str());
        }
        for (variable, secret) in login {
            command.env(variable, secret.expose());
        }
        command.env(REASON_VAR, reason);
    }

    /// The daemon's login, resolved for one lookup, or nothing on a session.
    ///
    /// # Errors
    ///
    /// Whatever [`AgentToken::resolve`] could not read. Never an absence: a
    /// lookup that could not read its own login has not established that a
    /// name is missing.
    fn vendor_login(&self) -> Result<Vec<(String, Secret)>, StoreError> {
        match &self.credentials {
            Some(credentials) => credentials.resolve(),
            None => Ok(Vec::new()),
        }
    }

    /// Build one `pass-cli run --env-file … -- printenv KEYLESS_PROBE` invocation.
    ///
    /// `ambient` is the environment the child would otherwise inherit whole.
    /// It is a parameter rather than a call to [`std::env::vars_os`] inside
    /// this function so a test can prove the filtering is **wired in here**,
    /// not merely that the filter works when called directly. That distinction
    /// is not academic: with the filter tested on its own, deleting this call
    /// left the suite green.
    fn probe_command<I>(
        &self,
        session_dir: &Path,
        env_file: &Path,
        name: &str,
        login: &[(String, Secret)],
        ambient: I,
    ) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("run");
        // `--flag=value`, like every other value this adapter passes: `TMPDIR`
        // decides this path and nothing here may assume it does not start with
        // `-`. See `flag_value`.
        flag_value(&mut command, "--env-file", env_file);
        // Required: the vendor's masking would otherwise replace the value in
        // the probe's own output, and this adapter would inject the mask token.
        command.arg("--no-masking");
        // Before the two variables below are set, so a caller who exported one
        // of them holding a `pass://` string cannot have it removed again.
        remove_ambient_references(&mut command, ambient);
        // Passed rather than inherited: the ambient session is a different
        // identity with a different set of vaults. See `session_dir`.
        self.scope(&mut command, session_dir, login, self.reason.for_name(name));
        command.arg("--");
        command.arg(&self.probe_binary);
        command.arg(PROBE_VAR);
        command
    }

    /// Build one `pass-cli item list --vault-name … --output json` invocation.
    ///
    /// Deliberately the same shape as [`ProtonStore::probe_command`], including
    /// the ambient filter and the two exported variables:
    ///
    /// - The **session directory** decides which identity enumerates the vault.
    ///   A listing read as the full account would find items the scoped agent
    ///   cannot read, so the failure would move from "no such item" to a
    ///   confusing denial at the value read.
    /// - The **reason** is not required by `item list` — measured 2026-08-08,
    ///   the verb succeeds with the variable unset and with it empty — but the
    ///   read is part of resolving one name and is recorded under the same
    ///   sentence, which is what makes an audit trail answer "which run was
    ///   this?". It carries no argument value, exactly as [`Reason`] describes.
    /// - The **ambient filter** applies for the same reason it does on the
    ///   probe: `pass-cli` resolves `pass://` strings it finds in the
    ///   environment, and an unrelated one costs a read nobody asked for.
    ///
    /// No value can come back from this verb: it prints ids, titles, states and
    /// timestamps. `--show-secrets` is what would print content, it is refused
    /// for agent sessions, and it is not passed here.
    fn list_command<I>(
        &self,
        session_dir: &Path,
        vault: &str,
        name: &str,
        login: &[(String, Secret)],
        ambient: I,
    ) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("item");
        command.arg("list");
        // `--vault-name=<vault>` as one argument. Naming the flag is what stops
        // the vault being taken as the wrong positional; joining the value with
        // `=` is what stops a vault whose name starts with `-` being read as a
        // flag. Passing them as two arguments does only the first, and the
        // vendor refuses it — see `flag_value`.
        flag_value(&mut command, "--vault-name", vault);
        command.arg("--output");
        command.arg("json");
        remove_ambient_references(&mut command, ambient);
        self.scope(&mut command, session_dir, login, self.reason.for_name(name));
        command
    }

    /// One vault's items, from the cache or from the CLI.
    ///
    /// # Two locks, and why neither one is the other
    ///
    /// A run resolves its names CONCURRENTLY — see [`crate::cmd::run`], where
    /// doing it in turn made N unresolvable names cost N deadlines. So "check,
    /// then fetch, then insert" is a race that costs one vendor CLI spawn per
    /// racing name, which is precisely the cost this cache exists to remove.
    ///
    /// The **map** lock is therefore held only long enough to hand out a vault's
    /// slot, so a lookup in a different vault is never serialised behind this
    /// one. The **slot** lock is held across the spawn on purpose: it is the
    /// thing that makes "one listing per vault per run" true rather than
    /// probable, and every thread waiting on it wants the answer that spawn is
    /// about to produce.
    ///
    /// A failed fetch leaves the slot empty, so a later name retries rather than
    /// inheriting a failure it did not cause.
    ///
    /// # Why the entry expires
    ///
    /// An entry is only reused while it is younger than
    /// [`crate::config::ProtonConfig::listing_ttl_ms`]. A cache with no expiry
    /// is a cache that can only be right about the moment it was filled, and
    /// what it is asked about later includes **whether an item is in the trash**
    /// — a question this adapter can answer only from a listing, because the
    /// vendor resolves a trashed item's reference without complaint. Kept
    /// forever, the entry does not merely go stale: it silently switches off the
    /// one rule standing between a deleted credential and a child's environment,
    /// for as long as whatever holds this adapter stays alive.
    ///
    /// A `keyless run` cannot reach the expiry — it resolves its names in one
    /// burst and exits — so the memoisation this cache exists for is untouched;
    /// see `several_names_from_one_vault_cost_exactly_one_listing`.
    ///
    /// An expired entry is replaced only by a fetch that succeeded. A refresh
    /// that fails returns the failure, which degrades the lookup, rather than
    /// falling back to the stale answer it was sent to replace.
    fn cached_items(
        &self,
        session_dir: &Path,
        vault: &str,
        name: &str,
    ) -> Result<Arc<Vec<ItemRecord>>, StoreError> {
        let slot = Arc::clone(self.cache().entry(vault.to_owned()).or_default());
        let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(cached) = slot.as_ref()
            && cached.at.elapsed() < self.listing_ttl
        {
            return Ok(Arc::clone(&cached.items));
        }
        let fetched = Arc::new(self.fetch_items(session_dir, vault, name)?);
        *slot = Some(Listed {
            items: Arc::clone(&fetched),
            at: Instant::now(),
        });
        Ok(fetched)
    }

    /// The listing cache, surviving a poisoned lock.
    ///
    /// A panic elsewhere cannot corrupt this map's meaning — it holds what the
    /// vendor said about a vault, with no invariant spanning two entries — so
    /// refusing to serve from it after an unrelated panic would degrade a run
    /// for no safety gain.
    fn cache(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, VaultSlot>> {
        self.listings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run the listing and parse it.
    fn fetch_items(
        &self,
        session_dir: &Path,
        vault: &str,
        name: &str,
    ) -> Result<Vec<ItemRecord>, StoreError> {
        let captured = capture(
            self.list_command(
                session_dir,
                vault,
                name,
                &self.vendor_login()?,
                std::env::vars_os(),
            ),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            // The vendor names the vault it could not find, which is a name
            // rather than a credential, so quoting its first line is safe and is
            // the only way "I typed the vault wrong" is distinguishable from "my
            // token expired".
            return Err(self.backend(format!(
                "cannot list vault `{vault}`: {}",
                summarise(&captured.stderr)
            )));
        }

        serde_json::from_slice::<ItemListing>(&captured.stdout)
            .map(|listing| listing.items)
            .map_err(|error| {
                self.backend(format!(
                    "`item list` for vault `{vault}` did not parse: {error}"
                ))
            })
    }

    /// Turn a stable address into a reference this session can resolve.
    ///
    /// Everything named in an error here is a coordinate — a vault name, an item
    /// title, an item id. None of them is a value, and the listing this reads
    /// cannot carry one.
    fn reference_for(
        &self,
        session_dir: &Path,
        name: &str,
        address: &ItemAddress,
    ) -> Result<String, StoreError> {
        let items = self.cached_items(session_dir, &address.vault, name)?;

        match match_title(&items, &address.item) {
            Matched::One(only) => Ok(format!(
                "{REFERENCE_SCHEME}{}/{}/{}",
                only.share_id, only.id, address.field
            )),
            Matched::None => Err(self.backend(format!(
                "vault `{}` holds no item titled `{}`",
                address.vault, address.item
            ))),
            Matched::OnlyTrashed => Err(self.backend(format!(
                "the only item titled `{}` in vault `{}` is in the trash; \
                 restore it, or point `{name}` at a live item",
                address.item, address.vault
            ))),
            Matched::Several(several) => Err(self.backend(format!(
                "{} live items in vault `{}` are titled `{}`, so `{name}` names no one item; \
                 pin one with \"reference\": \"pass://<share id>/<item id>/{}\" — candidates: {}",
                several.len(),
                address.vault,
                address.item,
                address.field,
                several
                    .iter()
                    .map(|record| record.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// Build one `pass-cli vault list --output json` invocation.
    ///
    /// Same shape as the other two: the session directory decides which identity
    /// answers, the reason is recorded, and an ambient `pass://` is removed. The
    /// verb prints vault names, ids and counts — no item content of any kind.
    fn vault_list_command<I>(
        &self,
        session_dir: &Path,
        login: &[(String, Secret)],
        ambient: I,
    ) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("vault");
        command.arg("list");
        command.arg("--output");
        command.arg("json");
        remove_ambient_references(&mut command, ambient);
        self.scope(
            &mut command,
            session_dir,
            login,
            self.reason.for_action("listing", "vaults"),
        );
        command
    }

    /// Build one `pass-cli item view --output json` invocation.
    ///
    /// # This is the one verb in the whole crate that prints a value
    ///
    /// It is here because it is the only way to learn an item's field NAMES, and
    /// the alternative — guessing them — costs one vault read and one permanent
    /// off-machine audit entry per guess. The value comes back on stdout, is
    /// captured into a buffer that zeroizes on drop, is parsed into
    /// [`ItemView`] which zeroizes on drop, and only field names built from key
    /// positions leave that type. Nothing on this path writes to this process's
    /// stdout, and no error message here is built from stdout.
    ///
    /// Addressed by `--item-id` rather than by title: the id comes from a listing
    /// this adapter just read, so `fields` and `run` are looking at the same item
    /// even if two share a title.
    ///
    /// Both ids are joined to their flags with `=`. Item and share ids are
    /// base64url, so about one in 64 begins with `-`, and passed as a separate
    /// argument the vendor's parser reads it as a short-flag cluster and refuses
    /// the whole command. See [`flag_value`].
    fn view_command<I>(
        &self,
        session_dir: &Path,
        item: &ItemRecord,
        login: &[(String, Secret)],
        ambient: I,
    ) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("item");
        command.arg("view");
        flag_value(&mut command, "--share-id", &item.share_id);
        flag_value(&mut command, "--item-id", &item.id);
        command.arg("--output");
        command.arg("json");
        remove_ambient_references(&mut command, ambient);
        self.scope(
            &mut command,
            session_dir,
            login,
            self.reason
                .for_action("inspecting the fields of", &item.title),
        );
        command
    }

    /// Every vault this identity can see.
    fn vaults(&self, session_dir: &Path) -> Result<Vec<String>, StoreError> {
        let captured = capture(
            self.vault_list_command(session_dir, &self.vendor_login()?, std::env::vars_os()),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            return Err(self.backend(format!(
                "cannot list vaults: {}",
                summarise(&captured.stderr)
            )));
        }

        serde_json::from_slice::<VaultListing>(&captured.stdout)
            .map(|listing| listing.vaults.into_iter().map(|v| v.name).collect())
            .map_err(|error| self.backend(format!("`vault list` did not parse: {error}")))
    }

    fn unavailable(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Unavailable {
            store: Store::id(self).to_owned(),
            detail: detail.into(),
        }
    }

    fn backend(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Backend {
            store: Store::id(self).to_owned(),
            detail: detail.into(),
        }
    }

    fn unreachable(&self, error: &CaptureError) -> StoreError {
        exec::unavailable(Store::id(self), &self.binary, error)
    }
}

impl Store for ProtonStore {
    fn id(&self) -> &str {
        STORE_ID
    }

    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        // Checked before the name's own reference, and before anything is
        // spawned or written. Without it there is no identity to read as, so
        // every name fails for this one reason and the systemic fault is what
        // the operator should see first.
        let session_dir = self.session_dir()?;

        let Some(address) = self.routing.route(name) else {
            // Deliberately an error rather than `Ok(None)`. "I was asked for a
            // name I have no address for" is a config mistake with a specific
            // fix, and reporting it as a plain absence would leave the user
            // hunting in the vault for an item that was never named.
            //
            // Two configs reach this line — an entry with no address, and no
            // entry at all — and this adapter cannot tell them apart, because
            // both arrive as a name that is missing from `addresses`. So the
            // fix names the FILE rather than an entry: told to add three fields
            // "to its config entry", the reader of the second config goes
            // looking for an entry that was never written.
            return Err(self.backend(format!(
                "no Proton address declared for `{name}`; \
                 give it \"vault\", \"item\" and \"field\" under \"secrets\""
            )));
        };

        // Resolved every time, never stored: a share id belongs to one session.
        let reference = match address {
            Address::Reference(reference) => reference.clone(),
            Address::Named(address) => self.reference_for(session_dir, name, address)?,
            Address::Unusable(detail) => return Err(self.backend(detail.clone())),
        };
        let reference = reference.as_str();

        let directory = std::env::temp_dir();
        let env_file = TempEnvFile::create(&directory, reference).map_err(|source| {
            self.unavailable(format!("cannot write a probe env file: {source}"))
        })?;

        let mut captured = capture(
            self.probe_command(
                session_dir,
                &env_file.path,
                name,
                &self.vendor_login()?,
                std::env::vars_os(),
            ),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            return Err(self.backend(summarise(&captured.stderr)));
        }

        let mut bytes = std::mem::take(&mut captured.stdout);
        strip_one_newline(&mut bytes);

        if bytes.is_empty() {
            return Err(self.backend(format!("`{reference}` resolved to an empty value")));
        }

        if looks_concealed(&bytes) {
            // `--no-masking` did not take effect. Injecting the mask token
            // would hand the child a string that is not the credential and
            // looks like one, which fails later and somewhere else.
            return Err(self.backend(
                "the value came back concealed; `--no-masking` was not honoured".to_owned(),
            ));
        }

        Secret::from_bytes(bytes)
            .map(Some)
            .ok_or_else(|| self.backend(format!("`{reference}` is not valid UTF-8")))
    }

    /// Local preconditions, then one round trip that proves the session is alive.
    ///
    /// # Why this asks the vendor something
    ///
    /// It used to check the session DIRECTORY and the binary and stop, on the
    /// reasoning that reachability and authentication "can be observed for free
    /// at the first real lookup, which degrades". Measured on 2026-08-08, that
    /// reasoning produces the exact failure this whole tool exists to kill:
    /// with the agent session expired, `doctor` printed `store proton ok` and
    /// `0 problem(s)` while EVERY Proton name was degrading, and the child ran
    /// with an empty bearer and came back HTTP 400 at exit 0.
    ///
    /// The premise was wrong in one word: **free**. A degraded lookup is only
    /// observable to somebody already reading stderr of a run that is failing
    /// for a reason they do not yet know. `doctor` is the command they are told
    /// to run to find that reason out, and `keyless run` never refuses, so a
    /// dead session has no other alarm anywhere on the machine. A health check
    /// that cannot see the single most common way this backend dies is not a
    /// cheaper check, it is a check of something else.
    ///
    /// One directory away, [`crate::store::infisical`] already pays this cost
    /// and documents why. This is that idiom, not a second one.
    ///
    /// # What the round trip costs, and what bounds it
    ///
    /// `vault list` prints vault names, ids and counts — no item content of any
    /// kind — so no credential is read and no item's audit trail gains an entry
    /// for a read nobody asked for. It is the same verb `keyless items` already
    /// spends when no vault is named.
    ///
    /// It cannot hang and it cannot prompt: [`capture`] gives the child
    /// `/dev/null` on stdin, so a vendor that decided to ask for a password gets
    /// end-of-file instead, and the configured timeout plus the output cap bound
    /// it either way.
    ///
    /// # Why a failure is a PROBLEM and not a third state
    ///
    /// Because it is one. A session this call cannot use is a session no lookup
    /// can use, so every Proton name in the config will degrade. Saying so is
    /// `doctor`'s whole job, and it stays inside `doctor`'s contract: a problem
    /// here degrades a run, it never blocks one. Nothing in `run` consults this.
    fn health(&self) -> Result<(), StoreError> {
        // Local facts first, so the message names the closest cause. Both are
        // preconditions of the round trip below: with no session directory there
        // is no identity to ask as, and with no binary there is nothing to ask.
        let session_dir = self.session_dir()?;

        if resolve_executable(&self.binary).is_none() {
            return Err(self.unavailable(format!(
                "`{}` is not on PATH or is not executable",
                self.binary.display()
            )));
        }

        let captured = capture(
            self.vault_list_command(session_dir, &self.vendor_login()?, std::env::vars_os()),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if captured.status.success() {
            // Deliberately no forensics on the success path. An orphan temp file
            // beside a session that ANSWERED is debris, not a fault, and a health
            // check that reports a problem on a working store is how a health
            // check gets ignored.
            return Ok(());
        }

        // stderr only, as everywhere else in this adapter, and with the fix
        // attached: the vendor says what is wrong, not what to do about it.
        let vendor = summarise(&captured.stderr);

        // Asked only once the round trip has already failed, so a working store
        // never pays for it and a passing report never depends on it.
        if let Some(write) = interrupted_write(session_dir) {
            return Err(self.unavailable(interrupted_write_detail(session_dir, &write, &vendor)));
        }

        Err(self.unavailable(format!(
            "the session at {} cannot be used: {vendor}; re-mint it with `{}` \
             (or re-issue the agent token) and check `stores.proton.session_dir`",
            session_dir.display(),
            login_into(session_dir)
        )))
    }
}

impl Discover for ProtonStore {
    fn id(&self) -> &str {
        Store::id(self)
    }

    fn items(&self, vault: Option<&str>) -> Result<Vec<ItemSummary>, StoreError> {
        let session_dir = self.session_dir()?;

        // One named vault, or every vault this identity can see. Enumerating all
        // of them is one extra spawn plus one per vault, which is the honest cost
        // of not making the caller already know the answer.
        let vaults = match vault {
            Some(one) => vec![one.to_owned()],
            None => self.vaults(session_dir)?,
        };

        let mut summaries = Vec::new();
        for name in vaults {
            let items = self.cached_items(session_dir, &name, &name)?;
            summaries.extend(items.iter().map(|record| ItemSummary {
                vault: name.clone(),
                title: record.title.clone(),
                // Verbatim, including `Trashed`: somebody hunting a name that
                // stopped resolving has to be able to see that the item exists
                // and is in the bin. The allowlist on `Active` guards resolution,
                // not visibility.
                state: record.state.clone(),
                kind: if record.item_type.is_empty() {
                    "unknown".to_owned()
                } else {
                    record.item_type.clone()
                },
            }));
        }
        Ok(summaries)
    }

    fn fields(&self, vault: Option<&str>, item: &str) -> Result<Vec<FieldSummary>, StoreError> {
        let session_dir = self.session_dir()?;
        // Required rather than searched for. Scanning every vault for a title
        // would read vaults nobody asked about, and each read is recorded
        // off-machine and permanently.
        let Some(vault) = vault else {
            return Err(self.backend(
                "name the vault as well: an item title is only unique within one vault, and \
                 searching every vault would read vaults nobody asked about"
                    .to_owned(),
            ));
        };

        let items = self.cached_items(session_dir, vault, item)?;
        let record = match match_title(&items, item) {
            Matched::One(only) => only,
            Matched::None => {
                return Err(self.backend(format!(
                    "vault `{vault}` holds no item titled `{item}`; `{} items --store proton \
                     --vault {vault}` lists the titles it does hold",
                    crate::NAME
                )));
            }
            // Said out loud rather than answered anyway. A trashed item's fields
            // are readable, and reporting them as though the item were usable
            // would send the reader back to a config entry that can never
            // resolve — the resolver refuses a trashed item on purpose.
            Matched::OnlyTrashed => {
                return Err(self.backend(format!(
                    "the only item titled `{item}` in vault `{vault}` is in the trash, so no \
                     config entry can resolve against it; restore it first"
                )));
            }
            Matched::Several(several) => {
                return Err(self.backend(format!(
                    "{} live items in vault `{vault}` are titled `{item}`, so this names no one \
                     item — candidates: {}",
                    several.len(),
                    several
                        .iter()
                        .map(|record| record.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        };

        let captured = capture(
            self.view_command(
                session_dir,
                record,
                &self.vendor_login()?,
                std::env::vars_os(),
            ),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            // stderr only, as everywhere else in this crate. `item view` puts the
            // item's contents on stdout, so a message built from stdout would be
            // the leak this verb exists to avoid.
            return Err(self.backend(format!(
                "cannot inspect `{item}`: {}",
                summarise(&captured.stderr)
            )));
        }

        // From here to the end of this function the plaintext is in this process.
        // `captured` scrubs its stdout on drop, `view` scrubs every string in the
        // parsed tree on drop, and the only thing that outlives either is a list
        // of names built from key positions.
        let view = ItemView::parse(&captured.stdout).map_err(|detail| self.backend(detail))?;
        let names = view.field_names();

        if names.is_empty() {
            return Err(self.backend(format!(
                "`{item}` reported no fields this build recognises; its shape may have changed"
            )));
        }
        Ok(names)
    }
}

/// Whether the bytes look like the vendor's concealment placeholder.
fn looks_concealed(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes)
        .to_ascii_lowercase()
        .contains(CONCEALED_MARKER)
}

/// Find `binary` as an executable file, following `PATH` for a bare name.
///
/// Written here rather than taken as a dependency: it is a dozen lines, and the
/// alternative is a crate in the trusted path of a secrets tool.
pub(crate) fn resolve_executable(binary: &Path) -> Option<PathBuf> {
    if binary.components().count() > 1 {
        return is_executable(binary).then(|| binary.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Address, ItemAddress, ItemListing, ItemRecord, ItemView, PROBE_VAR, ProtonStore,
        REASON_MAX, REASON_VAR, Reason, SESSION_DIR_VAR, TempEnvFile, looks_concealed,
        resolve_executable,
    };
    use crate::config::Config;
    use crate::store::Store;
    use crate::store::discover::Discover;
    use std::ffi::{OsStr, OsString};
    use std::path::Path;
    use std::time::Duration;

    /// The session directory these tests pretend was configured.
    ///
    /// A literal rather than a constant read out of the source: a test that
    /// asserts the adapter exports whatever the adapter decided to export
    /// proves nothing. This string is an independent statement of what the
    /// config asked for.
    const SCOPED: &str = "/tmp/keyless-tests-scoped-session";

    fn store_from(json: &str) -> ProtonStore {
        let config: Config = serde_json::from_str(json).expect("valid config");
        ProtonStore::from_config(&config, Reason::default())
    }

    /// The `secrets` block both hosts project, written once.
    ///
    /// Four entries on purpose: the reference form, the name form, an entry
    /// that says nothing about Proton at all, and a half-written one. The last
    /// two are the ones the two projections could disagree about — whether an
    /// entry is absent or merely unusable decides which sentence a lookup
    /// reports, and a daemon that disagreed with a session about that would
    /// tell an operator to fix the wrong file.
    const SHARED_SECRETS: &str = r#"{
        "BY_REFERENCE": { "reference": "pass://share/item/password" },
        "BY_NAME":      { "vault": "company", "item": "decoy", "field": "password" },
        "NOT_PROTON":   { "store": "keychain" },
        "HALF_WRITTEN": { "vault": "company" }
    }"#;

    #[test]
    fn a_daemon_projects_a_name_onto_the_address_a_session_projects_it_onto() {
        // The two hosts of this adapter read two different config types. What
        // must not differ is which name has an address and which address it is:
        // a daemon that resolved a name the session refuses, or refused one it
        // resolves, would be a second answer to a question with one answer.
        //
        // Each side is compared against a WRITTEN-OUT address rather than
        // against the other. Comparing the two projections to each other is
        // satisfied by any change that moves both — including deleting the
        // rule that decides what an address is.
        let config: Config = serde_json::from_str(&format!(
            r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}"}}}},"secrets":{SHARED_SECRETS}}}"#
        ))
        .expect("valid config");
        let secrets: std::collections::BTreeMap<String, crate::config::SecretRoute> =
            serde_json::from_str(SHARED_SECRETS).expect("valid secrets");

        let session = super::Routing::from_config(&config);
        let daemon = super::Routing::from_secrets(&secrets);

        let expected: [(&str, Option<Address>); 4] = [
            (
                "BY_REFERENCE",
                Some(Address::Reference("pass://share/item/password".to_owned())),
            ),
            (
                "BY_NAME",
                Some(Address::Named(ItemAddress {
                    vault: "company".to_owned(),
                    item: "decoy".to_owned(),
                    field: "password".to_owned(),
                })),
            ),
            // An entry that says nothing about Proton is ABSENT, not unusable:
            // the two have different remedies and a lookup reports different
            // sentences for them.
            ("NOT_PROTON", None),
            ("A_NAME_NOBODY_EVER_DECLARED", None),
        ];

        for (name, want) in &expected {
            assert_eq!(session.route(name), want.as_ref(), "session, `{name}`");
            assert_eq!(daemon.route(name), want.as_ref(), "daemon, `{name}`");
        }

        // The half-written one carries a sentence rather than a coordinate, so
        // the variant is what is pinned — on each side separately.
        assert!(matches!(
            session.route("HALF_WRITTEN"),
            Some(Address::Unusable(_))
        ));
        assert!(matches!(
            daemon.route("HALF_WRITTEN"),
            Some(Address::Unusable(_))
        ));
        assert_eq!(session.declared(), 3);
        assert_eq!(daemon.declared(), 3);
    }

    #[test]
    fn a_store_built_from_parts_carries_no_session_directory_until_it_is_given_one() {
        // `new` is the daemon's constructor, and the one default it must not
        // have is a session directory: inheriting the ambient one resolves
        // every name against an identity nobody chose, which is the failure
        // mode that looks exactly like success. See `session_dir`.
        let secrets: std::collections::BTreeMap<String, crate::config::SecretRoute> =
            serde_json::from_str(SHARED_SECRETS).expect("valid secrets");
        let store = ProtonStore::new(
            std::path::PathBuf::from("/nonexistent/pass-cli"),
            std::path::PathBuf::from("/usr/bin/printenv"),
            super::Routing::from_secrets(&secrets),
            Reason::default(),
        );

        let error = store
            .resolve("BY_NAME")
            .expect_err("a store with no session directory must degrade");
        assert!(
            error.to_string().contains("session_dir"),
            "the fault named is not the missing session directory: {error}"
        );

        // And once it is given one, the same store reaches the address rather
        // than the precondition above — the control that keeps the assertion
        // from passing for any reason at all.
        let pointed = store.in_session_dir(Some(std::path::PathBuf::from(SCOPED)));
        let error = pointed
            .resolve("A_NAME_NOBODY_EVER_DECLARED")
            .expect_err("an undeclared name must not resolve");
        assert!(
            error.to_string().contains("no Proton address declared"),
            "{error}"
        );
    }

    /// An ambient environment written out by hand.
    ///
    /// Independent of anything the implementation reads: it is a statement of
    /// what a caller's shell might hold, not a copy of this process's own
    /// environment, and it goes through the real `probe_command` so the
    /// filtering is tested where it is wired rather than where it is defined.
    fn ambient() -> Vec<(OsString, OsString)> {
        [
            ("PLAIN", "not-a-reference"),
            ("A_REFERENCE", "pass://share/item/password"),
            ("EMBEDDED", "prefix pass://share/item/password suffix"),
            ("LOOKALIKE", "passx://share/item/password"),
            ("EMPTY", ""),
        ]
        .into_iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect()
    }

    fn command_for(store: &ProtonStore, name: &str) -> std::process::Command {
        store.probe_command(
            Path::new(SCOPED),
            Path::new("/tmp/probe.env"),
            name,
            &[],
            ambient(),
        )
    }

    fn argv(store: &ProtonStore, name: &str) -> Vec<String> {
        let command = command_for(store, name);
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .map(std::borrow::Cow::into_owned)
            .collect()
    }

    /// The value the child would see for `key`, as the adapter set it.
    fn child_env(store: &ProtonStore, name: &str, key: &str) -> Option<String> {
        command_for(store, name)
            .get_envs()
            .find(|(k, _)| *k == OsStr::new(key))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
    }

    #[test]
    fn the_invocation_uses_run_and_never_the_verb_that_prints_a_value() {
        // `pass-cli item view --field` writes plaintext to stdout. Same rule as
        // Infisical's denied verbs: this adapter must not become the way there.
        let store = store_from(r#"{"secrets":{"X":{"reference":"pass://V/I/F"}}}"#);
        let argv = argv(&store, "X");
        assert_eq!(argv.get(1).map(String::as_str), Some("run"));
        for forbidden in ["item", "view", "--field", "show", "get"] {
            assert!(
                !argv.iter().any(|arg| arg == forbidden),
                "`{forbidden}` appeared in {argv:?}"
            );
        }
    }

    #[test]
    fn masking_is_disabled_for_the_probe_only() {
        // Without this the probe reads `<concealed by Proton Pass>` and injects
        // it as though it were the credential.
        let store = store_from("{}");
        assert!(argv(&store, "X").iter().any(|arg| arg == "--no-masking"));
    }

    #[test]
    fn a_concealed_value_is_refused_rather_than_injected() {
        assert!(looks_concealed(b"<concealed by Proton Pass>"));
        assert!(looks_concealed(b"<CONCEALED BY PROTON PASS>"));
        assert!(!looks_concealed(b"decoy-a-perfectly-ordinary-value"));
    }

    #[test]
    fn a_reason_is_set_on_every_read() {
        let store = store_from("{}");
        let reason =
            child_env(&store, "DECOY", REASON_VAR).expect("every read must carry a reason");
        assert!(!reason.is_empty(), "an empty reason is refused by the API");
        assert!(reason.contains("DECOY"));
    }

    #[test]
    fn every_read_names_the_session_directory_it_runs_under() {
        // The bug this replaces: with nothing exported, `pass-cli` falls back
        // to its shared per-user session. Measured 2026-08-08, that session was
        // the full account and saw two vaults where the scoped agent saw one —
        // so the scoping was bypassed while every name still resolved.
        let store = store_from("{}");
        assert_eq!(
            child_env(&store, "X", SESSION_DIR_VAR).as_deref(),
            Some(SCOPED),
            "the child would inherit whichever identity `pass-cli` was last logged into"
        );
    }

    #[test]
    fn an_ambient_reference_is_taken_out_of_the_probes_environment() {
        // Measured 2026-08-08: `pass-cli run` resolves every `pass://` in the
        // inherited environment, so one unrelated variable made the probe read
        // a second item from the vault — recorded off-machine, permanently —
        // and failed the whole lookup when that item did not resolve.
        //
        // Built through `probe_command`, not by calling the filter directly.
        // The direct call was the first version of this test, and deleting the
        // call site left it green — a test of a function nothing has to use.
        let store = store_from("{}");
        // `get_envs` yields `None` as the value for a removal.
        let removed: Vec<String> = command_for(&store, "X")
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();

        assert!(removed.contains(&"A_REFERENCE".to_owned()), "{removed:?}");
        assert!(
            removed.contains(&"EMBEDDED".to_owned()),
            "a reference inside a longer value is still resolved by the CLI: {removed:?}"
        );
        for kept in ["PLAIN", "LOOKALIKE", "EMPTY"] {
            assert!(
                !removed.contains(&kept.to_owned()),
                "`{kept}` was dropped from the probe's environment: {removed:?}"
            );
        }
    }

    #[test]
    fn a_store_with_no_session_directory_degrades_and_says_how_to_fix_it() {
        // Not a refusal to run: `resolve` returning `Unavailable` is exactly
        // what an unreachable backend returns, and `run` spawns the child on
        // both. See `never_block.rs` for the property itself.
        let store = store_from(r#"{"secrets":{"X":{"reference":"pass://S/I/F"}}}"#);
        let error = store
            .resolve("X")
            .expect_err("an unscoped lookup must not reach the ambient session");
        let message = error.to_string();
        assert!(message.contains("session_dir"), "{message}");
        assert!(
            store.health().is_err(),
            "`doctor` must say it before a run does"
        );
    }

    #[test]
    fn a_configured_session_directory_is_taken_verbatim_and_stops_the_complaint() {
        // The negative control for the two tests above: without it, both could
        // pass on a store that can never be configured at all.
        //
        // The binary is deliberately absent, so the remaining health failure is
        // about the binary. That is what proves the session complaint stopped
        // rather than merely being outranked by it.
        let store = store_from(
            r#"{"stores":{"proton":{"session_dir":"/tmp/kl-agent",
                                    "binary":"/nonexistent/keyless-test/pass-cli"}}}"#,
        );
        assert_eq!(
            store.session_dir().expect("configured"),
            Path::new("/tmp/kl-agent")
        );
        let message = store
            .health()
            .expect_err("the binary is absent")
            .to_string();
        assert!(
            !message.contains("session_dir"),
            "a configured session was still reported as missing: {message}"
        );
    }

    #[test]
    fn a_read_never_uses_the_manager_identity_even_when_one_is_configured() {
        // The reader/manager split, from the reader's side. `ProtonStore` must not
        // read the `manager` block at all: the tempting mistake is a "helpful"
        // fallback that prefers the manager when one is present, or falls back to
        // it when the reader's directory is missing. Either turns every one of ~20
        // sessions into an editor, silently, because a session that can write also
        // resolves every name successfully.
        let store = store_from(
            r#"{"stores":{"proton":{"session_dir":"/tmp/keyless-reader",
                                    "manager":{"session_dir":"/tmp/keyless-manager"}}}}"#,
        );
        assert_eq!(
            store.session_dir().expect("the reader is configured"),
            Path::new("/tmp/keyless-reader"),
            "a read resolved as the manager identity"
        );

        // And with no reader configured, the manager is NOT borrowed to stand in
        // for it: the lookup degrades and says to set `session_dir`.
        let manager_only: crate::config::Config = serde_json::from_str(
            r#"{"stores":{"proton":{"manager":{"session_dir":"/tmp/keyless-manager"}}}}"#,
        )
        .expect("valid config");
        let store = ProtonStore::from_config(&manager_only, Reason::default());
        let message = store
            .session_dir()
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(message.contains("session_dir"), "{message}");
        assert!(
            !message.contains("keyless-manager"),
            "the manager's directory was used as a reader fallback: {message}"
        );
    }

    #[test]
    fn the_reason_names_the_command_but_carries_no_argument_value() {
        // An argument vector is where every shape this tool exists to remove
        // ends up. The reason is assembled before anything has resolved, so
        // there is nothing to redact it with, and it is then sent to a vendor
        // and kept. An argument value must never be in it — this is the test
        // that says so.
        let leaked = "decoy-Zx91-would-be-a-leak-0042";
        let argv: Vec<OsString> = ["/usr/local/bin/psql", "--dbname", leaked]
            .iter()
            .map(OsString::from)
            .collect();
        let reason = Reason::for_run(&argv).for_name("DATABASE_URL");

        assert!(!reason.contains(leaked), "the reason leaked an argument");
        assert!(!reason.contains("--dbname"));
        assert!(reason.contains("psql"), "the reason must still be useful");
        assert!(reason.contains("2 args"));
        assert!(reason.contains("DATABASE_URL"));
    }

    #[test]
    fn a_reason_is_never_empty_and_never_over_the_cap() {
        // The cap is the vendor's; an over-long reason is rejected, and a
        // rejected read is a degraded run for a reason that is entirely ours.
        let long_name = "N".repeat(REASON_MAX * 2);
        let reason = Reason::default().for_name(&long_name);
        assert!(reason.len() <= REASON_MAX, "length was {}", reason.len());
        assert!(!reason.trim().is_empty());

        // A multi-byte name must not be cut mid-character.
        let wide = "é".repeat(REASON_MAX);
        let reason = Reason::default().for_name(&wide);
        assert!(reason.len() <= REASON_MAX);
        assert!(std::str::from_utf8(reason.as_bytes()).is_ok());

        // An empty argv still produces something.
        assert!(!Reason::for_run(&[]).for_name("X").trim().is_empty());
    }

    #[test]
    fn a_name_with_no_proton_address_says_what_to_add() {
        let store = store_from(&format!(
            r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}"}}}},"secrets":{{"X":{{}}}}}}"#
        ));
        let error = store
            .resolve("X")
            .expect_err("a Proton name needs an address");
        let message = error.to_string();
        for part in ["vault", "item", "field"] {
            assert!(message.contains(part), "{message}");
        }
    }

    // -----------------------------------------------------------------------
    // The name form: what the config may say, and what it may not.
    // -----------------------------------------------------------------------

    /// A store whose config declares `X` with `extra`, scoped and un-runnable.
    ///
    /// The binary does not exist, so any test below that reaches a spawn fails
    /// loudly instead of quietly asserting on the wrong error.
    fn store_with_route(extra: &str) -> ProtonStore {
        store_from(&format!(
            r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}",
                                       "binary":"/nonexistent/keyless-test/pass-cli"}}}},
                "secrets":{{"X":{{{extra}}}}}}}"#
        ))
    }

    #[test]
    fn declaring_both_an_address_and_a_reference_is_refused_rather_than_ranked() {
        // Two answers to one question. Picking whichever this build happens to
        // prefer is how the wrong item gets read with nothing said — the same
        // failure `Policy::Explicit` refuses for two backends and one name.
        let store = store_with_route(
            r#""reference":"pass://S/I/password","vault":"personal","item":"decoy","field":"password""#,
        );
        let message = store
            .resolve("X")
            .expect_err("a doubly-declared address must not resolve")
            .to_string();
        assert!(message.contains("reference"), "{message}");
        assert!(message.contains("vault"), "{message}");
    }

    #[test]
    fn a_half_written_name_form_names_every_part_that_is_missing() {
        // None of the three is inferable, so a partial entry is a refusal with
        // a list rather than a guess. An empty string counts as missing.
        let store = store_with_route(r#""vault":"personal","field":"""#);
        let message = store
            .resolve("X")
            .expect_err("an incomplete address must not resolve")
            .to_string();
        assert!(message.contains("item"), "{message}");
        assert!(message.contains("field"), "{message}");
        assert!(
            !message.contains("vault,"),
            "the part that WAS given was reported missing: {message}"
        );
    }

    #[test]
    fn a_field_containing_a_slash_is_refused_before_it_becomes_an_address() {
        // `pass://SHARE/ITEM/a/b` moves the boundary: the CLI would be handed a
        // different address than the one written down, and it would look fine.
        let store = store_with_route(r#""vault":"personal","item":"decoy","field":"a/b""#);
        let message = store
            .resolve("X")
            .expect_err("a field with a separator in it must not resolve")
            .to_string();
        assert!(message.contains('/'), "{message}");
        assert!(message.contains("field"), "{message}");
    }

    #[test]
    fn a_complete_name_form_is_an_address_and_a_reference_is_taken_verbatim() {
        // The negative control for the three refusals above: without it they
        // could all pass on a parser that accepts nothing at all.
        let named: crate::config::SecretRoute =
            serde_json::from_str(r#"{"vault":"personal","item":"decoy alpha","field":"password"}"#)
                .expect("valid route");
        assert_eq!(
            Address::from_route(&named),
            Some(Address::Named(ItemAddress {
                vault: "personal".to_owned(),
                item: "decoy alpha".to_owned(),
                field: "password".to_owned(),
            }))
        );

        let referenced: crate::config::SecretRoute =
            serde_json::from_str(r#"{"reference":"pass://S/I/password"}"#).expect("valid route");
        assert_eq!(
            Address::from_route(&referenced),
            Some(Address::Reference("pass://S/I/password".to_owned()))
        );

        let silent: crate::config::SecretRoute =
            serde_json::from_str(r#"{"account":"demo-token"}"#).expect("valid route");
        assert_eq!(Address::from_route(&silent), None);
    }

    // -----------------------------------------------------------------------
    // The listing that turns a name into this session's ids.
    // -----------------------------------------------------------------------

    fn list_argv(store: &ProtonStore, vault: &str) -> Vec<String> {
        let command = store.list_command(Path::new(SCOPED), vault, "X", &[], ambient());
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .map(std::borrow::Cow::into_owned)
            .collect()
    }

    #[test]
    fn the_listing_asks_one_vault_for_json_and_never_asks_for_content() {
        // `--show-secrets` is the flag that would make this verb print values.
        // It is refused for agent sessions, and it is never passed here either
        // way: this adapter reads coordinates, and the value comes back through
        // `run` where it never touches stdout.
        let store = store_from("{}");
        let argv = list_argv(&store, "personal");
        assert_eq!(argv.get(1).map(String::as_str), Some("item"));
        assert_eq!(argv.get(2).map(String::as_str), Some("list"));
        assert!(argv.iter().any(|arg| arg == "--output"));
        assert!(argv.iter().any(|arg| arg == "json"));
        // Named AND joined. Naming the flag stops the vault being taken as a
        // positional; joining it with `=` stops a vault whose name starts with
        // `-` being read as a short-flag cluster. Two separate arguments do only
        // the first, and the vendor refuses that outright.
        assert!(
            argv.iter().any(|arg| arg == "--vault-name=personal"),
            "{argv:?}"
        );
        assert!(
            !argv.iter().any(|arg| arg == "--vault-name"),
            "the flag and its value were passed as two arguments: {argv:?}"
        );
        for forbidden in ["--show-secrets", "view", "--field", "run"] {
            assert!(
                !argv.iter().any(|arg| arg == forbidden),
                "`{forbidden}` appeared in {argv:?}"
            );
        }
    }

    #[test]
    fn the_listing_runs_under_the_configured_session_and_carries_a_reason() {
        // A listing read as the full account would enumerate items the scoped
        // agent cannot read, so "no such item" would turn into a denial at the
        // value read — the same failure the session pin exists to prevent, one
        // step earlier.
        let store = store_from("{}");
        let command = store.list_command(Path::new(SCOPED), "personal", "DECOY", &[], ambient());
        let env: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();

        let session = env.iter().find(|(key, _)| key == SESSION_DIR_VAR);
        assert_eq!(
            session.and_then(|(_, value)| value.as_deref()),
            Some(SCOPED)
        );

        let reason = env
            .iter()
            .find(|(key, _)| key == REASON_VAR)
            .and_then(|(_, value)| value.clone())
            .expect("the listing must carry a reason of the same shape");
        assert!(reason.contains("DECOY"), "{reason}");
        assert!(!reason.trim().is_empty());
    }

    #[test]
    fn an_ambient_reference_is_taken_out_of_the_listings_environment_too() {
        // Built through `list_command`, not by calling the filter: the probe's
        // version of this test went green once after its call site was deleted,
        // because it exercised the function rather than the command builder.
        let store = store_from("{}");
        let removed: Vec<String> = store
            .list_command(Path::new(SCOPED), "personal", "X", &[], ambient())
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        assert!(removed.contains(&"A_REFERENCE".to_owned()), "{removed:?}");
        assert!(removed.contains(&"EMBEDDED".to_owned()), "{removed:?}");
        assert!(!removed.contains(&"PLAIN".to_owned()), "{removed:?}");
    }

    #[test]
    fn a_trashed_item_is_not_active_and_an_unknown_state_is_not_either() {
        // An allowlist, not a denylist: a state this build has never seen must
        // fail closed, because the alternative is injecting a value whose owner
        // believes it is gone.
        let record = |state: &str| ItemRecord {
            id: "id".to_owned(),
            share_id: "share".to_owned(),
            state: state.to_owned(),
            title: "keyless-decoy-alpha".to_owned(),
            item_type: "login".to_owned(),
        };
        assert!(record("Active").is_active());
        assert!(record("active").is_active());
        assert!(!record("Trashed").is_active());
        assert!(!record("PendingDeletion").is_active());
        assert!(!record("").is_active());
    }

    #[test]
    fn a_listing_ttl_is_clamped_so_no_config_can_switch_the_expiry_off() {
        // The trash rule above is only ever consulted against a listing, so a
        // `listing_ttl_ms` big enough to outlive any process would delete that
        // rule by arithmetic. Zero is the other end and is honest: list again
        // every time.
        assert_eq!(super::bounded_listing_ttl(0), Duration::ZERO);
        assert_eq!(
            super::bounded_listing_ttl(1_500),
            Duration::from_millis(1500)
        );
        assert_eq!(
            super::bounded_listing_ttl(super::MAX_LISTING_TTL_MS),
            Duration::from_millis(super::MAX_LISTING_TTL_MS)
        );
        assert_eq!(
            super::bounded_listing_ttl(u64::MAX),
            Duration::from_millis(super::MAX_LISTING_TTL_MS),
            "a config named a number large enough to mean `never`"
        );
    }

    #[test]
    fn the_default_config_gives_the_listing_cache_a_bounded_ttl() {
        // The default is what every run and every future long-lived holder gets
        // without asking, so it is the value that has to be bounded — not just
        // the clamp that catches an operator naming a silly one.
        let ttl = super::bounded_listing_ttl(crate::config::ProtonConfig::default().listing_ttl_ms);
        assert!(ttl > Duration::ZERO, "the default lists again every lookup");
        assert!(
            ttl <= Duration::from_millis(super::MAX_LISTING_TTL_MS),
            "the default is not bounded: {ttl:?}"
        );
    }

    #[test]
    fn a_listing_record_reads_the_item_id_from_id_and_not_from_item_id() {
        // Measured 2026-08-08: the record has `id`, `share_id`, `vault_id`,
        // `state`, `flags`, `create_time`, `modify_time`, `title`, `item_type`.
        // There is no `item_id`, so a reference built from one would be empty.
        let listing: ItemListing = serde_json::from_str(
            r#"{"items":[{"id":"ITEM1","share_id":"SHARE1","vault_id":"V","state":"Active",
                          "flags":[],"create_time":"2000-01-01T00:00:00",
                          "modify_time":"2000-01-01T00:00:01","title":"decoy",
                          "item_type":"login"}]}"#,
        )
        .expect("the vendor's shape must parse");
        assert_eq!(listing.items.len(), 1);
        assert_eq!(listing.items[0].id, "ITEM1");
        assert_eq!(listing.items[0].share_id, "SHARE1");
        assert!(listing.items[0].is_active());
    }

    // -----------------------------------------------------------------------
    // `fields`: the one path in this crate where a value enters the process.
    // -----------------------------------------------------------------------

    /// The value that must never appear in `fields` output.
    ///
    /// Distinctive enough that a grep for it in a failure message means a real
    /// leak, and placed in every value position the measured shape has.
    const VIEW_LEAK: &str = "decoy-Vw44-must-never-be-printed-0303";

    /// `item view --output json` for a CUSTOM item, as measured against
    /// `pass-cli` 2.2.5 on 2026-08-08.
    ///
    /// Written out by hand rather than generated from this adapter's own idea of
    /// the shape: a fixture built from the parser would agree with the parser
    /// whatever either became. The important detail is that this is **not** the
    /// `--get-template` shape — the label is `name`, not `field_name`, and the
    /// value sits inside a single-key object whose key is the field's type.
    fn custom_item_view() -> String {
        format!(
            r#"{{"item":{{"id":"ITEM1","share_id":"SHARE1","state":"Active","revision":3,
                "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
                "content":{{"item_uuid":"UUID1","title":"demo api key",
                  "note":"{VIEW_LEAK}",
                  "extra_fields":[
                    {{"name":"first hidden field","content":{{"Hidden":"{VIEW_LEAK}"}}}},
                    {{"name":"second hidden field","content":{{"Hidden":"{VIEW_LEAK}"}}}},
                    {{"name":"expires","content":{{"Timestamp":"1730000000"}}}},
                    {{"name":"comment","content":{{"Text":"{VIEW_LEAK}"}}}}
                  ]}}}}}}"#
        )
    }

    /// The `--get-template` shape, which a write builds and a future CLI might
    /// also return from `item view`.
    fn template_shape_view() -> String {
        format!(
            r#"{{"title":"decoy","note":"","sections":[{{"section_name":"keyless",
                "fields":[{{"field_name":"api key","field_type":"hidden",
                            "value":"{VIEW_LEAK}"}}]}}]}}"#
        )
    }

    #[test]
    fn the_measured_view_shape_yields_the_field_labels_a_config_entry_needs() {
        // The acceptance case: a custom item whose field name is not guessable
        // from anything else, reported by name.
        let view = ItemView::parse(custom_item_view().as_bytes()).expect("the shape must parse");
        let names: Vec<String> = view
            .field_names()
            .into_iter()
            .map(|field| field.name)
            .collect();
        assert!(
            names.contains(&"first hidden field".to_owned()),
            "{names:?}"
        );
        assert!(
            names.contains(&"second hidden field".to_owned()),
            "{names:?}"
        );
        assert!(names.contains(&"expires".to_owned()), "{names:?}");

        // And the sibling keys of the value are NOT reported as fields: `Hidden`
        // is the field's type, and `content` is where the credential lives.
        for structural in ["Hidden", "content", "item_uuid"] {
            assert!(
                !names.contains(&structural.to_owned()),
                "`{structural}` is structure, not a field: {names:?}"
            );
        }
    }

    #[test]
    fn no_extracted_field_name_is_ever_a_value() {
        // The whole security property of this verb, on both shapes. `item view`
        // prints the values and there is no vendor flag to stop it, so the only
        // thing between the credential and stdout is this extraction.
        for shape in [custom_item_view(), template_shape_view()] {
            let view = ItemView::parse(shape.as_bytes()).expect("parse");
            for field in view.field_names() {
                assert!(
                    !field.name.contains("decoy-Vw44"),
                    "a value reached the field list as `{}`",
                    field.name
                );
                assert!(!field.path.contains("decoy-Vw44"), "{}", field.path);
                assert!(
                    !field
                        .value_type
                        .as_deref()
                        .is_some_and(|named| named.contains("decoy-Vw44")),
                    "a value reached the type column"
                );
            }
        }
    }

    #[test]
    fn the_type_column_comes_from_a_key_and_names_the_field_type() {
        let view = ItemView::parse(custom_item_view().as_bytes()).expect("parse");
        let typed: Vec<(String, Option<String>)> = view
            .field_names()
            .into_iter()
            .map(|field| (field.name, field.value_type))
            .collect();
        assert!(
            typed.contains(&("first hidden field".to_owned(), Some("Hidden".to_owned()))),
            "{typed:?}"
        );
        // Worth reporting because a config entry pointed at this one resolves and
        // hands the child a timestamp.
        assert!(
            typed.contains(&("expires".to_owned(), Some("Timestamp".to_owned()))),
            "{typed:?}"
        );
    }

    #[test]
    fn the_template_shape_is_read_as_well_as_the_view_shape() {
        // The two shapes disagree about the label key, and the template's is the
        // only one readable without printing a credential — so it is the tempting
        // thing to build against, and building against it alone would report
        // nothing at all for a real item.
        let view = ItemView::parse(template_shape_view().as_bytes()).expect("parse");
        let names: Vec<String> = view
            .field_names()
            .into_iter()
            .map(|field| field.name)
            .collect();
        assert!(names.contains(&"api key".to_owned()), "{names:?}");
        assert!(!names.contains(&"value".to_owned()), "{names:?}");
    }

    #[test]
    fn a_descriptor_shaped_object_outside_an_array_degrades_rather_than_hiding_the_item() {
        // The view's own top-level `item` carries a `content` key. Without the
        // "must be an array element" condition, an `item` that ever gained a
        // `name` would be read as one field descriptor and every real field would
        // silently vanish. This asserts the fallback: keys, not nothing.
        let shape = r#"{"item":{"name":"looks like a label","content":{"title":"t",
                        "note":"n","extra_fields":[]}}}"#;
        let view = ItemView::parse(shape.as_bytes()).expect("parse");
        let names: Vec<String> = view
            .field_names()
            .into_iter()
            .map(|field| field.name)
            .collect();
        assert!(names.contains(&"title".to_owned()), "{names:?}");
        assert!(names.contains(&"note".to_owned()), "{names:?}");
        assert!(
            !names.contains(&"looks like a label".to_owned()),
            "an object outside an array was read as a field descriptor: {names:?}"
        );
    }

    #[test]
    fn an_item_view_debug_never_prints_the_item() {
        let view = ItemView::parse(custom_item_view().as_bytes()).expect("parse");
        let rendered = format!("{view:?}");
        assert_eq!(rendered, "ItemView(<redacted>)");
        assert!(!rendered.contains("decoy-Vw44"));
    }

    #[test]
    fn scrubbing_a_parsed_item_leaves_no_string_behind() {
        // `Drop` does this. Asserted on a tree held open, because the whole point
        // is that the plaintext does not survive the function that parsed it.
        let mut parsed: serde_json::Value =
            serde_json::from_str(&custom_item_view()).expect("parse");
        super::scrub(&mut parsed);
        let rendered = serde_json::to_string(&parsed).expect("re-encode");
        assert!(
            !rendered.contains("decoy-Vw44"),
            "a value survived the scrub: {rendered}"
        );
        // Keys are names and are deliberately left alone — they are the thing
        // being reported.
        assert!(rendered.contains("extra_fields"), "{rendered}");
    }

    #[test]
    fn the_view_invocation_addresses_one_item_by_id_and_asks_for_json() {
        let store = store_from("{}");
        let record = ItemRecord {
            id: "ITEM1".to_owned(),
            share_id: "SHARE1".to_owned(),
            state: "Active".to_owned(),
            title: "demo api key".to_owned(),
            item_type: "custom".to_owned(),
        };
        let command = store.view_command(Path::new(SCOPED), &record, &[], ambient());
        let argv: Vec<String> = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .map(std::borrow::Cow::into_owned)
            .collect();

        assert_eq!(argv.get(1).map(String::as_str), Some("item"));
        assert_eq!(argv.get(2).map(String::as_str), Some("view"));
        // By id, not by title: the id came from a listing this adapter just read,
        // so `fields` and `run` are looking at the same item even if two share a
        // title. Joined to its flag, because an id may begin with `-`.
        assert!(argv.iter().any(|arg| arg == "--item-id=ITEM1"), "{argv:?}");
        assert!(
            argv.iter().any(|arg| arg == "--share-id=SHARE1"),
            "{argv:?}"
        );
        for split in ["--item-id", "--share-id"] {
            assert!(
                !argv.iter().any(|arg| arg == split),
                "`{split}` and its value were passed as two arguments: {argv:?}"
            );
        }
        assert!(argv.iter().any(|arg| arg == "json"));

        // Same two variables as every other Proton call.
        let env: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            env.iter()
                .find(|(key, _)| key == SESSION_DIR_VAR)
                .and_then(|(_, value)| value.as_deref()),
            Some(SCOPED)
        );
        let reason = env
            .iter()
            .find(|(key, _)| key == REASON_VAR)
            .and_then(|(_, value)| value.clone())
            .expect("a reason");
        assert!(reason.contains("demo api key"), "{reason}");

        // And the ambient filter, wired here rather than merely defined.
        let removed: Vec<String> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        assert!(removed.contains(&"A_REFERENCE".to_owned()), "{removed:?}");
    }

    #[test]
    fn no_coordinate_ever_arrives_as_a_short_flag_cluster() {
        // The rule is the vendor's parser's, stated once and applied to every
        // invocation this adapter builds: clap reads a standalone argument that
        // begins with ONE `-` as a cluster of short flags, whatever option came
        // before it, and refuses the command with exit 2.
        //
        // Written as a property over the whole argument vector rather than as a
        // list of the flags this file happens to pass. A list would be the same
        // list twice — add a flag and it leaves the test in the same stroke.
        //
        // The values below are the shape that actually broke: Proton ids are
        // base64url, whose alphabet includes `-`, so an id can begin with one.
        // They are invented — the property under test is the leading `-`, and
        // nothing here needs a coordinate from anybody's real vault.
        fn no_cluster(argv: &[String], what: &str) {
            for arg in &argv[1..] {
                // A lone `-` is exempt: it is the vendor's own spelling for
                // stdin, and clap reads it as a value rather than as flags.
                let cluster = arg.starts_with('-') && !arg.starts_with("--") && arg != "-";
                assert!(
                    !cluster,
                    "{what} passed `{arg}`, which the vendor reads as short flags: {argv:?}"
                );
            }
        }

        let store = store_from("{}");

        let listing = list_argv(&store, "-dashvault");
        assert!(
            listing.iter().any(|arg| arg == "--vault-name=-dashvault"),
            "{listing:?}"
        );
        no_cluster(&listing, "`item list`");

        let record = ItemRecord {
            id: "-Kx7Qm2Za".to_owned(),
            share_id: "-Sh4r3".to_owned(),
            state: "Active".to_owned(),
            title: "demo.service".to_owned(),
            item_type: "custom".to_owned(),
        };
        let command = store.view_command(Path::new(SCOPED), &record, &[], ambient());
        let view: Vec<String> = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .map(std::borrow::Cow::into_owned)
            .collect();
        assert!(
            view.iter().any(|arg| arg == "--item-id=-Kx7Qm2Za"),
            "{view:?}"
        );
        assert!(
            view.iter().any(|arg| arg == "--share-id=-Sh4r3"),
            "{view:?}"
        );
        no_cluster(&view, "`item view`");

        // The negative control for the helper itself: it has to be able to fail.
        // Without this, `no_cluster` could be vacuous — a loop that never trips
        // reads exactly like a loop that cannot.
        let broken = vec![
            "pass-cli".to_owned(),
            "--item-id".to_owned(),
            "-Kx7Qm2Za".to_owned(),
        ];
        assert!(
            std::panic::catch_unwind(|| no_cluster(&broken, "the control")).is_err(),
            "the check passed an argument vector the vendor refuses"
        );
    }

    #[test]
    fn fields_needs_a_vault_and_says_so() {
        let store = store_from(&format!(
            r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}"}}}}}}"#
        ));
        let message = Discover::fields(&store, None, "anything")
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(message.contains("name the vault"), "{message}");
    }

    #[test]
    fn the_env_file_holds_a_reference_and_is_removed_afterwards() {
        let directory = std::env::temp_dir();
        let path;
        {
            let file = TempEnvFile::create(&directory, "pass://Personal/Router/password")
                .expect("the probe file must be writable");
            path = file.path.clone();
            let body = std::fs::read_to_string(&path).expect("readable");
            assert_eq!(
                body,
                format!("{PROBE_VAR}=pass://Personal/Router/password\n")
            );

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
                assert_eq!(
                    mode & 0o777,
                    0o600,
                    "the probe file must not be readable by others"
                );
            }
        }
        assert!(!path.exists(), "the probe file outlived its lookup");
    }

    #[test]
    fn a_missing_binary_is_unhealthy_rather_than_a_panic() {
        // `session_dir` is set in both, so the failure under test is the binary
        // rather than the session complaint that now precedes it.
        for binary in [
            "/nonexistent/keyless-test/pass-cli",
            "keyless-not-a-real-binary-anywhere",
        ] {
            let store = store_from(&format!(
                r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}","binary":"{binary}"}}}}}}"#
            ));
            let message = store
                .health()
                .expect_err("an absent binary is unhealthy")
                .to_string();
            assert!(message.contains(binary), "{message}");
        }
    }

    #[test]
    fn an_executable_on_path_is_found_and_a_directory_is_not() {
        assert!(resolve_executable(Path::new("/bin/sh")).is_some());
        assert!(resolve_executable(Path::new("/bin")).is_none());
        assert!(resolve_executable(Path::new("sh")).is_some());
    }
}
