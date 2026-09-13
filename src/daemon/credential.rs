//! The daemon's own vendor login: the file it lives in, and who may read it.
//!
//! # This file is the boundary, not a copy of it
//!
//! Everywhere else in this crate, a file mode is a defence in depth behind a
//! uid boundary. Here it IS the boundary. The daemon holds a long-lived
//! Infisical machine identity so that it can renew its own access token
//! forever and never ask a human — see
//! [`crate::store::infisical::VendorCredentials`] for why the alternative is
//! worse — and the whole cost of that choice is a credential sitting on a disk.
//!
//! What keeps that cost bounded is exactly two facts about one file: its mode
//! is `0600`, and its owner is the daemon. Either one wrong and every session
//! on the machine can read the credential that unlocks the vault, which is the
//! hole this project exists to close. So neither is assumed: [`inspect`] reads
//! both back off the filesystem and reports each fault in its own words,
//! because "the file is there" is the reassuring half of a sentence whose other
//! half is the one that matters.
//!
//! It reads what is IN the file too, and that is not a third boundary check —
//! it is the difference between a row about the file and a row about the login.
//! An empty file and a file holding a machine identity have the same mode and
//! the same owner, so a report built from those two alone says the same thing
//! about both, and the empty one is what every install starts with.
//!
//! # Why ownership is compared against the audit log
//!
//! Nothing in `keylessd.json` says which uid the daemon runs as — the launchd
//! plist says that, and this process does not read the plist. What the config
//! does name is the audit log, which the installer creates owned by the daemon
//! and which the daemon itself writes to on every request. Its owner is
//! therefore the daemon's uid on any machine where the daemon has ever run, and
//! it needs no new config key that could disagree with the plist.
//!
//! When there is no audit log to compare against, the owner is REPORTED and no
//! verdict is given. A guess would be worse than a gap: "owned by the right
//! user" is precisely the claim that must not be made without evidence.
//!
//! **The writer answers out of that same file, and this is one sentence rather
//! than two mechanisms.** [`store_entry`] takes the daemon's owner from its
//! caller, resolved by [`daemon_owner`] — so a file this module creates is
//! given to the uid [`inspect`] will later judge it against, and the two cannot
//! disagree about what "the daemon" means. It matters only where the file does
//! not exist yet: where one does, its own owner is preserved and nothing else
//! is consulted. And the reading side's refusal holds on the writing side too
//! — no audit log resolves, nothing is inferred, and the file keeps the uid
//! that wrote it for [`inspect`] to report.
//!
//! # Writing it
//!
//! [`store_entry`] is the only writer, and it takes a [`Secret`] rather than a
//! string, has no way to accept a value from an argument, and prints nothing.
//! The value reaches it from stdin — echoed nowhere, in no shell history and in
//! no process table — which is the same discipline `keyless put` follows and
//! the reason neither verb has a `--value` flag.
//!
//! What it does NOT take from an argument is who the file belongs to on the
//! path where it is created from nothing. Both writing verbs are typed with
//! `sudo`, so the uid running them is root and the daemon's is not; a file that
//! kept the writer's uid there would be a `0600` credential under `root:wheel`
//! inside a directory the daemon owns — which the daemon itself reads in
//! process and every other reader running as its uid is refused, including the
//! repair tooling somebody reaches for once the store is already degraded.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zeroize::Zeroize;

use crate::secret::Secret;
use crate::store::file::Contents;
use crate::store::proton;

/// The only mode this file may have.
///
/// Stricter than [`crate::store::file::FileStore`]'s rule, which forbids the
/// group and other bits and is indifferent to the rest. Here the exact mode is
/// asserted because there is exactly one program that writes this file and it
/// writes `0600`; anything else arrived by hand, and a hand that set `0640`
/// meant something by it.
pub const MODE: u32 = 0o600;

/// What could not be done to the credential file, in words an operator can act on.
#[derive(Debug)]
pub enum CredentialError {
    /// The path is unusable, or the write failed part way.
    Io { path: PathBuf, detail: String },
    /// The arrangement is refused rather than merely broken.
    Refused(String),
}

impl std::fmt::Display for CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialError::Io { path, detail } => write!(f, "{}: {detail}", path.display()),
            CredentialError::Refused(detail) => f.write_str(detail),
        }
    }
}

fn io_error(path: &Path, detail: impl Into<String>) -> CredentialError {
    CredentialError::Io {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

/// The uid the daemon runs as, read off a file only the daemon writes.
///
/// `None` when that file is not there yet, which is honest rather than
/// convenient: see the module header.
#[must_use]
pub fn daemon_uid(audit: &Path) -> Option<u32> {
    daemon_owner(audit).map(|owner| owner.uid)
}

/// The uid AND gid the daemon runs as, read off the same file.
///
/// One function rather than two, because the two facts have to come from the
/// same `stat` of the same file: a login that dropped to one file's uid and
/// another file's gid would create a session store under a pair no install ever
/// chose. [`daemon_uid`] is the narrow view of this, for the report that only
/// judges ownership.
#[must_use]
pub fn daemon_owner(audit: &Path) -> Option<super::login::Owner> {
    fs::metadata(audit).ok().map(|meta| super::login::Owner {
        uid: meta.uid(),
        gid: meta.gid(),
    })
}

/// What `keylessd check` says about the credential file.
///
/// `Ok` carries the detail of a sound file; `Err` carries the one fault found,
/// named specifically enough to fix. The faults are reported one at a time and
/// in this order — missing, then exposed, then misowned, then what is in it —
/// because each later one is only meaningful once the earlier one holds.
///
/// # Why the contents are read and not just the mode
///
/// The mode and the owner are the boundary, and they are the same on a file
/// holding a machine identity as on the empty one the installer leaves. A row
/// built from those two alone therefore said `ok` over a credential file with
/// nothing in it — which is the state every install starts in, and the state a
/// re-run used to put a working install back into. "The file is there, shut,
/// and the daemon's" is the reassuring half of a sentence whose other half is
/// whether there is a login in it.
///
/// # When the contents cannot be read
///
/// This runs as whoever typed `keylessd check`, and the file is `0600` under
/// the daemon's uid inside a `0700` directory — so an operator running it
/// unprivileged cannot open it, and cannot `stat` it either. That is the
/// boundary working, not a fault, and it is why the checks in the README are
/// written with `sudo`. Read as anybody else, the row reports what it could
/// establish and says the contents went unread, rather than counting zero
/// entries in a file it never opened.
///
/// # Errors
///
/// The sentence describing the fault. There is no error value here that means
/// "something is wrong": every one of them names which thing.
pub fn inspect(path: &Path, daemon: Option<u32>) -> Result<String, String> {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(format!(
                "{} does not exist, so every lookup through the store it belongs to will \
                 degrade. The installer creates it empty and owned by the daemon; \
                 `{} credential --store <store> --name <entry>` fills it without the value \
                 passing through a command line",
                path.display(),
                crate::DAEMON_NAME
            ));
        }
        Err(error) => {
            return Err(format!("{} cannot be read: {error}", path.display()));
        }
    };

    let mode = meta.permissions().mode() & 0o7777;
    if mode != MODE {
        return Err(format!(
            "{} is mode {mode:04o} and must be {MODE:04o}. This file holds a long-lived \
             credential and its mode IS the boundary — at anything wider, every session \
             on this machine can read the login that unlocks the vault. Run: chmod 0600 {}",
            path.display(),
            path.display()
        ));
    }

    let owner = meta.uid();
    if let Some(expected) = daemon
        && owner != expected
    {
        return Err(format!(
            "{} is mode {MODE:04o} and owned by uid {owner}, but the daemon runs as uid \
             {expected} — so the daemon cannot read its own login and every lookup through \
             that store will degrade. Run: chown {expected} {}",
            path.display(),
            path.display()
        ));
    }

    let held = entries_in(path)?;

    match daemon {
        Some(expected) => Ok(format!(
            "{held}, mode {MODE:04o}, owner uid {expected} — {}",
            path.display()
        )),
        // Reported, not judged. See the module header.
        None => Ok(format!(
            "{held}, mode {MODE:04o}, owner uid {owner}, unverified — there is no audit log \
             yet to read the daemon's own uid from, so nothing here has checked that {owner} \
             is it — {}",
            path.display()
        )),
    }
}

/// How many entries the credential file holds, in words, or why it holds none
/// that can be used.
///
/// # Errors
///
/// The empty file and the unparseable one, told apart. They are the two states
/// that used to render identically — as `ok` — and they have opposite remedies:
/// one wants the value put in, the other wants the file taken away first,
/// because [`store_entry`] refuses to rewrite a file it cannot parse rather
/// than lose what somebody put in it by hand.
fn entries_in(path: &Path) -> Result<String, String> {
    let mut bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            // The boundary, working. Said plainly rather than counted as zero.
            return Ok(format!(
                "contents unread — this process cannot open it, which is what {MODE:04o} \
                 under another uid means; run `sudo {} check` to have the entries counted",
                crate::DAEMON_NAME
            ));
        }
        Err(error) => return Err(format!("{} cannot be read: {error}", path.display())),
    };
    let contents = crate::store::file::classify(&bytes);
    bytes.zeroize();

    match contents {
        Contents::Empty => Err(format!(
            "{0} is mode {MODE:04o} and the daemon's, and it is EMPTY — no login has been \
             put in it, so every lookup through that store will degrade. That is the state a \
             fresh install leaves; fill it with `{1} credential --name <entry>`, or with \
             `{1} login --store <vendor>` where the vendor keeps a session. Neither takes a \
             value on a command line",
            path.display(),
            crate::DAEMON_NAME
        )),
        Contents::Malformed { line, column } => Err(format!(
            "{} is mode {MODE:04o} and the daemon's, and it is not a JSON object of name to \
             value (line {line}, column {column}) — so nothing can be read out of it and \
             every lookup through that store will degrade. `{} credential` will not rewrite it, \
             because that would lose whatever is in it; move it aside and write the entries \
             again",
            path.display(),
            crate::DAEMON_NAME
        )),
        Contents::Entries(mut entries) => {
            let held = entries.len();
            for value in entries.values_mut() {
                value.zeroize();
            }
            Ok(match held {
                1 => "1 entry".to_owned(),
                other => format!("{other} entries"),
            })
        }
    }
}

/// The `identity` rows `keylessd check` prints, and whether they are sound.
///
/// Nothing at all when no vendor login is declared: a report that said
/// "identity absent" on every install without Infisical would train an operator
/// to read past the row on the one install where it matters.
///
/// Two rows rather than one, because they answer different questions and an
/// operator acts on them differently. This one is about the FILE — is it there,
/// is it shut, is it the daemon's. Whether the tenant accepts what is in it is
/// the `store infisical` row, and a reader who conflates the two chases a
/// credential problem in the filesystem or a filesystem problem at the vendor.
///
/// # Errors
///
/// Whatever `out` returns.
pub fn report(config: &super::config::DaemonConfig, out: &mut dyn io::Write) -> io::Result<bool> {
    let mut sound = true;
    for login in vendor_logins(config) {
        if !login.in_use {
            sound &= orphaned(&login, out)?;
            continue;
        }
        match inspect(&login.path, daemon_uid(config.audit.as_path())) {
            Ok(detail) => writeln!(out, "identity ok {detail}")?,
            Err(detail) => {
                writeln!(out, "identity PROBLEM {detail}")?;
                sound = false;
            }
        }
        writeln!(
            out,
            "         whether {} accepts it is the `store {}` row below",
            login.vendor, login.store
        )?;
    }
    sound &= proton_token(config, out)?;
    Ok(sound)
}

/// How close to the agent token's expiry `keyless run` starts saying so on
/// every request the daemon serves.
///
/// Tighter than [`EXPIRY_WARNING_DAYS`] on purpose. That window is for
/// `keylessd check`, whose only reader is a person who chose to run it and may
/// not run it again for weeks. This one reaches whoever is running commands
/// right now, so it opens closer to the deadline rather than further from it —
/// wide enough to still act on, narrow enough that it says something has to
/// happen soon rather than becoming background noise on every invocation for a
/// month.
const RUN_EXPIRY_WARNING_DAYS: i64 = 14;

/// The stderr line `keyless run` should carry on every request while the
/// Proton agent token is inside its warning window — `None` outside it, and
/// `None` when no date was ever declared.
///
/// Reads only the date an operator wrote into `stores.proton.token_expires`;
/// the token's own value never passes through here.
#[must_use]
pub(crate) fn run_expiry_advisory(token_expires: Option<&str>) -> Option<String> {
    let date = token_expires?;
    let days = crate::time::days_until_utc(date).ok()?;
    if days > RUN_EXPIRY_WARNING_DAYS {
        return None;
    }
    if days < 0 {
        Some(format!(
            "the Proton agent token EXPIRED on {date}, {} day(s) ago; every Proton name is \
             degrading",
            -days
        ))
    } else {
        Some(format!(
            "the Proton agent token expires on {date}, in {days} day(s)"
        ))
    }
}

#[cfg(test)]
mod run_expiry_advisory_tests {
    use super::run_expiry_advisory;

    #[test]
    fn no_date_says_nothing() {
        assert_eq!(run_expiry_advisory(None), None);
    }

    #[test]
    fn a_date_far_out_says_nothing() {
        assert_eq!(run_expiry_advisory(Some("2099-01-01")), None);
    }

    #[test]
    fn inside_the_window_says_so() {
        let soon = in_days(RUN_EXPIRY_DAYS_UNDER_TEST);
        let said = run_expiry_advisory(Some(&soon)).expect("inside the window");
        assert!(said.contains(&soon), "{said}");
        assert!(said.contains("expires"), "{said}");
    }

    #[test]
    fn an_expired_date_says_so() {
        let gone = in_days(-3);
        let said = run_expiry_advisory(Some(&gone)).expect("expired is inside the window");
        assert!(said.contains("EXPIRED"), "{said}");
    }

    #[test]
    fn an_unparseable_date_says_nothing_rather_than_guessing() {
        assert_eq!(run_expiry_advisory(Some("not-a-date")), None);
    }

    /// A day count safely inside the window, used so the fixture below has one
    /// number to change if the window ever does.
    const RUN_EXPIRY_DAYS_UNDER_TEST: i64 = super::RUN_EXPIRY_WARNING_DAYS - 1;

    /// `YYYY-MM-DD` for `offset` days from today, built the same way
    /// [`crate::time`]'s own tests build a fixed date.
    fn in_days(offset: i64) -> String {
        let millis = crate::time::now_unix_millis() as i64 + offset * 86_400_000;
        crate::time::rfc3339_utc(millis as u128)[..10].to_owned()
    }
}

/// How many days before an agent token stops working that `check` starts
/// saying so.
///
/// Wide on purpose. This is not a deadline, it is the window in which somebody
/// can mint a replacement without an outage in it — and the only reader is a
/// person who happens to run `check`, who may not run it again for weeks.
const EXPIRY_WARNING_DAYS: i64 = 30;

/// The two `token` rows `keylessd check` prints about a Proton agent token.
///
/// Nothing at all unless the Proton store is enabled and names a credential,
/// for the reason [`report`] gives about rows nobody needs.
///
/// # Why these are rows of their own and not part of `identity`
///
/// `identity` answers "is the file there, is it shut, is it the daemon's" —
/// three facts about a FILE that are identical for every vendor. These two are
/// about what is IN it, and they are the two states that pass every file check
/// and still cannot log anything in:
///
/// - **Malformed.** A value that is not shaped like a token — a token's name,
///   an agent id, a line copied around one. See [`proton::classify_token`].
/// - **Expiring, or expired.** The state Infisical never had. A machine
///   identity renews itself; an agent token simply stops, at an hour nobody
///   chose, with nobody at the daemon to read the failure. And it cannot be
///   discovered by asking: the vendor's refusal is one sentence covering an
///   expired token, a revoked one and a mistyped one alike, so the date has to
///   have been written down beforehand or it is not knowable at all.
///
/// The fifth state — **refused by the vendor** — is deliberately NOT here. It
/// is the `store proton` row's, because it is the only one of the five that
/// takes a round trip to establish, and a file-shaped row claiming it would be
/// claiming something it never asked.
///
/// # Errors
///
/// Whatever `out` returns.
fn proton_token(config: &super::config::DaemonConfig, out: &mut dyn io::Write) -> io::Result<bool> {
    let settings = &config.stores.proton;
    if !settings.enabled || settings.credentials.is_empty() {
        return Ok(true);
    }

    let mut sound = true;

    match token_shape(settings.credentials_file.as_path(), &settings.credentials) {
        Shape::Sound(detail) => writeln!(out, "token    ok {detail}")?,
        // Not `ok`. The `identity` row above has already reported why the file
        // could not be read, and a second red row for one fault teaches a
        // reader that two problems can mean one problem — but `ok` beside a
        // thing nothing looked at is the exact false green this report exists
        // to remove. `unproven` is what the report already says elsewhere for
        // a question nobody could ask.
        Shape::Unread(detail) => writeln!(out, "token    unproven {detail}")?,
        Shape::Wrong(detail) => {
            writeln!(out, "token    PROBLEM {detail}")?;
            sound = false;
        }
    }

    match settings.token_expires.as_deref() {
        // Reported, not judged. A date nobody wrote down is a check that could
        // not be made, and a check that could not be made must not read as one
        // that passed — the same rule the owner row above follows.
        None => writeln!(
            out,
            "token    unproven `stores.proton.token_expires` names no date, so nothing here \
             knows when this token stops. The vendor cannot be asked: its refusal reads the \
             same for an expired token, a revoked one and a wrong one, so the first symptom \
             would be every Proton name degrading at an hour nobody chose"
        )?,
        Some(date) => match crate::time::days_until_utc(date) {
            Err(detail) => {
                writeln!(
                    out,
                    "token    PROBLEM `stores.proton.token_expires` cannot be read: {detail}"
                )?;
                sound = false;
            }
            Ok(days) if days < 0 => {
                writeln!(
                    out,
                    "token    PROBLEM the agent token EXPIRED on {date}, {} day(s) ago. Every \
                     Proton name is degrading now. Mint a fresh token, then run `{} login \
                     --store {} --replace`, which logs the dead session out, logs the new \
                     token in and records it — in that order, so nothing is written until \
                     the account has taken it",
                    -days,
                    crate::DAEMON_NAME,
                    proton::STORE_ID
                )?;
                sound = false;
            }
            Ok(days) if days <= EXPIRY_WARNING_DAYS => {
                writeln!(
                    out,
                    "token    PROBLEM the agent token expires on {date}, in {days} day(s). \
                     Nothing renews it and nothing will be awake when it stops — replace it \
                     while somebody is reading this"
                )?;
                sound = false;
            }
            Ok(days) => writeln!(out, "token    ok expires {date}, in {days} day(s)")?,
        },
    }

    Ok(sound)
}

/// What could be established about the value in the credential file.
///
/// Three outcomes, not two, and the third is the point: a question that could
/// not be asked must not render as one that passed. See [`token_shape`].
enum Shape {
    /// It is shaped like an agent token.
    Sound(String),
    /// Nothing was read. Either the boundary refused this process, or the
    /// `identity` row above has already said what is wrong with the file.
    Unread(String),
    /// It was read and it is not a token.
    Wrong(String),
}

/// Whether what is in the credential file is shaped like an agent token.
///
/// Reads the value and reports only structure — see
/// [`proton::classify_token`], which is where the rules and the vendor's own
/// wording live. Nothing here ever renders any part of it.
///
/// # Why the mode is checked here as well as in `inspect`
///
/// Not to report it twice — [`Shape::Unread`] deliberately defers to the
/// `identity` row for that. It is because this function opens the file with
/// [`fs::read`] rather than through [`crate::store::file::FileStore`], which
/// would refuse a file anybody else can read. Without the check, `check` would
/// read a credential file at a mode the daemon itself refuses, and report `ok`
/// on the contents of a file no lookup can use.
fn token_shape(path: &Path, declared: &BTreeMap<String, String>) -> Shape {
    let Some(entry) = declared.get(proton::TOKEN_VAR) else {
        return Shape::Wrong(format!(
            "`stores.proton.credentials` names no `{}`, so the daemon has no token to \
             re-establish its session with",
            proton::TOKEN_VAR
        ));
    };

    let deferred = || {
        Shape::Unread(format!(
            "the value in {} was not read — see the `identity` row above, which says why",
            path.display()
        ))
    };

    match fs::metadata(path) {
        Ok(meta) if meta.permissions().mode() & 0o7777 != MODE => return deferred(),
        Ok(_) => {}
        Err(_) => return deferred(),
    }

    let mut bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            // The boundary, working. Said plainly rather than counted as a
            // fault: this is what an operator running `check` unprivileged
            // gets, and it is the arrangement they were asked to create.
            return Shape::Unread(format!(
                "this process cannot open {}, which is what {MODE:04o} under another uid \
                 means; run `sudo {} check` to have the shape checked",
                path.display(),
                crate::DAEMON_NAME
            ));
        }
        Err(_) => return deferred(),
    };
    let contents = crate::store::file::classify(&bytes);
    bytes.zeroize();

    let Contents::Entries(mut entries) = contents else {
        return deferred();
    };
    let held = entries.get(entry).cloned();
    for value in entries.values_mut() {
        value.zeroize();
    }

    let Some(mut value) = held else {
        return Shape::Wrong(format!(
            "`{}` is declared to live in `{entry}` of {}, which holds no such entry",
            proton::TOKEN_VAR,
            path.display()
        ));
    };
    let verdict = proton::classify_token(&value);
    value.zeroize();

    match verdict {
        Ok(()) => Shape::Sound(format!(
            "`{entry}` is shaped like an agent token. Whether Proton Pass accepts it is the \
             `store {}` row below",
            proton::STORE_ID
        )),
        Err(detail) => Shape::Wrong(format!(
            "`{entry}` in {} is not an agent token: {detail}. Nothing about the value is \
             printed here",
            path.display()
        )),
    }
}

/// One vendor's login on the daemon's side of the boundary: the file it lives
/// in, and whether this config gives it anything to do.
///
/// One row per vendor the daemon can carry a login for, so a second vendor's
/// file cannot go unreported the way a file this report never knew about would.
struct VendorLogin {
    /// The vendor, as a report names it.
    vendor: &'static str,
    /// The store id, as the `store` row beside it spells it.
    store: &'static str,
    /// Where the login lives.
    path: PathBuf,
    /// Whether the store is enabled AND names a credential — the two facts
    /// that together mean a lookup will open the file.
    in_use: bool,
}

fn vendor_logins(config: &super::config::DaemonConfig) -> [VendorLogin; 3] {
    let infisical = &config.stores.infisical;
    let onepassword = &config.stores.onepassword;
    let proton = &config.stores.proton;
    [
        VendorLogin {
            vendor: "Infisical",
            store: "infisical",
            path: infisical.credentials_file.to_path_buf(),
            in_use: infisical.enabled && !infisical.credentials.is_empty(),
        },
        VendorLogin {
            vendor: "1Password",
            store: "onepassword",
            path: onepassword.credentials_file.to_path_buf(),
            in_use: onepassword.enabled && !onepassword.credentials.is_empty(),
        },
        VendorLogin {
            vendor: "Proton Pass",
            store: proton::STORE_ID,
            path: proton.credentials_file.to_path_buf(),
            in_use: proton.enabled && !proton.credentials.is_empty(),
        },
    ]
}

/// A vendor login on disk that this config gives nothing to do.
///
/// The one thing `check` can see of a config that lost a vendor's store block.
/// Nothing in the daemon remembers what the config used to say, so a store
/// deleted from it leaves no trace at all — no identity row, no `store
/// <vendor>` row, no warning — and the report is fully green while every
/// name that store served has stopped resolving. What does survive is the credential
/// FILE, because it lives outside the config, and a file with a login in it
/// that no store is configured to use is either that accident or an install
/// somebody reconfigured and never cleaned up.
///
/// Both are worth a red row. The second is what `install/uninstall.sh` argues
/// at length is a landmine: a long-lived credential left on a machine with
/// nothing to use it, still valid at the vendor, that nobody is thinking about.
///
/// Silence for a file that is absent, empty, or unreadable from here — an
/// install that never used the vendor must not be nagged, and a guess made
/// through a permission error would be exactly that.
fn orphaned(login: &VendorLogin, out: &mut dyn io::Write) -> io::Result<bool> {
    let path = &login.path;
    let holds_something = fs::metadata(path).is_ok_and(|meta| meta.len() > 0);
    if !holds_something {
        return Ok(true);
    }
    writeln!(
        out,
        "identity PROBLEM {} holds a vendor login and nothing in this config uses it: the \
         {} store is not enabled here, or names no credential. Either the `{}` \
         block was lost out of this config — in which case every name it served has stopped \
         resolving, silently — or the login is left over, in which case delete it and REVOKE \
         the identity at the vendor",
        path.display(),
        login.vendor,
        login.store
    )?;
    Ok(false)
}

/// Read one credential from stdin, echoed nowhere.
///
/// # Why this is one function and not one per verb
///
/// Two verbs now read a credential — `credential`, which writes it, and
/// `login`, which presents it to a vendor. The rules below are the whole of
/// what keeps a typed credential out of a scrollback, and a second copy of them
/// would be free to lose one:
///
/// - **Echo is switched off around the read, on the same descriptor the
///   `is_terminal` test asked about.** Testing one fd and muting another is how
///   a prompt echoes.
/// - **A terminal whose echo cannot be switched off is NOT prompted at all.**
///   Printing the credential as it is typed is worse than refusing, so the
///   refusal names the pipe form instead.
/// - **A pipe is read whole and a terminal is read to the first newline**,
///   which is [`read_value`](crate::cmd::write::read_value)'s rule and not this
///   function's.
///
/// `subject` names what is being asked for, and `remedy` is the exact pipeline
/// to run instead when the terminal will not go quiet.
///
/// # Errors
///
/// The sentence to print. Nothing here carries any part of the value.
pub fn prompt_for(subject: &str, remedy: &str) -> Result<Secret, String> {
    use std::io::{IsTerminal, Write};

    let interactive = io::stdin().is_terminal();
    let quiet = if interactive {
        match crate::tty::without_echo() {
            Ok(guard) => Some(guard),
            Err(error) => {
                return Err(format!(
                    "cannot switch terminal echo off ({error}), so the value would be printed \
                     as you typed it. Pipe it in instead: `{remedy}`"
                ));
            }
        }
    } else {
        None
    };

    if interactive {
        let _ = write!(
            io::stderr(),
            "{}: {subject} (not echoed): ",
            crate::DAEMON_NAME
        );
        let _ = io::stderr().flush();
    }
    let value = crate::cmd::write::read_value(&mut io::stdin(), interactive);
    drop(quiet);
    if interactive {
        // Echo was off, so the user's Enter produced no newline on screen.
        let _ = writeln!(io::stderr());
    }
    value.map_err(|error| error.to_string())
}

/// Put one value into the credential file, leaving its owner and mode alone.
///
/// Rewritten whole through a temporary file in the same directory and renamed
/// over, so a reader never sees a half-written store and a failed write leaves
/// the previous credential intact. The replacement is created at [`MODE`] and
/// chowned to whoever owned the file before it, because the alternative — a
/// file owned by whoever typed `sudo` — is a credential the daemon cannot read,
/// which is a failure that looks exactly like a wrong credential.
///
/// # Why the daemon's owner is an argument
///
/// Preserving needs a file that already exists, and on the path where none does
/// the process's own uid is the wrong answer: `keylessd login` and `keylessd
/// credential` are typed with `sudo`, so that answer is `root:wheel` for a file
/// the daemon has to read as itself. `daemon` is who it should be instead,
/// resolved by the caller from [`daemon_owner`] — the audit log, which the
/// module header argues is the one source of that fact that is evidence rather
/// than a guess, and which [`inspect`] already judges this file's owner
/// against. Writer and reader therefore answer "the daemon's uid" out of the
/// same file, which is the property a locally inferred owner would give up.
///
/// It is threaded rather than read here because this function takes a path and
/// bytes and knows nothing of a config. [`crate::store::proton_session`]'s
/// `create` and `publish` take the same pair for the same reason, from the same
/// callers.
///
/// `None` where no audit log resolves, and then nothing is inferred: the file
/// keeps the uid that wrote it, which is what happened before this argument
/// existed, and [`inspect`] reports it. A machine with no audit log has never
/// run the daemon, so there is no uid to attribute the file to — and this
/// module refuses to name an owner it has no evidence for on the reading side
/// for exactly that reason.
///
/// # Errors
///
/// [`CredentialError`] naming the step that failed. Nothing here is printed and
/// no error carries the value.
pub fn store_entry(
    path: &Path,
    name: &str,
    value: &Secret,
    daemon: Option<(u32, u32)>,
) -> Result<(), CredentialError> {
    if name.is_empty() {
        return Err(CredentialError::Refused(
            "an entry name is required: it is the name `credentials` in keylessd.json \
             points at"
                .to_owned(),
        ));
    }

    let (mut entries, owner) = read_existing(path)?;
    entries.insert(name.to_owned(), value.expose().to_owned());

    let mut body = serde_json::to_vec_pretty(&entries).map_err(|error| {
        io_error(
            path,
            format!("the credential file cannot be rendered: {error}"),
        )
    })?;
    // The map still holds a plaintext copy of every entry that was already
    // there, including the ones this call did not touch. Wiped as soon as the
    // bytes exist, and the bytes are wiped once they are on disk.
    for value in entries.values_mut() {
        value.zeroize();
    }
    body.push(b'\n');

    // `owner` is `None` only when the file was absent — `read_existing` errors
    // on a file whose owner cannot be read — so the daemon's answers exactly
    // where there is nothing to preserve.
    let result = write_atomically(path, &body, owner.or(daemon));
    body.zeroize();
    result
}

/// `ceil(256 / 6)` — the number of characters [`crate::random::generate`]'s
/// 64-symbol alphabet needs to carry at least as much entropy as 32 random
/// bytes, which is what [`crate::store::proton::KeyProvider::Env`] asks for.
/// Not a byte-oriented base64 encoder: that alphabet already IS base64url's,
/// and drawing each symbol independently avoids the small bias a fixed-length
/// byte grouping carries. See `src/random.rs` for the argument in full.
const GENERATED_LOCAL_KEY_LENGTH: usize = 43;

/// What [`ensure_generated_entry`] found, or did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedEntry {
    /// The entry already held a value; nothing was generated or written.
    AlreadyPresent,
    /// It held nothing, so a fresh value was generated and written.
    Generated,
}

/// Give `name` a value the one time it has none, generated by this crate
/// rather than by whatever later reads it.
///
/// # Why this reads before it writes, unlike [`store_entry`]
///
/// [`store_entry`] inserts unconditionally, which is correct for a value a
/// human just typed: `keylessd credential` is called once, on purpose, to
/// place or rotate one entry. This function is called on every daemon start,
/// so the same unconditional write would mint a fresh value every restart —
/// and every generation encrypted under an earlier value would go on
/// existing, silently unreadable under the new one. That is the exact class
/// of mismatch [`crate::store::proton::KeyProvider`] exists to remove; a
/// generator that does not check first would reintroduce it one file over.
/// So presence is decided by a read first, and only silence about the entry
/// reaches [`store_entry`].
///
/// A read that FAILS — a malformed file — is never read as absence. Treating
/// "could not be parsed" the same as "nothing here yet" is exactly the
/// shortcut that would overwrite a file this crate cannot make sense of,
/// rather than stopping and saying so.
///
/// # Errors
///
/// Whatever [`store_entry`] could not do, a malformed existing file, or a
/// generator failure ([`crate::random::generate`]'s own `/dev/urandom` read).
pub fn ensure_generated_entry(
    path: &Path,
    name: &str,
    daemon: Option<(u32, u32)>,
) -> Result<GeneratedEntry, CredentialError> {
    // The read and the write are ONE act, and two processes reach it: the
    // daemon's own start, and the `login` verb an operator runs beside it —
    // which the installer's documented sequence puts back to back. Left
    // unserialised, both find the entry absent, both generate, and the loser's
    // value lands on top of a key the winner has already established a session
    // under. The file then holds a key that opens nothing, which is this
    // slice's own failure mode moved one file over. The claim `KeyProvider`
    // makes — exactly one writer of the key — is true of two processes only
    // because of this claim.
    let _guard = Guard::take(path)?;

    let (mut entries, _owner) = read_existing(path)?;
    let present = entries.get(name).is_some_and(|value| !value.is_empty());
    // `read_existing` hands back every credential in the file in plaintext —
    // this entry, and the agent token beside it. That obligation travels with
    // the map rather than being enforced by it (`crate::store::file::Contents`
    // says so in its own doc), and this function is where the map lives
    // longest, so it is scrubbed here on both arms rather than on one.
    for value in entries.values_mut() {
        value.zeroize();
    }
    if present {
        return Ok(GeneratedEntry::AlreadyPresent);
    }

    let value = crate::random::generate(GENERATED_LOCAL_KEY_LENGTH)
        .map_err(|error| io_error(path, format!("a value could not be generated: {error}")))?;
    store_entry(path, name, &value, daemon)?;
    Ok(GeneratedEntry::Generated)
}

/// Give [`crate::store::proton::KeyProvider::Env`] a local key to read,
/// generated once at the daemon's own first start.
///
/// `Ok(None)` when there is nothing to generate: Proton is disabled, or `fs` is
/// still in force and owns its own key file.
///
/// # Why a config naming no entry is not one of those cases
///
/// The entry name is a label for a value this daemon generates and nobody ever
/// types, so an operator who has to supply one is being asked to invent a name
/// for something they will never see — and the cost of forgetting is every
/// Proton name degrading behind a warning nobody reads at boot.
/// [`super::config::DaemonProtonConfig::credential_entries`] fills the name in,
/// which is why this function no longer has an arm for its absence. systemd
/// draws the same line for the same object: its credential host key is
/// "automatically generated when needed", and its explicit `setup` verb exists
/// because it is cheaper to call than to discover, never as a prerequisite.
///
/// # Errors
///
/// Whatever [`ensure_generated_entry`] could not do, and a refusal where the
/// credential file is the file the `file` store serves — the same refusal
/// [`super::login::coordinates`] makes, for the same reason: everything in that
/// file is a name any attested client can ask for, so a key minted into it is
/// handed out on request.
pub fn ensure_proton_local_key(
    config: &super::config::DaemonConfig,
) -> Result<Option<GeneratedEntry>, CredentialError> {
    let settings = &config.stores.proton;
    if !settings.enabled || settings.key_provider != proton::KeyProvider::Env {
        return Ok(None);
    }
    let credentials_file = settings.credentials_file.to_path_buf();
    if config.stores.file.enabled && credentials_file == config.stores.file.path.to_path_buf() {
        return Err(CredentialError::Refused(format!(
            "{} is the file the `file` store serves, so a local key generated there is a name \
             any attested client can ask for over the socket. Point \
             `stores.proton.credentials_file` at a file of its own first",
            credentials_file.display()
        )));
    }
    let entries = settings.credential_entries();
    let Some(entry) = entries.get(proton::ENCRYPTION_KEY_VAR) else {
        return Ok(None);
    };
    let daemon = daemon_owner(&config.audit).map(|owner| (owner.uid, owner.gid));
    ensure_generated_entry(&credentials_file, entry, daemon).map(Some)
}

/// How long a writer waits for a claim another process is holding.
///
/// A holder that is alive is doing one file read and one atomic write, so a
/// wait this long is never spent in practice. What it bounds is the CALLER:
/// the renewal loop must not sit here while a session it could be renewing
/// expires, and giving up costs nothing now that the loop attempts the
/// generation again on its next tick.
///
/// Matched to the renewal loop's own shutdown grace deliberately. The wait
/// does not consult the stop flag — it cannot, since this module knows nothing
/// about a loop — so a wait longer than that grace would let a contended tick
/// outlive the patience shutdown has for it, and the process would report that
/// it was waiting on the vendor when it was waiting on a file.
const CLAIM_WAIT: Duration = Duration::from_secs(5);

/// An exclusive claim on one credential file, held across a read-then-write.
///
/// # Why the kernel holds this and no rule of ours does
///
/// The claim has to be released when its holder dies — killed by a signal, or
/// by the restart that installed the binary it was running. A claim marked by
/// the mere EXISTENCE of a file cannot be: a signal runs no destructor, so the
/// marker outlives the process and every later writer reads it as live. The
/// obvious repair is to break a claim that looks old, and it is a trap — every
/// way of reading "old" can fail (a clock that moved, a file another uid owns,
/// an mtime a filesystem rounds), each failure reads as "still held", and the
/// break itself un-serialises the one read-then-write the claim exists to
/// protect. Measured on 2026-09-11: a claim left by a killed start wedged
/// every later start for 87 minutes, and the timestamp repair for it would
/// have let two writers generate two keys and the slower one overwrite the
/// value the faster one had already published a session under.
///
/// `flock` answers it exactly, and answers nothing else. The lock belongs to
/// the open file description rather than to a path or a rule, so the kernel
/// releases it when the descriptor closes — which a process exit does, however
/// that exit happens. There is no staleness to judge, nothing to break, and no
/// identity to record: a dead holder holds nothing, and a live one is never
/// overtaken.
///
/// Read from the vendor rather than assumed: `File::try_lock` is
/// `flock(LOCK_EX | LOCK_NB)` on Unix, and "the lock will be released when this
/// file (along with any other file descriptors/handles duplicated or inherited
/// from it) is closed" — <https://doc.rust-lang.org/std/fs/struct.File.html>.
/// The descriptor is not inherited by the vendor children this daemon spawns,
/// because the standard library opens files close-on-exec.
///
/// The claim file itself is never removed. Unlinking a path another process
/// holds open is what reintroduces the identity problem this design removes,
/// and an empty file costs nothing.
struct Guard {
    /// The lock lives with this handle and is released when it drops.
    _file: fs::File,
}

impl Guard {
    /// Claim `target`, waiting up to [`CLAIM_WAIT`] for a live holder.
    fn take(target: &Path) -> Result<Self, CredentialError> {
        Self::take_within(target, CLAIM_WAIT)
    }

    /// The same, with the wait named by the caller, so a test can prove
    /// contention without spending the real one.
    fn take_within(target: &Path, wait: Duration) -> Result<Self, CredentialError> {
        let path = claim_path(target)?;
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(MODE)
            .open(&path)
            .map_err(|error| io_error(target, format!("cannot be claimed for writing: {error}")))?;

        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(fs::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(io_error(
                            target,
                            format!(
                                "a claim on it is held and was not released within {} \
                                 seconds: {} is locked by another process",
                                wait.as_secs(),
                                path.display()
                            ),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(fs::TryLockError::Error(error)) => {
                    return Err(io_error(
                        target,
                        format!("cannot be claimed for writing: {error}"),
                    ));
                }
            }
        }
    }
}

/// Where one credential file's claim lives — beside it, so it inherits the
/// directory's own mode and never lands somewhere world-writable.
fn claim_path(target: &Path) -> Result<PathBuf, CredentialError> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| io_error(target, "has no directory to write into"))?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("credentials");
    Ok(parent.join(format!(".{name}.claim")))
}

/// A file's owning uid and gid, kept together so a rewrite can hand them back.
type Owner = (u32, u32);

/// The entries already in the file, and the uid that owns it.
///
/// A missing file is an empty store rather than an error: the installer creates
/// it empty, and an empty file is what `install -m 0600 /dev/null` leaves.
fn read_existing(
    path: &Path,
) -> Result<(BTreeMap<String, String>, Option<Owner>), CredentialError> {
    let (mut bytes, owner) = match fs::read(path) {
        Ok(bytes) => {
            let meta = fs::metadata(path)
                .map_err(|error| io_error(path, format!("cannot be examined: {error}")))?;
            (bytes, Some((meta.uid(), meta.gid())))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (Vec::new(), None),
        Err(error) => return Err(io_error(path, format!("cannot be read: {error}"))),
    };

    // Classified by the same function the `file` store reads with, so the two
    // cannot disagree about what a given file IS. What they still decide
    // separately is what an empty one means for their verb: writing into one is
    // ordinary, and reading a name out of one cannot succeed.
    let contents = crate::store::file::classify(&bytes);
    bytes.zeroize();
    match contents {
        Contents::Empty => Ok((BTreeMap::new(), owner)),
        Contents::Entries(entries) => Ok((entries, owner)),
        // The contents are never quoted back: a parse error in a credential file
        // would otherwise print the credentials it failed to parse.
        Contents::Malformed { line, column } => Err(io_error(
            path,
            format!(
                "is not a JSON object of name to value, so rewriting it would lose what is \
                 in it (line {line}, column {column})"
            ),
        )),
    }
}

/// Rename a fresh `0600` file over the old one, giving it to `owner`.
fn write_atomically(path: &Path, body: &[u8], owner: Option<Owner>) -> Result<(), CredentialError> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Err(io_error(path, "has no directory to write into"));
    };
    // The process id is in the name because two `keylessd` processes can write
    // this file — the daemon's own start and an operator's `login` — and a
    // SHARED temporary is one inode two writers truncate and fill at their own
    // offsets, which leaves a splice of two JSON images that parses as neither.
    // A claim serialises the generator; this is what keeps every other writer
    // from colliding whether or not it took one.
    let temporary = parent.join(format!(
        ".{}.{}.new",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("credentials"),
        std::process::id()
    ));

    // Created at 0600 BEFORE anything is written to it, rather than written and
    // then chmodded: between those two calls the file would exist at whatever
    // the umask allowed, holding the credential.
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(MODE)
        .open(&temporary)
        .map_err(|error| io_error(&temporary, format!("cannot be created: {error}")))?;
    // An existing temporary would keep its old mode, which `.mode()` does not
    // apply. Set it unconditionally so the reused path cannot be the wide one.
    if let Err(error) = file.set_permissions(fs::Permissions::from_mode(MODE)) {
        let _ = fs::remove_file(&temporary);
        return Err(io_error(
            &temporary,
            format!("cannot be locked down to {MODE:04o}: {error}"),
        ));
    }
    if let Err(error) = write_all_and_sync(&file, body) {
        let _ = fs::remove_file(&temporary);
        return Err(io_error(&temporary, format!("cannot be written: {error}")));
    }
    drop(file);

    if let Some((uid, gid)) = owner
        && let Err(error) = std::os::unix::fs::chown(&temporary, Some(uid), Some(gid))
    {
        let _ = fs::remove_file(&temporary);
        return Err(io_error(
            &temporary,
            format!("cannot be given to uid {uid}: {error}"),
        ));
    }

    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        io_error(path, format!("cannot be replaced: {error}"))
    })
}

fn write_all_and_sync(mut file: &fs::File, body: &[u8]) -> io::Result<()> {
    use std::io::Write;
    file.write_all(body)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) const DECOY: &str = "decoy-Cred1-never-a-real-machine-identity-0808";

    pub(super) fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-credential-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// A decoy shaped the way a real agent token is: `pst_<token>::<key>`,
    /// with a base64url key. Invented, and long enough that a grep for it in
    /// any output would mean a real leak.
    pub(super) const TOKEN_DECOY: &str = "pst_decoy0Pat0never0real0Aa1::ZGVjb3kta2V5LTA5MDk=";

    /// The daemon's Proton block, with `token_expires` and the credential file
    /// under the caller's control.
    fn proton_config(dir: &Path, expires: &str) -> super::super::config::DaemonConfig {
        serde_json::from_str(&format!(
            r#"{{"audit":"{dir}/audit.jsonl",
                 "stores":{{"proton":{{"enabled":true,
                                       "session_dir":"{dir}/session",
                                       "credentials_file":"{dir}/proton.json",
                                       "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"TOKEN"}}
                                       {expires}}}}}}}"#,
            dir = dir.display(),
        ))
        .expect("a valid daemon config")
    }

    /// The rows `report` renders for one config, and its verdict.
    fn rows(config: &super::super::config::DaemonConfig) -> (String, bool) {
        let mut out: Vec<u8> = Vec::new();
        let sound = report(config, &mut out).expect("a Vec");
        (String::from_utf8(out).expect("ASCII rows"), sound)
    }

    /// The `token` rows only, so an assertion cannot be satisfied by the
    /// `identity` row above them.
    fn token_rows(rendered: &str) -> Vec<&str> {
        rendered
            .lines()
            .filter(|line| line.split_whitespace().next() == Some("token"))
            .collect()
    }

    /// The state word of a row: the second whitespace-separated column, read
    /// WHOLE. `contains("ok")` is satisfied by the sentences beside `PROBLEM`.
    fn state(row: &str) -> Option<&str> {
        row.split_whitespace().nth(1)
    }

    fn write_token_file(dir: &Path, entries: &[(&str, &str)]) {
        let path = dir.join("proton.json");
        let body: BTreeMap<&str, &str> = entries.iter().copied().collect();
        fs::write(&path, serde_json::to_vec(&body).expect("json")).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(MODE)).expect("chmod");
    }

    #[test]
    fn the_four_file_side_states_of_a_proton_token_are_told_apart() {
        // Four states that a row built from mode and owner alone renders
        // identically, and whose remedies point at four different places. The
        // fifth — refused by the vendor — is deliberately the `store proton`
        // row's, because it is the only one that takes a round trip to
        // establish. `store::proton::refused_the_token` covers that one.
        let dir = scratch("proton-states");

        // 1. ABSENT. No file at all, which is what a fresh install has before
        //    anybody writes a token.
        let (absent, sound) = rows(&proton_config(&dir, ""));
        assert!(!sound, "{absent}");
        assert!(absent.contains("does not exist"), "{absent}");
        // And the shape row over a file nothing read says so. `ok` there would
        // be the exact false green this report exists to remove: a verdict on
        // a value nobody looked at.
        assert_eq!(state(token_rows(&absent)[0]), Some("unproven"), "{absent}");

        // 1b. PRESENT AND WIDE OPEN. `identity` reports the mode; the shape row
        //     must not report `ok` on the contents of a file the daemon's own
        //     store would refuse to open. This one is easy to get wrong,
        //     because this function reads the file directly rather than through
        //     that store.
        write_token_file(&dir, &[("TOKEN", TOKEN_DECOY)]);
        fs::set_permissions(dir.join("proton.json"), fs::Permissions::from_mode(0o644))
            .expect("widen");
        let (wide, sound) = rows(&proton_config(&dir, ""));
        assert!(!sound, "{wide}");
        assert!(wide.contains("mode 0644"), "{wide}");
        assert_eq!(state(token_rows(&wide)[0]), Some("unproven"), "{wide}");

        // 2. MALFORMED. Present, 0600, one entry, and what is in it is not a
        //    token — a token's NAME, which is the most plausible paste of all.
        //    Every file check passes.
        write_token_file(&dir, &[("TOKEN", "keyless-daemon")]);
        let (malformed, sound) = rows(&proton_config(&dir, ""));
        assert!(!sound, "{malformed}");
        let row = token_rows(&malformed);
        assert_eq!(state(row[0]), Some("PROBLEM"), "{malformed}");
        assert!(row[0].contains("pst_"), "{malformed}");
        assert!(
            !malformed.contains("keyless-daemon"),
            "the value was printed: {malformed}"
        );

        // 3. WELL FORMED, expiry UNDECLARED. The shape row goes green and the
        //    expiry row says the question could not be asked — never that it
        //    passed.
        write_token_file(&dir, &[("TOKEN", TOKEN_DECOY)]);
        let (undeclared, _) = rows(&proton_config(&dir, ""));
        let row = token_rows(&undeclared);
        assert_eq!(state(row[0]), Some("ok"), "{undeclared}");
        assert_eq!(state(row[1]), Some("unproven"), "{undeclared}");
        assert!(
            !undeclared.contains(TOKEN_DECOY),
            "the token was printed: {undeclared}"
        );

        // 4a. EXPIRED, and 4b. EXPIRING. Two verdicts, not one, because one is
        //     an outage happening now and the other is a task with time in it.
        let (expired, sound) = rows(&proton_config(&dir, r#","token_expires":"2020-01-01""#));
        assert!(!sound, "{expired}");
        let row = token_rows(&expired);
        assert_eq!(state(row[1]), Some("PROBLEM"), "{expired}");
        assert!(row[1].contains("EXPIRED"), "{expired}");

        let (far, sound) = rows(&proton_config(&dir, r#","token_expires":"2099-01-01""#));
        let row = token_rows(&far);
        assert_eq!(state(row[1]), Some("ok"), "{far}");
        assert!(sound, "a sound Proton token was reported unsound: {far}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_daemon_with_no_proton_store_gets_no_token_rows_at_all() {
        // The negative control for every case above, and a rule in its own
        // right: a report that said something about a Proton token on every
        // install without one teaches an operator to read past the row on the
        // one install where it matters.
        let dir = scratch("proton-absent");
        let config: super::super::config::DaemonConfig = serde_json::from_str(&format!(
            r#"{{"audit":"{dir}/audit.jsonl","stores":{{"file":{{"enabled":true}}}}}}"#,
            dir = dir.display()
        ))
        .expect("valid");
        let (rendered, sound) = rows(&config);
        assert!(token_rows(&rendered).is_empty(), "{rendered}");
        assert!(sound, "{rendered}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_written_entry_is_readable_by_the_file_store_and_by_nobody_else() {
        let dir = scratch("write");
        let path = dir.join("infisical.json");
        store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("stored");

        let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o7777;
        assert_eq!(mode, MODE, "written at {mode:04o}");

        // Read back through the store the daemon actually uses, not through
        // this module's own parser — the two agreeing is the property.
        let store = crate::store::file::FileStore::new(path.clone());
        let read = crate::store::Store::resolve(&store, "MACHINE_IDENTITY").expect("resolve");
        assert_eq!(read.expect("present").expose(), DECOY);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_entry_joins_the_first_rather_than_replacing_the_file() {
        // A machine identity is two entries written by two separate commands.
        // A writer that truncated would leave the operator with a client secret
        // and no client id, and the failure would arrive at the next lookup.
        let dir = scratch("append");
        let path = dir.join("infisical.json");
        store_entry(
            &path,
            "CLIENT_ID",
            &Secret::new("decoy-id-0909".to_owned()),
            None,
        )
        .expect("first");
        store_entry(&path, "CLIENT_SECRET", &Secret::new(DECOY.to_owned()), None).expect("second");

        let store = crate::store::file::FileStore::new(path);
        for (name, expected) in [("CLIENT_ID", "decoy-id-0909"), ("CLIENT_SECRET", DECOY)] {
            let read = crate::store::Store::resolve(&store, name)
                .expect("resolve")
                .expect("present");
            assert_eq!(
                read.expose(),
                expected,
                "{name} did not survive the second write"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_file_is_an_empty_store_rather_than_a_parse_failure() {
        // What `install -m 0600 /dev/null <path>` leaves behind. Treating it as
        // malformed would make the installer's own artefact unwritable.
        let dir = scratch("empty");
        let path = dir.join("infisical.json");
        fs::write(&path, b"").expect("create");
        store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("stored");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_file_is_refused_without_quoting_what_it_holds() {
        let dir = scratch("malformed");
        let path = dir.join("infisical.json");
        fs::write(&path, format!("{{\"BROKEN\": \"{DECOY}\"")).expect("create");
        let said = store_entry(&path, "X", &Secret::new("decoy-x".to_owned()), None)
            .expect_err("a truncated object is not a store")
            .to_string();
        assert!(
            !said.contains(DECOY),
            "the refusal quoted the file's contents: {said}"
        );
        assert!(said.contains("lose what is in it"), "{said}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_generated_entry_is_written_once_and_reused_across_restarts() {
        // CONTROL: a generator that regenerated on every call — the shape a
        // daemon restart would exercise — is the exact mismatch `KeyProvider`
        // exists to remove, moved from the vendor's file into this one. This
        // is the case that failed before `ensure_generated_entry` checked
        // presence first: reverting that check back to an unconditional
        // `store_entry` turns this red, both on the second call's own verdict
        // (`AlreadyPresent` becomes `Generated` again) and on the length
        // assertion below the moment two draws land on different lengths.
        let dir = scratch("generate-once");
        let path = dir.join("proton.json");

        let first = ensure_generated_entry(&path, "PROTON_LOCAL_KEY", None).expect("first call");
        assert_eq!(first, GeneratedEntry::Generated, "nothing was there yet");

        let store = crate::store::file::FileStore::new(path.clone());
        let after_first = crate::store::Store::resolve(&store, "PROTON_LOCAL_KEY")
            .expect("resolve")
            .expect("present")
            .len();
        // The literal, not `GENERATED_LOCAL_KEY_LENGTH`: the constant is the
        // code under test, so comparing against it would hold whatever that
        // constant became — see `tests/oracle_independence.rs`.
        assert_eq!(
            after_first, 43,
            "a generated value is not the expected length"
        );

        let second = ensure_generated_entry(&path, "PROTON_LOCAL_KEY", None).expect("second call");
        assert_eq!(
            second,
            GeneratedEntry::AlreadyPresent,
            "a restart regenerated the key rather than reusing what was there"
        );

        let after_second = crate::store::Store::resolve(&store, "PROTON_LOCAL_KEY")
            .expect("resolve")
            .expect("present")
            .len();
        // The same literal both reads are held to, rather than comparing them
        // to each other: `after_first == after_second` holds even if both
        // calls wrote some other FIXED-but-wrong length, which asserts
        // nothing about a restart specifically. Pinning each read to `43`
        // independently is what a fixed-but-wrong length would actually fail.
        assert_eq!(
            after_second, 43,
            "the second call's read is not the expected length — a value changed size, or \
             regenerated, across what looks like a restart"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_that_already_holds_a_value_keeps_that_exact_value() {
        // What `AlreadyPresent` claims, checked against an oracle this
        // function cannot have produced: a value written here, by hand, and
        // read back unchanged. The verdict alone cannot carry this — a
        // generator that answered `AlreadyPresent` and rewrote the entry
        // anyway would pass every assertion in
        // `a_generated_entry_is_written_once_and_reused_across_restarts`,
        // because two draws from the same generator are the same LENGTH. A
        // rewritten key is how every generation encrypted under the old one
        // goes silently unreadable, so what is pinned here is the value, not
        // the verdict.
        let dir = scratch("generate-keeps");
        let path = dir.join("proton.json");
        store_entry(
            &path,
            "PROTON_LOCAL_KEY",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("write");

        assert_eq!(
            ensure_generated_entry(&path, "PROTON_LOCAL_KEY", None).expect("no error"),
            GeneratedEntry::AlreadyPresent
        );

        let store = crate::store::file::FileStore::new(path);
        let after = crate::store::Store::resolve(&store, "PROTON_LOCAL_KEY")
            .expect("resolve")
            .expect("present");
        assert_eq!(
            after.expose(),
            DECOY,
            "the value that was already there did not survive the call"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_credential_file_refuses_generation_rather_than_overwriting_it() {
        // The generation-specific mirror of `a_malformed_file_is_refused_
        // without_quoting_what_it_holds`: reading a parse failure as
        // "nothing here yet" is exactly the shortcut that would mint a fresh
        // key over a file this crate could not make sense of.
        let dir = scratch("generate-malformed");
        let path = dir.join("proton.json");
        fs::write(&path, format!("{{\"BROKEN\": \"{DECOY}\"")).expect("create");
        let said = ensure_generated_entry(&path, "PROTON_LOCAL_KEY", None)
            .expect_err("a truncated object is not a store")
            .to_string();
        assert!(
            !said.contains(DECOY),
            "the refusal quoted the file's contents: {said}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_daemons_first_start_hands_its_own_owner_to_the_key_it_generates() {
        // The path the defect arrives on, end to end from the entry point the
        // daemon's start calls. `ensure_proton_local_key` is the one caller
        // that resolves the owner rather than receiving it, so a resolve that
        // never reaches the write is invisible to every case that hands the
        // owner in by hand. Pointing the config's audit log at a file owned by
        // somebody else makes the resolved answer a uid this process cannot
        // chown to, and the refusal naming it is what proves the two ends are
        // joined.
        let dir = scratch("first-start-owner");
        let audit = Path::new("/usr/bin/env");
        let meta = fs::metadata(audit).expect("stat a file owned by somebody else");
        assert_ne!(
            meta.uid(),
            mine().0,
            "this case needs {} to be owned by somebody other than the suite",
            audit.display()
        );

        let config: super::super::config::DaemonConfig = serde_json::from_str(&format!(
            r#"{{"audit":"{audit}",
                 "stores":{{"proton":{{"enabled":true,
                                       "session_dir":"{dir}/session",
                                       "credentials_file":"{dir}/proton.json",
                                       "key_provider":"env",
                                       "credentials":{{"PROTON_PASS_ENCRYPTION_KEY":"PROTON_LOCAL_KEY"}}}}}}}}"#,
            audit = audit.display(),
            dir = dir.display(),
        ))
        .expect("a valid daemon config");

        let said = ensure_proton_local_key(&config)
            .expect_err("this process cannot give the key file to another uid")
            .to_string();
        assert!(
            said.contains(&format!("uid {}", meta.uid())),
            "the generated key was written without the daemon's own owner: {said}"
        );
        assert!(
            !dir.join("proton.json").exists(),
            "a refused generation left a credential file behind"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// The daemon's Proton block with an explicit `key_provider`, and the
    /// encryption-key entry declared or not.
    fn proton_config_for_generation(
        dir: &Path,
        key_provider: &str,
        name_the_entry: bool,
    ) -> super::super::config::DaemonConfig {
        let credentials = if name_the_entry {
            r#""credentials":{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"TOKEN",
                              "PROTON_PASS_ENCRYPTION_KEY":"PROTON_LOCAL_KEY"}"#
        } else {
            r#""credentials":{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"TOKEN"}"#
        };
        serde_json::from_str(&format!(
            r#"{{"audit":"{dir}/audit.jsonl",
                 "stores":{{"proton":{{"enabled":true,
                                       "session_dir":"{dir}/session",
                                       "credentials_file":"{dir}/proton.json",
                                       "key_provider":"{key_provider}",
                                       {credentials}}}}}}}"#,
            dir = dir.display(),
        ))
        .expect("a valid daemon config")
    }

    #[test]
    fn ensure_proton_local_key_generates_nothing_while_fs_is_still_in_force() {
        // The control named in the brief: under `fs` the daemon never touches
        // this entry, so a config still on the old provider is unaffected by
        // this function existing.
        let dir = scratch("generate-fs");
        let config = proton_config_for_generation(&dir, "fs", true);
        assert_eq!(
            ensure_proton_local_key(&config).expect("no error"),
            None,
            "fs asked this function to act"
        );
        assert!(
            !dir.join("proton.json").exists(),
            "a file was written for a provider that never reads one"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_config_naming_no_entry_still_gets_a_key_under_the_daemons_own_name() {
        // The state this removes: `env` in force, no entry named, so nothing
        // was generated and every Proton name degraded behind one warning
        // printed into a launchd log at boot. The entry labels a value nobody
        // types, so naming it is the daemon's job.
        let dir = scratch("generate-undeclared");
        let config = proton_config_for_generation(&dir, "env", false);

        assert_eq!(
            ensure_proton_local_key(&config).expect("no error"),
            Some(GeneratedEntry::Generated),
            "a config naming no entry generated nothing"
        );

        let store = crate::store::file::FileStore::new(dir.join("proton.json"));
        let under_default =
            crate::store::Store::resolve(&store, super::super::config::DEFAULT_LOCAL_KEY_ENTRY)
                .expect("resolve")
                .expect("present")
                .len();
        assert_eq!(
            under_default, 43,
            "the generated value is not the expected length"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_declared_entry_name_is_used_instead_of_the_daemons_own() {
        // The control for the case above: without it, that test passes on a
        // generator that writes to `LOCAL_KEY` unconditionally, which would
        // strand every machine whose config names an entry of its own.
        let dir = scratch("generate-declared-name");
        let config = proton_config_for_generation(&dir, "env", true);

        assert_eq!(
            ensure_proton_local_key(&config).expect("no error"),
            Some(GeneratedEntry::Generated)
        );

        let store = crate::store::file::FileStore::new(dir.join("proton.json"));
        assert!(
            crate::store::Store::resolve(&store, "PROTON_LOCAL_KEY")
                .expect("resolve")
                .is_some(),
            "the declared entry holds nothing"
        );
        assert!(
            crate::store::Store::resolve(&store, super::super::config::DEFAULT_LOCAL_KEY_ENTRY)
                .expect("resolve")
                .is_none(),
            "the daemon's own entry name was written beside the declared one"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_generators_racing_one_file_agree_on_one_value() {
        // The interleaving the claim exists for, and the one the installer's
        // own documented sequence produces: `keylessd run` starting while
        // `keylessd login` runs beside it. Without the claim both find the
        // entry absent, both generate, and the loser's value lands on top of a
        // key the winner has already established a session under — a file
        // holding a key that opens nothing.
        let dir = scratch("generate-race");
        let path = dir.join("proton.json");

        let verdicts: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let path = path.clone();
                    scope.spawn(move || ensure_generated_entry(&path, "PROTON_LOCAL_KEY", None))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("the generator panicked"))
                .collect()
        });

        let generated = verdicts
            .iter()
            .filter(|verdict| matches!(verdict, Ok(GeneratedEntry::Generated)))
            .count();
        let present = verdicts
            .iter()
            .filter(|verdict| matches!(verdict, Ok(GeneratedEntry::AlreadyPresent)))
            .count();
        assert_eq!(
            (generated, present),
            (1, 1),
            "two racing generators did not agree on one value: {verdicts:?}"
        );

        let store = crate::store::file::FileStore::new(path);
        assert_eq!(
            crate::store::Store::resolve(&store, "PROTON_LOCAL_KEY")
                .expect("resolve")
                .expect("present")
                .len(),
            43,
            "the surviving value is not one whole generated key"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_claim_a_dead_holder_left_behind_is_free_the_moment_it_dies() {
        // The outage of 2026-09-11, as a case. A start took the claim and the
        // restart that installed it killed the process mid-generation; the
        // marker outlived its holder, every later start read it as live, and
        // the machine served no Proton name for 87 minutes.
        //
        // Held by a REAL other process, because that is the only way to prove
        // the property that matters: the kernel releases the lock when the
        // holder dies, with no rule of ours judging how long is too long. The
        // child is killed rather than asked to exit, so nothing it might have
        // run on the way out can be what frees the claim.
        let dir = scratch("claim-dead-holder");
        fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("proton.json");
        let claim = claim_path(&path).expect("a claim path");
        fs::write(&claim, b"").expect("the claim file the holder will lock");

        let mut holder = std::process::Command::new("/usr/bin/python3")
            .arg("-c")
            .arg(
                "import fcntl, sys, time\n\
                 handle = open(sys.argv[1], 'r+')\n\
                 fcntl.flock(handle, fcntl.LOCK_EX)\n\
                 print('held', flush=True)\n\
                 time.sleep(300)\n",
            )
            .arg(&claim)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("a holder to contend with");

        // Wait for the child to say it holds the lock, rather than sleeping a
        // guess: a race here would test nothing and pass.
        let mut ready = String::new();
        {
            use std::io::{BufRead, BufReader};
            let stdout = holder.stdout.take().expect("the holder's stdout");
            BufReader::new(stdout)
                .read_line(&mut ready)
                .expect("the holder never reported");
        }
        assert_eq!(ready.trim(), "held", "the holder did not take the lock");

        let contended = Guard::take_within(&path, Duration::from_millis(200))
            .err()
            .map(|error| error.to_string());
        assert!(
            contended.is_some_and(|said| said.contains("is locked by another process")),
            "a claim a live holder is holding was taken anyway"
        );

        holder.kill().expect("kill the holder");
        holder.wait().expect("reap the holder");

        let taken = Guard::take_within(&path, Duration::from_millis(200))
            .expect("a claim whose holder died must be free at once");
        drop(taken);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_writers_of_one_file_never_hold_the_claim_at_once() {
        // What the claim is FOR, and the assertion the previous design could
        // not make: the generator's read and its write are one act. Threads
        // rather than processes, because `flock` is held per open file
        // description and two threads opening the file separately contend
        // exactly as two processes do.
        let dir = scratch("claim-exclusive");
        fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("proton.json");

        let held = Guard::take_within(&path, Duration::from_millis(200)).expect("first claim");

        let blocked = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    Guard::take_within(&path, Duration::from_millis(200))
                        .err()
                        .map(|error| error.to_string())
                })
                .join()
                .expect("the contender panicked")
        });
        assert!(
            blocked.is_some(),
            "two writers held the claim on one file at the same time"
        );

        drop(held);

        let after = Guard::take_within(&path, Duration::from_millis(200));
        assert!(
            after.is_ok(),
            "the claim was not released when its guard dropped"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_is_never_generated_into_the_file_the_file_store_serves() {
        // The refusal `login::coordinates` already makes, made by the writer
        // too: everything in that file is a name any attested client can ask
        // for, so a key minted there is handed out on request.
        let dir = scratch("generate-into-served-file");
        let shared = dir.join("secrets.json");
        let config: super::super::config::DaemonConfig = serde_json::from_str(&format!(
            r#"{{"audit":"{dir}/audit.jsonl",
                 "stores":{{"file":{{"enabled":true,"path":"{shared}"}},
                            "proton":{{"enabled":true,
                                       "session_dir":"{dir}/session",
                                       "credentials_file":"{shared}",
                                       "key_provider":"env",
                                       "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"TOKEN"}}}}}}}}"#,
            dir = dir.display(),
            shared = shared.display(),
        ))
        .expect("a valid daemon config");

        let said = ensure_proton_local_key(&config)
            .expect_err("a key was generated into the file the `file` store serves")
            .to_string();
        assert!(
            said.contains("file of its own"),
            "the refusal does not name the fix: {said}"
        );
        assert!(!shared.exists(), "the refused write left a file behind");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_proton_local_key_generates_a_value_for_an_env_daemon_with_a_declared_entry() {
        let dir = scratch("generate-env");
        let config = proton_config_for_generation(&dir, "env", true);

        let first = ensure_proton_local_key(&config).expect("no error");
        assert_eq!(first, Some(GeneratedEntry::Generated));

        let second = ensure_proton_local_key(&config).expect("no error");
        assert_eq!(
            second,
            Some(GeneratedEntry::AlreadyPresent),
            "a second daemon start regenerated the key"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_three_faults_are_reported_apart_from_each_other() {
        let dir = scratch("inspect");
        let path = dir.join("infisical.json");

        let missing = inspect(&path, Some(300)).expect_err("nothing is there");
        assert!(missing.contains("does not exist"), "{missing}");

        store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("stored");
        let owner = fs::metadata(&path).expect("stat").uid();

        // Sound: right mode, and the owner is the uid the daemon runs as.
        let sound = inspect(&path, Some(owner)).expect("mode and owner are both right");
        assert!(sound.contains("0600"), "{sound}");
        assert!(!sound.contains("unverified"), "{sound}");

        // Misowned, and it must not read as a mode fault.
        let misowned = inspect(&path, Some(owner + 1)).expect_err("a foreign owner");
        assert!(misowned.contains("cannot read its own login"), "{misowned}");
        assert!(misowned.contains("chown"), "{misowned}");
        assert!(
            !misowned.contains("chmod"),
            "an ownership fault was reported as a mode fault: {misowned}"
        );

        // Exposed, and it must not read as an ownership fault. Checked first, so
        // a file that is both wide open and misowned reports the mode — the one
        // that has already leaked.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let exposed = inspect(&path, Some(owner + 1)).expect_err("a readable credential");
        assert!(exposed.contains("mode 0644"), "{exposed}");
        assert!(exposed.contains("chmod 0600"), "{exposed}");
        assert!(
            !exposed.contains("chown"),
            "a mode fault was reported as an ownership fault: {exposed}"
        );

        // And with no audit log to read a uid from, the owner is reported and
        // not judged.
        fs::set_permissions(&path, fs::Permissions::from_mode(MODE)).expect("chmod");
        let unverified = inspect(&path, None).expect("nothing to compare against is not a fault");
        assert!(unverified.contains("unverified"), "{unverified}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_the_installer_leaves_does_not_report_the_identity_as_sound() {
        // The measured defect. An empty file, a file of whitespace and a file
        // of broken JSON have the same mode and the same owner as a file
        // holding a machine identity, and a row built from those two said `ok`
        // over all four. The empty one is what every install starts with and
        // what a re-run used to put a working install back into.
        let dir = scratch("contents");
        let path = dir.join("infisical.json");
        fs::write(&path, b"").expect("create");
        fs::set_permissions(&path, fs::Permissions::from_mode(MODE)).expect("chmod");
        let owner = fs::metadata(&path).expect("stat").uid();

        let empty = inspect(&path, Some(owner)).expect_err("an empty credential file");
        assert!(empty.contains("EMPTY"), "{empty}");
        assert!(empty.contains("credential --name"), "{empty}");

        // Whitespace is the same state, not a third one. The two readers used
        // to disagree about exactly these bytes.
        fs::write(&path, b"  \n\t\n").expect("create");
        let blank = inspect(&path, Some(owner)).expect_err("whitespace is not a login");
        assert!(blank.contains("EMPTY"), "{blank}");

        // Malformed is a different state with a different remedy, and it must
        // not read as the empty one.
        fs::write(&path, format!("{{\"BROKEN\": \"{DECOY}\"")).expect("create");
        let broken = inspect(&path, Some(owner)).expect_err("a truncated object");
        assert!(broken.contains("not a JSON object"), "{broken}");
        assert!(
            !broken.contains("EMPTY"),
            "a malformed file was reported as an empty one: {broken}"
        );
        assert!(!broken.contains(DECOY), "{broken}");

        // The remedy the malformed message prescribes: move it aside, because
        // the writer will not rewrite a file it cannot parse.
        store_entry(
            &path,
            "CLIENT_ID",
            &Secret::new("decoy-id-0177".to_owned()),
            None,
        )
        .expect_err("the writer refuses to overwrite what it cannot read");
        fs::remove_file(&path).expect("aside");

        // And a file with a login in it says how much is in it, so a rewrite
        // that dropped one half of a two-part identity is visible in the row
        // rather than only at the next lookup.
        store_entry(
            &path,
            "CLIENT_ID",
            &Secret::new("decoy-id-0177".to_owned()),
            None,
        )
        .expect("first");
        let one = inspect(&path, Some(owner)).expect("a sound file");
        assert!(one.contains("1 entry"), "{one}");
        store_entry(&path, "CLIENT_SECRET", &Secret::new(DECOY.to_owned()), None).expect("second");
        let two = inspect(&path, Some(owner)).expect("a sound file");
        assert!(two.contains("2 entries"), "{two}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_message_this_module_writes_can_carry_a_value() {
        // The blanket rule the rest of the crate holds to. Every sentence above
        // is built from a path, a mode and a uid, and this is what keeps it that
        // way as the wording changes.
        let dir = scratch("no-value");
        let path = dir.join("infisical.json");
        store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("stored");

        let owner = fs::metadata(&path).expect("stat").uid();

        // The contents are read now, so every sentence built from them is on
        // this list too — including the one about a file that cannot be parsed,
        // which is the sentence a parser would otherwise want to quote.
        let broken = dir.join("broken.json");
        fs::write(&broken, format!("{{\"BROKEN\": \"{DECOY}\"")).expect("create");
        fs::set_permissions(&broken, fs::Permissions::from_mode(MODE)).expect("chmod");

        let said = [
            inspect(&path, Some(owner)).unwrap_or_else(|e| e),
            inspect(&path, Some(owner + 1)).unwrap_or_else(|e| e),
            inspect(&path, None).unwrap_or_else(|e| e),
            inspect(&dir.join("absent.json"), Some(owner)).unwrap_or_else(|e| e),
            inspect(&broken, Some(owner)).unwrap_or_else(|e| e),
            store_entry(&dir, "X", &Secret::new(DECOY.to_owned()), None)
                .map(|()| String::new())
                .unwrap_or_else(|e| e.to_string()),
        ]
        .join(" ");
        assert!(!said.contains(DECOY), "{said}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// A uid and gid this process is not, and cannot become. `chown` to another
    /// uid is root's alone, so handing this pair to a write that reaches the
    /// syscall makes the refusal itself the evidence — which is the only way an
    /// unprivileged suite can watch an owner other than its own be applied.
    const NOT_THIS_PROCESS: Owner = (4242, 4243);

    /// This process's own uid and gid, read off a file it just made. The crate
    /// carries no libc dependency and does not need one for this.
    fn mine() -> Owner {
        let path = std::env::temp_dir().join(format!(
            "keyless-credential-whoami-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::write(&path, b"").expect("a file of my own");
        let meta = fs::metadata(&path).expect("stat");
        let _ = fs::remove_file(&path);
        (meta.uid(), meta.gid())
    }

    #[test]
    fn a_file_created_from_nothing_is_given_to_the_daemon_and_not_to_whoever_wrote_it() {
        // The defect, in the one form an unprivileged suite can actually watch.
        // A scratch directory is this process's, so a file written into one
        // carries this process's uid whatever the code decided — asserting that
        // uid would pass against the bug it is meant to catch. What cannot pass
        // by construction is a `chown` to somebody else: it is refused to
        // everybody but root, so the refusal naming the uid is proof the write
        // reached the syscall with the daemon's answer in hand. Before this
        // argument existed the same call succeeded silently and left the file
        // to whoever ran it.
        let dir = scratch("created-owner");
        let path = dir.join("proton.json");

        let refused = store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            Some(NOT_THIS_PROCESS),
        )
        .expect_err("this process cannot give a file to another uid");

        let said = refused.to_string();
        assert!(
            said.contains(&format!("uid {}", NOT_THIS_PROCESS.0)),
            "the write did not try to give the file to the daemon: {said}"
        );
        assert!(!said.contains(DECOY), "{said}");
        // Nothing half-made is left behind: the temporary goes with the refusal
        // and the target was never created.
        assert!(
            !path.exists(),
            "a refused write left a credential file behind"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_already_exists_keeps_its_own_owner_and_the_daemons_is_not_consulted() {
        // The preserving arm has to win, and the same uid that makes the case
        // above fail is what makes this one observable: were the daemon's
        // answer allowed to override an owner that already exists, this write
        // would be refused exactly as that one was. It succeeds, so the
        // existing owner was preferred rather than merely coinciding.
        let dir = scratch("existing-owner");
        let path = dir.join("proton.json");
        fs::write(&path, b"{}\n").expect("a file that already exists");
        fs::set_permissions(&path, fs::Permissions::from_mode(MODE)).expect("chmod");
        let before = fs::metadata(&path).expect("stat").uid();

        store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            Some(NOT_THIS_PROCESS),
        )
        .expect("an existing owner is preserved, so no foreign chown is attempted");

        let after = fs::metadata(&path).expect("stat").uid();
        assert_eq!(
            after, before,
            "the rewrite moved a file that already had an owner"
        );
        assert_eq!(
            fs::metadata(&path).expect("stat").mode() & 0o7777,
            MODE,
            "the rewrite widened the file"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_daemon_owner_infers_none_rather_than_guessing_one() {
        // A machine with no audit log has never run the daemon, so there is no
        // uid to attribute a new file to. The module refuses to NAME an owner
        // without evidence on the reading side — `inspect` reports and gives no
        // verdict — and this is the same refusal on the writing side: nothing is
        // inferred, the file keeps the uid that wrote it, and `inspect` is what
        // says so. A fallback invented here would be that guess, one file over.
        let dir = scratch("no-daemon-owner");
        let path = dir.join("proton.json");

        store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("a write with no daemon owner still writes");

        let file = fs::metadata(&path).expect("stat");
        assert_eq!(
            (file.uid(), file.gid()),
            mine(),
            "an owner was inferred where there was no evidence for one"
        );
        assert_eq!(file.mode() & 0o7777, MODE, "the write widened the file");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_generator_hands_the_daemons_owner_to_the_write_it_makes() {
        // The generator is the path the defect arrived on: it creates the entry
        // at first start, so on a machine whose credential file nobody made it
        // is what creates the file. A generator that resolved the owner and did
        // not pass it on would leave that file to whoever ran the daemon while
        // every other case here stayed green.
        let dir = scratch("generator-owner");
        let path = dir.join("proton.json");

        let refused = ensure_generated_entry(&path, "PROTON_LOCAL_KEY", Some(NOT_THIS_PROCESS))
            .expect_err("this process cannot give a file to another uid");

        let said = refused.to_string();
        assert!(
            said.contains(&format!("uid {}", NOT_THIS_PROCESS.0)),
            "the generated entry was written without the daemon's owner: {said}"
        );
        assert!(
            !path.exists(),
            "a refused generation left a credential file behind"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_daemons_owner_is_the_one_the_audit_log_carries() {
        // Writer and reader have to answer "the daemon's uid" out of the same
        // file, or a credential file can satisfy the write and fail `inspect`.
        // Both read it here: `daemon_owner` is what the caller passes in, and
        // `daemon_uid` is what `inspect` judges against. Pointed at a file this
        // process does not own, the pair answers with that file's uid rather
        // than with this process's — which is what makes it evidence rather
        // than a restatement of whoever is running.
        let (my_uid, _) = mine();
        let foreign = Path::new("/usr/bin/env");
        let meta = fs::metadata(foreign).expect("stat a file owned by somebody else");
        assert_ne!(
            meta.uid(),
            my_uid,
            "this case needs {} to be owned by somebody other than the suite",
            foreign.display()
        );

        assert_eq!(
            daemon_owner(foreign),
            Some(super::super::login::Owner {
                uid: meta.uid(),
                gid: meta.gid()
            })
        );
        assert_eq!(daemon_uid(foreign), Some(meta.uid()));

        // And an audit log that is not there is `None` rather than a guess,
        // which is the value `store_entry` reads as "infer nothing".
        let dir = scratch("no-audit-log");
        assert_eq!(daemon_owner(&dir.join("audit.jsonl")), None);
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod report_tests {
    use super::tests::DECOY;
    use super::*;
    use crate::daemon::config::DaemonConfig;

    fn config_from(json: &str) -> DaemonConfig {
        serde_json::from_str(json).expect("valid daemon config")
    }

    fn rendered(config: &DaemonConfig) -> (String, bool) {
        let mut out: Vec<u8> = Vec::new();
        let sound = report(config, &mut out).expect("a Vec never fails to be written");
        (String::from_utf8(out).expect("ASCII rows"), sound)
    }

    #[test]
    fn an_install_that_declares_no_vendor_login_says_nothing_about_one() {
        // The negative control for the whole row. A report that printed
        // "identity absent" on every install without Infisical would train a
        // reader to skip the line on the one install where it matters.
        //
        // The credential file is named explicitly and does not exist. Left at
        // its default this test would read whatever is under /usr/local on the
        // machine running it, and would start failing the day somebody
        // installed the daemon — which is a test reporting on a filesystem
        // rather than on a config.
        let dir = super::tests::scratch("no-login");
        let absent = dir.join("infisical.json");
        let (rows, sound) = rendered(&config_from(&format!(
            r#"{{"stores":{{"file":{{"enabled":true,"path":"{dir}/secrets.json"}},
                            "infisical":{{"credentials_file":"{absent}"}}}}}}"#,
            dir = dir.display(),
            absent = absent.display(),
        )));
        assert!(rows.is_empty(), "{rows}");
        assert!(sound);

        // And with Infisical on but no credential declared: still nothing, for
        // the same reason — a session-style install inherits its own login.
        let (rows, _) = rendered(&config_from(&format!(
            r#"{{"stores":{{"infisical":{{"enabled":true,
                                          "credentials_file":"{absent}"}}}},
                 "secrets":{{"X":{{"env":"fixture-env"}}}}}}"#,
            absent = absent.display(),
        )));
        assert!(rows.is_empty(), "{rows}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_login_on_disk_that_no_store_uses_is_a_row_rather_than_silence() {
        // What a config that lost its `infisical` block looks like from here.
        // Nothing else in the report can see that loss: no identity row, no
        // store row, no warning, and every name it served has quietly stopped
        // resolving. The credential file outlives the config and is the one
        // witness left.
        let dir = super::tests::scratch("orphan");
        let path = dir.join("infisical.json");
        store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("stored");

        let config = config_from(&format!(
            r#"{{"stores":{{"infisical":{{"credentials_file":"{path}"}}}}}}"#,
            path = path.display(),
        ));
        let (rows, sound) = rendered(&config);
        assert!(!sound, "{rows}");
        assert_eq!(
            rows.lines()
                .next()
                .expect("a row")
                .split_whitespace()
                .nth(1),
            Some("PROBLEM"),
            "{rows}"
        );
        assert!(rows.contains("REVOKE"), "{rows}");
        assert!(
            !rows.contains(DECOY),
            "the row carried the credential: {rows}"
        );

        // And an empty file left by an install that never used Infisical is
        // silence, or every such machine gets nagged forever.
        fs::write(&path, b"").expect("empty");
        let (rows, sound) = rendered(&config);
        assert!(rows.is_empty(), "{rows}");
        assert!(sound);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_vendors_orphaned_login_is_a_row_of_its_own() {
        // The row is per vendor, or a 1Password token left on disk after its
        // store block was lost would be exactly the file this report never
        // knew about. The sentence names the store whose block is missing, so
        // the reader edits the right one.
        let dir = super::tests::scratch("orphan-onepassword");
        let path = dir.join("onepassword.json");
        store_entry(
            &path,
            "SERVICE_ACCOUNT",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("stored");

        let config = config_from(&format!(
            r#"{{"stores":{{"onepassword":{{"credentials_file":"{path}"}}}}}}"#,
            path = path.display(),
        ));
        let (rows, sound) = rendered(&config);
        assert!(!sound, "{rows}");
        assert!(rows.contains("`onepassword` block"), "{rows}");
        assert!(rows.contains("1Password store"), "{rows}");
        assert!(
            !rows.contains("Infisical"),
            "the wrong vendor was named: {rows}"
        );
        assert!(
            !rows.contains(DECOY),
            "the row carried the credential: {rows}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_declared_login_is_reported_by_mode_and_owner_and_the_faults_read_apart() {
        let dir = super::tests::scratch("report");
        let path = dir.join("infisical.json");
        let audit = dir.join("audit.jsonl");
        std::fs::write(&audit, b"").expect("audit");
        store_entry(
            &path,
            "MACHINE_IDENTITY",
            &Secret::new(DECOY.to_owned()),
            None,
        )
        .expect("stored");

        let config = config_from(&format!(
            r#"{{"audit":"{audit}",
                 "stores":{{"infisical":{{"enabled":true,
                                          "credentials_file":"{path}",
                                          "credentials":{{"INFISICAL_TOKEN":"MACHINE_IDENTITY"}}}}}},
                 "secrets":{{"X":{{"env":"fixture-env"}}}}}}"#,
            audit = audit.display(),
            path = path.display(),
        ));

        // Sound. The row reads as a whole word, not as a substring: `ok` is a
        // suffix of nothing here, but the state column is what is being read
        // and a `contains` on it would pass on `PROBLEM ... not ok` too.
        let (rows, sound) = rendered(&config);
        assert!(sound, "{rows}");
        let state = rows
            .lines()
            .next()
            .expect("a row")
            .split_whitespace()
            .nth(1);
        assert_eq!(state, Some("ok"), "{rows}");
        assert!(rows.contains("store infisical"), "{rows}");
        assert!(
            !rows.contains(DECOY),
            "the row carried the credential: {rows}"
        );

        // Wrong mode.
        std::fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let (rows, sound) = rendered(&config);
        assert!(!sound, "{rows}");
        assert_eq!(
            rows.lines()
                .next()
                .expect("a row")
                .split_whitespace()
                .nth(1),
            Some("PROBLEM"),
            "{rows}"
        );
        assert!(rows.contains("mode 0644"), "{rows}");
        assert!(
            !rows.contains("chown"),
            "a mode fault named an owner fix: {rows}"
        );

        // Wrong owner, told apart from the mode fault by an audit log owned by
        // a uid this file is not owned by. Written as a separate file so the
        // two faults cannot be produced by the same edit.
        std::fs::set_permissions(&path, fs::Permissions::from_mode(MODE)).expect("chmod");
        let owner = fs::metadata(&path).expect("stat").uid();
        let misowned = inspect(&path, Some(owner + 1)).expect_err("a foreign owner");
        assert!(misowned.contains("chown"), "{misowned}");
        assert!(
            !misowned.contains("chmod"),
            "an owner fault named a mode fix: {misowned}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
