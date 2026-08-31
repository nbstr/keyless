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
//! # Writing it
//!
//! [`store_entry`] is the only writer, and it takes a [`Secret`] rather than a
//! string, has no way to accept a value from an argument, and prints nothing.
//! The value reaches it from stdin — echoed nowhere, in no shell history and in
//! no process table — which is the same discipline `keyless put` follows and
//! the reason neither verb has a `--value` flag.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::secret::Secret;
use crate::store::file::Contents;

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
    fs::metadata(audit).ok().map(|meta| meta.uid())
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
                "{} does not exist, so every Infisical lookup will degrade. The installer \
                 creates it empty and owned by the daemon; `{} credential --name <entry>` \
                 fills it without the value passing through a command line",
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
             {expected} — so the daemon cannot read its own login and every Infisical \
             lookup will degrade. Run: chown {expected} {}",
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
            "{} is mode {MODE:04o} and the daemon's, and it is EMPTY — no login has been put \
             in it, so every Infisical lookup will degrade. That is the state a fresh \
             install leaves; fill it with `{} credential --name <entry>`, which takes no \
             value on a command line",
            path.display(),
            crate::DAEMON_NAME
        )),
        Contents::Malformed { line, column } => Err(format!(
            "{} is mode {MODE:04o} and the daemon's, and it is not a JSON object of name to \
             value (line {line}, column {column}) — so nothing can be read out of it and \
             every Infisical lookup will degrade. `{} credential` will not rewrite it, \
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
    if !config.stores.infisical.enabled || config.stores.infisical.credentials.is_empty() {
        return orphaned(config, out);
    }
    let path = config.stores.infisical.credentials_file.to_path_buf();
    let sound = match inspect(&path, daemon_uid(config.audit.as_path())) {
        Ok(detail) => {
            writeln!(out, "identity ok {detail}")?;
            true
        }
        Err(detail) => {
            writeln!(out, "identity PROBLEM {detail}")?;
            false
        }
    };
    writeln!(
        out,
        "         whether Infisical accepts it is the `store infisical` row below"
    )?;
    Ok(sound)
}

/// A vendor login on disk that this config gives nothing to do.
///
/// The one thing `check` can see of a config that lost its `infisical` block.
/// Nothing in the daemon remembers what the config used to say, so a store
/// deleted from it leaves no trace at all — no identity row, no `store
/// infisical` row, no warning — and the report is fully green while every
/// Infisical name has stopped resolving. What does survive is the credential
/// FILE, because it lives outside the config, and a file with a login in it
/// that no store is configured to use is either that accident or an install
/// somebody reconfigured and never cleaned up.
///
/// Both are worth a red row. The second is what `install/uninstall.sh` argues
/// at length is a landmine: a long-lived credential left on a machine with
/// nothing to use it, still valid at the vendor, that nobody is thinking about.
///
/// Silence for a file that is absent, empty, or unreadable from here — an
/// install that never used Infisical must not be nagged, and a guess made
/// through a permission error would be exactly that.
fn orphaned(config: &super::config::DaemonConfig, out: &mut dyn io::Write) -> io::Result<bool> {
    let path = config.stores.infisical.credentials_file.to_path_buf();
    let holds_something = fs::metadata(&path).is_ok_and(|meta| meta.len() > 0);
    if !holds_something {
        return Ok(true);
    }
    writeln!(
        out,
        "identity PROBLEM {} holds a vendor login and nothing in this config uses it: the \
         Infisical store is not enabled here, or names no credential. Either the `infisical` \
         block was lost out of this config — in which case every name it served has stopped \
         resolving, silently — or the login is left over, in which case delete it and REVOKE \
         the identity at the vendor",
        path.display()
    )?;
    Ok(false)
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
/// # Errors
///
/// [`CredentialError`] naming the step that failed. Nothing here is printed and
/// no error carries the value.
pub fn store_entry(path: &Path, name: &str, value: &Secret) -> Result<(), CredentialError> {
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

    let result = write_atomically(path, &body, owner);
    body.zeroize();
    result
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

/// Rename a fresh `0600` file over the old one, keeping its owner.
fn write_atomically(path: &Path, body: &[u8], owner: Option<Owner>) -> Result<(), CredentialError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let temporary = match parent {
        Some(dir) => dir.join(format!(
            ".{}.new",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("credentials")
        )),
        None => return Err(io_error(path, "has no directory to write into")),
    };

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
            format!("cannot be given back to uid {uid}: {error}"),
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

    #[test]
    fn a_written_entry_is_readable_by_the_file_store_and_by_nobody_else() {
        let dir = scratch("write");
        let path = dir.join("infisical.json");
        store_entry(&path, "MACHINE_IDENTITY", &Secret::new(DECOY.to_owned())).expect("stored");

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
        store_entry(&path, "CLIENT_ID", &Secret::new("decoy-id-0909".to_owned())).expect("first");
        store_entry(&path, "CLIENT_SECRET", &Secret::new(DECOY.to_owned())).expect("second");

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
        store_entry(&path, "MACHINE_IDENTITY", &Secret::new(DECOY.to_owned())).expect("stored");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_file_is_refused_without_quoting_what_it_holds() {
        let dir = scratch("malformed");
        let path = dir.join("infisical.json");
        fs::write(&path, format!("{{\"BROKEN\": \"{DECOY}\"")).expect("create");
        let said = store_entry(&path, "X", &Secret::new("decoy-x".to_owned()))
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
    fn the_three_faults_are_reported_apart_from_each_other() {
        let dir = scratch("inspect");
        let path = dir.join("infisical.json");

        let missing = inspect(&path, Some(300)).expect_err("nothing is there");
        assert!(missing.contains("does not exist"), "{missing}");

        store_entry(&path, "MACHINE_IDENTITY", &Secret::new(DECOY.to_owned())).expect("stored");
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
        store_entry(&path, "CLIENT_ID", &Secret::new("decoy-id-0177".to_owned()))
            .expect_err("the writer refuses to overwrite what it cannot read");
        fs::remove_file(&path).expect("aside");

        // And a file with a login in it says how much is in it, so a rewrite
        // that dropped one half of a two-part identity is visible in the row
        // rather than only at the next lookup.
        store_entry(&path, "CLIENT_ID", &Secret::new("decoy-id-0177".to_owned())).expect("first");
        let one = inspect(&path, Some(owner)).expect("a sound file");
        assert!(one.contains("1 entry"), "{one}");
        store_entry(&path, "CLIENT_SECRET", &Secret::new(DECOY.to_owned())).expect("second");
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
        store_entry(&path, "MACHINE_IDENTITY", &Secret::new(DECOY.to_owned())).expect("stored");

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
            store_entry(&dir, "X", &Secret::new(DECOY.to_owned()))
                .map(|()| String::new())
                .unwrap_or_else(|e| e.to_string()),
        ]
        .join(" ");
        assert!(!said.contains(DECOY), "{said}");

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
        store_entry(&path, "MACHINE_IDENTITY", &Secret::new(DECOY.to_owned())).expect("stored");

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
    fn a_declared_login_is_reported_by_mode_and_owner_and_the_faults_read_apart() {
        let dir = super::tests::scratch("report");
        let path = dir.join("infisical.json");
        let audit = dir.join("audit.jsonl");
        std::fs::write(&audit, b"").expect("audit");
        store_entry(&path, "MACHINE_IDENTITY", &Secret::new(DECOY.to_owned())).expect("stored");

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
