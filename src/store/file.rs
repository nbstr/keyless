//! A flat file of names and values, readable only by the process that owns it.
//!
//! # Why this exists
//!
//! It is the concrete form of the sentence "the store credential lives on the
//! daemon's side of the boundary". A file at mode `0600` owned by the daemon's
//! uid is not readable by the calling user by any means short of `sudo` — no
//! wrapper, no deny rule and no file ACL is involved, just the uid the kernel
//! already enforces. That makes the boundary demonstrable rather than
//! asserted, which the keychain adapter cannot be: a keychain the daemon reads
//! is a keychain the daemon's user must own and unlock, and that setup cannot
//! be exercised without creating a second user.
//!
//! It is also what a migration lands in. The problem this whole daemon exists
//! for is that `security find-generic-password -s <service> -w` returns
//! plaintext with no prompt for anything in the calling user's login keychain.
//! Standing a daemon up does not change that by itself — the items are still in
//! that keychain and still readable. They have to *move* to something the
//! calling user cannot read, and then be deleted from where they were. This is
//! a destination that check can actually be run against.
//!
//! # The permission check is part of the store, not part of the installer
//!
//! [`FileStore`] refuses to read a file that any other user could read. An
//! installer that gets `chmod` wrong, an editor that rewrites the file with the
//! wrong mode, a `cp` that widened it — each of those turns the boundary into
//! nothing, silently. So the check runs on every read, and a widened file makes
//! the daemon report a backend error, which degrades every session and is very
//! loud. The alternative is a daemon that keeps serving from a world-readable
//! file and reports success.
//!
//! # And so is knowing whether there is anything in it
//!
//! A store file that has been emptied passes every permission check there is.
//! `install -m 0600 /dev/null <path>` is what empties one — it reads as "create
//! the file" and is a copy — and what it leaves behind is `0600`, owned by the
//! daemon, and worth nothing. So [`FileStore::health`] classifies the contents
//! as well, and an empty file is a fault rather than a store that happens to
//! have no names in it. That is the same refusal the audit log makes when rows
//! go missing from the end of it: losing data is bad, and losing it and then
//! reporting sound is what makes it impossible to notice.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;

/// Bits that must be clear on the file's mode: group and other, all of them.
const FORBIDDEN_MODE_BITS: u32 = 0o077;

/// What a store file's bytes are, before any name is looked for in them.
///
/// # Why this is one function and not two
///
/// Two programs read this shape of file: this store, and
/// [`crate::daemon::credential`], which writes the daemon's own vendor login
/// into one. They disagreed about the same bytes. The writer treated an
/// all-whitespace file as a store with nothing in it — which is what the
/// installer leaves behind, so it had to — and this store called those same
/// bytes malformed. So *"you have not put anything in it yet"* was reported to
/// the operator as *"your credential file is corrupt"*, and the two states have
/// completely different remedies.
///
/// Deciding it once means the verdict on a given file cannot depend on which
/// program opened it. What the two still do differ on is what an EMPTY store
/// means for their verb, and that difference is now explicit: writing into one
/// is ordinary, reading a name out of one cannot succeed.
///
/// # The values are live
///
/// [`Contents::Entries`] holds plaintext. Every caller here scrubs it before it
/// drops; that obligation travels with this type and is not enforced by it,
/// because a `Drop` impl would stop the one caller that must move an entry out.
pub enum Contents {
    /// Nothing but whitespace, including nothing at all.
    ///
    /// A file, not a fault — but a store with no names in it, and a name asked
    /// of it cannot be answered.
    Empty,
    /// A JSON object of names to values.
    Entries(BTreeMap<String, String>),
    /// Not that, at this position.
    ///
    /// The position and never the bytes: serde's own message quotes the input
    /// around the failure, and the input is a file of plaintext secrets.
    Malformed {
        /// One-based line the parse gave up on.
        line: usize,
        /// One-based column the parse gave up on.
        column: usize,
    },
}

/// Read one store file's bytes as one of the three things they can be.
#[must_use]
pub fn classify(bytes: &[u8]) -> Contents {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Contents::Empty;
    }
    match serde_json::from_slice::<BTreeMap<String, String>>(bytes) {
        Ok(entries) => Contents::Entries(entries),
        Err(error) => Contents::Malformed {
            line: error.line(),
            column: error.column(),
        },
    }
}

/// A JSON object of `{"NAME": "value"}` at a path only its owner can read.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    /// Point at a file. Nothing is read until a resolve.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        FileStore { path }
    }

    /// The file this store reads.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn unavailable(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Unavailable {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }

    fn backend(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Backend {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }

    /// The file, read and classified. Its bytes are scrubbed on the way out.
    fn contents(&self) -> Result<Contents, StoreError> {
        let mut raw = fs::read(&self.path)
            .map_err(|source| self.unavailable(format!("cannot read: {source}")))?;
        let contents = classify(&raw);
        raw.zeroize();
        Ok(contents)
    }

    /// Why an empty store file is a fault and not a state to pass over.
    ///
    /// Both readings are named because nothing on disk distinguishes them, and
    /// the operator is the only one who knows which it is. Saying only the
    /// first would make a wipe read as a fresh install.
    fn empty_detail(&self) -> String {
        format!(
            "{} holds no names at all — it is empty. Either nothing has been put in it yet, \
             or it was truncated or rewritten and what was in it is gone",
            self.path.display()
        )
    }

    /// Why a store file that is not a JSON object cannot be served from.
    fn malformed_detail(&self) -> String {
        format!(
            "{} is not a JSON object of names to values",
            self.path.display()
        )
    }

    /// Refuse a file any other user can read.
    fn check_permissions(&self) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&self.path)
                .map_err(|source| self.unavailable(format!("cannot stat: {source}")))?;
            let mode = meta.permissions().mode();
            if mode & FORBIDDEN_MODE_BITS != 0 {
                return Err(self.backend(format!(
                    "{} is mode {:04o}; a secret store must not be readable by group or other",
                    self.path.display(),
                    mode & 0o7777
                )));
            }
        }
        Ok(())
    }
}

impl Store for FileStore {
    fn id(&self) -> &str {
        "file"
    }

    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        self.check_permissions()?;

        let mut entries = match self.contents()? {
            Contents::Entries(entries) => entries,
            Contents::Empty => return Err(self.backend(self.empty_detail())),
            // The position is dropped here rather than reported. It is safe to
            // print — see [`Contents::Malformed`] — and this message is the one
            // a session sees when a lookup degrades, where a line number is
            // noise; `keylessd check` is where it is worth having.
            Contents::Malformed { .. } => return Err(self.backend(self.malformed_detail())),
        };

        let found = entries.remove(name);
        // Every other value was allocated by the parse and is about to be
        // dropped. Scrub them rather than leaving them for the allocator.
        for (_, mut value) in entries {
            value.zeroize();
        }

        match found {
            None => Ok(None),
            Some(value) if value.is_empty() => Err(self.backend(format!(
                "`{name}` is present in {} but its value is empty",
                self.path.display()
            ))),
            Some(value) => Ok(Some(Secret::new(value))),
        }
    }

    /// Whether this store could answer anything at all.
    ///
    /// The mode, and then the contents. A store file that is empty passes every
    /// permission check there is and can serve no name, and that is exactly
    /// what a `install -m 0600 /dev/null` over a full store leaves behind — so
    /// a health check that stopped at the mode reported a store that had just
    /// been wiped as sound. It is the same fault the audit log already refuses
    /// to be quiet about when rows go missing from the end of it.
    ///
    /// The values are read and scrubbed without being returned, counted or
    /// named anywhere. What comes back out of here is one of three verdicts
    /// about the file, never anything that was in it.
    fn health(&self) -> Result<(), StoreError> {
        self.check_permissions()?;
        match self.contents()? {
            Contents::Entries(mut entries) => {
                for value in entries.values_mut() {
                    value.zeroize();
                }
                Ok(())
            }
            Contents::Empty => Err(self.backend(self.empty_detail())),
            Contents::Malformed { line, column } => Err(self.backend(format!(
                "{} (line {line}, column {column})",
                self.malformed_detail()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FileStore;
    use crate::store::Store;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn write_store(tag: &str, body: &str, mode: u32) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "keyless-filestore-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, body).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn a_name_resolves_from_a_locked_down_file() {
        let path = write_store("ok", r#"{"DECOY":"decoy-file-value-0001"}"#, 0o600);
        let store = FileStore::new(path.clone());
        let secret = store.resolve("DECOY").expect("resolve").expect("present");
        assert_eq!(secret.expose(), "decoy-file-value-0001");
        assert!(store.health().is_ok());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_absent_name_is_none_rather_than_an_error() {
        let path = write_store("absent", r#"{"OTHER":"decoy"}"#, 0o600);
        let store = FileStore::new(path.clone());
        assert!(store.resolve("DECOY").expect("resolve").is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_group_readable_file_is_refused() {
        // The boundary is the file mode. A store that read this anyway would
        // be serving from something the calling user can open directly.
        let path = write_store("loose", r#"{"DECOY":"decoy-leaked"}"#, 0o640);
        let store = FileStore::new(path.clone());
        let error = store
            .resolve("DECOY")
            .expect_err("a group-readable secret store must be refused");
        assert!(error.to_string().contains("0640"), "{error}");
        assert!(store.health().is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_world_readable_file_is_refused() {
        let path = write_store("world", r#"{"DECOY":"decoy-leaked"}"#, 0o644);
        let store = FileStore::new(path.clone());
        assert!(store.resolve("DECOY").is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_missing_file_is_unavailable_rather_than_a_panic() {
        let store = FileStore::new(PathBuf::from("/nonexistent/keyless/secrets.json"));
        let error = store.resolve("X").expect_err("missing file");
        assert!(error.to_string().contains("unavailable"));
    }

    #[test]
    fn a_malformed_file_does_not_echo_its_contents_into_the_error() {
        // serde's parse errors quote the input around the failure, and the
        // input here is a file of plaintext secrets.
        let path = write_store(
            "malformed",
            r#"{"DECOY":"decoy-must-not-be-quoted-8823" oops}"#,
            0o600,
        );
        let store = FileStore::new(path.clone());
        let error = store.resolve("DECOY").expect_err("malformed");
        let rendered = error.to_string();
        assert!(
            !rendered.contains("8823"),
            "the store's contents reached an error message: {rendered}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_empty_file_is_empty_rather_than_malformed_and_is_never_healthy() {
        // Two readers used to give these bytes opposite verdicts. The daemon's
        // credential writer called an all-whitespace file a store with nothing
        // in it — it had to, because that is what the installer leaves — and
        // this store called it malformed, so "you have not put anything in yet"
        // reached the operator as "your file is corrupt".
        //
        // The health check is the half that matters after a truncation:
        // `install -m 0600 /dev/null` over a full store leaves a file that
        // passes every permission check there is and can serve nothing.
        for body in ["", "  \n\t\n"] {
            let path = write_store("empty-file", body, 0o600);
            let store = FileStore::new(path.clone());

            let resolving = store
                .resolve("DECOY")
                .expect_err("a store with nothing in it cannot answer a name")
                .to_string();
            assert!(resolving.contains("holds no names"), "{resolving}");
            assert!(
                !resolving.contains("not a JSON object"),
                "an empty store was reported as a broken one: {resolving}"
            );

            let health = store
                .health()
                .expect_err("an empty store is not a healthy one")
                .to_string();
            assert!(health.contains("holds no names"), "{health}");
            // Both readings, because nothing on disk tells them apart and only
            // the operator knows which happened.
            assert!(health.contains("truncated"), "{health}");

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn a_malformed_file_is_unhealthy_and_says_where_without_saying_what() {
        let path = write_store(
            "malformed-health",
            r#"{"DECOY":"decoy-must-not-be-quoted-4471" oops}"#,
            0o600,
        );
        let store = FileStore::new(path.clone());
        let health = store.health().expect_err("malformed").to_string();
        assert!(health.contains("not a JSON object"), "{health}");
        assert!(health.contains("line 1"), "{health}");
        assert!(
            !health.contains("4471"),
            "the store's contents reached a health message: {health}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_empty_value_is_an_error_rather_than_a_silent_blank() {
        let path = write_store("empty", r#"{"DECOY":""}"#, 0o600);
        let store = FileStore::new(path.clone());
        assert!(store.resolve("DECOY").is_err());
        let _ = std::fs::remove_file(path);
    }
}
