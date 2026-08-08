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

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;

/// Bits that must be clear on the file's mode: group and other, all of them.
const FORBIDDEN_MODE_BITS: u32 = 0o077;

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

        let mut raw = fs::read(&self.path)
            .map_err(|source| self.unavailable(format!("cannot read: {source}")))?;
        let parsed = serde_json::from_slice::<BTreeMap<String, String>>(&raw);
        raw.zeroize();

        // The parse error is reported without its position, because serde's
        // message quotes the input around the failure and the input is a file
        // of plaintext secrets.
        let mut entries = parsed.map_err(|_| {
            self.backend(format!(
                "{} is not a JSON object of names to values",
                self.path.display()
            ))
        })?;

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

    fn health(&self) -> Result<(), StoreError> {
        self.check_permissions()
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
    fn an_empty_value_is_an_error_rather_than_a_silent_blank() {
        let path = write_store("empty", r#"{"DECOY":""}"#, 0o600);
        let store = FileStore::new(path.clone());
        assert!(store.resolve("DECOY").is_err());
        let _ = std::fs::remove_file(path);
    }
}
