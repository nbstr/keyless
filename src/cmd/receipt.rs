//! What setup created, so that removing it can be exact.
//!
//! # Why a receipt exists at all
//!
//! An uninstaller has to answer one question — *did I put this here?* — and
//! there are only two ways to answer it. It can compare what it finds against a
//! list of things the installer ships, or it can read a record of what that
//! installer actually wrote. The first is cheaper and it is wrong, in a way that
//! is invisible until it costs somebody their configuration:
//!
//! ```text
//! before install   permissions.allow = ["Bash(keyless ls:*)"]      <- the user's own
//! install          already present, so nothing is added
//! uninstall        the rule is in the shipped list, so it is REMOVED
//! ```
//!
//! The install was a no-op and the uninstall was destructive. That asymmetry is
//! not a corner case: it fires for anybody who had already written the rule by
//! hand, which is exactly the population most likely to run this at all.
//!
//! # The second thing it buys: a deletion that stays deleted
//!
//! An install that re-adds what a user deliberately removed is the same fault
//! pointed the other way. Without a record, "never installed" and "installed and
//! then thrown out" are the same observation — an absent rule — and an installer
//! that treats them alike overwrites a decision every time it runs.
//!
//! With a record they are distinguishable, so setup re-adds nothing it has
//! already installed once. It says what is missing and offers `--restore`. That
//! is the difference between a tool that is idempotent and a tool that is
//! merely repeatable.
//!
//! # Why the hook installer writes into the same file
//!
//! `hooks/install.py` owns the merge into the agent's settings file, and it runs
//! standalone as well as under `keyless setup`. Two receipts would drift, so
//! there is one, and the two programs own disjoint keys in it: this module owns
//! `files`, the installer owns `claude`. Neither rewrites the other's key —
//! see `_load_receipt` in `hooks/install.py`.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit::sha256;
use crate::mask::encodings::hex_lower;

/// The schema version. Bumped only when an older receipt would be misread.
pub const VERSION: u32 = 1;

/// One file setup wrote in full.
///
/// Files that are MERGED into rather than written whole are not recorded here;
/// see [`Receipt::claude`], which records entries instead of a file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRecord {
    /// Where it is.
    pub path: PathBuf,
    /// Whether setup created it. A file that already existed is never deleted
    /// by an uninstall, whatever else is true of it.
    pub created: bool,
    /// The digest of the bytes setup wrote.
    ///
    /// Uninstall deletes only a file that still matches: an edited file is a
    /// file somebody took over, and taking it away would take their edit with
    /// it. Lower-case hex, so a person can compare it with `shasum -a 256`.
    pub sha256: String,
    /// Whether uninstall may remove it.
    ///
    /// `false` for anything that holds the user's own decisions — their config
    /// file above all. Removing the tool must not remove what they configured.
    pub remove_on_uninstall: bool,
}

/// What the hook installer merged into the agent's settings file.
///
/// Written by `hooks/install.py`, read by both. Entries rather than a digest,
/// because the file belongs to another program and is expected to change
/// underneath us for reasons that have nothing to do with this tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClaudeRecord {
    /// The settings file that was merged into.
    pub settings: PathBuf,
    /// Whether that file did not exist before.
    #[serde(default)]
    pub created: bool,
    /// The events a handler was registered on.
    #[serde(default)]
    pub events: Vec<String>,
    /// The `permissions.allow` rules that were added — never the ones that were
    /// already there.
    #[serde(default)]
    pub allow: Vec<String>,
    /// The `permissions.deny` rules that were added.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// The record of one setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Schema version.
    pub version: u32,
    /// The `keyless` that wrote it.
    #[serde(default)]
    pub tool_version: String,
    /// When, in UTC.
    #[serde(default)]
    pub written_at: String,
    /// Files written whole.
    #[serde(default)]
    pub files: Vec<FileRecord>,
    /// The agent settings merge, when there was one.
    #[serde(default)]
    pub claude: Option<ClaudeRecord>,
}

impl Default for Receipt {
    fn default() -> Self {
        Receipt {
            version: VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            written_at: crate::time::rfc3339_utc(crate::time::now_unix_millis()),
            files: Vec::new(),
            claude: None,
        }
    }
}

impl Receipt {
    /// Read the receipt at `path`, or `None` when there is none.
    ///
    /// A receipt that does not parse is reported rather than ignored. Silently
    /// treating it as absent would make an uninstall remove nothing and say
    /// nothing, which reads as "there was nothing to remove".
    ///
    /// # Errors
    ///
    /// The file exists and cannot be read or does not parse.
    pub fn load(path: &Path) -> io::Result<Option<Receipt>> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(problem) if problem.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(problem) => return Err(problem),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|problem| io::Error::other(format!("{}: {problem}", path.display())))
    }

    /// Write it, creating the parent directory.
    ///
    /// # Errors
    ///
    /// The directory cannot be created or the file cannot be written.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        std::fs::write(path, body + "\n")
    }

    /// The record for `path`, if setup wrote it.
    #[must_use]
    pub fn file(&self, path: &Path) -> Option<&FileRecord> {
        self.files.iter().find(|record| record.path == path)
    }

    /// Record a file, replacing any earlier record of the same path.
    pub fn record_file(&mut self, record: FileRecord) {
        self.files.retain(|existing| existing.path != record.path);
        self.files.push(record);
    }
}

/// The digest of `bytes`, in the form a receipt stores.
#[must_use]
pub fn digest_of(bytes: &[u8]) -> String {
    hex_lower(&sha256::digest(bytes))
}

/// Whether the file at `path` still holds exactly what was written.
///
/// `false` for a file that is absent, unreadable, or edited. All three mean the
/// same thing to an uninstaller — *do not delete this* — which is why one
/// function answers for all three rather than three call sites deciding.
#[must_use]
pub fn unchanged(path: &Path, expected: &str) -> bool {
    std::fs::read(path).is_ok_and(|bytes| digest_of(&bytes) == expected)
}

#[cfg(test)]
mod tests {
    use super::{ClaudeRecord, FileRecord, Receipt, digest_of, unchanged};
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-receipt-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn an_absent_receipt_is_none_and_not_an_error() {
        let dir = scratch("absent");
        assert!(
            Receipt::load(&dir.join("nothing.json"))
                .expect("no error")
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_receipt_is_an_error_rather_than_an_empty_one() {
        // An unreadable receipt reported as "nothing was installed" makes an
        // uninstall a silent no-op, which is the one outcome that leaves the
        // machine changed and the user told it was clean.
        let dir = scratch("corrupt");
        let path = dir.join("setup-receipt.json");
        std::fs::write(&path, "{ not json").expect("write");
        assert!(Receipt::load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `sha256("body")`, computed by `shasum -a 256` and written here as a
    /// literal.
    ///
    /// Deliberately not `digest_of(b"body")`. An expectation the code under
    /// test computes moves with that code, so the equality would hold whatever
    /// the digest function did — including returning the empty string for
    /// everything, which would make every uninstall delete every file.
    const BODY_DIGEST: &str = "230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5";

    #[test]
    fn a_receipt_round_trips_through_the_file() {
        let dir = scratch("round-trip");
        let path = dir.join("setup-receipt.json");
        let mut receipt = Receipt::default();
        receipt.record_file(FileRecord {
            path: dir.join("SKILL.md"),
            created: true,
            sha256: BODY_DIGEST.to_owned(),
            remove_on_uninstall: true,
        });
        receipt.claude = Some(ClaudeRecord {
            settings: dir.join("settings.json"),
            created: true,
            events: vec!["PreToolUse".to_owned()],
            allow: vec!["Bash(keyless ls:*)".to_owned()],
            deny: vec![],
        });
        receipt.save(&path).expect("save");

        let read = Receipt::load(&path).expect("load").expect("some");
        assert_eq!(read.version, 1);
        assert_eq!(read.files.len(), 1);
        assert_eq!(read.files[0].sha256, BODY_DIGEST);
        assert!(read.files[0].created);
        assert!(read.files[0].remove_on_uninstall);
        let claude = read.claude.expect("the installer's key survives the trip");
        assert_eq!(claude.events, ["PreToolUse"]);
        assert_eq!(claude.allow, ["Bash(keyless ls:*)"]);
        assert!(claude.deny.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_digest_is_the_real_sha256_of_what_it_is_given() {
        // The literal above is only worth anything if this is what the receipt
        // actually stores. One NIST vector plus the value the round trip uses.
        assert_eq!(
            digest_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest_of(b"body"), BODY_DIGEST);
    }

    #[test]
    fn recording_the_same_path_twice_keeps_one_record() {
        let mut receipt = Receipt::default();
        for body in [b"one".as_slice(), b"two".as_slice()] {
            receipt.record_file(FileRecord {
                path: PathBuf::from("/tmp/x"),
                created: true,
                sha256: digest_of(body),
                remove_on_uninstall: true,
            });
        }
        assert_eq!(receipt.files.len(), 1);
        assert_eq!(
            receipt.files[0].sha256,
            "3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3"
        );
    }

    #[test]
    fn an_edited_file_is_not_unchanged() {
        // The property uninstall rests on: a file somebody took over stays.
        let dir = scratch("edited");
        let path = dir.join("SKILL.md");
        std::fs::write(&path, "as written").expect("write");
        let recorded = "a51efc7c4bd2b4444723b58cee4847c45bafb5bdefa0362e13ba8e48fe395e89";
        assert!(unchanged(&path, recorded));
        std::fs::write(&path, "as written, plus my note").expect("write");
        assert!(!unchanged(&path, recorded));
        // And an absent file is not "unchanged" either, so a missing file is
        // never mistaken for one that matched.
        std::fs::remove_file(&path).expect("remove");
        assert!(!unchanged(&path, recorded));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
