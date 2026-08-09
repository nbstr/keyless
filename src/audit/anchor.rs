//! The one fact about the log that is not stored *in* the log: which row is
//! last.
//!
//! # Why the chain needs this at all
//!
//! Each row hashes its predecessor's hash, so editing or removing a row in the
//! middle breaks every row after it. Removing rows from the END breaks nothing:
//! what is left is a chain that is internally perfect and simply shorter.
//! **Nothing inside a file can say how long that file was supposed to be.** So
//! the fact has to live beside it.
//!
//! Measured before this existed: dropping the last row of a real log made
//! `keyless doctor` report no problem and exit 0, while dropping a middle row
//! was reported as `audit chain broken at line 2`. Tail truncation is also the
//! *common* case — a naive rotation, a restore from a stale copy, a stray
//! `head -n -1` — so the undetected half was the half that happens.
//!
//! # What this defends against, stated exactly
//!
//! The anchor is an ordinary file, written by the same process, in the same
//! directory, with the same permissions as the log. So:
//!
//! * **It detects accident.** A rotation that moves the log aside, a restore
//!   that puts back a shorter file, a truncating copy, a `head -n`. None of
//!   those touch the anchor, and all of them are then named rather than
//!   silently accepted.
//! * **It detects a rewrite by anything confined to the log file.** Recomputing
//!   every hash from genesis produces a file that verifies; it does not produce
//!   the row the anchor names.
//! * **On a log the writer owns, it does not defend against an adversary.**
//!   Whoever can rewrite the log can rewrite or delete the anchor beside it,
//!   and a deleted anchor reads as a log written before this existed. That is
//!   the bound the chain already has, and nothing here moves it.
//!
//! The one deployment where that last line reads differently is the installed
//! one, and it is not an accident of layout. `install/install.sh` creates
//! `/usr/local/var/log/keyless` mode `0755` owned by the daemon's uid, so a
//! session can read that directory and cannot create, rename or unlink
//! anything in it. The anchor is therefore on the same side of the privilege
//! boundary as the log it guards: a session can no more remove the anchor than
//! it can rewrite the log, and the anchor's guarantee tracks the log's exactly
//! instead of being the weaker of the two. Whoever changes that directory's
//! mode weakens both at once — which is the right coupling, because a
//! detection that can be switched off from outside is not one.
//!
//! # Why a hash and not a row count
//!
//! A count is the obvious content and it is the wrong one. It has to be
//! maintained (an extra O(n) read per append, or a sequence number in every
//! row), and it breaks the moment the log is rotated: a rotation that archives
//! old rows and keeps the newest leaves a live file whose row count is smaller
//! by design, which a count-based anchor reports as truncation forever.
//!
//! A hash costs nothing to maintain — the writer has just computed it — and
//! survives rotation, because the row it names is still in the segment that was
//! kept. The check is "is the anchored row still here?", which is the question
//! actually being asked.
//!
//! # The anchor may lag. It may never lead.
//!
//! The row is written first and the anchor second, so a crash between the two
//! leaves the anchor pointing at an earlier row. That direction is normal and
//! is reported as nothing at all. The reverse — an anchored row the log no
//! longer contains — is the only condition this file exists to name.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::AuditError;

/// Format of the anchor file itself, independent of the row schema.
const ANCHOR_VERSION: u32 = 1;
/// Appended to the log's file name, never substituted for its extension.
const SUFFIX: &str = ".anchor";

/// Distinguishes the temporary files of concurrent writers inside one process.
/// The lock on the log already serialises them; this costs one atomic and
/// removes the assumption.
static NONCE: AtomicU64 = AtomicU64::new(0);

/// The last row the writer knows it wrote.
#[derive(Debug, Serialize, Deserialize)]
pub struct Anchor {
    /// Anchor format version. A version this build does not know is refused
    /// rather than ignored — a newer anchor makes a stronger claim, and
    /// skipping it would turn an upgrade into a silent loss of detection.
    pub v: u32,
    /// Chain hash of the last row written, lower-case hex.
    pub hash: String,
}

/// The anchor that belongs to a log.
///
/// The suffix is appended to the whole file name, so `audit.jsonl` anchors at
/// `audit.jsonl.anchor`. Replacing the extension would collide with a log
/// literally named `audit.anchor`.
#[must_use]
pub fn path_for(log: &Path) -> PathBuf {
    let mut raw = log.as_os_str().to_owned();
    raw.push(SUFFIX);
    PathBuf::from(raw)
}

/// Read the anchor beside a log.
///
/// `Ok(None)` means there is none — a log written before this existed, which
/// verifies exactly as it always did. Present-but-unreadable is an error and
/// never `None`: a single stray byte must not turn the check off quietly.
pub fn read(log: &Path) -> Result<Option<Anchor>, AuditError> {
    let path = path_for(log);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(AuditError::Io { path, source }),
    };

    let anchor: Anchor = serde_json::from_str(&raw).map_err(|error| AuditError::Anchor {
        detail: format!(
            "{} exists but cannot be read ({error}); \
             the tail of the log is unchecked until it is repaired or removed",
            path.display()
        ),
    })?;

    if anchor.v != ANCHOR_VERSION {
        return Err(AuditError::Anchor {
            detail: format!(
                "{} is version {}, and this build understands version {ANCHOR_VERSION}; \
                 a newer anchor is refused rather than skipped",
                path.display(),
                anchor.v
            ),
        });
    }
    Ok(Some(anchor))
}

/// Record which row is last, replacing the previous anchor atomically.
///
/// Written to a temporary file, flushed, and renamed over the old one, so a
/// crash mid-write leaves the previous anchor intact rather than a half-written
/// one. The flush is deliberate and is the reason a corrupt anchor is a
/// condition worth reporting instead of a routine consequence of a hard kill.
///
/// The directory is not flushed. A rename that is lost leaves the anchor
/// pointing at an earlier row, which is the harmless direction.
pub fn write(log: &Path, mode: u32, hash: &str) -> Result<(), AuditError> {
    let path = path_for(log);
    let body = serde_json::to_string(&Anchor {
        v: ANCHOR_VERSION,
        hash: hash.to_owned(),
    })
    .map_err(|error| AuditError::Encode(error.to_string()))?;

    let mut temp = path.clone().into_os_string();
    temp.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let temp = PathBuf::from(temp);

    let written = write_temp_then_rename(&temp, &path, mode, body.as_bytes());
    // Unconditional, and not guarded by `written.is_err()`. On success the
    // rename already moved the temporary file away and this is a no-op; on
    // failure it removes what would otherwise accumulate, one per failure. A
    // branch here would be one no test can reach without a failing filesystem,
    // which is a branch that can be deleted or inverted with nothing noticing.
    let _ = fs::remove_file(&temp);
    written.map_err(|source| AuditError::Io { path, source })
}

fn write_temp_then_rename(
    temp: &Path,
    final_path: &Path,
    mode: u32,
    body: &[u8],
) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    let mut file = options.open(temp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Set explicitly rather than via the open mode: a temporary file left
        // by an earlier crash is truncated, not created, and would otherwise
        // keep whatever mode it already had.
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    file.write_all(body)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temp, final_path)
}

#[cfg(test)]
mod tests {
    use crate::error::AuditError;
    use std::path::{Path, PathBuf};

    fn temp_log(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "keyless-anchor-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("temp dir");
        path.push("audit.jsonl");
        path
    }

    #[test]
    fn an_anchor_that_cannot_be_read_is_an_error_and_never_absent() {
        // `Ok(None)` carries a specific meaning: there is no anchor, so verify
        // the log exactly as a build without this feature would. Collapsing any
        // OTHER read failure into that answer switches the tail check off and
        // says nothing — a permissions problem, or a directory sitting where
        // the anchor belongs, would silently restore the very hole this module
        // exists to close.
        //
        // Unreadable is arranged with a directory rather than with a mode,
        // because a suite running as root can read a mode-000 file and the test
        // would then prove nothing on exactly the machines that run it in a
        // container.
        let log = temp_log("unreadable");
        let anchor = super::path_for(&log);
        std::fs::create_dir_all(&anchor).expect("stand in for an unreadable anchor");

        let error = super::read(&log).expect_err("an unreadable anchor must not read as absent");
        assert!(
            matches!(error, AuditError::Io { .. }),
            "the failure must be reported as I/O: {error}"
        );

        let _ = std::fs::remove_dir_all(log.parent().expect("parent"));
    }

    #[test]
    fn an_anchor_that_is_simply_not_there_is_absent_and_not_an_error() {
        // The control for the test above, and the reason it cannot be satisfied
        // by returning an error unconditionally. Every log written before this
        // module existed reaches exactly this path.
        let absent = Path::new("/nonexistent/keyless-anchor/audit.jsonl");
        assert!(
            super::read(absent)
                .expect("an absent anchor is not a failure")
                .is_none(),
            "a missing anchor must be reported as absent, not as present"
        );
    }
}
