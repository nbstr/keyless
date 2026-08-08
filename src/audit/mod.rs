//! Append-only JSONL record of what ran, what was named, and what happened.
//!
//! # What is never in here
//!
//! A value. Not raw, not encoded, not hashed. The argv is masked with the same
//! [`Masker`] that redacts the child's output, so a value typed on the command
//! line — which is exactly the habit this tool exists to replace — is recorded
//! as `[keyless:NAME]` rather than as itself.
//!
//! # The chain, and what it is actually worth
//!
//! Each row carries `sha256(previous_row_hash || this_row_bytes)`. That is the
//! real construction, not the decorative one: the hash covers the payload and
//! links to the previous *hash* rather than to some id, so editing or deleting
//! any row breaks every row after it.
//!
//! **Its integrity is bounded by who can write the file.** A process that can
//! append can also rewrite the whole file and recompute every hash. The chain
//! therefore detects accidental truncation, partial writes, and tampering by
//! anything that cannot rewrite the file — and does not detect tampering by the
//! session itself. Making it detect that requires the writer to be a process
//! the session cannot impersonate, which is the privilege-boundary daemon's
//! job. The verifier here is what that daemon will use unchanged.
//!
//! # Concurrency
//!
//! ~20 agent sessions can append at once. Two defences, because either alone
//! has a hole: an exclusive advisory lock held across read-tail-and-append, and
//! a hard cap that keeps a row under `PIPE_BUF` so a single `write` stays
//! atomic even where the lock is not honoured. Long argv is truncated rather
//! than allowed to interleave with another session's row.

pub mod sha256;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::State;
use crate::error::AuditError;
use crate::mask::Masker;
use crate::mask::encodings::hex_lower;
use crate::time;

/// Hard ceiling on one serialized row, chosen to stay under macOS's 4096-byte
/// `PIPE_BUF` so the append remains a single atomic write.
pub const MAX_LINE_BYTES: usize = 4000;
/// Per-argument cap before truncation.
pub const MAX_ARG_CHARS: usize = 200;
/// Cap on recorded argv elements.
pub const MAX_ARGS: usize = 64;
/// Cap on recorded names.
pub const MAX_NAMES: usize = 64;
/// Cap on a recorded image path, so a deep path cannot crowd out the rest of a
/// row.
pub const MAX_IMAGE_CHARS: usize = 120;
/// Schema version, so a later reader can tell rows apart.
///
/// Still 1 after the daemon's peer fields were added, and deliberately: every
/// new field is `Option` with `skip_serializing_if`, so a row written by the
/// session binary is byte-for-byte what it was before, and an old row still
/// verifies. A version bump would be a claim that old rows need different
/// handling, and they do not.
const SCHEMA_VERSION: u32 = 1;
/// The chain's starting value.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Byte offset at which the payload begins: `{"hash":"` + 64 hex + `",`.
const PAYLOAD_OFFSET: usize = 9 + 64 + 2;

/// The verified identity of whoever asked the daemon for something.
///
/// Every field here comes from the kernel and was cross-checked before this
/// struct could be built — see [`crate::ipc::peer`]. Nothing a caller *claimed*
/// appears in it; a claim goes in the row's `cwd` and `argv`, which are labelled
/// as claims in this module's documentation and must never be read as facts.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Effective uid.
    pub uid: u32,
    /// Process id.
    pub pid: i32,
    /// Pid generation, which distinguishes this process from a later one that
    /// reuses its pid.
    pub generation: i32,
    /// A process identifier the kernel never reuses.
    pub unique_id: u64,
    /// Code directory hash of the running image, lower-case hex.
    pub code_hash: String,
    /// Path of the running image. Diagnostic; clipped on the way in.
    pub image: String,
}

/// One thing that happened.
#[derive(Debug, Clone)]
pub struct Event {
    verb: String,
    state: State,
    cwd: String,
    names: Vec<String>,
    unresolved: Vec<String>,
    argv: Vec<String>,
    argv_truncated: bool,
    exit_code: Option<i32>,
    peer: Option<Peer>,
    decision: Option<String>,
    identities: Vec<String>,
}

impl Event {
    /// Build an event, masking the argv on the way in.
    ///
    /// Taking the masker rather than pre-masked strings is the point: there is
    /// no way to construct an `Event` that skipped redaction.
    #[must_use]
    pub fn new<S: AsRef<std::ffi::OsStr>>(
        verb: &str,
        state: State,
        names: Vec<String>,
        argv: &[S],
        masker: &Masker,
    ) -> Self {
        let mut truncated = argv.len() > MAX_ARGS || names.len() > MAX_NAMES;
        let masked: Vec<String> = argv
            .iter()
            .take(MAX_ARGS)
            .map(|arg| {
                let text = masker.mask_str(&arg.as_ref().to_string_lossy());
                let (clipped, was_clipped) = clip(&text, MAX_ARG_CHARS);
                truncated |= was_clipped;
                clipped
            })
            .collect();

        let mut names = names;
        names.truncate(MAX_NAMES);

        Event {
            verb: verb.to_owned(),
            state,
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| String::from("?")),
            names,
            unresolved: Vec::new(),
            argv: masked,
            argv_truncated: truncated,
            exit_code: None,
            peer: None,
            decision: None,
            identities: Vec::new(),
        }
    }

    /// Record which store identity or identities the values came from or went to.
    ///
    /// `keychain (reader)`, `proton (reader)`, `proton (manager)`. There are now
    /// two identities per backend that has one, and a row that does not say which
    /// answered cannot settle the question a two-identity split exists to make
    /// answerable: did a `run` ever act as the writer?
    ///
    /// Optional and skipped when empty, like every field added since schema
    /// version 1, so a row from a build that never sets it still verifies.
    #[must_use]
    pub fn with_identities(mut self, mut identities: Vec<String>) -> Self {
        identities.truncate(MAX_NAMES);
        self.identities = identities;
        self
    }

    /// Record the verified identity of the caller.
    ///
    /// Only the daemon has one: a session writing its own log is the caller, so
    /// there is nobody to attest. The image path is clipped here rather than at
    /// the call site, so no caller can widen a row past the atomic-write cap by
    /// passing a deep path.
    #[must_use]
    pub fn with_peer(mut self, mut peer: Peer) -> Self {
        let (image, _) = clip(&peer.image, MAX_IMAGE_CHARS);
        peer.image = image;
        self.peer = Some(peer);
        self
    }

    /// Record what was decided and why, in the fixed vocabulary
    /// [`crate::attest::Denial::kind`] produces.
    #[must_use]
    pub fn with_decision(mut self, decision: &str) -> Self {
        self.decision = Some(decision.to_owned());
        self
    }

    /// Record which requested names did not arrive.
    ///
    /// Without this a degraded row says only that something went wrong, which
    /// is the least useful thing an audit row can say.
    #[must_use]
    pub fn with_unresolved(mut self, mut names: Vec<String>) -> Self {
        names.truncate(MAX_NAMES);
        self.unresolved = names;
        self
    }

    /// Record the child's exit code.
    #[must_use]
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Override the recorded working directory. Used by tests.
    #[must_use]
    pub fn with_cwd(mut self, cwd: String) -> Self {
        self.cwd = cwd;
        self
    }
}

#[derive(Serialize)]
struct Row<'a> {
    v: u32,
    ts: &'a str,
    ts_ms: u128,
    verb: &'a str,
    state: &'a str,
    cwd: &'a str,
    names: &'a [String],
    unresolved: &'a [String],
    argv: &'a [String],
    argv_truncated: bool,
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    identities: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_generation: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_unique_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_code_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_image: Option<&'a str>,
    prev: &'a str,
}

/// Mode for a log a session writes for itself: owner only.
pub const MODE_PRIVATE: u32 = 0o600;
/// Mode for a log the daemon writes and the session may read.
///
/// The whole unforgeability claim is this number plus who owns the file. The
/// daemon's uid owns it and may append; the session's uid is in the group and
/// may read, which is what lets `keyless doctor` verify the chain. What the
/// session cannot do is write — so it cannot rewrite a row and recompute the
/// hashes after it, which is precisely the attack the chain cannot detect on a
/// log the writer also owns.
pub const MODE_GROUP_READABLE: u32 = 0o640;

/// The append-only log at a path.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    mode: u32,
}

impl AuditLog {
    /// Point at a file. Nothing is created until the first append.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        AuditLog {
            path,
            mode: MODE_PRIVATE,
        }
    }

    /// Create the file with a specific mode if it does not exist yet.
    ///
    /// Only affects creation — an existing file keeps the mode it has, which is
    /// correct: the installer sets the mode and ownership, and a daemon that
    /// silently re-chmodded an existing log could undo a hardening an operator
    /// applied on purpose.
    #[must_use]
    pub const fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    /// The file this log writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one row.
    ///
    /// Every caller in this crate ignores the error and continues. That is not
    /// laziness: an unwritable log is a reason to warn, never a reason to
    /// refuse to run a command.
    pub fn append(&self, event: &Event) -> Result<(), AuditError> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|source| AuditError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let mut file = self.open()?;
        file.lock().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;

        let result = self.write_locked(&mut file, event);

        // Unlock explicitly so the error, if any, is not lost in a drop.
        let unlocked = file.unlock().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        });
        result.and(unlocked)
    }

    fn open(&self) -> Result<File, AuditError> {
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Names and working directories are not secrets, but they are not
            // everyone's business either.
            options.mode(self.mode);
        }
        options.open(&self.path).map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })
    }

    fn write_locked(&self, file: &mut File, event: &Event) -> Result<(), AuditError> {
        let prev = read_last_hash(file).map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;

        let ts_ms = time::now_unix_millis();
        let ts = time::rfc3339_utc(ts_ms);

        // Shrink argv until the row fits. Truncating is the alternative to
        // interleaving with another session's row.
        let mut argv_len = event.argv.len();
        let mut line = loop {
            let parts = Parts {
                cwd: &event.cwd,
                names: &event.names,
                unresolved: &event.unresolved,
                argv: &event.argv[..argv_len],
                truncated: event.argv_truncated || argv_len < event.argv.len(),
            };
            let line = render(event, &parts, &ts, ts_ms, &prev)?;
            if line.len() <= MAX_LINE_BYTES || argv_len == 0 {
                break line;
            }
            argv_len -= 1;
        };

        // Dropping every argument is not always enough: a deep working
        // directory plus 64 long names can exceed the cap on their own. Fall
        // back to a row carrying only the fixed fields and a clipped cwd, which
        // is bounded at roughly 300 bytes and therefore always fits.
        if line.len() > MAX_LINE_BYTES {
            let (cwd, _) = clip(&event.cwd, 120);
            let parts = Parts {
                cwd: &cwd,
                names: &[],
                unresolved: &[],
                argv: &[],
                truncated: true,
            };
            line = render(event, &parts, &ts, ts_ms, &prev)?;
        }

        file.seek(SeekFrom::End(0))
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })
    }

    /// Recompute every chain link. Returns the number of rows verified.
    ///
    /// A missing file verifies as zero rows: nothing has happened yet, which is
    /// consistent rather than broken.
    pub fn verify(&self) -> Result<usize, AuditError> {
        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(source) => {
                return Err(AuditError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };

        let mut prev = GENESIS.to_owned();
        let mut count = 0usize;
        for (index, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let number = index + 1;
            if line.len() < PAYLOAD_OFFSET || !line.starts_with("{\"hash\":\"") {
                return Err(AuditError::Chain {
                    line: number,
                    detail: "row does not start with its hash".to_owned(),
                });
            }
            let recorded = &line[9..9 + 64];
            let payload = &line[PAYLOAD_OFFSET..];
            let expected = chain_hash(&prev, payload);
            if recorded != expected {
                return Err(AuditError::Chain {
                    line: number,
                    detail: "hash does not match the row contents".to_owned(),
                });
            }
            prev = recorded.to_owned();
            count += 1;
        }
        Ok(count)
    }
}

/// The variable-length fields of a row, so the size fallback can shrink them
/// one group at a time without cloning the whole event.
struct Parts<'a> {
    cwd: &'a str,
    names: &'a [String],
    unresolved: &'a [String],
    argv: &'a [String],
    truncated: bool,
}

fn render(
    event: &Event,
    parts: &Parts<'_>,
    ts: &str,
    ts_ms: u128,
    prev: &str,
) -> Result<String, AuditError> {
    let row = Row {
        v: SCHEMA_VERSION,
        ts,
        ts_ms,
        verb: &event.verb,
        state: event.state.as_str(),
        cwd: parts.cwd,
        names: parts.names,
        unresolved: parts.unresolved,
        argv: parts.argv,
        argv_truncated: parts.truncated,
        exit_code: event.exit_code,
        decision: event.decision.as_deref(),
        identities: &event.identities,
        peer_uid: event.peer.as_ref().map(|p| p.uid),
        peer_pid: event.peer.as_ref().map(|p| p.pid),
        peer_generation: event.peer.as_ref().map(|p| p.generation),
        peer_unique_id: event.peer.as_ref().map(|p| p.unique_id),
        peer_code_hash: event.peer.as_ref().map(|p| p.code_hash.as_str()),
        peer_image: event.peer.as_ref().map(|p| p.image.as_str()),
        prev,
    };
    let body = serde_json::to_string(&row).map_err(|e| AuditError::Encode(e.to_string()))?;
    // `serde_json` always emits an object here, so the first byte is `{`.
    let payload = body
        .get(1..)
        .ok_or_else(|| AuditError::Encode("serialized row was not a JSON object".to_owned()))?;
    let hash = chain_hash(prev, payload);
    Ok(format!("{{\"hash\":\"{hash}\",{payload}"))
}

fn chain_hash(prev: &str, payload: &str) -> String {
    let mut buf = Vec::with_capacity(prev.len() + payload.len());
    buf.extend_from_slice(prev.as_bytes());
    buf.extend_from_slice(payload.as_bytes());
    hex_lower(&sha256::digest(&buf))
}

/// The hash of the last complete row, or the genesis value.
fn read_last_hash(file: &mut File) -> std::io::Result<String> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(GENESIS.to_owned());
    }
    // A row is capped at MAX_LINE_BYTES, so the last one is inside this window.
    let window = u64::min(len, (MAX_LINE_BYTES as u64) * 2);
    file.seek(SeekFrom::Start(len - window))?;
    let mut tail = String::new();
    // Lossy on purpose: a partially written row must not stop the next append.
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    tail.push_str(&String::from_utf8_lossy(&bytes));

    for line in tail.lines().rev() {
        if line.len() >= 9 + 64 && line.starts_with("{\"hash\":\"") {
            return Ok(line[9..9 + 64].to_owned());
        }
    }
    Ok(GENESIS.to_owned())
}

/// Clip to a character count, reporting whether anything was removed.
fn clip(text: &str, max_chars: usize) -> (String, bool) {
    if text.chars().count() <= max_chars {
        return (text.to_owned(), false);
    }
    let clipped: String = text.chars().take(max_chars).collect();
    (format!("{clipped}…"), true)
}

#[cfg(test)]
mod tests {
    use super::{AuditLog, Event, MAX_LINE_BYTES};
    use crate::State;
    use crate::mask::Masker;
    use crate::secret::Secret;
    use std::path::PathBuf;

    fn temp_path(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "keyless-audit-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path.push("audit.jsonl");
        path
    }

    fn masker_for(value: &str) -> Masker {
        let secret = Secret::new(value.to_owned());
        Masker::from_secrets([("DECOY", &secret)])
    }

    #[test]
    fn a_value_typed_on_the_command_line_is_masked_in_the_row() {
        let path = temp_path("mask");
        let log = AuditLog::new(path.clone());
        let masker = masker_for("decoy-plaintext-on-argv-0001");
        let event = Event::new(
            "run",
            State::Injected,
            vec!["DECOY".to_owned()],
            &[
                "curl",
                "-H",
                "Authorization: Bearer decoy-plaintext-on-argv-0001",
            ],
            &masker,
        )
        .with_exit_code(0);
        log.append(&event).expect("append");

        let raw = std::fs::read_to_string(&path).expect("read back");
        assert!(
            !raw.contains("decoy-plaintext-on-argv-0001"),
            "value leaked: {raw}"
        );
        assert!(raw.contains("[keyless:DECOY]"));
        assert!(raw.contains("\"state\":\"INJECTED\""));
    }

    #[test]
    fn the_chain_verifies_across_many_rows() {
        let path = temp_path("chain");
        let log = AuditLog::new(path);
        let masker = Masker::new();
        for i in 0..25 {
            let event = Event::new(
                "run",
                State::Degraded,
                vec![],
                &[format!("cmd{i}")],
                &masker,
            )
            .with_exit_code(i);
            log.append(&event).expect("append");
        }
        assert_eq!(log.verify().expect("verify"), 25);
    }

    #[test]
    fn editing_a_row_breaks_the_chain() {
        let path = temp_path("tamper");
        let log = AuditLog::new(path.clone());
        let masker = Masker::new();
        for i in 0..3 {
            log.append(&Event::new(
                "run",
                State::Injected,
                vec![],
                &[format!("c{i}")],
                &masker,
            ))
            .expect("append");
        }
        let raw = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, raw.replace("\"exit_code\":null", "\"exit_code\":0")).expect("write");
        let error = log.verify().expect_err("a tampered row must not verify");
        assert!(error.to_string().contains("chain broken"));
    }

    #[test]
    fn truncating_the_file_breaks_the_chain() {
        let path = temp_path("truncate");
        let log = AuditLog::new(path.clone());
        let masker = Masker::new();
        for i in 0..4 {
            log.append(&Event::new(
                "run",
                State::Injected,
                vec![],
                &[format!("c{i}")],
                &masker,
            ))
            .expect("append");
        }
        let raw = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = raw.lines().collect();
        // Drop the second row: rows 3 and 4 no longer chain.
        let kept = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]);
        std::fs::write(&path, kept).expect("write");
        assert!(log.verify().is_err());
    }

    #[test]
    fn a_missing_log_verifies_as_empty() {
        let log = AuditLog::new(PathBuf::from("/nonexistent/keyless/audit.jsonl"));
        assert_eq!(log.verify().expect("missing file is not an error"), 0);
    }

    #[test]
    fn an_enormous_argv_is_truncated_below_the_atomic_write_cap() {
        let path = temp_path("huge");
        let log = AuditLog::new(path.clone());
        let masker = Masker::new();
        let args: Vec<String> = (0..500)
            .map(|i| format!("--flag-number-{i}={}", "x".repeat(150)))
            .collect();
        log.append(&Event::new("run", State::Degraded, vec![], &args, &masker))
            .expect("append");

        let raw = std::fs::read_to_string(&path).expect("read");
        let line = raw.lines().next().expect("one row");
        assert!(line.len() <= MAX_LINE_BYTES, "row was {} bytes", line.len());
        assert!(line.contains("\"argv_truncated\":true"));
        assert_eq!(log.verify().expect("verify"), 1);
    }

    #[test]
    fn an_oversized_row_with_no_argv_left_still_fits() {
        // Dropping every argument is not always enough: a deep working
        // directory and 64 long names blow the cap on their own.
        let path = temp_path("oversized-fixed-fields");
        let log = AuditLog::new(path.clone());
        let masker = Masker::new();
        let names: Vec<String> = (0..64)
            .map(|i| format!("NAME_{i}_{}", "N".repeat(120)))
            .collect();
        let event = Event::new(
            "run",
            State::Degraded,
            names.clone(),
            &[] as &[String],
            &masker,
        )
        .with_unresolved(names)
        .with_cwd(format!("/{}", "deep/".repeat(400)));
        log.append(&event).expect("append");

        let raw = std::fs::read_to_string(&path).expect("read");
        let line = raw.lines().next().expect("one row");
        assert!(line.len() <= MAX_LINE_BYTES, "row was {} bytes", line.len());
        assert!(line.contains("\"argv_truncated\":true"));
        assert_eq!(log.verify().expect("verify"), 1);
    }

    #[test]
    fn a_daemon_row_carries_the_verified_peer_and_still_chains() {
        let path = temp_path("peer");
        let log = AuditLog::new(path.clone());
        let masker = Masker::new();
        let event = Event::new(
            "resolve",
            State::Injected,
            vec!["DECOY".to_owned()],
            &[] as &[String],
            &masker,
        )
        .with_peer(super::Peer {
            uid: 501,
            pid: 4412,
            generation: 20574530,
            unique_id: 11119263,
            code_hash: "a".repeat(40),
            image: "/usr/local/bin/keyless".to_owned(),
        })
        .with_decision("allow");
        log.append(&event).expect("append");

        let raw = std::fs::read_to_string(&path).expect("read");
        assert!(raw.contains("\"peer_pid\":4412"));
        assert!(raw.contains("\"peer_generation\":20574530"));
        assert!(raw.contains("\"peer_unique_id\":11119263"));
        assert!(raw.contains("\"decision\":\"allow\""));
        assert_eq!(log.verify().expect("verify"), 1);
    }

    #[test]
    fn a_session_row_is_unchanged_by_the_daemons_fields() {
        // Every peer field is optional and skipped when absent, so a row the
        // session binary writes has exactly the keys it had before the daemon
        // existed. Otherwise old logs would stop verifying.
        let path = temp_path("no-peer");
        let log = AuditLog::new(path.clone());
        let event = Event::new("run", State::Injected, vec![], &["true"], &Masker::new());
        log.append(&event).expect("append");
        let raw = std::fs::read_to_string(&path).expect("read");
        for absent in [
            "peer_uid",
            "peer_pid",
            "peer_generation",
            "peer_unique_id",
            "peer_code_hash",
            "peer_image",
            "decision",
        ] {
            assert!(!raw.contains(absent), "{absent} leaked into a session row");
        }
    }

    #[test]
    fn a_deep_image_path_cannot_blow_the_atomic_write_cap() {
        let path = temp_path("deep-image");
        let log = AuditLog::new(path.clone());
        let event = Event::new(
            "resolve",
            State::Degraded,
            vec![],
            &[] as &[String],
            &Masker::new(),
        )
        .with_peer(super::Peer {
            uid: 501,
            pid: 1,
            generation: 1,
            unique_id: 1,
            code_hash: "b".repeat(40),
            image: format!("/{}", "deep/".repeat(500)),
        });
        log.append(&event).expect("append");
        let raw = std::fs::read_to_string(&path).expect("read");
        let line = raw.lines().next().expect("one row");
        assert!(line.len() <= MAX_LINE_BYTES, "row was {} bytes", line.len());
        assert_eq!(log.verify().expect("verify"), 1);
    }

    #[test]
    fn the_daemons_log_is_created_group_readable_and_not_group_writable() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode");
        let log = AuditLog::new(path.clone()).with_mode(super::MODE_GROUP_READABLE);
        log.append(&Event::new(
            "resolve",
            State::Injected,
            vec![],
            &[] as &[String],
            &Masker::new(),
        ))
        .expect("append");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "mode was {mode:04o}");
        // The claim is precisely this: readable by the group, writable by
        // nobody but the owner. Group write would void the whole chain.
        assert_eq!(mode & 0o020, 0, "the group must not be able to write");
        assert_eq!(mode & 0o007, 0, "other must have nothing");
    }

    #[test]
    fn a_session_log_stays_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("mode-private");
        let log = AuditLog::new(path.clone());
        log.append(&Event::new(
            "run",
            State::Injected,
            vec![],
            &["true"],
            &Masker::new(),
        ))
        .expect("append");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:04o}");
    }

    #[test]
    fn concurrent_appends_do_not_interleave() {
        let path = temp_path("concurrent");
        let log = AuditLog::new(path.clone());
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let log = log.clone();
                scope.spawn(move || {
                    let masker = Masker::new();
                    for i in 0..12 {
                        let event = Event::new(
                            "run",
                            State::Injected,
                            vec![format!("W{worker}")],
                            &[format!("worker-{worker}-iteration-{i}")],
                            &masker,
                        );
                        log.append(&event).expect("append");
                    }
                });
            }
        });

        let raw = std::fs::read_to_string(&path).expect("read");
        let rows = raw.lines().filter(|l| !l.trim().is_empty()).count();
        assert_eq!(rows, 96, "every append must produce exactly one whole row");
        for line in raw.lines() {
            assert!(line.starts_with("{\"hash\":\""), "row is not whole: {line}");
            assert!(line.ends_with('}'), "row is not whole: {line}");
        }
        assert_eq!(log.verify().expect("verify"), 96);
    }
}
