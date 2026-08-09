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
//! therefore detects a row edited or removed from the middle, a partial write,
//! and tampering by anything that cannot rewrite the file — and does not detect
//! tampering by the session itself. Making it detect that requires the writer
//! to be a process the session cannot impersonate, which is the
//! privilege-boundary daemon's job. The verifier here is what that daemon will
//! use unchanged.
//!
//! **The chain does not detect a short tail, and no chain can.** Removing rows
//! from the end leaves a chain that is internally perfect; nothing inside a
//! file can say how long the file was supposed to be. That fact lives in the
//! [`anchor`] beside the log, and [`AuditLog::verify`] checks it. Read that
//! module for exactly what it does and does not defend against — in one line,
//! it names accident and a rewrite confined to the log, and it does not move
//! the adversary bound above by one inch.
//!
//! # Concurrency
//!
//! ~20 agent sessions can append at once. Two defences, because either alone
//! has a hole: an exclusive advisory lock held across read-tail-and-append, and
//! a hard cap that keeps a row under `PIPE_BUF` so a single `write` stays
//! atomic even where the lock is not honoured. Long argv is truncated rather
//! than allowed to interleave with another session's row.

pub mod anchor;
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
            })?;

        // The row is durable before the anchor moves, so the anchor can only
        // ever lag. See `anchor` for why that direction is the safe one and the
        // reverse is the only thing worth reporting.
        let hash = line
            .get(9..9 + 64)
            .ok_or_else(|| AuditError::Encode("rendered row carries no hash".to_owned()))?;
        anchor::write(&self.path, self.mode, hash)
    }

    /// Recompute every chain link, and check the log still ends where the
    /// writer last said it ended. Returns the number of rows verified.
    ///
    /// A missing file with no anchor beside it verifies as zero rows: nothing
    /// has happened yet, which is consistent rather than broken. A missing file
    /// with an anchor is the opposite claim — rows were written and are gone —
    /// and is reported.
    pub fn verify(&self) -> Result<usize, AuditError> {
        // Read before the log, so a corrupt or future-versioned anchor is
        // reported rather than quietly skipped by an early return below.
        let anchor = anchor::read(&self.path)?;

        let raw = match fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return match anchor {
                    None => Ok(0),
                    Some(anchor) => Err(AuditError::Anchor {
                        detail: format!(
                            "the log is absent, and the anchor beside it records row {}; \
                             rows that were written are no longer there",
                            short(&anchor.hash)
                        ),
                    }),
                };
            }
            Err(source) => {
                return Err(AuditError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };

        let mut prev = GENESIS.to_owned();
        let mut count = 0usize;
        let mut anchored_row_is_present = false;
        for (index, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let number = index + 1;
            // `<=`, not `<`. A line of exactly `PAYLOAD_OFFSET` bytes is a hash
            // and a comma with NOTHING after it, and `render` cannot produce
            // one — the payload always carries at least a schema version. Under
            // `<` such a line was accepted as a row and counted, because the
            // empty payload hashes to something and that something can be
            // written into the line by hand. A row with no contents is not a
            // row.
            if line.len() <= PAYLOAD_OFFSET || !line.starts_with("{\"hash\":\"") {
                return Err(AuditError::Chain {
                    line: number,
                    detail: "row does not begin with a hash and a payload".to_owned(),
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
            if let Some(anchor) = &anchor
                && recorded == anchor.hash
            {
                anchored_row_is_present = true;
            }
            prev = recorded.to_owned();
            count += 1;
        }

        if let Some(anchor) = &anchor
            && !anchored_row_is_present
        {
            return Err(AuditError::Anchor {
                detail: format!(
                    "the log holds {count} row(s) and none of them is row {}, which the anchor \
                     beside it records as written; rows were removed from the end, or the file \
                     was rewritten",
                    short(&anchor.hash)
                ),
            });
        }

        Ok(count)
    }
}

/// Enough of a chain hash to identify a row in a message, and no more.
fn short(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
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
        // Edit the SECOND row specifically, and assert the reported line
        // number. Rewriting every row at once would land the failure on line 1,
        // where an off-by-one in the counter is invisible — and the line number
        // is the whole of what this error tells a person to go and look at.
        let lines: Vec<&str> = raw.lines().collect();
        let tampered = lines[1].replace("\"exit_code\":null", "\"exit_code\":0");
        assert_ne!(tampered, lines[1], "the fixture edited nothing");
        std::fs::write(&path, format!("{}\n{}\n{}\n", lines[0], tampered, lines[2]))
            .expect("write");
        let error = log.verify().expect_err("a tampered row must not verify");
        assert_eq!(
            error.to_string(),
            "audit chain broken at line 2: hash does not match the row contents",
            "the second row was edited and the report must say so"
        );
    }

    #[test]
    fn a_row_at_the_size_cap_is_still_found_by_the_next_append() {
        // `read_last_hash` reads a WINDOW off the end rather than the whole
        // file, and the window has to be wide enough to contain the longest row
        // the writer can produce. Shrink that window and the last row falls
        // outside it, `read_last_hash` finds no row, silently returns the
        // genesis value, and the next append writes a row whose `prev` points
        // at nothing. The log then holds two chains and the file that was
        // supposed to be tamper-evident is broken by ordinary use.
        //
        // Nothing exercised this. One test builds a row exactly at the cap, but
        // it never appends a SECOND row, so the window is never asked to find
        // anything. The append after a large row is the whole mechanism.
        let path = temp_path("wide-window");
        let log = AuditLog::new(path.clone());
        let masker = Masker::new();

        let big = Event::new("run", State::Injected, vec![], &[] as &[String], &masker)
            .with_cwd("d".repeat(3000));
        log.append(&big).expect("append the wide row");
        let first = std::fs::read_to_string(&path).expect("read");
        let first_line = first.lines().next().expect("one row");
        assert!(
            first_line.len() > MAX_LINE_BYTES / 2,
            "the fixture row is {} bytes, which is not wide enough to test the window",
            first_line.len()
        );

        log.append(&Event::new(
            "run",
            State::Injected,
            vec![],
            &["after"],
            &masker,
        ))
        .expect("append after the wide row");

        assert_eq!(
            log.verify().expect("a wide row must not break the chain"),
            2
        );
    }

    #[test]
    fn a_row_left_half_written_by_a_crash_does_not_break_the_next_append() {
        // A process killed mid-append leaves a fragment at the end of the file:
        // the start of a row, no newline, no hash to read. The next append must
        // walk past it to the last COMPLETE row, and must not read the fragment
        // as if it were a row — slicing 64 bytes of hash out of a 12-byte line
        // is a panic, and a panic here takes down a command that had nothing to
        // do with the audit log.
        //
        // The complete row sits EXACTLY on the size cap, and the length is
        // solved for rather than guessed. The window `read_last_hash` reads has
        // to hold a whole maximal row plus whatever fragment follows it; a
        // comfortable fixture is satisfied by a window far narrower than the
        // real worst case, and every arithmetic change to that window then goes
        // unnoticed. Guessing a length instead of solving for one lands either
        // short — testing nothing — or over the cap, where the writer clips the
        // working directory and hands back a 300-byte row.
        let masker = Masker::new();
        let render_with = |tag: &str, cwd_len: usize| -> String {
            let path = temp_path(tag);
            let log = AuditLog::new(path.clone());
            log.append(
                &Event::new("run", State::Injected, vec![], &[] as &[String], &masker)
                    .with_cwd("d".repeat(cwd_len)),
            )
            .expect("append");
            std::fs::read_to_string(&path).expect("read")
        };
        // `d` needs no JSON escaping, so one byte of working directory is one
        // byte of row and a single measurement gives the offset to the cap.
        const PROBE: usize = 200;
        let probe = render_with("half-written-probe", PROBE);
        let wanted = PROBE + MAX_LINE_BYTES - probe.trim_end().len();

        let path = temp_path("half-written");
        let log = AuditLog::new(path.clone());
        log.append(
            &Event::new("run", State::Injected, vec![], &[] as &[String], &masker)
                .with_cwd("d".repeat(wanted)),
        )
        .expect("append");
        let complete = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            complete.trim_end().len(),
            MAX_LINE_BYTES,
            "the fixture did not land on the cap, so the window is never stressed"
        );
        let first_hash = complete[9..9 + 64].to_owned();

        // Shorter than a hash, and beginning exactly like a real row: the two
        // properties that together turn a length check into a panic.
        std::fs::write(&path, format!("{complete}{{\"hash\":\"abc\n")).expect("write a fragment");

        log.append(&Event::new(
            "run",
            State::Injected,
            vec![],
            &["second"],
            &masker,
        ))
        .expect("appending after a fragment must not fail");

        let raw = std::fs::read_to_string(&path).expect("read");
        let last = raw.lines().last().expect("three lines");
        assert!(
            last.contains(&format!("\"prev\":\"{first_hash}\"")),
            "the append chained onto the fragment instead of the last whole row: {last}"
        );
    }

    #[test]
    fn a_row_too_short_to_hold_a_hash_is_reported_rather_than_panicking() {
        // The reading half of the case above. `verify` slices a fixed 64-byte
        // hash out of every line, so the length check in front of that slice is
        // load-bearing: widen it by one comparison and a truncated row panics
        // the verifier instead of being reported as a broken row.
        //
        // Written by hand rather than appended, so there is no anchor beside it
        // and this tests the row check alone.
        let path = temp_path("short-row");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(&path, "{\"hash\":\"abc\n").expect("write a short row");
        let log = AuditLog::new(path.clone());
        let error = log
            .verify()
            .expect_err("a row too short to hold a hash must not verify");
        assert_eq!(
            error.to_string(),
            "audit chain broken at line 1: row does not begin with a hash and a payload"
        );
    }

    #[test]
    fn a_line_that_is_a_hash_and_nothing_else_is_not_a_row() {
        // Exactly `PAYLOAD_OFFSET` bytes: the hash, the comma, and no contents.
        // `render` cannot produce this — every payload carries at least a
        // schema version — so the only way one appears is by hand. The empty
        // payload still hashes to something, and that something can be written
        // into the line, so a length check that admits this length admits a row
        // that says nothing and chains anyway.
        let path = temp_path("empty-payload");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        let line = format!("{{\"hash\":\"{}\",", "0".repeat(64));
        assert_eq!(
            line.len(),
            super::PAYLOAD_OFFSET,
            "the fixture must land exactly on the boundary being tested"
        );
        std::fs::write(&path, format!("{line}\n")).expect("write");
        let error = AuditLog::new(path)
            .verify()
            .expect_err("a hash with no payload is not a row");
        assert_eq!(
            error.to_string(),
            "audit chain broken at line 1: row does not begin with a hash and a payload"
        );
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
    fn dropping_the_last_row_breaks_verification() {
        // The case the chain alone cannot see, and the most common one in
        // practice: a crash mid-rotation, a naive `head -n -1`, a restore from
        // a stale copy. Removing rows from the END leaves a chain that is
        // internally perfect and simply shorter, because nothing inside the
        // file says how long the file was supposed to be.
        //
        // The sibling test above drops a MIDDLE row, which the chain does
        // catch. Both existing tamper tests did that, so the hole sat exactly
        // where the tests were not looking.
        let path = temp_path("tail-truncate");
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
        // The control: the fixture verifies before anything is removed, so a
        // failure below is the truncation and not a broken fixture.
        assert_eq!(log.verify().expect("verify"), 4);

        let raw = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = raw.lines().collect();
        let dropped = &lines[3][9..9 + 64];
        let kept = format!("{}\n{}\n{}\n", lines[0], lines[1], lines[2]);
        std::fs::write(&path, kept).expect("write");

        let error = log
            .verify()
            .expect_err("dropping the last row must not verify");
        assert!(
            matches!(error, super::AuditError::Anchor { .. }),
            "a short tail must be reported as a tail-anchor failure, not as {error}"
        );
        // The message has to name the row that went missing and how many are
        // left, or it tells an operator that something is wrong without telling
        // them what to go and look for.
        let text = error.to_string();
        assert!(
            text.contains(&dropped[..12]),
            "the report does not name the row the anchor recorded: {text}"
        );
        assert!(
            text.contains("3 row(s)"),
            "the report does not say how many rows survived: {text}"
        );
    }

    #[test]
    fn emptying_the_log_entirely_is_detected() {
        // Truncation to zero rows is the extreme of the case above, and it is
        // what a naive rotation (`mv log log.1; touch log`) produces. Without
        // the anchor this reads as "nothing has happened yet", which is the
        // single most misleading answer this function can give.
        let path = temp_path("tail-empty");
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
        std::fs::write(&path, "").expect("truncate to nothing");
        let error = log.verify().expect_err("an emptied log must not verify");
        assert!(
            matches!(error, super::AuditError::Anchor { .. }),
            "an emptied log must be reported as a tail-anchor failure, not as {error}"
        );

        // And the same again with the file removed rather than emptied, since
        // `verify` has a deliberate early return for a missing file.
        std::fs::remove_file(&path).expect("remove");
        let error = log.verify().expect_err("a deleted log must not verify");
        assert!(
            matches!(error, super::AuditError::Anchor { .. }),
            "a deleted log must be reported as a tail-anchor failure, not as {error}"
        );
    }

    #[test]
    fn rewriting_every_row_with_a_valid_chain_is_detected() {
        // The attack the chain provably cannot see: recompute every hash from
        // genesis and the file verifies. The anchor catches it, because the
        // anchor names a row the rewritten file no longer contains. This is a
        // detection the chain alone does not have, and it is bounded by exactly
        // one thing — whoever rewrote the log could rewrite the anchor too.
        let masker = Masker::new();
        let victim = temp_path("rewrite-victim");
        let log = AuditLog::new(victim.clone());
        for i in 0..3 {
            log.append(&Event::new(
                "run",
                State::Injected,
                vec![],
                &[format!("real{i}")],
                &masker,
            ))
            .expect("append");
        }

        // A separate, internally perfect log, standing in for the forgery.
        let forgery = temp_path("rewrite-forgery");
        let other = AuditLog::new(forgery.clone());
        for i in 0..3 {
            other
                .append(&Event::new(
                    "run",
                    State::Injected,
                    vec![],
                    &[format!("forged{i}")],
                    &masker,
                ))
                .expect("append");
        }
        assert_eq!(other.verify().expect("the forgery chains"), 3);

        let forged = std::fs::read_to_string(&forgery).expect("read");
        std::fs::write(&victim, forged).expect("swap the contents in");

        let error = log
            .verify()
            .expect_err("a wholesale rewrite must not verify");
        assert!(
            matches!(error, super::AuditError::Anchor { .. }),
            "a rewritten log must be reported as a tail-anchor failure, not as {error}"
        );
    }

    #[test]
    fn an_anchor_left_behind_by_a_crash_is_not_a_problem() {
        // The control for all three tests above, and the one that decides
        // whether this mechanism is usable. The row is written before the
        // anchor, so a crash between the two leaves the anchor pointing at an
        // EARLIER row. That direction is normal and must stay silent — an
        // anchor can only ever legitimately lag, never lead.
        //
        // Without this test, "always report a problem" passes every assertion
        // above and `doctor` cries wolf after every hard kill.
        let path = temp_path("anchor-behind");
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
        let second = raw.lines().nth(1).expect("four rows");
        let stale = second[9..9 + 64].to_owned();
        super::anchor::write(&path, super::MODE_PRIVATE, &stale).expect("stale anchor");

        assert_eq!(
            log.verify().expect("an anchor that lags must verify"),
            4,
            "a crash between the row write and the anchor write must not read as tampering"
        );
    }

    #[test]
    fn a_log_with_no_anchor_verifies_exactly_as_it_did_before() {
        // Every log written before this mechanism existed has no anchor beside
        // it. Those must keep verifying, or an upgrade turns every existing
        // install into a reported problem on the day it lands.
        let path = temp_path("no-anchor");
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
        std::fs::remove_file(super::anchor::path_for(&path)).expect("stand in for a legacy log");
        assert_eq!(log.verify().expect("a legacy log still verifies"), 3);

        // And the chain still does the job it always did on such a log: a
        // middle row removed is still caught with no anchor present.
        let raw = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = raw.lines().collect();
        std::fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).expect("write");
        assert!(log.verify().is_err(), "the chain still catches a gap");
    }

    #[test]
    fn a_corrupt_anchor_is_reported_rather_than_ignored() {
        // A half-written anchor must not silently disable the check. Ignoring
        // an unparsable anchor would mean a single stray byte turns the
        // detection off with nothing said about it.
        let path = temp_path("anchor-corrupt");
        let log = AuditLog::new(path.clone());
        log.append(&Event::new(
            "run",
            State::Injected,
            vec![],
            &["true"],
            &Masker::new(),
        ))
        .expect("append");
        std::fs::write(super::anchor::path_for(&path), "{\"v\":1,\"hash\":").expect("corrupt it");
        let error = log.verify().expect_err("a corrupt anchor must be reported");
        assert!(
            matches!(error, super::AuditError::Anchor { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_anchor_is_no_more_readable_than_the_log_it_guards() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("anchor-mode");
        let log = AuditLog::new(path.clone()).with_mode(super::MODE_GROUP_READABLE);
        log.append(&Event::new(
            "resolve",
            State::Injected,
            vec![],
            &[] as &[String],
            &Masker::new(),
        ))
        .expect("append");
        let mode = std::fs::metadata(super::anchor::path_for(&path))
            .expect("stat the anchor")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "anchor mode was {mode:04o}");
        assert_eq!(mode & 0o022, 0, "nobody but the owner may write the anchor");
    }

    #[test]
    fn a_missing_log_verifies_as_empty() {
        let log = AuditLog::new(PathBuf::from("/nonexistent/keyless/audit.jsonl"));
        assert_eq!(log.verify().expect("missing file is not an error"), 0);
    }

    #[test]
    fn a_log_that_cannot_be_read_is_an_error_rather_than_zero_rows() {
        // The other half of the test above, and the one that matters. "Absent"
        // verifies as zero rows because nothing has happened yet. "Present and
        // unreadable" must NOT, or `verify` answers `Ok(0)` for a log it never
        // opened — a verification that reports success without verifying is the
        // worst possible failure of this function.
        //
        // Unreadable is arranged with a directory rather than with permissions,
        // because a suite that runs as root can read a mode-000 file and the
        // test would then prove nothing on exactly the machines that run it in a
        // container.
        let path = temp_path("unreadable");
        std::fs::create_dir_all(&path).expect("stand in for an unreadable file");
        let log = AuditLog::new(path.clone());
        let error = log
            .verify()
            .expect_err("a log that cannot be read must not verify as empty");
        assert!(
            matches!(error, super::AuditError::Io { .. }),
            "the failure must be reported as I/O, not as a broken chain: {error}"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn a_row_whose_argv_the_writer_shrank_says_it_was_truncated() {
        // 40 arguments of 190 characters each. Every one is under MAX_ARG_CHARS
        // and there are fewer than MAX_ARGS of them, so `Event::new` clips
        // nothing and reports nothing truncated — asserted below, because that
        // is the whole point of the fixture. Together they are far past the row
        // cap, so it is the WRITER that drops arguments.
        //
        // Nothing else covers that path. The two existing truncation tests both
        // arrive with `argv_truncated` already true, so the writer's own term is
        // never the term that decides, and a row could claim to carry a complete
        // argv while carrying part of one.
        let path = temp_path("writer-shrunk");
        let log = AuditLog::new(path.clone());
        let masker = Masker::new();
        let args: Vec<String> = (0..40).map(|i| format!("arg{i:0>187}")).collect();
        let event = Event::new("run", State::Injected, vec![], &args, &masker);
        assert!(
            !event.argv_truncated,
            "the fixture must reach the writer untruncated, or it tests nothing"
        );
        log.append(&event).expect("append");

        let raw = std::fs::read_to_string(&path).expect("read");
        let line = raw.lines().next().expect("one row");
        assert!(line.len() <= MAX_LINE_BYTES, "row was {} bytes", line.len());
        assert!(
            line.contains("\"argv_truncated\":true"),
            "the writer dropped arguments and the row does not say so: {line}"
        );
        assert!(
            !line.contains("\"argv\":[]"),
            "this must be the shrink path, not the drop-everything fallback"
        );
        assert_eq!(log.verify().expect("verify"), 1);
    }

    #[test]
    fn a_row_of_exactly_the_cap_keeps_its_names() {
        // `MAX_LINE_BYTES` is a ceiling the row is allowed to touch, and the
        // whole difference between `>` and `>=` at the fallback is that one
        // length. At exactly the cap, `>=` throws away every name and every
        // argument and clips the working directory — for a row that already
        // fit. One row in every few thousand would arrive gutted, and nothing
        // in the file would say why.
        //
        // The fixture SOLVES for that length instead of hard-coding it. The
        // row also carries a timestamp and a schema, so a constant here would
        // be a number that stops meaning anything the next time the row shape
        // changes, and the test would keep passing while testing a different
        // length.
        let masker = Masker::new();
        let name = "N".repeat(40);
        let render_with = |tag: &str, cwd_len: usize| -> String {
            let path = temp_path(tag);
            let log = AuditLog::new(path.clone());
            let event = Event::new(
                "run",
                State::Injected,
                vec![name.clone()],
                &[] as &[String],
                &masker,
            )
            .with_cwd("d".repeat(cwd_len));
            log.append(&event).expect("append");
            let raw = std::fs::read_to_string(&path).expect("read");
            raw.lines().next().expect("one row").to_owned()
        };

        // Every byte of the working directory is one byte of the row: `d` needs
        // no JSON escaping. So one measurement gives the offset to the cap.
        const PROBE: usize = 200;
        let probe = render_with("cap-probe", PROBE);
        let wanted = PROBE + MAX_LINE_BYTES - probe.len();
        let line = render_with("cap-exact", wanted);
        assert_eq!(
            line.len(),
            MAX_LINE_BYTES,
            "the fixture did not land on the cap, so it tests the wrong length"
        );

        assert!(
            line.contains(&name),
            "a row that is exactly at the cap lost its names: {}",
            &line[..120]
        );
        assert!(
            line.contains("\"argv_truncated\":false"),
            "a row that is exactly at the cap was reported as truncated"
        );
    }

    #[test]
    fn a_row_that_fits_is_not_marked_truncated() {
        // The control for the test above. Without it, "always true" reads as a
        // correct answer to "was this row truncated?", and every truncation
        // assertion in this file passes for a flag that never says no.
        let path = temp_path("not-truncated");
        let log = AuditLog::new(path.clone());
        let masker = Masker::new();
        let event = Event::new("run", State::Injected, vec![], &["ls", "-la"], &masker);
        log.append(&event).expect("append");

        let raw = std::fs::read_to_string(&path).expect("read");
        let line = raw.lines().next().expect("one row");
        assert!(
            line.contains("\"argv_truncated\":false"),
            "a short row must not claim truncation: {line}"
        );
        assert_eq!(log.verify().expect("verify"), 1);
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
