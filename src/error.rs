//! Error types.
//!
//! Every variant here is hand-written rather than derived, for one reason: an
//! error type in this crate can be handed a secret by accident, and a derived
//! `Display` makes that invisible. Writing each message by hand forces the
//! author to look at what goes into it. `StoreError` in particular is built
//! only from a backend's *stderr* and never from its stdout, because stdout is
//! where the value comes from.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// A store failed to answer. Never carries a secret value.
#[derive(Debug)]
pub enum StoreError {
    /// The backend could not be reached at all — binary missing, daemon down,
    /// no network. The distinction from [`StoreError::Backend`] matters to
    /// `doctor`: unavailable is an install problem, backend is a data problem.
    Unavailable {
        /// Store identifier, e.g. `keychain`.
        store: String,
        /// Human-readable cause. Never contains a secret value.
        detail: String,
    },
    /// The backend was reached and refused, errored, or answered unusably.
    Backend {
        /// Store identifier, e.g. `keychain`.
        store: String,
        /// Human-readable cause, taken from the backend's stderr only.
        detail: String,
    },
    /// The backend was **not asked**, because the request is underspecified: a
    /// coordinate the vendor requires is missing and `keyless` will not invent
    /// one.
    ///
    /// A third variant rather than a reuse of the two above, because the reader
    /// has to be sent to a different place. [`StoreError::Unavailable`] sends
    /// them to the install, [`StoreError::Backend`] sends them to the vault, and
    /// this one sends them to one line of their own config — which is the only
    /// place the fix exists. Reporting it as either of the others sends them
    /// looking for a problem that is not there.
    ///
    /// Nothing was contacted, so the detail is written by this crate rather than
    /// taken from a backend's stderr. It still carries no value: there is no
    /// value to carry when no lookup happened.
    Misconfigured {
        /// Store identifier, e.g. `infisical`.
        store: String,
        /// What is missing, and how to supply it.
        detail: String,
    },
}

impl StoreError {
    /// The store that produced this error, for grouping in messages.
    #[must_use]
    pub fn store(&self) -> &str {
        match self {
            StoreError::Unavailable { store, .. }
            | StoreError::Backend { store, .. }
            | StoreError::Misconfigured { store, .. } => store,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Unavailable { store, detail } => {
                write!(f, "store `{store}` is unavailable: {detail}")
            }
            StoreError::Backend { store, detail } => {
                write!(f, "store `{store}` failed: {detail}")
            }
            StoreError::Misconfigured { store, detail } => {
                write!(f, "store `{store}` was not asked: {detail}")
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// The config file could not be read or understood.
///
/// This is never fatal. It downgrades the run; it does not stop it.
#[derive(Debug)]
pub enum ConfigError {
    /// The file exists but could not be read.
    Read { path: PathBuf, source: io::Error },
    /// The file was read but is not valid config.
    Parse { path: PathBuf, detail: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read { path, source } => {
                write!(f, "cannot read config at {}: {source}", path.display())
            }
            ConfigError::Parse { path, detail } => {
                write!(f, "cannot parse config at {}: {detail}", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Read { source, .. } => Some(source),
            ConfigError::Parse { .. } => None,
        }
    }
}

/// The audit log could not be appended to or verified.
///
/// Also never fatal: an unwritable log must not stop a command from running.
#[derive(Debug)]
pub enum AuditError {
    /// Filesystem failure opening, locking, or writing the log.
    Io { path: PathBuf, source: io::Error },
    /// A row could not be serialized. Only reachable if a field contains
    /// something serde refuses, which the row type makes unrepresentable.
    Encode(String),
    /// A row's chain hash does not match its contents, or the file is not
    /// shaped like an audit log.
    Chain { line: usize, detail: String },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::Io { path, source } => {
                write!(f, "audit log at {}: {source}", path.display())
            }
            AuditError::Encode(detail) => write!(f, "cannot encode audit row: {detail}"),
            AuditError::Chain { line, detail } => {
                write!(f, "audit chain broken at line {line}: {detail}")
            }
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AuditError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// The only two ways `run` can end without a child process existing.
///
/// Both mean there was nothing to spawn — neither is `keyless` declining to
/// spawn something it could have spawned. That distinction is the whole
/// never-block invariant, so these two variants are deliberately the complete
/// list, and adding a third is a design change rather than a bug fix.
#[derive(Debug)]
pub enum RunError {
    /// No command followed the flags.
    NoCommand,
    /// The command exists as text but not as an executable.
    SpawnFailed { program: String, source: io::Error },
}

impl RunError {
    /// The process exit code to report.
    ///
    /// 127 for "command not found" follows the shell convention, so a caller's
    /// existing error handling keeps working.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            RunError::NoCommand => 64, // EX_USAGE
            RunError::SpawnFailed { .. } => 127,
        }
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::NoCommand => f.write_str("no command given"),
            RunError::SpawnFailed { program, source } => {
                write!(f, "cannot execute `{program}`: {source}")
            }
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RunError::SpawnFailed { source, .. } => Some(source),
            RunError::NoCommand => None,
        }
    }
}
