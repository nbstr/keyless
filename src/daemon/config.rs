//! What the daemon is told, and what it refuses to be told.
//!
//! # A bad config is fatal here, and only here
//!
//! Everywhere else in this crate a configuration problem degrades and never
//! blocks, because blocking means refusing to run somebody's command. The
//! daemon is the exception and the reason is the same rule read the other way:
//! a daemon that starts with a policy it failed to parse is a daemon whose
//! allowlist is silently empty or silently wrong. Refusing to start is visible;
//! starting wrong is not. The sessions are unaffected either way — a daemon
//! that is not running is a daemon that is not there, which is a `DEGRADED`
//! that `run` already handles.
//!
//! # What is deliberately not configurable
//!
//! **The interpreter refusal.** There is no `refuse_interpreters` key. Allowing
//! an interpreted caller means authorising every program that interpreter will
//! ever run, and an operator reaching for that switch at 2am to make something
//! work would be turning the boundary off without knowing it. The flag exists
//! in [`crate::attest::Policy`] so the rule has a negative control in the test
//! suite, and it is not reachable from a file.
//!
//! **A "trust any uid" wildcard.** An empty `allow_uids` authorises nobody
//! rather than everybody.

mod backends;
pub mod infisical;
pub mod keychain;
pub mod onepassword;
pub mod proton;
pub mod renewal;
#[cfg(test)]
mod tests;
mod warnings;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::attest::{Policy, is_interpreter};
// `Policy` in this module is the ATTESTATION policy — who may ask. The store
// policy is a different question with the same word, so it is aliased at the
// import rather than renamed in the config file, where it is `stores.policy`
// exactly as a session spells it.
use crate::config::{Policy as StorePolicy, SecretRoute};
use crate::error::ConfigError;
use crate::ipc::peer::decode_hex;
use crate::paths::ConfigPath;
use crate::store::Registry;
use crate::store::catalogue::Source;

use self::infisical::DaemonInfisicalConfig;
use self::keychain::DaemonKeychainConfig;
use self::onepassword::DaemonOnePasswordConfig;
use self::proton::DaemonProtonConfig;

/// The daemon's whole configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    /// Where to listen.
    #[serde(default = "default_socket")]
    pub socket: ConfigPath,
    /// Where to append the audit log. Must be a path the calling user cannot
    /// write; the installer is what makes that true.
    #[serde(default = "default_audit")]
    pub audit: ConfigPath,
    /// How long a resolved value is served from memory without asking a store.
    #[serde(default = "default_ttl_seconds")]
    pub cache_ttl_seconds: u64,
    /// How long past that a value may still be served, while its refresh runs
    /// or after a refresh could not reach its store.
    ///
    /// Zero turns stale serving off and leaves the freshness window alone. A
    /// zero `cache_ttl_seconds` turns both off, because a daemon told to cache
    /// nothing has nothing to serve stale.
    ///
    /// This window opens on any refresh slower than a second, so it stays
    /// short; a store's longer silence is `cache_silent_seconds`'s to cover.
    /// A store that answers ends it either way: a value replaces the entry,
    /// and an answer that disowns it — no such item, a refused token — evicts
    /// it.
    #[serde(default = "default_stale_seconds")]
    pub cache_stale_seconds: u64,
    /// How old a value may be and still be served once its store has fallen
    /// silent: given no verdict within its timeout.
    ///
    /// Separate from the stale window, which opens on any slow refresh and so
    /// also on a healthy store. This one opens only on silence, and never for a
    /// name the store disowned. Zero turns it off, as does a zero
    /// `cache_ttl_seconds`.
    #[serde(default = "default_silent_seconds")]
    pub cache_silent_seconds: u64,
    /// How long a connection may sit idle before it is dropped.
    #[serde(default = "default_idle_seconds")]
    pub idle_timeout_seconds: u64,
    /// Who may ask.
    #[serde(default)]
    pub peer: PeerConfig,
    /// Where the values come from.
    #[serde(default)]
    pub stores: DaemonStores,
    /// Which store each name lives in, when the daemon runs more than one.
    ///
    /// Deliberately [`crate::config::SecretRoute`], the same type and the same
    /// spelling the session's config uses, because this is the same decision
    /// moved across the uid boundary rather than a second mechanism. Reusing
    /// the type means a route an operator moves from a session config into
    /// `keylessd.json` keeps working instead of being silently dropped as an
    /// unknown key.
    ///
    /// `store` decides which of the daemon's backends answers a name; `env`,
    /// `path` and `key` are the Infisical coordinates that backend looks the
    /// name up at, read by [`DaemonConfig::infisical_routing`]; `item`,
    /// `section` and `field` are the 1Password ones, read by
    /// [`DaemonConfig::onepassword_routing`]. The remaining fields describe
    /// adapters the daemon does not carry and are ignored.
    ///
    /// **`env` here is the ONLY place a daemon-hosted lookup can get an
    /// Infisical environment from.** See [`DaemonConfig::infisical_routing`].
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRoute>,
}

/// The stores a daemon resolves through, and the ones it can enumerate.
pub struct Backends {
    /// Every configured store, in search order.
    pub registry: Registry,
    /// The enumerable subset, paired with its naming rule. Empty where no
    /// catalogue was handed in.
    pub sources: Vec<Source>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            socket: default_socket(),
            audit: default_audit(),
            cache_ttl_seconds: default_ttl_seconds(),
            cache_stale_seconds: default_stale_seconds(),
            cache_silent_seconds: default_silent_seconds(),
            idle_timeout_seconds: default_idle_seconds(),
            peer: PeerConfig::default(),
            stores: DaemonStores::default(),
            secrets: BTreeMap::new(),
        }
    }
}

/// Who may ask.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PeerConfig {
    /// Authorised uids. Empty authorises nobody.
    #[serde(default)]
    pub allow_uids: Vec<u32>,
    /// Authorised client code hashes, lower-case hex, 40 characters each.
    /// Produced by `keylessd pin`. Empty authorises nobody.
    #[serde(default)]
    pub allow_images: Vec<String>,
}

/// Where the daemon reads values from.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DaemonStores {
    /// A flat file only the daemon's uid can read.
    #[serde(default)]
    pub file: FileStoreConfig,
    /// A keychain the daemon's uid owns.
    #[serde(default)]
    pub keychain: DaemonKeychainConfig,
    /// Infisical, reached through the vendor CLI under the daemon's own uid.
    #[serde(default)]
    pub infisical: DaemonInfisicalConfig,
    /// 1Password, reached through `op` under the daemon's own uid, as a
    /// service account pinned to one vault.
    #[serde(default)]
    pub onepassword: DaemonOnePasswordConfig,
    /// Proton Pass, reached through `pass-cli` under the daemon's own uid, as
    /// a viewer-role agent token in a session directory the daemon owns.
    #[serde(default)]
    pub proton: DaemonProtonConfig,
    /// How a name that pins no store chooses one. See [`crate::config::Policy`].
    ///
    /// The strict one by default, on the daemon exactly as on a session: the
    /// daemon's two stores are no more interchangeable than a company vault
    /// and a personal one, and picking by configuration order picks wrong
    /// silently.
    #[serde(default)]
    pub policy: StorePolicy,
    /// The store a name that pins none resolves against.
    ///
    /// Named `default` in the file, under `stores`, which is where the session
    /// config puts it. Without it, a daemon running both stores can answer no
    /// unpinned name at all.
    #[serde(default, rename = "default", skip_serializing_if = "Option::is_none")]
    pub default_store: Option<String>,
}

/// Settings for the file store.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileStoreConfig {
    /// Off unless asked for.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the `{"NAME":"value"}` file.
    #[serde(default = "default_secrets_file")]
    pub path: ConfigPath,
}

impl Default for FileStoreConfig {
    fn default() -> Self {
        FileStoreConfig {
            enabled: false,
            path: default_secrets_file(),
        }
    }
}

/// The entry [`DaemonProtonConfig::credential_entries`] writes the generated
/// local key under when the config names none.
///
/// Named rather than derived from the variable, because it is a label in a
/// credential file and reads beside `AGENT_TOKEN` rather than beside
/// `PROTON_PASS_*`.
pub const DEFAULT_LOCAL_KEY_ENTRY: &str = "LOCAL_KEY";

fn default_socket() -> ConfigPath {
    ConfigPath::from(crate::ipc::default_socket_path())
}

fn default_audit() -> ConfigPath {
    ConfigPath::from(
        PathBuf::from("/usr/local/var/log")
            .join(crate::NAME)
            .join("audit.jsonl"),
    )
}

fn default_secrets_file() -> ConfigPath {
    ConfigPath::from(
        PathBuf::from("/usr/local/var/lib")
            .join(crate::NAME)
            .join("secrets.json"),
    )
}

const fn default_ttl_seconds() -> u64 {
    60
}

/// Four minutes past freshness, so the two windows together reach five.
///
/// The AWS Secrets Manager Agent's own default TTL is 300 seconds, and Vault
/// Proxy's static-secret cache accepts a five-minute bound on how late a
/// permission change takes effect. This daemon's window is narrower than
/// either: it opens only while a store cannot answer.
const fn default_stale_seconds() -> u64 {
    240
}

/// The longest either cache window may be, whatever a config says.
///
/// Both windows bound how long a value the vendor has replaced can still be
/// handed to a child, so neither is a number a config may set to a day. Fifteen
/// minutes matches the listing cache's own ceiling.
pub const MAX_CACHE_SECONDS: u64 = 900;

/// A configured window in seconds, clamped to `ceiling`.
const fn bounded_cache_seconds(seconds: u64, ceiling: u64) -> u64 {
    if seconds > ceiling { ceiling } else { seconds }
}

/// Four hours: the shortest window that covered practically every silence
/// measured, where the last good value was at most that old.
const fn default_silent_seconds() -> u64 {
    4 * 60 * 60
}

/// The longest the silent window may be, whatever a config says.
///
/// A credential revoked while its store is silent keeps reaching children for
/// this long, so it is bounded on the same rule as the other two windows: a
/// config is not a trusted input.
pub const MAX_SILENT_SECONDS: u64 = 24 * 60 * 60;

const fn default_idle_seconds() -> u64 {
    15
}

// The three below are the session config's own defaults, reached rather than
// re-spelled: a second literal here would be free to drift, and the drift would
// be invisible because both spellings resolve.
fn default_listing_ttl_ms() -> u64 {
    crate::config::default_listing_ttl_ms()
}

fn default_probe_binary() -> ConfigPath {
    crate::config::default_probe_binary()
}

/// Thirty seconds per vendor call on this side, where the session allows ten.
///
/// The two sides wait for different things. A session's call has a person in
/// front of it, and ten seconds is already longer than anyone wants to watch.
/// A daemon's call has a heartbeat in front of it — the client's deadline is a
/// silence deadline under a 120 s ceiling (`crate::ipc::client`) — so a late
/// value still arrives, while a call abandoned at ten seconds is a degraded run
/// that no amount of waiting recovers.
///
/// Ten was what a vendor process needed on an idle machine. Under memory
/// pressure the same process spends the same hundredths of a second of CPU
/// against ten seconds of wall time, and every call that was killed at the
/// ceiling had reached the vendor and was waiting on the scheduler. Thirty is
/// past that, and well under the ceiling.
const fn default_timeout_ms() -> u64 {
    30_000
}

impl DaemonConfig {
    /// Read a config file.
    ///
    /// A missing file is an error rather than a default, unlike the session's
    /// config: a daemon with default settings authorises nothing and would
    /// simply refuse every request, which is a confusing way to say "you have
    /// not configured me".
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|error| ConfigError::Parse {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })
    }

    /// The freshness window: how long a value is served without asking.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        Duration::from_secs(bounded_cache_seconds(
            self.cache_ttl_seconds,
            MAX_CACHE_SECONDS,
        ))
    }

    /// The stale window: how long past freshness a value may still be served
    /// while its store cannot answer.
    ///
    /// Zero whenever caching itself is off, so one key turns the whole
    /// mechanism off rather than leaving a second one to be remembered.
    #[must_use]
    pub const fn stale(&self) -> Duration {
        if self.cache_ttl_seconds == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs(bounded_cache_seconds(
            self.cache_stale_seconds,
            MAX_CACHE_SECONDS,
        ))
    }

    /// The silent window: how old a value may be and still be served while
    /// its store is silent.
    ///
    /// Zero whenever caching itself is off, for the reason [`Self::stale`] is.
    #[must_use]
    pub const fn silent(&self) -> Duration {
        if self.cache_ttl_seconds == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs(bounded_cache_seconds(
            self.cache_silent_seconds,
            MAX_SILENT_SECONDS,
        ))
    }

    /// The per-connection idle timeout.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_seconds)
    }

    /// Build the attestation policy, refusing anything it cannot parse.
    ///
    /// A malformed pin is an error rather than a skipped entry. Skipping would
    /// mean a typo in one of five hashes silently locks out one client and
    /// leaves four working — a failure that looks like a client bug and gets
    /// debugged in the wrong place for an afternoon.
    pub fn policy(&self) -> Result<Policy, PolicyError> {
        let mut policy = Policy::new();
        for uid in &self.peer.allow_uids {
            policy = policy.allow_uid(*uid);
        }
        let mut seen = BTreeSet::new();
        for hex in &self.peer.allow_images {
            let trimmed = hex.trim();
            let Some(hash) = decode_hex(trimmed) else {
                return Err(PolicyError::BadPin(trimmed.to_owned()));
            };
            if !seen.insert(hash) {
                return Err(PolicyError::DuplicatePin(trimmed.to_owned()));
            }
            policy = policy.allow_image(hash);
        }
        Ok(policy)
    }
}

/// The allowlist could not be turned into a policy.
#[derive(Debug)]
pub enum PolicyError {
    /// A pin is not 40 hex characters.
    BadPin(String),
    /// The same pin appears twice, which usually means a copy-paste that was
    /// meant to be two different clients.
    DuplicatePin(String),
    /// A pin names something whose identity is an interpreter's.
    InterpreterPin(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::BadPin(text) => write!(
                f,
                "`{text}` is not a 40-character code hash; run `keylessd pin --path <binary>`"
            ),
            PolicyError::DuplicatePin(text) => {
                write!(f, "`{text}` is pinned twice")
            }
            PolicyError::InterpreterPin(name) => write!(
                f,
                "`{name}` is an interpreter; pinning it would authorise every program it runs"
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Refuse to pin an interpreter.
///
/// The request-time check in [`crate::attest`] already refuses one. This is the
/// same rule moved to the earliest possible moment, so an operator finds out
/// while reading a command's output rather than while reading a refusal in the
/// audit log a week later.
pub fn refuse_interpreter_pin(path: &Path) -> Result<(), PolicyError> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if is_interpreter(name) {
        return Err(PolicyError::InterpreterPin(name.to_owned()));
    }
    Ok(())
}
