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
use crate::store::file::FileStore;
use crate::store::infisical::{InfisicalStore, Routing};
use crate::store::keychain::KeychainStore;
use crate::store::{Registry, Store};

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
    /// How long a resolved value may be reused from memory.
    #[serde(default = "default_ttl_seconds")]
    pub cache_ttl_seconds: u64,
    /// How long a connection may sit idle before it is dropped.
    #[serde(default = "default_idle_seconds")]
    pub idle_timeout_seconds: u64,
    /// Who may ask.
    #[serde(default)]
    pub peer: PeerConfig,
    /// Where the values come from.
    #[serde(default)]
    pub stores: DaemonStores,
    /// Names the daemon will admit to knowing, for the `names` operation.
    ///
    /// Empty means "answer with nothing", which is the safe default: name
    /// enumeration is a small leak, but it is a leak, and it should be opt-in.
    #[serde(default)]
    pub names: Vec<String>,
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
    /// name up at, read by [`DaemonConfig::infisical_routing`]. The remaining
    /// fields describe adapters the daemon does not carry and are ignored.
    ///
    /// **`env` here is the ONLY place a daemon-hosted lookup can get an
    /// Infisical environment from.** See [`DaemonConfig::infisical_routing`].
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRoute>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            socket: default_socket(),
            audit: default_audit(),
            cache_ttl_seconds: default_ttl_seconds(),
            idle_timeout_seconds: default_idle_seconds(),
            peer: PeerConfig::default(),
            stores: DaemonStores::default(),
            names: Vec::new(),
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

/// Settings for a keychain the daemon owns.
///
/// Separate from [`crate::config::KeychainConfig`] for one reason: that one
/// defaults to enabled, which is right for a session reading its own login
/// keychain and wrong for a daemon, where the safe default is to have no store
/// at all until an operator names one.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonKeychainConfig {
    /// Off unless asked for.
    #[serde(default)]
    pub enabled: bool,
    /// Generic-password service.
    #[serde(default = "default_service")]
    pub service: String,
    /// Path to the `security` binary.
    #[serde(default = "default_security_binary")]
    pub binary: ConfigPath,
    /// The keychain file to search.
    ///
    /// **Required in practice.** A daemon has no login keychain, so leaving
    /// this unset makes `security` search the default list of a user that has
    /// no GUI session, which finds nothing. The installer creates a keychain
    /// owned by the daemon's uid and names it here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keychain: Option<ConfigPath>,
}

impl Default for DaemonKeychainConfig {
    fn default() -> Self {
        DaemonKeychainConfig {
            enabled: false,
            service: default_service(),
            binary: default_security_binary(),
            keychain: None,
        }
    }
}

/// Settings for the Infisical backend, on the daemon's side of the boundary.
///
/// Separate from [`crate::config::InfisicalConfig`] for one reason, and it is
/// the reason this adapter can be hosted here at all: **that type has an `env`
/// field and this one does not.** The session's is dead — kept only so a config
/// that still sets it can be told so — but a daemon-side copy of it would be a
/// key an operator could write to give every name an environment, which is
/// exactly the "any invented name resolves against production" hazard that
/// motivated removing it. Here there is no field to write. See
/// [`DaemonConfig::infisical_routing`].
///
/// Everything else is a coordinate or a knob, spelled as the session config
/// spells it, so a setting moved across the boundary keeps its name.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonInfisicalConfig {
    /// Off unless asked for.
    #[serde(default)]
    pub enabled: bool,
    /// Path to, or name of, the `infisical` binary.
    ///
    /// **Worth an absolute path here.** A launchd daemon's `PATH` is whatever
    /// launchd hands it, not a login shell's, so the bare name a session
    /// resolves happily may resolve to nothing under the daemon.
    #[serde(default = "default_infisical_binary")]
    pub binary: ConfigPath,
    /// Folder used by a name that declares none. The vendor's own `/`.
    #[serde(default = "default_infisical_path")]
    pub path: String,
    /// Project id. See [`crate::store::infisical::InfisicalStore::in_project`]
    /// for why a daemon usually needs this or `config_dir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Directory holding `.infisical.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_dir: Option<ConfigPath>,
    /// How long one lookup may take before it degrades the run.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// The helper that reads one variable out of the child environment.
    #[serde(default = "default_probe_binary")]
    pub probe_binary: ConfigPath,
}

impl Default for DaemonInfisicalConfig {
    fn default() -> Self {
        DaemonInfisicalConfig {
            enabled: false,
            binary: default_infisical_binary(),
            path: default_infisical_path(),
            project_id: None,
            config_dir: None,
            timeout_ms: default_timeout_ms(),
            probe_binary: default_probe_binary(),
        }
    }
}

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

const fn default_idle_seconds() -> u64 {
    15
}

fn default_service() -> String {
    crate::NAME.to_owned()
}

fn default_security_binary() -> ConfigPath {
    ConfigPath::from("/usr/bin/security")
}

// The three below are the session config's own defaults, reached rather than
// re-spelled: a second literal here would be free to drift, and the drift would
// be invisible because both spellings resolve.
fn default_infisical_binary() -> ConfigPath {
    crate::config::default_infisical_binary()
}

fn default_infisical_path() -> String {
    crate::config::default_infisical_path()
}

fn default_probe_binary() -> ConfigPath {
    crate::config::default_probe_binary()
}

const fn default_timeout_ms() -> u64 {
    crate::config::DEFAULT_TIMEOUT_MS
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

    /// The cache TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        Duration::from_secs(self.cache_ttl_seconds)
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

    /// Where each name lives inside Infisical, with **no environment of the
    /// daemon's own** anywhere behind it.
    ///
    /// # The whole security argument for hosting this adapter here
    ///
    /// The measured hazard of the Infisical adapter is that a caller-supplied
    /// name becomes a key lookup at the root of whatever environment is in
    /// scope: given one, an invented name spawns the vendor and asks a real
    /// vault for it. On a session that environment can come from
    /// `keyless run --env <slug>`, which is the caller's own word.
    ///
    /// A daemon cannot be told one. [`crate::ipc::protocol::Request`] carries
    /// `v`, `op`, `name`, `cwd` and `argv` and no environment field, so there
    /// is nothing on the wire to read — and this method supplies none either,
    /// which is why it calls the constructor that has no parameter for it. A
    /// name resolves only against the `env` an operator wrote beside it under
    /// `secrets`, in a file the calling user cannot write. Every other name is
    /// refused before a process is spawned or a packet is sent.
    ///
    /// **There is deliberately no daemon-level default environment, and `env`
    /// must never join the wire protocol.** Both would restore the hazard on
    /// the untrusted side of the uid boundary, and both would look like they
    /// worked: a wrong environment answers with a real, plausible value.
    ///
    /// The folder path is defaulted to the vendor's own `/`, which invents
    /// nothing — see [`crate::config::InfisicalConfig::path`] for why the two
    /// coordinates are treated differently.
    #[must_use]
    pub fn infisical_routing(&self) -> Routing {
        Routing::without_invocation_env(&self.secrets, &self.stores.infisical.path)
    }

    /// Whether any declared name states an Infisical environment.
    ///
    /// Read off [`DaemonConfig::infisical_routing`] rather than off `secrets`
    /// directly, so this asks the same question a lookup asks. A second walk of
    /// the map is how a warning stops matching the behaviour it warns about.
    fn declares_any_infisical_environment(&self) -> bool {
        let routing = self.infisical_routing();
        self.secrets
            .keys()
            .any(|name| routing.route(name).env.is_some())
    }

    /// Which name is pinned to which store, by store id.
    ///
    /// Only [`SecretRoute::store`] is read here: the coordinate fields beside
    /// it say where a name lives *inside* a backend, which is
    /// [`DaemonConfig::infisical_routing`]'s question rather than this one's.
    fn routes(&self) -> BTreeMap<String, String> {
        self.secrets
            .iter()
            .filter_map(|(name, route)| route.store.clone().map(|store| (name.clone(), store)))
            .collect()
    }

    /// Build the store registry, with the routing that decides which store
    /// answers a name.
    ///
    /// Order is search order, and the file store comes first because it is the
    /// one whose permissions this crate can actually enforce. Order is **not**
    /// how a name picks a store, though: under the default
    /// [`StorePolicy::Explicit`] a name resolves against its own pin, else
    /// `stores.default`, else the single configured store — and two stores with
    /// neither is reported as ambiguous rather than guessed at.
    ///
    /// The routing has to live here, on the daemon's side, because the daemon
    /// is the side that knows what its stores hold. A session cannot settle it:
    /// [`crate::store::build`] drops every per-name pin when the daemon is
    /// enabled, precisely so a client cannot steer which vault answers.
    #[must_use]
    pub fn registry(&self) -> Registry {
        let mut stores: Vec<Box<dyn Store>> = Vec::new();
        if self.stores.file.enabled {
            stores.push(Box::new(FileStore::new(
                self.stores.file.path.to_path_buf(),
            )));
        }
        if self.stores.keychain.enabled {
            stores.push(Box::new(
                KeychainStore::new(
                    self.stores.keychain.binary.to_path_buf(),
                    self.stores.keychain.service.clone(),
                )
                .in_keychain(
                    self.stores
                        .keychain
                        .keychain
                        .as_deref()
                        .map(|path| path.to_path_buf()),
                ),
            ));
        }
        if self.stores.infisical.enabled {
            let settings = &self.stores.infisical;
            stores.push(Box::new(
                InfisicalStore::new(
                    settings.binary.to_path_buf(),
                    settings.probe_binary.to_path_buf(),
                    // The environment-free routing, and the only one this side
                    // ever builds. See `infisical_routing` for why the absence
                    // is what makes hosting this adapter here safe.
                    self.infisical_routing(),
                )
                .with_timeout(settings.timeout_ms)
                .in_project(
                    settings.project_id.clone(),
                    settings
                        .config_dir
                        .as_deref()
                        .map(|path| path.to_path_buf()),
                ),
            ));
        }
        Registry::new(stores)
            .with_routes(self.routes())
            .with_policy(self.stores.policy)
            .with_default_store(self.stores.default_store.clone())
    }

    /// Problems worth telling an operator about that are not fatal.
    ///
    /// Returned rather than printed so `keylessd` and its tests see the same
    /// list.
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.peer.allow_uids.is_empty() {
            warnings.push("no uid is authorised, so every request will be refused".to_owned());
        }
        if self.peer.allow_images.is_empty() {
            warnings.push(
                "no client image is pinned, so every request will be refused; run `keylessd pin`"
                    .to_owned(),
            );
        }
        if !self.stores.file.enabled
            && !self.stores.keychain.enabled
            && !self.stores.infisical.enabled
        {
            warnings.push("no store is enabled, so no name can resolve".to_owned());
        }
        if self.stores.infisical.enabled && !self.declares_any_infisical_environment() {
            // The operator-facing form of the rule in `infisical_routing`. Left
            // unsaid, the first anyone hears of it is every Infisical name
            // degrading with a sentence about a config key, and nothing having
            // mentioned it while the config was being written.
            warnings.push(
                "the Infisical store is enabled and no name under `secrets` declares an \
                 \"env\", so no name can resolve against it: a daemon has no invocation \
                 environment and there is deliberately no default"
                    .to_owned(),
            );
        }
        if self.stores.keychain.enabled && self.stores.keychain.keychain.is_none() {
            warnings.push(
                "the keychain store has no keychain file; a daemon has no login keychain, \
                 so lookups will find nothing"
                    .to_owned(),
            );
        }

        // The store ids come from the registry the daemon will actually build,
        // rather than from a second list of names kept in step with it. A
        // hand-written list is how a store gets renamed and its warning quietly
        // stops firing.
        let registry = self.registry();
        let configured: Vec<&str> = registry.stores().iter().map(|store| store.id()).collect();

        // Silent until the first request otherwise: every unpinned name comes
        // back ambiguous, each session degrades with a sentence about config
        // keys, and nothing said so while the config was being written.
        if configured.len() > 1
            && self.stores.default_store.is_none()
            && self.stores.policy == StorePolicy::Explicit
        {
            warnings.push(format!(
                "{} stores are enabled ({}) and none is the default, so a name that pins no \
                 store resolves against nothing; set \"stores.default\", or give each name a \
                 \"store\" under `secrets`",
                configured.len(),
                configured.join(", ")
            ));
        }

        // A pin naming a store that is off fails at resolve time with `routed
        // store is not configured`, which reaches a session as a degraded run
        // and points at a store only this file can enable.
        let mut dangling: Vec<String> = self
            .routes()
            .into_iter()
            .filter(|(_, store)| !configured.contains(&store.as_str()))
            .map(|(name, store)| format!("{name} -> {store}"))
            .collect();
        if let Some(default) = &self.stores.default_store
            && !configured.contains(&default.as_str())
        {
            dangling.push(format!("stores.default -> {default}"));
        }
        if !dangling.is_empty() {
            dangling.sort();
            warnings.push(format!(
                "these routes name a store that is not enabled, so the names they cover \
                 resolve against nothing: {}",
                dangling.join(", ")
            ));
        }

        warnings
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

#[cfg(test)]
mod tests {
    use super::{DaemonConfig, PolicyError, StorePolicy, refuse_interpreter_pin};
    use std::path::Path;

    fn parse(json: &str) -> DaemonConfig {
        serde_json::from_str(json).expect("valid daemon config")
    }

    #[test]
    fn an_empty_config_authorises_nothing_and_says_so() {
        let config = parse("{}");
        let policy = config.policy().expect("an empty allowlist still parses");
        assert!(policy.is_empty());
        assert_eq!(policy.image_count(), 0);
        let warnings = config.warnings();
        assert!(warnings.iter().any(|w| w.contains("no uid")));
        assert!(warnings.iter().any(|w| w.contains("no client image")));
        assert!(warnings.iter().any(|w| w.contains("no store")));
    }

    #[test]
    fn a_malformed_pin_is_an_error_rather_than_a_skipped_entry() {
        let config = parse(r#"{"peer":{"allow_uids":[501],"allow_images":["deadbeef"]}}"#);
        assert!(matches!(config.policy(), Err(PolicyError::BadPin(_))));
    }

    #[test]
    fn a_duplicated_pin_is_an_error() {
        let hash = "a".repeat(40);
        let config = parse(&format!(
            r#"{{"peer":{{"allow_uids":[501],"allow_images":["{hash}","{hash}"]}}}}"#
        ));
        assert!(matches!(config.policy(), Err(PolicyError::DuplicatePin(_))));
    }

    #[test]
    fn a_well_formed_config_yields_a_usable_policy() {
        let config = parse(
            r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"file":{"enabled":true,"path":"/tmp/x.json"}}}"#,
        );
        let policy = config.policy().expect("valid");
        assert!(!policy.is_empty());
        assert_eq!(policy.image_count(), 1);
        assert_eq!(config.registry().stores().len(), 1);
        assert!(config.warnings().is_empty());
    }

    #[test]
    fn two_stores_with_no_default_are_warned_about_before_a_request_arrives() {
        // Otherwise the first anyone hears of it is a session degrading, with
        // a message about config keys nobody has been told belong to this file.
        let config = parse(
            r#"{"stores":{"file":{"enabled":true},
                          "keychain":{"enabled":true,"keychain":"/tmp/k.keychain-db"}}}"#,
        );
        let said = config.warnings().join(" ");
        assert!(said.contains("stores.default"), "{said}");
        assert!(said.contains("file"), "{said}");
        assert!(said.contains("keychain"), "{said}");
    }

    #[test]
    fn a_default_store_silences_the_two_store_warning() {
        // The negative control for the test above: without it, that warning
        // could be firing on every two-store config regardless of routing.
        let config = parse(
            r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"file":{"enabled":true},
                          "keychain":{"enabled":true,"keychain":"/tmp/k.keychain-db"},
                          "default":"file"}}"#,
        );
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
    }

    #[test]
    fn a_route_naming_a_store_that_is_not_enabled_is_warned_about() {
        let config = parse(
            r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"file":{"enabled":true}},
                "secrets":{"DATABASE_URL":{"store":"keychain"}}}"#,
        );
        let said = config.warnings().join(" ");
        assert!(said.contains("DATABASE_URL -> keychain"), "{said}");
    }

    #[test]
    fn a_names_own_pin_decides_which_of_the_daemons_stores_answers() {
        // Both keys are read off the same file, and the name's own pin
        // outranks the default — the precedence the session config has, so a
        // route moved across the boundary keeps meaning what it meant.
        let config = parse(
            r#"{"stores":{"file":{"enabled":true},
                          "keychain":{"enabled":true,"keychain":"/tmp/k.keychain-db"},
                          "default":"keychain"},
                "secrets":{"DATABASE_URL":{"store":"file"}}}"#,
        );
        let registry = config.registry();
        assert_eq!(registry.stores().len(), 2);
        // The file store's path does not exist, so this cannot be a value; the
        // question is only WHICH store was asked, and a route to a store that
        // is not registered says `routed store is not configured`.
        for name in ["DATABASE_URL", "ANYTHING_ELSE"] {
            assert!(
                !registry
                    .resolve(name)
                    .reason()
                    .contains("stores could answer"),
                "`{name}` was ambiguous despite a route covering it"
            );
        }
    }

    #[test]
    fn the_store_policy_is_read_from_the_file_like_a_sessions_is() {
        let config = parse(
            r#"{"stores":{"file":{"enabled":true},
                          "keychain":{"enabled":true,"keychain":"/tmp/k.keychain-db"},
                          "policy":"ordered"}}"#,
        );
        assert_eq!(config.stores.policy, StorePolicy::Ordered);
        // Ordering never refuses to choose, so it is never ambiguous — and the
        // two-store warning is about ambiguity, so it does not fire.
        let said = config.warnings().join(" ");
        assert!(!said.contains("stores.default"), "{said}");
    }

    // -----------------------------------------------------------------------
    // The Infisical coordinates, and the environment the daemon cannot have.
    // -----------------------------------------------------------------------

    #[test]
    fn a_names_own_coordinates_are_read_from_the_daemons_own_config() {
        // `env`, `path` and `key` parsed into `SecretRoute` long before
        // anything read them. This is the projection that starts reading them,
        // and it must produce exactly what was written down.
        let config = parse(
            r#"{"secrets":{"DATABASE_URL":{"store":"infisical","env":"staging",
                                           "path":"/backend","key":"PG_URL"}}}"#,
        );
        let route = config.infisical_routing().route("DATABASE_URL");
        assert_eq!(route.env.as_deref(), Some("staging"));
        assert_eq!(route.path, "/backend");
        assert_eq!(route.key, "PG_URL");
    }

    #[test]
    fn a_declared_name_that_states_no_environment_gets_none() {
        // Not an error here — it is a route with nothing to look up, and the
        // adapter turns that into a refusal that spawns nothing.
        let config = parse(r#"{"secrets":{"DATABASE_URL":{"store":"infisical"}}}"#);
        assert_eq!(config.infisical_routing().route("DATABASE_URL").env, None);
    }

    #[test]
    fn no_daemon_config_key_supplies_a_default_infisical_environment() {
        // The rule this whole adapter's daemon port rests on, asserted the way
        // `there_is_no_config_key_that_permits_interpreted_callers` asserts
        // its own: a future key spelled any of these ways is dropped by serde,
        // so what matters is that the PARSED config cannot express one and the
        // routing built from it hands an undeclared name no environment.
        //
        // Every spelling below is one somebody reaching for a default would
        // try, including the session config's own dead `stores.infisical.env`.
        let config = parse(
            r#"{"stores":{"infisical":{"env":"prod"},"env":"prod","default_env":"prod"},
                "env":"prod","infisical_env":"prod",
                "secrets":{"DECLARED":{"store":"infisical","env":"staging"}}}"#,
        );
        let rendered = serde_json::to_string(&config).expect("serialize");
        for spelling in ["prod", "default_env", "infisical_env"] {
            assert!(
                !rendered.contains(spelling),
                "`{spelling}` survived the parse: {rendered}"
            );
        }

        let routing = config.infisical_routing();
        // The negative control, and it is not decoration: without it every
        // assertion here would be satisfied by a routing that resolves nothing
        // at all, which is not the property being claimed.
        assert_eq!(routing.route("DECLARED").env.as_deref(), Some("staging"));
        assert_eq!(
            routing.route("A_NAME_NOBODY_EVER_DECLARED").env,
            None,
            "a name the daemon's config never declared must have no environment, \
             or it becomes a key lookup against a real vault"
        );
    }

    #[test]
    fn an_undeclared_name_takes_the_vendors_own_folder_and_its_own_key() {
        // The other two coordinates ARE defaulted, and the asymmetry is the
        // point: a wrong folder can only miss inside an environment somebody
        // named, and with no environment the lookup never happens anyway.
        let route = parse("{}")
            .infisical_routing()
            .route("A_NAME_NOBODY_EVER_DECLARED");
        assert_eq!(route.path, "/");
        assert_eq!(route.key, "A_NAME_NOBODY_EVER_DECLARED");
    }

    #[test]
    fn enabling_infisical_registers_it_and_leaves_the_other_stores_alone() {
        let config = parse(
            r#"{"stores":{"infisical":{"enabled":true,
                                       "binary":"/nonexistent/keyless-test/infisical"}},
                "secrets":{"DATABASE_URL":{"env":"staging"}}}"#,
        );
        let registry = config.registry();
        let ids: Vec<&str> = registry.stores().iter().map(|store| store.id()).collect();
        assert_eq!(ids, ["infisical"]);

        // The negative control: with the branch removed the registry is empty,
        // and an empty registry answers `not found in any store` — which reads
        // as a working lookup that came back empty rather than as an absent
        // adapter. Asking for the store id is what tells them apart.
        assert_eq!(parse("{}").registry().stores().len(), 0);
    }

    #[test]
    fn an_undeclared_name_reaches_no_vendor_because_it_has_no_environment() {
        // The whole safety argument, at the level this file can assert it: the
        // binary does not exist, so a lookup that SPAWNED would report the
        // store unavailable. A refusal that names the missing environment is a
        // lookup that never happened. `tests/daemon_infisical.rs` proves the
        // absence of the spawn itself, against a stand-in that records its argv.
        let config = parse(
            r#"{"stores":{"infisical":{"enabled":true,
                                       "binary":"/nonexistent/keyless-test/infisical"}},
                "secrets":{"DECLARED":{"env":"staging"}}}"#,
        );
        let registry = config.registry();

        let invented = registry.resolve("A_NAME_NOBODY_EVER_DECLARED").reason();
        assert!(invented.contains("was not asked"), "{invented}");
        assert!(
            !invented.contains("unavailable"),
            "the vendor was reached for a name nobody declared: {invented}"
        );

        // And the control that stops the above being satisfied by a store that
        // cannot look anything up: a DECLARED name does reach for the binary.
        let declared = registry.resolve("DECLARED").reason();
        assert!(
            declared.contains("unavailable"),
            "a declared name must actually be looked up: {declared}"
        );
    }

    #[test]
    fn an_infisical_store_with_no_environment_anywhere_is_warned_about() {
        let said = parse(
            r#"{"stores":{"infisical":{"enabled":true}},
                             "secrets":{"DATABASE_URL":{}}}"#,
        )
        .warnings()
        .join(" ");
        assert!(said.contains("no name can resolve against it"), "{said}");

        // The negative control: one name with an environment silences it.
        let quiet = parse(
            r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"infisical":{"enabled":true}},
                "secrets":{"DATABASE_URL":{"env":"staging"}}}"#,
        )
        .warnings();
        assert!(quiet.is_empty(), "{quiet:?}");
    }

    #[test]
    fn there_is_no_config_key_that_permits_interpreted_callers() {
        // The rule exists to be un-turn-off-able from a file. A future key
        // called anything like this would be ignored by serde, so the check
        // that matters is that the parsed config cannot express it.
        let config = parse(r#"{"peer":{"refuse_interpreters":false,"allow_uids":[501]}}"#);
        let rendered = serde_json::to_string(&config).expect("serialize");
        assert!(!rendered.contains("refuse_interpreters"));
    }

    #[test]
    fn pinning_an_interpreter_is_refused_at_the_earliest_moment() {
        assert!(refuse_interpreter_pin(Path::new("/opt/homebrew/bin/node")).is_err());
        assert!(refuse_interpreter_pin(Path::new("/usr/bin/python3")).is_err());
        assert!(refuse_interpreter_pin(Path::new("/usr/local/bin/keyless")).is_ok());
    }

    #[test]
    fn a_missing_daemon_config_is_an_error_rather_than_defaults() {
        assert!(DaemonConfig::load(Path::new("/nonexistent/keylessd.json")).is_err());
    }
}
