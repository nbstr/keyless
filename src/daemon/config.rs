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
use std::sync::Arc;
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
use crate::store::catalogue::{Catalogue, ProtonMint, Source};
use crate::store::file::FileStore;
use crate::store::infisical::{
    ACCESS_TOKEN, IDENTITY_CLIENT_ID, IDENTITY_CLIENT_SECRET, InfisicalStore, Routing,
    VendorCredentials,
};
use crate::store::keychain::KeychainStore;
use crate::store::onepassword::{
    OnePasswordStore, Routing as OnePasswordRouting, SERVICE_ACCOUNT_TOKEN, ServiceAccount,
};
use crate::store::proton::{
    AgentToken, ENCRYPTION_KEY_VAR as PROTON_ENCRYPTION_KEY, KeyProvider, ProtonStore,
    Reason as ProtonReason, Routing as ProtonRouting, TOKEN_VAR as PROTON_TOKEN,
};
use crate::store::proton_session::Generations;
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
    /// This is the window a store's SILENCE opens. A store that answers ends
    /// it either way: a value replaces the entry, and an answer that disowns it
    /// — no such item, a refused token — evicts it.
    #[serde(default = "default_stale_seconds")]
    pub cache_stale_seconds: u64,
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
    /// Which Infisical instance to reach, when it is not the vendor's default.
    ///
    /// **The vendor's default is the US cloud, and a wrong region is quiet.**
    /// An identity minted in another region has no account there, so the
    /// refusal an operator reads is about their credentials rather than about
    /// their region — and `config_dir` cannot settle it either: measured
    /// against 0.43.124, a `.infisical.json` beside a machine identity is not
    /// consulted for the project at all.
    ///
    /// A URL, not a secret. See
    /// [`crate::store::infisical::InfisicalStore::at_domain`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// How long one lookup may take before it degrades the run.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// The helper that reads one variable out of the child environment.
    #[serde(default = "default_probe_binary")]
    pub probe_binary: ConfigPath,
    /// The vendor's own login: which `INFISICAL_*` variable holds it, and which
    /// entry of [`DaemonInfisicalConfig::credentials_file`] its value is in.
    ///
    /// **Names, never values.** This file holds coordinates, exactly as a
    /// session's does, and there is no field here a token fits in — which is
    /// what lets `keylessd.json` be readable by whoever administers the machine.
    /// See [`crate::store::infisical::VendorCredentials`] for why the daemon
    /// needs this at all and why the plist is the wrong place for it.
    ///
    /// Only `INFISICAL_*` is accepted. A variable named here that is not one is
    /// refused by every lookup, and said out loud by [`DaemonConfig::warnings`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, String>,
    /// The mode-`0600` file those values live in.
    ///
    /// **A file of its own by default, beside the secrets file rather than
    /// inside it.** Anything in the file the `file` store serves is a name an
    /// attested client can ask for by name — so a machine identity kept there
    /// would be handed to any session that guessed its label, which is the
    /// opposite of moving the credential behind the boundary. Pointing this at
    /// the same file is possible and is warned about.
    #[serde(default = "default_infisical_credentials_file")]
    pub credentials_file: ConfigPath,
}

impl Default for DaemonInfisicalConfig {
    fn default() -> Self {
        DaemonInfisicalConfig {
            enabled: false,
            binary: default_infisical_binary(),
            path: default_infisical_path(),
            project_id: None,
            config_dir: None,
            domain: None,
            timeout_ms: default_timeout_ms(),
            probe_binary: default_probe_binary(),
            credentials: BTreeMap::new(),
            credentials_file: default_infisical_credentials_file(),
        }
    }
}

/// Settings for the 1Password backend, on the daemon's side of the boundary.
///
/// This is where the vault allowlist becomes a boundary. A session's `op`
/// inherits a login that sees every vault the person can see; the daemon's
/// `op` is handed a **service account**, which the vendor minted with access to
/// named vaults and refuses everything else — and that token lives in a file
/// only the daemon's uid can read. `vault` here is required exactly as it is
/// in a session, and for the same reason: which vault a name resolves against
/// must be written down, never inferred from what the login happens to see.
///
/// Spelled as the session config spells it, so a setting moved across the
/// boundary keeps its name.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonOnePasswordConfig {
    /// Off unless asked for.
    #[serde(default)]
    pub enabled: bool,
    /// Path to, or name of, the `op` binary. Worth an absolute path here, for
    /// the reason [`DaemonInfisicalConfig::binary`] gives.
    #[serde(default = "default_onepassword_binary")]
    pub binary: ConfigPath,
    /// The one vault this daemon reads. See
    /// [`crate::config::OnePasswordConfig::vault`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Which account, as `--account`. A service account implies its own and
    /// usually needs none; a daemon signed in some other way names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The field a name reads when its own entry declares none. See
    /// [`crate::config::OnePasswordConfig::field`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The CLI's own configuration directory, as `--config`.
    ///
    /// **Worth setting here.** `op` keeps an account list and a cache socket
    /// under the calling user's config directory, and a daemon uid's home may
    /// not be one the vendor can write to. This names one it can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_dir: Option<ConfigPath>,
    /// How long one lookup may take before it degrades the run.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// How long one vault listing may be reused. See
    /// [`crate::config::OnePasswordConfig::listing_ttl_ms`].
    #[serde(default = "default_listing_ttl_ms")]
    pub listing_ttl_ms: u64,
    /// The helper that reads one variable out of the child environment.
    #[serde(default = "default_probe_binary")]
    pub probe_binary: ConfigPath,
    /// The vendor's own login: which `OP_*` variable holds it, and which entry
    /// of [`DaemonOnePasswordConfig::credentials_file`] its value is in.
    ///
    /// **Names, never values**, exactly as for Infisical. The ordinary entry
    /// is `{"OP_SERVICE_ACCOUNT_TOKEN": "<entry>"}`; a Connect deployment
    /// names `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` instead. Only `OP_*` is
    /// accepted, and anything else is refused by every lookup and said out
    /// loud by [`DaemonConfig::warnings`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, String>,
    /// The mode-`0600` file those values live in. A file of its own by
    /// default, beside the secrets file rather than inside it, for the reason
    /// [`DaemonInfisicalConfig::credentials_file`] gives.
    #[serde(default = "default_onepassword_credentials_file")]
    pub credentials_file: ConfigPath,
}

impl Default for DaemonOnePasswordConfig {
    fn default() -> Self {
        DaemonOnePasswordConfig {
            enabled: false,
            binary: default_onepassword_binary(),
            vault: None,
            account: None,
            field: None,
            config_dir: None,
            timeout_ms: default_timeout_ms(),
            listing_ttl_ms: default_listing_ttl_ms(),
            probe_binary: default_probe_binary(),
            credentials: BTreeMap::new(),
            credentials_file: default_onepassword_credentials_file(),
        }
    }
}

/// Settings for the Proton Pass backend, on the daemon's side of the boundary.
///
/// # Why this one needs settings a session's does not
///
/// A session's `pass-cli` is pointed at a session directory and inherits
/// everything else: a login keychain holding the local key, a home directory,
/// an ambient environment. A daemon's uid has none of those, and each absence
/// is a field here.
///
/// - [`DaemonProtonConfig::key_provider`] replaces the login keychain, and is
///   the one that decides whether the session store survives being read at
///   all. See [`KeyProvider`].
/// - [`DaemonProtonConfig::credentials`] replaces the login, naming the agent
///   token — and, under [`KeyProvider::Env`], the local key beside it.
/// - [`DaemonProtonConfig::session_dir`] is the same field a session has and
///   means more here: the directory, the store inside it and (under
///   [`KeyProvider::Fs`]) the key inside it must all be the daemon's, because
///   `pass-cli` writes to that directory on invocations that only read.
///
/// # A viewer token, and exactly one of them
///
/// [`crate::config::ProtonConfig`] carries a second identity — an editor-role
/// `manager` session the write verbs use. There is deliberately no counterpart
/// here. With `daemon.enabled`, [`crate::store::manage`] returns
/// `DaemonHoldsIt` and refuses every write for every store, so an editor token
/// in the daemon's file would be a strictly larger prize with no ability
/// whatsoever to be used. The manager stays on the session side, where the
/// verbs that need it live.
///
/// Spelled as the session config spells it, so a setting moved across the
/// boundary keeps its name.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonProtonConfig {
    /// Off unless asked for.
    #[serde(default)]
    pub enabled: bool,
    /// Path to, or name of, the `pass-cli` binary. Worth an absolute path
    /// here, for the reason [`DaemonInfisicalConfig::binary`] gives.
    #[serde(default = "default_proton_binary")]
    pub binary: ConfigPath,
    /// The ROOT of the daemon's generation directories — see
    /// [`crate::store::proton_session::Generations`]. Each login creates
    /// `<session_dir>/gen-<millis>-<pid>/`, which is what the vendor actually
    /// sees; `<session_dir>/current` names which one is live.
    ///
    /// No default, and an absent one degrades every Proton name rather than
    /// falling back to a shared per-user location — see
    /// [`crate::store::proton::ProtonStore::session_dir`] for why inheriting is
    /// the worst of the three available answers. It matters more here than on
    /// a session: the location `pass-cli` falls back to is derived from the
    /// caller's home, and a daemon's uid either has none or has one nobody
    /// intended to be a credential store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_dir: Option<ConfigPath>,
    /// Where the key encrypting that session directory is kept.
    ///
    /// **Not the vendor's default**, which is the login keychain, which a
    /// daemon's uid does not have. See [`KeyProvider`] for what `pass-cli` does
    /// when it cannot find the local key, and why `keyring` is not a value this
    /// field can hold.
    #[serde(default)]
    pub key_provider: KeyProvider,
    /// How long one lookup may take before it degrades the run.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// How long one vault listing may be reused. See
    /// [`crate::config::ProtonConfig::listing_ttl_ms`].
    #[serde(default = "default_listing_ttl_ms")]
    pub listing_ttl_ms: u64,
    /// The helper that reads one variable out of the child environment.
    #[serde(default = "default_probe_binary")]
    pub probe_binary: ConfigPath,
    /// The daemon's own login: which `PROTON_PASS_*` variable holds it, and
    /// which entry of [`DaemonProtonConfig::credentials_file`] its value is in.
    ///
    /// **Names, never values**, exactly as for the other two vendors. The
    /// ordinary entry is `{"PROTON_PASS_PERSONAL_ACCESS_TOKEN": "<entry>"}`; a
    /// daemon running [`KeyProvider::Env`] names `PROTON_PASS_ENCRYPTION_KEY`
    /// beside it.
    ///
    /// Only those two variables are accepted — a narrower rule than the
    /// `INFISICAL_*` prefix next door, and deliberately so. Every other
    /// `PROTON_PASS_*` variable this adapter cares about is one it SETS
    /// itself: `PROTON_PASS_SESSION_DIR` chooses which identity answers and
    /// `PROTON_PASS_KEY_PROVIDER` chooses whether the session store survives,
    /// so a prefix rule would let a credential entry quietly overrule both.
    /// [`crate::store::proton::AgentToken::refused`] is what says so, and
    /// [`DaemonConfig::warnings`] says it out loud.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, String>,
    /// The mode-`0600` file those values live in. A file of its own by
    /// default, beside the secrets file rather than inside it, for the reason
    /// [`DaemonInfisicalConfig::credentials_file`] gives.
    #[serde(default = "default_proton_credentials_file")]
    pub credentials_file: ConfigPath,
    /// The day the agent token stops working, as `YYYY-MM-DD`.
    ///
    /// # Why an operator writes this down instead of the daemon asking
    ///
    /// A Proton agent token expires — the vendor's own default is months, not
    /// years — and this is the one setting whose failure arrives on a schedule
    /// nobody chose with nobody awake to read it. Infisical never needed the
    /// field because a machine identity there renews itself; there is no
    /// counterpart here.
    ///
    /// It cannot be discovered at lookup time. Read out of the 2.3.2 binary,
    /// the vendor's answer to a token it will not accept is one sentence for
    /// three different causes: `This personal access token is invalid, expired
    /// or has been deleted.` So a daemon that waited to be told would learn
    /// nothing it could act on, and would learn it at the moment every Proton
    /// name had already stopped resolving.
    ///
    /// Written down, `keylessd check` can say `expires in <n> days` while
    /// there is still time to do something, and `EXPIRED` afterwards — which
    /// is the difference between a scheduled task and an outage. Absent, the
    /// row says the date was never declared and stops there: a check nobody
    /// could make must not read as one that passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires: Option<String>,
    /// Whether this daemon keeps its own Proton session alive, and on what
    /// clock. Off by default; see [`SessionRenewal`].
    #[serde(default)]
    pub session: SessionRenewal,
}

/// The entry [`DaemonProtonConfig::credential_entries`] writes the generated
/// local key under when the config names none.
///
/// Named rather than derived from the variable, because it is a label in a
/// credential file and reads beside `AGENT_TOKEN` rather than beside
/// `PROTON_PASS_*`.
pub const DEFAULT_LOCAL_KEY_ENTRY: &str = "LOCAL_KEY";

impl DaemonProtonConfig {
    /// The credential entries this store reads: the operator's own, plus the
    /// local key's entry filled in when [`KeyProvider::Env`] is in force and
    /// the config named none.
    ///
    /// # Why the default is here rather than a refusal somewhere else
    ///
    /// Every other entry in this map is a label for a value a person typed and
    /// holds elsewhere; this one labels a value the daemon GENERATES and nobody
    /// ever sees. Asking an operator to name it buys nothing and costs every
    /// Proton name on the machine the day they forget, behind a warning printed
    /// once into a launchd log.
    ///
    /// One function rather than three defaults: the generator, the spawn's
    /// credential resolution and any check that asks what this store reads all
    /// have to agree about the name, and a fact three readers derive
    /// separately is a fact that drifts.
    /// A config naming NO credential at all gets nothing filled in: it has no
    /// token either, so it cannot establish a session whatever key it holds,
    /// and inventing an entry there would send a reader at a credential file
    /// the operator never pointed at. The gap this closes is the config that
    /// names a token and forgets the key, which is the shape an upgrade
    /// produces.
    #[must_use]
    pub fn credential_entries(&self) -> BTreeMap<String, String> {
        let mut entries = self.credentials.clone();
        if self.key_provider == KeyProvider::Env && !entries.is_empty() {
            entries
                .entry(PROTON_ENCRYPTION_KEY.to_owned())
                .or_insert_with(|| DEFAULT_LOCAL_KEY_ENTRY.to_owned());
        }
        entries
    }
}

/// The renewal loop's settings — how the daemon puts its own session back
/// before the vendor takes it away.
///
/// # Why a loop is needed at all
///
/// A session opened with a personal access token lasts **two hours**, and the
/// vendor publishes no renewal verb: "Sessions established with a personal
/// access token have a lifetime of 2 hours, so you need to log in again once it
/// expires" — <https://protonpass.github.io/pass-cli/commands/personal-access-token/>.
/// Logging in again IS the renewal, and it is unattended and free.
///
/// So expiry every two hours is the design working, and the only question is
/// what runs the loop. Until this struct existed, nothing here did:
/// [`DaemonProtonConfig::session_dir`] already says that a daemon "must be able
/// to put that session back when the vendor drops it", and the daemon shipped
/// with no code that ever did. Every Proton name degraded on a clock nobody
/// chose, with nobody awake to read it.
///
/// # Why it is opt-in
///
/// The loop still ends every generation it replaces with a real,
/// account-level `pass-cli logout` — see [`crate::daemon::login::retire`] —
/// even though a read is never made to wait for the replacement itself (see
/// [`SessionRenewal::login_after_minutes`]). Switching it on for the first
/// time on an existing install therefore still changes what happens to a
/// session directory an operator may be managing by hand, from outside this
/// process — later, and never on a lookup's own time, but a real logout all
/// the same. A default that started rotating and logging out sessions on
/// upgrade would be a surprising thing for a patch release to do to a
/// working install.
///
/// # The shape is Vault Agent's, minus one field
///
/// HashiCorp's Vault Agent solves the same problem with the same three parts —
/// a bootstrap credential on the agent's own disk, a renewal loop, and a sink —
/// and its `auto_auth` block carries `min_backoff`, `max_backoff` and
/// `exit_on_err`. The two backoffs are mirrored here.
///
/// `exit_on_err` is deliberately NOT: Vault Agent brokers one identity, so
/// exiting takes away only what was already broken. This daemon serves several
/// stores, and a Proton login that keeps failing would take Infisical, the file
/// store and the keychain down with it. The loop latches instead — it keeps
/// trying at [`SessionRenewal::max_backoff_seconds`] forever, and the names
/// from every other store keep resolving.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct SessionRenewal {
    /// Off unless asked for.
    #[serde(default)]
    pub auto_login: bool,
    /// How old a session may get before the loop replaces it, in minutes.
    ///
    /// Under the vendor's 120-minute cap by a margin wide enough to absorb a
    /// failed attempt and a backoff, so a session is never renewed at the edge
    /// of the cliff it exists to stay off.
    ///
    /// The replacement establishes a fresh generation, verifies it, and swaps
    /// the current pointer to it — see
    /// [`crate::daemon::login::establish`] — so the generation the daemon was
    /// already serving from keeps answering, unmodified, for the whole
    /// duration of the replacement. A read is never made to wait for it.
    #[serde(default = "default_login_after_minutes")]
    pub login_after_minutes: u64,
    /// How often the loop wakes to check the session's age.
    ///
    /// It also decides how fast an unhealthy session is noticed, so it is well
    /// under [`SessionRenewal::login_after_minutes`] rather than equal to it.
    #[serde(default = "default_probe_interval_seconds")]
    pub probe_interval_seconds: u64,
    /// The first wait after a failed login.
    #[serde(default = "default_min_backoff_seconds")]
    pub min_backoff_seconds: u64,
    /// The longest wait between failed logins. The loop never stops trying.
    #[serde(default = "default_max_backoff_seconds")]
    pub max_backoff_seconds: u64,
}

impl Default for SessionRenewal {
    fn default() -> Self {
        SessionRenewal {
            auto_login: false,
            login_after_minutes: default_login_after_minutes(),
            probe_interval_seconds: default_probe_interval_seconds(),
            min_backoff_seconds: default_min_backoff_seconds(),
            max_backoff_seconds: default_max_backoff_seconds(),
        }
    }
}

/// The vendor's cap on a personal-access-token session, in minutes.
///
/// Not configurable and not discovered: it is Proton's, documented at
/// <https://protonpass.github.io/pass-cli/commands/personal-access-token/>, and
/// it is here so a mistuned `login_after_minutes` can be judged against the
/// number it has to stay under.
const PROTON_SESSION_CAP_MINUTES: u64 = 120;

const fn default_login_after_minutes() -> u64 {
    90
}

const fn default_probe_interval_seconds() -> u64 {
    300
}

const fn default_min_backoff_seconds() -> u64 {
    1
}

const fn default_max_backoff_seconds() -> u64 {
    300
}

impl Default for DaemonProtonConfig {
    fn default() -> Self {
        DaemonProtonConfig {
            enabled: false,
            binary: default_proton_binary(),
            session_dir: None,
            key_provider: KeyProvider::default(),
            timeout_ms: default_timeout_ms(),
            listing_ttl_ms: default_listing_ttl_ms(),
            probe_binary: default_probe_binary(),
            credentials: BTreeMap::new(),
            credentials_file: default_proton_credentials_file(),
            token_expires: None,
            session: SessionRenewal::default(),
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

/// Where the vendor's own machine identity lives, by default.
///
/// A sibling of the secrets file rather than the same file: see
/// [`DaemonInfisicalConfig::credentials_file`] for why sharing one would make
/// the credential servable over the socket under its own name.
fn default_infisical_credentials_file() -> ConfigPath {
    ConfigPath::from(
        PathBuf::from("/usr/local/var/lib")
            .join(crate::NAME)
            .join("infisical.json"),
    )
}

/// Where the daemon's 1Password service account lives, by default.
///
/// Its own file, and a sibling of the Infisical one rather than the same file:
/// each vendor's credential is written by `keylessd credential --store`, and
/// one file per store is what lets a rotation of one leave the other alone.
fn default_onepassword_credentials_file() -> ConfigPath {
    ConfigPath::from(
        PathBuf::from("/usr/local/var/lib")
            .join(crate::NAME)
            .join("onepassword.json"),
    )
}

/// Where the daemon's Proton agent token lives, by default.
///
/// Its own file, a sibling of the other two, for the reason
/// [`default_onepassword_credentials_file`] gives.
fn default_proton_credentials_file() -> ConfigPath {
    ConfigPath::from(
        PathBuf::from("/usr/local/var/lib")
            .join(crate::NAME)
            .join("proton.json"),
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

/// A configured window in seconds, clamped to [`MAX_CACHE_SECONDS`].
const fn bounded_cache_seconds(seconds: u64) -> u64 {
    if seconds > MAX_CACHE_SECONDS {
        MAX_CACHE_SECONDS
    } else {
        seconds
    }
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

fn default_onepassword_binary() -> ConfigPath {
    crate::config::default_onepassword_binary()
}

fn default_proton_binary() -> ConfigPath {
    crate::config::default_proton_binary()
}

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
        Duration::from_secs(bounded_cache_seconds(self.cache_ttl_seconds))
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
        Duration::from_secs(bounded_cache_seconds(self.cache_stale_seconds))
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

    /// The vendor's own login, read out of the daemon's own file.
    ///
    /// Deliberately a [`FileStore`] of its own rather than the registry the
    /// daemon serves names from: the credential must not become a name a client
    /// can ask for, and it needs the mode check no other backend has.
    ///
    /// `None` when nothing is declared, which leaves the vendor authenticating
    /// from whatever the daemon's own environment carries — nearly nothing,
    /// under launchd.
    fn vendor_credentials(&self) -> Option<VendorCredentials> {
        let settings = &self.stores.infisical;
        if settings.credentials.is_empty() {
            return None;
        }
        Some(VendorCredentials::new(
            Box::new(FileStore::new(settings.credentials_file.to_path_buf())),
            settings.credentials.clone(),
        ))
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

    /// Where each name lives inside the daemon's one 1Password vault.
    ///
    /// The same projection a session builds, from the same fields of the same
    /// [`SecretRoute`] type. There is no daemon-side default vault for the
    /// reason there is none on a session — see
    /// [`crate::config::OnePasswordConfig::vault`] — and no per-name `vault`
    /// can widen it, because `read_route` refuses one that disagrees.
    #[must_use]
    pub fn onepassword_routing(&self) -> OnePasswordRouting {
        OnePasswordRouting::new(
            &self.secrets,
            self.stores.onepassword.vault.clone(),
            self.stores.onepassword.field.clone(),
        )
    }

    /// Where each name lives inside Proton Pass.
    ///
    /// The same projection a session builds, from the same fields of the same
    /// [`SecretRoute`] type, through the same constructor — see
    /// [`crate::store::proton::Routing`] for why one walk rather than two.
    ///
    /// # There is no coordinate here a daemon has to supply
    ///
    /// This is the reason the Proton adapter needed no new gate to be hosted
    /// behind the socket, and the reason it differs from the Infisical one next
    /// door. An Infisical name is `<key>` at `<path>` of `<environment>`, and
    /// two of those three have defaults, so an undeclared name is still a
    /// well-formed query the vendor will answer. A Proton name is a vault, an
    /// item and a field, **none** of which is inferable: guessing any of them
    /// would send a read, and a permanent off-machine audit entry, to an item
    /// nobody asked for. So `Address::from_route` yields nothing for a name
    /// that declares nothing, `resolve` turns that into an error, and no
    /// process is created.
    ///
    /// `tests/daemon_proton.rs` asserts that as the ABSENCE of a vendor
    /// invocation rather than as a returned status.
    #[must_use]
    pub fn proton_routing(&self) -> ProtonRouting {
        ProtonRouting::from_secrets(&self.secrets)
    }

    /// The daemon's Proton login, read out of its own file.
    ///
    /// The same arrangement as [`DaemonConfig::vendor_credentials`], for the
    /// same reasons — and one more that is specific to this vendor: the token
    /// is what lets a dropped session put itself back, so a daemon without one
    /// works right up until anything disturbs its session directory and then
    /// stops, with nobody there to log it back in.
    fn agent_token(&self) -> Option<AgentToken> {
        let settings = &self.stores.proton;
        // `credential_entries`, so a store-side spawn carries the local key on
        // the same terms the login-side ones do. Under `env` that map is never
        // empty, which is the point: a config declaring only a token still has
        // a key to hand the vendor, and it is the one this daemon generated.
        let entries = settings.credential_entries();
        if entries.is_empty() {
            return None;
        }
        Some(AgentToken::new(
            Box::new(FileStore::new(settings.credentials_file.to_path_buf())),
            entries,
        ))
    }

    /// The daemon's 1Password login, read out of its own file.
    ///
    /// The same arrangement as [`DaemonConfig::vendor_credentials`], for the
    /// same reasons.
    fn service_account(&self) -> Option<ServiceAccount> {
        let settings = &self.stores.onepassword;
        if settings.credentials.is_empty() {
            return None;
        }
        Some(ServiceAccount::new(
            Box::new(FileStore::new(settings.credentials_file.to_path_buf())),
            settings.credentials.clone(),
        ))
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

    /// The generation layout this config names, or `None` when there is
    /// nothing to build one over.
    ///
    /// `Some` exactly when Proton is enabled and `session_dir` is set — the
    /// same precondition [`crate::store::proton::ProtonStore::session_dir`]
    /// and [`super::login::coordinates`] already enforce, so a caller that
    /// gets `Some` here knows every other Proton-reading call in this crate
    /// will too. Fresh on every call rather than cached: this method builds
    /// the type, and *which instance* is shared across the daemon is decided
    /// once, by [`Daemon::bind`](super::Daemon::bind) — every other caller
    /// that wants the SAME running layout takes it from there rather than
    /// calling this again.
    #[must_use]
    pub fn generations(&self) -> Option<Arc<Generations>> {
        if !self.stores.proton.enabled {
            return None;
        }
        let root = self.stores.proton.session_dir.as_deref()?;
        // The same guard `ProtonStore::session_dir` applies on the session
        // side, restated here because a `Some` from this function is what
        // makes `ProtonStore::enter`'s daemon-side arm skip that call
        // entirely. Returning `None` for a relative root — rather than
        // building a `Generations` over it — is what sends the daemon read
        // path back through `session_dir()`'s own check and its
        // named-config-line message, instead of degrading later as
        // `CurrentFault::Absent`, a sentence that points an operator at "no
        // session established" when the real fault is one config line.
        if !root.is_absolute() {
            return None;
        }
        Some(Arc::new(Generations::at(root.to_path_buf())))
    }

    /// The Proton adapter this daemon reads through.
    ///
    /// Factored out because the daemon builds TWO of them over one identity —
    /// the one that resolves, and the one the catalogue rebuilder enumerates
    /// through — and two constructions of the same fifteen settings would be
    /// free to disagree about which vault, which timeout, which key provider.
    /// The disagreement would be invisible: the rebuilder would simply mint
    /// names for a vault the resolver cannot read.
    ///
    /// `catalogue` is `None` for the discovering twin: enumeration takes no
    /// route, so an index that fed itself would only be a way for a stale
    /// snapshot to keep itself alive.
    fn proton_store(
        &self,
        generations: Option<&Arc<Generations>>,
        catalogue: Option<Arc<Catalogue>>,
    ) -> ProtonStore {
        let settings = &self.stores.proton;
        ProtonStore::new(
            settings.binary.to_path_buf(),
            settings.probe_binary.to_path_buf(),
            self.proton_routing().with_catalogue(catalogue),
            // Not `Reason::for_run(argv)`. The reason is written into
            // Proton's own remote audit trail, permanently, and a
            // daemon's `argv` arrives from a client — `crate::audit`
            // records it as a CLAIM, never a fact. A registry is built
            // once at startup anyway, so there is no per-request reason
            // to be had here even if one were wanted.
            ProtonReason::for_verb(crate::DAEMON_NAME),
        )
        .in_session_dir(
            settings
                .session_dir
                .as_deref()
                .map(|path| path.to_path_buf()),
        )
        // Always named here, never left to the vendor's default. See
        // `KeyProvider`: the default is a keyring, a daemon uid has
        // none, and `pass-cli` answers that by reinitialising the
        // session store it was asked to read.
        .with_key_provider(Some(settings.key_provider))
        // Whoever runs the vendor owns what it writes, and it writes on
        // invocations that only read. Read off the audit log, which is
        // the same source the login verbs use.
        .with_run_as(
            super::credential::daemon_owner(&self.audit).map(|owner| (owner.uid, owner.gid)),
        )
        .with_timeout(settings.timeout_ms)
        .with_listing_ttl(settings.listing_ttl_ms)
        .with_generations(generations.cloned())
        .with_agent_token(self.agent_token())
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
    ///
    /// `shared` is the [`Generations`] the renewal loop creates and retires
    /// generations through, when one is already built — the running daemon's
    /// own case. `None` builds a fresh, PRIVATE `Generations` from this same
    /// config instead of leaving the registry with none at all: `keylessd
    /// check` resolves in its own process and renews nothing, but it still has
    /// to read `<root>/current` to report on the store honestly.
    #[must_use]
    pub fn registry(&self, shared: Option<&Arc<Generations>>) -> Registry {
        self.backends(shared, None).registry
    }

    /// The registry, and the sources a catalogue rebuild enumerates through.
    ///
    /// Both at once because the discovering twin has to be built over the
    /// resolving store's own listing cache, and the sharing pays in ONE
    /// direction: the twin refuses a cached listing — see
    /// [`ProtonStore::always_relisting`], which exists because a rebuild queued
    /// by a miss cannot answer that miss out of a listing fetched before the
    /// item existed — so it never reuses anything. What it does is WRITE: the
    /// fresh listing it fetches lands in the shared slot, and the next cold
    /// resolve is served from it instead of spawning a `pass-cli item list` of
    /// its own. Built over separate caches, every rebuild would be a listing
    /// nobody else could use.
    ///
    /// `catalogue` decides only what the RESOLVING adapters read their
    /// undeclared addresses out of. The sources are built either way, so a
    /// caller that wants to enumerate — `keylessd check` — does not have to
    /// construct a catalogue it will not read. The cost is one `ProtonStore`
    /// built and dropped by [`DaemonConfig::registry`], which is a struct and
    /// no vendor call.
    #[must_use]
    pub fn backends(
        &self,
        shared: Option<&Arc<Generations>>,
        catalogue: Option<&Arc<Catalogue>>,
    ) -> Backends {
        let generations = shared.cloned().or_else(|| self.generations());
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
                )
                .at_domain(settings.domain.clone())
                .with_vendor_credentials(self.vendor_credentials()),
            ));
        }
        if self.stores.onepassword.enabled {
            let settings = &self.stores.onepassword;
            stores.push(Box::new(
                OnePasswordStore::new(
                    settings.binary.to_path_buf(),
                    settings.probe_binary.to_path_buf(),
                    self.onepassword_routing(),
                )
                .with_timeout(settings.timeout_ms)
                .with_listing_ttl(settings.listing_ttl_ms)
                .for_account(settings.account.clone())
                .in_config_dir(
                    settings
                        .config_dir
                        .as_deref()
                        .map(|path| path.to_path_buf()),
                )
                .with_vendor_credentials(self.service_account()),
            ));
        }
        let mut sources: Vec<Source> = Vec::new();
        if self.stores.proton.enabled {
            let resolving = self.proton_store(generations.as_ref(), catalogue.cloned());
            sources.push(Source {
                discover: Box::new(
                    self.proton_store(generations.as_ref(), None)
                        .sharing_listings_with(&resolving)
                        .always_relisting(),
                ),
                mint: Box::new(ProtonMint),
            });
            stores.push(Box::new(resolving));
        }
        Backends {
            registry: Registry::new(stores)
                .with_routes(self.routes())
                .with_policy(self.stores.policy)
                .with_default_store(self.stores.default_store.clone()),
            sources,
        }
    }

    /// Problems worth telling an operator about that are not fatal.
    ///
    /// Returned rather than printed so `keylessd` and its tests see the same
    /// list.
    /// What is wrong with `stores.proton.session`, in sentences an operator can act on.
    ///
    /// Warnings rather than refusals: every one of these leaves a daemon that
    /// serves every other store correctly, and a Proton renewal that is merely
    /// mistuned is worth saying out loud rather than worth refusing to start
    /// four other stores over. The one arrangement that DOES refuse — asking
    /// for the loop with a config that cannot support a login — is refused by
    /// [`super::session::spawn`], because there the operator has said the
    /// session matters and starting anyway reproduces the silent outage.
    fn session_warnings(&self) -> Vec<String> {
        let settings = self.stores.proton.session;
        if !settings.auto_login {
            return Vec::new();
        }
        let mut warnings = Vec::new();
        if !self.stores.proton.enabled {
            warnings.push(
                "`stores.proton.session.auto_login` is true while `stores.proton.enabled` is                  false, so no session is kept alive and no Proton name resolves"
                    .to_owned(),
            );
        }
        if settings.login_after_minutes >= PROTON_SESSION_CAP_MINUTES {
            warnings.push(format!(
                "`stores.proton.session.login_after_minutes` is {}, at or past the vendor's                  {PROTON_SESSION_CAP_MINUTES}-minute cap on a personal-access-token session, so                  the session expires before the loop replaces it and every Proton name degrades                  in between",
                settings.login_after_minutes
            ));
        }
        if settings.probe_interval_seconds >= settings.login_after_minutes.saturating_mul(60) {
            warnings.push(format!(
                "`stores.proton.session.probe_interval_seconds` is {}, which is not shorter than                  the {}-minute renewal age, so the loop can only notice a session is due after                  it already expired",
                settings.probe_interval_seconds, settings.login_after_minutes
            ));
        }
        if settings.max_backoff_seconds < settings.min_backoff_seconds {
            warnings.push(format!(
                "`stores.proton.session.max_backoff_seconds` ({}) is below `min_backoff_seconds`                  ({}), so the backoff never grows and a failing login retries at the minimum                  forever",
                settings.max_backoff_seconds, settings.min_backoff_seconds
            ));
        }
        warnings
    }

    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        warnings.extend(self.session_warnings());
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
            && !self.stores.onepassword.enabled
            && !self.stores.proton.enabled
        {
            warnings.push("no store is enabled, so no name can resolve".to_owned());
        }
        if self.stores.proton.enabled && self.stores.proton.session_dir.is_none() {
            // The operator-facing form of the rule in `ProtonStore::session_dir`,
            // said while the config is being written rather than as every
            // Proton name degrading with a sentence about a key nobody was
            // told belongs here. There is no default to fall back to and there
            // must not be: the vendor's own fallback is derived from the
            // caller's home, and a daemon's uid either has none or has one
            // nobody meant to be a credential store.
            warnings.push(
                "the Proton store is enabled and `stores.proton.session_dir` names no \
                 directory, so no name can resolve against it: a daemon has no ambient \
                 session to inherit and inheriting one would read an identity nobody chose"
                    .to_owned(),
            );
        }
        if self.stores.proton.enabled && self.stores.proton.credentials.is_empty() {
            warnings.push(format!(
                "the Proton store is enabled and names no credential, so the daemon's \
                 `pass-cli` cannot re-establish its session if the vendor ever drops it, \
                 and every Proton name degrades from that moment with nobody watching. \
                 Name `{PROTON_TOKEN}` under `stores.proton.credentials` and write it with \
                 `{} credential --store proton`",
                crate::DAEMON_NAME
            ));
        }
        let refused = AgentToken::refused(&self.stores.proton.credentials);
        if !refused.is_empty() {
            warnings.push(format!(
                "these Proton credential variables are refused, and every Proton lookup \
                 will degrade while they are named: {}. Only `{PROTON_TOKEN}` and \
                 `{PROTON_ENCRYPTION_KEY}` may be written this way — every other \
                 `PROTON_PASS_*` variable is one this adapter sets itself, and one named \
                 here would overrule which identity answers or where its key is looked for",
                refused.join(", ")
            ));
        }
        if !self.stores.proton.credentials.is_empty()
            && self.stores.file.enabled
            && self.stores.proton.credentials_file.to_path_buf()
                == self.stores.file.path.to_path_buf()
        {
            warnings.push(format!(
                "the Proton credential file is the same file the `file` store serves, so \
                 {} {} a name any attested client can ask for; put the credential in a file \
                 of its own and name it in `stores.proton.credentials_file`",
                self.stores
                    .proton
                    .credentials
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if self.stores.proton.credentials.len() == 1 {
                    "is"
                } else {
                    "are"
                }
            ));
        }
        // `""` is checked beside absence rather than after it: an empty vault
        // is the same config as no vault — `OnePasswordRouting` normalises the
        // two together — and it is the one that looks answered in the file.
        if self.stores.onepassword.enabled
            && self
                .stores
                .onepassword
                .vault
                .as_deref()
                .is_none_or(str::is_empty)
        {
            // The operator-facing form of the rule in `onepassword_routing`:
            // said at startup, rather than as every 1Password name degrading
            // with a sentence about a config key nobody was told belongs here.
            warnings.push(
                "the 1Password store is enabled and `stores.onepassword.vault` names no vault, \
                 so no name can resolve against it: the daemon reads exactly one vault, an \
                 empty string is not one, and there is deliberately no default"
                    .to_owned(),
            );
        }
        // The one property of this backend an operator cannot read off its
        // config, and the one that changes meaning when it moves behind the
        // socket. A store-wide `field` supplies the ONLY coordinate an
        // undeclared name is missing — the vault is the store's and the title
        // is the name itself — so with it set, every item in the vault is
        // reachable by title by any attested client, whether or not `secrets`
        // mentions it. That is this backend's design and it is exactly why the
        // vault is pinned; what it is not is discoverable, and nothing else in
        // this tool says it.
        //
        // Not a refusal, because it is the merged and tested behaviour of an
        // adapter whose whole scoping story is the vault. It is a warning at
        // the one moment the operator is reading: the vault they just named is
        // now the allowlist, and the switch that narrows it is one line away.
        if let Some(vault) = self
            .stores
            .onepassword
            .vault
            .as_deref()
            .filter(|vault| !vault.is_empty())
            && self.stores.onepassword.enabled
            && self
                .stores
                .onepassword
                .field
                .as_deref()
                .is_some_and(|field| !field.is_empty())
        {
            warnings.push(format!(
                "the 1Password store is enabled with `stores.onepassword.field` set, which \
                 makes vault `{vault}` itself the allowlist: a name in NO `secrets` entry \
                 resolves as the item of that title in that vault, so an attested client can \
                 ask for anything the vault holds by guessing its title. Keep only what every \
                 client may read in it. To serve declared names and nothing else, drop \
                 `stores.onepassword.field` and put \"field\" on each name under `secrets` — an \
                 undeclared name is then refused before anything is spawned"
            ));
        }
        if self.stores.onepassword.enabled && self.stores.onepassword.credentials.is_empty() {
            // Not a misconfiguration — an operator may have signed the daemon's
            // uid in some other way — but it is the arrangement nobody
            // intends, and a lookup that fails for it reads as a network fault.
            warnings.push(format!(
                "the 1Password store is enabled and names no credential, so the daemon's `op` \
                 has only whatever login its own uid carries, which under launchd is none. \
                 Name `{SERVICE_ACCOUNT_TOKEN}` under `stores.onepassword.credentials` and \
                 write it with `{} credential --store onepassword`",
                crate::DAEMON_NAME
            ));
        }
        let refused = ServiceAccount::refused(&self.stores.onepassword.credentials);
        if !refused.is_empty() {
            warnings.push(format!(
                "these 1Password credential variables are refused because they are not \
                 `OP_*`, and every 1Password lookup will degrade while they are named: {}",
                refused.join(", ")
            ));
        }
        if !self.stores.onepassword.credentials.is_empty()
            && self.stores.file.enabled
            && self.stores.onepassword.credentials_file.to_path_buf()
                == self.stores.file.path.to_path_buf()
        {
            warnings.push(format!(
                "the 1Password credential file is the same file the `file` store serves, so \
                 {} {} a name any attested client can ask for; put the credential in a file \
                 of its own and name it in `stores.onepassword.credentials_file`",
                self.stores
                    .onepassword
                    .credentials
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if self.stores.onepassword.credentials.len() == 1 {
                    "is"
                } else {
                    "are"
                }
            ));
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

        let refused = VendorCredentials::refused(&self.stores.infisical.credentials);
        if !refused.is_empty() {
            warnings.push(format!(
                "these Infisical credential variables are refused because they are not \
                 `INFISICAL_*`, and every Infisical lookup will degrade while they are \
                 named: {}",
                refused.join(", ")
            ));
        }

        if let Some(missing) =
            VendorCredentials::half_an_identity(&self.stores.infisical.credentials)
        {
            warnings.push(format!(
                "a universal-auth machine identity is half declared: `{missing}` is named by \
                 nothing. `infisical run` authenticates with neither half on its own, so \
                 every Infisical lookup will degrade; name both, or name \
                 `{ACCESS_TOKEN}` instead"
            ));
        }

        // Not a misconfiguration — a token works — but it is the one setting
        // whose failure arrives on a schedule nobody chose and with nobody
        // awake to read it. Said at startup, which is the last moment an
        // operator is standing here.
        if self.stores.infisical.credentials.contains_key(ACCESS_TOKEN)
            && !VendorCredentials::is_an_identity(&self.stores.infisical.credentials)
        {
            warnings.push(format!(
                "the Infisical login is an access token, which expires. When it does, every \
                 Infisical name degrades at whatever hour that happens and nothing here is \
                 watching. Name `{IDENTITY_CLIENT_ID}` and `{IDENTITY_CLIENT_SECRET}` \
                 instead and the daemon mints its own token per lookup"
            ));
        }

        // The one arrangement that quietly undoes the point of moving the
        // credential behind the boundary. Everything in the file store is a
        // name an attested client can ask for, so a machine identity kept there
        // is handed out to any session that guesses its label.
        if !self.stores.infisical.credentials.is_empty()
            && self.stores.file.enabled
            && self.stores.infisical.credentials_file.to_path_buf()
                == self.stores.file.path.to_path_buf()
        {
            warnings.push(format!(
                "the Infisical credential file is the same file the `file` store serves, so \
                 {} {} a name any attested client can ask for; put the credential in a file \
                 of its own and name it in `stores.infisical.credentials_file`",
                self.stores
                    .infisical
                    .credentials
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if self.stores.infisical.credentials.len() == 1 {
                    "is"
                } else {
                    "are"
                }
            ));
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
        let registry = self.registry(None);
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

    /// A config that says nothing about the loop gets one that is off, so an
    /// upgrade cannot start replacing a session an operator manages by hand.
    #[test]
    fn the_session_loop_is_off_and_tuned_under_the_cap_by_default() {
        let session = parse("{}").stores.proton.session;
        assert!(!session.auto_login);
        assert_eq!(session.login_after_minutes, 90);
        assert!(session.login_after_minutes < super::PROTON_SESSION_CAP_MINUTES);
        assert_eq!(session.probe_interval_seconds, 300);
        assert_eq!(session.min_backoff_seconds, 1);
        assert_eq!(session.max_backoff_seconds, 300);
    }

    #[test]
    fn the_session_loop_reads_every_field_an_operator_writes() {
        let session = parse(
            r#"{"stores":{"proton":{"session":{"auto_login":true,"login_after_minutes":60,
               "probe_interval_seconds":60,"min_backoff_seconds":2,"max_backoff_seconds":60}}}}"#,
        )
        .stores
        .proton
        .session;
        assert!(session.auto_login);
        assert_eq!(session.login_after_minutes, 60);
        assert_eq!(session.probe_interval_seconds, 60);
        assert_eq!(session.min_backoff_seconds, 2);
        assert_eq!(session.max_backoff_seconds, 60);
    }

    #[test]
    fn the_daemon_config_builds_generations_only_where_proton_names_a_root() {
        assert!(
            parse("{}").generations().is_none(),
            "a config with no Proton store built a generation layout"
        );
        assert!(
            parse(r#"{"stores":{"proton":{"enabled":true}}}"#)
                .generations()
                .is_none(),
            "an enabled store with no session_dir built a generation layout"
        );
        assert!(
            parse(r#"{"stores":{"proton":{"session_dir":"/tmp/kl-gen"}}}"#)
                .generations()
                .is_none(),
            "a session_dir with the store not enabled built a generation layout"
        );

        let generations =
            parse(r#"{"stores":{"proton":{"enabled":true,"session_dir":"/tmp/kl-gen-root"}}}"#)
                .generations()
                .expect("enabled and session_dir together must build one");
        assert_eq!(generations.root(), Path::new("/tmp/kl-gen-root"));
    }

    /// Silence while the loop is off: none of these numbers does anything, so
    /// warning about them would train an operator to ignore the list.
    #[test]
    fn a_mistuned_loop_that_is_off_warns_about_nothing() {
        let config = parse(
            r#"{"stores":{"proton":{"session":{"login_after_minutes":600,
               "probe_interval_seconds":99999}}}}"#,
        );
        assert!(config.session_warnings().is_empty());
    }

    #[test]
    fn renewing_at_or_past_the_vendor_cap_is_warned_about() {
        let config = parse(
            r#"{"stores":{"proton":{"enabled":true,"session":{"auto_login":true,
               "login_after_minutes":120}}}}"#,
        );
        let said = config.session_warnings().join("\n");
        assert!(said.contains("login_after_minutes"), "{said}");
        assert!(said.contains("120-minute cap"), "{said}");
    }

    #[test]
    fn a_probe_slower_than_the_renewal_age_is_warned_about() {
        let config = parse(
            r#"{"stores":{"proton":{"enabled":true,"session":{"auto_login":true,
               "login_after_minutes":90,"probe_interval_seconds":5400}}}}"#,
        );
        let said = config.session_warnings().join("\n");
        assert!(said.contains("probe_interval_seconds"), "{said}");
    }

    #[test]
    fn a_backoff_ceiling_below_its_floor_is_warned_about() {
        let config = parse(
            r#"{"stores":{"proton":{"enabled":true,"session":{"auto_login":true,
               "min_backoff_seconds":60,"max_backoff_seconds":10}}}}"#,
        );
        let said = config.session_warnings().join("\n");
        assert!(said.contains("max_backoff_seconds"), "{said}");
    }

    /// The arrangement that keeps nothing alive while reading as configured.
    #[test]
    fn asking_for_the_loop_on_a_disabled_store_is_warned_about() {
        let config = parse(r#"{"stores":{"proton":{"session":{"auto_login":true}}}}"#);
        let said = config.session_warnings().join("\n");
        assert!(said.contains("stores.proton.enabled"), "{said}");
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
        assert_eq!(config.registry(None).stores().len(), 1);
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
        let registry = config.registry(None);
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
        let registry = config.registry(None);
        let ids: Vec<&str> = registry.stores().iter().map(|store| store.id()).collect();
        assert_eq!(ids, ["infisical"]);

        // The negative control: with the branch removed the registry is empty,
        // and an empty registry answers `not found in any store` — which reads
        // as a working lookup that came back empty rather than as an absent
        // adapter. Asking for the store id is what tells them apart.
        assert_eq!(parse("{}").registry(None).stores().len(), 0);
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
        let registry = config.registry(None);

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
    fn keeping_the_vendor_login_in_the_served_secrets_file_is_warned_about() {
        // The arrangement that quietly undoes the point of moving the
        // credential behind the boundary: everything in the file store is a
        // name an attested client can ask for, so a machine identity kept
        // there is handed to any session that guesses its label.
        let config = parse(
            r#"{"stores":{"file":{"enabled":true,"path":"/tmp/keyless-test/secrets.json"},
                          "infisical":{"enabled":true,
                                       "credentials_file":"/tmp/keyless-test/secrets.json",
                                       "credentials":{"INFISICAL_TOKEN":"MACHINE_IDENTITY"}}},
                "secrets":{"DATABASE_URL":{"env":"staging","store":"infisical"}}}"#,
        );
        let said = config.warnings().join(" ");
        assert!(said.contains("same file the `file` store serves"), "{said}");
        assert!(said.contains("MACHINE_IDENTITY"), "{said}");

        // The negative control: a file of its own — the default arrangement —
        // says nothing. Without it the warning could be firing on every config
        // that names a credential at all.
        //
        // A machine identity rather than the access token above, because a
        // token draws a warning of its own about expiring and this control has
        // to be able to assert SILENCE.
        let separate = parse(
            r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"file":{"enabled":true,"path":"/tmp/keyless-test/secrets.json"},
                          "infisical":{"enabled":true,"default":"file",
                                       "credentials_file":"/tmp/keyless-test/infisical.json",
                                       "credentials":{
                            "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID":"MACHINE_IDENTITY_CLIENT_ID",
                            "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET":"MACHINE_IDENTITY_SECRET"}},
                          "default":"file"},
                "secrets":{"DATABASE_URL":{"env":"staging","store":"infisical"}}}"#,
        )
        .warnings();
        assert!(separate.is_empty(), "{separate:?}");
    }

    #[test]
    fn a_credential_variable_outside_the_vendors_own_prefix_is_named_at_startup() {
        let said = parse(
            r#"{"stores":{"infisical":{"enabled":true,
                                       "credentials":{"PATH":"X","INFISICAL_TOKEN":"Y"}}},
                "secrets":{"DATABASE_URL":{"env":"staging"}}}"#,
        )
        .warnings()
        .join(" ");
        assert!(said.contains("not `INFISICAL_*`"), "{said}");
        assert!(said.contains("PATH"), "{said}");
        // The negative control, in the same sentence: the variable that IS the
        // vendor's own must not be listed as refused, or the warning is just
        // "you named credentials" and says nothing.
        assert!(
            !said.contains("INFISICAL_TOKEN"),
            "an accepted variable was reported as refused: {said}"
        );
    }

    // -----------------------------------------------------------------------
    // The 1Password vault, and the login the daemon is handed.
    // -----------------------------------------------------------------------

    /// A 1Password daemon config with everything a lookup needs, so the
    /// warnings can be asserted SILENT — the control every warning test here
    /// needs, or a warning could fire on every config regardless.
    ///
    /// The name carries its own `field` and the store sets no store-wide one,
    /// which is the config that serves DECLARED names and nothing else. A
    /// store-wide `field` is warned about — see the test below — because it is
    /// the switch that turns the vault into the allowlist.
    const ONEPASSWORD_WELL_FORMED: &str = r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"onepassword":{"enabled":true,"vault":"company",
                                         "credentials_file":"/tmp/keyless-test/onepassword.json",
                                         "credentials":{"OP_SERVICE_ACCOUNT_TOKEN":"SERVICE_ACCOUNT"}}},
                "secrets":{"DECOY":{"store":"onepassword","item":"Router","field":"password"}}}"#;

    #[test]
    fn a_well_formed_onepassword_config_registers_the_store_and_warns_about_nothing() {
        let config = parse(ONEPASSWORD_WELL_FORMED);
        let ids: Vec<String> = config
            .registry(None)
            .stores()
            .iter()
            .map(|store| store.id().to_owned())
            .collect();
        assert_eq!(ids, ["onepassword"]);
        assert!(config.warnings().is_empty(), "{:?}", config.warnings());
    }

    #[test]
    fn a_names_onepassword_coordinates_are_read_from_the_daemons_own_config() {
        let config = parse(
            r#"{"stores":{"onepassword":{"vault":"company","field":"password"}},
                "secrets":{"A":{"store":"onepassword","item":"Router","section":"other",
                                "field":"api key"}}}"#,
        );
        let routing = config.onepassword_routing();
        assert_eq!(routing.vault().expect("pinned"), "company");
        let address = routing.address("A").expect("declared");
        assert_eq!(address.item, "Router");
        assert_eq!(address.section.as_deref(), Some("other"));
        assert_eq!(address.field, "api key");
        // An undeclared name is its own title at the store-wide field, in the
        // one vault — there is nowhere else it could point.
        assert_eq!(
            routing
                .address("A_NAME_NOBODY_EVER_DECLARED")
                .expect("addressable")
                .item,
            "A_NAME_NOBODY_EVER_DECLARED"
        );
    }

    #[test]
    fn no_daemon_config_key_supplies_a_default_onepassword_vault() {
        // The same shape of assertion as the Infisical environment above: every
        // spelling somebody reaching for a default would try is dropped by
        // serde, and the routing built from the parsed config names no vault.
        let config = parse(
            r#"{"stores":{"onepassword":{"enabled":true,"default_vault":"personal"},
                          "vault":"personal"},
                "vault":"personal","onepassword_vault":"personal"}"#,
        );
        let rendered = serde_json::to_string(&config).expect("serialize");
        assert!(
            !rendered.contains("personal"),
            "a vault survived the parse: {rendered}"
        );
        assert!(config.onepassword_routing().vault().is_err());
        let said = config.warnings().join(" ");
        assert!(said.contains("stores.onepassword.vault"), "{said}");
    }

    #[test]
    fn a_store_wide_field_is_told_that_it_makes_the_vault_the_allowlist() {
        // Behind the socket this is the property nobody can read off the
        // config. A store-wide `field` supplies the ONLY coordinate an
        // undeclared name lacks — the vault is the store's and the title is the
        // name itself — so every item in the pinned vault becomes reachable by
        // title to any attested client, `secrets` entry or not.
        //
        // The daemon has no declared-name population to check against (see
        // `crate::daemon::resolver`), and this adapter has no refusal of its
        // own, so nothing downstream would ever say it. It is said here, once,
        // where the operator is looking at the file they just wrote.
        let config = parse(
            r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"onepassword":{"enabled":true,"vault":"company","field":"password",
                                         "credentials_file":"/tmp/keyless-test/onepassword.json",
                                         "credentials":{"OP_SERVICE_ACCOUNT_TOKEN":"SA"}}},
                "secrets":{"DECOY":{"store":"onepassword","item":"Router"}}}"#,
        );
        let said = config.warnings().join(" ");
        assert!(said.contains("stores.onepassword.field"), "{said}");
        assert!(said.contains("allowlist"), "{said}");
        assert!(
            said.contains("company"),
            "the warning must name the vault: {said}"
        );
        // And the way out, or the warning is a fact with no action attached.
        assert!(said.contains("\"field\" on each name"), "{said}");

        // The behaviour the warning describes, asserted rather than assumed —
        // a warning about a property the code does not have is worse than none.
        let routing = config.onepassword_routing();
        let address = routing
            .address("A_NAME_NOBODY_EVER_DECLARED")
            .expect("a store-wide field makes an undeclared name addressable");
        assert_eq!(address.item, "A_NAME_NOBODY_EVER_DECLARED");

        // The control, which is also the remedy: with each name carrying its
        // own field and the store carrying none, the warning is silent AND an
        // undeclared name is refused before anything is spawned.
        let narrowed = parse(ONEPASSWORD_WELL_FORMED);
        assert!(narrowed.warnings().is_empty(), "{:?}", narrowed.warnings());
        assert!(
            narrowed
                .onepassword_routing()
                .address("A_NAME_NOBODY_EVER_DECLARED")
                .is_err(),
            "with no store-wide field an undeclared name must have nowhere to point"
        );
    }

    #[test]
    fn an_empty_onepassword_vault_is_warned_about_exactly_as_a_missing_one_is() {
        // `""` parses, so it is the one spelling that reads as answered in the
        // file. Behind the daemon it must fail the same way `vault` absent does
        // — at startup, in the operator's own words — rather than reaching the
        // vendor as `--vault=` and a reference with a hole where the vault is.
        let config =
            parse(r#"{"stores":{"onepassword":{"enabled":true,"vault":"","field":"password"}}}"#);
        let said = config.warnings().join(" ");
        assert!(said.contains("stores.onepassword.vault"), "{said}");
        assert!(said.contains("names no vault"), "{said}");
        assert!(config.onepassword_routing().vault().is_err());

        // The control: a real vault silences exactly this warning, so the
        // assertion above is about the empty string and not about every config.
        let named =
            parse(r#"{"stores":{"onepassword":{"enabled":true,"vault":"company"}}}"#).warnings();
        assert!(
            !named
                .iter()
                .any(|warning| warning.contains("names no vault")),
            "{named:?}"
        );
    }

    #[test]
    fn a_name_declaring_another_vault_is_refused_on_the_daemon_too() {
        // The whole point of hosting this adapter behind the boundary is that
        // a name cannot widen the vault. The daemon's config is the operator's,
        // but a wrong entry in it must still fail closed.
        let config = parse(
            r#"{"stores":{"onepassword":{"vault":"company","field":"password"}},
                "secrets":{"A":{"store":"onepassword","vault":"personal","item":"Router"}}}"#,
        );
        let said = config
            .onepassword_routing()
            .address("A")
            .expect_err("another vault is not this store's");
        assert!(said.contains("pinned to `company`"), "{said}");
    }

    #[test]
    fn a_onepassword_store_with_no_credential_is_warned_about() {
        let said = parse(r#"{"stores":{"onepassword":{"enabled":true,"vault":"company"}}}"#)
            .warnings()
            .join(" ");
        assert!(said.contains("names no credential"), "{said}");
        assert!(said.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{said}");
        assert!(said.contains("credential --store onepassword"), "{said}");
    }

    #[test]
    fn a_onepassword_credential_variable_outside_the_vendors_prefix_is_named_at_startup() {
        let said = parse(
            r#"{"stores":{"onepassword":{"enabled":true,"vault":"company",
                          "credentials":{"HOME":"X","OP_SERVICE_ACCOUNT_TOKEN":"Y"}}}}"#,
        )
        .warnings()
        .join(" ");
        assert!(said.contains("not `OP_*`"), "{said}");
        assert!(said.contains("HOME"), "{said}");
        assert!(
            !said.contains("refused because they are not `OP_*`, and every 1Password lookup will degrade while they are named: HOME, OP_"),
            "an accepted variable was reported as refused: {said}"
        );
    }

    #[test]
    fn keeping_the_service_account_in_the_served_secrets_file_is_warned_about() {
        let said = parse(
            r#"{"stores":{"file":{"enabled":true,"path":"/tmp/keyless-test/secrets.json"},
                          "onepassword":{"enabled":true,"vault":"company",
                                         "credentials_file":"/tmp/keyless-test/secrets.json",
                                         "credentials":{"OP_SERVICE_ACCOUNT_TOKEN":"SERVICE_ACCOUNT"}},
                          "default":"file"}}"#,
        )
        .warnings()
        .join(" ");
        assert!(said.contains("same file the `file` store serves"), "{said}");
        assert!(said.contains("SERVICE_ACCOUNT"), "{said}");
        assert!(
            said.contains("stores.onepassword.credentials_file"),
            "{said}"
        );
    }

    #[test]
    fn the_two_vendor_credential_files_default_to_different_paths() {
        // One file per store is what lets a rotation of one leave the other
        // alone, and what keeps `keylessd credential --store` meaningful.
        let config = parse("{}");
        assert_ne!(
            config.stores.onepassword.credentials_file.to_path_buf(),
            config.stores.infisical.credentials_file.to_path_buf()
        );
        assert_ne!(
            config.stores.onepassword.credentials_file.to_path_buf(),
            config.stores.file.path.to_path_buf()
        );
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

    #[test]
    fn the_key_provider_that_forces_a_logout_cannot_be_written_into_a_config() {
        // `keyring` is the vendor's default and the one value a daemon must
        // never use: its uid has no login keychain, `pass-cli` answers a
        // missing local key beside an existing session store by reinitialising
        // that store, and a session store that is reinitialised on every
        // lookup is a store that never works and quietly destroys what it
        // replaces. So it is a parse error rather than a warning, which on a
        // daemon means the process refuses to start.
        let refused = serde_json::from_str::<DaemonConfig>(
            r#"{"stores":{"proton":{"enabled":true,"key_provider":"keyring"}}}"#,
        )
        .expect_err("`keyring` must not parse");
        let said = refused.to_string();
        assert!(
            said.contains("FORCING A LOGOUT"),
            "the refusal does not say what `keyring` does here: {said}"
        );

        // The control: both accepted values parse, so the assertion above is
        // about this one word and not about the field being unreadable.
        for word in ["fs", "env"] {
            let config = parse(&format!(
                r#"{{"stores":{{"proton":{{"enabled":true,"key_provider":"{word}"}}}}}}"#
            ));
            assert_eq!(config.stores.proton.key_provider.as_str(), word);
        }

        // And the default is `env`, so a config that says nothing is not
        // silently the vendor's `keyring` default — see `KeyProvider`'s own
        // doc for why `env` rather than `fs` is that default now.
        assert_eq!(parse("{}").stores.proton.key_provider.as_str(), "env");
    }

    #[test]
    fn a_proton_name_is_routed_only_where_the_daemons_own_config_declares_it() {
        // A daemon-hosted Proton lookup reaches exactly the vault, item and
        // field an operator wrote in a file the calling user cannot write.
        // Nothing is defaulted, so a name that appears nowhere has no address
        // at all — which is what makes an invented name cost no vendor process.
        let config = parse(
            r#"{"stores":{"proton":{"enabled":true}},
                "secrets":{"DECLARED":{"store":"proton","vault":"company",
                                       "item":"decoy","field":"password"},
                           "ELSEWHERE":{"store":"keychain"}}}"#,
        );
        let routing = config.proton_routing();

        // Counted, not tested for emptiness: `ELSEWHERE` says nothing about
        // Proton and must not be projected, and a `> 0` check cannot see that.
        assert_eq!(routing.declared(), 1);
    }

    #[test]
    fn neither_cache_window_can_be_configured_past_the_ceiling() {
        // Both windows bound how long a value the vendor has replaced can
        // still reach a child, so neither is a number a config file may set to
        // a day. A config is not a trusted input: it can be handed in with
        // `--config`.
        let config = parse(r#"{"cache_ttl_seconds": 86400, "cache_stale_seconds": 86400}"#);
        assert_eq!(config.ttl().as_secs(), super::MAX_CACHE_SECONDS);
        assert_eq!(config.stale().as_secs(), super::MAX_CACHE_SECONDS);
    }

    #[test]
    fn caching_switched_off_leaves_no_stale_window_behind() {
        // One key turns the whole mechanism off. A daemon told to cache
        // nothing must not keep serving values for four minutes because a
        // second key still holds its default.
        let config = parse(r#"{"cache_ttl_seconds": 0}"#);
        assert_eq!(config.ttl(), std::time::Duration::ZERO);
        assert_eq!(
            config.stale(),
            std::time::Duration::ZERO,
            "a zero freshness window left a stale window standing"
        );
    }

    #[test]
    fn a_config_that_names_neither_window_takes_both_defaults() {
        let config = parse("{}");
        assert_eq!(config.ttl().as_secs(), 60);
        assert_eq!(config.stale().as_secs(), 240);
    }

    #[test]
    fn the_daemon_has_no_second_proton_identity_for_writes() {
        // The session config carries a `manager` block — an editor-role token
        // the write verbs use. There is deliberately no counterpart here:
        // `store::manage` refuses every write under a daemon, so an editor
        // token in the daemon's file would be a larger prize with no way to be
        // used. A key added later would be dropped by serde in silence, so the
        // check is that the parsed config cannot express one.
        let config = parse(
            r#"{"stores":{"proton":{"enabled":true,
                                    "manager":{"session_dir":"/nonexistent/manager"}}}}"#,
        );
        let rendered = serde_json::to_string(&config).expect("serialize");
        assert!(!rendered.contains("manager"), "{rendered}");
    }
}
