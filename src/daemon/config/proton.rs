use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::renewal::SessionRenewal;
use super::{
    DEFAULT_LOCAL_KEY_ENTRY, DaemonConfig, default_listing_ttl_ms, default_probe_binary,
    default_timeout_ms,
};
use crate::paths::ConfigPath;
use crate::store::file::FileStore;
use crate::store::proton::{
    AgentToken, ENCRYPTION_KEY_VAR as PROTON_ENCRYPTION_KEY, KeyProvider, Routing as ProtonRouting,
    TOKEN_VAR as PROTON_TOKEN,
};

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

fn default_proton_binary() -> ConfigPath {
    crate::config::default_proton_binary()
}

impl DaemonConfig {
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
    pub(super) fn agent_token(&self) -> Option<AgentToken> {
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

    pub(super) fn proton_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
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
        warnings
    }
}
