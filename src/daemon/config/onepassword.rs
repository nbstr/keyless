use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{DaemonConfig, default_listing_ttl_ms, default_probe_binary, default_timeout_ms};
use crate::paths::ConfigPath;
use crate::store::file::FileStore;
use crate::store::onepassword::{
    Routing as OnePasswordRouting, SERVICE_ACCOUNT_TOKEN, ServiceAccount,
};

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

fn default_onepassword_binary() -> ConfigPath {
    crate::config::default_onepassword_binary()
}

impl DaemonConfig {
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

    /// The daemon's 1Password login, read out of its own file.
    ///
    /// The same arrangement as [`DaemonConfig::vendor_credentials`], for the
    /// same reasons.
    pub(super) fn service_account(&self) -> Option<ServiceAccount> {
        let settings = &self.stores.onepassword;
        if settings.credentials.is_empty() {
            return None;
        }
        Some(ServiceAccount::new(
            Box::new(FileStore::new(settings.credentials_file.to_path_buf())),
            settings.credentials.clone(),
        ))
    }

    pub(super) fn onepassword_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
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
        warnings
    }
}
