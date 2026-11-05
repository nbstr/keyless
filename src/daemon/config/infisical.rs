use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{DaemonConfig, default_probe_binary, default_timeout_ms};
use crate::paths::ConfigPath;
use crate::store::file::FileStore;
use crate::store::infisical::{
    ACCESS_TOKEN, IDENTITY_CLIENT_ID, IDENTITY_CLIENT_SECRET, Routing, VendorCredentials,
};

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

fn default_infisical_binary() -> ConfigPath {
    crate::config::default_infisical_binary()
}

fn default_infisical_path() -> String {
    crate::config::default_infisical_path()
}

impl DaemonConfig {
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
    pub(super) fn vendor_credentials(&self) -> Option<VendorCredentials> {
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

    pub(super) fn infisical_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
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
        warnings
    }
}
