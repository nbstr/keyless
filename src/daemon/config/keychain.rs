use serde::{Deserialize, Serialize};

use super::DaemonConfig;
use crate::paths::ConfigPath;

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

fn default_service() -> String {
    crate::NAME.to_owned()
}

fn default_security_binary() -> ConfigPath {
    ConfigPath::from("/usr/bin/security")
}

impl DaemonConfig {
    pub(super) fn keychain_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.stores.keychain.enabled && self.stores.keychain.keychain.is_none() {
            warnings.push(
                "the keychain store has no keychain file; a daemon has no login keychain, \
                 so lookups will find nothing"
                    .to_owned(),
            );
        }
        warnings
    }
}
