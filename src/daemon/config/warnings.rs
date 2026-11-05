use super::DaemonConfig;
use super::StorePolicy;

impl DaemonConfig {
    /// Problems worth telling an operator about that are not fatal.
    ///
    /// Returned rather than printed so `keylessd` and its tests see the same
    /// list.
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
        warnings.extend(self.proton_warnings());
        warnings.extend(self.onepassword_warnings());
        warnings.extend(self.infisical_warnings());
        warnings.extend(self.keychain_warnings());

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
