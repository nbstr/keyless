use std::fmt;
use std::process::Command;

/// The environment variable a read's justification travels in.
pub(crate) const REASON_VAR: &str = "PROTON_PASS_AGENT_REASON";

/// The environment variable that chooses which logged-in identity answers.
pub(crate) const SESSION_DIR_VAR: &str = "PROTON_PASS_SESSION_DIR";

/// The environment variable that chooses where the local encryption key lives.
///
/// See [`KeyProvider`], which is the whole story.
pub const KEY_PROVIDER_VAR: &str = "PROTON_PASS_KEY_PROVIDER";

/// The environment variable [`KeyProvider::Env`] reads that key out of.
pub const ENCRYPTION_KEY_VAR: &str = "PROTON_PASS_ENCRYPTION_KEY";

/// Switches the vendor's telemetry off.
///
/// The FAQ documents the name and what it does — "If the environment variable
/// is set telemetry will not be saved and the currently saved locally will be
/// cleared" — but no value, only that it must be "set". See
/// [`set_vendor_switch_offs`] for the value this crate sends.
pub(crate) const DISABLE_TELEMETRY_VAR: &str = "PROTON_PASS_DISABLE_TELEMETRY";

/// Switches the vendor's automatic update check off.
///
/// Undocumented: found only in the installed binary's own strings, beside its
/// update-check code and the manifest URL it would otherwise fetch. There is
/// nothing here for that check to offer: `stores.proton.binary` names one
/// absolute, operator-chosen path, and this crate never rewrites what is
/// there — replacing it, like installing it, is the operator's own act, not
/// something a spawned child should attempt on its own initiative.
pub(crate) const NO_UPDATE_CHECK_VAR: &str = "PROTON_PASS_NO_UPDATE_CHECK";

/// Put both vendor switch-offs on one command.
///
/// # Why `1`, for both
///
/// Neither variable's value is documented — see [`DISABLE_TELEMETRY_VAR`] and
/// [`NO_UPDATE_CHECK_VAR`]. `1` is this crate's default for a boolean-shaped
/// variable the vendor never published a value for.
pub(crate) fn set_vendor_switch_offs(command: &mut Command) {
    command.env(DISABLE_TELEMETRY_VAR, "1");
    command.env(NO_UPDATE_CHECK_VAR, "1");
}

/// The value a built [`Command`] would export for `key`, read off it directly
/// rather than off the process's own environment.
///
/// Written once for this module's own tests and for
/// [`assert_vendor_switch_offs`], which the sibling adapters' tests call
/// rather than reaching for this.
///
/// A variable somebody removed with `env_remove` arrives here as the same
/// `None` an untouched variable gives, because `get_envs` reports a removal as
/// a `None` value. A test that has to tell those apart reads `get_envs`
/// itself, the way the ambient-filter tests do.
#[cfg(test)]
pub(super) fn env_value(command: &Command, key: &str) -> Option<String> {
    command
        .get_envs()
        .find(|(k, _)| *k == std::ffi::OsStr::new(key))
        .and_then(|(_, value)| value)
        .map(|value| value.to_string_lossy().into_owned())
}

/// Both vendor switch-offs are on `command`, each with the value
/// [`set_vendor_switch_offs`] sends.
#[cfg(test)]
pub(crate) fn assert_vendor_switch_offs(command: &Command) {
    for variable in [DISABLE_TELEMETRY_VAR, NO_UPDATE_CHECK_VAR] {
        // The observed value, never the `Command` itself: its `Debug` prints
        // every variable it carries, and these commands carry a login token.
        let observed = env_value(command, variable);
        assert_eq!(
            observed.as_deref(),
            Some("1"),
            "`{variable}` reads {observed:?} on this command, not `1`"
        );
    }
}

/// Where `pass-cli` keeps the key its local session store is encrypted with.
///
/// # This is the field that decides whether a login survives
///
/// `pass-cli` encrypts its session database with a **local key**, and where
/// that key is kept is chosen by [`KEY_PROVIDER_VAR`]. Read out of the 2.3.2
/// binary, it accepts exactly three words: `fs`, `keyring` and `env`, and it
/// says so — `Invalid PROTON_PASS_KEY_PROVIDER value: '<what you wrote>'. Valid
/// values are 'fs', 'keyring', or 'env'`.
///
/// Two of those three are representable here. `keyring` is not, and that is
/// this type's entire reason to exist.
///
/// **The default is `keyring`, and a keyring belongs to the uid that unlocked
/// it.** So a process with no login keychain — a daemon's uid, a build agent,
/// anything started without a user session — asks the keyring for the local
/// key and is told there is none. The binary's own words for what happens
/// next: `Local encryption key not found but local data exists. Forcing logout
/// for security.` It then reinitialises the session store at that path.
///
/// That is the mechanism behind this adapter's oldest and worst hazard, the
/// one [`remove_ambient_references`] documents: a `pass-cli` invoked with a
/// stripped environment **destroys a web-login session**, unrecoverably. The
/// stripping was never the cause; it was one way of reaching the cause, by
/// taking away what the keyring provider needed to answer. A daemon reaches
/// the same cause by simply not having a login keychain in the first place.
///
/// Naming a provider that keeps the key somewhere a daemon can reach is
/// therefore not a convenience — it is the difference between an adapter that
/// works behind a uid boundary and one that empties a session store every time
/// it runs. So the field is not optional, and the unsafe value cannot be
/// written into a config at all: a `keyring` there is a parse error, which on
/// a daemon means it refuses to start, which is visible. See
/// [`crate::daemon::config`] on why that is the right direction for a daemon
/// to fail in.
///
/// # The default is `env`, and `fs` is not merely the OTHER safe value
///
/// `fs`'s file — read out of `pass-cli`'s own source, in
/// `FsLocalKeyProvider::get_local_key` — is minted with `create_new(true)` on
/// ANY verb that finds none, so of two children that both find it missing the
/// one that loses the race fails that call outright rather than picking up
/// the key the winner just wrote, and `local_key_path`
/// calls `std::fs::canonicalize` on the session directory, so it errors
/// instead of minting when that directory does not exist yet. Worse,
/// `pass-cli logout` calls `remove_key` UNCONDITIONALLY before it deletes the
/// session data — which for `fs` deletes the file — so a concurrent reader's
/// still-open session outlives its own key by however long the race takes,
/// and the generation is undecryptable from that moment on with no local
/// symptom until the next read.
///
/// `env` has none of that surface, not a narrower version of it: the key
/// arrives in [`ENCRYPTION_KEY_VAR`] and is derived per process, so there is
/// no file to race for, none to be absent, and `EnvLocalKeyProvider::remove_key`
/// is a documented no-op — "Nothing to remove since the key only lives in
/// process memory". Pairing it with a daemon that generates that value once,
/// into its own credential file, at first start (see
/// [`crate::daemon::credential`]) is what makes "no `pass-cli` process can
/// ever create, replace or lose a key" true rather than merely likely: there
/// is exactly one writer, and it is not the vendor.
///
/// `fs` stays accepted for a machine not yet reconfigured onto `env` — it is
/// still safer than the vendor's own `keyring` default, which is why it was
/// the default here first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KeyProvider {
    /// The key is a file inside the session directory. Whoever owns that
    /// directory can read it, and nobody else, which is the same boundary the
    /// session store itself has — but see this type's own doc for why it is
    /// no longer the default.
    Fs,
    /// The key arrives in [`ENCRYPTION_KEY_VAR`], base64url-shaped. Nothing is
    /// written beside the session store, at the cost of the daemon having to
    /// hold one more value in its own credential file — which it generates
    /// itself; see [`crate::daemon::credential`].
    #[default]
    Env,
}

impl KeyProvider {
    /// The word the vendor accepts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyProvider::Fs => "fs",
            KeyProvider::Env => "env",
        }
    }
}

impl fmt::Display for KeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for KeyProvider {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for KeyProvider {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let word = String::deserialize(deserializer)?;
        match word.as_str() {
            "fs" => Ok(KeyProvider::Fs),
            "env" => Ok(KeyProvider::Env),
            // Refused by name, with the reason, rather than by serde's
            // "unknown variant" — an operator reading that would reasonably
            // conclude this build is out of date, and set out to find one that
            // accepts the vendor's own documented value.
            "keyring" => Err(serde::de::Error::custom(format!(
                "`{KEY_PROVIDER_VAR}` may not be `keyring` here. A keyring belongs to the \
                 uid that unlocked it, so a daemon's uid finds no local key in one — and \
                 `pass-cli` answers a missing local key beside an existing session store by \
                 FORCING A LOGOUT and reinitialising the store. Use `fs`, which keeps the \
                 key in the session directory, or `env`, which takes it from \
                 `{ENCRYPTION_KEY_VAR}`"
            ))),
            other => Err(serde::de::Error::custom(format!(
                "`{other}` is not a key provider; this build accepts `fs` and `env`"
            ))),
        }
    }
}

/// The scheme `pass-cli` treats as a secret reference wherever it finds one.
pub(crate) const REFERENCE_SCHEME: &str = "pass://";

/// Environment variables the probe must not inherit, and why there are any.
///
/// **Measured 2026-08-08, `pass-cli` 2.2.5:** `run` resolves every `pass://`
/// reference it finds in the **whole inherited environment**, not only the ones
/// in `--env-file`. A single unrelated `UNRELATED=pass://…` exported in the
/// caller's shell is enough to make
/// `pass-cli run -- printenv HOME` exit 1 with `Failed to resolve secret … in
/// variable UNRELATED`.
///
/// That costs `keyless` two things at once, and both are exactly the kind of
/// over-reach the rest of this adapter is written to avoid:
///
/// - **Reads nobody asked for.** Each extra reference is fetched from the
///   vault and recorded, permanently and off-machine, against an audit trail
///   the user reads to answer "what did this tool touch?". `keyless` asked for
///   one name; a stale shell variable would make it read a second item and
///   leave a receipt saying it did.
/// - **A denial with a misleading cause.** One unresolvable reference anywhere
///   in the environment fails the *whole* probe, so every Proton-backed name in
///   the config degrades and the message is about a variable that has nothing
///   to do with any of them.
///
/// So the probe's environment is filtered rather than cleared.
///
/// # Never clear it — clearing DESTROYS the user's login
///
/// Clearing was tried, on 2026-08-08, and it did more than fail. Run under
/// `env -i` with `PROTON_PASS_SESSION_DIR` set and little else, `pass-cli`
/// 2.2.5 reports `This operation requires an authenticated client` **and
/// reinitialises the session database at that path**, replacing a logged-in
/// session with an empty one.
///
/// How bad that is depends on how the session was created, and the difference
/// is worth knowing before anyone experiments here:
///
/// - A **personal-access-token** session recovers by itself **from an emptied
///   store, which is the only case this section is about**. The token is held
///   outside the session database, so the next command re-establishes the
///   session — with a **new share id for the same vault**, which is why a
///   reference is written against the session that will resolve it and not
///   copied from anywhere else. Do not read it as covering EXPIRY: an expired
///   session leaves the store populated and invalid, `pass-cli` answers a
///   login over it with `Client is already authenticated`, and nothing
///   re-establishes it. That is [`crate::daemon::session`]'s job.
/// - A **web-login** session does not. It is gone, the only way back is
///   `pass-cli login`, and nothing on disk restores it. That is not a
///   hypothetical: stripping the environment of a probe is enough to destroy a
///   web-login session that took a browser round trip to create.
///
/// The rule that follows is unconditional and applies to any future change
/// here: **`pass-cli` may rewrite its session store on any invocation, so never
/// invoke it with an environment you have stripped.** Remove exactly the
/// variables that are known to cause a problem and leave the rest alone.
///
/// The caller's own environment is untouched: this filters the argument list of
/// one short-lived probe, not the environment `keyless` hands the real child.
///
/// `environment` is a parameter rather than a call to [`std::env::vars_os`] so
/// the rule can be tested against a hand-written list. Mutating this process's
/// environment to test it would be `unsafe` in a suite that runs its tests on
/// several threads, and the wiring to the real environment is covered live in
/// `tests/proton_live.rs`.
pub(crate) fn remove_ambient_references<I>(command: &mut Command, environment: I)
where
    I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
{
    for (key, value) in environment {
        if value.to_string_lossy().contains(REFERENCE_SCHEME) {
            command.env_remove(&key);
        }
    }
}
