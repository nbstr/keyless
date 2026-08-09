//! Config: which names exist, and which store answers for each.
//!
//! JSON, because the audit log already needs `serde_json` and a second
//! serialization format would be a dependency bought for cosmetics.
//!
//! Unknown fields are **accepted and ignored**. That is a deliberate forward
//! -compatibility choice: when a later build adds another `stores` section, an
//! older binary must degrade to "I cannot serve those names" rather than refuse
//! to parse the file and therefore refuse to serve any.
//!
//! **Nothing in this file is ever a secret value.** It holds names, references,
//! store kinds, paths and timeouts. There is no field a value fits in, which is
//! why the file needs no special permissions and can be committed.
//!
//! ```json
//! {
//!   "stores": {
//!     "keychain": { "service": "keyless" },
//!     "infisical": { "enabled": true },
//!     "proton": { "enabled": true },
//!     "default": "keychain"
//!   },
//!   "secrets": {
//!     "DATABASE_URL": { "store": "infisical", "env": "staging", "path": "/backend" },
//!     "GITHUB_TOKEN": { "account": "demo-token", "service": "demo" },
//!     "HOME_WIFI": { "store": "proton", "vault": "Personal", "item": "Router",
//!                    "field": "password" }
//!   }
//! }
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::NAME;
use crate::error::ConfigError;
use crate::paths::ConfigPath;

/// The whole config file.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    /// Per-store settings.
    #[serde(default)]
    pub stores: Stores,
    /// Declared names. A name absent from here is still resolvable — it just
    /// falls back to the default store with its own name as the account — but
    /// only declared names are enumerable, so only they appear in `ls`.
    #[serde(default)]
    pub secrets: BTreeMap<String, SecretRoute>,
}

/// Settings for each store backend, plus how a name picks one.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Stores {
    /// macOS Keychain.
    #[serde(default)]
    pub keychain: KeychainConfig,
    /// Infisical, via its CLI's `run` verb.
    #[serde(default)]
    pub infisical: InfisicalConfig,
    /// Proton Pass, via `pass-cli run`.
    #[serde(default)]
    pub proton: ProtonConfig,
    /// How an unpinned name chooses a backend. See [`Policy`].
    #[serde(default)]
    pub policy: Policy,
    /// Backend for names that pin none, when several are enabled.
    ///
    /// Named `default` in the file. Setting it is an explicit statement — "my
    /// unpinned names live here" — which is a different thing from the tool
    /// guessing, and it is the only way an unpinned name resolves under
    /// [`Policy::Explicit`] with more than one backend configured.
    #[serde(default, rename = "default", skip_serializing_if = "Option::is_none")]
    pub default_store: Option<String>,
    /// `keylessd`, across the uid boundary.
    ///
    /// When this is enabled, **every local backend above is suppressed** —
    /// keychain, Infisical and Proton alike — whatever their own `enabled`
    /// flags say, and per-name `store` pins are dropped. See
    /// [`crate::store::build`] for why that is a rule rather than a default.
    #[serde(default)]
    pub daemon: DaemonClientConfig,
}

/// How a name that pins no store chooses one.
///
/// The default is deliberately the strict one. With a company vault and a
/// personal vault both configured, "first backend that has it wins" resolves
/// `DATABASE_URL` to whichever store happens to be listed first — silently, and
/// with no way for the caller to notice. That is a cross-tenant leak wearing a
/// convenience feature's clothes, so it is not the default and it has to be
/// asked for by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Exactly one backend may answer a name, and which one is never inferred
    /// from ordering: the name's own `store`, else `stores.default`, else the
    /// single configured backend. Anything else is reported as ambiguous and
    /// degrades the run.
    #[default]
    Explicit,
    /// Ask every backend in configuration order and take the first hit.
    ///
    /// Convenient with one tenant, unsafe with two. Opt in only when every
    /// configured backend holds secrets of the same trust level.
    Ordered,
}

/// How this process talks to `keylessd`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonClientConfig {
    /// Off unless asked for, so an install with no daemon behaves exactly as
    /// it did before one existed.
    #[serde(default)]
    pub enabled: bool,
    /// Socket path. Absent means the built-in default, which honours
    /// `KEYLESS_SOCKET`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<ConfigPath>,
    /// Deadline for the whole exchange, in milliseconds.
    ///
    /// This is a ceiling on how long `keyless run` can be delayed by a daemon
    /// that is wedged. It is short on purpose: waiting is indistinguishable
    /// from blocking to whoever is watching a terminal.
    #[serde(default = "default_daemon_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for DaemonClientConfig {
    fn default() -> Self {
        DaemonClientConfig {
            enabled: false,
            socket: None,
            timeout_ms: default_daemon_timeout_ms(),
        }
    }
}

impl DaemonClientConfig {
    /// The socket to use.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.socket
            .as_deref()
            .map(Path::to_path_buf)
            .unwrap_or_else(crate::ipc::default_socket_path)
    }

    /// The exchange deadline, clamped to [`MAX_TIMEOUT_MS`].
    #[must_use]
    pub const fn timeout(&self) -> std::time::Duration {
        bounded_timeout(self.timeout_ms)
    }
}

/// Deadline for one socket exchange with the daemon.
///
/// Distinct from the vendor-CLI deadline further down, and much shorter: this
/// is a local socket round trip, not a process spawn that may hit the network.
const fn default_daemon_timeout_ms() -> u64 {
    3_000
}

/// macOS Keychain settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeychainConfig {
    /// The generic-password *service* every lookup uses unless a route
    /// overrides it.
    #[serde(default = "default_service")]
    pub service: String,
    /// Path to the `security` binary.
    ///
    /// Configurable so the adapter can be exercised against a stub in tests
    /// without ever touching a real keychain, and so an unusual install still
    /// works.
    #[serde(default = "default_security_binary")]
    pub binary: ConfigPath,
    /// How long one lookup may take before it degrades the run.
    ///
    /// This backend is local and it is the one enabled by default, which is
    /// exactly why it needs the deadline the other two always had: `security`
    /// is a path in a config file, so "a local call cannot hang" is a statement
    /// about a binary nobody has checked. It is also the pathological case for
    /// an unbounded read — a `security` that writes `/dev/zero` to its stdout
    /// grows this process by gigabytes for as long as it is allowed to run.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Set false to take the backend out of the search order without deleting
    /// its settings.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for KeychainConfig {
    fn default() -> Self {
        KeychainConfig {
            service: default_service(),
            binary: default_security_binary(),
            timeout_ms: default_timeout_ms(),
            enabled: true,
        }
    }
}

/// Infisical settings.
///
/// Everything here is a coordinate or a knob. The login itself is the CLI's:
/// `keyless` never reads `~/.infisical/.token`, never reads the encrypted
/// backup cache beside it, and has no field in which to put a token.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InfisicalConfig {
    /// Path to, or name of, the `infisical` binary.
    #[serde(default = "default_infisical_binary")]
    pub binary: ConfigPath,
    /// **Read by nothing. Kept only so a config that still sets it is told so.**
    ///
    /// Infisical requires an environment on every call — its own CLI makes
    /// `--env` mandatory and has no default. `keyless` used to default this
    /// field to `dev` and fall back to it whenever a name declared none, which
    /// meant **any name a caller invented resolved against whatever one machine
    /// happened to put here.** Measured against a config whose value was `prod`:
    /// a name declared in no config at all came back with a production value,
    /// exit 0, no warning.
    ///
    /// A per-machine default cannot be made safe by choosing a better value for
    /// it. The hazard is not which environment it names, it is that the
    /// environment is invisible at the point of use — so the fix is that there
    /// is no config-level environment at all. Declare `env` on the name, or pass
    /// `keyless run --env <slug>` for the whole invocation.
    ///
    /// This field survives as an `Option` for one reason: unknown keys are
    /// silently ignored by design (see the module documentation), so deleting it
    /// outright would make an existing `"env": "prod"` vanish without a word,
    /// and the reader would be left with names that stopped resolving and no
    /// sentence connecting the two. Keeping it lets [`crate::store::build`] name
    /// the exact line to delete. It is never consulted by a lookup; see
    /// [`crate::store::infisical::Routing`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// Folder path used when a name declares none. Defaults to `/`.
    ///
    /// **This one stays defaulted, and the asymmetry with [`InfisicalConfig::env`]
    /// above is deliberate.** `/` is the vendor's OWN default for `--path`, so
    /// defaulting it here invents nothing; the environment default was an
    /// invention of `keyless`, which is what made it this tool's hazard to
    /// remove. The two also fail differently: a wrong path can only miss a
    /// folder *inside the environment you named*, which degrades the run and
    /// says so, while a wrong environment returned a real, plausible value from
    /// the other side of the tenancy boundary.
    ///
    /// `ls` prints the path beside the environment for every Infisical name, so
    /// a folder that holds nothing is visible without a lookup.
    #[serde(default = "default_infisical_path")]
    pub path: String,
    /// Project id, for when the working directory has no `.infisical.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Directory holding `.infisical.json`, when it is not the working directory.
    ///
    /// `keyless` runs wherever the caller is, and the CLI resolves its project
    /// by walking up from the working directory. Without this, the same config
    /// resolves in one checkout and degrades in another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_dir: Option<ConfigPath>,
    /// How long one lookup may take before it degrades the run.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// The helper that reads one variable out of the child environment.
    ///
    /// Configurable for the same two reasons as the keychain binary: an unusual
    /// install still works, and the adapter is exercisable against a stub.
    #[serde(default = "default_probe_binary")]
    pub probe_binary: ConfigPath,
    /// Set false to take the backend out of the search order.
    #[serde(default)]
    pub enabled: bool,
}

impl Default for InfisicalConfig {
    fn default() -> Self {
        InfisicalConfig {
            binary: default_infisical_binary(),
            env: None,
            path: default_infisical_path(),
            project_id: None,
            config_dir: None,
            timeout_ms: default_timeout_ms(),
            probe_binary: default_probe_binary(),
            // Off unless asked for: a backend nobody configured must not add a
            // process spawn and a network round trip to every lookup.
            enabled: false,
        }
    }
}

/// Proton Pass settings.
///
/// As with Infisical, the login is the CLI's. There is no field for an agent
/// token; `pass-cli` reads its own. What there *is* a field for is **which**
/// login — see [`ProtonConfig::session_dir`], which is the difference between
/// reading one vault and reading the whole account.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtonConfig {
    /// Path to, or name of, the `pass-cli` binary.
    #[serde(default = "default_proton_binary")]
    pub binary: ConfigPath,
    /// The session directory every lookup runs under, as
    /// `PROTON_PASS_SESSION_DIR`.
    ///
    /// **This is the scoping control, and it has no safe default.** `pass-cli`
    /// keeps one logged-in identity per session directory, and it falls back to
    /// a shared per-user location when the variable is unset. On a machine
    /// where somebody has ever run a plain `pass-cli login`, that shared
    /// location holds the *full account* — every vault, not the one a vault
    /// -scoped agent token was minted for.
    ///
    /// The two sessions therefore see different accounts: a shared session
    /// reaches whatever identity was last logged in there, and the agent
    /// session at `~/.keyless-pass-session` reaches only the vault its token
    /// was minted for. Inheriting the ambient session is not a neutral default
    /// — it is the scoping being bypassed, and it bypasses it invisibly,
    /// because a session that can read everything resolves every name
    /// successfully.
    ///
    /// Absent means the Proton backend degrades every lookup rather than
    /// guessing which identity was meant. See [`crate::store::proton`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_dir: Option<ConfigPath>,
    /// The SECOND identity: an editor-role token, used by the write verbs only.
    ///
    /// [`ProtonConfig::session_dir`] above is the **reader**. It is the default
    /// and the only identity `run`, `ls`, `items` and `fields` can reach — see
    /// [`crate::store::proton::ProtonStore::from_config`], which does not read
    /// this field at all. `new` and `put` use this one and nothing else.
    ///
    /// Absent means the write verbs refuse and name the token to mint. That is
    /// deliberately a refusal rather than a degrade; see
    /// [`crate::store::manage`] for the asymmetry with `run`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<ProtonManagerConfig>,
    /// How long one lookup may take before it degrades the run.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// The helper that reads one variable out of the child environment.
    #[serde(default = "default_probe_binary")]
    pub probe_binary: ConfigPath,
    /// Set false to take the backend out of the search order.
    #[serde(default)]
    pub enabled: bool,
}

impl Default for ProtonConfig {
    fn default() -> Self {
        ProtonConfig {
            binary: default_proton_binary(),
            session_dir: None,
            manager: None,
            timeout_ms: default_timeout_ms(),
            probe_binary: default_probe_binary(),
            enabled: false,
        }
    }
}

/// The write identity for Proton Pass: a second agent token, editor role.
///
/// # Why this is a separate block rather than a role flag
///
/// A role is a property of the **token**, and `pass-cli` keeps one token per
/// session directory. So "which role am I acting as?" is answered by which
/// directory a child is pointed at, and nothing else. Two roles therefore need
/// two directories, and a config that expressed the role any other way would be
/// describing something the CLI cannot act on.
///
/// # What this split is, and what it is not
///
/// It is two tokens, two audit trails and two expiries: a `run` in any of ~20
/// sessions cannot create, move or trash an item, and Proton's own log shows
/// which token did what. That is real and it is worth having.
///
/// It is **not** a boundary, and this is the sentence not to skip: a session
/// that can read this config can set `PROTON_PASS_SESSION_DIR` itself and use
/// the manager token directly. Everything on this side of the uid line is
/// reachable by anything running as this uid — the same fact
/// [`crate::daemon`] exists to change. Locally the split is advisory. The
/// enforced version needs the manager token to live behind the daemon's uid,
/// and `keylessd` carries no Proton adapter and no write operation yet, which
/// is why [`crate::store::manage::manager`] refuses to write locally when the
/// daemon is enabled rather than reaching around it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtonManagerConfig {
    /// `PROTON_PASS_SESSION_DIR` for the write verbs' children.
    ///
    /// Optional in the type so a half-written block degrades one verb instead of
    /// failing the whole config parse — a parse failure would fall back to
    /// defaults and take `run` down with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_dir: Option<ConfigPath>,
    /// How long one write may take before it fails.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for ProtonManagerConfig {
    fn default() -> Self {
        ProtonManagerConfig {
            session_dir: None,
            timeout_ms: default_timeout_ms(),
        }
    }
}

/// Where one name lives, when the defaults are not right.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecretRoute {
    /// Store identifier, e.g. `keychain`. Absent means "decide by policy".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// Keychain service override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Keychain account override. Defaults to the name itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Infisical environment slug — `dev`, `staging`, `prod`.
    ///
    /// **Not an override: this is the primary way a name gets an environment,
    /// and there is no default behind it.** Absent, the name resolves only if
    /// the invocation supplied one with `keyless run --env <slug>`; absent both,
    /// the lookup does not happen and the run degrades naming this field.
    ///
    /// It outranks `--env`, because a name that says where it lives must not be
    /// repainted by a blanket flag aimed at the names that do not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    /// Infisical folder path override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Infisical secret key override. Defaults to the name itself.
    ///
    /// **This field is also read by [`SecretRoute::aliases`]**, because an
    /// Infisical key IS an environment variable name: `infisical run` injects a
    /// project's secrets into a child under their keys. So a name declaring
    /// `"key": "DATABASE_URL"` has already said, in the only vocabulary the
    /// store has, that this credential is the variable `DATABASE_URL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Another environment variable this credential answers to.
    ///
    /// For stores whose coordinates name an ITEM rather than a variable — a
    /// keychain account, a Proton vault and item — nothing about the route says
    /// which variable a program reads, so there is nothing to derive and this is
    /// where it is said. See [`SecretRoute::aliases`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub var: Option<String>,
    /// Proton Pass vault NAME, e.g. `personal`. Part of the name form.
    ///
    /// Names are what a person types and what stays true; the ids underneath
    /// them are minted per session. See [`crate::store::proton`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
    /// Proton Pass item TITLE, matched exactly within [`SecretRoute::vault`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// Which field of that item holds the value, e.g. `password`.
    ///
    /// Never defaulted. Guessing a field would send a read — and a permanent,
    /// off-machine audit entry — to something nobody asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Proton Pass reference, `pass://SHARE_ID/ITEM_ID/FIELD`.
    ///
    /// The id form. It still works and it still pins exactly one item, which is
    /// why it is the escape hatch for two items sharing a title. Two costs come
    /// with it, and both are silent:
    ///
    /// - **A share id is minted per session**, so a reference written today
    ///   stops resolving as soon as the session is re-established — as a
    ///   degraded run, not an error.
    /// - **It resolves a trashed item.** Measured 2026-08-08: `pass-cli run`
    ///   returns a trashed item's value, exit 0, no warning. The trash rule
    ///   lives in the listing, and this form never lists.
    ///
    /// Prefer `vault` + `item` + `field`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Free-text note shown by `ls`. Never a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl SecretRoute {
    /// The other environment variables this credential answers to, besides the
    /// declared name itself.
    ///
    /// # The wall this removes
    ///
    /// **A name labels a secret. It is not the variable a program reads.** The
    /// two are routinely different — a store holds one credential per
    /// environment and needs distinct labels for them, while every program in
    /// every environment reads the same variable. So a declaration says
    /// `"NAME_FOR_STAGING": {"key": "THE_VARIABLE"}` and the two halves are
    /// written down side by side.
    ///
    /// `keyless` held both halves and injected only the literal one, so a bare
    /// `-s NAME_FOR_STAGING` set a variable nothing reads. The command then
    /// fails for a reason that looks nothing like a naming problem: the variable
    /// it wanted was simply never set, so it reports a missing credential, or an
    /// unauthenticated call, or nothing at all at exit 0.
    ///
    /// Reconciling those two halves was left to whoever typed the command, every
    /// time, from knowledge that appears nowhere in it. This method is that
    /// reconciliation, done by the tool that already has both.
    ///
    /// # Why both, and not instead
    ///
    /// The value is injected under the declared name AND under each of these.
    /// Substituting one for the other would be a second silent variable-name
    /// failure aimed the other way — every script that reads `$NAME` today would
    /// find it unset — and trading one invisible unset variable for another is
    /// not a fix. Under both, nothing that works today stops working, and the
    /// case that used to need a person stops needing one.
    ///
    /// # What is NOT derived, and why the omission is deliberate
    ///
    /// A keychain `account`, a Proton `vault`/`item`/`field`: those coordinates
    /// name an item in a store, and no rule turns `Router` + `password` into the
    /// variable a program reads. Guessing would inject a variable nobody named,
    /// from a word that was never an environment variable. Those declarations
    /// say it with [`SecretRoute::var`] instead.
    ///
    /// The caller's own `ENV=NAME` is not routed through here at all: a spelled
    /// target is an instruction, and it stays exactly as narrow as it was typed.
    #[must_use]
    pub fn aliases(&self, name: &str) -> Vec<String> {
        // `var` is a statement; `key` is evidence. An explicit statement is not
        // added to, because a route that says which variable it means has
        // answered the question this method exists to ask.
        let candidate = self.var.as_ref().or(self.key.as_ref());
        candidate
            .filter(|variable| variable.as_str() != name)
            .into_iter()
            .cloned()
            .collect()
    }
}

fn default_service() -> String {
    NAME.to_owned()
}

fn default_security_binary() -> ConfigPath {
    ConfigPath::from("/usr/bin/security")
}

fn default_infisical_binary() -> ConfigPath {
    ConfigPath::from("infisical")
}

fn default_infisical_path() -> String {
    "/".to_owned()
}

fn default_proton_binary() -> ConfigPath {
    ConfigPath::from("pass-cli")
}

/// Ten seconds per lookup.
///
/// Long enough that a cold CLI start, a TLS handshake and a token refresh all
/// fit without ever degrading a run that would have worked. Short enough that a
/// black-holed network costs one command a pause rather than wedging a terminal
/// until the user reaches for Ctrl-C — and the expiry is a degraded path, so
/// the command still runs when it fires.
fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

/// Ten seconds, as a constant a store can reach without a config.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;

/// `printenv NAME` writes one variable's value to stdout and nothing else. It
/// is not a shell, so the name is an argument rather than something interpolated
/// into a command line.
fn default_probe_binary() -> ConfigPath {
    ConfigPath::from("/usr/bin/printenv")
}

fn default_true() -> bool {
    true
}

/// A config load attempt: always yields a usable config.
///
/// The warning is reported to the caller rather than returned as an error,
/// because no config problem may stop a command from running.
#[derive(Debug)]
pub struct ConfigLoad {
    /// The parsed config, or the defaults when parsing failed.
    pub config: Config,
    /// Present when the file existed but could not be used.
    pub problem: Option<ConfigError>,
    /// Whether a file was actually read.
    pub loaded: bool,
}

/// The longest any single lookup may be allowed to take, whatever the config says.
///
/// A `timeout_ms` is the knob that says how long a backend gets. Without a
/// ceiling it is also the knob that says how long `keyless run` may hang: a
/// `"timeout_ms": 86400000` is a wedged terminal expressed as a number, and a
/// config is not a trusted input — it can be handed in with `--config` or
/// `KEYLESS_CONFIG` by whatever wrote the file.
///
/// Sixty seconds is far above every real backend measured here (a cold vendor
/// CLI, a TLS handshake and a token refresh together fit inside ten) and far
/// below the point where a person concludes the tool is broken.
pub const MAX_TIMEOUT_MS: u64 = 60_000;

/// A configured `timeout_ms` as a duration, clamped to [`MAX_TIMEOUT_MS`].
///
/// One function rather than a clamp at each of the five call sites: five copies
/// would eventually disagree, and the one that forgot the clamp would be the one
/// that hangs.
#[must_use]
pub const fn bounded_timeout(milliseconds: u64) -> std::time::Duration {
    let bounded = if milliseconds > MAX_TIMEOUT_MS {
        MAX_TIMEOUT_MS
    } else {
        milliseconds
    };
    std::time::Duration::from_millis(bounded)
}

/// The largest config file that will be read.
///
/// A config holds names, store kinds, paths and timeouts — a thousand declared
/// secrets fit in well under a hundred kilobytes. One mebibyte is therefore
/// generous by three orders of magnitude while still being a bound, and a bound
/// is what stops a regular file the size of a disk from being read into memory
/// before anyone notices there is no child process yet.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Read the config file, or say why it will not be read.
///
/// `Ok(None)` means the file is absent, which is not a problem.
///
/// # Why this is not `fs::read_to_string`
///
/// `read_to_string` has no bound in either dimension, and a path is not
/// necessarily a file. Both failures are **hangs rather than errors**, and both
/// were reachable through `KEYLESS_CONFIG`:
///
/// - A FIFO with no writer. `open` blocks until a writer appears, so the process
///   never reaches the read, never reaches the spawn, and shows nothing.
/// - A character device such as `/dev/zero`. It reads successfully and forever;
///   memory climbs until the kernel or the operator ends it.
///
/// Neither exits, so neither is a failure the never-block invariant could
/// classify. They simply never spawn the child.
///
/// The two guards below are ordered against a swap between them. `O_NONBLOCK`
/// comes first: it makes `open` on a writerless FIFO return immediately instead
/// of blocking, so the file type can be checked from the **descriptor** rather
/// than from a `stat` that a rename could invalidate before the `open`. Regular
/// files ignore the flag for reads, so it costs the ordinary path nothing.
fn read_config_file(path: &Path) -> Result<Option<String>, ConfigError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let metadata = file.metadata().map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;

    if !metadata.is_file() {
        return Err(ConfigError::Unusable {
            path: path.to_path_buf(),
            detail: "not a regular file, so reading it could never end".to_owned(),
        });
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Unusable {
            path: path.to_path_buf(),
            detail: format!(
                "{} bytes, over the {MAX_CONFIG_BYTES} byte cap",
                metadata.len()
            ),
        });
    }

    // `take` as well as the length check above: the length came from the
    // descriptor, but a file being appended to between the two would otherwise
    // grow past the cap while being read.
    let mut raw = String::new();
    file.take(MAX_CONFIG_BYTES)
        .read_to_string(&mut raw)
        .map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(Some(raw))
}

impl Config {
    /// Read `path`, falling back to defaults on any problem.
    ///
    /// A missing file is not a problem — it is the normal state before anyone
    /// has declared a name.
    #[must_use]
    pub fn load(path: &Path) -> ConfigLoad {
        let raw = match read_config_file(path) {
            Ok(Some(raw)) => raw,
            // Absent, which is the normal state before anyone declares a name.
            Ok(None) => {
                return ConfigLoad {
                    config: Config::default(),
                    problem: None,
                    loaded: false,
                };
            }
            Err(problem) => {
                return ConfigLoad {
                    config: Config::default(),
                    problem: Some(problem),
                    loaded: false,
                };
            }
        };

        match serde_json::from_str::<Config>(&raw) {
            Ok(config) => ConfigLoad {
                config,
                problem: None,
                loaded: true,
            },
            Err(error) => ConfigLoad {
                config: Config::default(),
                problem: Some(ConfigError::Parse {
                    path: path.to_path_buf(),
                    detail: error.to_string(),
                }),
                loaded: false,
            },
        }
    }

    /// The route for `name`, or an empty route when it is undeclared.
    #[must_use]
    pub fn route(&self, name: &str) -> SecretRoute {
        self.secrets.get(name).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::path::Path;

    #[test]
    fn a_missing_file_is_not_a_problem() {
        let load = Config::load(Path::new("/nonexistent/keyless/config.json"));
        assert!(load.problem.is_none());
        assert!(!load.loaded);
        assert!(load.config.secrets.is_empty());
        assert_eq!(load.config.stores.keychain.service, "keyless");
    }

    #[test]
    fn unknown_fields_are_ignored_rather_than_fatal() {
        let parsed: Config = serde_json::from_str(
            r#"{"stores":{"infisical":{"path":"/prod"}},"secrets":{"A":{}},"future":1}"#,
        )
        .expect("unknown keys must not fail the parse");
        assert!(parsed.secrets.contains_key("A"));
    }

    #[test]
    fn routes_default_when_a_name_is_undeclared() {
        let config = Config::default();
        let route = config.route("ANYTHING");
        assert!(route.store.is_none());
        assert!(route.account.is_none());
    }

    #[test]
    fn the_daemon_is_off_unless_asked_for() {
        let config = Config::default();
        assert!(!config.stores.daemon.enabled);
        assert_eq!(config.stores.daemon.timeout_ms, 3_000);
    }

    #[test]
    fn a_daemon_section_round_trips() {
        let parsed: Config = serde_json::from_str(
            r#"{"stores":{"daemon":{"enabled":true,"socket":"/tmp/d.sock","timeout_ms":750}}}"#,
        )
        .expect("valid config");
        assert!(parsed.stores.daemon.enabled);
        assert_eq!(
            parsed.stores.daemon.socket_path(),
            std::path::Path::new("/tmp/d.sock")
        );
        assert_eq!(parsed.stores.daemon.timeout().as_millis(), 750);
    }

    #[test]
    fn there_is_no_config_level_infisical_environment() {
        // The default that used to live here made every name a caller invented
        // resolve against one machine's idea of an environment. The field is
        // still parsed so an existing config can be told it is ignored, and it
        // is empty by default so nothing can fall back to it.
        assert!(Config::default().stores.infisical.env.is_none());

        let parsed: Config = serde_json::from_str(r#"{"stores":{"infisical":{"env":"prod"}}}"#)
            .expect("valid config");
        assert_eq!(
            parsed.stores.infisical.env.as_deref(),
            Some("prod"),
            "the stale key must survive the parse so it can be reported"
        );
        // The vendor's own default, and the only coordinate still defaulted.
        assert_eq!(parsed.stores.infisical.path, "/");
    }

    #[test]
    fn a_name_carries_its_own_environment() {
        let parsed: Config =
            serde_json::from_str(r#"{"secrets":{"DB":{"env":"staging","path":"/backend"}}}"#)
                .expect("valid config");
        let route = parsed.route("DB");
        assert_eq!(route.env.as_deref(), Some("staging"));
        assert_eq!(route.path.as_deref(), Some("/backend"));
    }

    #[test]
    fn a_store_side_key_is_a_variable_the_credential_answers_to() {
        // The whole of the fix, at the layer that holds both halves: the label
        // and the variable are written down side by side, and reconciling them
        // stops being somebody's job.
        let parsed: Config =
            serde_json::from_str(r#"{"secrets":{"LABEL":{"key":"THE_VARIABLE"}}}"#)
                .expect("valid config");
        assert_eq!(parsed.route("LABEL").aliases("LABEL"), ["THE_VARIABLE"]);
    }

    #[test]
    fn a_statement_outranks_the_evidence() {
        // `var` is somebody saying which variable they mean; `key` is a store
        // coordinate that usually happens to be one. A route carrying both has
        // already answered the question, so nothing is added to the answer.
        let parsed: Config =
            serde_json::from_str(r#"{"secrets":{"LABEL":{"key":"FROM_KEY","var":"FROM_VAR"}}}"#)
                .expect("valid config");
        assert_eq!(parsed.route("LABEL").aliases("LABEL"), ["FROM_VAR"]);
    }

    #[test]
    fn a_key_that_is_already_the_name_adds_nothing() {
        let parsed: Config =
            serde_json::from_str(r#"{"secrets":{"SAME":{"key":"SAME"}}}"#).expect("valid config");
        assert!(parsed.route("SAME").aliases("SAME").is_empty());
    }

    #[test]
    fn a_route_naming_no_variable_answers_to_nothing_else() {
        // Coordinates that name an ITEM — a keychain account, a Proton vault and
        // item — say nothing about which variable a program reads, and guessing
        // from them would inject a variable nobody named.
        let parsed: Config = serde_json::from_str(
            r#"{"secrets":{"WIFI":{"vault":"Personal","item":"Router","field":"password",
                                   "account":"acct","service":"svc","note":"n"}}}"#,
        )
        .expect("valid config");
        assert!(parsed.route("WIFI").aliases("WIFI").is_empty());
    }

    #[test]
    fn an_undeclared_name_answers_to_nothing_but_itself() {
        assert!(Config::default().route("ANY").aliases("ANY").is_empty());
    }

    #[test]
    fn a_declared_route_round_trips() {
        let parsed: Config =
            serde_json::from_str(r#"{"secrets":{"GH":{"account":"demo-token","service":"demo"}}}"#)
                .expect("valid config parses");
        let route = parsed.route("GH");
        assert_eq!(route.account.as_deref(), Some("demo-token"));
        assert_eq!(route.service.as_deref(), Some("demo"));
    }
}
