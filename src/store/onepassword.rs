//! 1Password, via `op run`, pinned to exactly one vault.
//!
//! # What this backend is for
//!
//! One vault, named once in the config, and nothing this store does can reach
//! another. That is the whole design: an agent given this backend gets the
//! items somebody deliberately put in that vault, and the rest of the account
//! stays where it is. Every coordinate this adapter builds starts
//! `op://<that vault>/`, a name whose own entry says a different vault is
//! refused before anything is spawned, and `items` will not list a vault it was
//! not pinned to. See [`crate::config::OnePasswordConfig::vault`].
//!
//! **Locally that is an allowlist, not a boundary.** The vendor CLI inherits
//! whatever login the calling user has, and a session that can run `keyless`
//! can run `op read` against every vault that login sees. The boundary is the
//! identity: a 1Password **service account** is minted with access to named
//! vaults and no others, and the vendor refuses it everything else. Handed to a
//! session it is a token in a shell; handed to [`crate::daemon`], it lives in a
//! file only the daemon's uid can read, and the socket carries names and values
//! but never the token. See [`ServiceAccount`] for that arrangement.
//!
//! # Status: `op` 2.39.0 on macOS, 2026-08-31
//!
//! Every claim below is marked. **Measured** means the real CLI was run and the
//! sentence is what it did. **Documented** means the vendor's own `--help` or
//! reference documentation, with no signed-in account to check it against —
//! the authenticated path has not been exercised, and the README's *Not built
//! yet* says so. The stubs in `tests/support` encode the documented shapes, and
//! a disagreement between a stub and the real CLI is a bug in the stub, never a
//! finding about this adapter.
//!
//! | Observation | Status | Consequence here |
//! |---|---|---|
//! | `op run` reads `op://` references out of its environment and hands the child the values | documented | the lookup is a `run` whose child is `printenv` |
//! | `op run` masks values in the child's output as `<concealed by 1Password>` unless `--no-masking` is passed | measured (the marker is in the binary; the flag is in `--help`) | `--no-masking` on every probe, and a concealed value is refused |
//! | `op run` with **no** reference in its environment runs the child without authenticating at all | measured | a health check cannot be built on `run`; it uses `vault get` |
//! | with more than one account configured and no sign-in, every authenticated verb fails with `multiple accounts found. Use the --account flag …`, exit 1 | measured | `account` is a config field and is passed as `--account=` |
//! | a bogus `OP_SERVICE_ACCOUNT_TOKEN` fails with `DecodeSACredentials`, exit 9 on `vault get` and exit 1 under `run` | measured | that wording is read as a refused login, never as a missing name |
//! | `op` finds its account list under `env -i` with only `HOME` and `PATH` | measured | the probe runs in a cleared environment |
//! | `op item list --vault … --format json` prints ids, titles and categories and no field content; archived items carry `"state": "ARCHIVED"` and appear only with `--include-archive` | documented | the listing is how a title becomes an id, and how an archived item is refused |
//! | `op item get … --format json` prints every field **including its value** | documented | `fields` parses it in memory, scrubs it on drop, and prints labels only |
//! | `op vault get <vault> --format json` prints the vault's id, name and item count | documented | the health check, which reads no item |
//! | the vendor writes errors as `[ERROR] <date> <time> <message>` on stderr | measured | the timestamp is stripped before a message is quoted |
//!
//! # The mechanism, and why it is the same one twice over
//!
//! `op read` and `op item get` print plaintext to stdout, so they are the
//! verbs the hook pack refuses and the verbs this adapter never spells. `op run
//! -- <cmd>` prints nothing: it resolves every `op://` reference in its
//! environment and execs the command with the values in place. So a lookup sets
//! ONE variable, [`PROBE_VAR`], to one reference and runs `printenv` under it.
//! The value goes into a pipe this process owns, into a [`Secret`] that
//! zeroizes on drop, and out again only into the real child's environment —
//! masked on the way back. That is the Infisical adapter's shape and the Proton
//! adapter's shape, and it is chosen here for the reasons written there rather
//! than repeated.
//!
//! # Addressing: titles in the config, ids resolved fresh
//!
//! The vendor accepts a title or an id in a reference, and refuses a title two
//! items share. This adapter does not hand it a title. It lists the vault first
//! — `op item list --vault <vault> --format json --include-archive`, memoised
//! for one run — and builds the reference from the **id** of the one live item
//! whose title (or id) matches exactly. Three things that buys, each stated:
//!
//! - **An absent title is an absence.** `Ok(None)`, so `doctor` says the item
//!   is not in the vault rather than quoting a vendor error that says the same
//!   thing less clearly — and a name nobody declared costs a listing, never a
//!   read.
//! - **An archived item never resolves.** The vendor still resolves a reference
//!   to one (documented), which would hand a child a value its owner put away.
//!   The rule is an allowlist on "no `state` at all", so a state this build has
//!   never heard of fails closed.
//! - **Two live items with one title are refused, never picked.** The error
//!   names both ids, and an id goes in `item` exactly as a title does.
//!
//! The listing is reused while it is younger than
//! [`crate::config::OnePasswordConfig::listing_ttl_ms`], for the reason the
//! Proton adapter gives: the listing IS the archive rule, and a listing kept
//! forever keeps resolving an item archived after it was taken.
//!
//! # The environment is cleared, and the reasons are inherited
//!
//! The probe runs with `env_clear()` and exactly [`FORWARDED_EXACT`] plus every
//! `OP_*` variable handed back in. Two adapters already paid for this lesson:
//! `printenv` cannot tell a variable the vendor injected from one this process
//! carried, and `op run` resolves every reference it finds in the whole
//! environment, so an unrelated `SOMETHING=op://…` in the caller's shell would
//! cost a read nobody asked for and fail the probe with a message about a
//! variable that has nothing to do with the name. Clearing closes both.
//!
//! Clearing is safe here in a way it was not for Proton: measured, `op`
//! locates its accounts with `HOME` alone, and it keeps its login in the
//! desktop app or in the system keyring rather than in a session store it
//! rewrites on every call.
//!
//! # What this adapter never touches
//!
//! No token file, no keyring item, no app-integration socket of its own. The
//! login belongs to `op`, is inherited by spawning it, and there is no config
//! field in which one would fit. A daemon has no login to inherit and is handed
//! a service account instead — read per lookup out of a mode-`0600` file on its
//! own side of the boundary, never held, and never written anywhere by this
//! crate. See [`ServiceAccount`].
//!
//! # No telemetry flag, because the CLI has none to switch off
//!
//! `op --help` lists no telemetry option and the binary carries no `telemetry`
//! string, so there is nothing here that corresponds to the Infisical
//! adapter's `--telemetry=false`. What the CLI does do is check for updates and
//! print a notice about one; that goes to stderr and is never read as a value.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::config::{Config, SecretRoute};
use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;
use crate::store::discover::{Discover, FieldKind, FieldSummary, ItemSummary};
use crate::store::exec::{self, CaptureError, capture, first_line, strip_one_newline};
use crate::store::proton::{bounded_listing_ttl, flag_value, resolve_executable, scrub};

/// This backend's id, as it appears in a `store` pin and in every message.
pub const STORE_ID: &str = "onepassword";

/// The scheme the vendor treats as a secret reference wherever it finds one.
pub const REFERENCE_SCHEME: &str = "op://";

/// What the vendor's masking substitutes for a value, lower-cased.
///
/// Measured: the literal `<concealed by 1Password>` is in the 2.39.0 binary.
/// The guard that uses it is a second line of defence behind `--no-masking`,
/// never the only one.
const CONCEALED_MARKER: &str = "concealed by 1password";

/// The variable the probe reads out of the child environment.
///
/// Fixed rather than derived from the secret's name, as in the Proton adapter:
/// the name is `keyless`'s, this is one probe's, and a fixed name that is never
/// forwarded means the value read back can only have come from the vendor.
pub const PROBE_VAR: &str = "KEYLESS_PROBE";

/// The variables forwarded into the cleared environment the vendor runs in.
///
/// The Infisical adapter's nine, which are the ordinary way a machine says
/// where home is, where binaries are and how to reach the network — plus
/// `XDG_CONFIG_HOME`, which the vendor documents as the parent of its config
/// directory on platforms that set it.
///
/// Short on purpose: nothing here is a name anybody stores a credential under,
/// and [`PROBE_VAR`] is deliberately not on it.
pub const FORWARDED_EXACT: [&str; 10] = [
    "HOME",
    "PATH",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "no_proxy",
    "XDG_CONFIG_HOME",
];

/// Every variable starting with this is forwarded too.
///
/// A service-account token, a Connect host and token, an `OP_SESSION_*` from a
/// plain `op signin`, and `OP_ACCOUNT` all arrive this way. Measured: these are
/// the sixteen `OP_*` names the 2.39.0 binary reads, and every one of them is a
/// login, a coordinate or a knob rather than a secret of the user's.
pub const FORWARDED_PREFIX: &str = "OP_";

/// The variable a service-account token travels in.
///
/// The identity that turns this store's vault allowlist into a boundary: a
/// service account is created with access to named vaults, and the vendor
/// refuses it everything else. It has no browser, no biometric and no keyring,
/// which is what makes it usable by a daemon.
pub const SERVICE_ACCOUNT_TOKEN: &str = "OP_SERVICE_ACCOUNT_TOKEN";

/// Whether a variable of this process is handed to the vendor CLI.
#[must_use]
fn is_forwarded(name: &str) -> bool {
    FORWARDED_EXACT.contains(&name) || name.starts_with(FORWARDED_PREFIX)
}

/// This process's forwarded variables, name and value.
fn forwarded_vars() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| is_forwarded(&name.to_string_lossy()))
        .collect()
}

/// Why nothing can be looked up until a vault is named.
const NO_VAULT: &str = "`stores.onepassword.vault` is not set, so this store does not know which vault to \
     read and will not guess one. Name the ONE vault this machine may read there — every \
     lookup, listing and health check is confined to it";

/// Where one name lives inside the pinned vault.
///
/// The vault is deliberately not a field: there is exactly one, it is the
/// store's, and an address that could carry its own would be an address that
/// could widen the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// The item's title, or its id. Matched exactly against the listing.
    pub item: String,
    /// The section the field sits in, for a custom field.
    pub section: Option<String>,
    /// The field whose value is the credential.
    pub field: String,
}

impl Address {
    /// The reference the vendor resolves, once the item's id is known.
    ///
    /// `op://<vault>/<id>/[<section>/]<field>`, in the vendor's documented
    /// form. The id rather than the title, so a lookup and `fields` agree on
    /// which item they mean even when two share a title.
    #[must_use]
    fn reference(&self, vault: &str, id: &str) -> String {
        match &self.section {
            Some(section) => format!("{REFERENCE_SCHEME}{vault}/{id}/{section}/{}", self.field),
            None => format!("{REFERENCE_SCHEME}{vault}/{id}/{}", self.field),
        }
    }
}

/// Every declared name's coordinates, resolved against the store's defaults.
///
/// Shared by the session's constructor and the daemon's, so the two cannot
/// disagree about where a name points — and built once, so every refusal below
/// is decided before anything is spawned.
#[derive(Debug, Clone, Default)]
pub struct Routing {
    vault: Option<String>,
    default_field: Option<String>,
    routes: BTreeMap<String, Result<Address, String>>,
}

impl Routing {
    /// Read the session config.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let settings = &config.stores.onepassword;
        Self::new(
            &config.secrets,
            settings.vault.clone(),
            settings.field.clone(),
        )
    }

    /// Build from explicit parts, for a caller whose config is not a session's.
    #[must_use]
    pub fn new(
        secrets: &BTreeMap<String, SecretRoute>,
        vault: Option<String>,
        default_field: Option<String>,
    ) -> Self {
        let routes = secrets
            .iter()
            .map(|(name, route)| {
                (
                    name.clone(),
                    read_route(name, route, vault.as_deref(), default_field.as_deref()),
                )
            })
            .collect();
        Routing {
            vault,
            default_field,
            routes,
        }
    }

    /// The pinned vault, or the sentence saying there is none.
    ///
    /// # Errors
    ///
    /// [`NO_VAULT`], which names the config key and nothing else.
    pub fn vault(&self) -> Result<&str, String> {
        self.vault.as_deref().ok_or_else(|| NO_VAULT.to_owned())
    }

    /// Where `name` points, or why it points nowhere.
    ///
    /// An undeclared name is addressed by its own name as the title, in the
    /// pinned vault, at the store-wide field — and with no store-wide field it
    /// is refused, because a field is the one coordinate that must not be
    /// guessed.
    ///
    /// # Errors
    ///
    /// The sentence an operator needs, naming the field to add.
    pub fn address(&self, name: &str) -> Result<Address, String> {
        match self.routes.get(name) {
            Some(known) => known.clone(),
            None => read_route(
                name,
                &SecretRoute::default(),
                self.vault.as_deref(),
                self.default_field.as_deref(),
            ),
        }
    }
}

/// One config entry as an address, or precisely why it is not one.
///
/// Every refusal here spawns nothing and reads nothing.
fn read_route(
    name: &str,
    route: &SecretRoute,
    vault: Option<&str>,
    default_field: Option<&str>,
) -> Result<Address, String> {
    if route.reference.is_some() {
        return Err(
            "`reference` is the Proton form and this store does not read it: a 1Password item \
             is addressed by \"item\" — its title, or its id when two items share a title — \
             inside the vault `stores.onepassword.vault` names"
                .to_owned(),
        );
    }

    // The scoping rule, at the one place a config entry could reach around
    // it. A name may restate the pinned vault; it may not name another.
    if let (Some(pinned), Some(declared)) = (vault, route.vault.as_deref())
        && declared != pinned
    {
        return Err(format!(
            "`{name}` declares vault `{declared}`, and this store is pinned to `{pinned}`. A \
             name cannot widen the vault a store reads; drop its \"vault\", or pin the store \
             to the vault you meant"
        ));
    }

    let item = route
        .item
        .clone()
        .filter(|item| !item.is_empty())
        .unwrap_or_else(|| name.to_owned());

    let Some(field) = route
        .field
        .as_deref()
        .or(default_field)
        .filter(|field| !field.is_empty())
    else {
        return Err(format!(
            "`{name}` names no field. A 1Password item has several — `password` on a Login or \
             Password item, `credential` on an API Credential — and guessing one resolves the \
             name to the wrong field of the right item. Put \"field\" on \"{name}\" under \
             `secrets`, or set `stores.onepassword.field` when every item in the vault has \
             the same shape; `{} fields onepassword --item <TITLE>` lists the names",
            crate::NAME
        ));
    };

    // A `/` or `?` would move a boundary inside the reference this builds —
    // into a section, or into the vendor's query syntax — so the CLI would be
    // handed a different address than the one written down.
    for (label, value) in [
        ("field", Some(field)),
        ("section", route.section.as_deref()),
    ] {
        if let Some(value) = value
            && (value.contains('/') || value.contains('?'))
        {
            return Err(format!(
                "`{label}` may not contain `/` or `?`: `{value}` would address something else \
                 once it is written into an op:// reference. A field inside a section is \
                 declared with \"section\""
            ));
        }
    }

    Ok(Address {
        item,
        section: route.section.clone().filter(|section| !section.is_empty()),
        field: field.to_owned(),
    })
}

/// One record of `op item list --format json`.
///
/// Only the keys this adapter acts on are named, so a key the vendor adds
/// later cannot fail the parse and content this adapter did not ask for is
/// never held. Every one of them is a coordinate.
///
/// **Documented, not measured** — see the module header. `state` is present
/// only on an archived item (`"ARCHIVED"`), which is why it is optional and
/// why [`ItemRecord::is_active`] is an allowlist on its absence.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ItemRecord {
    pub(crate) id: String,
    pub(crate) title: String,
    /// The vendor's category word. `Option` so a `null` cannot fail the parse.
    #[serde(default)]
    pub(crate) category: Option<String>,
    /// Present only on an archived item. `Option` for the same reason, and
    /// because absent and `null` must both read as live.
    #[serde(default)]
    pub(crate) state: Option<String>,
}

impl ItemRecord {
    /// Whether this item is live, as an allowlist rather than a denylist.
    ///
    /// An item with any state at all — `ARCHIVED`, or a word a later CLI adds
    /// — is not resolvable. Archived is the documented case: the vendor still
    /// resolves a reference to one, and this listing is the only thing standing
    /// between a put-away credential and a child's environment.
    pub(crate) fn is_active(&self) -> bool {
        self.state.as_deref().is_none_or(str::is_empty)
    }

    /// The word `items` prints for this item's state.
    fn state_word(&self) -> String {
        match self.state.as_deref() {
            Some(state) if !state.is_empty() => state.to_owned(),
            _ => "Active".to_owned(),
        }
    }
}

/// Which item a config entry's `item` named, in the four shapes a caller has
/// to be told apart.
pub(crate) enum Matched<'a> {
    /// Exactly one live item carries the title or id.
    One(&'a ItemRecord),
    /// Nothing does.
    None,
    /// Only archived items do. Never silently promoted to `One`.
    OnlyArchived,
    /// Several live items do. Refused, never ranked.
    Several(Vec<&'a ItemRecord>),
}

/// Find the one live item `wanted` names, by title or by id, or say which of
/// the other three it is.
///
/// Exact and case-sensitive, so a looser match cannot be a second way to
/// reach an item nobody named. Shared by the resolver and by `fields`, so the
/// two cannot disagree about which item a title means.
pub(crate) fn match_item<'a>(items: &'a [ItemRecord], wanted: &str) -> Matched<'a> {
    let (live, put_away): (Vec<&ItemRecord>, Vec<&ItemRecord>) = items
        .iter()
        .filter(|record| record.title == wanted || record.id == wanted)
        .partition(|record| record.is_active());

    match live.as_slice() {
        [only] => Matched::One(only),
        [] if put_away.is_empty() => Matched::None,
        [] => Matched::OnlyArchived,
        _ => Matched::Several(live),
    }
}

/// One vault's items, and when they were fetched.
struct Listed {
    items: Arc<Vec<ItemRecord>>,
    at: Instant,
}

/// The vendor's rendering of ONE item, which **contains that item's values**.
///
/// The same radioactive shape as the Proton adapter's, for the same reason:
/// the only vendor verb that reveals an item's field labels is `item get`, and
/// `--format json` prints every field's value beside its label. So the values
/// enter this process, and everything from here on is about what happens
/// before the first byte of output. No `Display`, a `Debug` that redacts, a
/// `Drop` that zeroizes every string in the tree, and one accessor that reads
/// labels and types and never a value.
struct ItemView(serde_json::Value);

impl ItemView {
    /// Parse the vendor's JSON without ever quoting it.
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .map(ItemView)
            .map_err(|error| {
                format!(
                    "`item get` did not return JSON this build understands (at line {}, \
                     column {})",
                    error.line(),
                    error.column()
                )
            })
    }

    /// Every labelled field on the item: its label, whether it is one of the
    /// category's own, the vendor's type word, and where it sits.
    ///
    /// **Documented shape:** `fields[]`, each with `label`, `type`, an optional
    /// `purpose` on the category's built-in fields, an optional `section`
    /// object with its own `label`, and `value`. Only the first four are read.
    /// A field with no label is skipped: there is nothing a config entry
    /// could name it by.
    fn field_names(&self) -> Vec<FieldSummary> {
        let Some(fields) = self.0.get("fields").and_then(serde_json::Value::as_array) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for (index, field) in fields.iter().enumerate() {
            let Some(label) = field.get("label").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if label.is_empty() {
                continue;
            }
            let section = field
                .get("section")
                .and_then(|section| section.get("label"))
                .and_then(serde_json::Value::as_str)
                .filter(|label| !label.is_empty());
            found.push(FieldSummary {
                name: label.to_owned(),
                kind: if field.get("purpose").is_some() {
                    FieldKind::Builtin
                } else {
                    FieldKind::Custom
                },
                value_type: field
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                // The section is a coordinate a config entry has to state, so
                // it is printed where somebody writing one will see it.
                path: match section {
                    Some(section) => format!("fields[{index}] in section \"{section}\""),
                    None => format!("fields[{index}]"),
                },
            });
        }
        found
    }
}

impl fmt::Debug for ItemView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ItemView(<redacted>)")
    }
}

impl Drop for ItemView {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

/// The vendor's own login, for a caller that carries none.
///
/// A session spawns `op` and inherits its login — the desktop app's
/// integration, or an `OP_SESSION_*` a plain `op signin` exported. A daemon
/// has neither: no app, no terminal, no keyring it unlocked. It is handed a
/// **service account** instead, which the vendor mints with access to named
/// vaults only and which `op` reads from [`SERVICE_ACCOUNT_TOKEN`] in its
/// environment.
///
/// Where that token must NOT come from is written at length beside the
/// Infisical adapter's [`crate::store::infisical::VendorCredentials`] and is the
/// same here: not the world-readable launchd plist, not `keylessd.json`. It
/// comes from a [`Store`] the daemon reads under its own uid — a mode-`0600`
/// file — and this type names the entry and never holds the value. Read per
/// lookup, dropped with the [`Secret`] that carried it, so a rotated token
/// takes effect without a restart and nothing keeps a plaintext copy between
/// calls.
///
/// Unlike an Infisical access token, a service-account token does not expire
/// unless it was minted with an expiry, and there is no exchange to perform:
/// it is handed to the vendor as it is.
pub struct ServiceAccount {
    source: Box<dyn Store>,
    names: BTreeMap<String, String>,
}

impl ServiceAccount {
    /// Read the values for `names` — vendor variable to entry name — out of
    /// `source`.
    #[must_use]
    pub fn new(source: Box<dyn Store>, names: BTreeMap<String, String>) -> Self {
        ServiceAccount { source, names }
    }

    /// The named variables this adapter will not set.
    ///
    /// Only `OP_*` is accepted, for the reason the Infisical adapter gives:
    /// without that bound the field is a "set any variable on a child process,
    /// as the daemon's uid" primitive, and `PATH` would choose which binary the
    /// vendor is.
    #[must_use]
    pub fn refused(names: &BTreeMap<String, String>) -> Vec<String> {
        names
            .keys()
            .filter(|variable| !variable.starts_with(FORWARDED_PREFIX))
            .cloned()
            .collect()
    }

    /// Every named value, or the sentence saying which one could not be read.
    fn resolve(&self) -> Result<Vec<(String, Secret)>, StoreError> {
        if let Some(variable) = Self::refused(&self.names).first() {
            return Err(StoreError::Misconfigured {
                store: STORE_ID.to_owned(),
                detail: format!(
                    "`{variable}` is named as a 1Password credential and is not an \
                     `{FORWARDED_PREFIX}*` variable. Only the vendor's own credential \
                     variables may be set this way; anything else would choose which \
                     binary runs or which login it finds"
                ),
            });
        }

        let mut resolved = Vec::with_capacity(self.names.len());
        for (variable, name) in &self.names {
            match self.source.resolve(name) {
                Ok(Some(secret)) => resolved.push((variable.clone(), secret)),
                Ok(None) => {
                    return Err(StoreError::Misconfigured {
                        store: STORE_ID.to_owned(),
                        detail: format!(
                            "the 1Password credential `{variable}` is declared to live in \
                             `{name}` of the `{}` store, which holds no such entry",
                            self.source.id()
                        ),
                    });
                }
                Err(error) => {
                    return Err(StoreError::Misconfigured {
                        store: STORE_ID.to_owned(),
                        detail: format!(
                            "the 1Password credential `{variable}` could not be read: {error}"
                        ),
                    });
                }
            }
        }
        Ok(resolved)
    }
}

/// The vendor's message, without the log prefix it wraps every error in.
///
/// Measured: `[ERROR] 2026/08/31 15:51:38 multiple accounts found. …`. The
/// prefix is the vendor's log format, not the diagnosis, and quoting a
/// wall-clock instant into a message somebody pastes into a bug report is
/// noise at best. Built from stderr only, as everywhere in this crate.
fn vendor_said(stderr: &[u8]) -> String {
    let line = first_line(stderr);
    let Some(rest) = line.strip_prefix("[ERROR] ") else {
        return line;
    };
    // `<date> <time> <message>`: two space-separated words, then the rest.
    let mut words = rest.splitn(3, ' ');
    match (words.next(), words.next(), words.next()) {
        (Some(date), Some(time), Some(message))
            if date.contains('/') && time.contains(':') && !message.is_empty() =>
        {
            message.to_owned()
        }
        _ => rest.to_owned(),
    }
}

/// Whether a vendor failure was about the LOGIN rather than about a name.
///
/// The measured spellings, and the documented ones beside them: no sign-in,
/// no account chosen, a service-account token the vendor could not decode, and
/// an HTTP refusal. A message that matches none of these is quoted as it is —
/// less specific, never wrong.
#[must_use]
fn refused_login(message: &str) -> bool {
    [
        "not signed in",
        "multiple accounts found",
        "DecodeSACredentials",
        "requires authentication",
        "Unauthorized",
        "(401)",
        "401:",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

/// Whether the bytes read back are the vendor's concealment placeholder.
fn looks_concealed(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes)
        .to_ascii_lowercase()
        .contains(CONCEALED_MARKER)
}

/// Whether the bytes read back are the reference itself, unresolved.
///
/// `op run` with nothing to resolve runs the child untouched (measured), so a
/// probe whose reference the vendor did not recognise as one would read the
/// literal `op://…` back out of `printenv` and, without this, inject it as the
/// credential.
fn looks_unresolved(bytes: &[u8]) -> bool {
    bytes.starts_with(REFERENCE_SCHEME.as_bytes())
}

/// Reads one 1Password item at a time through `op run`.
pub struct OnePasswordStore {
    binary: PathBuf,
    probe_binary: PathBuf,
    routing: Routing,
    account: Option<String>,
    config_dir: Option<PathBuf>,
    timeout: Duration,
    listing_ttl: Duration,
    credentials: Option<ServiceAccount>,
    /// The pinned vault's items, until they expire. In memory and nowhere
    /// else. Held across the vendor spawn, so several names resolving at once
    /// cost one listing.
    listing: Mutex<Option<Listed>>,
}

impl OnePasswordStore {
    /// Construct from a parsed session config.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let settings = &config.stores.onepassword;
        OnePasswordStore::new(
            settings.binary.to_path_buf(),
            settings.probe_binary.to_path_buf(),
            Routing::from_config(config),
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
    }

    /// Construct from explicit parts, for the daemon.
    #[must_use]
    pub fn new(binary: PathBuf, probe_binary: PathBuf, routing: Routing) -> Self {
        OnePasswordStore {
            binary,
            probe_binary,
            routing,
            account: None,
            config_dir: None,
            timeout: crate::config::bounded_timeout(crate::config::DEFAULT_TIMEOUT_MS),
            listing_ttl: bounded_listing_ttl(crate::config::default_listing_ttl_ms()),
            credentials: None,
            listing: Mutex::new(None),
        }
    }

    /// Bound one vendor call, in milliseconds. Clamped.
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout = crate::config::bounded_timeout(timeout_ms);
        self
    }

    /// Bound how long a listing is reused, in milliseconds. Clamped.
    #[must_use]
    pub fn with_listing_ttl(mut self, ttl_ms: u64) -> Self {
        self.listing_ttl = bounded_listing_ttl(ttl_ms);
        self
    }

    /// Name the account, as `--account=`. `None` leaves the CLI's own choice.
    #[must_use]
    pub fn for_account(mut self, account: Option<String>) -> Self {
        self.account = account;
        self
    }

    /// Point the CLI at a configuration directory of its own, as `--config=`.
    #[must_use]
    pub fn in_config_dir(mut self, config_dir: Option<PathBuf>) -> Self {
        self.config_dir = config_dir;
        self
    }

    /// Supply the vendor's own login, for a process that carries none.
    #[must_use]
    pub fn with_vendor_credentials(mut self, credentials: Option<ServiceAccount>) -> Self {
        self.credentials = credentials;
        self
    }

    /// The vendor's login, resolved now, or nothing when none was configured.
    fn vendor_credentials(&self) -> Result<Vec<(String, Secret)>, StoreError> {
        match &self.credentials {
            Some(credentials) => credentials.resolve(),
            None => Ok(Vec::new()),
        }
    }

    /// The invocation every verb here starts from.
    ///
    /// The environment is cleared down to [`FORWARDED_EXACT`] and `OP_*`, with
    /// a configured credential set AFTER the forwarded set so the config wins
    /// over whatever this process happened to carry. Then the two global
    /// flags, each as one `--flag=value` argument — see
    /// [`crate::store::proton::flag_value`] for why the `=` form and no other.
    fn base_command(&self, credentials: &[(String, Secret)]) -> Command {
        let mut command = Command::new(&self.binary);
        command.env_clear();
        command.envs(forwarded_vars());
        for (variable, secret) in credentials {
            command.env(variable, secret.expose());
        }
        if let Some(account) = &self.account {
            flag_value(&mut command, "--account", account);
        }
        if let Some(dir) = &self.config_dir {
            flag_value(&mut command, "--config", dir);
        }
        command
    }

    /// Build one `op run --no-masking -- printenv KEYLESS_PROBE` invocation.
    ///
    /// The reference travels in the ENVIRONMENT, never in argv: an argument is
    /// readable from the process table, and while a reference is a coordinate
    /// rather than a value, the vendor's own documentation puts it in the
    /// environment and this adapter has no reason to be looser.
    fn probe_command(&self, reference: &str, credentials: &[(String, Secret)]) -> Command {
        let mut command = self.base_command(credentials);
        command.env(PROBE_VAR, reference);
        command.arg("run");
        // Required: the vendor's masking would otherwise replace the value in
        // the probe's own output, and this adapter would inject the mask.
        command.arg("--no-masking");
        command.arg("--");
        command.arg(&self.probe_binary);
        command.arg(PROBE_VAR);
        command
    }

    /// Build one `op item list --vault=… --format=json --include-archive`.
    ///
    /// No value can come back from this verb: it prints ids, titles,
    /// categories and timestamps. `--include-archive` so an archived item is
    /// VISIBLE, with its state, to somebody hunting a name that stopped
    /// resolving — the resolver refuses it either way.
    fn list_command(&self, vault: &str, credentials: &[(String, Secret)]) -> Command {
        let mut command = self.base_command(credentials);
        command.arg("item");
        command.arg("list");
        flag_value(&mut command, "--vault", vault);
        command.arg("--format=json");
        command.arg("--include-archive");
        command
    }

    /// Build one `op vault get <vault> --format=json`, the health check.
    fn vault_command(&self, vault: &str, credentials: &[(String, Secret)]) -> Command {
        let mut command = self.base_command(credentials);
        command.arg("vault");
        command.arg("get");
        command.arg(vault);
        command.arg("--format=json");
        command
    }

    /// Build one `op item get <id> --vault=… --format=json`, for `fields`.
    ///
    /// Addressed by id, out of a listing this adapter just read, so `fields`
    /// and `run` inspect the same item even when two share a title. Its stdout
    /// carries the item's values and is never quoted; see [`ItemView`].
    fn view_command(&self, vault: &str, id: &str, credentials: &[(String, Secret)]) -> Command {
        let mut command = self.base_command(credentials);
        command.arg("item");
        command.arg("get");
        command.arg(id);
        flag_value(&mut command, "--vault", vault);
        command.arg("--format=json");
        command
    }

    /// The pinned vault's items, from the cache or from the CLI.
    ///
    /// One slot, because there is one vault. The lock is held across the spawn
    /// on purpose: it is what makes "one listing per run" true rather than
    /// probable when a run resolves its names concurrently. A failed fetch
    /// leaves the slot empty so a later name retries.
    fn cached_items(&self, vault: &str) -> Result<Arc<Vec<ItemRecord>>, StoreError> {
        let mut slot = self.listing.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(listed) = slot.as_ref()
            && listed.at.elapsed() < self.listing_ttl
        {
            return Ok(Arc::clone(&listed.items));
        }
        let items = Arc::new(self.fetch_items(vault)?);
        *slot = Some(Listed {
            items: Arc::clone(&items),
            at: Instant::now(),
        });
        Ok(items)
    }

    /// One `item list` round trip, parsed.
    fn fetch_items(&self, vault: &str) -> Result<Vec<ItemRecord>, StoreError> {
        let captured = capture(
            self.list_command(vault, &self.vendor_credentials()?),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            let said = vendor_said(&captured.stderr);
            return Err(self.backend(format!(
                "cannot list vault `{vault}`: {}",
                self.explained(&said)
            )));
        }

        serde_json::from_slice::<Vec<ItemRecord>>(&captured.stdout).map_err(|error| {
            // Position only: a listing carries no values, but the rule that a
            // message is never built from stdout has no exceptions.
            self.backend(format!(
                "`item list` did not return JSON this build understands (at line {}, column {})",
                error.line(),
                error.column()
            ))
        })
    }

    /// The one live item `address` names, as a reference the vendor resolves,
    /// or the reason there is none.
    ///
    /// `Ok(None)` is an absence: no item in the vault carries the title or id,
    /// live or archived.
    fn reference_for(
        &self,
        vault: &str,
        name: &str,
        address: &Address,
    ) -> Result<Option<String>, StoreError> {
        let items = self.cached_items(vault)?;
        match match_item(&items, &address.item) {
            Matched::One(record) => Ok(Some(address.reference(vault, &record.id))),
            Matched::None => Ok(None),
            Matched::OnlyArchived => Err(self.backend(format!(
                "the only item titled `{}` in vault `{vault}` is archived, so `{name}` will not \
                 resolve against it; restore the item, or point the name at another",
                address.item
            ))),
            Matched::Several(several) => Err(self.backend(format!(
                "{} live items in vault `{vault}` are titled `{}`, so `{name}` names no one \
                 item — put one of these ids in \"item\" instead: {}",
                several.len(),
                address.item,
                several
                    .iter()
                    .map(|record| record.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// A vendor message with the remedy attached, when the message is about
    /// the login.
    fn explained(&self, said: &str) -> String {
        if !refused_login(said) {
            return said.to_owned();
        }
        let remedy = if self.credentials.is_some() {
            format!(
                "The daemon's service account was refused. Rewrite `{SERVICE_ACCOUNT_TOKEN}` \
                 with `{} credential`, or check at the vendor that the service account still \
                 exists and can read this vault",
                crate::DAEMON_NAME
            )
        } else {
            "Sign in with `op signin`, and name the account in `stores.onepassword.account` \
             when this machine has more than one"
                .to_owned()
        };
        format!(
            "1Password refused the login, which is not a missing name. {remedy}. The vendor said: {said}"
        )
    }

    fn unavailable(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Unavailable {
            store: STORE_ID.to_owned(),
            detail: detail.into(),
        }
    }

    fn backend(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Backend {
            store: STORE_ID.to_owned(),
            detail: detail.into(),
        }
    }

    fn misconfigured(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Misconfigured {
            store: STORE_ID.to_owned(),
            detail: detail.into(),
        }
    }

    fn unreachable(&self, error: &CaptureError) -> StoreError {
        exec::unavailable(STORE_ID, &self.binary, error)
    }

    /// The pinned vault, or the refusal that spawns nothing.
    fn vault(&self) -> Result<&str, StoreError> {
        self.routing
            .vault()
            .map_err(|detail| self.misconfigured(detail))
    }

    /// `vault`, when it is the pinned one or unstated.
    ///
    /// The listing verbs take a `--vault` for the backends that have several.
    /// This one has one, and naming another is refused rather than honoured:
    /// enumerating a vault the store was pinned away from is the scoping being
    /// bypassed, one verb over.
    fn only_the_pinned_vault(&self, vault: Option<&str>) -> Result<&str, StoreError> {
        let pinned = self.vault()?;
        match vault {
            Some(other) if other != pinned => Err(self.misconfigured(format!(
                "this store is pinned to vault `{pinned}` and will not list `{other}`. Drop \
                 `--vault`, or change `stores.onepassword.vault` if that is the vault you meant"
            ))),
            _ => Ok(pinned),
        }
    }
}

impl Store for OnePasswordStore {
    fn id(&self) -> &str {
        STORE_ID
    }

    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        // Both refusals spawn nothing: no vault is a store that cannot look
        // anything up, and a bad entry is one line of the config file.
        let vault = self.vault()?;
        let address = self
            .routing
            .address(name)
            .map_err(|detail| self.misconfigured(detail))?;

        let Some(reference) = self.reference_for(vault, name, &address)? else {
            return Ok(None);
        };

        let mut captured = capture(
            self.probe_command(&reference, &self.vendor_environment()?),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            // stderr only. The vendor's failures leave stdout empty and the
            // rule stands regardless.
            let said = vendor_said(&captured.stderr);
            return Err(self.backend(self.explained(&said)));
        }

        let mut bytes = std::mem::take(&mut captured.stdout);
        strip_one_newline(&mut bytes);

        if bytes.is_empty() {
            return Err(self.backend(format!(
                "`{}` of `{}` in vault `{vault}` is set but empty",
                address.field, address.item
            )));
        }
        if looks_unresolved(&bytes) {
            return Err(self.backend(format!(
                "the vendor ran the probe without resolving the reference for `{}`, so what \
                 came back is the reference itself and not a value; check that `op run` \
                 still reads references out of its environment",
                address.item
            )));
        }
        if looks_concealed(&bytes) {
            return Err(self.backend(
                "the value came back concealed; `--no-masking` was not honoured".to_owned(),
            ));
        }

        Secret::from_bytes(bytes)
            .map(Some)
            .ok_or_else(|| self.backend(format!("`{}` is not valid UTF-8", address.field)))
    }

    /// Local preconditions, then one round trip that proves the login can see
    /// the pinned vault.
    ///
    /// `vault get` rather than `run`, and the reason is measured: `op run`
    /// with nothing to resolve runs its child without authenticating, so a
    /// health check built on it would print green over a dead login. `vault
    /// get` authenticates, names the vault, and reads no item — and a vault the
    /// identity cannot see is exactly the failure a scoped service account
    /// produces when it was minted for the wrong vault.
    fn health(&self) -> Result<(), StoreError> {
        let vault = self.vault()?;

        if resolve_executable(&self.binary).is_none() {
            return Err(self.unavailable(format!(
                "`{}` is not on PATH or is not executable",
                self.binary.display()
            )));
        }

        let captured = capture(
            self.vault_command(vault, &self.vendor_environment()?),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if captured.status.success() {
            return Ok(());
        }
        let said = vendor_said(&captured.stderr);
        Err(self.unavailable(format!(
            "vault `{vault}` cannot be read: {}",
            self.explained(&said)
        )))
    }
}

impl OnePasswordStore {
    /// What the vendor's child is given in order to be authenticated: the
    /// configured credential, verbatim. There is no exchange to perform.
    fn vendor_environment(&self) -> Result<Vec<(String, Secret)>, StoreError> {
        self.vendor_credentials()
    }
}

impl Discover for OnePasswordStore {
    fn id(&self) -> &str {
        STORE_ID
    }

    fn items(&self, vault: Option<&str>) -> Result<Vec<ItemSummary>, StoreError> {
        let vault = self.only_the_pinned_vault(vault)?;
        let items = self.cached_items(vault)?;
        Ok(items
            .iter()
            .map(|record| ItemSummary {
                vault: vault.to_owned(),
                title: record.title.clone(),
                state: record.state_word(),
                kind: match record.category.as_deref() {
                    Some(category) if !category.is_empty() => category.to_ascii_lowercase(),
                    _ => "unknown".to_owned(),
                },
            })
            .collect())
    }

    fn fields(&self, vault: Option<&str>, item: &str) -> Result<Vec<FieldSummary>, StoreError> {
        let vault = self.only_the_pinned_vault(vault)?;
        let items = self.cached_items(vault)?;
        let record = match match_item(&items, item) {
            Matched::One(only) => only,
            Matched::None => {
                return Err(self.backend(format!(
                    "vault `{vault}` holds no item titled `{item}`; `{} items onepassword` \
                     lists the titles it does hold",
                    crate::NAME
                )));
            }
            Matched::OnlyArchived => {
                return Err(self.backend(format!(
                    "the only item titled `{item}` in vault `{vault}` is archived, so no \
                     config entry can resolve against it; restore it first"
                )));
            }
            Matched::Several(several) => {
                return Err(self.backend(format!(
                    "{} live items in vault `{vault}` are titled `{item}`, so this names no \
                     one item — candidates: {}",
                    several.len(),
                    several
                        .iter()
                        .map(|record| record.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        };

        let captured = capture(
            self.view_command(vault, &record.id, &self.vendor_environment()?),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            let said = vendor_said(&captured.stderr);
            return Err(self.backend(format!(
                "cannot inspect `{item}`: {}",
                self.explained(&said)
            )));
        }

        // From here to the end of this function the item's values are in this
        // process. `captured` scrubs its stdout on drop, `view` scrubs the
        // parsed tree on drop, and what outlives both is a list of labels.
        let view = ItemView::parse(&captured.stdout).map_err(|detail| self.backend(detail))?;
        let names = view.field_names();
        if names.is_empty() {
            return Err(self.backend(format!(
                "`{item}` reported no labelled fields; its shape may have changed"
            )));
        }
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FORWARDED_EXACT, ItemRecord, ItemView, Matched, OnePasswordStore, PROBE_VAR,
        REFERENCE_SCHEME, Routing, ServiceAccount, is_forwarded, looks_concealed, looks_unresolved,
        match_item, refused_login, vendor_said,
    };
    use crate::config::Config;
    use crate::store::Store;
    use crate::store::discover::{Discover, FieldKind};
    use std::collections::BTreeMap;
    use std::ffi::OsStr;

    fn config_from(json: &str) -> Config {
        serde_json::from_str(json).expect("valid config")
    }

    fn store_from(json: &str) -> OnePasswordStore {
        OnePasswordStore::from_config(&config_from(json))
    }

    /// A store pinned to a vault, with a store-wide field, and a binary that
    /// does not exist — so a lookup that reaches for the vendor is visible as
    /// `unavailable` rather than as anything it did.
    fn pinned(secrets: &str) -> OnePasswordStore {
        store_from(&format!(
            r#"{{"stores":{{"onepassword":{{"enabled":true,"vault":"company","field":"password",
                              "binary":"/nonexistent/keyless-test/op"}}}},
                "secrets":{secrets}}}"#
        ))
    }

    /// The rendered argv of a command.
    fn argv(command: &std::process::Command) -> Vec<String> {
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .map(std::borrow::Cow::into_owned)
            .collect()
    }

    // -----------------------------------------------------------------------
    // The vault: one, named once, never guessed and never widened.
    // -----------------------------------------------------------------------

    #[test]
    fn a_store_with_no_vault_looks_nothing_up_and_says_which_key_to_set() {
        let store = store_from(
            r#"{"stores":{"onepassword":{"enabled":true,"field":"password",
                                         "binary":"/nonexistent/keyless-test/op"}},
                "secrets":{"DECOY":{}}}"#,
        );
        let said = store
            .resolve("DECOY")
            .expect_err("no vault means no lookup")
            .to_string();
        // `was not asked` is the Misconfigured wording: nothing was spawned.
        // A store that reached for the absent binary would say `unavailable`.
        assert!(said.contains("was not asked"), "{said}");
        assert!(said.contains("stores.onepassword.vault"), "{said}");
        assert!(store.health().is_err());
        assert!(Discover::items(&store, None).is_err());
    }

    #[test]
    fn a_name_that_declares_another_vault_is_refused_before_anything_is_spawned() {
        // The scoping rule at the one place a config entry could reach around
        // it: a per-name `vault` must not widen the store.
        let store = pinned(r#"{"ELSEWHERE":{"vault":"personal","item":"Router"}}"#);
        let said = store
            .resolve("ELSEWHERE")
            .expect_err("another vault is not this store's")
            .to_string();
        assert!(said.contains("was not asked"), "{said}");
        assert!(said.contains("pinned to `company`"), "{said}");
        assert!(said.contains("personal"), "{said}");
    }

    #[test]
    fn a_name_that_restates_the_pinned_vault_is_an_ordinary_name() {
        let store = pinned(r#"{"SAME":{"vault":"company","item":"Router"}}"#);
        let address = store.routing.address("SAME").expect("agrees with the pin");
        assert_eq!(address.item, "Router");
        assert_eq!(address.field, "password");
    }

    #[test]
    fn a_listing_refuses_any_vault_but_the_pinned_one() {
        // Enumerating a vault the store was pinned away from is the scoping
        // being bypassed, one verb over.
        let store = pinned("{}");
        let said = Discover::items(&store, Some("personal"))
            .expect_err("another vault must not be listed")
            .to_string();
        assert!(said.contains("pinned to vault `company`"), "{said}");
        assert!(said.contains("personal"), "{said}");
        // The negative control: the pinned vault, and no vault, both reach for
        // the vendor — which is absent, so they say so.
        for vault in [Some("company"), None] {
            let said = Discover::items(&store, vault)
                .expect_err("the binary does not exist")
                .to_string();
            assert!(said.contains("unavailable"), "{said}");
        }
    }

    // -----------------------------------------------------------------------
    // The field: never guessed by keyless, stated once by an operator.
    // -----------------------------------------------------------------------

    #[test]
    fn a_name_with_no_field_anywhere_is_refused_and_told_where_to_put_one() {
        let store = store_from(
            r#"{"stores":{"onepassword":{"enabled":true,"vault":"company",
                                         "binary":"/nonexistent/keyless-test/op"}},
                "secrets":{"DECOY":{}}}"#,
        );
        let said = store
            .resolve("DECOY")
            .expect_err("a field is the coordinate that must not be guessed")
            .to_string();
        assert!(said.contains("was not asked"), "{said}");
        assert!(said.contains("\"field\""), "{said}");
        assert!(said.contains("stores.onepassword.field"), "{said}");
        assert!(said.contains("fields onepassword"), "{said}");
    }

    #[test]
    fn a_names_own_field_outranks_the_store_wide_one() {
        let store = pinned(r#"{"OWN":{"field":"credential"},"LOOSE":{}}"#);
        assert_eq!(
            store.routing.address("OWN").expect("own").field,
            "credential"
        );
        assert_eq!(
            store.routing.address("LOOSE").expect("store-wide").field,
            "password"
        );
    }

    #[test]
    fn an_undeclared_name_is_its_own_title_at_the_store_wide_field() {
        // The vault is fixed by the store, so a title is the only coordinate
        // left to guess — and guessing it costs a listing, never a read.
        let store = pinned("{}");
        let address = store.routing.address("INVENTED").expect("addressable");
        assert_eq!(address.item, "INVENTED");
        assert_eq!(address.field, "password");
        assert!(address.section.is_none());
    }

    #[test]
    fn a_slash_or_query_in_a_field_or_section_is_refused() {
        // Either would move a boundary inside the reference, so the vendor
        // would be handed a different address than the one written down.
        for extra in [
            r#""field":"a/b""#,
            r#""field":"otp?attribute=otp""#,
            r#""section":"x/y""#,
        ] {
            let store = pinned(&format!(r#"{{"WEIRD":{{{extra}}}}}"#));
            let said = store
                .routing
                .address("WEIRD")
                .expect_err("a boundary character must be refused");
            assert!(said.contains("may not contain"), "{said}");
            assert!(said.contains("\"section\""), "{said}");
        }
    }

    #[test]
    fn the_proton_reference_form_is_refused_rather_than_read() {
        let store = pinned(r#"{"REF":{"reference":"pass://S/I/password"}}"#);
        let said = store
            .routing
            .address("REF")
            .expect_err("a pass:// reference is not a 1Password address");
        assert!(said.contains("Proton form"), "{said}");
        assert!(said.contains("\"item\""), "{said}");
    }

    // -----------------------------------------------------------------------
    // The reference, and the invocation that resolves it.
    // -----------------------------------------------------------------------

    #[test]
    fn a_reference_is_vault_id_and_field_with_the_section_between() {
        let store = pinned(r#"{"A":{"item":"Router"},"B":{"item":"Router","section":"other"}}"#);
        let a = store.routing.address("A").expect("a");
        assert_eq!(
            a.reference("company", "It3mOne"),
            "op://company/It3mOne/password"
        );
        let b = store.routing.address("B").expect("b");
        assert_eq!(
            b.reference("company", "It3mOne"),
            "op://company/It3mOne/other/password"
        );
    }

    #[test]
    fn the_invocation_uses_run_and_no_verb_that_prints_a_value() {
        // The security property of this adapter, on the argv itself. `read`,
        // `item get` and `inject` print plaintext and are refused by the hook
        // pack; if one appears here this adapter has become the way around it.
        let store = pinned("{}");
        let argv = argv(&store.probe_command("op://company/I/password", &[]));
        assert_eq!(argv.get(1).map(String::as_str), Some("run"));
        assert!(argv.iter().any(|arg| arg == "--no-masking"), "{argv:?}");
        for forbidden in ["read", "get", "inject", "reveal", "--reveal"] {
            assert!(
                !argv.iter().any(|arg| arg == forbidden),
                "`{forbidden}` appeared in {argv:?}"
            );
        }
        let separator = argv
            .iter()
            .position(|arg| arg == "--")
            .expect("the child command is separated");
        let child: Vec<&str> = argv[separator + 1..].iter().map(String::as_str).collect();
        assert_eq!(child, ["/usr/bin/printenv", PROBE_VAR], "{argv:?}");
    }

    #[test]
    fn the_reference_travels_in_the_environment_and_never_in_argv() {
        let store = pinned("{}");
        let command = store.probe_command("op://company/It3mOne/password", &[]);
        assert!(
            !argv(&command)
                .iter()
                .any(|arg| arg.contains(REFERENCE_SCHEME)),
            "the reference is in argv: {:?}",
            argv(&command)
        );
        let probe = command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new(PROBE_VAR))
            .and_then(|(_, value)| value)
            .expect("the probe variable is set");
        assert_eq!(probe, "op://company/It3mOne/password");
    }

    #[test]
    fn the_vendor_is_handed_only_the_forwarded_variables_and_the_probe() {
        // The clearing is what makes `printenv` exact: nothing this process
        // carries can come back as a value, and no ambient `op://` can cost a
        // read nobody asked for.
        let store = pinned("{}");
        let command = store.probe_command("op://company/I/password", &[]);
        for (name, _) in command.get_envs() {
            let name = name.to_string_lossy().into_owned();
            assert!(
                is_forwarded(&name) || name == PROBE_VAR,
                "`{name}` was handed to the vendor and is neither forwarded nor the probe"
            );
        }
        // And the listing hands over even less: no probe.
        let command = store.list_command("company", &[]);
        for (name, _) in command.get_envs() {
            let name = name.to_string_lossy().into_owned();
            assert!(is_forwarded(&name), "`{name}` reached the listing");
        }
    }

    #[test]
    fn the_forwarded_set_is_the_documented_one() {
        assert!(is_forwarded("HOME"));
        assert!(is_forwarded("PATH"));
        assert!(is_forwarded("XDG_CONFIG_HOME"));
        assert!(is_forwarded("OP_SERVICE_ACCOUNT_TOKEN"));
        assert!(is_forwarded("OP_SESSION_my"));
        assert!(!is_forwarded("DATABASE_URL"));
        assert!(
            !is_forwarded(PROBE_VAR),
            "the probe must never be forwarded"
        );
        assert_eq!(FORWARDED_EXACT.len(), 10);
    }

    #[test]
    fn account_and_config_dir_reach_argv_only_when_configured_and_as_one_word() {
        let bare = pinned("{}");
        let rendered = argv(&bare.probe_command("op://company/I/password", &[]));
        assert!(!rendered.iter().any(|arg| arg.contains("--account")));
        assert!(!rendered.iter().any(|arg| arg.contains("--config")));

        let named = store_from(
            r#"{"stores":{"onepassword":{"enabled":true,"vault":"company","field":"password",
                                         "account":"-dashvault","config_dir":"/tmp/opcfg"}}}"#,
        );
        let rendered = argv(&named.probe_command("op://company/I/password", &[]));
        // `--flag=value` as one argument, so a value beginning with `-` is a
        // value and not a flag cluster. See `store::proton::flag_value`.
        assert!(
            rendered.iter().any(|arg| arg == "--account=-dashvault"),
            "{rendered:?}"
        );
        assert!(
            rendered.iter().any(|arg| arg == "--config=/tmp/opcfg"),
            "{rendered:?}"
        );
        // And on every verb, not only the probe.
        for command in [
            named.list_command("company", &[]),
            named.vault_command("company", &[]),
            named.view_command("company", "It3mOne", &[]),
        ] {
            let rendered = argv(&command);
            assert!(
                rendered.iter().any(|arg| arg == "--account=-dashvault"),
                "{rendered:?}"
            );
        }
    }

    #[test]
    fn the_listing_asks_one_vault_for_json_including_the_archive_and_never_for_content() {
        let store = pinned("{}");
        let rendered = argv(&store.list_command("company", &[]));
        assert_eq!(&rendered[1..3], ["item", "list"]);
        assert!(
            rendered.iter().any(|arg| arg == "--vault=company"),
            "{rendered:?}"
        );
        assert!(
            rendered.iter().any(|arg| arg == "--format=json"),
            "{rendered:?}"
        );
        assert!(
            rendered.iter().any(|arg| arg == "--include-archive"),
            "{rendered:?}"
        );
        assert!(!rendered.iter().any(|arg| arg == "get"), "{rendered:?}");
    }

    #[test]
    fn the_health_check_authenticates_against_the_vault_and_not_through_run() {
        // Measured: `op run` with nothing to resolve runs its child without
        // authenticating, so a health check built on it is a green line over a
        // dead login.
        let store = pinned("{}");
        let rendered = argv(&store.vault_command("company", &[]));
        assert_eq!(&rendered[1..4], ["vault", "get", "company"]);
        assert!(!rendered.iter().any(|arg| arg == "run"));
    }

    #[test]
    fn the_view_addresses_one_item_by_id_inside_the_pinned_vault() {
        let store = pinned("{}");
        let rendered = argv(&store.view_command("company", "-Kx7Qm2Za", &[]));
        assert_eq!(&rendered[1..4], ["item", "get", "-Kx7Qm2Za"]);
        assert!(
            rendered.iter().any(|arg| arg == "--vault=company"),
            "{rendered:?}"
        );
        assert!(
            !rendered.iter().any(|arg| arg == "--reveal"),
            "{rendered:?}"
        );
    }

    #[test]
    fn a_missing_binary_degrades_rather_than_panicking() {
        let store = pinned(r#"{"DECOY":{}}"#);
        let error = store
            .resolve("DECOY")
            .expect_err("a missing binary must error");
        assert!(error.to_string().contains("unavailable"), "{error}");
        assert!(store.health().is_err());
    }

    // -----------------------------------------------------------------------
    // What comes back, and what is refused.
    // -----------------------------------------------------------------------

    #[test]
    fn a_reference_read_back_unresolved_is_refused_rather_than_injected() {
        assert!(looks_unresolved(b"op://company/I/password"));
        assert!(!looks_unresolved(b"decoy-value"));
    }

    #[test]
    fn a_concealed_value_is_refused_rather_than_injected() {
        assert!(looks_concealed(b"<concealed by 1Password>"));
        assert!(!looks_concealed(b"decoy-value"));
    }

    #[test]
    fn the_vendors_log_prefix_is_stripped_and_nothing_else_is() {
        // Measured wording, 2.39.0.
        assert_eq!(
            vendor_said(
                b"[ERROR] 2001/01/01 00:00:00 multiple accounts found. Use the --account flag\n"
            ),
            "multiple accounts found. Use the --account flag"
        );
        // A line that is not in that format is quoted as it is.
        assert_eq!(
            vendor_said(b"something else entirely\n"),
            "something else entirely"
        );
        assert_eq!(vendor_said(b"[ERROR] not a timestamp\n"), "not a timestamp");
    }

    #[test]
    fn a_refused_login_is_told_apart_from_a_missing_name() {
        for said in [
            "account is not signed in",
            "multiple accounts found. Use the --account flag",
            "failed to DecodeSACredentials: invalid character",
            "(401) Unauthorized",
        ] {
            assert!(refused_login(said), "{said}");
        }
        assert!(!refused_login(
            "\"Router\" isn't an item in the \"company\" vault"
        ));

        // And the remedy names the login the caller has, not the other one.
        let session = pinned("{}");
        let said = session.explained("account is not signed in");
        assert!(said.contains("op signin"), "{said}");
        assert!(!said.contains("credential"), "{said}");
        assert!(said.contains("not a missing name"), "{said}");
    }

    // -----------------------------------------------------------------------
    // The listing: the documented shape, and the four ways a title matches.
    // -----------------------------------------------------------------------

    fn listing(json: &str) -> Vec<ItemRecord> {
        serde_json::from_str(json).expect("the documented shape parses")
    }

    #[test]
    fn a_listing_record_reads_the_documented_shape_and_an_absent_state_is_live() {
        let items = listing(
            r#"[{"id":"It3mL1v3","title":"Router","version":1,
                 "vault":{"id":"V1","name":"company"},"category":"LOGIN",
                 "created_at":"2000-01-01T00:00:00Z"},
                {"id":"It3mDead","title":"Router","category":"PASSWORD","state":"ARCHIVED"},
                {"id":"It3mTwo","title":"decoy alpha","category":"API_CREDENTIAL",
                 "state":"SOMETHING_NEW"},
                {"id":"It3mOne","title":"Router","category":null,"state":null}]"#,
        );
        assert!(items[0].is_active());
        assert!(!items[1].is_active(), "archived is not live");
        assert!(!items[2].is_active(), "an unknown state fails closed");
        assert!(items[3].is_active(), "a null state is an absent one");
        assert_eq!(items[0].state_word(), "Active");
        assert_eq!(items[1].state_word(), "ARCHIVED");
    }

    #[test]
    fn a_title_matches_one_live_item_or_says_which_of_the_other_three_it_is() {
        let items = listing(
            r#"[{"id":"It3mL1v3","title":"Router"},
                {"id":"It3mDead","title":"Router","state":"ARCHIVED"},
                {"id":"It3mOne","title":"decoy alpha"},
                {"id":"It3mTwo","title":"decoy alpha"},
                {"id":"-Kx7Qm2Za","title":"DECOY","state":"ARCHIVED"}]"#,
        );
        assert!(matches!(match_item(&items, "Router"), Matched::One(r) if r.id == "It3mL1v3"));
        // By id as well as by title, which is the escape hatch for a shared title.
        assert!(matches!(match_item(&items, "It3mTwo"), Matched::One(r) if r.id == "It3mTwo"));
        assert!(matches!(match_item(&items, "decoy alpha"), Matched::Several(v) if v.len() == 2));
        assert!(matches!(match_item(&items, "DECOY"), Matched::OnlyArchived));
        assert!(matches!(match_item(&items, "nowhere"), Matched::None));
        // Exact: a case-insensitive match would be a second way to reach an
        // item nobody named.
        assert!(matches!(match_item(&items, "router"), Matched::None));
    }

    // -----------------------------------------------------------------------
    // `fields`: labels out, and never a value.
    // -----------------------------------------------------------------------

    /// The documented `item get --format json` shape, with a marker in every
    /// value position so "no value reached the output" is an assertion.
    fn item_view() -> String {
        r#"{"id":"It3mOne","title":"demo api key","version":2,
            "vault":{"id":"V1","name":"company"},"category":"API_CREDENTIAL",
            "sections":[{"id":"t","label":"other"}],
            "fields":[
              {"id":"username","type":"STRING","purpose":"USERNAME","label":"username",
               "value":"decoy-value-one","reference":"op://company/It3mOne/username"},
              {"id":"credential","type":"CONCEALED","label":"credential",
               "value":"decoy-value-two","reference":"op://company/It3mOne/credential"},
              {"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain",
               "value":"decoy-value-three"},
              {"id":"b","section":{"id":"t","label":"other"},"type":"CONCEALED",
               "label":"api key","value":"decoy-value-four"},
              {"id":"c","type":"STRING","value":"decoy-value-five"}
            ]}"#
        .to_owned()
    }

    #[test]
    fn the_documented_view_shape_yields_the_labels_a_config_entry_needs() {
        let view = ItemView::parse(item_view().as_bytes()).expect("parses");
        let names = view.field_names();
        let labels: Vec<&str> = names.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(labels, ["username", "credential", "notesPlain", "api key"]);

        let by_name = |name: &str| names.iter().find(|f| f.name == name).expect(name);
        assert_eq!(by_name("username").kind, FieldKind::Builtin);
        assert_eq!(by_name("credential").kind, FieldKind::Custom);
        assert_eq!(
            by_name("credential").value_type.as_deref(),
            Some("CONCEALED")
        );
        assert_eq!(by_name("api key").path, "fields[3] in section \"other\"");
        assert_eq!(by_name("username").path, "fields[0]");
    }

    #[test]
    fn no_extracted_field_name_is_ever_a_value() {
        let view = ItemView::parse(item_view().as_bytes()).expect("parses");
        let rendered = format!("{:?}", view.field_names());
        assert!(
            !rendered.contains("decoy-value"),
            "a value leaked: {rendered}"
        );
        assert_eq!(format!("{view:?}"), "ItemView(<redacted>)");
    }

    #[test]
    fn a_view_with_no_fields_array_yields_nothing_rather_than_panicking() {
        let view = ItemView::parse(br#"{"id":"It3mOne","title":"demo api key"}"#).expect("parses");
        assert!(view.field_names().is_empty());
        assert!(ItemView::parse(b"not json").is_err());
    }

    // -----------------------------------------------------------------------
    // The daemon's login.
    // -----------------------------------------------------------------------

    #[test]
    fn a_credential_variable_outside_the_vendors_prefix_is_refused() {
        let names: BTreeMap<String, String> = [
            ("PATH".to_owned(), "X".to_owned()),
            ("OP_SERVICE_ACCOUNT_TOKEN".to_owned(), "Y".to_owned()),
        ]
        .into_iter()
        .collect();
        assert_eq!(ServiceAccount::refused(&names), ["PATH"]);
    }

    #[test]
    fn a_daemon_routing_is_built_from_the_same_projection_a_session_uses() {
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "A".to_owned(),
            crate::config::SecretRoute {
                item: Some("Router".to_owned()),
                ..Default::default()
            },
        );
        let routing = Routing::new(
            &secrets,
            Some("company".to_owned()),
            Some("password".to_owned()),
        );
        assert_eq!(routing.vault().expect("pinned"), "company");
        assert_eq!(routing.address("A").expect("declared").item, "Router");
        assert_eq!(routing.address("B").expect("undeclared").item, "B");

        let unpinned = Routing::new(&secrets, None, None);
        assert!(unpinned.vault().is_err());
    }
}
