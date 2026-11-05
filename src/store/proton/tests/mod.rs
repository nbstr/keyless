mod failure;
mod fields;
mod generations;
mod invocation;
mod listing;
mod probe;
mod routing;
mod token;

use crate::config::Config;
use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;
use crate::store::proton::listing::ItemRecord;
use crate::store::proton::reason::Reason;
use crate::store::proton::routing::Routing;
use crate::store::proton::store::ProtonStore;
use std::ffi::{OsStr, OsString};
use std::path::Path;

/// A fresh, empty directory for one gate test's `Generations` to live in.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyless-proton-gate-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// The session directory these tests pretend was configured.
///
/// A literal rather than a constant read out of the source: a test that
/// asserts the adapter exports whatever the adapter decided to export
/// proves nothing. This string is an independent statement of what the
/// config asked for.
const SCOPED: &str = "/tmp/keyless-tests-scoped-session";

fn store_from(json: &str) -> ProtonStore {
    let config: Config = serde_json::from_str(json).expect("valid config");
    ProtonStore::from_config(&config, Reason::default())
}

/// The `secrets` block both hosts project, written once.
///
/// Four entries on purpose: the reference form, the name form, an entry
/// that says nothing about Proton at all, and a half-written one. The last
/// two are the ones the two projections could disagree about — whether an
/// entry is absent or merely unusable decides which sentence a lookup
/// reports, and a daemon that disagreed with a session about that would
/// tell an operator to fix the wrong file.
const SHARED_SECRETS: &str = r#"{
    "BY_REFERENCE": { "reference": "pass://share/item/password" },
    "BY_NAME":      { "vault": "company", "item": "decoy", "field": "password" },
    "NOT_PROTON":   { "store": "keychain" },
    "HALF_WRITTEN": { "vault": "company" }
}"#;

/// An ambient environment written out by hand.
///
/// Independent of anything the implementation reads: it is a statement of
/// what a caller's shell might hold, not a copy of this process's own
/// environment, and it goes through the real `probe_command` so the
/// filtering is tested where it is wired rather than where it is defined.
fn ambient() -> Vec<(OsString, OsString)> {
    [
        ("PLAIN", "not-a-reference"),
        ("A_REFERENCE", "pass://share/item/password"),
        ("EMBEDDED", "prefix pass://share/item/password suffix"),
        ("LOOKALIKE", "passx://share/item/password"),
        ("EMPTY", ""),
    ]
    .into_iter()
    .map(|(key, value)| (OsString::from(key), OsString::from(value)))
    .collect()
}

/// The program and its arguments, in the order a shell would show them.
fn argv_of(command: &std::process::Command) -> Vec<String> {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(OsStr::to_string_lossy)
        .map(std::borrow::Cow::into_owned)
        .collect()
}

/// A credential source that answers every entry with a fixed value, so a
/// case can build an [`AgentToken`] without a file on disk.
struct Fixed;
impl Store for Fixed {
    fn id(&self) -> &str {
        "fixed"
    }
    fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
        Ok(Some(Secret::new("decoy-credential".to_owned())))
    }
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

fn list_argv(store: &ProtonStore, vault: &str) -> Vec<String> {
    argv_of(&store.list_command(Path::new(SCOPED), vault, "X", &[], ambient()))
}

/// An ordinary, active item — a base for a test whose own point lies
/// elsewhere to override with `..record()`.
fn record() -> ItemRecord {
    ItemRecord {
        id: "id".to_owned(),
        share_id: "share".to_owned(),
        state: "Active".to_owned(),
        title: "keyless-decoy-alpha".to_owned(),
        item_type: "login".to_owned(),
    }
}

/// A store built from parts, with no config behind it.
fn parts_store() -> ProtonStore {
    let secrets: std::collections::BTreeMap<String, crate::config::SecretRoute> =
        serde_json::from_str(SHARED_SECRETS).expect("valid secrets");
    ProtonStore::new(
        std::path::PathBuf::from("/nonexistent/pass-cli"),
        std::path::PathBuf::from("/usr/bin/printenv"),
        Routing::from_secrets(&secrets),
        Reason::default(),
    )
}
