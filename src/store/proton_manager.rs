//! Writing to Proton Pass, as the editor-role identity.
//!
//! A separate type from [`ProtonStore`](crate::store::proton::ProtonStore), in a
//! separate file, holding a separate session directory. That separation is the
//! mechanism, not decoration: nothing constructs this type except
//! [`crate::store::manage::manager`], a
//! [`crate::store::Registry`] cannot hold it, and `ProtonStore` never reads the
//! `manager` block — so there is no expression in this crate by which a `run`
//! acts as the editor.
//!
//! # The value never touches a command line
//!
//! `pass-cli item create login --password <VALUE>` exists and is not used.
//! `item create <type> --from-template -` reads a JSON template **from stdin**,
//! which is the whole reason a write verb is buildable here at all: an argument
//! is readable from the process table for as long as the child lives, which is
//! the CLI-flag shape this tool exists to remove.
//!
//! Two consequences of that choice, both stated rather than left to be found:
//!
//! - **`item update` is not used, so this creates and never overwrites.**
//!   `item update` takes `--field name=value` and offers no template on stdin, so
//!   updating an existing item would mean putting the value in argv. A name whose
//!   item already exists is therefore refused, with the reason. Rotation through
//!   this verb is not available until the vendor accepts an update on stdin.
//! - **A duplicate title would break reads, so it is checked first.** Two live
//!   items with one title make the name form ambiguous, and the resolver refuses
//!   an ambiguous title rather than guessing. Creating one is how a write verb
//!   silently breaks a working `run`, so the pre-flight listing is load-bearing
//!   and not politeness.
//!
//! # What the vendor's templates actually look like
//!
//! Measured 2026-08-08 against `pass-cli` 2.2.5, via `--get-template`, which
//! prints a shape and no values:
//!
//! ```text
//! login:  {"title":"","username":null,"email":null,"password":null,"totp_uri":null,"urls":[]}
//! custom: {"title":"","note":"","sections":[{"section_name":"…",
//!           "fields":[{"field_name":"…","field_type":"text|hidden|totp|timestamp","value":""}]}]}
//! ```
//!
//! So a name whose `field` is one of the login item's own fields becomes a login
//! item, and anything else becomes a custom item with one hidden field of that
//! name. `hidden` rather than `text` because the field holds a credential, and
//! Proton's own UI conceals a hidden field.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use zeroize::Zeroize;

use crate::config::{Config, SecretRoute};
use crate::secret::Secret;
use crate::store::exec::{self, CaptureError, capture, capture_with_input, summarise};
use crate::store::manage::{Manage, ManageError, Stored, mint_a_manager_token};
use crate::store::proton::{
    ItemListing, Matched, REASON_VAR, REFERENCE_SCHEME, Reason, SESSION_DIR_VAR, flag_value,
    match_title, relative_session_dir, remove_ambient_references, resolve_executable, scrub,
};

/// The fields a `login` item has of its own.
///
/// A name pointed at one of these becomes a login item, which is what a person
/// expects to see in Proton's UI for a password. Anything else becomes a custom
/// item, because a login item has nowhere to put it.
const LOGIN_FIELDS: &[&str] = &["username", "email", "password", "totp_uri"];

/// The section a generated custom item puts its one field in.
///
/// Named after the tool so somebody reading the item in Proton's UI can tell
/// where it came from. It is a label, never a coordinate: a config entry
/// addresses the field, not the section.
const SECTION_NAME: &str = "keyless";

/// The field type a generated custom field is given.
///
/// `hidden` conceals the value in Proton's own UI. `text` would show a credential
/// on screen to anyone who opens the item, which is the same disclosure this tool
/// removes from a terminal.
const HIDDEN: &str = "hidden";

/// Substrings the vendor uses when the token's role is the problem.
///
/// Measured 2026-08-08 against a live account and `pass-cli` 2.2.5. A viewer-role
/// token answers:
///
/// ```text
/// Error: Error creating login item
///
/// Caused by:
///     Could not perform operation. Reason: NotAllowed
/// ```
///
/// **`NotAllowed` is on the `Caused by:` line, not the first one**, which is why
/// this adapter reads the vendor's whole stderr through
/// [`crate::store::exec::summarise`]. Quoting only the first line reported the
/// refusal as `Error creating login item` — a sentence that names no cause — and
/// the guidance below never fired. That was a live failure, not a hypothetical.
///
/// Matched case-insensitively and in several spellings, because the point is to
/// attach the fix to the failure.
const ROLE_REFUSALS: &[&str] = &["notallowed", "not allowed", "permission", "forbidden"];

/// Whether a create failure the vendor did not explain is worth blaming on the role.
///
/// Yes, and it has to be said as a likelihood rather than a fact. `--role` on
/// `pass-cli agent access grant` defaults to `viewer`, so an unexplained create
/// failure is far more often a read-only token than anything else — but asserting
/// it would be wrong the day the vault is full or the network drops, and a
/// confidently wrong diagnosis costs more than an honest guess.
///
/// It names the FLAG and not a command line. The command that sets the role is
/// part of the recipe appended right after this sentence, where it is spelled
/// once, in full, with the session it runs in — see
/// [`crate::store::manage::mint_a_manager_token`]. Half a command here would be
/// a second thing to keep correct, and the half that gets dropped is always the
/// session.
const UNEXPLAINED_CREATE_HINT: &str = "the vendor did not say why. By far the most common cause is the token's ROLE: `--role` \
     defaults to `viewer` when an agent is granted access to a vault, and a viewer cannot create \
     an item";

/// Writes items to Proton Pass through `pass-cli item create`.
pub struct ProtonManager {
    binary: PathBuf,
    /// `PROTON_PASS_SESSION_DIR` for every child. The **manager's**, never the
    /// reader's.
    session_dir: PathBuf,
    timeout: Duration,
    reason: Reason,
}

impl ProtonManager {
    /// Build from a parsed config, or say what has to be minted.
    ///
    /// # Errors
    ///
    /// [`ManageError::NoIdentity`] when `stores.proton.manager.session_dir` is
    /// absent. There is deliberately no fallback to the reader's session
    /// directory: a viewer token cannot write, so falling back would turn a
    /// legible "mint an editor token" into the vendor's `NotAllowed` — and if the
    /// reader token were ever granted write access, the fallback would silently
    /// undo the whole split.
    ///
    /// The same variant when that directory is RELATIVE. A read degrades on this
    /// and still runs the command; a write refuses, which is the asymmetry
    /// [`crate::store::manage`] documents — a write that "degraded" would report
    /// success with nothing stored, and here it would store into a session
    /// directory that depends on where the operator was standing.
    pub fn from_config(config: &Config, reason: Reason) -> Result<Self, ManageError> {
        let settings = &config.stores.proton;
        let manager = settings.manager.as_ref().and_then(|manager| {
            manager
                .session_dir
                .as_deref()
                .map(|dir| (manager, dir.to_path_buf()))
        });

        let Some((manager, session_dir)) = manager else {
            return Err(ManageError::NoIdentity {
                store: "proton".to_owned(),
                detail: mint_a_manager_token(None),
            });
        };

        if !session_dir.is_absolute() {
            return Err(ManageError::NoIdentity {
                store: "proton".to_owned(),
                detail: relative_session_dir(
                    "stores.proton.manager.session_dir",
                    session_dir.as_path(),
                ),
            });
        }

        Ok(ProtonManager {
            binary: settings.binary.to_path_buf(),
            session_dir,
            timeout: crate::config::bounded_timeout(manager.timeout_ms),
            reason,
        })
    }

    /// Where this name's item goes, or which parts of the config are missing.
    fn address(name: &str, route: &SecretRoute) -> Result<Address, ManageError> {
        let address = |detail: String| ManageError::Address {
            store: "proton".to_owned(),
            detail,
        };

        if route.reference.is_some() {
            // A `pass://SHARE/ITEM/FIELD` names an item that already exists, by
            // ids this session minted. It says nothing about which vault to
            // create in or what to call the item, and creating cannot target an
            // existing item anyway.
            return Err(address(format!(
                "`{name}` is declared with a `reference`, which addresses an item that already \
                 exists; a write needs \"vault\", \"item\" and \"field\""
            )));
        }

        let missing: Vec<&str> = [
            ("vault", &route.vault),
            ("item", &route.item),
            ("field", &route.field),
        ]
        .into_iter()
        .filter(|(_, part)| part.as_deref().is_none_or(str::is_empty))
        .map(|(label, _)| label)
        .collect();

        if !missing.is_empty() {
            return Err(address(format!(
                "`{name}` needs {} in its config entry before anything can be written for it; \
                 nothing here is inferable, and a guessed vault would create an item somewhere \
                 nobody asked for",
                missing.join(", ")
            )));
        }

        let field = route.field.clone().unwrap_or_default();
        if field.contains('/') {
            return Err(address(format!(
                "`field` may not contain `/`: `{field}` would address a different item once it is \
                 written into a pass:// reference"
            )));
        }

        Ok(Address {
            vault: route.vault.clone().unwrap_or_default(),
            item: route.item.clone().unwrap_or_default(),
            field,
        })
    }

    /// Build one `pass-cli item list --vault-name … --output json` invocation.
    ///
    /// Under the MANAGER's session, deliberately: the pre-flight check has to see
    /// what the writer will see. Read as the reader it could miss an item the
    /// editor can see, and then the create would produce the duplicate this check
    /// exists to prevent.
    /// `ambient` is a parameter rather than a call to [`std::env::vars_os`] here
    /// so a test can prove the filtering is **wired in**, not merely that the
    /// filter works when called directly. On the read adapter, testing the filter
    /// on its own left the suite green after its call site was deleted.
    fn list_command<I>(&self, vault: &str, ambient: I) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("item");
        command.arg("list");
        // Joined with `=`: a vault whose name starts with `-` is read as a
        // short-flag cluster when it arrives as its own argument. See
        // [`flag_value`].
        flag_value(&mut command, "--vault-name", vault);
        command.arg("--output");
        command.arg("json");
        remove_ambient_references(&mut command, ambient);
        command.env(SESSION_DIR_VAR, &self.session_dir);
        command.env(REASON_VAR, self.reason.for_action("listing", vault));
        command
    }

    /// Build one `pass-cli item create <kind> --vault-name … --from-template -`.
    ///
    /// The template arrives on stdin. `-` is the vendor's own spelling for that,
    /// so this is the documented path rather than a trick.
    fn create_command<I>(&self, kind: &str, address: &Address, ambient: I) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("item");
        command.arg("create");
        command.arg(kind);
        flag_value(&mut command, "--vault-name", &address.vault);
        command.arg("--from-template");
        command.arg("-");
        remove_ambient_references(&mut command, ambient);
        command.env(SESSION_DIR_VAR, &self.session_dir);
        command.env(
            REASON_VAR,
            self.reason.for_action("creating", &address.item),
        );
        command
    }

    /// Refuse when the title is already taken, so a read cannot be broken by a write.
    fn refuse_a_duplicate_title(&self, address: &Address) -> Result<(), ManageError> {
        let captured = capture(
            self.list_command(&address.vault, std::env::vars_os()),
            self.timeout,
        )
        .map_err(|error| self.unavailable(&error))?;

        if !captured.status.success() {
            return Err(self.refused(
                &captured.stderr,
                &format!(
                    "cannot list vault `{}` as the manager identity, so it is not known whether \
                     `{}` already exists",
                    address.vault, address.item
                ),
                false,
            ));
        }

        let listing = serde_json::from_slice::<ItemListing>(&captured.stdout).map_err(|error| {
            ManageError::Backend {
                store: "proton".to_owned(),
                detail: format!("`item list` did not parse: {error}"),
            }
        })?;

        match match_title(&listing.items, &address.item) {
            Matched::None => Ok(()),
            Matched::One(existing) => Err(ManageError::Address {
                store: "proton".to_owned(),
                detail: format!(
                    "vault `{}` already holds a live item titled `{}`. This verb creates and \
                     never overwrites — the vendor's update verb takes the value on a command \
                     line, which is the leak this tool removes. Change the value in Proton, or \
                     use a different `item`. Its id is {}",
                    address.vault, address.item, existing.id
                ),
            }),
            Matched::OnlyTrashed => Err(ManageError::Address {
                store: "proton".to_owned(),
                detail: format!(
                    "vault `{}` holds a TRASHED item titled `{}`. Creating a second one would \
                     leave two items with one title the moment the first is restored, and the \
                     resolver refuses an ambiguous title. Empty the trash first, or restore it",
                    address.vault, address.item
                ),
            }),
            Matched::Several(several) => Err(ManageError::Address {
                store: "proton".to_owned(),
                detail: format!(
                    "vault `{}` already holds {} live items titled `{}`, so no config entry can \
                     resolve against that title at all",
                    address.vault,
                    several.len(),
                    address.item
                ),
            }),
        }
    }

    fn unavailable(&self, error: &CaptureError) -> ManageError {
        match exec::unavailable(self.id(), &self.binary, error) {
            // Every variant collapses to the same write-side error: whether the
            // binary was missing, the vendor refused, or the request was
            // underspecified, the caller's fact is that nothing was written and
            // here is why. Matched exhaustively rather than with `_` so a new
            // variant is a compile error to be considered, not a silent join.
            crate::error::StoreError::Unavailable { store, detail }
            | crate::error::StoreError::Backend { store, detail }
            | crate::error::StoreError::Misconfigured { store, detail } => {
                ManageError::Unavailable { store, detail }
            }
        }
    }

    /// A refusal, with the role fix attached.
    ///
    /// `create_failed` says whether this was the create itself, rather than the
    /// listing before it. On a create the role guidance is always attached — as a
    /// stated fact when the vendor named `NotAllowed`, and as the likely cause when
    /// it named nothing. On a listing failure it is not: a viewer can list, so a
    /// listing that failed is a different fault and blaming the role would send the
    /// reader somewhere useless.
    fn refused(&self, stderr: &[u8], context: &str, create_failed: bool) -> ManageError {
        let vendor = summarise(stderr);
        let lowered = vendor.to_ascii_lowercase();
        let named_the_role = ROLE_REFUSALS.iter().any(|marker| lowered.contains(marker));

        let detail = if named_the_role {
            format!(
                "{context}: {vendor}. That is the token's ROLE, not the request: an agent token \
                 with viewer access cannot create or trash an item. {}",
                mint_a_manager_token(Some(&self.session_dir))
            )
        } else if create_failed {
            format!(
                "{context}: {vendor}. {UNEXPLAINED_CREATE_HINT}. {}",
                mint_a_manager_token(Some(&self.session_dir))
            )
        } else {
            format!("{context}: {vendor}")
        };
        ManageError::Backend {
            store: self.id().to_owned(),
            detail,
        }
    }
}

/// Where one write goes.
struct Address {
    vault: String,
    item: String,
    field: String,
}

/// The template for one item, holding the plaintext, scrubbed on drop.
///
/// The same reasoning as [`Secret`] and for the same reason: this is a
/// `Vec<u8>` with the credential in it, and the only thing that must be able to
/// happen to it is being written to a child's stdin.
struct Template(Vec<u8>);

impl Template {
    /// Build the JSON `item create <kind> --from-template -` expects.
    ///
    /// `serde_json` does the escaping. Hand-formatting this would be the classic
    /// way a value containing a quote or a backslash becomes either a parse error
    /// or a different value.
    fn build(kind: Kind, address: &Address, value: &Secret) -> Result<Self, ManageError> {
        let body = match kind {
            Kind::Login => {
                // Built through a map rather than the `json!` macro because the
                // KEY is chosen at runtime: which of the login item's own fields
                // this name lives in comes from the config.
                let mut item = serde_json::Map::new();
                item.insert(
                    "title".to_owned(),
                    serde_json::Value::String(address.item.clone()),
                );
                item.insert(
                    address.field.clone(),
                    serde_json::Value::String(value.expose().to_owned()),
                );
                serde_json::Value::Object(item)
            }
            Kind::Custom => serde_json::json!({
                "title": address.item,
                "note": "",
                "sections": [{
                    "section_name": SECTION_NAME,
                    "fields": [{
                        "field_name": address.field,
                        "field_type": HIDDEN,
                        "value": value.expose(),
                    }],
                }],
            }),
        };

        // `to_vec` rather than `to_string` so what exists is a byte buffer this
        // type owns and scrubs, not a `String` that a `format!` could copy.
        let encoded = serde_json::to_vec(&body);
        // The tree above holds the plaintext in a `Value::String`, which has no
        // `Drop` of its own. Scrubbed here, on both the success and the error
        // path, so it does not survive in freed heap.
        let mut body = body;
        scrub(&mut body);

        encoded.map(Template).map_err(|error| ManageError::Value {
            store: "proton".to_owned(),
            detail: format!("the item template could not be encoded: {error}"),
        })
    }
}

impl std::fmt::Debug for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Template(<redacted>)")
    }
}

impl Drop for Template {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Which `item create` subcommand a field implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Login,
    Custom,
}

impl Kind {
    /// The login item's own fields become a login item; everything else becomes
    /// a custom item with one hidden field.
    fn for_field(field: &str) -> Self {
        if LOGIN_FIELDS.contains(&field) {
            Kind::Login
        } else {
            Kind::Custom
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Custom => "custom",
        }
    }
}

impl Manage for ProtonManager {
    fn id(&self) -> &str {
        "proton"
    }

    fn store(
        &self,
        name: &str,
        route: &SecretRoute,
        value: &Secret,
    ) -> Result<Stored, ManageError> {
        let address = Self::address(name, route)?;

        if value.is_empty() {
            return Err(ManageError::Value {
                store: self.id().to_owned(),
                detail: "the value is empty; the resolver treats an empty item as a \
                         misconfiguration rather than a credential, so this would never resolve"
                    .to_owned(),
            });
        }

        if resolve_executable(&self.binary).is_none() {
            return Err(ManageError::Unavailable {
                store: self.id().to_owned(),
                detail: format!(
                    "`{}` is not on PATH or is not executable",
                    self.binary.display()
                ),
            });
        }

        self.refuse_a_duplicate_title(&address)?;

        let kind = Kind::for_field(&address.field);
        let template = Template::build(kind, &address, value)?;
        let captured = capture_with_input(
            self.create_command(kind.as_str(), &address, std::env::vars_os()),
            self.timeout,
            &template.0,
        )
        .map_err(|error| self.unavailable(&error))?;

        if !captured.status.success() {
            return Err(self.refused(
                &captured.stderr,
                &format!(
                    "cannot create `{}` in vault `{}`",
                    address.item, address.vault
                ),
                true,
            ));
        }

        // Deliberately not read: `item create` echoes the item it made, and this
        // build does not need any of it. The reference a config entry resolves is
        // rebuilt from a fresh listing on every lookup anyway, because a share id
        // belongs to one session.
        Ok(Stored {
            location: format!(
                "{REFERENCE_SCHEME}{}/{}/{} ({} item)",
                address.vault,
                address.item,
                address.field,
                kind.as_str()
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, Kind, ProtonManager, Template};
    use crate::config::{Config, SecretRoute};
    use crate::secret::Secret;
    use crate::store::manage::Manage;
    use crate::store::proton::{REASON_VAR, Reason, SESSION_DIR_VAR};
    use std::ffi::OsStr;

    /// The reader's session directory, and the manager's. Two literals, written
    /// out by hand: a test that compares the adapter's export against the
    /// adapter's own field proves nothing.
    const READER: &str = "/tmp/keyless-tests-reader-session";
    const MANAGER: &str = "/tmp/keyless-tests-manager-session";

    fn config() -> Config {
        serde_json::from_str(&format!(
            r#"{{"stores":{{"proton":{{"enabled":true,"session_dir":"{READER}",
                 "manager":{{"session_dir":"{MANAGER}"}},
                 "binary":"/nonexistent/keyless-test/pass-cli"}}}}}}"#
        ))
        .expect("valid config")
    }

    fn manager() -> ProtonManager {
        ProtonManager::from_config(&config(), Reason::for_verb("new")).expect("a manager")
    }

    fn route(json: &str) -> SecretRoute {
        serde_json::from_str(json).expect("valid route")
    }

    fn address() -> Address {
        Address {
            vault: "personal".to_owned(),
            item: "decoy".to_owned(),
            field: "api key".to_owned(),
        }
    }

    /// An ambient environment written out by hand, independent of this process's.
    fn ambient() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        [
            ("PLAIN", "not-a-reference"),
            ("A_REFERENCE", "pass://share/item/password"),
            ("EMBEDDED", "prefix pass://share/item/password suffix"),
            ("LOOKALIKE", "passx://share/item/password"),
        ]
        .into_iter()
        .map(|(key, value)| {
            (
                std::ffi::OsString::from(key),
                std::ffi::OsString::from(value),
            )
        })
        .collect()
    }

    #[test]
    fn every_write_runs_under_the_manager_session_and_never_the_readers() {
        // The whole point of the two-identity split, asserted on the environment
        // the child would actually get.
        let manager = manager();
        for command in [
            manager.create_command("custom", &address(), ambient()),
            manager.list_command("personal", ambient()),
        ] {
            let session = command
                .get_envs()
                .find(|(key, _)| *key == OsStr::new(SESSION_DIR_VAR))
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned());
            assert_eq!(session.as_deref(), Some(MANAGER));
            assert_ne!(
                session.as_deref(),
                Some(READER),
                "a write ran as the reader identity"
            );
        }
    }

    #[test]
    fn a_write_carries_a_reason_that_names_no_argument_value() {
        let manager = manager();
        let reason = manager
            .create_command("custom", &address(), ambient())
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(REASON_VAR))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
            .expect("every Proton call must carry a reason");
        assert!(reason.contains("creating"), "{reason}");
        assert!(reason.contains("decoy"), "{reason}");
        assert!(!reason.trim().is_empty());
    }

    #[test]
    fn the_value_is_never_an_argument_and_the_template_comes_from_stdin() {
        // The CLI-flag shape, structurally excluded: `--password` exists on the
        // vendor's login verb and must never appear here.
        let manager = manager();
        let argv: Vec<String> = {
            let command = manager.create_command("login", &address(), ambient());
            std::iter::once(command.get_program())
                .chain(command.get_args())
                .map(OsStr::to_string_lossy)
                .map(std::borrow::Cow::into_owned)
                .collect()
        };
        assert!(argv.iter().any(|arg| arg == "--from-template"));
        assert!(argv.iter().any(|arg| arg == "-"));
        for forbidden in ["--password", "--username", "--email", "--field", "--value"] {
            assert!(
                !argv.iter().any(|arg| arg == forbidden),
                "`{forbidden}` appeared in {argv:?}"
            );
        }
    }

    #[test]
    fn an_ambient_reference_is_taken_out_of_a_writes_environment_too() {
        // `pass-cli` resolves every `pass://` it finds in the environment it
        // inherits, so an unrelated one costs a read nobody asked for — and fails
        // the write for a reason that has nothing to do with it.
        // Built through `create_command`, not by calling the filter directly: the
        // read adapter's version of this test went green once after its call site
        // was deleted, because it exercised the function and not the builder.
        let manager = manager();
        for command in [
            manager.create_command("custom", &address(), ambient()),
            manager.list_command("personal", ambient()),
        ] {
            // `get_envs` yields `None` as the value for a removal.
            let removed: Vec<String> = command
                .get_envs()
                .filter(|(_, value)| value.is_none())
                .map(|(key, _)| key.to_string_lossy().into_owned())
                .collect();
            assert!(removed.contains(&"A_REFERENCE".to_owned()), "{removed:?}");
            assert!(
                removed.contains(&"EMBEDDED".to_owned()),
                "a reference inside a longer value is still resolved by the CLI: {removed:?}"
            );
            for kept in ["PLAIN", "LOOKALIKE"] {
                assert!(!removed.contains(&kept.to_owned()), "{removed:?}");
            }
        }
    }

    #[test]
    fn a_field_the_login_item_owns_makes_a_login_item_and_anything_else_a_custom_one() {
        assert_eq!(Kind::for_field("password"), Kind::Login);
        assert_eq!(Kind::for_field("username"), Kind::Login);
        assert_eq!(Kind::for_field("totp_uri"), Kind::Login);
        assert_eq!(Kind::for_field("api key"), Kind::Custom);
        assert_eq!(Kind::for_field("Hidden Field"), Kind::Custom);
    }

    #[test]
    fn the_template_puts_the_value_where_the_vendor_expects_it() {
        // Read back through serde rather than by string matching, so an escaping
        // bug shows up as a wrong value rather than as a passing substring test.
        let value = Secret::new("decoy-template-value-4242".to_owned());
        let login = Template::build(
            Kind::Login,
            &Address {
                vault: "personal".to_owned(),
                item: "decoy".to_owned(),
                field: "password".to_owned(),
            },
            &value,
        )
        .expect("encode");
        let parsed: serde_json::Value = serde_json::from_slice(&login.0).expect("valid JSON");
        assert_eq!(parsed["title"], "decoy");
        assert_eq!(parsed["password"], "decoy-template-value-4242");

        let custom = Template::build(Kind::Custom, &address(), &value).expect("encode");
        let parsed: serde_json::Value = serde_json::from_slice(&custom.0).expect("valid JSON");
        assert_eq!(parsed["sections"][0]["fields"][0]["field_name"], "api key");
        assert_eq!(parsed["sections"][0]["fields"][0]["field_type"], "hidden");
        assert_eq!(
            parsed["sections"][0]["fields"][0]["value"],
            "decoy-template-value-4242"
        );
    }

    #[test]
    fn a_value_with_json_metacharacters_survives_the_template() {
        // Hand-formatted JSON is how a value containing a quote becomes either a
        // parse error or a different value.
        let awkward = "decoy\"back\\slash\nnewline-\u{e9}";
        let template = Template::build(Kind::Custom, &address(), &Secret::new(awkward.to_owned()))
            .expect("encode");
        let parsed: serde_json::Value = serde_json::from_slice(&template.0).expect("valid JSON");
        assert_eq!(parsed["sections"][0]["fields"][0]["value"], awkward);
    }

    #[test]
    fn a_template_debug_never_prints_the_value() {
        let template = Template::build(
            Kind::Custom,
            &address(),
            &Secret::new("decoy-9911".to_owned()),
        )
        .expect("encode");
        assert_eq!(format!("{template:?}"), "Template(<redacted>)");
    }

    #[test]
    fn a_half_written_config_entry_names_every_part_that_is_missing() {
        let error = ProtonManager::address("X", &route(r#"{"vault":"personal"}"#))
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("item"), "{error}");
        assert!(error.contains("field"), "{error}");
    }

    #[test]
    fn a_reference_only_entry_is_refused_because_it_addresses_something_that_exists() {
        let error = ProtonManager::address("X", &route(r#"{"reference":"pass://S/I/password"}"#))
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("already exists"), "{error}");
    }

    #[test]
    fn a_complete_entry_is_an_address() {
        // The negative control for the two refusals above: without it, both could
        // pass on an `address` that accepts nothing at all.
        let address = ProtonManager::address(
            "X",
            &route(r#"{"vault":"personal","item":"d","field":"password"}"#),
        )
        .expect("a complete entry");
        assert_eq!(address.vault, "personal");
        assert_eq!(address.field, "password");
    }

    #[test]
    fn a_field_with_a_separator_is_refused_before_anything_is_created() {
        let error =
            ProtonManager::address("X", &route(r#"{"vault":"c","item":"d","field":"a/b"}"#))
                .map(|_| String::new())
                .unwrap_or_else(|error| error.to_string());
        assert!(error.contains('/'), "{error}");
    }

    #[test]
    fn an_empty_value_is_refused_rather_than_stored() {
        // The resolver treats an empty item as a misconfiguration, so storing one
        // creates a name that can never resolve and says nothing about why.
        let error = manager()
            .store(
                "X",
                &route(r#"{"vault":"personal","item":"d","field":"password"}"#),
                &Secret::new(String::new()),
            )
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("empty"), "{error}");
    }

    #[test]
    fn a_missing_binary_fails_before_anything_is_spawned() {
        let error = manager()
            .store(
                "X",
                &route(r#"{"vault":"personal","item":"d","field":"password"}"#),
                &Secret::new("decoy-value-0001".to_owned()),
            )
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("not on PATH"), "{error}");
    }

    #[test]
    fn a_vendor_refusal_about_the_role_carries_the_fix() {
        // The exact bytes the live account produced on 2026-08-08. `NotAllowed` is
        // on the `Caused by:` line, three lines down — quoting only the first line
        // reported this as `Error creating login item`, which names no cause, and
        // the guidance below never fired.
        let stderr = b"Error: Error creating login item\n\nCaused by:\n    Could not perform \
                       operation. Reason: NotAllowed\n";
        let detail = manager()
            .refused(stderr, "cannot create `d`", true)
            .to_string();
        assert!(detail.contains("NotAllowed"), "{detail}");
        assert!(detail.contains("ROLE"), "{detail}");
        assert!(detail.contains("--role editor"), "{detail}");

        // The negative control for reading past the first line: with only the
        // first line quoted this fails, which is what makes the assertion above a
        // statement about `summarise` being wired in here.
        assert!(
            !crate::store::exec::first_line(stderr).contains("NotAllowed"),
            "the first line already carried the cause, so this test proves nothing"
        );
    }

    #[test]
    fn an_unexplained_create_failure_names_the_role_as_a_likelihood_not_a_fact() {
        // `--role` defaults to `viewer`, so an unexplained create failure is far
        // more often a read-only token than anything else. Saying so is useful;
        // asserting it would be wrong the day the network drops.
        let detail = manager()
            .refused(
                b"Error: Error creating login item\n",
                "cannot create `d`",
                true,
            )
            .to_string();
        assert!(detail.contains("most common cause"), "{detail}");
        assert!(detail.contains("--role editor"), "{detail}");
        assert!(
            !detail.contains("That is the token's ROLE"),
            "an unexplained failure was reported as a certainty: {detail}"
        );
    }

    #[test]
    fn a_listing_failure_is_not_blamed_on_the_role() {
        // A viewer CAN list. Attaching the role guidance here would send the
        // reader to fix something that is not broken.
        let detail = manager()
            .refused(
                b"Error: Error finding vault\n",
                "cannot list vault `personal`",
                false,
            )
            .to_string();
        assert!(detail.contains("finding vault"), "{detail}");
        assert!(!detail.contains("--role"), "{detail}");
    }

    #[test]
    fn a_config_with_no_manager_block_yields_no_writer_at_all() {
        let bare: Config =
            serde_json::from_str(r#"{"stores":{"proton":{"session_dir":"/tmp/r"}}}"#)
                .expect("valid");
        assert!(ProtonManager::from_config(&bare, Reason::default()).is_err());

        // And a manager block with no session directory is the same fault, not a
        // silent fallback to the reader's.
        let half: Config =
            serde_json::from_str(r#"{"stores":{"proton":{"session_dir":"/tmp/r","manager":{}}}}"#)
                .expect("valid");
        assert!(ProtonManager::from_config(&half, Reason::default()).is_err());
    }
}
