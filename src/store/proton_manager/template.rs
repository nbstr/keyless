//! The JSON template `item create` reads from stdin, holding the plaintext
//! and scrubbing it on drop.

use zeroize::Zeroize;

use super::address::Address;
use crate::secret::Secret;
use crate::store::manage::ManageError;
use crate::store::proton::scrub;

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

/// The template for one item, holding the plaintext, scrubbed on drop.
///
/// The same reasoning as [`Secret`] and for the same reason: this is a
/// `Vec<u8>` with the credential in it, and the only thing that must be able to
/// happen to it is being written to a child's stdin.
pub(super) struct Template(pub(super) Vec<u8>);

impl Template {
    /// Build the JSON `item create <kind> --from-template -` expects.
    ///
    /// `serde_json` does the escaping. Hand-formatting this would be the classic
    /// way a value containing a quote or a backslash becomes either a parse error
    /// or a different value.
    pub(super) fn build(
        kind: Kind,
        address: &Address,
        value: &Secret,
    ) -> Result<Self, ManageError> {
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
pub(super) enum Kind {
    Login,
    Custom,
}

impl Kind {
    /// The login item's own fields become a login item; everything else becomes
    /// a custom item with one hidden field.
    pub(super) fn for_field(field: &str) -> Self {
        if LOGIN_FIELDS.contains(&field) {
            Kind::Login
        } else {
            Kind::Custom
        }
    }

    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Kind::Login => "login",
            Kind::Custom => "custom",
        }
    }
}
