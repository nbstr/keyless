use std::fmt;

use zeroize::Zeroize;

use crate::store::discover::{FieldKind, FieldSummary};

/// Keys whose **value** is a field's label rather than a field's content.
///
/// This and [`VALUE_KEYS`] together are the only place in this crate where a
/// string from a value position may reach stdout, and the pair is deliberately
/// tiny. Measured against `pass-cli` 2.2.5, the two shapes are not the same:
///
/// | Where | Label key | Value key |
/// |---|---|---|
/// | `item view --output json`, on a custom item | `item.content.extra_fields[N].name` | `…[N].content` |
/// | `item create custom --get-template` | `sections[].fields[].field_name` | `…value` |
///
/// **The template's shape is NOT the view's shape**, which is worth stating
/// because the template is the only one of the two that can be read without
/// printing a credential — so it is the tempting thing to build against, and it is
/// wrong. Both are handled: the write path builds a template, the read path parses
/// a view.
const LABEL_KEYS: &[&str] = &["field_name", "name"];

/// Keys whose value is a field's CONTENT. Never printed, in any form.
///
/// Their presence is what identifies the object around them as a field
/// descriptor, so they are read as structure and never as data. On the view shape
/// `content` is itself an object — `{"Hidden": "<the credential>"}` — whose single
/// key is the field's type, which is why [`FieldSummary::value_type`] can report a
/// type without going anywhere near the value.
const VALUE_KEYS: &[&str] = &["content", "value"];

/// Keys that are never a usable field name, so their key is not printed either.
///
/// Two groups. The first is item metadata — ids, states, timestamps — which is
/// not addressable in a `pass://` reference and would be noise in a listing. The
/// second is the structural keys of a custom field: `value` above all, whose
/// **key** is safe to print but whose presence in the output would invite exactly
/// the wrong conclusion, and `field_name` / `field_type`, whose names are handled
/// by [`NAME_KEYS`] or ignored.
const NEVER_A_FIELD: &[&str] = &[
    "value",
    "content",
    "field_name",
    "field_type",
    "section_name",
    "id",
    "item_id",
    "item_uuid",
    "share_id",
    "vault_id",
    "state",
    "flags",
    "revision",
    "create_time",
    "modify_time",
    "content_format_version",
    "item_type",
    "type",
];

/// The vendor's rendering of ONE item, which **contains that item's values**.
///
/// The only radioactive object in this crate outside [`Secret`] itself, and it
/// exists because of an unavoidable fact: the sole `pass-cli` verb that reveals
/// an item's field NAMES is `item view`, which also prints their values. So the
/// values enter this process whether anyone wants them or not, and the whole
/// question is what happens between arrival and the first byte of output.
///
/// Four properties, each closing one way this has leaked in other tools:
///
/// - **No `Display` and a hand-written `Debug`.** `{:?}` prints
///   `ItemView(<redacted>)`, so an `assert!` message, an `expect`, a stray
///   `dbg!` or a derived `Debug` on any struct holding one cannot print an item.
/// - **`Drop` scrubs every string in the tree**, so the plaintext does not sit
///   in freed heap for the rest of the process. That covers the early-return and
///   panic paths as well, which is the reason it is a `Drop` and not a call at
///   the end of a function.
/// - **The only accessor is [`ItemView::field_names`]**, which returns names
///   built from key positions and from [`NAME_KEYS`]. There is no method that
///   returns a value, and no method that returns a value's length.
/// - **It is never serialized.** It has no `Serialize`, so it cannot reach the
///   audit log by someone adding a field to a row.
pub(super) struct ItemView(serde_json::Value);

impl ItemView {
    /// Parse the vendor's JSON, or say it did not parse without quoting it.
    ///
    /// The error deliberately does not include serde's own message beyond its
    /// position: serde_json reports unexpected input by quoting it, and the input
    /// here is an item's contents.
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .map(ItemView)
            .map_err(|error| {
                format!(
                    "`item view` did not return JSON this build understands (at line {}, column {})",
                    error.line(),
                    error.column()
                )
            })
    }

    /// Every field name on the item, with where it was found.
    ///
    /// Document order rather than sorted: it is the order the item shows in
    /// Proton's own UI, which is what somebody comparing the two expects.
    /// Duplicates are dropped, because a name and a path together are unique and
    /// repeating them says nothing.
    pub(super) fn field_names(&self) -> Vec<FieldSummary> {
        let mut found = Vec::new();
        collect_fields(&self.0, "", false, &mut found);
        found.dedup();
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

/// Zeroize every string in a JSON tree, in place.
///
/// Object *keys* are left alone: they are field names, which is the thing being
/// reported, and `serde_json`'s map gives no mutable access to them anyway.
pub(crate) fn scrub(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => {
            for item in items {
                scrub(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_, child) in map.iter_mut() {
                scrub(child);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// Walk `value`, emitting field names and nothing else.
///
/// Two rules, and there is no third:
///
/// 1. **An array element that is a field descriptor** — an object carrying a key
///    from [`LABEL_KEYS`] beside one from [`VALUE_KEYS`] — contributes its label as
///    a custom field's name, and is **not** recursed into. That is the only rule by
///    which a string from a value position reaches the output.
/// 2. **An entry whose value is a JSON scalar** contributes its KEY as a built-in
///    field's name, unless the key is in [`NEVER_A_FIELD`] or the slot is unfilled —
///    `null` or an empty string.
///
/// Everything else is recursed into.
///
/// # Why an unfilled slot is not a field
///
/// A login item always carries its four built-in slots — `username`, `email`,
/// `password`, `totp_uri` — whether or not a person filled them. The template
/// prints an unfilled one as `null`; the view prints it as `""`. Measured
/// 2026-09-02 against `pass-cli` 2.2.5: a `pass://` reference to an unfilled
/// slot fails with `Failed to resolve secret`, so a config entry pointed at it
/// can never resolve, and listing it hands a declaration generator a name that
/// is broken on the day it is written. Both spellings are skipped, because the
/// two shapes disagree and a listing has to be right on either.
///
/// # Why rule 1 requires being inside an array
///
/// Both vendor shapes keep field descriptors in a list — `extra_fields[]` on the
/// view, `sections[].fields[]` on the template — and nothing else in either shape
/// is one. Without that condition the rule is much looser than it looks: the
/// view's own top-level `item` object carries a `content` key, so an `item` that
/// ever gained a `name` would be read as a single field descriptor and the whole
/// item's fields would silently vanish from the listing. Requiring an array
/// element makes the rule structural rather than a guess about key names.
///
/// A shape that puts a descriptor outside an array falls back to rule 2, which
/// emits keys. That is a **worse listing, never a leak** — which is the direction
/// this has to fail in.
fn collect_fields(
    value: &serde_json::Value,
    path: &str,
    in_array: bool,
    out: &mut Vec<FieldSummary>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if in_array && let Some((label, value_type)) = field_descriptor(map) {
                out.push(FieldSummary {
                    name: label,
                    kind: FieldKind::Custom,
                    value_type,
                    path: path.to_owned(),
                });
                // Deliberately no recursion: everything below here is the value.
                return;
            }

            for (key, child) in map {
                let here = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if is_scalar(child) {
                    if !is_unfilled(child) && !NEVER_A_FIELD.contains(&key.as_str()) {
                        out.push(FieldSummary {
                            name: key.clone(),
                            kind: FieldKind::Builtin,
                            value_type: None,
                            path: path.to_owned(),
                        });
                    }
                    continue;
                }
                collect_fields(child, &here, false, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_fields(item, &format!("{path}[{index}]"), true, out);
            }
        }
        _ => {}
    }
}

/// A field descriptor's label and, when the shape carries one, its type.
///
/// Returns `None` unless the object holds both a label and a value container:
/// a label alone is just a string somewhere, and a container alone has no name to
/// report.
///
/// The type comes from the container's own single key on the view shape —
/// `{"Hidden": …}` — or from a sibling `field_type` on the template shape. Reading
/// a key is not reading a value, so this stays on the safe side of the line.
fn field_descriptor(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Option<(String, Option<String>)> {
    let container = VALUE_KEYS
        .iter()
        .find_map(|key| map.get(*key).map(|value| (*key, value)))?;

    let label = LABEL_KEYS.iter().find_map(|key| match map.get(*key) {
        Some(serde_json::Value::String(label)) if !label.is_empty() => Some(label.clone()),
        _ => None,
    })?;

    let value_type = match map.get("field_type") {
        Some(serde_json::Value::String(named)) if !named.is_empty() => Some(named.clone()),
        // The view shape wraps the value in a single-key object whose key is the
        // type. More than one key means this build does not understand the shape,
        // and inventing a type would be worse than reporting none.
        _ => match container.1 {
            serde_json::Value::Object(inner) if inner.len() == 1 => inner.keys().next().cloned(),
            _ => None,
        },
    };

    Some((label, value_type))
}

/// Whether a JSON value is a leaf rather than a container.
/// Whether a built-in slot holds nothing: `null` on the template shape, `""` on
/// the view shape. See the note on [`collect_fields`].
fn is_unfilled(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::String(text) => text.is_empty(),
        _ => false,
    }
}

fn is_scalar(value: &serde_json::Value) -> bool {
    !matches!(
        value,
        serde_json::Value::Object(_) | serde_json::Value::Array(_)
    )
}
