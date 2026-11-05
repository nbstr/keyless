//! The naming rule: how a store's titles and fields mint the names the
//! daemon serves, and how a request's own spelling is looked up.

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::config::SecretRoute;
use crate::store::discover::{FieldSummary, ItemSummary};

/// The field whose minted name carries no suffix.
///
/// One field per item has to be the item's own name, or every credential would
/// be addressed by a two-part name and the common case — an item holding one
/// password — would read worst. `password` is the choice because it is the
/// built-in every vault backend has and the one a login item always carries.
pub const BARE_FIELD: &str = "password";

/// What separates an item's minted name from a field's.
///
/// Two underscores rather than one, so a field name cannot be confused with the
/// continuation of a title: `A_B` with field `C` and `A` with field `B_C` mint
/// `A_B__C` and `A__B_C`, which are different names. It is not a parseable
/// boundary — see the module docs — it is a joiner.
pub(super) const FIELD_JOIN: &str = "__";

/// A store whose vocabulary can mint names.
///
/// Pure by contract: an implementation spawns nothing and reads nothing. It is a
/// naming rule, so a test can hold it against a fixture of real titles without a
/// vault anywhere in sight — which is how the 50-name reproduction is asserted.
pub trait Mint {
    /// The store id these names belong to.
    fn store(&self) -> &str;

    /// The name one field of one item mints, or `None` where the store's
    /// vocabulary cannot mint one.
    fn name(&self, item: &ItemSummary, field: &FieldSummary) -> Option<String>;

    /// The bare name of an item — the one its [`BARE_FIELD`] answers to.
    fn bare_name(&self, item: &ItemSummary) -> Option<String>;

    /// Where one minted name lives, as a route the resolver can take.
    fn route(&self, item: &ItemSummary, field: &str) -> SecretRoute;
}

/// Every character that is not ASCII-alphanumeric becomes one `_`.
///
/// # Why per CHARACTER, and why not `str::to_uppercase` first
///
/// Both halves are load-bearing and both were measured against the live
/// declarations on 2026-09-12.
///
/// Per character, because a title carrying `é` must produce ONE underscore:
/// `Type de base de données` is declared as `TYPE_DE_BASE_DE_DONN_ES`, and a
/// byte-wise walk of its UTF-8 would emit two for that one letter.
///
/// ASCII uppercase, because Unicode uppercasing is not length-preserving:
/// `ß`.to_uppercase() is `SS`, so uppercasing before the mapping would turn one
/// unmappable character into two underscores. Every character this rule keeps is
/// ASCII by construction, so there is nothing an ASCII fold can get wrong.
#[must_use]
pub fn normalise(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    // A leading digit makes the result an illegal environment variable name in
    // every shell, so `1up` is `_1UP`. Prefixed rather than dropped: dropping
    // would collide `1up` with `up`.
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// The name an item title and a field name mint together.
///
/// `password` mints the bare name, everything else appends [`FIELD_JOIN`] and
/// the normalised field. An empty title mints nothing: a name of `""`, or of
/// nothing but underscores, is not addressable and would collide with every
/// other untitled item.
#[must_use]
pub fn mint(title: &str, field: &str) -> Option<String> {
    let bare = mint_bare(title)?;
    if field.eq_ignore_ascii_case(BARE_FIELD) {
        return Some(bare);
    }
    let suffix = normalise(field);
    if suffix.is_empty() {
        return None;
    }
    Some(format!("{bare}{FIELD_JOIN}{suffix}"))
}

/// The bare name of a title, or `None` where the title mints nothing.
#[must_use]
pub fn mint_bare(title: &str) -> Option<String> {
    let bare = normalise(title);
    if bare.is_empty() {
        return None;
    }
    Some(bare)
}

/// The name a request is looked up under: what its own text mints.
///
/// A caller who addresses an item by its title — `nexus-linear`,
/// `nexus-mission__SECRET_KEY` — is asking for what that title mints, and
/// running the request through [`normalise`] reproduces the minted form exactly
/// because it IS the minting rule. Nothing is guessed: a spelling that two
/// items mint is ambiguous under either spelling alike.
///
/// Borrowed when the name is already a fixed point of [`normalise`], which
/// every minted name is, so a lookup that hits gains no allocation.
pub(super) fn spelling(name: &str) -> Cow<'_, str> {
    let minted = !name.starts_with(|c: char| c.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if minted {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(normalise(name))
    }
}

pub(super) fn declared_under<'a, V>(
    map: &'a BTreeMap<String, V>,
    name: &str,
    spelt: &str,
) -> Option<&'a V> {
    map.get(name)
        .or_else(|| (spelt != name).then(|| map.get(spelt)).flatten())
}

#[cfg(test)]
mod tests {
    use super::{normalise, spelling};
    use std::borrow::Cow;

    #[test]
    fn a_borrowed_spelling_is_exactly_what_normalise_would_have_returned() {
        // The borrow is a shortcut past `normalise`, so it is only sound where
        // `normalise` is the identity. Each side of that boundary is here.
        for name in [
            "NEXUS_LINEAR",
            "NEXUS_MISSION__SECRET_KEY",
            "_1UP",
            "",
            "nexus-linear",
            "Nexus_Linear",
            "1UP",
            "A B",
            "données",
        ] {
            let spelt = spelling(name);
            assert_eq!(spelt, normalise(name), "{name}");
            assert_eq!(
                matches!(spelt, Cow::Borrowed(_)),
                normalise(name) == name,
                "{name}"
            );
        }
    }
}
