//! Asking a store what it holds — structure, never content.
//!
//! # Why this exists
//!
//! `keyless ls` lists the names in the config file, which answers "what have I
//! declared?" and nothing else. Before this module there was no way to ask a
//! store what is actually in it, so writing a correct config entry meant reading
//! the item first — with a verb that prints its value. Setting the tool up
//! required doing the exact thing the tool exists to prevent, and that is not a
//! gap in the documentation, it is a hole in the design.
//!
//! Measured on 2026-08-08: a Proton item of type `custom` was created, the
//! configured `field` did not match the item's real field name, `keyless`
//! degraded, and **the field name could not be found** — the only vendor verb
//! that reveals it also prints the value, so any policy that forbids printing a
//! value also forbids finding the field name. `items` and `fields` close that.
//!
//! # The line this seam draws
//!
//! A [`Discover`] implementation may return **coordinates**: vault names, item
//! titles, item states, item types, field names. It may not return a value, and
//! it may not return a value's **length** either — a length is information about
//! a secret, which is the rule `doctor --probe` already follows, and "22
//! characters" plus a password policy is a materially smaller search space.
//!
//! There is no `Discover` method that takes a field name and returns anything
//! about it. That is the structural half of the promise: adding a verb that
//! prints a value would mean adding a method here, and this file is short enough
//! that such a method could not be added quietly.
//!
//! # Not every store can do this safely, and that is reported rather than faked
//!
//! [`discoverer`] returns an error naming the reason for a backend that has no
//! safe enumeration path. A verb that leaks in one backend and not another is
//! worse than a verb that is honestly absent in one: the caller learns to trust
//! it from the backend where it is safe.

use crate::config::Config;
use crate::error::StoreError;
use crate::store::infisical::InfisicalStore;
use crate::store::proton::{ProtonStore, Reason};

/// What kind of thing a name came from.
///
/// Reported because it changes what a config entry has to say: a built-in field
/// is addressable by its own name, where a custom field's name is whatever the
/// person who made the item typed, spaces and capitals included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// A field the item type always has — `password`, `username`, `note`.
    Builtin,
    /// A field somebody added to the item, whose name is theirs.
    Custom,
}

impl FieldKind {
    /// The word printed in the `fields` listing.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            FieldKind::Builtin => "builtin",
            FieldKind::Custom => "custom",
        }
    }
}

/// One item a store holds. Every field is a coordinate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    /// The vault it is in, when the store has vaults.
    pub vault: String,
    /// The item's title, which is what a config entry's `item` must match.
    pub title: String,
    /// `Active`, `Trashed`, or whatever else the backend says.
    ///
    /// Reported verbatim and never filtered here, so a trashed item is
    /// **visible** — somebody hunting for an item that stopped resolving needs to
    /// see that it exists and is in the bin. Resolution is where the allowlist on
    /// `Active` lives; see [`crate::store::proton`].
    pub state: String,
    /// The backend's own word for the item type: `login`, `custom`, `note`.
    pub kind: String,
}

impl ItemSummary {
    /// Whether this item is live, by the same allowlist the resolver uses.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state.eq_ignore_ascii_case("active")
    }
}

/// One field of one item. A name and where it sits — never a value, never a length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSummary {
    /// The name to put in a config entry's `field`.
    pub name: String,
    /// Built-in or added by hand.
    pub kind: FieldKind,
    /// The backend's own word for what sort of value it holds — `Hidden`,
    /// `Text`, `Timestamp`, `totp`. `None` when the shape does not say.
    ///
    /// Worth reporting and safe to report: on Proton's view shape it is the KEY of
    /// the object wrapping the value, so reading it is reading structure. It is
    /// also the fastest way to notice that a config entry points at a `Timestamp`
    /// field, which resolves and is not the credential.
    pub value_type: Option<String>,
    /// Where in the backend's own structure it was found, e.g.
    /// `sections[0].fields[1]`.
    ///
    /// Useful and safe: it is a path, so it says how the item is shaped without
    /// saying anything about what is in it. It is also what makes two fields of
    /// the same name in different sections tellable apart.
    pub path: String,
}

/// A store that can be asked about its own structure.
pub trait Discover {
    /// Stable identifier, matching the [`crate::store::Store`] of the same backend.
    fn id(&self) -> &str;

    /// Every item the store holds, optionally narrowed to one vault.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the backend cannot be reached or refuses. Never a
    /// partial list presented as a whole one.
    fn items(&self, vault: Option<&str>) -> Result<Vec<ItemSummary>, StoreError>;

    /// The field NAMES on one item.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the item cannot be addressed unambiguously, when it is
    /// in the trash, or when the backend refuses.
    fn fields(&self, vault: Option<&str>, item: &str) -> Result<Vec<FieldSummary>, StoreError>;
}

/// Why the macOS keychain has no `items` or `fields`.
///
/// `security` has no verb that lists generic passwords for one service.
/// `dump-keychain` dumps every application's items for a whole keychain file, in
/// a format with no documented grammar, and the same verb with `-d` prints the
/// values — so an implementation would be a hand-rolled parser of an unstable
/// format, one flag away from printing plaintext, scoped to far more than the
/// caller asked about. That is not a safe enumeration path, so there is not one.
const KEYCHAIN_HAS_NO_LISTING: &str = "the macOS keychain has no verb that lists items for one service without dumping the whole \
     keychain file, and the verb that dumps it prints values with one extra flag. Address a \
     keychain name directly with \"service\" and \"account\" instead";

/// The [`Discover`] implementation for a store id, or the reason there is none.
///
/// `reason` is the justification Proton Pass records against everything it
/// serves, exactly as for a read. Enumerating is a read of the vault's structure
/// and is logged off-machine like any other, so it carries the same sentence and
/// the same rule about what may be in it — the verb, the program's base name, an
/// argument count, and the subject. Never an argument value.
///
/// # Errors
///
/// [`StoreError::Unavailable`] naming the backend and why it cannot enumerate.
pub fn discoverer(
    config: &Config,
    store: &str,
    reason: &Reason,
) -> Result<Box<dyn Discover>, StoreError> {
    let unavailable = |detail: &str| StoreError::Unavailable {
        store: store.to_owned(),
        detail: detail.to_owned(),
    };

    match store {
        "proton" => Ok(Box::new(ProtonStore::from_config(config, reason.clone()))),
        // The environment `infisical run` builds is the listing. It carries no
        // value out of the child, and no environment slug is defaulted, so the
        // verb enumerates only a coordinate somebody named or declared. See
        // [`crate::store::infisical`] and [`crate::store::envnames`].
        "infisical" => Ok(Box::new(InfisicalStore::from_config(config, None))),
        "keychain" => Err(unavailable(KEYCHAIN_HAS_NO_LISTING)),
        "daemon" => Err(unavailable(
            "the daemon deliberately cannot be enumerated: a client that could list the store \
             could read what it never named, which is the hole the uid boundary exists to close. \
             Ask on the machine that holds the vault",
        )),
        other => Err(StoreError::Unavailable {
            store: other.to_owned(),
            detail: "no such store".to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldKind, ItemSummary, discoverer};
    use crate::config::Config;
    use crate::store::proton::Reason;

    fn config() -> Config {
        serde_json::from_str(r#"{"stores":{"proton":{"session_dir":"/tmp/kl"}}}"#).expect("valid")
    }

    #[test]
    fn the_two_vault_backends_enumerate_and_the_others_say_why_they_do_not() {
        // The honest-degrade rule: a verb that works in one backend and leaks in
        // another is worse than one that is plainly absent in the second.
        assert!(discoverer(&config(), "proton", &Reason::default()).is_ok());
        // Infisical enumerates through the same verb it resolves through, so a
        // build where this went back to a refusal has lost the listing rather
        // than gained a protection.
        assert!(discoverer(&config(), "infisical", &Reason::default()).is_ok());

        for (store, expected) in [
            ("keychain", "whole keychain file"),
            ("daemon", "uid boundary"),
        ] {
            let message = discoverer(&config(), store, &Reason::default())
                .map(|_| String::new())
                .unwrap_or_else(|error| error.to_string());
            assert!(
                message.contains(expected),
                "`{store}` must say why it cannot enumerate: {message}"
            );
        }
    }

    #[test]
    fn an_unknown_store_is_named_rather_than_defaulted() {
        let error = discoverer(&config(), "vault-of-the-future", &Reason::default())
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("vault-of-the-future"), "{error}");
    }

    #[test]
    fn a_trashed_item_is_reported_as_not_active() {
        let summary = |state: &str| ItemSummary {
            vault: "personal".to_owned(),
            title: "decoy".to_owned(),
            state: state.to_owned(),
            kind: "login".to_owned(),
        };
        assert!(summary("Active").is_active());
        assert!(!summary("Trashed").is_active());
        assert!(!summary("SomethingNew").is_active());
    }

    #[test]
    fn the_field_kinds_render_as_stable_words() {
        assert_eq!(FieldKind::Builtin.as_str(), "builtin");
        assert_eq!(FieldKind::Custom.as_str(), "custom");
    }
}
