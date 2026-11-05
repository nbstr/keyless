use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::config::{Config, SecretRoute};
use crate::store::catalogue::{Catalogue, Route as CatalogueRoute, find_declared};

use super::STORE_ID;

/// Where one name lives, in the stable form: vault name, item title, field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ItemAddress {
    pub(super) vault: String,
    pub(super) item: String,
    pub(super) field: String,
}

/// How a declared name says where its value is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Address {
    /// `pass://SHARE_ID/ITEM_ID/FIELD`, taken verbatim. Pins one item, and dies
    /// when the session that minted the share id is replaced.
    Reference(String),
    /// Vault name, item title and field. The ids are resolved at lookup time.
    Named(ItemAddress),
    /// The config names a Proton backend in a way that cannot be an address.
    /// Carries the sentence an operator needs; see [`Address::from_route`].
    Unusable(String),
}

impl Address {
    /// Read one config entry, or say precisely why it is not an address.
    ///
    /// Returns `None` when the entry says nothing about Proton at all, which is
    /// a different fault with a different message — see [`ProtonStore::resolve`].
    ///
    /// Every rejection here is decided **before** anything is spawned, so a
    /// malformed entry costs no vault read and leaves no audit entry.
    pub(super) fn from_route(route: &SecretRoute) -> Option<Self> {
        let named = [&route.vault, &route.item, &route.field];
        let any_named = named.iter().any(|part| part.is_some());

        match (&route.reference, any_named) {
            (None, false) => None,
            // Refusing rather than ranking them: a config that states an
            // address twice has two answers to one question, and picking the
            // one this build happens to prefer is how the wrong item gets read
            // silently. Same rule as two backends answering one name.
            (Some(_), true) => Some(Address::Unusable(
                "both `reference` and the `vault`/`item`/`field` form are declared; \
                 keep one — the name form survives a new session, the reference does not"
                    .to_owned(),
            )),
            (Some(reference), false) => Some(Address::Reference(reference.clone())),
            (None, true) => Some(Self::named(route)),
        }
    }

    /// The name form, once at least one of its three parts is present.
    fn named(route: &SecretRoute) -> Self {
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
            // None of the three is inferable. A vault or a field guessed from
            // the secret's name would send a read, and a permanent off-machine
            // audit entry, to an item nobody asked for.
            return Address::Unusable(format!(
                "the `vault`/`item`/`field` form needs all three, and {} {} missing or empty",
                missing.join(", "),
                if missing.len() == 1 { "is" } else { "are" }
            ));
        }

        let address = ItemAddress {
            vault: route.vault.clone().unwrap_or_default(),
            item: route.item.clone().unwrap_or_default(),
            field: route.field.clone().unwrap_or_default(),
        };

        // A `/` in the field would move the boundary inside the reference this
        // builds, so the CLI would be handed a different address than the one
        // written down — silently, and with a plausible-looking result.
        if address.field.contains('/') {
            return Address::Unusable(format!(
                "`field` may not contain `/`: `{}` would address a different item once \
                 it is written into a pass:// reference",
                address.field
            ));
        }

        Address::Named(address)
    }
}

/// Where every declared name lives inside Proton Pass.
///
/// # Why the projection is a type and not a map built at each call site
///
/// Two hosts build this adapter now — a session, from
/// [`crate::config::Config`], and a daemon, from its own `secrets` block — and
/// the one property that must hold in both is the one this file's whole safety
/// argument rests on: **a name that appears in no config has no address, and a
/// lookup with no address is a lookup that never spawns anything.** Two walks
/// of two maps would be free to disagree about which entries are addresses, and
/// the disagreement would be invisible: the daemon would simply resolve a name
/// the session refuses, or refuse one the session resolves.
///
/// So both hosts project through [`Routing::from_secrets`], and the session's
/// [`Routing::from_config`] is a thin wrapper over it rather than a second
/// implementation. What a daemon has that a session does not is a config file
/// the calling user cannot write — which is what turns "declared" into a
/// boundary rather than a convention.
pub struct Routing {
    /// name -> where its value lives. An entry that says nothing about Proton
    /// is absent, exactly as it is absent from a session's own projection.
    addresses: BTreeMap<String, Address>,
    /// The daemon's derived index, when it has one.
    ///
    /// `None` on a session, which has no enumerating side and no index to read.
    /// Consulted only after `addresses` has answered nothing, so a declaration
    /// wins by lookup order rather than by a precedence rule somebody has to
    /// remember. See [`crate::store::catalogue`].
    catalogue: Option<Arc<Catalogue>>,
}

impl Routing {
    /// The projection a session builds, from its own parsed config.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self::from_secrets(&config.secrets)
    }

    /// The projection either host builds, from a `secrets` map.
    #[must_use]
    pub fn from_secrets(secrets: &BTreeMap<String, SecretRoute>) -> Self {
        Routing {
            addresses: secrets
                .iter()
                .filter_map(|(name, route)| {
                    Address::from_route(route).map(|address| (name.clone(), address))
                })
                .collect(),
            catalogue: None,
        }
    }

    /// Read derived addresses out of `catalogue` as well as declared ones.
    ///
    /// The arrow points this way on purpose: this routing HOLDS the catalogue
    /// and reads from it. A catalogue that held the adapters would close a
    /// cycle, which is why the rebuilder — the thing that owns the discoverers
    /// — pushes snapshots in rather than being called out to.
    #[must_use]
    pub fn with_catalogue(mut self, catalogue: Option<Arc<Catalogue>>) -> Self {
        self.catalogue = catalogue;
        self
    }

    /// How many names carry a Proton address of any kind, usable or not.
    ///
    /// Counted rather than tested for emptiness so an operator-facing warning
    /// can say how many names it is talking about. An [`Address::Unusable`]
    /// counts: it is a name somebody meant to declare, and reporting "no name
    /// declares an address" over a config full of typos would send the reader
    /// to the wrong file.
    #[must_use]
    pub fn declared(&self) -> usize {
        self.addresses.len()
    }

    /// Where one name lives, or `None` when nothing declares it.
    ///
    /// `None` is the property `tests/daemon_proton.rs` asserts as the absence
    /// of a vendor process: see [`ProtonStore::resolve`], which turns it into
    /// an error before a temporary file is written or a child is created.
    ///
    /// A declaration answers to the item's own title as well as to its name —
    /// `demo-login` reaches a declared `DEMO_LOGIN` — by [`find_declared`]'s
    /// order, which is also the catalogue's. Here as well as there because a
    /// session's routing has no catalogue.
    pub(super) fn route(&self, name: &str) -> Option<Cow<'_, Address>> {
        // Borrowed on the declared path, owned on the derived one. A resolve
        // that produces a value must not gain an allocation it did not have,
        // and a declared `Address::Named` is three `String`s — cloned here, a
        // cold resolve of a declared name would allocate them per lookup where
        // it used to borrow.
        if let Some(declared) = find_declared(&self.addresses, name) {
            return Some(Cow::Borrowed(declared));
        }
        // An ambiguous or unknown name yields nothing here, so it never reaches
        // a spawn. That is the same absence the paragraph above describes, and
        // `tests/catalogue_daemon.rs` asserts it the same way: by counting the
        // vendor processes that were not created.
        match self.catalogue.as_ref()?.route(name) {
            CatalogueRoute::Known(entry) if entry.store == STORE_ID => {
                Address::from_route(&entry.route).map(Cow::Owned)
            }
            _ => None,
        }
    }
}
