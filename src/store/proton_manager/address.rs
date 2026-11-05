//! Where a write goes, and the pre-flight check that the title it would
//! create is still free.

use super::ProtonManager;
use crate::config::SecretRoute;
use crate::store::exec::capture;
use crate::store::manage::ManageError;
use crate::store::proton::{ItemListing, Matched, match_title};

/// Where one write goes.
pub(super) struct Address {
    pub(super) vault: String,
    pub(super) item: String,
    pub(super) field: String,
}

impl ProtonManager {
    /// Where this name's item goes, or which parts of the config are missing.
    pub(super) fn address(name: &str, route: &SecretRoute) -> Result<Address, ManageError> {
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

    /// Refuse when the title is already taken, so a read cannot be broken by a write.
    pub(super) fn refuse_a_duplicate_title(&self, address: &Address) -> Result<(), ManageError> {
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
}
