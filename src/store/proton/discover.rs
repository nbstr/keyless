use crate::error::StoreError;
use crate::store::Store;
use crate::store::discover::{Discover, FieldSummary, ItemSummary};
use crate::store::exec::{capture, summarise};

use super::item_view::ItemView;
use super::listing::{Matched, match_title};
use super::store::ProtonStore;

impl Discover for ProtonStore {
    fn id(&self) -> &str {
        Store::id(self)
    }

    fn items(&self, vault: Option<&str>) -> Result<Vec<ItemSummary>, StoreError> {
        // One pass for the whole call, spanning every vendor child it may
        // spawn — the vault listing below and one item listing per vault.
        let pass = self.enter()?;

        // One named vault, or every vault this identity can see. Enumerating all
        // of them is one extra spawn plus one per vault, which is the honest cost
        // of not making the caller already know the answer.
        let vaults = match vault {
            Some(one) => vec![one.to_owned()],
            None => self.vaults(&pass)?,
        };

        let mut summaries = Vec::new();
        for name in vaults {
            let items = self.listed_items(&pass, &name, &name, self.reusable_for())?;
            summaries.extend(items.iter().map(|record| ItemSummary {
                id: record.id.clone(),
                vault: name.clone(),
                title: record.title.clone(),
                // Verbatim, including `Trashed`: somebody hunting a name that
                // stopped resolving has to be able to see that the item exists
                // and is in the bin. The allowlist on `Active` guards resolution,
                // not visibility.
                state: record.state.clone(),
                kind: if record.item_type.is_empty() {
                    "unknown".to_owned()
                } else {
                    record.item_type.clone()
                },
            }));
        }
        Ok(summaries)
    }

    fn fields(&self, vault: Option<&str>, item: &str) -> Result<Vec<FieldSummary>, StoreError> {
        // Required rather than searched for. Scanning every vault for a title
        // would read vaults nobody asked about, and each read is recorded
        // off-machine and permanently.
        let Some(vault) = vault else {
            return Err(self.backend(
                "name the vault as well: an item title is only unique within one vault, and \
                 searching every vault would read vaults nobody asked about"
                    .to_owned(),
            ));
        };

        // One pass spans the listing below and the `item view` capture.
        let pass = self.enter()?;
        // The same freshness rule `items` takes, and for the same reason one
        // level down: a rebuilder's `fields` resolves the item through this
        // listing, so a stale one lets it address an item that has been renamed
        // or trashed — the defect `always_relisting` exists for, arriving at
        // the other half of the same store.
        let items = self.listed_items(&pass, vault, item, self.reusable_for())?;
        let record = match match_title(&items, item) {
            Matched::One(only) => only,
            Matched::None => {
                return Err(self.backend(format!(
                    "vault `{vault}` holds no item titled `{item}`; `{} items --store proton \
                     --vault {vault}` lists the titles it does hold",
                    crate::NAME
                )));
            }
            // Said out loud rather than answered anyway. A trashed item's fields
            // are readable, and reporting them as though the item were usable
            // would send the reader back to a config entry that can never
            // resolve — the resolver refuses a trashed item on purpose.
            Matched::OnlyTrashed => {
                return Err(self.backend(format!(
                    "the only item titled `{item}` in vault `{vault}` is in the trash, so no \
                     config entry can resolve against it; restore it first"
                )));
            }
            Matched::Several(several) => {
                return Err(self.backend(format!(
                    "{} live items in vault `{vault}` are titled `{item}`, so this names no one \
                     item — candidates: {}",
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
            self.view_command(
                pass.dir(),
                record,
                &self.vendor_login()?,
                std::env::vars_os(),
            ),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            // stderr only, as everywhere else in this crate. `item view` puts the
            // item's contents on stdout, so a message built from stdout would be
            // the leak this verb exists to avoid.
            let said = summarise(&captured.stderr);
            let error =
                self.vendor_failed(&pass, format!("cannot inspect `{item}`: {said}"), &said);
            drop(pass);
            return Err(error);
        }
        drop(pass);

        // From here to the end of this function the plaintext is in this process.
        // `captured` scrubs its stdout on drop, `view` scrubs every string in the
        // parsed tree on drop, and the only thing that outlives either is a list
        // of names built from key positions.
        let view = ItemView::parse(&captured.stdout).map_err(|detail| self.backend(detail))?;
        let names = view.field_names();

        if names.is_empty() {
            return Err(self.backend(format!(
                "`{item}` reported no fields this build recognises; its shape may have changed"
            )));
        }
        Ok(names)
    }
}
