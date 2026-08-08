//! `keyless items` and `keyless fields` — what a store actually holds.
//!
//! Two verbs in one file because they are one behaviour at two granularities:
//! ask a backend for its structure and print it. Neither prints a value. Neither
//! prints a value's LENGTH either — a length is still information about a secret,
//! which is the rule `doctor --probe` already follows.
//!
//! # What these are for
//!
//! `keyless ls` reads the config file. It answers "what have I declared?" and
//! nothing else, so before these verbs existed the only way to write a correct
//! config entry was to open the item in a vault client, or to run a vendor verb
//! that prints its value. **Setting the tool up required doing the thing the tool
//! exists to prevent.** These two close that: enough structure to write a correct
//! entry, and not one byte more.
//!
//! # Output shape
//!
//! Tab-separated columns, same reasoning as `ls`: this output is read by agents at
//! least as often as by people, and a fixed column order is trivially parseable
//! without a JSON mode nobody maintains.

use std::io::{self, Write};

use crate::store::discover::Discover;

/// List the items a store holds, optionally narrowed to one vault.
///
/// Columns: `vault`, `state`, `type`, `title`. A trashed item is listed with its
/// state, never hidden — somebody hunting a name that stopped resolving has to be
/// able to see that the item exists and is in the bin. Refusing to *resolve* one
/// is the resolver's job and it still refuses.
///
/// # Errors
///
/// Fails only when `out` cannot be written. A backend failure is written to
/// `notes` and reported as exit code 1, because these verbs are diagnostics: they
/// have no child process to protect, so they are allowed to be judgemental.
pub fn items(
    discover: &dyn Discover,
    vault: Option<&str>,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> io::Result<i32> {
    let items = match discover.items(vault) {
        Ok(items) => items,
        Err(error) => {
            writeln!(notes, "{}: {error}", crate::NAME)?;
            return Ok(1);
        }
    };

    if items.is_empty() {
        writeln!(
            notes,
            "{}: store `{}` reports no items{}",
            crate::NAME,
            discover.id(),
            vault.map_or_else(String::new, |vault| format!(" in vault `{vault}`"))
        )?;
        return Ok(0);
    }

    for item in &items {
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            item.vault, item.state, item.kind, item.title
        )?;
    }
    Ok(0)
}

/// List the field NAMES on one item.
///
/// Columns: `name`, `kind` (`builtin` or `custom`), `type` (the backend's own word
/// for the sort of value, or `-`), `path` — where in the backend's own structure it
/// sits, which is how two fields of the same name in different sections are told
/// apart. The `name` column is what goes in a config entry's `field`.
///
/// # Errors
///
/// Fails only when `out` cannot be written; see [`items`].
pub fn fields(
    discover: &dyn Discover,
    vault: Option<&str>,
    item: &str,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> io::Result<i32> {
    let fields = match discover.fields(vault, item) {
        Ok(fields) => fields,
        Err(error) => {
            writeln!(notes, "{}: {error}", crate::NAME)?;
            return Ok(1);
        }
    };

    for field in &fields {
        let path = if field.path.is_empty() {
            "-"
        } else {
            field.path.as_str()
        };
        writeln!(
            out,
            "{}\t{}\t{}\t{}",
            field.name,
            field.kind.as_str(),
            field.value_type.as_deref().unwrap_or("-"),
            path
        )?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::{fields, items};
    use crate::error::StoreError;
    use crate::store::discover::{Discover, FieldKind, FieldSummary, ItemSummary};

    /// A backend whose answers are written out by hand.
    ///
    /// This fake cannot express a value, because [`Discover`] has no method that
    /// returns one — which is the point of the seam. The test that a *real*
    /// backend does not leak one has to live where the vendor's JSON is parsed;
    /// see `no_extracted_field_name_is_ever_a_value` in `store::proton`.
    struct Fake;

    impl Discover for Fake {
        fn id(&self) -> &str {
            "fake"
        }
        fn items(&self, vault: Option<&str>) -> Result<Vec<ItemSummary>, StoreError> {
            Ok(vec![
                ItemSummary {
                    vault: vault.unwrap_or("personal").to_owned(),
                    title: "demo api key".to_owned(),
                    state: "Active".to_owned(),
                    kind: "custom".to_owned(),
                },
                ItemSummary {
                    vault: vault.unwrap_or("personal").to_owned(),
                    title: "keyless-decoy-alpha".to_owned(),
                    state: "Trashed".to_owned(),
                    kind: "login".to_owned(),
                },
            ])
        }
        fn fields(
            &self,
            _vault: Option<&str>,
            _item: &str,
        ) -> Result<Vec<FieldSummary>, StoreError> {
            Ok(vec![
                FieldSummary {
                    name: "password".to_owned(),
                    kind: FieldKind::Builtin,
                    value_type: None,
                    path: String::new(),
                },
                FieldSummary {
                    name: "api key".to_owned(),
                    kind: FieldKind::Custom,
                    value_type: Some("Hidden".to_owned()),
                    path: "sections[0].fields[0]".to_owned(),
                },
            ])
        }
    }

    struct Broken;

    impl Discover for Broken {
        fn id(&self) -> &str {
            "broken"
        }
        fn items(&self, _vault: Option<&str>) -> Result<Vec<ItemSummary>, StoreError> {
            Err(StoreError::Unavailable {
                store: "broken".to_owned(),
                detail: "no session".to_owned(),
            })
        }
        fn fields(
            &self,
            _vault: Option<&str>,
            _item: &str,
        ) -> Result<Vec<FieldSummary>, StoreError> {
            Err(StoreError::Backend {
                store: "broken".to_owned(),
                detail: "the only item with that title is in the trash".to_owned(),
            })
        }
    }

    fn render_items(discover: &dyn Discover) -> (String, String, i32) {
        let mut out: Vec<u8> = Vec::new();
        let mut notes: Vec<u8> = Vec::new();
        let code =
            items(discover, Some("personal"), &mut out, &mut notes).expect("writing to a Vec");
        (
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&notes).into_owned(),
            code,
        )
    }

    fn render_fields(discover: &dyn Discover) -> (String, String, i32) {
        let mut out: Vec<u8> = Vec::new();
        let mut notes: Vec<u8> = Vec::new();
        let code = fields(
            discover,
            Some("personal"),
            "demo api key",
            &mut out,
            &mut notes,
        )
        .expect("writing to a Vec");
        (
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&notes).into_owned(),
            code,
        )
    }

    #[test]
    fn items_shows_a_trashed_item_and_marks_its_state() {
        // Hiding it would leave somebody hunting for an item that is right there
        // in the bin. Showing it unmarked would be worse: they would write a
        // config entry against a title that can never resolve.
        let (listing, _, code) = render_items(&Fake);
        assert_eq!(code, 0);
        let trashed = listing
            .lines()
            .find(|line| line.contains("keyless-decoy-alpha"))
            .expect("the trashed item must be listed");
        assert!(
            trashed.contains("Trashed"),
            "a trashed item was listed without its state: {trashed}"
        );

        // And the live one is distinguishable, which is what makes the column
        // worth reading rather than decorative.
        let live = listing
            .lines()
            .find(|line| line.contains("demo api key"))
            .expect("the live item must be listed");
        assert!(live.contains("Active"), "{live}");
    }

    #[test]
    fn items_prints_four_tab_separated_columns_and_nothing_else() {
        let (listing, _, _) = render_items(&Fake);
        for line in listing.lines() {
            assert_eq!(
                line.split('\t').count(),
                4,
                "column count changed, which breaks every parser: {line}"
            );
        }
    }

    #[test]
    fn fields_prints_the_name_the_kind_the_type_and_the_path() {
        let (listing, _, code) = render_fields(&Fake);
        assert_eq!(code, 0);
        assert!(listing.contains("password"), "{listing}");
        assert!(listing.contains("api key"), "{listing}");
        assert!(listing.contains("custom"), "{listing}");
        assert!(listing.contains("Hidden"), "{listing}");
        assert!(listing.contains("sections[0].fields[0]"), "{listing}");
        for line in listing.lines() {
            assert_eq!(line.split('\t').count(), 4, "{line}");
        }
        // A field with no reported type gets a placeholder rather than an empty
        // column, so the column count never depends on the data.
        assert!(
            listing.lines().any(|line| line.contains("\t-\t")),
            "{listing}"
        );
    }

    #[test]
    fn fields_never_prints_a_length_either() {
        // A length is information about a secret. `doctor --probe` already refuses
        // to print one, and this verb is the newer, easier place to leak it.
        let (listing, notes, _) = render_fields(&Fake);
        let everything = format!("{listing}{notes}");
        for forbidden in ["bytes", "chars", "length", "len "] {
            assert!(
                !everything.to_ascii_lowercase().contains(forbidden),
                "`{forbidden}` appeared in the output: {everything}"
            );
        }
    }

    #[test]
    fn a_backend_failure_is_reported_on_notes_and_exits_nonzero() {
        let (listing, notes, code) = render_items(&Broken);
        assert_eq!(code, 1);
        assert!(listing.is_empty(), "a failure printed a listing: {listing}");
        assert!(notes.contains("no session"), "{notes}");

        let (listing, notes, code) = render_fields(&Broken);
        assert_eq!(code, 1);
        assert!(listing.is_empty());
        assert!(notes.contains("trash"), "{notes}");
    }
}
