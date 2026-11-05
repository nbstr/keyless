use super::{SCOPED, store_from};
use crate::store::discover::Discover;
use crate::store::proton::item_view::{ItemView, scrub};

/// The value that must never appear in `fields` output.
///
/// Distinctive enough that a grep for it in a failure message means a real
/// leak, and placed in every value position the measured shape has.
const VIEW_LEAK: &str = "decoy-Vw44-must-never-be-printed-0303";

/// `item view --output json` for a CUSTOM item, as measured against
/// `pass-cli` 2.2.5 on 2026-08-08.
///
/// Written out by hand rather than generated from this adapter's own idea of
/// the shape: a fixture built from the parser would agree with the parser
/// whatever either became. The important detail is that this is **not** the
/// `--get-template` shape — the label is `name`, not `field_name`, and the
/// value sits inside a single-key object whose key is the field's type.
fn custom_item_view() -> String {
    format!(
        r#"{{"item":{{"id":"ITEM1","share_id":"SHARE1","state":"Active","revision":3,
            "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
            "content":{{"item_uuid":"UUID1","title":"demo api key",
              "note":"{VIEW_LEAK}",
              "extra_fields":[
                {{"name":"first hidden field","content":{{"Hidden":"{VIEW_LEAK}"}}}},
                {{"name":"second hidden field","content":{{"Hidden":"{VIEW_LEAK}"}}}},
                {{"name":"expires","content":{{"Timestamp":"1730000000"}}}},
                {{"name":"comment","content":{{"Text":"{VIEW_LEAK}"}}}}
              ]}}}}}}"#
    )
}

/// The `--get-template` shape, which a write builds and a future CLI might
/// also return from `item view`.
fn template_shape_view() -> String {
    format!(
        r#"{{"title":"decoy","note":"","sections":[{{"section_name":"keyless",
            "fields":[{{"field_name":"api key","field_type":"hidden",
                        "value":"{VIEW_LEAK}"}}]}}]}}"#
    )
}

#[test]
fn the_measured_view_shape_yields_the_field_labels_a_config_entry_needs() {
    // The acceptance case: a custom item whose field name is not guessable
    // from anything else, reported by name.
    let view = ItemView::parse(custom_item_view().as_bytes()).expect("the shape must parse");
    let names: Vec<String> = view
        .field_names()
        .into_iter()
        .map(|field| field.name)
        .collect();
    assert!(
        names.contains(&"first hidden field".to_owned()),
        "{names:?}"
    );
    assert!(
        names.contains(&"second hidden field".to_owned()),
        "{names:?}"
    );
    assert!(names.contains(&"expires".to_owned()), "{names:?}");

    // And the sibling keys of the value are NOT reported as fields: `Hidden`
    // is the field's type, and `content` is where the credential lives.
    for structural in ["Hidden", "content", "item_uuid"] {
        assert!(
            !names.contains(&structural.to_owned()),
            "`{structural}` is structure, not a field: {names:?}"
        );
    }
}

#[test]
fn an_unfilled_login_slot_is_not_listed() {
    // A login item always carries all four built-in slots. The view prints
    // an unfilled one as `""` and the template as `null`; the vendor cannot
    // resolve a reference to either, so a listing that named one would hand
    // a declaration generator a name that is broken the moment it is
    // written. Measured 2026-09-02: this is the view's shape for a login
    // with only an email and a password filled in, with a `null` on one
    // slot so the template's spelling is covered by the same case.
    let view = ItemView::parse(
        br#"{"item":{"item_uuid":"u","content":{"title":"demo login","note":"",
            "content":{"Login":{"username":"","email":"decoy-Vw44@example",
            "password":"decoy-Vw44","totp_uri":null,"urls":[],"passkeys":[]}},
            "extra_fields":[]}}}"#,
    )
    .expect("parse");
    let names: Vec<String> = view
        .field_names()
        .into_iter()
        .map(|field| field.name)
        .collect();
    assert!(names.contains(&"email".to_owned()), "{names:?}");
    assert!(names.contains(&"password".to_owned()), "{names:?}");
    for unfilled in ["username", "totp_uri"] {
        assert!(
            !names.contains(&unfilled.to_owned()),
            "`{unfilled}` is unfilled on this item and cannot resolve: {names:?}"
        );
    }
}

#[test]
fn no_extracted_field_name_is_ever_a_value() {
    // The whole security property of this verb, on both shapes. `item view`
    // prints the values and there is no vendor flag to stop it, so the only
    // thing between the credential and stdout is this extraction.
    for shape in [custom_item_view(), template_shape_view()] {
        let view = ItemView::parse(shape.as_bytes()).expect("parse");
        for field in view.field_names() {
            assert!(
                !field.name.contains("decoy-Vw44"),
                "a value reached the field list as `{}`",
                field.name
            );
            assert!(!field.path.contains("decoy-Vw44"), "{}", field.path);
            assert!(
                !field
                    .value_type
                    .as_deref()
                    .is_some_and(|named| named.contains("decoy-Vw44")),
                "a value reached the type column"
            );
        }
    }
}

#[test]
fn the_type_column_comes_from_a_key_and_names_the_field_type() {
    let view = ItemView::parse(custom_item_view().as_bytes()).expect("parse");
    let typed: Vec<(String, Option<String>)> = view
        .field_names()
        .into_iter()
        .map(|field| (field.name, field.value_type))
        .collect();
    assert!(
        typed.contains(&("first hidden field".to_owned(), Some("Hidden".to_owned()))),
        "{typed:?}"
    );
    // Worth reporting because a config entry pointed at this one resolves and
    // hands the child a timestamp.
    assert!(
        typed.contains(&("expires".to_owned(), Some("Timestamp".to_owned()))),
        "{typed:?}"
    );
}

#[test]
fn the_template_shape_is_read_as_well_as_the_view_shape() {
    // The two shapes disagree about the label key, and the template's is the
    // only one readable without printing a credential — so it is the tempting
    // thing to build against, and building against it alone would report
    // nothing at all for a real item.
    let view = ItemView::parse(template_shape_view().as_bytes()).expect("parse");
    let names: Vec<String> = view
        .field_names()
        .into_iter()
        .map(|field| field.name)
        .collect();
    assert!(names.contains(&"api key".to_owned()), "{names:?}");
    assert!(!names.contains(&"value".to_owned()), "{names:?}");
}

#[test]
fn a_descriptor_shaped_object_outside_an_array_degrades_rather_than_hiding_the_item() {
    // The view's own top-level `item` carries a `content` key. Without the
    // "must be an array element" condition, an `item` that ever gained a
    // `name` would be read as one field descriptor and every real field would
    // silently vanish. This asserts the fallback: keys, not nothing.
    let shape = r#"{"item":{"name":"looks like a label","content":{"title":"t",
                    "note":"n","extra_fields":[]}}}"#;
    let view = ItemView::parse(shape.as_bytes()).expect("parse");
    let names: Vec<String> = view
        .field_names()
        .into_iter()
        .map(|field| field.name)
        .collect();
    assert!(names.contains(&"title".to_owned()), "{names:?}");
    assert!(names.contains(&"note".to_owned()), "{names:?}");
    assert!(
        !names.contains(&"looks like a label".to_owned()),
        "an object outside an array was read as a field descriptor: {names:?}"
    );
}

#[test]
fn an_item_view_debug_never_prints_the_item() {
    let view = ItemView::parse(custom_item_view().as_bytes()).expect("parse");
    let rendered = format!("{view:?}");
    assert_eq!(rendered, "ItemView(<redacted>)");
    assert!(!rendered.contains("decoy-Vw44"));
}

#[test]
fn scrubbing_a_parsed_item_leaves_no_string_behind() {
    // `Drop` does this. Asserted on a tree held open, because the whole point
    // is that the plaintext does not survive the function that parsed it.
    let mut parsed: serde_json::Value = serde_json::from_str(&custom_item_view()).expect("parse");
    scrub(&mut parsed);
    let rendered = serde_json::to_string(&parsed).expect("re-encode");
    assert!(
        !rendered.contains("decoy-Vw44"),
        "a value survived the scrub: {rendered}"
    );
    // Keys are names and are deliberately left alone — they are the thing
    // being reported.
    assert!(rendered.contains("extra_fields"), "{rendered}");
}

#[test]
fn fields_needs_a_vault_and_says_so() {
    let store = store_from(&format!(
        r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}"}}}}}}"#
    ));
    let message = Discover::fields(&store, None, "anything")
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(message.contains("name the vault"), "{message}");
}
