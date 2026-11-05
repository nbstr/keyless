use super::address;
use crate::secret::Secret;
use crate::store::proton_manager::address::Address;
use crate::store::proton_manager::template::{Kind, Template};

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
