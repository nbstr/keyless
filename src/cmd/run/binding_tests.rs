use super::Binding;

use crate::config::Config;

pub(super) fn config_of(json: &str) -> Config {
    serde_json::from_str(json).expect("valid config")
}

#[test]
fn a_bare_name_binds_to_itself() {
    assert_eq!(
        Binding::parse("GITHUB_TOKEN").expect("valid"),
        Binding {
            env: "GITHUB_TOKEN".to_owned(),
            name: "GITHUB_TOKEN".to_owned(),
            also: Vec::new(),
        }
    );
}

/// The seam. `parse` is syntax and must stay so: every existing caller of it
/// binds exactly one variable, and a `parse` that started consulting a
/// config would change what those callers do without any of them being
/// touched.
#[test]
fn parse_alone_never_widens_a_request() {
    let binding = Binding::parse("LABEL").expect("valid");
    assert!(binding.also.is_empty());
    assert_eq!(binding.targets(), ["LABEL"]);
}

#[test]
fn a_declared_name_also_lands_in_the_variable_its_route_names() {
    let config = config_of(r#"{"secrets":{"LABEL":{"key":"THE_VARIABLE"}}}"#);
    let binding = Binding::declared("LABEL", &config).expect("valid");
    assert_eq!(binding.env, "LABEL");
    assert_eq!(binding.targets(), ["LABEL", "THE_VARIABLE"]);
}

#[test]
fn a_spelled_request_is_never_widened() {
    let config = config_of(r#"{"secrets":{"LABEL":{"key":"THE_VARIABLE"}}}"#);
    let binding = Binding::declared("CHOSEN=LABEL", &config).expect("valid");
    assert_eq!(binding.targets(), ["CHOSEN"]);
}

#[test]
fn a_declaration_that_would_hijack_the_child_is_dropped_not_obeyed() {
    // A config is not a trusted input. Every derived variable meets the same
    // two refusals a typed one does, and a refused one costs the alias
    // rather than the run.
    for hostile in ["PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "IFS"] {
        let config = config_of(&format!(
            r#"{{"secrets":{{"LABEL":{{"var":"{hostile}"}}}}}}"#
        ));
        let binding = Binding::declared("LABEL", &config).expect("valid");
        assert_eq!(binding.targets(), ["LABEL"], "{hostile} was injected");
    }
}

#[test]
fn a_declaration_naming_something_no_environment_can_hold_is_dropped() {
    let config = config_of(r#"{"secrets":{"LABEL":{"var":"not a variable"}}}"#);
    assert_eq!(
        Binding::declared("LABEL", &config)
            .expect("valid")
            .targets(),
        ["LABEL"]
    );
}

#[test]
fn an_undeclared_name_answers_to_itself_alone() {
    let config = config_of(r#"{"secrets":{"OTHER":{"key":"THE_VARIABLE"}}}"#);
    assert_eq!(
        Binding::declared("LABEL", &config)
            .expect("valid")
            .targets(),
        ["LABEL"]
    );
}

#[test]
fn an_alias_binds_to_a_different_variable() {
    let binding = Binding::parse("GH_TOKEN=work-github-pat").expect("valid");
    assert_eq!(binding.env, "GH_TOKEN");
    assert_eq!(binding.name, "work-github-pat");
}

#[test]
fn an_unusable_variable_name_is_rejected_at_parse_time() {
    assert!(Binding::parse("9LIVES").is_err());
    assert!(Binding::parse("has space=X").is_err());
    assert!(Binding::parse("=X").is_err());
}

#[test]
fn underscores_and_digits_are_fine_after_the_first_character() {
    assert!(Binding::parse("_PRIVATE_1").is_ok());
}
