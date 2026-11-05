use super::parse;
use crate::daemon::config::{DaemonConfig, PolicyError, refuse_interpreter_pin};
use std::path::Path;

#[test]
fn an_empty_config_authorises_nothing_and_says_so() {
    let config = parse("{}");
    let policy = config.policy().expect("an empty allowlist still parses");
    assert!(policy.is_empty());
    assert_eq!(policy.image_count(), 0);
    let warnings = config.warnings();
    assert!(warnings.iter().any(|w| w.contains("no uid")));
    assert!(warnings.iter().any(|w| w.contains("no client image")));
    assert!(warnings.iter().any(|w| w.contains("no store")));
}

#[test]
fn a_malformed_pin_is_an_error_rather_than_a_skipped_entry() {
    let config = parse(r#"{"peer":{"allow_uids":[501],"allow_images":["deadbeef"]}}"#);
    assert!(matches!(config.policy(), Err(PolicyError::BadPin(_))));
}

#[test]
fn a_duplicated_pin_is_an_error() {
    let hash = "a".repeat(40);
    let config = parse(&format!(
        r#"{{"peer":{{"allow_uids":[501],"allow_images":["{hash}","{hash}"]}}}}"#
    ));
    assert!(matches!(config.policy(), Err(PolicyError::DuplicatePin(_))));
}

#[test]
fn a_well_formed_config_yields_a_usable_policy() {
    let config = parse(
        r#"{"peer":{"allow_uids":[501],
                "allow_images":["00112233445566778899aabbccddeeff00112233"]},
                "stores":{"file":{"enabled":true,"path":"/tmp/x.json"}}}"#,
    );
    let policy = config.policy().expect("valid");
    assert!(!policy.is_empty());
    assert_eq!(policy.image_count(), 1);
    assert_eq!(config.registry(None).stores().len(), 1);
    assert!(config.warnings().is_empty());
}

#[test]
fn there_is_no_config_key_that_permits_interpreted_callers() {
    // The rule exists to be un-turn-off-able from a file. A future key
    // called anything like this would be ignored by serde, so the check
    // that matters is that the parsed config cannot express it.
    let config = parse(r#"{"peer":{"refuse_interpreters":false,"allow_uids":[501]}}"#);
    let rendered = serde_json::to_string(&config).expect("serialize");
    assert!(!rendered.contains("refuse_interpreters"));
}

#[test]
fn pinning_an_interpreter_is_refused_at_the_earliest_moment() {
    assert!(refuse_interpreter_pin(Path::new("/opt/homebrew/bin/node")).is_err());
    assert!(refuse_interpreter_pin(Path::new("/usr/bin/python3")).is_err());
    assert!(refuse_interpreter_pin(Path::new("/usr/local/bin/keyless")).is_ok());
}

#[test]
fn a_missing_daemon_config_is_an_error_rather_than_defaults() {
    assert!(DaemonConfig::load(Path::new("/nonexistent/keylessd.json")).is_err());
}
