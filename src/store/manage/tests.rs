use super::{ManageError, manager};
use crate::config::Config;
use crate::store::proton::Reason;

fn config_from(json: &str) -> Config {
    serde_json::from_str(json).expect("valid config")
}

#[test]
fn a_configured_daemon_refuses_every_local_write() {
    // The rule the daemon design rests on, applied to the write verbs:
    // enabling the daemon must not leave a local path open beside it.
    let config = config_from(
        r#"{"stores":{"daemon":{"enabled":true},
                      "proton":{"enabled":true,"session_dir":"/tmp/r",
                                "manager":{"session_dir":"/tmp/m"}}}}"#,
    );
    for store in ["proton", "keychain"] {
        let error = manager(&config, store, &Reason::default())
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("uid boundary"), "{store}: {error}");
    }
}

#[test]
fn without_a_daemon_a_configured_manager_is_available() {
    // The negative control for the test above: without it, that one could
    // pass on a `manager` that never returns a writer under any config.
    let config = config_from(
        r#"{"stores":{"proton":{"enabled":true,"session_dir":"/tmp/r",
                                "manager":{"session_dir":"/tmp/m"}}}}"#,
    );
    let writer = manager(&config, "proton", &Reason::default()).expect("a manager");
    assert_eq!(writer.id(), "proton");
    assert_eq!(writer.identity(), "proton (manager)");
    assert!(manager(&config, "keychain", &Reason::default()).is_ok());
}

#[test]
fn proton_without_a_manager_block_names_the_token_to_mint() {
    let config = config_from(r#"{"stores":{"proton":{"enabled":true,"session_dir":"/tmp/r"}}}"#);
    let error = manager(&config, "proton", &Reason::default())
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(error.contains("manager"), "{error}");
    assert!(error.contains("agent access grant"), "{error}");
    assert!(
        error.contains("--role editor"),
        "the message must name the flag, not just the idea: {error}"
    );
    assert!(error.contains("viewer-only"), "{error}");
    // The step that was missing entirely. `agent create` prints a token and
    // writes to no session directory, so a recipe that stops at `access
    // grant` leaves the configured directory empty and every later write
    // failing authentication with nothing on the machine to explain it.
    assert!(
        error.contains("PROTON_PASS_PERSONAL_ACCESS_TOKEN"),
        "the recipe never says how the token becomes a session: {error}"
    );
    assert!(
        error.contains("PROTON_PASS_SESSION_DIR"),
        "the recipe never says which session it lands in: {error}"
    );
    // As ONE command line. Naming both halves in separate sentences is what
    // the doctor row used to do, and it is followable only by somebody who
    // already knew the answer.
    assert!(
        error.contains(
            "PROTON_PASS_SESSION_DIR=<the session directory you chose> \
             PROTON_PASS_PERSONAL_ACCESS_TOKEN"
        ),
        "the two halves are named but never joined into one line: {error}"
    );
    // Never the flag form: an argument is readable from the process table.
    assert!(
        !error.contains("login --pat"),
        "the recipe recommends a credential in argv: {error}"
    );
}

#[test]
fn the_manager_recipe_names_the_configured_directory_when_there_is_one() {
    // The negative control for the test above, and a separate property: once
    // `manager.session_dir` IS set, the login step must name THAT directory
    // rather than the placeholder. A write refused by the vendor is the one
    // moment an operator needs to re-mint into a directory that already
    // exists, and a placeholder there sends them to invent a second one.
    let recipe = super::mint_a_manager_token(Some(std::path::Path::new("/tmp/mgr-session")));
    assert!(
        recipe.contains(
            "PROTON_PASS_SESSION_DIR=/tmp/mgr-session \
                         PROTON_PASS_PERSONAL_ACCESS_TOKEN"
        ),
        "{recipe}"
    );
    assert!(
        !recipe.contains("<the session directory you chose>"),
        "a configured directory was reported as unknown: {recipe}"
    );
}

#[test]
fn infisical_says_why_it_has_no_writer_and_names_the_reason() {
    let error = manager(&config_from("{}"), "infisical", &Reason::default())
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(error.contains("command-line argument"), "{error}");
}

#[test]
fn onepassword_says_it_has_no_writer_yet_and_names_the_stdin_form() {
    // A gap rather than a refusal, and the sentence must send nobody to
    // the assignment form — `password=<value>` is the CLI-flag shape.
    let error = manager(&config_from("{}"), "onepassword", &Reason::default())
        .map(|_| String::new())
        .unwrap_or_else(|error| error.to_string());
    assert!(error.contains("stdin"), "{error}");
    assert!(error.contains("process table"), "{error}");
}

#[test]
fn the_exit_codes_separate_a_config_fault_from_a_data_fault() {
    assert_eq!(
        ManageError::NoIdentity {
            store: "proton".to_owned(),
            detail: String::new()
        }
        .exit_code(),
        78
    );
    assert_eq!(
        ManageError::Value {
            store: "keychain".to_owned(),
            detail: String::new()
        }
        .exit_code(),
        65
    );
    assert_eq!(
        ManageError::Backend {
            store: "proton".to_owned(),
            detail: String::new()
        }
        .exit_code(),
        1
    );
}

#[test]
fn no_manage_error_message_can_carry_a_value() {
    // Every variant is built from a store id and a detail that this crate
    // takes from stderr. This is the guard that a variant carrying the value
    // itself would have to be added past.
    let leak = "decoy-would-be-a-leak-5150";
    for error in [
        ManageError::Value {
            store: "keychain".to_owned(),
            detail: "it contains a newline".to_owned(),
        },
        ManageError::Backend {
            store: "proton".to_owned(),
            detail: "NotAllowed".to_owned(),
        },
    ] {
        assert!(!error.to_string().contains(leak));
    }
}
