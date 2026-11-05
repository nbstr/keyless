use std::ffi::OsStr;

use super::{MANAGER, READER, address, ambient, manager};
use crate::store::proton::{REASON_VAR, SESSION_DIR_VAR, assert_vendor_switch_offs};

#[test]
fn every_write_runs_under_the_manager_session_and_never_the_readers() {
    // The whole point of the two-identity split, asserted on the environment
    // the child would actually get.
    let manager = manager();
    for command in [
        manager.create_command("custom", &address(), ambient()),
        manager.list_command("personal", ambient()),
    ] {
        let session = command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(SESSION_DIR_VAR))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned());
        assert_eq!(session.as_deref(), Some(MANAGER));
        assert_ne!(
            session.as_deref(),
            Some(READER),
            "a write ran as the reader identity"
        );
    }
}

#[test]
fn a_write_carries_a_reason_that_names_no_argument_value() {
    let manager = manager();
    let reason = manager
        .create_command("custom", &address(), ambient())
        .get_envs()
        .find(|(key, _)| *key == OsStr::new(REASON_VAR))
        .and_then(|(_, value)| value)
        .map(|value| value.to_string_lossy().into_owned())
        .expect("every Proton call must carry a reason");
    assert!(reason.contains("creating"), "{reason}");
    assert!(reason.contains("decoy"), "{reason}");
    assert!(!reason.trim().is_empty());
}

#[test]
fn every_write_switches_off_the_vendors_telemetry_and_update_check() {
    let manager = manager();
    for command in [
        manager.create_command("custom", &address(), ambient()),
        manager.list_command("personal", ambient()),
    ] {
        assert_vendor_switch_offs(&command);
    }
}

#[test]
fn the_value_is_never_an_argument_and_the_template_comes_from_stdin() {
    // The CLI-flag shape, structurally excluded: `--password` exists on the
    // vendor's login verb and must never appear here.
    let manager = manager();
    let argv: Vec<String> = {
        let command = manager.create_command("login", &address(), ambient());
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .map(std::borrow::Cow::into_owned)
            .collect()
    };
    assert!(argv.iter().any(|arg| arg == "--from-template"));
    assert!(argv.iter().any(|arg| arg == "-"));
    for forbidden in ["--password", "--username", "--email", "--field", "--value"] {
        assert!(
            !argv.iter().any(|arg| arg == forbidden),
            "`{forbidden}` appeared in {argv:?}"
        );
    }
}

#[test]
fn an_ambient_reference_is_taken_out_of_a_writes_environment_too() {
    // `pass-cli` resolves every `pass://` it finds in the environment it
    // inherits, so an unrelated one costs a read nobody asked for — and fails
    // the write for a reason that has nothing to do with it.
    // Built through `create_command`, not by calling the filter directly: the
    // read adapter's version of this test went green once after its call site
    // was deleted, because it exercised the function and not the builder.
    let manager = manager();
    for command in [
        manager.create_command("custom", &address(), ambient()),
        manager.list_command("personal", ambient()),
    ] {
        // `get_envs` yields `None` as the value for a removal.
        let removed: Vec<String> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        assert!(removed.contains(&"A_REFERENCE".to_owned()), "{removed:?}");
        assert!(
            removed.contains(&"EMBEDDED".to_owned()),
            "a reference inside a longer value is still resolved by the CLI: {removed:?}"
        );
        for kept in ["PLAIN", "LOOKALIKE"] {
            assert!(!removed.contains(&kept.to_owned()), "{removed:?}");
        }
    }
}
