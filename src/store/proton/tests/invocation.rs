use super::{SCOPED, ambient, argv_of, list_argv, record, store_from};
use crate::store::Store;
use crate::store::proton::commands::{PROBE_VAR, TempEnvFile};
use crate::store::proton::environment::{REASON_VAR, SESSION_DIR_VAR, assert_vendor_switch_offs};
use crate::store::proton::listing::ItemRecord;
use crate::store::proton::store::resolve_executable;
use std::path::Path;

#[test]
fn the_view_invocation_addresses_one_item_by_id_and_asks_for_json() {
    let store = store_from("{}");
    let item = ItemRecord {
        id: "ITEM1".to_owned(),
        share_id: "SHARE1".to_owned(),
        title: "demo api key".to_owned(),
        item_type: "custom".to_owned(),
        ..record()
    };
    let command = store.view_command(Path::new(SCOPED), &item, &[], ambient());

    // By id, not by title: the id came from a listing this adapter just
    // read, so `fields` and `run` are looking at the same item even if two
    // share a title. Joined to its flag, because an id may begin with `-`.
    // The exact argv implies that on its own, and it is read off the same
    // command `assert_vendor_switch_offs` checks below rather than a
    // second one built just for that.
    assert_eq!(
        argv_of(&command),
        vec![
            "pass-cli",
            "item",
            "view",
            "--share-id=SHARE1",
            "--item-id=ITEM1",
            "--output",
            "json",
        ]
    );
    assert_vendor_switch_offs(&command);

    // Same two variables as every other Proton call.
    let env: Vec<(String, Option<String>)> = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert_eq!(
        env.iter()
            .find(|(key, _)| key == SESSION_DIR_VAR)
            .and_then(|(_, value)| value.as_deref()),
        Some(SCOPED)
    );
    let reason = env
        .iter()
        .find(|(key, _)| key == REASON_VAR)
        .and_then(|(_, value)| value.clone())
        .expect("a reason");
    assert!(reason.contains("demo api key"), "{reason}");

    // And the ambient filter, wired here rather than merely defined.
    let removed: Vec<String> = command
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    assert!(removed.contains(&"A_REFERENCE".to_owned()), "{removed:?}");
}

#[test]
fn no_coordinate_ever_arrives_as_a_short_flag_cluster() {
    // The rule is the vendor's parser's, stated once and applied to every
    // invocation this adapter builds: clap reads a standalone argument that
    // begins with ONE `-` as a cluster of short flags, whatever option came
    // before it, and refuses the command with exit 2.
    //
    // Written as a property over the whole argument vector rather than as a
    // list of the flags this file happens to pass. A list would be the same
    // list twice — add a flag and it leaves the test in the same stroke.
    //
    // The values below are the shape that actually broke: Proton ids are
    // base64url, whose alphabet includes `-`, so an id can begin with one.
    // They are invented — the property under test is the leading `-`, and
    // nothing here needs a coordinate from anybody's real vault.
    fn no_cluster(argv: &[String], what: &str) {
        for arg in &argv[1..] {
            // A lone `-` is exempt: it is the vendor's own spelling for
            // stdin, and clap reads it as a value rather than as flags.
            let cluster = arg.starts_with('-') && !arg.starts_with("--") && arg != "-";
            assert!(
                !cluster,
                "{what} passed `{arg}`, which the vendor reads as short flags: {argv:?}"
            );
        }
    }

    let store = store_from("{}");

    let listing = list_argv(&store, "-dashvault");
    assert!(
        listing.iter().any(|arg| arg == "--vault-name=-dashvault"),
        "{listing:?}"
    );
    no_cluster(&listing, "`item list`");

    let item = ItemRecord {
        id: "-Kx7Qm2Za".to_owned(),
        share_id: "-Sh4r3".to_owned(),
        title: "demo.service".to_owned(),
        item_type: "custom".to_owned(),
        ..record()
    };
    let command = store.view_command(Path::new(SCOPED), &item, &[], ambient());
    let view = argv_of(&command);
    assert!(
        view.iter().any(|arg| arg == "--item-id=-Kx7Qm2Za"),
        "{view:?}"
    );
    assert!(
        view.iter().any(|arg| arg == "--share-id=-Sh4r3"),
        "{view:?}"
    );
    no_cluster(&view, "`item view`");

    // The negative control for the helper itself: it has to be able to fail.
    // Without this, `no_cluster` could be vacuous — a loop that never trips
    // reads exactly like a loop that cannot.
    let broken = vec![
        "pass-cli".to_owned(),
        "--item-id".to_owned(),
        "-Kx7Qm2Za".to_owned(),
    ];
    assert!(
        std::panic::catch_unwind(|| no_cluster(&broken, "the control")).is_err(),
        "the check passed an argument vector the vendor refuses"
    );
}

#[test]
fn the_env_file_holds_a_reference_and_is_removed_afterwards() {
    let directory = std::env::temp_dir();
    let path;
    {
        let file = TempEnvFile::create(&directory, "pass://Personal/Router/password")
            .expect("the probe file must be writable");
        path = file.path.clone();
        let body = std::fs::read_to_string(&path).expect("readable");
        assert_eq!(
            body,
            format!("{PROBE_VAR}=pass://Personal/Router/password\n")
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the probe file must not be readable by others"
            );
        }
    }
    assert!(!path.exists(), "the probe file outlived its lookup");
}

#[test]
fn a_missing_binary_is_unhealthy_rather_than_a_panic() {
    // `session_dir` is set in both, so the failure under test is the binary
    // rather than the session complaint that now precedes it.
    for binary in [
        "/nonexistent/keyless-test/pass-cli",
        "keyless-not-a-real-binary-anywhere",
    ] {
        let store = store_from(&format!(
            r#"{{"stores":{{"proton":{{"session_dir":"{SCOPED}","binary":"{binary}"}}}}}}"#
        ));
        let message = store
            .health()
            .expect_err("an absent binary is unhealthy")
            .to_string();
        assert!(message.contains(binary), "{message}");
    }
}

#[test]
fn an_executable_on_path_is_found_and_a_directory_is_not() {
    assert!(resolve_executable(Path::new("/bin/sh")).is_some());
    assert!(resolve_executable(Path::new("/bin")).is_none());
    assert!(resolve_executable(Path::new("sh")).is_some());
}
