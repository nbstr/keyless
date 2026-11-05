use crate::cmd::doctor::tests::{Named, flat, loaded, report};
use crate::store::Registry;

/// The detail column of one row of a computed set, by store id.
fn detail_of(rows: &[super::StoreRow], id: &str) -> String {
    rows.iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("no `{id}` row was produced"))
        .detail
        .clone()
}

/// Rows for a config in which every KNOWN backend is dormant.
///
/// The live store carries a backend id this build has never heard of, which
/// is what keeps all four known rows dormant while still leaving something
/// answering — a set that is dormant end to end is reported as the single
/// `(none) absent` summary instead of as rows, and there would be nothing to
/// read.
fn dormant_rows(json: &str) -> Vec<super::StoreRow> {
    let load = loaded(json);
    super::store_rows(
        &load.config,
        &Registry::new(vec![Box::new(Named("elsewhere"))]),
    )
}

#[test]
fn a_dormant_row_says_which_of_the_silences_it_is() {
    // Three silences that used to look identical, and each sends the reader
    // somewhere different: the daemon serves this machine, you switched this
    // store off, or the config enables it and this registry did not build it
    // — the last of which means the line the reader would go and edit is
    // already correct.
    //
    // The daemon is the one that is decided by its own question rather than
    // by an `enabled` flag, and the test that its row is chosen BY ID is the
    // whole of this case: with that comparison inverted every other backend
    // is answered as though it were the daemon, and the daemon is answered
    // with a sentence about a config key nobody wrote.
    //
    // The socket is named explicitly and points nowhere, so this asserts on
    // the config in front of it rather than on whether a daemon happens to
    // be running on the machine executing the suite.
    let enabled = dormant_rows(
        r#"{"stores":{"keychain":{"enabled":true},
                      "infisical":{"enabled":true},
                      "onepassword":{"enabled":true},
                      "proton":{"enabled":true},
                      "daemon":{"enabled":false,
                                "socket":"/nonexistent/keyless-doctor/daemon.sock"}},
            "secrets":{}}"#,
    );
    for id in ["keychain", "infisical", "onepassword", "proton"] {
        assert_eq!(
            detail_of(&enabled, id),
            "enabled here, but this registry did not construct it",
            "`{id}` is enabled in this config, so `you switched it off` would \
             send the reader to edit a line that is already right"
        );
    }
    assert_eq!(
        detail_of(&enabled, "daemon"),
        "not enabled in this config",
        "the daemon row is chosen by the store's id, and it is the one row \
         that has no `enabled` sentence to give"
    );

    // The other silence, from the same function: a store the reader really
    // did switch off. Without this the assertions above hold for a row that
    // never reads the flag at all.
    let off = dormant_rows(
        r#"{"stores":{"keychain":{"enabled":false},
                      "daemon":{"enabled":false,
                                "socket":"/nonexistent/keyless-doctor/daemon.sock"}},
            "secrets":{}}"#,
    );
    assert_eq!(
        detail_of(&off, "keychain"),
        "\"enabled\": false under `stores.keychain`"
    );

    // And the third, which outranks both: with the daemon serving, a local
    // store is suppressed rather than off.
    let served = dormant_rows(
        r#"{"stores":{"keychain":{"enabled":true},
                      "daemon":{"enabled":true,
                                "socket":"/nonexistent/keyless-doctor/daemon.sock"}},
            "secrets":{}}"#,
    );
    assert_eq!(
        detail_of(&served, "keychain"),
        "suppressed: the daemon serves every name on this machine"
    );
}

#[test]
fn a_dormant_detail_reaches_the_report_a_person_reads() {
    // The rows above are a computed set; this is the render. A detail column
    // that never left `store_rows` would be a fact the reader never gets.
    let load = loaded(
        r#"{"stores":{"keychain":{"enabled":true},
                      "daemon":{"enabled":false,
                                "socket":"/nonexistent/keyless-doctor/daemon.sock"}},
            "secrets":{}}"#,
    );
    let (text, _) = report(
        &load,
        Registry::new(vec![Box::new(Named("elsewhere"))]),
        false,
    );
    assert!(
        flat(&text).contains("enabled here, but this registry did not construct it"),
        "{text}"
    );
}
