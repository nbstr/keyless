use super::KNOWN;
use super::probe::sole_store;
use crate::config::Config;

#[test]
fn the_detection_config_isolates_one_backend_at_a_time() {
    for id in KNOWN {
        let on = crate::store::enabled_stores(&sole_store(&Config::default(), id));
        assert_eq!(on, vec![id], "detecting `{id}` enabled {on:?}");
    }
}

#[test]
fn isolating_a_backend_keeps_every_coordinate_the_probe_needs() {
    // The defect: isolation was performed by BUILDING a config from a
    // literal string rather than by switching flags on the real one, so
    // every probe ran with no `secrets`, no `project_id` and no
    // `session_dir`. Infisical's health check reads an `env` off a declared
    // name and Proton's reads `session_dir`, so both reported a fault that
    // was an artefact of the probe — and `doctor`, reading the same file,
    // contradicted them minutes later.
    let mine: Config = serde_json::from_str(
        r#"{"stores":{"infisical":{"project_id":"proj-abc"},
                      "proton":{"session_dir":"/tmp/session"}},
            "secrets":{"DATABASE_URL":{"store":"infisical","env":"staging"}}}"#,
    )
    .expect("valid");

    for id in KNOWN {
        let probed = sole_store(&mine, id);
        assert_eq!(
            probed.stores.infisical.project_id.as_deref(),
            Some("proj-abc"),
            "probing `{id}` dropped the Infisical project"
        );
        assert!(
            probed.stores.proton.session_dir.is_some(),
            "probing `{id}` dropped the Proton session directory"
        );
        assert!(
            probed.secrets.contains_key("DATABASE_URL"),
            "probing `{id}` dropped the declared names, so no `env` can be found"
        );
    }
}

#[test]
fn an_enabled_daemon_never_answers_for_a_local_backend() {
    // The one thing isolation must genuinely discard. An enabled daemon
    // suppresses every local backend whatever its flag says, so leaving it
    // on would make all three DETECTED rows describe the daemon.
    let mut with_daemon = Config::default();
    with_daemon.stores.daemon.enabled = true;
    for id in KNOWN {
        let on = crate::store::enabled_stores(&sole_store(&with_daemon, id));
        assert_eq!(on, vec![id], "the daemon answered for `{id}`");
    }
}
