use super::parse;

/// A config that says nothing about the loop gets one that is off, so an
/// upgrade cannot start replacing a session an operator manages by hand.
#[test]
fn the_session_loop_is_off_and_tuned_under_the_cap_by_default() {
    let session = parse("{}").stores.proton.session;
    assert!(!session.auto_login);
    assert_eq!(session.login_after_minutes, 90);
    assert!(
        session.login_after_minutes < crate::daemon::config::renewal::PROTON_SESSION_CAP_MINUTES
    );
    assert_eq!(session.probe_interval_seconds, 300);
    assert_eq!(session.min_backoff_seconds, 1);
    assert_eq!(session.max_backoff_seconds, 300);
}

#[test]
fn the_session_loop_reads_every_field_an_operator_writes() {
    let session = parse(
        r#"{"stores":{"proton":{"session":{"auto_login":true,"login_after_minutes":60,
               "probe_interval_seconds":60,"min_backoff_seconds":2,"max_backoff_seconds":60}}}}"#,
    )
    .stores
    .proton
    .session;
    assert!(session.auto_login);
    assert_eq!(session.login_after_minutes, 60);
    assert_eq!(session.probe_interval_seconds, 60);
    assert_eq!(session.min_backoff_seconds, 2);
    assert_eq!(session.max_backoff_seconds, 60);
}

/// Silence while the loop is off: none of these numbers does anything, so
/// warning about them would train an operator to ignore the list.
#[test]
fn a_mistuned_loop_that_is_off_warns_about_nothing() {
    let config = parse(
        r#"{"stores":{"proton":{"session":{"login_after_minutes":600,
               "probe_interval_seconds":99999}}}}"#,
    );
    assert!(config.session_warnings().is_empty());
}

#[test]
fn renewing_at_or_past_the_vendor_cap_is_warned_about() {
    let config = parse(
        r#"{"stores":{"proton":{"enabled":true,"session":{"auto_login":true,
               "login_after_minutes":120}}}}"#,
    );
    let said = config.session_warnings().join("\n");
    assert!(said.contains("login_after_minutes"), "{said}");
    assert!(said.contains("120-minute cap"), "{said}");
}

#[test]
fn a_probe_slower_than_the_renewal_age_is_warned_about() {
    let config = parse(
        r#"{"stores":{"proton":{"enabled":true,"session":{"auto_login":true,
               "login_after_minutes":90,"probe_interval_seconds":5400}}}}"#,
    );
    let said = config.session_warnings().join("\n");
    assert!(said.contains("probe_interval_seconds"), "{said}");
}

#[test]
fn a_backoff_ceiling_below_its_floor_is_warned_about() {
    let config = parse(
        r#"{"stores":{"proton":{"enabled":true,"session":{"auto_login":true,
               "min_backoff_seconds":60,"max_backoff_seconds":10}}}}"#,
    );
    let said = config.session_warnings().join("\n");
    assert!(said.contains("max_backoff_seconds"), "{said}");
}

/// The arrangement that keeps nothing alive while reading as configured.
#[test]
fn asking_for_the_loop_on_a_disabled_store_is_warned_about() {
    let config = parse(r#"{"stores":{"proton":{"session":{"auto_login":true}}}}"#);
    let said = config.session_warnings().join("\n");
    assert!(said.contains("stores.proton.enabled"), "{said}");
}
