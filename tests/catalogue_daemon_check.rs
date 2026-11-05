#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod catalogue_daemon_support;
mod support;

use std::path::Path;

use keyless::daemon::config::DaemonConfig;

use catalogue_daemon_support::{DECOY, ONE_VAULT, daemon_over, listing_of};
use support::backend::Backend;
use support::proton::stub_pass_cli_catalogue;
use support::scratch;

/// The check report, rendered with the client question deliberately
/// unanswerable — a walk of the real `PATH` would make every case here a
/// statement about the machine the suite runs on.
fn check_report(config: &DaemonConfig, dir: &Path) -> (String, bool) {
    let mut out: Vec<u8> = Vec::new();
    let sound = keyless::daemon::check::report(
        config,
        &dir.join("keylessd.json"),
        &keyless::daemon::shadow::Client::NoPath,
        &mut out,
    )
    .expect("writing to a Vec cannot fail");
    (String::from_utf8(out).expect("utf-8"), sound)
}

#[test]
fn check_reports_an_item_nobody_declared_and_a_declaration_no_item_backs() {
    // C6, both directions in one report, because they are two readings of the
    // same comparison and a fixture that showed one at a time could not prove
    // the report makes them apart.
    let dir = scratch("check-drift");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["decoy alpha", "demo login"]),
        "{}",
    );
    let mut config = daemon_over(&dir, &vendor);
    config.secrets.insert(
        "DEMO_LOGIN".to_owned(),
        serde_json::from_str(
            r#"{"store":"proton","vault":"personal","item":"demo login","field":"password"}"#,
        )
        .expect("valid"),
    );
    config.secrets.insert(
        "RENAMED_AWAY".to_owned(),
        serde_json::from_str(
            r#"{"store":"proton","vault":"personal","item":"keyless-decoy-alpha","field":"password"}"#,
        )
        .expect("valid"),
    );

    let (rows, sound) = check_report(&config, &dir);

    // Direction one: an item the vault holds that nothing declares. Counted,
    // never a fault — it is the ordinary state now that names are derived.
    let served = rows
        .lines()
        .find(|line| line.contains("name(s) served"))
        .unwrap_or_else(|| panic!("the report says nothing about what is served:\n{rows}"));
    assert!(
        served.contains("2 declared, 1 derived"),
        "the undeclared item is not counted as derived: {served}"
    );

    // Direction two: a declaration whose item is not there any more. A fault,
    // because the config parses, the name lists, and it resolves to nothing.
    let renamed = rows
        .lines()
        .find(|line| line.contains("RENAMED_AWAY"))
        .unwrap_or_else(|| panic!("the dead declaration is not reported:\n{rows}"));
    assert!(renamed.contains("PROBLEM"), "{renamed}");
    assert!(renamed.contains("keyless-decoy-alpha"), "{renamed}");
    assert!(
        !sound,
        "a declaration that resolves to nothing was reported sound:\n{rows}"
    );

    // The control: the declaration that IS backed is not reported at all, so
    // the case above is about the drift and not about a check that complains
    // about every declaration.
    assert!(
        !rows.lines().any(|line| line.contains("DEMO_LOGIN")),
        "a healthy declaration was reported as drift:\n{rows}"
    );
}

#[test]
fn check_names_the_colliding_titles_that_the_socket_may_not() {
    // Root-side, against the daemon's own config, is the one place a title may
    // be printed — and it is the only way an operator can act on a collision
    // the socket reports as a store id and a count.
    let dir = scratch("check-collision");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["my-key", "My Key"]),
        "{}",
    );
    let config = daemon_over(&dir, &vendor);
    let (rows, sound) = check_report(&config, &dir);

    let clash = rows
        .lines()
        .find(|line| line.contains("MY_KEY"))
        .unwrap_or_else(|| panic!("the collision is not reported:\n{rows}"));
    assert!(clash.contains("PROBLEM"), "{clash}");
    assert!(
        clash.contains("my-key") && clash.contains("My Key"),
        "{clash}"
    );
    assert!(!sound, "{rows}");
}

#[test]
fn a_store_that_cannot_be_enumerated_is_unproven_and_not_a_fault() {
    // The distinction `client_row` already draws: a comparison nobody could
    // make must not read as one that passed, and must not read as one that
    // failed either. Without this, an outage would report every declared name
    // as pointing at nothing.
    let dir = scratch("check-unproven");
    let vendor = support::proton::stub_pass_cli_dead_session(&dir);
    let mut config = daemon_over(&dir, &vendor);
    config.secrets.insert(
        "DECLARED".to_owned(),
        serde_json::from_str(
            r#"{"store":"proton","vault":"personal","item":"decoy","field":"password"}"#,
        )
        .expect("valid"),
    );

    let (rows, _) = check_report(&config, &dir);
    // The state is read as a WHOLE column, never as a substring: `unproven`
    // contains `proven`, so a `contains` check here could not fail on the
    // change it is named for.
    let unproven = rows
        .lines()
        .filter(|line| line.split_whitespace().next() == Some("catalog"))
        .find(|line| line.split_whitespace().nth(2) == Some("unproven"))
        .unwrap_or_else(|| panic!("an unenumerable store must say so:\n{rows}"));
    assert_eq!(
        unproven.split_whitespace().nth(1),
        Some("proton"),
        "{unproven}"
    );
    // And its declared names are left uncompared rather than condemned.
    assert!(
        !rows.lines().any(|line| line.contains("DECLARED")),
        "a declared name was condemned by a comparison nobody could make:\n{rows}"
    );
}
