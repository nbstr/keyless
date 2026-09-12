//! What a session can learn about the names behind the daemon.
//!
//! # The defect this file is the control for
//!
//! `Op::Names` had a handler in the daemon and no sender anywhere in the crate,
//! so `keyless ls` on a machine whose secrets live behind the daemon printed
//! NOTHING — on exactly the installs where the session's own config is empty by
//! design and the listing is the only way to find out a name exists.
//!
//! Every assertion here is about NAMES. A client may learn what the daemon will
//! serve; it may never learn what a store HOLDS, which is why no test below
//! looks for a vault, a title, a field or a count.

#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod support;

use keyless::cmd::ls::ls;
use keyless::config::Config;

use std::path::Path;
use std::time::{Duration, Instant};

use keyless::daemon::config::DaemonConfig;
use keyless::ipc::client::Client;
use keyless::ipc::protocol::{Reply, Request};
use keyless::store::{Invocation, Resolution, build};

use support::{
    Backend, client_config, daemon_config, policy_allowing_self, scratch, set_catalogue_listing,
    short_socket_path, start_daemon, stub_pass_cli_catalogue, write_secrets,
};

/// The value the stand-in vendor injects. Never asserted against a store's
/// config — only against what came back through the socket.
const DECOY: &str = "decoy-Cat4-derived-name-answered-0912";

/// One vault, which is what the mint's `vault` coordinate is taken from.
const ONE_VAULT: &str = r#"{"vaults":[{"name":"personal","id":"V1"}]}"#;

/// A listing holding the titles named, all live.
fn listing_of(titles: &[&str]) -> String {
    let items: Vec<String> = titles
        .iter()
        .enumerate()
        .map(|(nth, title)| {
            // The id is bound rather than interpolated inline, so the literal
            // below reads as a template to `tests/publication.rs`'s coordinate
            // scanner. A spelled-out `It3m{nth}` is not a metavariable there and
            // lands as an unallowlisted coordinate.
            let id = format!("It3m{nth}");
            format!(
                r#"{{"id":"{id}","share_id":"ShAr3","state":"Active","title":"{title}","item_type":"login"}}"#
            )
        })
        .collect();
    format!(r#"{{"items":[{}]}}"#, items.join(","))
}

/// A daemon over one Proton vault and an EMPTY `secrets` map.
///
/// Empty on purpose: every name these cases resolve is one nobody declared, so
/// a fixture with declarations would prove nothing about deriving them.
///
/// The listing TTL is the crate's own default, deliberately. It was 1 ms here
/// while the rebuilder still read through the shared cache like any other
/// reader, and that hid the defect rather than testing around it: on a real
/// install the default is 60 s, so a rebuild queued by a miss would have spent
/// a minute reading a listing fetched before the item existed. The rebuilder's
/// own adapter now refuses a cached listing, so the fixture no longer needs a
/// TTL nobody runs with.
fn daemon_over(dir: &Path, vendor: &Path) -> DaemonConfig {
    support::publish_generation(&dir.join("session"));
    let credentials = dir.join("proton.json");
    write_secrets(
        &credentials,
        &[("AGENT_TOKEN", "token-decoy"), ("LOCAL_KEY", "key-decoy")],
    );
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "credentials_file":"{credentials}",
                                   "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN",
                                                   "PROTON_PASS_ENCRYPTION_KEY":"LOCAL_KEY"}},
                                   "timeout_ms":60000}}}},
             "secrets":{{}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = dir.join("session").display(),
        credentials = credentials.display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

/// A resolution in one word.
///
/// [`Resolution`] carries a [`keyless::secret::Secret`] and so implements no
/// `Debug` — which is the point of that type. A panic message needs a word for
/// which arm came back, and this is it, with nothing from inside the arm.
fn arm(resolution: &Resolution) -> &'static str {
    match resolution {
        Resolution::Found { .. } => "found",
        Resolution::NotFound { .. } => "not-found",
        Resolution::Failed { .. } => "failed",
        Resolution::Ambiguous { .. } => "ambiguous",
    }
}

/// How long the vendor tallies must sit still before a rebuild is called done.
///
/// Sized against ONE gap: a rebuild is a `vault list` and then one `item list`
/// per vault, so the longest a running rebuild can leave the tallies unmoved is
/// the time to spawn one stub process. The worker's idle wait is unbounded and
/// wakes on its condvar, so there is no polling interval to cover any more —
/// this was 750 ms against a 250 ms `WORKER_POLL` that no longer exists, and it
/// stays there as headroom for a loaded machine rather than as a number derived
/// from anything.
///
/// A ceiling, never a measurement: a machine slower than this goes RED at the
/// deadline in [`settle`] rather than green.
const QUIET: Duration = Duration::from_millis(750);

/// Wait until no rebuild is running or pending.
///
/// # Why waiting for the NAME is not enough
///
/// `wait_until_served` returns the moment an index containing the name exists,
/// which says nothing about whether another rebuild is still in flight — and
/// while no index exists at all, every `Op::Names` the poll sends queues one.
/// A test that mutated the vault at that point could have its change read by a
/// rebuild it did not ask for, and its first resolve would then HIT: the case
/// would report a pass having proved nothing about the retry.
///
/// The observable is the stub's own spawn tallies. Two conditions together:
/// the two counts are EQUAL, which rules out a rebuild sitting between its
/// vault listing and its item listing, and neither has moved for [`QUIET`],
/// which rules out one starting. After that the only producers left are a
/// resolve miss and an `Op::Names` over a daemon with no index, and the caller
/// controls both.
fn settle(dir: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let before = (support::vault_list_count(dir), support::listing_count(dir));
        std::thread::sleep(QUIET);
        let after = (support::vault_list_count(dir), support::listing_count(dir));
        if before == after && after.0 == after.1 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the vendor tallies never settled: {before:?} then {after:?}"
        );
    }
}

/// Wait until the daemon lists `name`, or give up.
///
/// Polling the SOCKET rather than the index: a test that reached into the
/// catalogue would be asserting against the implementation, and this is the
/// only view a caller has.
fn wait_until_served(socket: &Path, name: &str) -> Vec<String> {
    let client = Client::new(socket.to_path_buf(), Duration::from_secs(3));
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = Vec::new();
    while Instant::now() < deadline {
        if let Ok(Reply::Info { names }) = client.request(&Request::names()) {
            if names.iter().any(|listed| listed == name) {
                return names;
            }
            last = names;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("`{name}` never reached the listing; it held {last:?}");
}

/// The listing, as a parser gets it.
fn listing(config: &Config) -> (String, String) {
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    ls(config, false, &mut out, &mut err).expect("writing to a Vec cannot fail");
    (
        String::from_utf8(out).expect("utf-8"),
        String::from_utf8(err).expect("utf-8"),
    )
}

#[test]
fn ls_over_an_empty_session_config_prints_what_the_daemon_serves() {
    let dir = scratch("ls-serves");
    let mut config = daemon_config(&dir);
    config.secrets.insert(
        "DECLARED_BEHIND_THE_DAEMON".to_owned(),
        serde_json::from_str(r#"{"store":"file"}"#).expect("valid"),
    );
    write_secrets(
        &config.stores.file.path,
        &[("DECLARED_BEHIND_THE_DAEMON", "unread-by-this-test")],
    );
    let running = start_daemon(&config, policy_allowing_self());

    // The session's own config declares no secret at all — the case that
    // printed an empty listing before `Request::names` existed.
    let session = client_config(running.socket(), 3_000);
    assert!(
        session.secrets.is_empty(),
        "the fixture must declare nothing"
    );

    let (listed, complaints) = listing(&session);
    assert!(complaints.is_empty(), "{complaints}");

    let row = listed
        .lines()
        .find(|line| line.starts_with("DECLARED_BEHIND_THE_DAEMON"))
        .unwrap_or_else(|| panic!("the daemon's name is not in the listing:\n{listed}"));
    let fields: Vec<&str> = row.split('\t').collect();
    // The four-field contract is load-bearing and unchanged: a daemon row says
    // `daemon` and then says nothing, because location and note would both be
    // things the client is not allowed to learn.
    assert_eq!(fields.len(), 4, "{row}");
    assert_eq!(fields[1], "daemon", "{row}");
    assert_eq!(fields[2], "-", "{row}");
    assert_eq!(fields[3], "-", "{row}");

    // The negative control for the whole file: the value the daemon holds for
    // that name is not in the listing, and neither is the store path.
    assert!(!listed.contains("unread-by-this-test"), "{listed}");
}

#[test]
fn a_daemon_that_cannot_answer_leaves_the_local_listing_standing() {
    // An absent daemon must not turn a listing into an error: a hard failure
    // here reads as an empty vault, which is the one wrong answer.
    let dir = scratch("ls-absent");
    let mut session = client_config(&dir.join("nothing-is-bound-here.sock"), 300);
    session.secrets.insert(
        "LOCAL".to_owned(),
        serde_json::from_str(r#"{"note":"still mine"}"#).expect("valid"),
    );

    let (listed, complaints) = listing(&session);
    assert!(listed.starts_with("LOCAL"), "{listed}");
    assert!(listed.contains("still mine"), "{listed}");
    assert!(
        complaints.contains("could not say what it serves"),
        "the degrade is said once, on stderr: {complaints:?}"
    );
}

#[test]
fn an_item_added_after_the_daemon_started_is_usable_after_one_retry() {
    // C1, and the whole point of the effort: no `sudo`, no restart, and no
    // edit to a root-owned config between the miss and the value.
    let dir = scratch("catalogue-new-item");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["decoy"]),
        "{}",
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = build(&client, &Invocation::default()).registry;

    // The daemon enumerates FIRST, so the listing it holds is already cached
    // when the vault changes. Without that the case is vacuous: a rebuild with
    // nothing cached fetches fresh whatever the rules are, and the defect this
    // is written against is a rebuild reading a listing older than the question
    // that queued it. At the crate's default TTL that is a full minute of a
    // daemon unable to learn what it was started to learn.
    wait_until_served(running.socket(), "DECOY");
    // And then until nothing is still enumerating. Rewriting the fixture under
    // a rebuild that is already running lets it read the new listing, and the
    // first resolve below then HITS — the assertion would fail, correctly,
    // having proved nothing.
    settle(&dir);
    // One enumeration, not one per poll. `Op::Names` asks for a rebuild
    // whenever it finds no index, and the worker clears the request when it
    // TAKES it — so without the in-flight guard every poll of the wait above
    // bought another whole vault walk, and each of those is a permanent
    // off-machine audit entry. It is also what made this case racy: a second
    // rebuild still running when the fixture changed read the new listing.
    assert_eq!(
        support::vault_list_count(&dir),
        1,
        "priming the index cost more than one enumeration"
    );

    // Somebody adds an item to the vault. Nothing else happens: the daemon is
    // not signalled, not restarted, and its config is not touched.
    set_catalogue_listing(&dir, &listing_of(&["decoy", "decoy alpha"]));

    // The first ask misses — the index was built before the item existed.
    let first = registry.resolve("DECOY_ALPHA");
    assert!(
        !matches!(first, Resolution::Found { .. }),
        "the fixture must start from a genuine miss: {}",
        arm(&first)
    );

    // That miss is what queues the rebuild. Once it lands, the name is served.
    let served = wait_until_served(running.socket(), "DECOY_ALPHA");
    assert!(served.contains(&"DECOY".to_owned()), "{served:?}");

    match registry.resolve("DECOY_ALPHA") {
        Resolution::Found { secret, store } => {
            assert_eq!(secret.expose(), DECOY);
            assert_eq!(store, "daemon");
        }
        other => panic!("the retry after the rebuild must resolve: {}", arm(&other)),
    }
}

#[test]
fn two_items_minting_one_name_are_refused_without_asking_any_store() {
    // C4. The assertion that matters is the ABSENCE of a vendor `run`: a
    // first-wins ambiguity would hand back a real credential that is the wrong
    // credential, and nothing downstream could tell.
    let dir = scratch("catalogue-ambiguous");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["my-key", "My Key", "other-key"]),
        "{}",
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = build(&client, &Invocation::default()).registry;

    // Enumerate first, so the miss below is a decision about a name the daemon
    // knows two items mint — not a name it has never heard of.
    let served = wait_until_served(running.socket(), "OTHER_KEY");
    assert!(
        !served.contains(&"MY_KEY".to_owned()),
        "a name the daemon refuses must not be listed: {served:?}"
    );

    let refused = registry.resolve("MY_KEY");
    assert!(
        !matches!(refused, Resolution::Found { .. }),
        "a colliding name must not resolve: {}",
        arm(&refused)
    );
    // No `run` was created. `pass-cli.argv` is written by the stub's run branch
    // and by nothing else, so its absence is the assertion — the same shape
    // `tests/daemon_proton.rs` argues for an undeclared name.
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a colliding name reached the vendor"
    );

    // The control: a non-colliding name from the same listing still resolves,
    // so the case above is about the collision and not about a broken fixture.
    match registry.resolve("OTHER_KEY") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), DECOY),
        other => panic!("the collision must not spread: {}", arm(&other)),
    }
    assert!(dir.join("pass-cli.argv").exists());
}

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
    let vendor = support::stub_pass_cli_dead_session(&dir);
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

/// The string sitting in every value position of the view fixture below.
///
/// A field view is the one enumeration that reads an item's CONTENT, so it is
/// the only place a value could ride out into a name. Distinct and
/// recognisable, so its absence from the listing is an assertion rather than a
/// hope.
const VIEW_LEAK: &str = "decoy-Cat4-never-in-a-listing-0912";

#[test]
fn a_field_nobody_could_guess_is_named_after_one_miss_and_carries_no_value() {
    // The case with no other route to it: a field whose label nobody would
    // guess from the item's name — on the live machine an accented French one —
    // serves a name no caller derives from anything they hold. Stage two is
    // fetched for THIS item only, and only because a miss inverted onto its
    // title. The label here is a decoy from the allowlist rather than the live
    // one: a coordinate naming anything in a real account must not be in this
    // repository, and the character classes that make the rule hard are pinned
    // in `tests/catalogue.rs` instead, where nothing is a coordinate.
    let dir = scratch("catalogue-field-view");
    let view = format!(
        r#"{{"item":{{"id":"It3mOne","share_id":"ShAr3","state":"Active","revision":2,
            "content":{{"item_uuid":"UU1D","title":"demo api key",
              "note":"{VIEW_LEAK}",
              "extra_fields":[{{"name":"Expiry Date","content":{{"Hidden":"{VIEW_LEAK}"}}}}]}}}}}}"#
    );
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["demo api key"]),
        &view,
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = build(&client, &Invocation::default()).registry;

    // Stage one. No field view has been fetched yet, and that is the point:
    // reading every item's fields on every rebuild would be one vendor call per
    // item, each a permanent off-machine audit entry.
    wait_until_served(running.socket(), "DEMO_API_KEY");
    assert_eq!(
        support::view_count(&dir),
        0,
        "stage two ran before anything asked for it"
    );

    // A caller guesses the English name and misses. That miss inverts onto a
    // live title, so it is the one thing that buys a field view.
    let guess = registry.resolve("DEMO_API_KEY__EXPIRES");
    assert!(
        !matches!(guess, Resolution::Found { .. }),
        "the guess must miss: {}",
        arm(&guess)
    );

    let served = wait_until_served(running.socket(), "DEMO_API_KEY__EXPIRY_DATE");
    assert!(support::view_count(&dir) >= 1, "no field view was fetched");

    // C3 over the one enumeration that touches content: the view fixture holds
    // the marker in every value position, and neither it nor its length reaches
    // the listing.
    let rendered = served.join(",");
    assert!(!rendered.contains(VIEW_LEAK), "{rendered}");
    assert!(
        !rendered.contains(&VIEW_LEAK.len().to_string()),
        "the length of a value reached the listing: {rendered}"
    );

    match registry.resolve("DEMO_API_KEY__EXPIRY_DATE") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), DECOY),
        other => panic!("a derived field name must resolve: {}", arm(&other)),
    }
}
