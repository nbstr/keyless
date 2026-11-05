//! Proton items addressed by name, resolved to this session's ids at lookup.

mod stores_support;
mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use keyless::State;
use keyless::store::proton::Reason;

use support::{
    Backend, Listing, PROTON_DECOY, SCOPED_SESSION_DIR, install_executable, listing_count,
    recorded, recorded_lines, run_with, scratch, stub_pass_cli_listing, witness, witnessed,
};

use stores_support::{PROTON_REFERENCE, registry_from};

const EX_USAGE: i32 = 64;

// ---------------------------------------------------------------------------
// The name form: a stable address, resolved to this session's ids at lookup.
//
// A share id is minted per session — measured 2026-08-08, one vault answered
// with two different ids to two live sessions of one account — so an address
// made of ids cannot survive a token renewal. These cover the address that can:
// vault name, item title, field. Every one runs through `run`, so the
// never-block invariant is asserted alongside the rule, and a rule that
// "refuses" is checked by the CLI's `run` verb never being spawned at all.
// ---------------------------------------------------------------------------

/// A vault listing in the vendor's shape, measured 2026-08-08.
///
/// Written out by hand rather than generated: a fixture built from the
/// adapter's own idea of the record would agree with it whatever that became.
/// The item id is under `id`; there is no `item_id` key.
const ONE_LIVE_ITEM: &str = r#"{"items":[
    {"id":"It3mL1v3","share_id":"ShAr3L1v3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"}]}"#;

/// The same vault, with the only matching item in the trash.
const ONE_TRASHED_ITEM: &str = r#"{"items":[
    {"id":"It3mDead","share_id":"ShAr3L1v3","vault_id":"V","state":"Trashed","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"}]}"#;

/// Two live items sharing one title, plus a trashed third that must not count.
const TWO_LIVE_ITEMS: &str = r#"{"items":[
    {"id":"It3mOne","share_id":"ShAr3L1v3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"},
    {"id":"It3mTwo","share_id":"ShAr3L1v3","vault_id":"V","state":"Active","flags":[],
     "create_time":"2000-01-02T00:00:00","modify_time":"2000-01-02T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"},
    {"id":"It3mDead","share_id":"ShAr3L1v3","vault_id":"V","state":"Trashed","flags":[],
     "create_time":"2000-01-03T00:00:00","modify_time":"2000-01-03T00:00:01",
     "title":"keyless-decoy-alpha","item_type":"login"}]}"#;

/// A config whose names are addressed by vault, title and field.
fn named_config(binary: &Path, secrets: &str) -> String {
    named_config_extra(binary, secrets, "")
}

/// The same, with `proton_extra` spliced into the `stores.proton` block.
///
/// Written as raw JSON rather than as a typed builder so the tests below state
/// the file an operator writes, which is the only form this crate promises.
fn named_config_extra(binary: &Path, secrets: &str, proton_extra: &str) -> String {
    format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","session_dir":"{SCOPED_SESSION_DIR}",
                        "timeout_ms":60000{proton_extra}}}}},
            "secrets":{secrets}}}"#,
        binary.display()
    )
}

/// The one name most fixtures below declare, addressed by name.
const DECOY_BY_NAME: &str =
    r#"{"DECOY":{"vault":"personal","item":"keyless-decoy-alpha","field":"password"}}"#;

#[test]
fn a_named_item_is_addressed_by_the_ids_this_session_minted() {
    // The whole point: nothing in the config holds an id, and the reference the
    // CLI receives holds the ones the listing just reported.
    let dir = scratch("proton-named");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_LIVE_ITEM),
    );
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(outcome.state, State::Injected);
    assert_eq!(notes, "", "a successful run says nothing at all");
    assert_eq!(
        recorded(&dir.join("pass-cli.reference")).trim(),
        "pass://ShAr3L1v3/It3mL1v3/password",
        "the reference was not built from the listing this session returned"
    );

    // The listing asked for the vault the config named, and asked for nothing
    // that could print content.
    let list_argv = recorded_lines(&dir.join("pass-cli.list.argv"));
    assert!(
        list_argv.iter().any(|arg| arg == "--vault-name=personal"),
        "{list_argv:?}"
    );
    assert!(
        !list_argv.iter().any(|arg| arg == "--show-secrets"),
        "{list_argv:?}"
    );
}

#[test]
fn a_trashed_item_is_refused_and_the_command_never_runs() {
    // Resolving one would hand the child a value its owner believes they
    // deleted — and silently, since a trashed item is still listed. The `run`
    // verb must never be reached.
    let dir = scratch("proton-trashed");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_TRASHED_ITEM),
    );
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 17), &[]);

    assert!(!marker.exists(), "the child started: {notes}");
    assert_eq!(outcome.exit_code, EX_USAGE, "{notes}");
    assert_eq!(outcome.state, State::Refused);
    assert!(notes.contains("DECOY"), "{notes}");
    assert!(notes.contains("trash"), "the banner must say why: {notes}");
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "the value of a trashed item was read before it was refused"
    );
}

#[test]
fn two_live_items_with_one_title_degrade_and_name_the_candidates() {
    // The house rule for ambiguity: refuse and name the candidates, exactly as
    // `Policy::Explicit` does for two backends answering one name. Picking the
    // first would be right half the time and silent the other half.
    let dir = scratch("proton-ambiguous");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(TWO_LIVE_ITEMS),
    );
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 23), &[]);

    assert_eq!(witnessed(&marker), "<unset>", "an ambiguous title resolved");
    assert_eq!(outcome.exit_code, 23);
    assert_eq!(outcome.state, State::Degraded);
    for candidate in ["It3mOne", "It3mTwo"] {
        assert!(notes.contains(candidate), "{candidate} unnamed: {notes}");
    }
    assert!(
        !notes.contains("It3mDead"),
        "a trashed twin was counted as a candidate: {notes}"
    );
    assert!(
        notes.contains("reference"),
        "the banner must say how to pin one: {notes}"
    );
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "an ambiguous name was read from anyway"
    );
}

#[test]
fn a_title_that_is_in_no_vault_is_refused_and_the_command_never_runs() {
    // The negative control for the three above: with an empty listing they
    // could all pass on an adapter that never resolves anything at all.
    let dir = scratch("proton-no-such-item");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(&dir, &Backend::Injects(PROTON_DECOY), &Listing::EMPTY);
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 11), &[]);

    assert!(!marker.exists(), "the child started: {notes}");
    assert_eq!(outcome.exit_code, EX_USAGE, "{notes}");
    assert_eq!(outcome.state, State::Refused);
    assert!(notes.contains("keyless-decoy-alpha"), "{notes}");
    assert!(
        !notes.contains("trash"),
        "nothing was in the trash: {notes}"
    );
}

#[test]
fn a_name_with_no_proton_address_is_refused_and_the_command_never_runs() {
    let dir = scratch("proton-no-address");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_LIVE_ITEM),
    );
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(
        &registry,
        &["NEVER_DECLARED"],
        &witness(&marker, "NEVER_DECLARED", 9),
        &[],
    );

    assert!(!marker.exists(), "the child started: {notes}");
    assert_eq!(outcome.exit_code, EX_USAGE, "{notes}");
    assert_eq!(outcome.state, State::Refused);
    assert!(notes.contains("NEVER_DECLARED"), "{notes}");
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a name with no address was read from anyway"
    );
}

#[test]
fn a_vault_the_session_cannot_list_degrades_and_still_runs() {
    // An expired token, a renamed vault, a grant that was revoked. Measured
    // 2026-08-08: the CLI exits 1 and says `Could not find vault <name>`.
    let dir = scratch("proton-no-such-vault");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(&dir, &Backend::Injects(PROTON_DECOY), &Listing::NoSuchVault);
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 13), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 13);
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("personal"),
        "the banner must name the vault: {notes}"
    );
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a value was read out of a vault that could not even be listed"
    );
}

#[test]
fn declaring_both_an_address_and_a_reference_degrades_without_spawning_anything() {
    // Two answers to one question. Refused before anything runs, so the
    // ambiguity costs no vault read and leaves no audit entry.
    let dir = scratch("proton-both-forms");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_LIVE_ITEM),
    );
    let secrets = format!(
        r#"{{"DECOY":{{"vault":"personal","item":"keyless-decoy-alpha","field":"password",
                       "reference":"{PROTON_REFERENCE}"}}}}"#
    );
    let registry = registry_from(&named_config(&stub, &secrets), &Reason::default());

    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 31), &[]);

    assert_eq!(witnessed(&marker), "<unset>");
    assert_eq!(outcome.exit_code, 31);
    assert_eq!(outcome.state, State::Degraded);
    assert!(
        notes.contains("reference") && notes.contains("vault"),
        "the banner must name both forms so one can be deleted: {notes}"
    );
    assert_eq!(listing_count(&dir), 0, "a vault was enumerated anyway");
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a doubly-declared address was read from anyway"
    );
}

#[test]
fn several_names_from_one_vault_cost_exactly_one_listing() {
    // One `keyless run` routinely asks for several names, and the listing is
    // memoised for the life of the process — in memory, never on disk. Counted
    // from the stub's side, so an adapter that spawned twice fails here.
    let dir = scratch("proton-one-listing");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_listing(
        &dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(ONE_LIVE_ITEM),
    );
    let secrets = r#"{"DECOY":{"vault":"personal","item":"keyless-decoy-alpha","field":"password"},
                      "SECOND":{"vault":"personal","item":"keyless-decoy-alpha","field":"username"}}"#;
    let registry = registry_from(&named_config(&stub, secrets), &Reason::default());

    let (outcome, notes) = run_with(
        &registry,
        &["DECOY", "SECOND"],
        &witness(&marker, "SECOND", 0),
        &[],
    );

    assert_eq!(outcome.state, State::Injected, "{notes}");
    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(
        listing_count(&dir),
        1,
        "one vault was enumerated once per name instead of once per run"
    );
}

/// A `pass-cli` stand-in whose vault CHANGES after its first listing: the item
/// is `Active` the first time it is listed and `Trashed` every time after.
///
/// That is somebody emptying an item into the trash while a process that has
/// already listed the vault is still alive — the one event a memoised listing
/// cannot see, and the one the trash rule exists to catch.
///
/// Only `item list` is answered here. Everything else is handed to the ordinary
/// stub in the same directory, so a lookup that gets as far as a value still
/// records its argv, its reason and its reference where the tests above read
/// them. The tally goes to the same `pass-cli.list.count` [`listing_count`]
/// reads, so "was the vault listed again" is counted from the vendor's side.
fn stub_pass_cli_trashed_after_first_listing(dir: &Path) -> PathBuf {
    let delegate = stub_pass_cli_listing(dir, &Backend::Injects(PROTON_DECOY), &Listing::EMPTY);
    let listed_once = dir.join("pass-cli.listed-once");
    let body = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'list' ]; then\n\
         \x20 echo one >> '{count}'\n\
         \x20 if [ -e '{flag}' ]; then\n\
         \x20   printf '%s' '{trashed}'\n\
         \x20 else\n\
         \x20   : > '{flag}'\n\
         \x20   printf '%s' '{live}'\n\
         \x20 fi\n\
         \x20 exit 0\n\
         fi\n\
         exec '{delegate}' \"$@\"\n",
        count = dir.join("pass-cli.list.count").display(),
        flag = listed_once.display(),
        trashed = ONE_TRASHED_ITEM,
        live = ONE_LIVE_ITEM,
        delegate = delegate.display(),
    );
    install_executable(&dir.join("pass-cli-trashing-stub"), &body)
}

#[test]
fn a_listing_older_than_its_ttl_is_fetched_again_before_it_is_trusted() {
    // The trash rule lives in the LISTING: the reference form has none, and
    // `pass-cli run` resolves a trashed item happily — measured 2026-08-08, see
    // `keyless::config::SecretRoute::reference`. So a listing that is memoised
    // and never re-fetched is that rule switched off, silently, for as long as
    // whatever holds this adapter stays alive: the item is in the trash and the
    // cached record still says `Active`.
    let dir = scratch("proton-listing-expiry");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_trashed_after_first_listing(&dir);
    let registry = registry_from(
        &named_config_extra(&stub, DECOY_BY_NAME, r#","listing_ttl_ms":20"#),
        &Reason::default(),
    );

    let (first, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(first.state, State::Injected, "{notes}");
    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(listing_count(&dir), 1);

    // Past the TTL by a wide margin, so the assertion below is about expiry and
    // not about how long a machine took to get here.
    std::thread::sleep(Duration::from_millis(250));

    std::fs::remove_file(&marker).expect("clear the first run's witness");
    let (second, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 19), &[]);

    assert!(
        !marker.exists(),
        "a run went ahead on a listing that predates the trashing: {notes}"
    );
    assert_eq!(
        listing_count(&dir),
        2,
        "the vault was never listed again, so nothing in this process can ever \
         learn that an item was trashed"
    );
    assert_eq!(second.exit_code, EX_USAGE, "{notes}");
    assert_eq!(second.state, State::Refused);
    assert!(notes.contains("trash"), "the banner must say why: {notes}");
}

#[test]
fn a_lookup_inside_the_ttl_serves_the_cache_and_lists_nothing() {
    // The other direction, and the control that keeps the test above honest: a
    // TTL that expired instantly would satisfy it and would also undo the
    // memoisation, turning N names into N vendor spawns and N audit entries.
    //
    // The stub answers a DIFFERENT vault on its second listing, so serving the
    // first answer is positive evidence the cache was read — not the absence of
    // evidence that it was not.
    let dir = scratch("proton-listing-within-ttl");
    let marker = dir.join("witness");
    let stub = stub_pass_cli_trashed_after_first_listing(&dir);
    // The default TTL, spelled by leaving it out: a default too short to
    // survive two lookups in a row would fail here.
    let registry = registry_from(&named_config(&stub, DECOY_BY_NAME), &Reason::default());

    let (first, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(first.state, State::Injected, "{notes}");
    assert_eq!(witnessed(&marker), PROTON_DECOY);

    let (second, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);

    assert_eq!(second.state, State::Injected, "{notes}");
    assert_eq!(witnessed(&marker), PROTON_DECOY);
    assert_eq!(
        listing_count(&dir),
        1,
        "a second lookup inside the TTL listed the vault again, so the cache \
         this adapter is built around is doing nothing"
    );
}
