use super::{SCOPED, ambient, argv_of, parts_store, record, scratch, store_from};
use crate::store::proton::environment::{REASON_VAR, SESSION_DIR_VAR, assert_vendor_switch_offs};
use crate::store::proton::listing::{
    ItemListing, ItemRecord, Listed, MAX_LISTING_TTL_MS, bounded_listing_ttl,
};
use crate::store::proton_session::Generations;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn the_listing_asks_one_vault_for_json_and_never_asks_for_content() {
    // `--show-secrets` is the flag that would make this verb print values.
    // It is refused for agent sessions, and it is never passed here either
    // way: this adapter reads coordinates, and the value comes back through
    // `run` where it never touches stdout.
    //
    // The exact argv, rather than a check per forbidden flag: a full match
    // implies every one of them is absent, and it is the same command
    // `assert_vendor_switch_offs` checks below rather than a second one
    // built just for that.
    //
    // Named AND joined. Naming the flag stops the vault being taken as a
    // positional; joining it with `=` stops a vault whose name starts with
    // `-` being read as a short-flag cluster. Two separate arguments do only
    // the first, and the vendor refuses that outright.
    let store = store_from("{}");
    let command = store.list_command(Path::new(SCOPED), "personal", "X", &[], ambient());
    assert_eq!(
        argv_of(&command),
        vec![
            "pass-cli",
            "item",
            "list",
            "--vault-name=personal",
            "--output",
            "json",
        ]
    );
    assert_vendor_switch_offs(&command);
}

#[test]
fn the_listing_runs_under_the_configured_session_and_carries_a_reason() {
    // A listing read as the full account would enumerate items the scoped
    // agent cannot read, so "no such item" would turn into a denial at the
    // value read — the same failure the session pin exists to prevent, one
    // step earlier.
    let store = store_from("{}");
    let command = store.list_command(Path::new(SCOPED), "personal", "DECOY", &[], ambient());
    let env: Vec<(String, Option<String>)> = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();

    let session = env.iter().find(|(key, _)| key == SESSION_DIR_VAR);
    assert_eq!(
        session.and_then(|(_, value)| value.as_deref()),
        Some(SCOPED)
    );

    let reason = env
        .iter()
        .find(|(key, _)| key == REASON_VAR)
        .and_then(|(_, value)| value.clone())
        .expect("the listing must carry a reason of the same shape");
    assert!(reason.contains("DECOY"), "{reason}");
    assert!(!reason.trim().is_empty());
}

#[test]
fn an_ambient_reference_is_taken_out_of_the_listings_environment_too() {
    // Built through `list_command`, not by calling the filter: the probe's
    // version of this test went green once after its call site was deleted,
    // because it exercised the function rather than the command builder.
    let store = store_from("{}");
    let removed: Vec<String> = store
        .list_command(Path::new(SCOPED), "personal", "X", &[], ambient())
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    assert!(removed.contains(&"A_REFERENCE".to_owned()), "{removed:?}");
    assert!(removed.contains(&"EMBEDDED".to_owned()), "{removed:?}");
    assert!(!removed.contains(&"PLAIN".to_owned()), "{removed:?}");
}

#[test]
fn a_trashed_item_is_not_active_and_an_unknown_state_is_not_either() {
    // An allowlist, not a denylist: a state this build has never seen must
    // fail closed, because the alternative is injecting a value whose owner
    // believes it is gone.
    let record = |state: &str| ItemRecord {
        state: state.to_owned(),
        ..record()
    };
    assert!(record("Active").is_active());
    assert!(record("active").is_active());
    assert!(!record("Trashed").is_active());
    assert!(!record("PendingDeletion").is_active());
    assert!(!record("").is_active());
}

#[test]
fn a_listing_ttl_is_clamped_so_no_config_can_switch_the_expiry_off() {
    // The trash rule above is only ever consulted against a listing, so a
    // `listing_ttl_ms` big enough to outlive any process would delete that
    // rule by arithmetic. Zero is the other end and is honest: list again
    // every time.
    assert_eq!(bounded_listing_ttl(0), Duration::ZERO);
    assert_eq!(bounded_listing_ttl(1_500), Duration::from_millis(1500));
    assert_eq!(
        bounded_listing_ttl(MAX_LISTING_TTL_MS),
        Duration::from_millis(MAX_LISTING_TTL_MS)
    );
    assert_eq!(
        bounded_listing_ttl(u64::MAX),
        Duration::from_millis(MAX_LISTING_TTL_MS),
        "a config named a number large enough to mean `never`"
    );
}

#[test]
fn the_default_config_gives_the_listing_cache_a_bounded_ttl() {
    // The default is what every run and every future long-lived holder gets
    // without asking, so it is the value that has to be bounded — not just
    // the clamp that catches an operator naming a silly one.
    let ttl = bounded_listing_ttl(crate::config::ProtonConfig::default().listing_ttl_ms);
    assert!(ttl > Duration::ZERO, "the default lists again every lookup");
    assert!(
        ttl <= Duration::from_millis(MAX_LISTING_TTL_MS),
        "the default is not bounded: {ttl:?}"
    );
}

#[test]
fn a_listing_cached_under_one_generation_is_not_reused_under_the_next() {
    // A renewal changes which identity a session DIRECTORY serves without
    // changing its path, so the generation is the only signal that a
    // listing has gone stale for the reason a renewal makes it stale — the
    // trash rule this cache carries is only as good as knowing when to
    // refetch.
    let dir = scratch("listing-per-generation");
    let generations = Arc::new(Generations::at(dir.clone()));
    let (a, _) = generations.create(None).expect("create A");
    generations.publish(&a, None).expect("publish A");

    // `/nonexistent/pass-cli` — a cache HIT never spawns it, and a cache
    // MISS fails loudly rather than silently, which is what tells the two
    // states apart without a working vendor binary.
    let store = parts_store()
        .in_session_dir(Some(dir.clone()))
        .with_generations(Some(Arc::clone(&generations)));

    let vault = "company";
    let slot = Arc::clone(store.cache().entry(vault.to_owned()).or_default());
    *slot.lock().expect("lock the fresh slot") = Some(Listed {
        items: Arc::new(Vec::new()),
        at: Instant::now(),
        generation: Some(a.clone()),
        logins: 0,
    });

    let pass_a = store.enter().expect("a pass over A");
    assert!(
        store.cached_items(&pass_a, vault, "X").is_ok(),
        "a listing cached under the current generation was refetched anyway"
    );
    drop(pass_a);

    let (b, _) = generations.create(None).expect("create B");
    generations.publish(&b, None).expect("publish B");

    let pass_b = store.enter().expect("a pass over B");
    assert!(
        store.cached_items(&pass_b, vault, "X").is_err(),
        "a listing cached under A answered a read scoped at the next generation, B"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_listing_record_reads_the_item_id_from_id_and_not_from_item_id() {
    // Measured 2026-08-08: the record has `id`, `share_id`, `vault_id`,
    // `state`, `flags`, `create_time`, `modify_time`, `title`, `item_type`.
    // There is no `item_id`, so a reference built from one would be empty.
    let listing: ItemListing = serde_json::from_str(
        r#"{"items":[{"id":"ITEM1","share_id":"SHARE1","vault_id":"V","state":"Active",
                      "flags":[],"create_time":"2000-01-01T00:00:00",
                      "modify_time":"2000-01-01T00:00:01","title":"decoy",
                      "item_type":"login"}]}"#,
    )
    .expect("the vendor's shape must parse");
    assert_eq!(listing.items.len(), 1);
    assert_eq!(listing.items[0].id, "ITEM1");
    assert_eq!(listing.items[0].share_id, "SHARE1");
    assert!(listing.items[0].is_active());
}

// -----------------------------------------------------------------------
// `vault list`: every vault this identity can see. No item content of any
// kind, so this is the one builder above with no `name` to carry a reason.
// `vault_list_command` has exactly the two tests below, so neither builds
// a shared `vault_list_argv` helper: one caller each is inlined.
// -----------------------------------------------------------------------

#[test]
fn vault_list_asks_for_json_and_carries_no_show_secrets() {
    let store = store_from("{}");
    let argv = argv_of(&store.vault_list_command(Path::new(SCOPED), &[], ambient()));
    assert_eq!(
        argv,
        vec!["pass-cli", "vault", "list", "--output", "json"],
        "{argv:?}"
    );
}

#[test]
fn vault_list_switches_off_the_vendors_telemetry_and_update_check() {
    // `vault_list_command` had no test at all before the two variables
    // below were added, so this stays its own test rather than folding
    // into the one above: there is no pre-existing construction to share.
    let store = store_from("{}");
    let command = store.vault_list_command(Path::new(SCOPED), &[], ambient());
    assert_vendor_switch_offs(&command);
}

// -----------------------------------------------------------------------
// `fields`: the one path in this crate where a value enters the process.
// -----------------------------------------------------------------------
