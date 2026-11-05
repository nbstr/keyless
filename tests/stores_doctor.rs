//! `doctor` over a network store: a dead session, and the word `proven`.

mod stores_support;
mod support;

use keyless::State;
use keyless::store::proton::Reason;

use support::{
    Backend, ONEPASSWORD_DECOY, OnePasswordListing, SCOPED_SESSION_DIR, recorded_lines, run_with,
    scratch, stub_op, stub_op_listing, stub_pass_cli_discovery, witness, witnessed,
};

use stores_support::{
    LIVE_AND_TRASHED, ONE_VAULT, ONEPASSWORD_DECOY_BY_TITLE, doctor_report, flattened, mentions,
    onepassword_config, proton_config, proton_row, registry_from, state_of,
};

// ---------------------------------------------------------------------------
// `doctor` and a dead session.
//
// Measured on 2026-08-08: with the agent session expired, `keyless doctor`
// printed `store proton ok` and `0 problem(s)` while every Proton name was
// degrading — the child ran with an empty bearer and the resulting HTTP 400
// came back at exit 0. `doctor` is the command a session is told to run to find
// that out, and `keyless run` degrades on a dead session, so nothing else on
// the machine could have said it.
// ---------------------------------------------------------------------------

#[test]
fn doctor_reports_an_expired_proton_session_as_a_problem() {
    let dir = scratch("doctor-dead-session");
    let stub = support::stub_pass_cli_dead_session(&dir);
    let (report, code) = doctor_report(&dir, &proton_config(&stub));

    // Not proven, and the row says which kind of not-proven it is. A dead
    // session is `absent` rather than `broken`: the store is installed and
    // reachable, and the identity it needs has expired — so the reader is sent
    // to a login, not to the vault.
    assert!(
        !proton_row(&report).contains("proven"),
        "a dead session was reported as proven:\n{report}"
    );
    assert_eq!(state_of(proton_row(&report)), "absent", "{report}");
    // The vendor's own words, so the reader knows which of the many ways this
    // backend fails they are looking at.
    //
    // Read against a whitespace-collapsed copy: the report wraps a long detail
    // across lines for a person to read, so a phrase can straddle a newline.
    // `doctor` is the human surface and `ls` is the parseable one — see
    // `crate::cmd::ls` for the four tab-separated fields a program should read
    // instead of this.
    let flat = report.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("authenticated client"),
        "the report did not say what the vendor said:\n{report}"
    );
    // And the fix, because "requires an authenticated client" does not tell
    // anybody which session directory to re-mint.
    // As ONE string. Asserting the command and the directory separately passes
    // on a report that names both and joins neither, which is the report that
    // cost the hours: `pass-cli login` typed without the variable in front of it
    // reaches the DEFAULT session and answers `Already authenticated`.
    assert!(
        flat.contains(&format!(
            "PROTON_PASS_SESSION_DIR={SCOPED_SESSION_DIR} pass-cli login"
        )),
        "{report}"
    );
    assert_eq!(code, 1, "{report}");
    assert!(!report.contains("0 problem(s)"), "{report}");

    // The check reached the vendor rather than concluding from the config, and
    // it asked for the one verb that reads no item content.
    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert_eq!(argv.first().map(String::as_str), Some("vault"));
    assert_eq!(argv.get(1).map(String::as_str), Some("list"));
    for forbidden in ["run", "view", "--show-secrets", "--env-file"] {
        assert!(
            !mentions(&argv, forbidden),
            "a health check asked for `{forbidden}`: {argv:?}"
        );
    }
}

#[test]
fn doctor_reports_a_live_proton_session_as_ok() {
    // The negative control for the test above. Without it, that one passes on an
    // implementation that reports every Proton store as broken, which would be a
    // false RED — the same defect wearing the other colour, and the one that
    // gets a health check deleted.
    let dir = scratch("doctor-live-session");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let (report, code) = doctor_report(&dir, &proton_config(&stub));

    assert_eq!(state_of(proton_row(&report)), "proven", "{report}");
    // And never the word that was false. `ok` said "the binary answered" while
    // reading as "your secrets are reachable"; a row is green here only because
    // a read path came back.
    assert!(!proton_row(&report).contains(" ok"), "{report}");
    assert_eq!(code, 0, "{report}");
    assert!(report.contains("0 problem(s)"), "{report}");

    // `ok` here is a claim about a live session, and the default report is
    // still allowed to make it because it MEASURED it — for the price of one
    // spawn that reads no item content. The last thing the vendor was asked
    // is the proof: `vault list`, never `run`.
    let argv = recorded_lines(&dir.join("pass-cli.argv"));
    assert_eq!(argv.first().map(String::as_str), Some("vault"));
    assert!(!mentions(&argv, "run"), "{argv:?}");

    // And the report says which question it did NOT ask. `--probe` resolves
    // every name, which READS every credential; that is why it is opt-in, and
    // why the report has to name it rather than leave the reader believing
    // `store proton ok` covers their names too.
    assert!(report.contains("not probed"), "{report}");
    assert!(report.contains("--probe"), "{report}");
}

#[test]
fn a_proton_store_with_no_session_directory_is_unhealthy_without_spawning_anything() {
    // The local preconditions still come first, and they still short-circuit.
    // A health check that spawned the vendor before noticing there is no
    // identity to ask as would report the wrong cause, and — measured
    // 2026-08-08 — `pass-cli` REINITIALISES the session database at whatever
    // path it is pointed at, so "spawn first, ask later" is not a cosmetic
    // mistake here.
    let dir = scratch("doctor-no-session");
    let stub = stub_pass_cli_discovery(&dir, ONE_VAULT, LIVE_AND_TRASHED, "{}");
    let config = format!(
        r#"{{"stores":{{"keychain":{{"enabled":false}},
             "proton":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}}}}"#,
        stub.display()
    );
    let (report, code) = doctor_report(&dir, &config);

    let state = state_of(proton_row(&report));
    assert!(
        state == "config" || state == "absent",
        "the row's state is `{state}`, and an unset session directory is either \
         a config fault or an unreachable store:\n{report}"
    );
    assert!(report.contains("session_dir"), "{report}");
    assert_eq!(code, 1, "{report}");
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "the vendor was spawned with no session directory configured"
    );
}

// ---------------------------------------------------------------------------
// The health check, and the word `proven` over it.
// ---------------------------------------------------------------------------

/// One STORES row of a rendered report, by backend id.
fn store_row<'a>(report: &'a str, id: &str) -> &'a str {
    report
        .lines()
        .find(|line| line.split_whitespace().nth(1) == Some(id))
        .unwrap_or_else(|| panic!("the report has no `{id}` row:\n{report}"))
}

#[test]
fn doctor_never_proves_a_onepassword_vault_whose_items_it_cannot_list() {
    // The defect this pins: the health check used to run `op vault get`, a verb
    // NO lookup runs — lookups run `item list` and then `run`. The vendor grants
    // a service account a vault as `--vault <name>:read_items`, an ITEM
    // permission, while `vault get` reads the vault RECORD, so a login allowed
    // one and refused the other is the ordinary arrangement rather than a
    // contrived one.
    //
    // Against exactly that stub the row read `proven` while every name degraded.
    // The two must agree, so both halves are asserted from the one fixture.
    let dir = scratch("onepassword-listable-vault-only");
    let stub = stub_op_listing(
        &dir,
        &Backend::Injects(ONEPASSWORD_DECOY),
        &OnePasswordListing::ItemsRefused,
        "{}",
    );
    let config = onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE);
    let (report, code) = doctor_report(&dir, &config);
    let row = store_row(&report, "onepassword");

    assert!(
        !row.contains("proven"),
        "a vault whose items cannot be listed was reported as proven:\n{report}"
    );
    assert_ne!(code, 0, "{report}");
    // The vendor's own words, so the reader knows which refusal this is.
    assert!(
        flattened(&report).contains("permission to list items"),
        "{report}"
    );

    // And the lookup agrees, from the same fixture: the row and the run must
    // not disagree about whether this store works.
    let marker = dir.join("witness");
    let registry = registry_from(&config, &Reason::default());
    let (outcome, notes) = run_with(&registry, &["DECOY"], &witness(&marker, "DECOY", 0), &[]);
    assert_eq!(outcome.state, State::Degraded, "{notes}");
    assert_eq!(witnessed(&marker), "<unset>");
}

#[test]
fn doctor_proves_a_listable_onepassword_vault_and_says_what_it_did_not_prove() {
    // The control for the case above. Without it that one passes on an
    // implementation reporting every 1Password store broken — the same defect
    // wearing the other colour, and the one that gets a health check deleted.
    let dir = scratch("onepassword-listable");
    let stub = stub_op(&dir, &Backend::Injects(ONEPASSWORD_DECOY));
    let (report, code) =
        doctor_report(&dir, &onepassword_config(&stub, ONEPASSWORD_DECOY_BY_TITLE));

    assert_eq!(state_of(store_row(&report, "onepassword")), "proven");
    assert_eq!(code, 0, "{report}");

    // It reached the vendor, and it asked for the verb a lookup starts with —
    // never the vault record, and never a verb that prints a value.
    let argv = recorded_lines(&dir.join("op.argv"));
    assert_eq!(argv.first().map(String::as_str), Some("item"));
    assert_eq!(argv.get(1).map(String::as_str), Some("list"));
    for forbidden in ["vault", "run", "get", "read", "inject"] {
        assert!(
            !mentions(&argv, forbidden),
            "a health check asked for `{forbidden}`: {argv:?}"
        );
    }

    // And the green row says which half of a lookup it proved. `proven` beside
    // a store where `op run` has never resolved anything is the shape this
    // repository spent a day removing: a tick next to a word that denies it.
    let flat = flattened(&report);
    assert!(flat.contains("op run"), "{report}");
    assert!(flat.contains("--probe"), "{report}");
    assert!(
        ["did not", "no value", "not known"]
            .iter()
            .any(|denial| flat.contains(denial)),
        "the row must DENY having read a value, not merely omit it:\n{report}"
    );
}
