//! `stores.proton.session.auto_login`: a session Proton ended is logged in
//! again with the agent token from the keychain, and the read retried once.
//!
//! The vendor half is a stand-in written from `pass-cli` 2.7.0's source: a read
//! that finds no `session.json` refuses with `there is no session`, and `login`
//! with a token in `PROTON_PASS_PERSONAL_ACCESS_TOKEN` writes one. Each login
//! mints a new share id, because a share id belongs to the session that listed
//! it. The keychain half is a `security` stand-in; no real keychain is read.

mod support;

use std::path::{Path, PathBuf};

use keyless::config::Config;
use keyless::store::proton::Reason;
use keyless::store::{self, Built, Invocation, Resolution};

use support::{PROTON_DECOY, install_executable, recorded_lines, scratch};

/// The agent token the keychain stand-in holds. A decoy: grep for it in any
/// argument vector means a leak.
const AGENT_TOKEN: &str = "pst_decoy-agent-token-not-a-real-one::decoykey0606";

/// The keychain item the configs below name, under a service of its own.
const TOKEN_SERVICE: &str = "keyless-proton";
const TOKEN_ACCOUNT: &str = "test-agent";

/// A `pass-cli` stand-in that keeps a session the way the vendor does.
///
/// Every call appends `<verb> <token-in-env|no-token>` to `pass-cli.calls`,
/// never the token itself. `login` checks the token, writes a `session.json`
/// that holds a login, and bumps the session number. Any other verb refuses
/// with `there is no session` when the file is missing OR holds no login,
/// which is what a real expiry left behind on 2026-11-11. `item list` answers
/// with a share id that changes after the first session, and `run` refuses a
/// reference minted under another session.
fn stub_vendor(dir: &Path) -> PathBuf {
    let body = format!(
        r#"#!/bin/sh
root="${{PROTON_PASS_SESSION_DIR-}}"
session="$root/.session/session.json"
token="${{PROTON_PASS_PERSONAL_ACCESS_TOKEN:+token-in-env}}"
printf '%s %s\n' "$1" "${{token:-no-token}}" >> '{calls}'
if [ "$1" = 'login' ]; then
  printf '%s\n' "$@" > '{login_argv}'
  if [ "${{PROTON_PASS_PERSONAL_ACCESS_TOKEN-}}" != '{AGENT_TOKEN}' ]; then
    echo 'Error: This personal access token is invalid, expired or has been deleted.' >&2
    exit 1
  fi
  number=$(( $(cat '{sessions}' 2>/dev/null || echo 0) + 1 ))
  echo "$number" > '{sessions}'
  mkdir -p "$root/.session" && printf 'session=%s\nauth=yes\n' "$number" > "$session"
  exit 0
fi
if ! grep -q '^auth=yes$' "$session" 2>/dev/null; then
  # Slow enough that a sibling's login lands while this read is still failing.
  sleep 0.3
  echo 'ERROR pass-cli/src/main.rs:360: Command is not logout there is no session' >&2
  echo 'Error: This operation requires an authenticated client' >&2
  exit 1
fi
number=$(sed -n -e 's/^session=//p' "$session")
if [ "$1" = 'info' ]; then echo 'Personal Access Token: decoy-agent'; exit 0; fi
if [ "$number" = 1 ]; then share=ShAr3; else share=ShAr3L1v3; fi
if [ "$1" = 'item' ] && [ "$2" = 'list' ]; then
  echo listed >> '{listed}'
  if [ "$share" = ShAr3 ]; then
    printf '%s' '{{"items":[{{"id":"It3mL1v3","share_id":"ShAr3","vault_id":"V","state":"Active","flags":[],"create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01","title":"keyless-decoy-alpha","item_type":"login"}}]}}'
  else
    printf '%s' '{{"items":[{{"id":"It3mL1v3","share_id":"ShAr3L1v3","vault_id":"V","state":"Active","flags":[],"create_time":"2000-01-01T00:00:00","modify_time":"2000-01-01T00:00:01","title":"keyless-decoy-alpha","item_type":"login"}}]}}'
  fi
  exit 0
fi
if [ "$1" = 'vault' ] && [ "$2" = 'list' ]; then
  printf '%s' '{{"vaults":[{{"name":"personal","id":"V"}}]}}'
  exit 0
fi
if [ "$1" = 'run' ]; then
  for arg in "$@"; do
    case "$arg" in --env-file=*) env_file="${{arg#--env-file=}}" ;; esac
  done
  if ! grep -q "pass://$share/" "$env_file"; then
    echo 'Error: share not found' >&2
    exit 1
  fi
  printf '%s\n' '{PROTON_DECOY}'
  exit 0
fi
exit 1
"#,
        calls = dir.join("pass-cli.calls").display(),
        login_argv = dir.join("pass-cli.login.argv").display(),
        sessions = dir.join("pass-cli.sessions").display(),
        listed = dir.join("pass-cli.listed").display(),
    );
    install_executable(&dir.join("pass-cli-stub"), &body)
}

/// A `security` stand-in that records its arguments and holds `token`, or
/// answers `errSecItemNotFound` (exit 44) when there is none.
fn stub_keychain(dir: &Path, token: Option<&str>) -> PathBuf {
    let answer = match token {
        Some(token) => format!("printf '%s\\n' '{token}'\nexit 0"),
        None => "exit 44".to_owned(),
    };
    let body = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{argv}'\n{answer}\n",
        argv = dir.join("security.argv").display(),
    );
    install_executable(&dir.join("security-stub"), &body)
}

/// A config with auto-login switched as asked, one name addressed by title.
fn config(dir: &Path, auto_login: bool, token: Option<&str>) -> String {
    let token_item = token.map_or_else(String::new, |item| format!(r#","token":{item}"#));
    format!(
        r#"{{"stores":{{
             "keychain":{{"enabled":false,"service":"keyless","binary":"{security}","timeout_ms":60000}},
             "proton":{{"enabled":true,"binary":"{vendor}","session_dir":"{session}","timeout_ms":60000,
                        "session":{{"auto_login":{auto_login}{token_item}}}}}}},
            "secrets":{{"DECOY":{{"store":"proton","vault":"personal",
                                  "item":"keyless-decoy-alpha","field":"password"}}}}}}"#,
        security = dir.join("security-stub").display(),
        vendor = dir.join("pass-cli-stub").display(),
        session = session_dir(dir).display(),
    )
}

fn token_item() -> String {
    format!(r#"{{"service":"{TOKEN_SERVICE}","account":"{TOKEN_ACCOUNT}"}}"#)
}

fn session_dir(dir: &Path) -> PathBuf {
    dir.join("session")
}

/// A scratch directory holding both stand-ins and an empty session directory:
/// what a session looks like once Proton has ended it.
fn ended_session(tag: &str, keychain_holds: Option<&str>) -> PathBuf {
    let dir = scratch(tag);
    stub_vendor(&dir);
    stub_keychain(&dir, keychain_holds);
    std::fs::create_dir_all(session_dir(&dir)).expect("create the session directory");
    dir
}

fn built(json: &str) -> Built {
    let config: Config = serde_json::from_str(json).expect("the test config must be valid");
    store::build(
        &config,
        &Invocation {
            reason: Reason::default(),
            infisical_env: None,
        },
    )
}

fn resolved(resolution: &Resolution) -> Option<&str> {
    match resolution {
        Resolution::Found { secret, .. } => Some(secret.expose()),
        _ => None,
    }
}

fn failure(resolution: &Resolution) -> String {
    assert!(
        matches!(resolution, Resolution::Failed(_)),
        "expected a failure, got: {}",
        resolution.reason()
    );
    resolution.reason()
}

/// How many times the stand-in ran `verb`, and with the token in reach.
fn calls(dir: &Path, verb: &str) -> Vec<String> {
    recorded_lines(&dir.join("pass-cli.calls"))
        .into_iter()
        .filter(|line| line.split(' ').next() == Some(verb))
        .collect()
}

#[test]
fn an_ended_session_is_logged_in_again_and_the_name_resolves() {
    let dir = ended_session("auto-login-happy", Some(AGENT_TOKEN));
    let registry = built(&config(&dir, true, Some(&token_item()))).registry;

    let resolution = registry.resolve("DECOY");

    assert_eq!(
        resolved(&resolution),
        Some(PROTON_DECOY),
        "{}",
        resolution.reason()
    );
    assert_eq!(calls(&dir, "login"), ["login token-in-env"]);
    // The token travels in the environment and nowhere else: the argument
    // vector is the verb alone, and no other call carried it.
    assert_eq!(recorded_lines(&dir.join("pass-cli.login.argv")), ["login"]);
    assert!(
        recorded_lines(&dir.join("pass-cli.calls"))
            .iter()
            .filter(|line| !line.starts_with("login "))
            .all(|line| line.ends_with(" no-token")),
        "only the login may carry the token"
    );
    assert_eq!(
        recorded_lines(&dir.join("security.argv")),
        [
            "find-generic-password",
            "-s",
            TOKEN_SERVICE,
            "-a",
            TOKEN_ACCOUNT,
            "-w"
        ]
    );
}

#[test]
fn control_with_auto_login_off_an_ended_session_stays_ended() {
    let dir = ended_session("auto-login-off", Some(AGENT_TOKEN));
    let registry = built(&config(&dir, false, Some(&token_item()))).registry;

    let resolution = registry.resolve("DECOY");

    assert_eq!(resolved(&resolution), None);
    assert!(failure(&resolution).contains("authenticated client"));
    assert!(calls(&dir, "login").is_empty(), "nobody asked for a login");
    assert!(
        !dir.join("security.argv").exists(),
        "nobody asked for the token"
    );
}

#[test]
fn a_failure_that_keeps_the_session_logs_nobody_in() {
    let dir = ended_session("auto-login-name-fault", Some(AGENT_TOKEN));
    let registry = built(&config(&dir, true, Some(&token_item()))).registry;
    assert!(resolved(&registry.resolve("DECOY")).is_some());

    // The session answers; the vault is what lacks the name.
    let missing = config(&dir, true, Some(&token_item()))
        .replace("keyless-decoy-alpha", "an-item-nobody-created");
    let resolution = built(&missing).registry.resolve("DECOY");

    assert_eq!(resolved(&resolution), None);
    assert_eq!(
        calls(&dir, "login").len(),
        1,
        "only the first, ended, session"
    );
}

#[test]
fn the_retry_lists_the_vault_again_because_a_share_id_belongs_to_one_session() {
    let dir = ended_session("auto-login-relist", Some(AGENT_TOKEN));
    let registry = built(&config(&dir, true, Some(&token_item()))).registry;
    assert!(resolved(&registry.resolve("DECOY")).is_some());

    // Proton ends the session while the listing is still fresh in memory.
    std::fs::remove_dir_all(session_dir(&dir).join(".session")).expect("end the session");
    let resolution = registry.resolve("DECOY");

    assert_eq!(
        resolved(&resolution),
        Some(PROTON_DECOY),
        "{}",
        resolution.reason()
    );
    assert_eq!(calls(&dir, "login").len(), 2);
    // Two listings for the first session's login, and one more after the
    // second: a retry through the cached listing would have asked for `Sh1`.
    assert_eq!(calls(&dir, "item").len(), 3);
}

#[test]
fn a_session_proton_ended_in_place_is_logged_in_again() {
    let dir = ended_session("auto-login-in-place", Some(AGENT_TOKEN));
    let registry = built(&config(&dir, true, Some(&token_item()))).registry;
    assert!(resolved(&registry.resolve("DECOY")).is_some());

    // What the real expiry of 2026-11-11 left: `session.json` still there,
    // holding no login, and every read answering `there is no session`. A
    // check on the file alone took that for a live session and never logged
    // in.
    let session = session_dir(&dir).join(".session").join("session.json");
    std::fs::write(&session, "session=1\n").expect("end the session in place");
    let resolution = registry.resolve("DECOY");

    assert_eq!(
        resolved(&resolution),
        Some(PROTON_DECOY),
        "{}",
        resolution.reason()
    );
    assert_eq!(calls(&dir, "login").len(), 2);
}

#[test]
fn names_that_find_the_session_ended_together_log_in_once() {
    let dir = ended_session("auto-login-once", Some(AGENT_TOKEN));
    let registry = built(&config(&dir, true, Some(&token_item()))).registry;

    let resolutions: Vec<Resolution> = std::thread::scope(|scope| {
        let readers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| registry.resolve("DECOY")))
            .collect();
        readers
            .into_iter()
            .map(|reader| reader.join().expect("a reader panicked"))
            .collect()
    });

    for resolution in &resolutions {
        assert_eq!(
            resolved(resolution),
            Some(PROTON_DECOY),
            "{}",
            resolution.reason()
        );
    }
    assert_eq!(calls(&dir, "login").len(), 1);
    // One listing for the new session, reused by every retry: measured in a
    // real run of 33 names, clearing it per retry cost one listing per name.
    assert_eq!(recorded_lines(&dir.join("pass-cli.listed")).len(), 1);
}

#[test]
fn an_empty_keychain_item_names_the_command_that_fills_it() {
    let dir = ended_session("auto-login-no-item", None);
    let registry = built(&config(&dir, true, Some(&token_item()))).registry;

    let said = failure(&registry.resolve("DECOY"));

    assert!(
        said.contains("security add-generic-password -U -s keyless-proton -a test-agent -w"),
        "{said}"
    );
    assert!(calls(&dir, "login").is_empty(), "no token, no login");
}

#[test]
fn a_refused_token_says_to_mint_a_new_one_rather_than_to_log_in() {
    let dir = ended_session(
        "auto-login-refused",
        Some("pst_decoy-a-token-proton-revoked::k"),
    );
    let registry = built(&config(&dir, true, Some(&token_item()))).registry;

    let said = failure(&registry.resolve("DECOY"));

    assert!(said.contains("refused the agent token"), "{said}");
    assert!(said.contains("Mint a new one"), "{said}");
    assert!(
        !said.contains("pst_"),
        "a message never carries the token: {said}"
    );

    // The next name of the same run gets the same answer without a second
    // login that would fail the same way.
    assert!(failure(&registry.resolve("DECOY")).contains("refused the agent token"));
    assert_eq!(calls(&dir, "login").len(), 1);
}

#[test]
fn doctor_reports_the_session_the_next_run_will_meet() {
    let dir = ended_session("auto-login-doctor", Some(AGENT_TOKEN));
    let built = built(&config(&dir, true, Some(&token_item())));

    let unhealthy: Vec<String> = built
        .registry
        .stores()
        .iter()
        .filter_map(|store| store.health().err().map(|error| error.to_string()))
        .collect();

    assert!(unhealthy.is_empty(), "{unhealthy:?}");
    assert_eq!(calls(&dir, "login").len(), 1);
}

#[test]
fn auto_login_with_no_token_item_is_said_on_every_run() {
    let dir = ended_session("auto-login-no-token", Some(AGENT_TOKEN));
    let built = built(&config(&dir, true, None));

    assert!(
        built
            .warnings
            .iter()
            .any(|w| w.contains("names no keychain item")),
        "{:?}",
        built.warnings
    );
    assert_eq!(resolved(&built.registry.resolve("DECOY")), None);
    assert!(calls(&dir, "login").is_empty());
}

#[test]
fn a_token_item_keyless_run_could_hand_out_turns_auto_login_off() {
    let dir = ended_session("auto-login-servable", Some(AGENT_TOKEN));
    let own_service = format!(r#"{{"service":"keyless","account":"{TOKEN_ACCOUNT}"}}"#);
    let declared = config(&dir, true, Some(&token_item())).replace(
        r#""secrets":{"#,
        &format!(
            r#""secrets":{{"LEAK":{{"store":"keychain","service":"{TOKEN_SERVICE}","account":"{TOKEN_ACCOUNT}"}},"#
        ),
    );

    for json in [config(&dir, true, Some(&own_service)), declared] {
        let built = built(&json);
        assert!(
            built
                .warnings
                .iter()
                .any(|w| w.contains("would hand the agent token")),
            "{:?}",
            built.warnings
        );
        assert_eq!(resolved(&built.registry.resolve("DECOY")), None);
    }
    assert!(calls(&dir, "login").is_empty());
}
