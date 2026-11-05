use std::path::Path;
use std::time::Duration;

use keyless::daemon::config::DaemonConfig;

use super::{DECLARED, ENCRYPTION_KEY_DECOY, ITEM, TOKEN_DECOY, VAULT, session_dir};
use crate::support::client::write_secrets;
use crate::support::{install_executable, short_socket_path};

/// What the stand-in's plain `logout` (never `--force`) does.
///
/// `--force` is not a variant here: every case below answers it the vendor's
/// own way — it deletes local data and succeeds — because no case in this
/// file needs it to do anything else, and the retirement procedure's own
/// fallback shape is what `a_renewal_whose_old_store_cannot_be_decrypted…`
/// exercises through the PLAIN answer failing.
pub enum LogoutAnswer {
    /// The account had a session; it is ended.
    Ok,
    /// `pass-cli`'s own wording for a directory with nothing to end.
    AlreadyLoggedOut,
    /// Fails with `said` on stderr, exit 1 — the shape a corrupt local store
    /// produces: the vendor's own words, verbatim.
    Fails(&'static str),
}

impl LogoutAnswer {
    pub fn shell(&self) -> (i32, String) {
        match self {
            LogoutAnswer::Ok => (0, "echo 'Session logged out'".to_owned()),
            LogoutAnswer::AlreadyLoggedOut => (
                0,
                "echo 'There was not an active session, you are already logged out'".to_owned(),
            ),
            LogoutAnswer::Fails(said) => (1, format!("echo '{said}' >&2")),
        }
    }
}

/// What the stand-in's `run` verb — the read path — does before letting
/// `inner` actually answer it: hold the scoped directory open for `delay`,
/// then check whether `marker` (a file the fixture planted inside that
/// directory ahead of time) is still there, and append `intact` or `missing`
/// to `witness`.
///
/// Every other fixture in these suites passes `None` to
/// [`stub_with_session_verbs`] and gets the pre-existing shape back exactly:
/// `run` answers at once, nothing is held open, nothing is recorded. This is
/// the minimal extension the in-flight-read case needed — a single new `run)`
/// arm in that stub's `case`, gated on this being `Some`.
pub struct ReadProbe {
    pub delay: Duration,
    pub marker: &'static str,
    pub witness: std::path::PathBuf,
}

/// A `pass-cli` stand-in that answers `login`, `info` and `logout` itself,
/// and execs `inner` for every other verb — `run`, `item list`, `vault list`,
/// `item view`, whatever `inner` already knows how to answer.
///
/// Every call, of any verb, appends one line to `<dir>/pass-cli.verbs`:
/// `<verb> <PROTON_PASS_SESSION_DIR> current=<contents of the root's
/// current>` — the root being `PROTON_PASS_SESSION_DIR`'s own parent, true
/// for every verb this file scopes at a GENERATION. That line is what proves,
/// after the fact, which directory a verb ran against and what `current` held
/// at that instant — never inferred from timing.
///
/// `read_probe`, when `Some`, additionally intercepts `run` — see
/// [`ReadProbe`] — before the same `exec '{inner}' "$@"` fallthrough every
/// other verb already uses answers it.
pub fn stub_with_session_verbs(
    dir: &Path,
    inner: &Path,
    login_delay: Duration,
    info_answers: bool,
    logout_answer: LogoutAnswer,
    read_probe: Option<ReadProbe>,
) -> std::path::PathBuf {
    let verbs_log = dir.join("pass-cli.verbs");
    let (info_body, info_exit) = if info_answers {
        ("echo 'ok'".to_owned(), 0)
    } else {
        (
            "echo 'Error: This operation requires an authenticated client' >&2".to_owned(),
            1,
        )
    };
    let (logout_exit, logout_body) = logout_answer.shell();
    let run_case = match &read_probe {
        Some(probe) => format!(
            "\x20 run)\n\
             \x20   sleep {delay}\n\
             \x20   if [ -e \"$scoped/{marker}\" ]; then\n\
             \x20     echo intact >> '{witness}'\n\
             \x20   else\n\
             \x20     echo missing >> '{witness}'\n\
             \x20   fi\n\
             \x20   ;;\n",
            delay = probe.delay.as_secs_f64(),
            marker = probe.marker,
            witness = probe.witness.display(),
        ),
        None => String::new(),
    };

    let body = format!(
        "#!/bin/sh\n\
         scoped=\"$PROTON_PASS_SESSION_DIR\"\n\
         root=\"$(dirname \"$scoped\")\"\n\
         now_current=\"$(cat \"$root/current\" 2>/dev/null | tr -d '\\n')\"\n\
         if [ -n \"${{PROTON_PASS_ENCRYPTION_KEY+x}}\" ]; then\n\
         \x20 key_len=${{#PROTON_PASS_ENCRYPTION_KEY}}\n\
         \x20 key_fp=$(printf '%s' \"$PROTON_PASS_ENCRYPTION_KEY\" | shasum | cut -c1-12)\n\
         else\n\
         \x20 key_len=\"<unset>\"\n\
         \x20 key_fp=\"<unset>\"\n\
         fi\n\
         printf '%s %s current=%s key_provider=%s key_len=%s key_fp=%s\\n' \"$1\" \"$scoped\" \
         \"$now_current\" \"${{PROTON_PASS_KEY_PROVIDER-<unset>}}\" \"$key_len\" \"$key_fp\" >> '{verbs}'\n\
         case \"$1\" in\n\
         \x20 login)\n\
         \x20   sleep {login_delay}\n\
         \x20   echo 'Personal access token session created successfully'\n\
         \x20   exit 0 ;;\n\
         \x20 info)\n\
         \x20   {info_body}\n\
         \x20   exit {info_exit} ;;\n\
         \x20 logout)\n\
         \x20   case \"$2\" in\n\
         \x20     --force) echo 'Session logged out'; exit 0 ;;\n\
         \x20   esac\n\
         \x20   {logout_body}\n\
         \x20   exit {logout_exit} ;;\n\
         {run_case}\
         esac\n\
         exec '{inner}' \"$@\"\n",
        verbs = verbs_log.display(),
        login_delay = login_delay.as_secs_f64(),
        inner = inner.display(),
    );
    install_executable(&dir.join("pass-cli-session-verbs-stub"), &body)
}

/// A daemon config with the renewal loop switched on against a real
/// session-verbs stand-in, tuned for a short test run.
///
/// `timeout_ms` is BOTH the store's own read ceiling and the input the
/// retirement grace is derived from (`2 × timeout_ms + REAP_GRACE(2s) + 1s`)
/// — the same field serves both roles in production, so a test choosing it
/// small to keep grace fast for a RETIREMENT case is choosing the same small
/// number as the ceiling every vendor spawn in that test gets. Pass `3_000`
/// (grace 9s) only for a case that is actually waiting on the grace; every
/// other case should pass `60_000`, the suite's own generous ceiling, so a
/// loaded machine cannot turn it red for a reason that has nothing to do with
/// what it is testing.
pub fn daemon_config_with_generations_loop(
    dir: &Path,
    vendor: &Path,
    login_after_minutes: u64,
    probe_interval_seconds: u64,
    timeout_ms: u64,
) -> DaemonConfig {
    std::fs::write(dir.join("audit.jsonl"), b"").expect("audit");
    let credentials = dir.join("proton.json");
    write_secrets(&credentials, &[("AGENT_TOKEN", TOKEN_DECOY)]);
    // `key_provider` is pinned to `fs` explicitly, rather than left to the
    // type's own default, so the generation-timing cases below stay about
    // generation timing when that default moves — see
    // `daemon_config_with_generations_loop_env` for the cases that are
    // actually about the key provider.
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                        "session_dir":"{session}",
                        "timeout_ms":{timeout_ms},
                        "key_provider":"fs",
                        "credentials_file":"{credentials}",
                        "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN"}},
                        "session":{{"auto_login":true,"login_after_minutes":{login_after_minutes},
                                    "probe_interval_seconds":{probe_interval_seconds},
                                    "min_backoff_seconds":1,"max_backoff_seconds":5}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        credentials = credentials.display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

/// The same fixture as [`daemon_config_with_generations_loop`], scoped at
/// `key_provider: env` with [`ENCRYPTION_KEY_DECOY`] already written under
/// its declared entry — the state a real install reaches once
/// `credential::ensure_proton_local_key` has run once, which this fixture
/// stands in for rather than re-exercising: that generation step is proven
/// at the unit level in `daemon::credential`'s own tests.
pub fn daemon_config_with_generations_loop_env(
    dir: &Path,
    vendor: &Path,
    login_after_minutes: u64,
    probe_interval_seconds: u64,
    timeout_ms: u64,
) -> DaemonConfig {
    daemon_config_env_with_key(
        dir,
        vendor,
        login_after_minutes,
        probe_interval_seconds,
        timeout_ms,
        true,
    )
}

/// The same, with `key_written` deciding whether the credential file already
/// holds the local key — `false` is the state a machine reaches when its first
/// start lost the race to generate one.
pub fn daemon_config_env_with_key(
    dir: &Path,
    vendor: &Path,
    login_after_minutes: u64,
    probe_interval_seconds: u64,
    timeout_ms: u64,
    key_written: bool,
) -> DaemonConfig {
    std::fs::write(dir.join("audit.jsonl"), b"").expect("audit");
    let credentials = dir.join("proton.json");
    if key_written {
        write_secrets(
            &credentials,
            &[
                ("AGENT_TOKEN", TOKEN_DECOY),
                ("LOCAL_KEY", ENCRYPTION_KEY_DECOY),
            ],
        );
    } else {
        write_secrets(&credentials, &[("AGENT_TOKEN", TOKEN_DECOY)]);
    }
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                        "session_dir":"{session}",
                        "timeout_ms":{timeout_ms},
                        "key_provider":"env",
                        "credentials_file":"{credentials}",
                        "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN",
                                        "PROTON_PASS_ENCRYPTION_KEY":"LOCAL_KEY"}},
                        "session":{{"auto_login":true,"login_after_minutes":{login_after_minutes},
                                    "probe_interval_seconds":{probe_interval_seconds},
                                    "min_backoff_seconds":1,"max_backoff_seconds":5}}}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        credentials = credentials.display(),
        session = session_dir(dir).display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

/// One recorded line of `pass-cli.verbs`, parsed.
///
/// `key_provider` and `key_len` read `<unset>` for a stub predating this
/// pair — every stand-in built through [`stub_with_session_verbs`] carries
/// both, so the only way to see the sentinel is a variable the vendor child
/// genuinely never received. `key_len` is a character COUNT, never the
/// value: see `stub_with_session_verbs`'s own script for why.
#[derive(Debug)]
pub struct VerbLine {
    pub verb: String,
    pub dir: String,
    pub current: String,
    pub key_provider: String,
    pub key_len: String,
    /// A fingerprint of the key the child was handed — a hash prefix, never
    /// the value. A LENGTH cannot tell two keys apart, because every key this
    /// daemon generates is the same length: a run that generated one key,
    /// published a session under it, and then wrote a second over it reads
    /// identically to a correct one under a length oracle.
    pub key_fp: String,
}

pub fn parse_verbs(text: &str) -> Vec<VerbLine> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let verb = fields.next()?.to_owned();
            let dir = fields.next()?.to_owned();
            let current = fields
                .next()?
                .strip_prefix("current=")
                .unwrap_or_default()
                .to_owned();
            let key_provider = fields
                .next()
                .and_then(|field| field.strip_prefix("key_provider="))
                .unwrap_or("<unset>")
                .to_owned();
            let key_len = fields
                .next()
                .and_then(|field| field.strip_prefix("key_len="))
                .unwrap_or("<unset>")
                .to_owned();
            let key_fp = fields
                .next()
                .and_then(|field| field.strip_prefix("key_fp="))
                .unwrap_or("<unset>")
                .to_owned();
            Some(VerbLine {
                verb,
                dir,
                current,
                key_provider,
                key_len,
                key_fp,
            })
        })
        .collect()
}
