//! The STORES section: one row per backend this build knows about — live,
//! failing, or switched off — the coordinates it was asked for, and what to
//! type next when it could not answer.

use std::collections::BTreeMap;
use std::io::{self, Write};

use crate::cmd::status::{Mark, Style, action, heading, row};
use crate::config::Config;
use crate::error::StoreError;
use crate::store::{Registry, Store};

/// Every backend this build knows about, in the order a report lists them.
///
/// Named here rather than taken from the registry, because a store that is
/// **switched off** is invisible to the registry and is exactly what a reader
/// came to check. `"keychain": {"enabled": false}` in a config used to produce
/// no line at all, which reads identically to a build that has no keychain
/// support.
const KNOWN_STORES: [&str; 4] = [
    "keychain",
    crate::store::infisical::STORE_ID,
    "proton",
    crate::store::daemon::DAEMON_STORE_ID,
];

/// What one store row says.
///
/// Visible to [`super::names`] as well as to this module: a name routed to a
/// store that is already down reports that store's state instead of being
/// asked.
pub(super) struct StoreRow {
    pub(super) id: String,
    pub(super) mark: Mark,
    pub(super) state: &'static str,
    pub(super) detail: String,
    /// The next action, for every row that is not proven. Never empty on a
    /// failing row: a diagnosis with no next action is the shape this report
    /// used to have.
    pub(super) action: Option<String>,
}

/// One row per backend this build knows about, live or not.
pub(super) fn store_rows(config: &Config, registry: &Registry) -> Vec<StoreRow> {
    let live: BTreeMap<&str, &dyn Store> = registry
        .stores()
        .iter()
        .map(|store| (store.id(), store.as_ref()))
        .collect();

    // Known first, then anything live this list has not heard of. Dropping an
    // unknown backend would be the same defect as dropping a disabled one: a
    // store that is answering, absent from the report that exists to list them.
    let ids: Vec<&str> = KNOWN_STORES
        .iter()
        .copied()
        .chain(live.keys().copied().filter(|id| !KNOWN_STORES.contains(id)))
        .collect();

    ids.iter()
        .map(|id| match live.get(id) {
            Some(store) => match store.health() {
                Ok(()) => StoreRow {
                    id: (*id).to_owned(),
                    mark: Mark::Proven,
                    state: "proven",
                    detail: points_at(config, id),
                    action: None,
                },
                Err(error) => failing_row(config, id, &error),
            },
            None => dormant_row(config, id),
        })
        .collect()
}

/// The coordinates a live store was ASKED for, for the detail column of a
/// proven row.
///
/// A proven row still has to say WHAT was proven against, or two machines with
/// wildly different configurations produce the same green line. Every word this
/// returns is read out of the config file, though, and none of it is read back
/// from the backend that answered — so it names the coordinates handed to the
/// store, never coordinates the report established.
///
/// For three of the four backends those are the same sentence: the keychain
/// service, the Proton session directory and the daemon socket are each passed
/// to the backend verbatim, so config is what the lookup used.
///
/// Infisical is the one where that gap is load-bearing rather than pedantic.
/// The adapter hands the vendor CLI this process's `HOME` and every
/// `INFISICAL_*` variable and passes neither a domain nor a token, so WHICH
/// SERVER answered and AS WHOM are decided entirely by the ambient environment
/// — which this report never reads and this config never states. Its row says
/// so out loud, because `path /backend, project p-1` printed against a
/// self-hosted instance nobody here named is a green line that misidentifies
/// the thing it certifies.
fn points_at(config: &Config, id: &str) -> String {
    match id {
        "keychain" => format!("service \"{}\"", config.stores.keychain.service),
        "infisical" => {
            let path = &config.stores.infisical.path;
            let asked = match &config.stores.infisical.project_id {
                Some(project) => format!("path {path}, project {project}"),
                None => format!("path {path}, project from the working directory"),
            };
            format!(
                "{asked} — from this config. WHICH INSTANCE answered, and AS \
                 WHOM, are decided by the environment's HOME and INFISICAL_*; \
                 this row reads neither and does not establish the instance."
            )
        }
        "proton" => match &config.stores.proton.session_dir {
            Some(dir) => format!("session {}", dir.as_path().display()),
            None => "session directory unset".to_owned(),
        },
        "daemon" => config.stores.daemon.socket_path().display().to_string(),
        // A backend this build does not have settings for. It answered, which
        // is the whole claim the row makes; inventing coordinates for it would
        // be worse than saying nothing.
        other => format!("backend `{other}`"),
    }
}

/// A live store that could not answer.
///
/// The three [`StoreError`] variants already separate the three places a reader
/// has to be sent — the install, their own config file, and the store itself —
/// so the mark and the action are read off the variant rather than sniffed out
/// of a message.
fn failing_row(config: &Config, id: &str, error: &StoreError) -> StoreRow {
    let (mark, state) = match error {
        // Not there yet: no binary, no login, no network. A step nobody took,
        // which is amber rather than red — but still a problem, because a store
        // that was ENABLED and cannot answer is a store that cannot serve.
        StoreError::Unavailable { .. } => (Mark::NotSetUp, "absent"),
        // One line of the config file, and nothing was contacted.
        StoreError::Misconfigured { .. } => (Mark::NotSetUp, "config"),
        // Installed, reached, and saying no.
        StoreError::Backend { .. } => (Mark::Broken, "broken"),
    };
    StoreRow {
        id: id.to_owned(),
        mark,
        state,
        // The vendor's own words, so a reader knows which of the many ways this
        // backend fails they are looking at. Never its stdout; see
        // `crate::error`.
        detail: detail_of(error),
        action: Some(remedy(config, id, error)),
    }
}

/// The cause, without the `store `x`` prefix `Display` adds for a log line.
fn detail_of(error: &StoreError) -> String {
    match error {
        StoreError::Unavailable { detail, .. }
        | StoreError::Backend { detail, .. }
        | StoreError::Misconfigured { detail, .. } => detail.clone(),
    }
}

/// What to type next, per backend and per kind of failure.
///
/// Written here rather than inside each adapter because it is advice about this
/// MACHINE, not about the lookup that failed — and because a `Misconfigured`
/// error already carries the config fix in its own detail, so repeating it would
/// give a reader two sentences to reconcile.
fn remedy(config: &Config, id: &str, error: &StoreError) -> String {
    if matches!(error, StoreError::Misconfigured { .. }) {
        return format!(
            "the fix is one line of {}'s config file, not anything in the store",
            crate::NAME
        );
    }
    match id {
        "keychain" => "unlock the login keychain in Keychain Access, \
                       or check `stores.keychain.binary`"
            .to_owned(),
        "infisical" => "`infisical login`, then check `stores.infisical.project_id` \
                        and the `env` on each name"
            .to_owned(),
        // The command with THIS machine's session directory already in it. The
        // sentence it replaces — "`pass-cli login` into
        // `stores.proton.session_dir`" — is followable only by someone who
        // already knows that the directory travels in an environment variable;
        // typed literally it logs into the DEFAULT session, which on a machine
        // with a full-account login answers `Already authenticated` and leaves
        // the broken session untouched. That answer cost a day.
        "proton" => match &config.stores.proton.session_dir {
            Some(dir) => format!(
                "`{}`, or re-issue the agent token — the variable is not optional, \
                 a bare `pass-cli login` logs into the DEFAULT session",
                crate::store::proton::login_into(dir.as_path())
            ),
            None => format!(
                "set `stores.proton.session_dir`, then log in with `{}`",
                crate::store::proton::scoped_command_template("login")
            ),
        },
        "daemon" => "start `keylessd`, or set `stores.daemon.enabled` to false so \
                     this machine reads its own stores"
            .to_owned(),
        other => format!("check the settings for `stores.{other}`"),
    }
}

/// A backend that is not in the registry, and why.
///
/// Three different silences that used to look the same — the store is off, the
/// daemon suppressed it, or a daemon is listening that nothing is routed to.
fn dormant_row(config: &Config, id: &str) -> StoreRow {
    let daemon_on = config.stores.daemon.enabled;
    if id == crate::store::daemon::DAEMON_STORE_ID {
        let socket = config.stores.daemon.socket_path();
        let listening = std::fs::symlink_metadata(&socket)
            .map(|meta| {
                use std::os::unix::fs::FileTypeExt;
                meta.file_type().is_socket()
            })
            .unwrap_or(false);
        // The case worth catching: a socket that exists while the config does
        // not mention it. The daemon is installed and running, and every
        // session is quietly still reading the local stores directly. Nothing
        // else in the tool would ever say so, because from `run`'s point of
        // view everything is working.
        return StoreRow {
            id: id.to_owned(),
            mark: Mark::Off,
            state: "off",
            detail: if listening {
                format!(
                    "{} is listening, and nothing is routed to it",
                    socket.display()
                )
            } else {
                "not enabled in this config".to_owned()
            },
            action: listening.then(|| {
                "set `stores.daemon.enabled` to route through it; until then \
                 secrets are read directly by this user"
                    .to_owned()
            }),
        };
    }
    let enabled = match id {
        "keychain" => config.stores.keychain.enabled,
        "infisical" => config.stores.infisical.enabled,
        "proton" => config.stores.proton.enabled,
        // Not a backend this build has a flag for, and not in the registry
        // either. There is nothing here to have switched off.
        _ => false,
    };
    StoreRow {
        id: id.to_owned(),
        mark: Mark::Off,
        state: "off",
        // Three different silences, and the row says which. Reading the flag
        // rather than assuming it is what stops the last arm being a lie: a
        // store can be absent from the registry for a reason the config does
        // not show, and "you switched it off" would then be wrong in the one
        // direction that sends a reader to edit a line that is already correct.
        detail: if daemon_on {
            "suppressed: the daemon serves every name on this machine".to_owned()
        } else if enabled {
            "enabled here, but this registry did not construct it".to_owned()
        } else {
            format!("\"enabled\": false under `stores.{id}`")
        },
        action: None,
    }
}

/// The STORES section. Returns how many rows are problems.
pub(super) fn report_stores(
    rows: &[StoreRow],
    style: Style,
    out: &mut dyn Write,
) -> io::Result<i32> {
    heading(out, style, "STORES")?;

    if rows.iter().all(|row| row.mark == Mark::Off) {
        row(
            out,
            style,
            Mark::NotSetUp,
            "(none)",
            subject_width(rows),
            "absent",
            "none configured, so no name can resolve",
        )?;
        action(
            out,
            style,
            &format!(
                "{} init detects what is installed and enables it",
                crate::NAME
            ),
        )?;
        return Ok(1);
    }

    let width = subject_width(rows);
    let mut problems = 0;
    for entry in rows {
        row(
            out,
            style,
            entry.mark,
            &entry.id,
            width,
            entry.state,
            &entry.detail,
        )?;
        if let Some(text) = &entry.action {
            action(out, style, text)?;
        }
        problems += i32::from(entry.mark.is_problem());
    }
    Ok(problems)
}

fn subject_width(rows: &[StoreRow]) -> usize {
    rows.iter()
        .map(|row| row.id.len())
        .max()
        .unwrap_or(6)
        .max(6)
}

#[cfg(test)]
mod tests {
    use super::{points_at, remedy};
    // The whole-report fixtures, so a row asserted here can also be followed
    // into the render a person actually reads.
    use crate::cmd::doctor::tests::{Named, flat, loaded, report};
    use crate::error::StoreError;
    use crate::store::Registry;

    #[test]
    fn a_proven_infisical_row_never_reads_as_having_established_the_instance() {
        // The defect this pins is a green line that misidentifies what it
        // certifies. The adapter hands the vendor CLI this process's `HOME` and
        // every `INFISICAL_*` variable and passes no domain and no token, so the
        // server that answered and the account it answered for are decided by
        // the ambient environment — while the detail column is built entirely
        // from the config file. `proven — path /backend, project p-decoy` was
        // therefore printable for a lookup that reached a different instance
        // altogether.
        //
        // Asserted as a property, not as a sentence: the row must NAME the
        // levers it cannot see and must DENY having read them. Any rewording
        // that keeps the meaning keeps both; a row that quietly grew back into a
        // claim about the instance would keep neither.
        use crate::store::infisical::{FORWARDED_EXACT, FORWARDED_PREFIX};

        let load = loaded(
            r#"{"stores":{"infisical":{"enabled":true,"path":"/backend","project_id":"p-decoy"}},
                "secrets":{}}"#,
        );
        let detail = points_at(&load.config, "infisical");

        // The coordinates survive: telling two machines apart is the reason this
        // column exists, and a caveat that ate the content would be its own bug.
        assert!(detail.contains("/backend"), "{detail}");
        assert!(detail.contains("p-decoy"), "{detail}");
        // ...attributed, so a reader can tell a config echo from a reading.
        assert!(
            detail.contains("config"),
            "the coordinates must say where they came from: {detail}"
        );

        // The levers, read off the adapter's own constants rather than typed
        // here. If what the adapter forwards ever changes, this is what drags
        // the report along instead of letting the caveat go quietly stale.
        assert!(
            FORWARDED_EXACT.contains(&"HOME"),
            "the adapter stopped forwarding HOME; the row's caveat now names the \
             wrong lever: {FORWARDED_EXACT:?}"
        );
        assert!(detail.contains("HOME"), "{detail}");
        assert!(detail.contains(FORWARDED_PREFIX), "{detail}");

        // The denial itself, matched as a negation rather than as a sentence. A
        // row that CLAIMS the instance ("verified against ...", "authenticated
        // as ...") carries no negation at all, which is the single thing this
        // assertion exists to catch.
        assert!(
            ["not ", "never", "neither", "cannot"]
                .iter()
                .any(|denial| detail.contains(denial)),
            "the row must DENY having read the instance, not merely omit it: {detail}"
        );

        // And it reaches the report a person actually reads, wrapping included.
        let (text, _) = report(
            &load,
            Registry::new(vec![Box::new(Named("infisical"))]),
            false,
        );
        assert!(flat(&text).contains(FORWARDED_PREFIX), "{text}");
    }

    #[test]
    fn the_ambient_caveat_belongs_only_to_the_backend_that_has_one() {
        // The control for the case above, which would otherwise pass on a report
        // that appends the same disclaimer to every proven row. A caveat printed
        // everywhere is read nowhere, and it would stop meaning anything on the
        // one row where it is true. The keychain service is handed to `security`
        // verbatim, so those coordinates ARE the ones the lookup used.
        let load = loaded(r#"{"stores":{"keychain":{"enabled":true}},"secrets":{}}"#);
        let detail = points_at(&load.config, "keychain");
        assert!(
            !detail.contains(crate::store::infisical::FORWARDED_PREFIX),
            "{detail}"
        );
        assert!(!detail.contains("HOME"), "{detail}");
    }

    /// A `Unavailable` from a store, for the rows that are about the ACTION.
    fn unavailable(store: &str) -> StoreError {
        StoreError::Unavailable {
            store: store.to_owned(),
            detail: "the session cannot be used".to_owned(),
        }
    }

    #[test]
    fn the_proton_next_action_names_the_variable_that_selects_the_session() {
        // The action column is a separate sentence from the adapter's detail,
        // and it is the one a reader copies. `pass-cli login` on its own logs
        // into the DEFAULT session — on macOS `~/Library/Application
        // Support/proton-pass-cli/.session` — which on a machine with a
        // full-account login answers `Already authenticated` and leaves the
        // configured session exactly as broken as it was. That answer is true,
        // it is about a different session, and it cost a day on 2026-08-10.
        let load = loaded(
            r#"{"stores":{"proton":{"enabled":true,"session_dir":"/tmp/keyless-doctor-agent"}}}"#,
        );
        let action = remedy(&load.config, "proton", &unavailable("proton"));
        assert!(
            action.contains("PROTON_PASS_SESSION_DIR=/tmp/keyless-doctor-agent pass-cli login"),
            "the next action did not name this machine's session directory: {action}"
        );
    }

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
                          "proton":{"enabled":true},
                          "daemon":{"enabled":false,
                                    "socket":"/nonexistent/keyless-doctor/daemon.sock"}},
                "secrets":{}}"#,
        );
        for id in ["keychain", "infisical", "proton"] {
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

    #[test]
    fn the_proton_next_action_with_no_session_directory_asks_for_one_first() {
        // There is no directory to name, so the advice must not invent one. It
        // still says how the directory travels, because that is the half nobody
        // guesses.
        let load = loaded(r#"{"stores":{"proton":{"enabled":true}}}"#);
        let action = remedy(&load.config, "proton", &unavailable("proton"));
        assert!(action.contains("stores.proton.session_dir"), "{action}");
        assert!(action.contains("PROTON_PASS_SESSION_DIR"), "{action}");
    }
}
