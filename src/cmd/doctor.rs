//! `keyless doctor` — what is proven, what is not, and what to do about it.
//!
//! Answers the questions a degraded run raises: does the config parse, is the
//! backend reachable, does the audit log still chain. With `--probe` it also
//! asks each declared name whether it resolves — and prints only that it
//! resolved, that it is absent, or the backend's error. Never a value, never a
//! length, because a length is still information about a secret.
//!
//! # `ok` was a lie about a measurement, and this report no longer has the word
//!
//! `store keychain ok` was printed after running `security list-keychains`, a
//! command that proves a binary answered and touches no item. Every name under
//! that store could fail and the line stayed green. That is the failure class
//! this whole crate is about — a check that reports on itself rather than on the
//! thing — arriving in the one command a person runs precisely when something is
//! already wrong.
//!
//! So the report has one green and it means one thing: **something came back
//! through the whole path.** See [`crate::cmd::status`] for the vocabulary and
//! for why the axis is depth of proof rather than "connected". Two subjects,
//! two depths:
//!
//! - a **store** is proven when a read path answered — for the keychain, a
//!   search that reached the item database; for Infisical, a fetch of a
//!   non-credential key; for Proton, a vault listing as this session. None of
//!   the three reads a credential of yours.
//! - a **name** is proven only under `--probe`, which reads the real credential.
//!
//! # Why the extra variables a name delivers are printed here
//!
//! A bare `-s NAME` lands in `$NAME` **and** in every variable that name's own
//! declaration says it answers to. That is a fact the tool holds and a person
//! cannot otherwise discover: it is not in `ls`, whose four tab-separated fields
//! are a parser's contract and may not grow a fifth, and it is not visible at
//! the point of use, because a run that works prints nothing.
//!
//! The variables are read through [`Binding::declared`] — the same function the
//! run itself calls — rather than re-derived from the route here. A second
//! derivation would be free to disagree with the first, and the failure it would
//! produce is a report promising a variable the child never gets.
//!
//! # Why a name whose store failed is not asked
//!
//! A store that is down makes every name under it fail, identically, for the
//! same reason. Printing that reason once per name buries the one row that
//! matters underneath its own consequences — and asking would spend a doomed
//! vendor call per name, plus one permanent off-machine audit entry per item
//! against Proton. So the store rows are computed first, and a name routed to a
//! failing store is marked `blocked` and points up. Nothing is asked.
//!
//! # Why there is no capability check, and why the report says so out loud
//!
//! A credential has two properties a reader wants and this tool can only supply
//! one. It can say whether a name **resolves**. It cannot say what the value
//! **can do**, or **whose** it is, and the gap between those is where the
//! expensive mistakes live: every link green while the token turns out to be an
//! account-wide grant, or to authenticate as somebody else.
//!
//! A probe for the second was designed and refused. The reasons are measurements,
//! not taste:
//!
//! - **A capability probe can only test the capability you already suspected.**
//!   Being wrong about what a credential holds is the defect; a probe fired at
//!   the powers you thought to declare cannot find the ones you did not.
//!   Measured 2026-08-09: two tokens written down as a two-permission pair each
//!   carried **383 permission groups**, including the right to mint further
//!   tokens and to change billing. No probe anybody would have written for that
//!   pair would have asked about billing.
//! - **A read-only probe understates, and understating is the dangerous
//!   direction.** An overstated credential fails loudly at the call. An
//!   understated one stops the call being attempted, and nothing anywhere
//!   errors. Two sessions planned around a restriction that did not exist.
//! - **A green probe would be a new false green.** A vendor's token-verify
//!   endpoint answers 200 for a one-permission token and for an account-wide
//!   one alike. A `capability ok` line would be read as "capability
//!   established" and would be worth less than the silence it replaced.
//! - **Enumerating a grant is the provider's act, not this tool's.** One vendor
//!   measured that day will hand back a token's own policies — and even there it
//!   is not general: of four real tokens, two lacked the permission to read
//!   their own description and were refused it. A feature that works at one
//!   endpoint of one vendor, sometimes, is not a feature in a broker.
//! - **And it would make the config executable.** A declared probe fires from a
//!   verb somebody types for health, without naming what it runs. `run` already
//!   hands a value to any command — but only one a person typed at that moment.
//!
//! So the report states the boundary instead, on every invocation, for every
//! name. **An absent check and a passing check must never look alike**; the way
//! to guarantee that is to have no passing check to mistake, and to print the
//! absence rather than leave a hole a hand-written note drifts into.

use std::collections::BTreeMap;
use std::io::{self, Write};

use crate::audit::AuditLog;
use crate::checkout::Checkout;
use crate::cmd::run::Binding;
use crate::config::{Config, ConfigLoad};
use crate::error::StoreError;
use crate::freshness::{self, Freshness};
use crate::paths::Paths;
use crate::store::{self, Registry, Resolution, Store};

use super::status::{Mark, Style, action, heading, note, row, verbatim};

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
struct StoreRow {
    id: String,
    mark: Mark,
    state: &'static str,
    detail: String,
    /// The next action, for every row that is not proven. Never empty on a
    /// failing row: a diagnosis with no next action is the shape this report
    /// used to have.
    action: Option<String>,
}

/// Everything one report is about.
///
/// A struct rather than eight parameters, for the reason
/// [`crate::cmd::run::RunRequest`] is one: a ninth fact added by widening a call
/// signature is a change nobody reads, and two of these — `probe` and `style` —
/// are bare `bool`-shaped things whose meaning is invisible at a call site.
pub struct DoctorRequest<'a> {
    /// Where the config and the audit log live.
    pub paths: &'a Paths,
    /// The config, and whatever went wrong reading it.
    pub load: &'a ConfigLoad,
    /// The backends the config turned on.
    pub registry: &'a Registry,
    /// The log to verify.
    pub audit: &'a AuditLog,
    /// Where the guards' switch is, so this report can say when it is off.
    ///
    /// `None` skips the row entirely rather than reporting an unknown state.
    /// A caller with no opinion about setup is asking about stores and names,
    /// and inventing a guards row for it would be a claim nobody made.
    pub setup: Option<&'a crate::paths::SetupPaths>,
    /// How the registry was assembled, for someone who came to ask.
    pub notes: &'a [String],
    /// Also ask each declared name whether it resolves. READS each credential.
    pub probe: bool,
    /// Colour and character set.
    ///
    /// A field rather than something detected inside, for the reason
    /// [`crate::cmd::ls::ls`] takes `interactive`: the caller already knows which
    /// stream it is writing to, and a function that guesses cannot be driven
    /// down both paths by a test.
    pub style: Style,
}

/// Run every check, writing a report to `out`.
///
/// Returns the process exit code: 0 when everything checked out, 1 when
/// anything did not. `doctor` is the one verb allowed to be judgemental,
/// because nothing depends on it succeeding.
///
/// # Errors
///
/// Only a write failure on `out`.
pub fn doctor(request: &DoctorRequest<'_>, out: &mut dyn Write) -> io::Result<i32> {
    let DoctorRequest {
        paths,
        load,
        registry,
        audit,
        setup,
        notes,
        probe,
        style,
    } = *request;
    let mut problems = 0;

    header(paths, load, style, out)?;
    if let Some(setup) = setup {
        guards(setup, style, out)?;
    }
    problems += report_build(&freshness::check(), &crate::checkout::check(), style, out)?;

    if !notes.is_empty() {
        heading(out, style, "NOTES")?;
        for text in notes {
            note(out, style, text)?;
        }
    }

    if let Some(problem) = &load.problem {
        problems += 1;
        heading(out, style, "CONFIG")?;
        row(
            out,
            style,
            Mark::Broken,
            "config",
            6,
            "broken",
            &problem.to_string(),
        )?;
        action(
            out,
            style,
            "fix the file, or move it aside; commands still run, with defaults",
        )?;
    }

    let rows = store_rows(&load.config, registry);
    problems += report_stores(&rows, style, out)?;
    problems += report_names(&load.config, registry, &rows, probe, style, out)?;
    problems += report_audit(audit, style, out)?;

    if !load.config.secrets.is_empty() {
        report_capability_boundary(style, out)?;
    }

    writeln!(
        out,
        "\n{problems} problem(s). A problem here degrades a run; it never blocks one."
    )?;

    Ok(i32::from(problems > 0))
}

/// The orienting line: which build, which file, how many names.
fn header(paths: &Paths, load: &ConfigLoad, style: Style, out: &mut dyn Write) -> io::Result<()> {
    let names = load.config.secrets.len();
    let summary = if load.problem.is_some() {
        "unreadable; see CONFIG below".to_owned()
    } else if load.loaded {
        format!("{names} name(s) declared")
    } else {
        "no config file yet".to_owned()
    };
    writeln!(
        out,
        "{} {}   {}   {summary}",
        crate::NAME,
        env!("CARGO_PKG_VERSION"),
        paths.config.display()
    )?;
    if !load.loaded && load.problem.is_none() {
        action(
            out,
            style,
            &format!("{} setup detects your stores and writes one", crate::NAME),
        )?;
    }
    Ok(())
}

/// One row of the BUILD section, before it is printed.
///
/// Built rather than written straight out, so the heading can be printed only
/// when a row exists. A `BUILD` heading over nothing is what a hand-ordered
/// sequence of `writeln!`s produces the first time a verdict goes silent.
struct BuildRow {
    mark: Mark,
    subject: &'static str,
    state: &'static str,
    detail: String,
    next: Option<String>,
}

/// How wide the subject column is here. `checkout` is the longest.
const BUILD_SUBJECT_WIDTH: usize = 8;

/// Whether the code answering you is the code anybody is reading. Returns how
/// many rows are problems.
///
/// **Directly under the header, above every other section, and it counts.** A
/// stale binary does not make one row wrong; it makes the whole report a
/// statement about code nobody is reading — including the rows that say
/// everything is fine. So it is placed where it cannot be reached by scrolling
/// past a wall of green, for the same reason [`guards`] is.
///
/// # Two rows, because it is two questions and one of them cannot be answered
///
/// The chain is `upstream → source → binary`, and each link fails on its own:
///
/// - `build` compares the binary against the source tree beside it. It PROVES
///   that link and nothing else, and it says so in the row, because
///   `✔ build proven` at the top of a health report is read as "the code is
///   current" and that is not what it measured. On 2026-08-10 that exact tick
///   certified a binary built from a checkout six commits behind, carrying a
///   false green fixed in one of those six.
/// - `checkout` compares that source tree against the branch it tracks — and it
///   is never a tick, whatever it finds, because [`crate::checkout`] refuses to
///   make a network call and the ref it reads is only as new as the last fetch.
///   [`Checkout::Behind`] is a positive fact a stale ref cannot invent, so it is
///   the one verdict here that is red.
///
/// Both go silent on a machine with no source tree, which is the normal state of
/// an installed release: nothing to compare, no finding, and a row on every
/// invocation would teach people to skip this section. Every other unanswerable
/// case prints as `unproven` and costs no exit code — a comparison that could
/// not be made must never read as one that passed, and must not read as a fault
/// either.
fn report_build(
    freshness: &Freshness,
    checkout: &Checkout,
    style: Style,
    out: &mut dyn Write,
) -> io::Result<i32> {
    let rows: Vec<BuildRow> = [build_row(freshness), checkout_row(checkout)]
        .into_iter()
        .flatten()
        .collect();
    if rows.is_empty() {
        return Ok(0);
    }
    heading(out, style, "BUILD")?;
    let mut problems = 0;
    for BuildRow {
        mark,
        subject,
        state,
        detail,
        next,
    } in rows
    {
        row(
            out,
            style,
            mark,
            subject,
            BUILD_SUBJECT_WIDTH,
            state,
            &detail,
        )?;
        if let Some(text) = next {
            action(out, style, &text)?;
        }
        problems += i32::from(mark.is_problem());
    }
    Ok(problems)
}

/// The binary against the source beside it.
fn build_row(freshness: &Freshness) -> Option<BuildRow> {
    let (mark, state, detail, next) = match freshness {
        Freshness::NoSourceTree => return None,
        Freshness::Current => (
            Mark::Proven,
            "proven",
            format!(
                "newer than every source file in {}. That is the whole claim: \
                 whether that checkout is itself current is the row below, and \
                 this one cannot see it",
                freshness::source_dir().display()
            ),
            None,
        ),
        Freshness::Unknown { reason } => (Mark::Unproven, "unproven", reason.clone(), None),
        Freshness::Stale { newest } => (
            Mark::Broken,
            "stale",
            format!(
                "{} changed after this binary was built, so every row here is about \
                 older code",
                newest.display()
            ),
            Some(format!(
                "cargo build --release   (in {})",
                freshness::source_dir().display()
            )),
        ),
    };
    Some(BuildRow {
        mark,
        subject: "build",
        state,
        detail,
        next,
    })
}

/// That source tree against the branch it tracks.
///
/// Every arm names the directory, because the person reading this is not
/// necessarily standing in it — and on a machine with two clones of this
/// repository, "which one" is the entire question.
fn checkout_row(checkout: &Checkout) -> Option<BuildRow> {
    let here = freshness::source_dir().display().to_string();
    let (mark, state, detail, next) = match checkout {
        Checkout::NoSourceTree => return None,
        Checkout::CannotAsk { reason } => (Mark::Unproven, "unproven", reason.clone(), None),
        Checkout::Detached => (
            Mark::Unproven,
            "unproven",
            format!("HEAD in {here} is not on a branch, so there is no upstream to be behind"),
            Some(format!(
                "git -C {here} checkout <branch>   restores the comparison"
            )),
        ),
        Checkout::NoUpstream { branch } => (
            Mark::Unproven,
            "unproven",
            format!(
                "branch {branch} in {here} tracks nothing, so how far behind it is \
                 cannot be asked"
            ),
            Some(format!(
                "git -C {here} branch --set-upstream-to=origin/{branch} {branch}"
            )),
        ),
        Checkout::Shallow { upstream } => (
            Mark::Unproven,
            "unproven",
            format!(
                "{here} is a shallow clone, so a distance from {upstream} would be \
                 WRONG rather than absent. None is given"
            ),
            Some(format!("git -C {here} fetch --unshallow")),
        ),
        Checkout::Behind {
            upstream,
            behind,
            ahead,
            fetched_ago,
        } => (
            Mark::Broken,
            "behind",
            format!(
                "{here} is at least {behind} commit(s) behind {upstream}, {}. This \
                 binary is built from source that old, and the row above cannot see \
                 it",
                as_of(*fetched_ago)
            ),
            Some(if *ahead == 0 {
                format!("git -C {here} pull --ff-only && cargo build --release")
            } else {
                format!(
                    "{ahead} local commit(s) are not on {upstream}, so a \
                     fast-forward refuses. Reconcile, then: cargo build --release \
                     (in {here})"
                )
            }),
        ),
        Checkout::NotBehind {
            upstream,
            ahead,
            fetched_ago,
        } => (
            Mark::Unproven,
            "unproven",
            format!(
                "not behind {upstream}, {}. NOTHING here contacted the remote, so a \
                 commit pushed since then is invisible to this row{}",
                as_of(*fetched_ago),
                if *ahead == 0 {
                    String::new()
                } else {
                    format!("; {ahead} local commit(s) are not pushed, which is not a fault")
                }
            ),
            Some(format!(
                "git -C {here} fetch   asks the remote; this report never does"
            )),
        ),
    };
    Some(BuildRow {
        mark,
        subject: "checkout",
        state,
        detail,
        next,
    })
}

/// When the ref a checkout verdict rests on was last refreshed.
///
/// Printed beside every verdict, red or not. It is the difference between "this
/// checkout is level" and "this checkout is level according to something a week
/// old", and those are not the same sentence.
fn as_of(fetched_ago: Option<std::time::Duration>) -> String {
    fetched_ago.map_or_else(
        || "as of a last fetch this cannot date".to_owned(),
        |elapsed| format!("as of a fetch {}", crate::checkout::ago(elapsed)),
    )
}

/// Whether the guards are firing — and it is at the TOP of the report for one
/// reason.
///
/// A disabled install that reports healthy is the worst false green available
/// here: the reader believes a whole layer is protecting them and it is inert.
/// So the state is stated before the store rows rather than after them, in the
/// same vocabulary as everything else, with a distinct glyph and a distinct
/// word — and a reader who scans only the marks still sees it.
///
/// It deliberately does NOT count as a problem for the exit code. Somebody who
/// turned the guards off meant to, and a health command that goes red over a
/// choice is a health command people stop running — which is how the switch
/// stops being an honest alternative to gutting the settings file by hand.
fn guards(setup: &crate::paths::SetupPaths, style: Style, out: &mut dyn Write) -> io::Result<()> {
    use crate::cmd::setup::Guards;

    heading(out, style, "GUARDS")?;
    match crate::cmd::setup::guards(setup) {
        Guards::Armed => {
            let registered = std::fs::read_to_string(setup.settings())
                .is_ok_and(|text| text.contains("keyless_hook.py"));
            if registered {
                row(
                    out,
                    style,
                    Mark::Proven,
                    "guards",
                    6,
                    "proven",
                    &format!("registered in {}", setup.settings().display()),
                )?;
            } else {
                row(
                    out,
                    style,
                    Mark::NotSetUp,
                    "guards",
                    6,
                    "absent",
                    "nothing refuses a command that would print a credential",
                )?;
                action(
                    out,
                    style,
                    &format!(
                        "{} setup   installs them, naming every file it touches",
                        crate::NAME
                    ),
                )?;
            }
        }
        Guards::Disabled => {
            row(
                out,
                style,
                Mark::Off,
                "guards",
                6,
                "off",
                &format!(
                    "SWITCHED OFF. No check fires, whatever is registered. \
                     `enabled: false` in {}",
                    setup.hooks_config.display()
                ),
            )?;
            action(
                out,
                style,
                &format!("{} enable   turns them back on, instantly", crate::NAME),
            )?;
        }
        Guards::Observing => {
            row(
                out,
                style,
                Mark::Off,
                "guards",
                6,
                "off",
                &format!(
                    "recording only. Every check runs and NOTHING is blocked. \
                     `observe: true` in {}",
                    setup.hooks_config.display()
                ),
            )?;
        }
    }
    Ok(())
}

/// One row per backend this build knows about, live or not.
fn store_rows(config: &Config, registry: &Registry) -> Vec<StoreRow> {
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
                Err(error) => failing_row(id, &error),
            },
            None => dormant_row(config, id),
        })
        .collect()
}

/// Where a live store points, for the detail column of a proven row.
///
/// A proven row still has to say WHAT was proven against, or two machines with
/// wildly different configurations produce the same green line. The state word
/// says how far the proof reached; this says where it reached to.
fn points_at(config: &Config, id: &str) -> String {
    match id {
        "keychain" => format!("service \"{}\"", config.stores.keychain.service),
        "infisical" => {
            let path = &config.stores.infisical.path;
            match &config.stores.infisical.project_id {
                Some(project) => format!("path {path}, project {project}"),
                None => format!("path {path}, project from the working directory"),
            }
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
fn failing_row(id: &str, error: &StoreError) -> StoreRow {
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
        action: Some(remedy(id, error)),
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
fn remedy(id: &str, error: &StoreError) -> String {
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
        "proton" => "`pass-cli login` into `stores.proton.session_dir`, \
                     or re-issue the agent token"
            .to_owned(),
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
fn report_stores(rows: &[StoreRow], style: Style, out: &mut dyn Write) -> io::Result<i32> {
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

/// The NAMES section. Returns how many rows are problems.
fn report_names(
    config: &Config,
    registry: &Registry,
    stores: &[StoreRow],
    probe: bool,
    style: Style,
    out: &mut dyn Write,
) -> io::Result<i32> {
    if config.secrets.is_empty() {
        return Ok(0);
    }
    heading(out, style, "NAMES")?;

    if !probe {
        // Say what was NOT checked, and say what it costs, in the one place
        // somebody is looking when something is broken. The flag has existed all
        // along and the README documents it; this report never mentioned it, so
        // it was reached only by people who had already read the manual for a
        // different reason. A capability nothing points at is one nobody runs.
        //
        // The cost is stated because it is the answer to "why is this not the
        // default": resolving a name READS that credential out of the store —
        // for Proton, one vendor call per name and one permanent off-machine
        // audit entry per item. A health command that reads every credential you
        // own on every invocation is a worse default than one that checks less.
        // Its own width. Padding a one-row summary out to the longest DECLARED
        // name indents the detail past the line budget and wraps a sentence
        // that fits — the alignment was serving rows that this branch never
        // prints.
        row(
            out,
            style,
            Mark::Unproven,
            "(all)",
            "(all)".len(),
            "unproven",
            &format!(
                "{} declared, not probed; nothing has been read back",
                config.secrets.len()
            ),
        )?;
        action(
            out,
            style,
            &format!(
                "{} doctor --probe asks each one; it READS each credential to do so",
                crate::NAME
            ),
        )?;
        report_extra_variables(config, style, out)?;
        return Ok(0);
    }

    let width = config
        .secrets
        .keys()
        .map(String::len)
        .max()
        .unwrap_or(6)
        .max(6);

    let failed: BTreeMap<&str, &StoreRow> = stores
        .iter()
        .filter(|row| row.mark != Mark::Proven)
        .map(|row| (row.id.as_str(), row))
        .collect();

    let mut problems = 0;
    for name in config.secrets.keys() {
        // The store this name would use, by exactly the rule a lookup applies.
        // A name whose store is already down is not asked: see this module's
        // documentation for why that is a saving rather than a shortcut.
        if let Ok(id) = store::choose_store(config, Some(name), None)
            && let Some(store) = failed.get(id.as_str())
        {
            row(
                out,
                style,
                Mark::Unproven,
                name,
                width,
                "blocked",
                &format!("nothing asked; store `{id}` is `{}` above", store.state),
            )?;
            continue;
        }

        let (mark, state, detail, next) = match registry.resolve(name) {
            // Never `ok`. `ok` is a verdict on the credential and this is a
            // verdict on the lookup: an expired token, an account-wide one, and
            // somebody else's all resolve identically.
            Resolution::Found { store, .. } => (
                Mark::Proven,
                "proven",
                format!("read back from {store}{}", delivered_suffix(config, name)),
                None,
            ),
            Resolution::NotFound => (
                Mark::NotSetUp,
                "absent",
                "declared here, and no store holds it".to_owned(),
                Some(format!(
                    "{} put {name}   (reads the value on stdin, and never echoes it)",
                    crate::NAME
                )),
            ),
            Resolution::Failed(errors) => (
                Mark::Broken,
                "broken",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
                Some("the store answered and refused this name".to_owned()),
            ),
            // Nothing was asked, so nothing is known about whether the name
            // exists. Saying `absent` here would send the reader to the vault
            // instead of to the one line of config that fixes it.
            ambiguous @ Resolution::Ambiguous { .. } => (
                Mark::NotSetUp,
                "ambiguous",
                ambiguous.reason(),
                Some(format!(
                    "add \"store\" to \"{name}\", or set \"stores.default\""
                )),
            ),
        };
        row(out, style, mark, name, width, state, &detail)?;
        if let Some(text) = next {
            action(out, style, &text)?;
        }
        problems += i32::from(mark.is_problem());
    }
    Ok(problems)
}

/// Which variables a bare `-s NAME` would set, beyond the name itself.
///
/// Through [`Binding::declared`], so this cannot disagree with the run. An
/// undeclared name, and a declaration that names no variable, both yield an
/// empty list and print nothing.
fn extra_variables(config: &Config, name: &str) -> Vec<String> {
    Binding::declared(name, config)
        .map(|binding| binding.also)
        .unwrap_or_default()
}

/// The tail of a proven name's detail: what the child will actually see.
fn delivered_suffix(config: &Config, name: &str) -> String {
    match extra_variables(config, name).as_slice() {
        [] => String::new(),
        extra => format!(", delivered as ${name} and ${}", extra.join(" and $")),
    }
}

/// Say which names arrive under a second variable, when nothing was probed.
///
/// Printed even without `--probe`, because it costs no store call: it is a fact
/// about the config file, and it is the one fact a person most often needs
/// before a run rather than after one.
fn report_extra_variables(config: &Config, style: Style, out: &mut dyn Write) -> io::Result<()> {
    let mut said = false;
    for name in config.secrets.keys() {
        let extra = extra_variables(config, name);
        if extra.is_empty() {
            continue;
        }
        if !said {
            note(
                out,
                style,
                "these also arrive under a second variable, so a program reading its own \
                 name finds the value without anybody spelling it:",
            )?;
            said = true;
        }
        // `verbatim`, so the indent that groups these under the sentence above
        // survives: wrapping collapses runs of spaces.
        verbatim(
            out,
            style,
            &format!("  -s {name}  sets ${name} and ${}", extra.join(" and $")),
        )?;
    }
    Ok(())
}

/// The AUDIT section. Returns how many rows are problems.
fn report_audit(audit: &AuditLog, style: Style, out: &mut dyn Write) -> io::Result<i32> {
    heading(out, style, "AUDIT")?;
    let path = audit.path().display().to_string();
    match audit.verify() {
        Ok(0) => {
            row(out, style, Mark::Unproven, "audit", 6, "unproven", &path)?;
            note(out, style, "no rows yet, so there is no chain to check")?;
            Ok(0)
        }
        Ok(rows) => {
            row(out, style, Mark::Proven, "audit", 6, "proven", &path)?;
            note(out, style, &format!("{rows} rows, chain intact"))?;
            Ok(0)
        }
        Err(error) => {
            row(
                out,
                style,
                Mark::Broken,
                "audit",
                6,
                "broken",
                &error.to_string(),
            )?;
            action(out, style, &format!("the log is at {path}"))?;
            Ok(1)
        }
    }
}

/// State the one thing this report can never establish, every time it runs.
///
/// Not a check and not a finding — a standing boundary, printed whether or not
/// `--probe` was asked for, and never counted as a problem. The module docs hold
/// the reasoning and the measurement; this is the line a reader actually meets.
///
/// It exists because the alternative is a hole. A report that lists names and
/// says nothing about scope leaves the reader to fill scope in from somewhere,
/// and the somewhere is a note in `ls` that nothing has re-read since the day it
/// was typed. Saying "not checked here, ask the provider" costs five lines and
/// removes the vacancy.
fn report_capability_boundary(style: Style, out: &mut dyn Write) -> io::Result<()> {
    heading(out, style, "SCOPE")?;
    row(
        out,
        style,
        Mark::Unproven,
        "scope",
        6,
        "unproven",
        "not checked, and never will be",
    )?;
    note(
        out,
        style,
        "a name that resolves proves a store answered. It proves nothing about",
    )?;
    note(
        out,
        style,
        "what the credential may DO or WHOSE it is. An `ls` note claiming a scope",
    )?;
    note(
        out,
        style,
        "is prose; ask the provider to enumerate its own grant, and read that.",
    )
}

#[cfg(test)]
mod tests {
    use super::{doctor, report_build};
    use crate::audit::AuditLog;
    use crate::checkout::Checkout;
    use crate::cmd::status::Style;
    use crate::config::Config;
    use crate::error::StoreError;
    use crate::freshness::Freshness;
    use crate::paths::Paths;
    use crate::secret::Secret;
    use crate::store::{Registry, Store};
    use std::path::{Path, PathBuf};

    struct Healthy;
    impl Store for Healthy {
        fn id(&self) -> &str {
            "healthy"
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            Ok(Some(Secret::new("decoy-doctor-value".to_owned())))
        }
        fn health(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    /// A registry whose one store carries a real backend id, so the NAMES
    /// section can route to it the way a real config would.
    struct Named(&'static str);
    impl Store for Named {
        fn id(&self) -> &str {
            self.0
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            Ok(Some(Secret::new("decoy-doctor-value".to_owned())))
        }
        fn health(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    fn loaded(json: &str) -> crate::config::ConfigLoad {
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let mut load = Config::load(&paths.config);
        load.config = serde_json::from_str(json).expect("valid");
        load.loaded = true;
        load
    }

    /// A checkout verdict that says nothing, so a test about the BUILD row is
    /// about the BUILD row.
    fn quiet() -> Checkout {
        Checkout::NoSourceTree
    }

    /// One BUILD section, rendered plain, with the number of problems it counted.
    fn build_section(freshness: &Freshness, checkout: &Checkout) -> (String, i32) {
        let mut out: Vec<u8> = Vec::new();
        let problems = report_build(freshness, checkout, Style::PLAIN, &mut out).expect("write");
        (String::from_utf8(out).expect("utf-8"), problems)
    }

    /// A render with every run of whitespace collapsed to one space.
    ///
    /// Detail text is wrapped to the terminal budget, so a phrase a reader sees
    /// as one sentence is split across two lines by a newline and a column of
    /// padding. A `contains` over the raw render therefore fails on any
    /// assertion longer than a few words — which reads as a missing message and
    /// is a present one, wrapped.
    fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The one line of a rendered section whose subject column says `subject`.
    ///
    /// The mark is the FIRST character of the row, and `Mark::Proven` renders
    /// `+` in [`Style::PLAIN`] while `Mark::Unproven` renders `~`. Asserting on
    /// the glyph rather than the word matters here: `unproven` contains
    /// `proven`, so a `contains("proven")` check cannot tell the only two states
    /// this section needs to keep apart.
    fn line_for<'a>(text: &'a str, subject: &str) -> &'a str {
        text.lines()
            .find(|line| line.split_whitespace().nth(1) == Some(subject))
            .unwrap_or_else(|| panic!("no {subject} row in:\n{text}"))
    }

    #[test]
    fn a_stale_binary_is_a_problem_and_names_both_the_file_and_the_fix() {
        let (text, problems) = build_section(
            &Freshness::Stale {
                newest: PathBuf::from("/somewhere/src/store/infisical.rs"),
            },
            &quiet(),
        );
        assert_eq!(problems, 1, "{text}");
        assert!(text.contains("stale"), "{text}");
        assert!(
            text.contains("/somewhere/src/store/infisical.rs"),
            "the row must name the evidence a reader can check: {text}"
        );
        assert!(
            text.contains("cargo build --release"),
            "a diagnosis with no next action is the shape this report used to have: {text}"
        );
    }

    #[test]
    fn a_current_binary_costs_no_problem_and_disclaims_the_checkout() {
        // The narrowing is the point. `+ build proven` at the top of a health
        // report is read as "the code is current", and on 2026-08-10 that exact
        // tick certified a binary built from a checkout six commits behind. The
        // row states what it compared and refuses the wider reading in the same
        // breath.
        let (text, problems) = build_section(&Freshness::Current, &quiet());
        assert_eq!(problems, 0, "{text}");
        assert!(
            flat(&text).contains("newer than every source file in"),
            "{text}"
        );
        assert!(
            flat(&text).contains("whether that checkout is itself current is the row below"),
            "the passing row must name what it does NOT prove: {text}"
        );
    }

    #[test]
    fn a_machine_with_no_source_tree_is_told_nothing_at_all() {
        // The control first: the same function does print for a verdict.
        let (present, _) = build_section(&Freshness::Current, &quiet());
        assert!(!present.is_empty());

        let (text, problems) = build_section(&Freshness::NoSourceTree, &Checkout::NoSourceTree);
        assert_eq!(problems, 0);
        assert!(
            text.is_empty(),
            "an installed release has no tree to compare against and no finding \
             to report; a row on every invocation teaches people to skip this \
             section — and the heading must go with the rows: {text}"
        );
    }

    #[test]
    fn a_comparison_that_could_not_be_made_never_reads_as_one_that_passed() {
        let (text, problems) = build_section(
            &Freshness::Unknown {
                reason: "cannot locate the running binary".to_owned(),
            },
            &quiet(),
        );
        assert_eq!(problems, 0, "an unanswered question is not a fault: {text}");
        assert!(text.contains("unproven"), "{text}");
        assert!(text.contains("cannot locate the running binary"), "{text}");
        assert!(
            !text.contains("newer than every source file"),
            "an unknown verdict must not borrow the passing row's words: {text}"
        );
    }

    #[test]
    fn a_checkout_behind_its_upstream_is_a_problem_and_names_the_count_and_the_fix() {
        // The defect this section was extended for: the binary matches its
        // source, the source is six commits old, and the old report said
        // `proven` and exited 0.
        let (text, problems) = build_section(
            &Freshness::Current,
            &Checkout::Behind {
                upstream: "origin/master".to_owned(),
                behind: 6,
                ahead: 0,
                fetched_ago: Some(std::time::Duration::from_secs(7_200)),
            },
        );
        assert_eq!(problems, 1, "{text}");
        assert!(
            flat(&text).contains("at least 6 commit(s) behind origin/master"),
            "{text}"
        );
        assert!(
            flat(&text).contains("as of a fetch 2h ago"),
            "a verdict from a ref must carry that ref's age: {text}"
        );
        assert!(text.contains("pull --ff-only"), "{text}");
    }

    #[test]
    fn a_diverged_checkout_is_not_offered_a_fast_forward() {
        let (text, problems) = build_section(
            &Freshness::Current,
            &Checkout::Behind {
                upstream: "origin/master".to_owned(),
                behind: 3,
                ahead: 2,
                fetched_ago: None,
            },
        );
        assert_eq!(problems, 1, "{text}");
        assert!(
            !text.contains("pull --ff-only"),
            "a fast-forward refuses with a local commit in the way, so printing it \
             sends the reader to a command that cannot work: {text}"
        );
        assert!(
            flat(&text).contains("2 local commit(s) are not on origin/master"),
            "{text}"
        );
        assert!(
            flat(&text).contains("as of a last fetch this cannot date"),
            "an unknown fetch time must not read as a recent one: {text}"
        );
    }

    #[test]
    fn a_checkout_that_is_not_behind_is_never_a_tick() {
        // The whole reason this row has no green: `@{u}` is only as new as the
        // last fetch, and nothing here fetches. A tick would be a false green
        // with an extra step.
        let (text, problems) = build_section(
            &Freshness::Current,
            &Checkout::NotBehind {
                upstream: "origin/master".to_owned(),
                ahead: 0,
                fetched_ago: Some(std::time::Duration::from_secs(604_800)),
            },
        );
        assert_eq!(problems, 0, "not behind is not a fault either: {text}");
        let checkout = line_for(&text, "checkout");
        assert!(
            checkout.trim_start().starts_with('~'),
            "the mark must be Unproven, not Proven: {checkout}"
        );
        assert!(
            line_for(&text, "build").trim_start().starts_with('+'),
            "the control: the build row above IS a tick in the same render:\n{text}"
        );
        assert!(
            flat(checkout).contains("as of a fetch 7d ago"),
            "{checkout}"
        );
        assert!(
            flat(&text).contains("NOTHING here contacted the remote"),
            "the row must say what it did not do: {text}"
        );
        assert!(text.contains("fetch"), "{text}");
    }

    #[test]
    fn an_unpushed_commit_is_reported_without_being_called_a_fault() {
        let (text, problems) = build_section(
            &Freshness::Current,
            &Checkout::NotBehind {
                upstream: "origin/master".to_owned(),
                ahead: 2,
                fetched_ago: Some(std::time::Duration::from_secs(30)),
            },
        );
        assert_eq!(
            problems, 0,
            "a row that went red between every commit and its push would be \
             removed within a week: {text}"
        );
        assert!(
            flat(&text).contains("2 local commit(s) are not pushed"),
            "{text}"
        );
    }

    #[test]
    fn a_checkout_that_cannot_be_asked_says_which_way_it_failed() {
        for (checkout, expected) in [
            (
                Checkout::CannotAsk {
                    reason: "cannot ask git: cannot run it: No such file".to_owned(),
                },
                "cannot ask git",
            ),
            (Checkout::Detached, "not on a branch"),
            (
                Checkout::NoUpstream {
                    branch: "wip".to_owned(),
                },
                "branch wip",
            ),
            (
                Checkout::Shallow {
                    upstream: "origin/master".to_owned(),
                },
                "shallow clone",
            ),
        ] {
            let (text, problems) = build_section(&Freshness::Current, &checkout);
            assert_eq!(problems, 0, "{text}");
            assert!(
                flat(&text).contains(expected),
                "{expected} missing from:\n{text}"
            );
            assert!(
                line_for(&text, "checkout").trim_start().starts_with('~'),
                "an unanswerable question is neither a pass nor a fault:\n{text}"
            );
        }
    }

    #[test]
    fn the_build_row_comes_before_everything_it_would_invalidate() {
        // Placement is the claim: a stale binary does not make one row wrong, it
        // makes every row a statement about code nobody is reading. Reported
        // below the stores, it is reached by scrolling past the green it
        // invalidates.
        let load = loaded(r#"{"secrets":{"A":{}}}"#);
        let (text, _) = report(&load, Registry::new(vec![Box::new(Healthy)]), false);
        let build = text.find("BUILD").expect("the BUILD section is rendered");
        for later in ["STORES", "NAMES", "AUDIT"] {
            assert!(
                build < text.find(later).unwrap_or(usize::MAX),
                "BUILD must precede {later}:\n{text}"
            );
        }
    }

    fn report(load: &crate::config::ConfigLoad, registry: Registry, probe: bool) -> (String, i32) {
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let audit = AuditLog::new(PathBuf::from("/nonexistent/keyless-doctor/audit.jsonl"));
        render(&paths, load, &registry, &audit, probe)
    }

    /// One report, rendered plain. `Style::PLAIN` on purpose: every assertion
    /// here is about WORDS, and a coloured render wraps each one in escapes a
    /// `contains` cannot see through.
    fn render(
        paths: &Paths,
        load: &crate::config::ConfigLoad,
        registry: &Registry,
        audit: &AuditLog,
        probe: bool,
    ) -> (String, i32) {
        let mut out: Vec<u8> = Vec::new();
        let code = doctor(
            &super::DoctorRequest {
                paths,
                load,
                registry,
                audit,
                setup: None,
                notes: &[],
                probe,
                style: Style::PLAIN,
            },
            &mut out,
        )
        .expect("write");
        (String::from_utf8(out).expect("utf-8"), code)
    }

    #[test]
    fn probe_reports_presence_and_never_a_value() {
        let load = loaded(r#"{"secrets":{"DECOY":{}}}"#);
        let (text, code) = report(&load, Registry::new(vec![Box::new(Healthy)]), true);

        assert!(text.contains("DECOY"), "{text}");
        assert!(text.contains("proven"), "{text}");
        assert!(
            !text.contains("decoy-doctor-value"),
            "doctor leaked a value"
        );
        assert_eq!(code, 0, "{text}");
    }

    #[test]
    fn a_resolving_name_is_never_reported_as_a_verdict_on_the_credential() {
        // `ok` was a verdict on the credential; every state word in this report
        // is a verdict on a MEASUREMENT. An expired token, an account-wide one
        // and somebody else's all resolve identically, so the word has to name
        // what was actually observed.
        let load = loaded(r#"{"secrets":{"DECOY":{}}}"#);
        let (text, _) = report(&load, Registry::new(vec![Box::new(Healthy)]), true);
        assert!(
            !text.contains(" ok"),
            "the report used `ok`, which is the word that was false: {text}"
        );
    }

    #[test]
    fn the_scope_boundary_is_stated_whether_or_not_names_were_probed() {
        // The absence of a capability check is a printed line, not a hole. A
        // hole is what a hand-written `ls` note drifts into, and a note nothing
        // re-reads is how a token carrying 383 permission groups travelled as
        // `Zone:Read` + `DNS:Edit` through three briefs.
        let load = loaded(r#"{"secrets":{"DECOY":{}}}"#);
        for probe in [false, true] {
            let (text, code) = report(&load, Registry::new(vec![Box::new(Healthy)]), probe);
            assert!(text.contains("SCOPE"), "{text}");
            assert!(text.contains("not checked, and never will be"), "{text}");
            assert!(text.contains("WHOSE it is"), "{text}");
            // Never counted as a problem: it is a standing boundary, not a
            // finding, and a health command that always exits 1 gets ignored.
            assert_eq!(code, 0, "the boundary was counted as a problem: {text}");
        }
    }

    #[test]
    fn a_config_declaring_nothing_states_no_boundary() {
        // Without this, the assertions above pass on an implementation that
        // prints the block unconditionally — including for a machine that has
        // declared no names at all, where there is no scope to be wrong about.
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let load = Config::load(&paths.config);
        let (text, _) = report(&load, Registry::new(vec![Box::new(Healthy)]), false);
        assert!(!text.contains("SCOPE"), "{text}");
    }

    #[test]
    fn an_unprobed_report_says_so_and_names_the_flag_and_its_cost() {
        // The gap this closes is not a missing capability. `--probe` has always
        // existed and the README has always documented it; nothing in the
        // report a person actually reads ever mentioned it, so it was found
        // only by people who had already gone looking elsewhere.
        let load = loaded(r#"{"secrets":{"DECOY":{}}}"#);
        let (unprobed, _) = report(&load, Registry::new(vec![Box::new(Healthy)]), false);
        assert!(unprobed.contains("not probed"), "{unprobed}");
        assert!(unprobed.contains("--probe"), "{unprobed}");
        // The cost, so the reader can tell why it is not the default rather than
        // concluding the default is simply lazy.
        assert!(unprobed.contains("READS each credential"), "{unprobed}");

        // And the line is absent when the names WERE probed, so it can never
        // describe a report that does not match it.
        let (probed, _) = report(&load, Registry::new(vec![Box::new(Healthy)]), true);
        assert!(!probed.contains("not probed"), "{probed}");
    }

    #[test]
    fn a_store_that_is_switched_off_gets_a_row_and_is_not_a_problem() {
        // A config with `"enabled": false` used to produce no line at all, which
        // reads exactly like a build with no support for that backend. The row
        // is the whole point of the section: a reader came to see the stores,
        // including the ones they turned off.
        let load = loaded(r#"{"stores":{"keychain":{"enabled":false}},"secrets":{}}"#);
        let (text, code) = report(
            &load,
            Registry::new(vec![Box::new(Named("infisical"))]),
            false,
        );
        assert!(text.contains("keychain"), "{text}");
        assert!(text.contains("off"), "{text}");
        assert!(text.contains("proton"), "{text}");
        // A store nobody enabled is not an error, so it must not raise the
        // exit code.
        assert_eq!(
            code, 0,
            "an unenabled store was counted as a problem: {text}"
        );
    }

    #[test]
    fn a_name_whose_store_is_down_is_marked_blocked_and_never_asked() {
        // The relationship rule. A store that is down makes every name under it
        // fail for the same reason; printing that reason once per name buries
        // the one row that matters. Asking would also spend a doomed vendor call
        // per name — and against Proton, one permanent off-machine audit entry
        // per item.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Counting(Arc<AtomicUsize>);
        impl Store for Counting {
            fn id(&self) -> &str {
                "proton"
            }
            fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(None)
            }
            fn health(&self) -> Result<(), StoreError> {
                Err(StoreError::Unavailable {
                    store: "proton".to_owned(),
                    detail: "no session".to_owned(),
                })
            }
        }

        let asked = Arc::new(AtomicUsize::new(0));
        let load = loaded(
            r#"{"stores":{"keychain":{"enabled":false},"proton":{"enabled":true}},
                "secrets":{"A":{"store":"proton"},"B":{"store":"proton"}}}"#,
        );
        let registry = Registry::new(vec![Box::new(Counting(asked.clone()))]).with_routes(
            [
                ("A".to_owned(), "proton".to_owned()),
                ("B".to_owned(), "proton".to_owned()),
            ]
            .into_iter()
            .collect(),
        );
        let (text, code) = report(&load, registry, true);

        assert!(text.contains("blocked"), "{text}");
        assert_eq!(
            asked.load(Ordering::SeqCst),
            0,
            "a name was asked through a store already known to be down:\n{text}"
        );
        // The store row is still the problem, and it is counted once rather
        // than once per name it took down with it.
        assert_eq!(code, 1, "{text}");
        assert!(text.contains("\n1 problem(s)"), "{text}");
    }

    #[test]
    fn no_stores_is_reported_as_a_problem() {
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let load = Config::load(&paths.config);
        let (text, code) = report(&load, Registry::new(Vec::new()), false);
        assert_eq!(code, 1, "{text}");
        assert!(text.contains("none configured"), "{text}");
    }

    #[test]
    fn a_log_with_rows_removed_from_the_end_is_reported_as_a_problem() {
        // The measured defect this closes, at the layer a person actually
        // reads. Before the tail anchor existed, `doctor` printed
        // "ok, N rows, chain intact" and exited 0 for a log whose last row had
        // been deleted, while the same log missing a MIDDLE row was reported as
        // "audit chain broken at line 2". The undetected half is the common
        // one: a naive rotation, a stale restore, a stray `head -n -1`.
        //
        // A PROBLEM, not a refusal: `doctor` degrades a run and never blocks
        // one, which is why the assertion below is on the report and the exit
        // code, and there is nothing here about stopping anything.
        let dir = std::env::temp_dir().join(format!(
            "keyless-doctor-tail-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let log_path = dir.join("audit.jsonl");

        let audit = AuditLog::new(log_path.clone());
        let masker = crate::mask::Masker::new();
        for i in 0..3 {
            audit
                .append(&crate::audit::Event::new(
                    "run",
                    crate::State::Injected,
                    vec![],
                    &[format!("c{i}")],
                    &masker,
                ))
                .expect("append");
        }

        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let load = crate::config::Config::load(&paths.config);
        let registry = Registry::new(vec![Box::new(Healthy)]);

        // The control: with the log intact, this exact call is clean. Without
        // it, an assertion below would pass for a `doctor` that reports a
        // problem no matter what it is given.
        let (intact, code) = render(&paths, &load, &registry, &audit, false);
        assert!(intact.contains("chain intact"), "{intact}");
        assert_eq!(code, 0, "an intact log must not be a problem: {intact}");

        let raw = std::fs::read_to_string(&log_path).expect("read");
        let lines: Vec<&str> = raw.lines().collect();
        std::fs::write(&log_path, format!("{}\n{}\n", lines[0], lines[1])).expect("drop the last");

        let (text, code) = render(&paths, &load, &registry, &audit, false);
        assert!(
            text.contains("truncated or replaced"),
            "a log with its last row removed was not reported: {text}"
        );
        assert!(
            !text.contains("chain intact"),
            "a truncated log must not also be described as intact: {text}"
        );
        assert_eq!(code, 1, "{text}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_redirected_report_carries_no_escape_sequence() {
        // The rule the whole rendering rests on, asserted at the layer that
        // actually writes to stdout rather than only in the styling module.
        let load = loaded(r#"{"secrets":{"DECOY":{}}}"#);
        let (text, _) = report(&load, Registry::new(vec![Box::new(Healthy)]), true);
        assert!(!text.contains('\x1b'), "a redirected report was coloured");
    }
}
