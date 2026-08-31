//! `keyless doctor` — what is proven, what is not, and what to do about it.
//!
//! Answers the questions a degraded run raises: does the config parse, is the
//! backend reachable, does the audit log still chain. With `--probe` it also
//! asks each declared name whether it resolves — and prints only that it
//! resolved, that it is absent, or the backend's error. Never a value, never a
//! length, because a length is still information about a secret.
//!
//! # Where the sections live
//!
//! Three sections are each a subject of their own — their own row type, their
//! own vocabulary, their own reasoning — and each is a file beside this one:
//! `build` compares the binary to its source and that source to its upstream,
//! `stores` prints one row per backend, and `names` prints one row per declared
//! name. What stays here is the report itself: what a report is about, the
//! order the sections come in, and the sections that are a single row — the
//! header, the guards, a config that would not parse, the audit chain, and the
//! scope this tool can never establish.
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
//!   non-credential key; for 1Password, the pinned vault's own record; for
//!   Proton, a vault listing as this session. None of the four reads a
//!   credential of yours.
//! - a **name** is proven only under `--probe`, which reads the real credential.
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

mod build;
mod names;
mod stores;

use std::io::{self, Write};

use crate::audit::AuditLog;
use crate::checkout::Checkout;
use crate::config::ConfigLoad;
use crate::freshness::Freshness;
use crate::paths::Paths;
use crate::store::Registry;

use self::build::report_build;
use self::names::report_names;
use self::stores::{report_stores, store_rows};
use super::status::{Mark, Style, action, heading, note, row};

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
    /// How fresh the running binary is against the source tree it was built
    /// from.
    ///
    /// Injected rather than measured inside, for the same reason `style` is.
    /// [`crate::freshness::check`] and [`crate::checkout::check`] read the REAL
    /// repository, so a `doctor` that called them itself made every test that
    /// went through it a test of the developer's working copy. Measured: five
    /// cases here failed the moment a branch diverged from its remote and
    /// `checkout` began -- correctly -- reporting a problem. The report is a
    /// pure function of what it is told; asking the world is the caller's job.
    pub freshness: &'a Freshness,
    /// Where this checkout stands against its upstream, injected for the reason
    /// above.
    pub checkout: &'a Checkout,
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
        freshness,
        checkout,
        style,
    } = *request;
    let mut problems = 0;

    header(paths, load, style, out)?;
    if let Some(setup) = setup {
        guards(setup, style, out)?;
    }
    problems += report_build(freshness, checkout, style, out)?;

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
    // Several fixtures below are `pub(super)`: the section modules render
    // through this same report, so a row asserted in `build` or `stores` is
    // followed into the text a person actually reads with the helper that
    // produced it here.
    use super::doctor;
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
    pub(super) struct Named(pub(super) &'static str);
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

    /// A config and a registry in which `DECOY` actually resolves.
    ///
    /// [`Healthy`]'s id is not a backend the router knows, so under a bare
    /// `{"secrets":{"DECOY":{}}}` the name goes to the DEFAULT store, which that
    /// registry never constructed — the row reads `blocked`, nothing is asked,
    /// and a case about what a probe reports is about a probe that never ran.
    /// A case whose subject is the resolution has to be handed one.
    fn resolving_decoy() -> (crate::config::ConfigLoad, Registry) {
        let load = loaded(
            r#"{"stores":{"keychain":{"enabled":true}},"secrets":{"DECOY":{"store":"keychain"}}}"#,
        );
        let registry = Registry::new(vec![Box::new(Named("keychain"))]).with_routes(
            [("DECOY".to_owned(), "keychain".to_owned())]
                .into_iter()
                .collect(),
        );
        (load, registry)
    }

    pub(super) fn loaded(json: &str) -> crate::config::ConfigLoad {
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let mut load = Config::load(&paths.config);
        load.config = serde_json::from_str(json).expect("valid");
        load.loaded = true;
        load
    }

    /// A render with every run of whitespace collapsed to one space.
    ///
    /// Detail text is wrapped to the terminal budget, so a phrase a reader sees
    /// as one sentence is split across two lines by a newline and a column of
    /// padding. A `contains` over the raw render therefore fails on any
    /// assertion longer than a few words — which reads as a missing message and
    /// is a present one, wrapped.
    pub(super) fn flat(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// The state column of one rendered row: `<mark> <subject> <state> <detail>`.
    ///
    /// A state word is a WHOLE column, and reading it as one is the difference
    /// between an assertion and a decoration. `unproven` CONTAINS `proven`, so
    /// `contains("proven")` passes on the single state it exists to exclude —
    /// and it is a live hole rather than a hypothetical one: every `proven` in
    /// this crate can be rewritten to `unproven`, leaving a green `✔` beside the
    /// word that denies it, and the whole suite stays green.
    pub(super) fn state_of(text: &str, subject: &str) -> String {
        text.lines()
            .find(|line| line.split_whitespace().nth(1) == Some(subject))
            .unwrap_or_else(|| panic!("no `{subject}` row in:\n{text}"))
            .split_whitespace()
            .nth(2)
            .unwrap_or_default()
            .to_owned()
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

    /// The everyday fixture: a current build and nothing to note.
    ///
    /// Fixed rather than probed. See the field docs on
    /// [`DoctorRequest::freshness`]: these cases are about names and stores, and
    /// a real reading here made them a test of whoever's checkout happened to be
    /// running them.
    ///
    /// `Current` rather than `NoSourceTree`: no source tree renders NO BUILD
    /// section at all, and one case here asserts the section's POSITION, so the
    /// quiet value would have deleted the thing it measures. `Current` renders
    /// the section and contributes no problem, which is what every case reached
    /// through this helper needs.
    pub(super) fn report(
        load: &crate::config::ConfigLoad,
        registry: Registry,
        probe: bool,
    ) -> (String, i32) {
        report_over(load, &registry, probe, &Freshness::Current, &[])
    }

    /// A report whose BUILD verdict and notes the case chooses.
    ///
    /// Both are sections [`report`] deliberately holds quiet, and two cases here
    /// need them: one counts what the whole report adds up to, and one asserts a
    /// heading that must never appear over nothing.
    fn report_over(
        load: &crate::config::ConfigLoad,
        registry: &Registry,
        probe: bool,
        freshness: &Freshness,
        notes: &[String],
    ) -> (String, i32) {
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let audit = AuditLog::new(PathBuf::from("/nonexistent/keyless-doctor/audit.jsonl"));
        render(&paths, load, registry, &audit, probe, freshness, notes)
    }

    /// One report, rendered plain. `Style::PLAIN` on purpose: every assertion
    /// here is about WORDS, and a coloured render wraps each one in escapes a
    /// `contains` cannot see through.
    ///
    /// The checkout verdict is the one fact no case varies: `NotBehind` renders
    /// the row and costs no problem, so a case about the arithmetic below is
    /// counting the sections it named rather than this one.
    fn render(
        paths: &Paths,
        load: &crate::config::ConfigLoad,
        registry: &Registry,
        audit: &AuditLog,
        probe: bool,
        freshness: &Freshness,
        notes: &[String],
    ) -> (String, i32) {
        let mut out: Vec<u8> = Vec::new();
        let code = doctor(
            &super::DoctorRequest {
                paths,
                load,
                registry,
                audit,
                setup: None,
                notes,
                probe,
                freshness,
                checkout: &Checkout::NotBehind {
                    upstream: String::new(),
                    ahead: 0,
                    fetched_ago: None,
                },
                style: Style::PLAIN,
            },
            &mut out,
        )
        .expect("write");
        (String::from_utf8(out).expect("utf-8"), code)
    }

    #[test]
    fn probe_reports_presence_and_never_a_value() {
        let (load, registry) = resolving_decoy();
        let (text, code) = report(&load, registry, true);

        assert!(text.contains("DECOY"), "{text}");
        // The DECOY row's own state column, not a `contains` over the report:
        // every report carries `unproven` in SCOPE and in AUDIT, so
        // `text.contains("proven")` was satisfied whatever the probed name did.
        assert_eq!(state_of(&text, "DECOY"), "proven", "{text}");
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
        let (load, registry) = resolving_decoy();
        let (text, _) = report(&load, registry, true);
        // The name must actually have resolved, or the absence below is the
        // absence of a row rather than the absence of a word.
        assert_eq!(state_of(&text, "DECOY"), "proven", "{text}");
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
        assert_eq!(state_of(&text, "keychain"), "off", "{text}");
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

        // A state word is a WHOLE word in a row, not a substring of one:
        // `contains("blocked")` also holds for `blockedX`, so it cannot fail on
        // a change to the vocabulary and is not an assertion at all.
        assert!(
            text.split_whitespace().any(|word| word == "blocked"),
            "no row carries `blocked` as its state word:\n{text}"
        );
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
        let (intact, code) = render(
            &paths,
            &load,
            &registry,
            &audit,
            false,
            &Freshness::Current,
            &[],
        );
        assert!(intact.contains("chain intact"), "{intact}");
        assert_eq!(code, 0, "an intact log must not be a problem: {intact}");

        let raw = std::fs::read_to_string(&log_path).expect("read");
        let lines: Vec<&str> = raw.lines().collect();
        std::fs::write(&log_path, format!("{}\n{}\n", lines[0], lines[1])).expect("drop the last");

        let (text, code) = render(
            &paths,
            &load,
            &registry,
            &audit,
            false,
            &Freshness::Current,
            &[],
        );
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

    #[test]
    fn the_first_line_orients_the_reader_before_any_section() {
        // The whole header could be deleted and every other case here stayed
        // green: not one of them read the line above the sections. It is the
        // line that says WHICH build is talking and WHICH file it read, which is
        // the first thing wrong when two installs disagree — a report whose rows
        // are all correct about somebody else's config is worse than no report.
        let load = loaded(r#"{"secrets":{"DECOY":{},"OTHER":{}}}"#);
        let (text, _) = report(&load, Registry::new(vec![Box::new(Healthy)]), false);
        let first = text.lines().next().expect("a report has a first line");

        assert!(first.contains(crate::NAME), "{first}");
        assert!(
            first.contains(env!("CARGO_PKG_VERSION")),
            "the header must name the version that is answering: {first}"
        );
        assert!(
            first.contains("keyless-doctor"),
            "the header must name the config file it read: {first}"
        );
        assert!(
            first.contains("2 name(s) declared"),
            "the header must count what it found there: {first}"
        );
    }

    /// A store that answers, and holds nothing.
    ///
    /// `Healthy` resolves every name, so a case that needs a name to come back
    /// ABSENT — which is the cheapest way to make the NAMES section contribute
    /// exactly one problem — cannot be built from it.
    struct Absent;
    impl Store for Absent {
        fn id(&self) -> &str {
            "keychain"
        }
        fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
            Ok(None)
        }
        fn health(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn the_trailing_count_is_the_number_of_problems_above_it() {
        // The arithmetic itself. Every `problems +=` in this report could be a
        // `*=` or a `-=` and the suite stayed green, because the only assertions
        // on the count were `0` and `1` — and `0` survives a multiplication
        // while `1` is reachable from several wrong sums. So both cases below
        // are built to total exactly TWO, from two different pairs of sections,
        // and both the printed number and the exit code are read.
        //
        // The exit code as well as the line: they are computed from the same
        // counter, and a reader who scripts around `doctor` reads only one of
        // them.

        // A broken config, which is the pair BUILD + CONFIG. `Config::load` over
        // a directory is a real `Unusable`, so nothing here has to construct an
        // error by hand or write a file to be cleaned up.
        let unreadable = Config::load(&std::env::temp_dir());
        assert!(
            unreadable.problem.is_some(),
            "the fixture must actually be a config problem"
        );
        let (text, code) = report_over(
            &unreadable,
            &Registry::new(vec![Box::new(Named("keychain"))]),
            false,
            &Freshness::Stale {
                newest: PathBuf::from("/somewhere/src/lib.rs"),
            },
            &[],
        );
        assert!(
            text.contains("\n2 problem(s)."),
            "a stale build and an unreadable config are two problems: {text}"
        );
        assert_eq!(code, 1, "{text}");

        // And the pair BUILD + NAMES, which is counted through a different
        // return value and a different loop.
        let declared = loaded(
            r#"{"stores":{"keychain":{"enabled":true}},"secrets":{"MISSING":{"store":"keychain"}}}"#,
        );
        let registry = Registry::new(vec![Box::new(Absent)]).with_routes(
            [("MISSING".to_owned(), "keychain".to_owned())]
                .into_iter()
                .collect(),
        );
        let (text, code) = report_over(
            &declared,
            &registry,
            true,
            &Freshness::Stale {
                newest: PathBuf::from("/somewhere/src/lib.rs"),
            },
            &[],
        );
        assert_eq!(
            state_of(&text, "MISSING"),
            "absent",
            "the fixture must actually be a missing name: {text}"
        );
        assert!(
            text.contains("\n2 problem(s)."),
            "a stale build and one absent name are two problems: {text}"
        );
        assert_eq!(code, 1, "{text}");
    }

    #[test]
    fn the_setup_action_is_offered_only_when_there_is_no_config_file_at_all() {
        // Three states, and the action belongs to exactly one of them. Offering
        // `setup` to somebody whose config is BROKEN sends them to a command
        // that writes a new file over the one they need to fix; withholding it
        // from somebody who has no file at all leaves the report saying `no
        // config file yet` and nothing about what to do.
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let offer = format!("{} setup detects your stores", crate::NAME);

        let absent = Config::load(&paths.config);
        let (text, _) = report(&absent, Registry::new(vec![Box::new(Healthy)]), false);
        assert!(text.contains("no config file yet"), "{text}");
        assert!(
            flat(&text).contains(&offer),
            "a machine with no config was not told how to get one: {text}"
        );

        let present = loaded(r#"{"secrets":{"DECOY":{}}}"#);
        let (text, _) = report(&present, Registry::new(vec![Box::new(Healthy)]), false);
        assert!(
            !flat(&text).contains(&offer),
            "a config that loaded was told to go and create one: {text}"
        );

        let unreadable = Config::load(&std::env::temp_dir());
        let (text, _) = report(&unreadable, Registry::new(vec![Box::new(Healthy)]), false);
        assert!(
            !flat(&text).contains(&offer),
            "a file that exists and will not parse is fixed where it is, not \
             overwritten by `setup`: {text}"
        );
    }

    #[test]
    fn the_notes_heading_is_never_printed_over_nothing() {
        // An empty heading is not a small cosmetic fault here: every other
        // heading in this report introduces rows, so a `NOTES` with nothing
        // under it reads as a note that failed to render — and sends the reader
        // looking for the missing sentence.
        let load = loaded(r#"{"secrets":{"DECOY":{}}}"#);
        let registry = Registry::new(vec![Box::new(Healthy)]);

        let (quiet, _) = report_over(&load, &registry, false, &Freshness::Current, &[]);
        assert!(
            !quiet.contains("NOTES"),
            "a report with nothing to note printed the heading anyway: {quiet}"
        );

        // The control: the same call DOES print the section when there is
        // something to put in it, so the absence above is the absence of notes
        // rather than of the whole feature.
        let (spoken, _) = report_over(
            &load,
            &registry,
            false,
            &Freshness::Current,
            &["the daemon is serving every name".to_owned()],
        );
        assert!(spoken.contains("NOTES"), "{spoken}");
        assert!(
            flat(&spoken).contains("the daemon is serving every name"),
            "{spoken}"
        );
    }
}
