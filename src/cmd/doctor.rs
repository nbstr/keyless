//! `keyless doctor` — is anything wrong, and which layer.
//!
//! Answers the questions a degraded run raises: does the config parse, is the
//! backend reachable, does the audit log still chain. With `--probe` it also
//! asks each declared name whether it resolves — and prints only `resolves`,
//! `missing` or the backend's error. Never a value, never a length, because a
//! length is still information about a secret.
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

use std::io::{self, Write};

use crate::audit::AuditLog;
use crate::config::ConfigLoad;
use crate::paths::Paths;
use crate::store::{Registry, Resolution};

/// Run every check, writing a report to `out`.
///
/// Returns the process exit code: 0 when everything checked out, 1 when
/// anything did not. `doctor` is the one verb allowed to be judgemental,
/// because nothing depends on it succeeding.
pub fn doctor(
    paths: &Paths,
    load: &ConfigLoad,
    registry: &Registry,
    audit: &AuditLog,
    notes: &[String],
    probe: bool,
    out: &mut dyn Write,
) -> io::Result<i32> {
    let mut problems = 0;

    for note in notes {
        writeln!(out, "note     {note}")?;
    }

    writeln!(out, "config   {}", paths.config.display())?;
    match &load.problem {
        Some(problem) => {
            problems += 1;
            writeln!(out, "         PROBLEM {problem}")?;
            writeln!(out, "         running with defaults; commands still run")?;
        }
        None if load.loaded => writeln!(
            out,
            "         ok, {} names declared",
            load.config.secrets.len()
        )?,
        None => writeln!(out, "         absent, using defaults")?,
    }

    writeln!(out, "audit    {}", audit.path().display())?;
    match audit.verify() {
        Ok(0) => writeln!(out, "         empty")?,
        Ok(rows) => writeln!(out, "         ok, {rows} rows, chain intact")?,
        Err(error) => {
            problems += 1;
            writeln!(out, "         PROBLEM {error}")?;
        }
    }

    if registry.is_empty() {
        problems += 1;
        writeln!(out, "stores   none configured")?;
    }
    for store in registry.stores() {
        match store.health() {
            Ok(()) => writeln!(out, "store    {} ok", store.id())?,
            Err(error) => {
                problems += 1;
                writeln!(out, "store    {} PROBLEM {error}", store.id())?;
            }
        }
    }

    report_daemon(load, out)?;

    if probe {
        for name in load.config.secrets.keys() {
            match registry.resolve(name) {
                // `resolves`, never `ok`. `ok` is a verdict on the credential
                // and this is a verdict on the lookup: a store answered. What
                // came back may be an expired token, an account-wide one, or
                // somebody else's — all three resolve identically.
                Resolution::Found { .. } => writeln!(out, "name     {name} resolves")?,
                Resolution::NotFound => {
                    problems += 1;
                    writeln!(out, "name     {name} missing")?;
                }
                Resolution::Failed(errors) => {
                    problems += 1;
                    let detail = errors
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ");
                    writeln!(out, "name     {name} PROBLEM {detail}")?;
                }
                // Reported as a problem rather than as "missing": nothing was
                // asked, so nothing is known about whether the name exists.
                // Saying `missing` here would send the reader to the vault
                // instead of to the one line of config that fixes it.
                ambiguous @ Resolution::Ambiguous { .. } => {
                    problems += 1;
                    writeln!(out, "name     {name} AMBIGUOUS {}", ambiguous.reason())?;
                }
            }
        }
    } else if !load.config.secrets.is_empty() {
        // Say what was NOT checked, and say what it costs, in the one place
        // somebody is looking when something is broken.
        //
        // The flag has existed all along and the README documents it; this
        // report never mentioned it, so it was reached by people who had
        // already read the manual for a different reason. A capability nothing
        // points at is one nobody runs.
        //
        // The cost is stated because it is the answer to "why is this not the
        // default": `--probe` resolves each name, and resolving a name READS
        // that credential out of the store — for Proton, one vendor `run` per
        // name and one permanent off-machine audit entry per item. A health
        // command that reads every credential you own on every invocation is a
        // worse default than one that checks less. Whether each STORE is alive
        // is checked above either way, and that costs no credential at all.
        writeln!(
            out,
            "names    {} declared, not probed",
            load.config.secrets.len()
        )?;
        writeln!(
            out,
            "         `{} doctor --probe` asks each one; it READS each credential to do so",
            crate::NAME
        )?;
    }

    if !load.config.secrets.is_empty() {
        report_capability_boundary(out)?;
    }

    writeln!(
        out,
        "\n{} problem(s). A problem here degrades a run; it never blocks one.",
        problems
    )?;

    Ok(i32::from(problems > 0))
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
fn report_capability_boundary(out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "scope    not checked, and never will be")?;
    writeln!(
        out,
        "         a name that resolves proves a store answered. It proves nothing"
    )?;
    writeln!(
        out,
        "         about what the credential may DO or WHOSE it is. An `ls` note"
    )?;
    writeln!(
        out,
        "         claiming a scope is prose; ask the provider to enumerate its own"
    )?;
    writeln!(out, "         grant, and read that.")
}

/// Say something about the daemon even when it is not configured.
///
/// The case worth catching is a socket that exists while the config does not
/// mention it: the daemon is installed and running, and every session is
/// quietly still reading the keychain directly. Nothing else in the tool would
/// ever mention that, because from `run`'s point of view everything is working.
///
/// It is not counted as a problem. `doctor`'s exit code is about whether this
/// machine can serve secrets, and it can.
fn report_daemon(load: &ConfigLoad, out: &mut dyn Write) -> io::Result<()> {
    let daemon = &load.config.stores.daemon;
    let socket = daemon.socket_path();
    let present = std::fs::symlink_metadata(&socket)
        .map(|meta| {
            use std::os::unix::fs::FileTypeExt;
            meta.file_type().is_socket()
        })
        .unwrap_or(false);

    match (daemon.enabled, present) {
        (true, true) => writeln!(out, "daemon   {} in use", socket.display()),
        (true, false) => writeln!(
            out,
            "daemon   {} enabled but absent; every name degrades",
            socket.display()
        ),
        (false, true) => {
            writeln!(out, "daemon   {} is listening, unused", socket.display())?;
            writeln!(
                out,
                "         set stores.daemon.enabled to route through it; \
                 until then secrets are read directly by this user"
            )
        }
        (false, false) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::doctor;
    use crate::audit::AuditLog;
    use crate::config::Config;
    use crate::error::StoreError;
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

    #[test]
    fn probe_reports_presence_and_never_a_value() {
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let load = Config::load(&paths.config);
        let mut load = load;
        load.config = serde_json::from_str(r#"{"secrets":{"DECOY":{}}}"#).expect("valid");
        load.loaded = true;
        let registry = Registry::new(vec![Box::new(Healthy)]);
        let audit = AuditLog::new(PathBuf::from("/nonexistent/keyless-doctor/audit.jsonl"));

        let mut out: Vec<u8> = Vec::new();
        let code = doctor(&paths, &load, &registry, &audit, &[], true, &mut out).expect("write");
        let report = String::from_utf8(out).expect("utf-8");

        assert!(report.contains("name     DECOY resolves"));
        assert!(
            !report.contains("decoy-doctor-value"),
            "doctor leaked a value"
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn a_resolving_name_is_never_reported_as_a_verdict_on_the_credential() {
        // `ok` was a verdict on the credential and this is a verdict on the
        // lookup. An expired token, an account-wide one and somebody else's all
        // resolve identically, so the word has to name what was actually
        // observed: a store answered.
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let mut load = Config::load(&paths.config);
        load.config = serde_json::from_str(r#"{"secrets":{"DECOY":{}}}"#).expect("valid");
        load.loaded = true;
        let registry = Registry::new(vec![Box::new(Healthy)]);
        let audit = AuditLog::new(PathBuf::from("/nonexistent/keyless-doctor/audit.jsonl"));

        let mut out: Vec<u8> = Vec::new();
        doctor(&paths, &load, &registry, &audit, &[], true, &mut out).expect("write");
        let report = String::from_utf8(out).expect("utf-8");
        assert!(
            !report.contains("DECOY ok"),
            "a lookup was reported as a verdict on the credential: {report}"
        );
    }

    #[test]
    fn the_scope_boundary_is_stated_whether_or_not_names_were_probed() {
        // The absence of a capability check is a printed line, not a hole. A
        // hole is what a hand-written `ls` note drifts into, and a note nothing
        // re-reads is how a token carrying 383 permission groups travelled as
        // `Zone:Read` + `DNS:Edit` through three briefs.
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let mut load = Config::load(&paths.config);
        load.config = serde_json::from_str(r#"{"secrets":{"DECOY":{}}}"#).expect("valid");
        load.loaded = true;
        let registry = Registry::new(vec![Box::new(Healthy)]);
        let audit = AuditLog::new(PathBuf::from("/nonexistent/keyless-doctor/audit.jsonl"));

        for probe in [false, true] {
            let mut out: Vec<u8> = Vec::new();
            let code =
                doctor(&paths, &load, &registry, &audit, &[], probe, &mut out).expect("write");
            let report = String::from_utf8(out).expect("utf-8");
            assert!(report.contains("scope    not checked"), "{report}");
            assert!(report.contains("WHOSE it is"), "{report}");
            // Never counted as a problem: it is a standing boundary, not a
            // finding, and a health command that always exits 1 gets ignored.
            assert_eq!(code, 0, "the boundary was counted as a problem: {report}");
        }
    }

    #[test]
    fn a_config_declaring_nothing_states_no_boundary() {
        // Without this, the assertions above pass on an implementation that
        // prints the block unconditionally — including for a machine that has
        // declared no names at all, where there is no scope to be wrong about.
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let load = Config::load(&paths.config);
        let registry = Registry::new(vec![Box::new(Healthy)]);
        let audit = AuditLog::new(PathBuf::from("/nonexistent/keyless-doctor/audit.jsonl"));

        let mut out: Vec<u8> = Vec::new();
        doctor(&paths, &load, &registry, &audit, &[], false, &mut out).expect("write");
        let report = String::from_utf8(out).expect("utf-8");
        assert!(!report.contains("scope    not checked"), "{report}");
    }

    #[test]
    fn an_unprobed_report_says_so_and_names_the_flag_and_its_cost() {
        // The gap this closes is not a missing capability. `--probe` has always
        // existed and the README has always documented it; nothing in the
        // report a person actually reads ever mentioned it, so it was found
        // only by people who had already gone looking elsewhere.
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let mut load = Config::load(&paths.config);
        load.config = serde_json::from_str(r#"{"secrets":{"DECOY":{}}}"#).expect("valid");
        load.loaded = true;
        let registry = Registry::new(vec![Box::new(Healthy)]);
        let audit = AuditLog::new(PathBuf::from("/nonexistent/keyless-doctor/audit.jsonl"));

        let mut out: Vec<u8> = Vec::new();
        doctor(&paths, &load, &registry, &audit, &[], false, &mut out).expect("write");
        let unprobed = String::from_utf8(out).expect("utf-8");
        assert!(unprobed.contains("not probed"), "{unprobed}");
        assert!(unprobed.contains("--probe"), "{unprobed}");
        // The cost, so the reader can tell why it is not the default rather than
        // concluding the default is simply lazy.
        assert!(unprobed.contains("READS each credential"), "{unprobed}");

        // And the line is absent when the names WERE probed, so it can never
        // describe a report that does not match it. Without this the assertions
        // above pass on an implementation that prints the line unconditionally.
        let mut out: Vec<u8> = Vec::new();
        doctor(&paths, &load, &registry, &audit, &[], true, &mut out).expect("write");
        let probed = String::from_utf8(out).expect("utf-8");
        assert!(!probed.contains("not probed"), "{probed}");
        assert!(probed.contains("name     DECOY resolves"), "{probed}");
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
        let mut out: Vec<u8> = Vec::new();
        let code = doctor(&paths, &load, &registry, &audit, &[], false, &mut out).expect("write");
        let intact = String::from_utf8(out).expect("utf-8");
        assert!(intact.contains("chain intact"), "{intact}");
        assert_eq!(code, 0, "an intact log must not be a problem: {intact}");

        let raw = std::fs::read_to_string(&log_path).expect("read");
        let lines: Vec<&str> = raw.lines().collect();
        std::fs::write(&log_path, format!("{}\n{}\n", lines[0], lines[1])).expect("drop the last");

        let mut out: Vec<u8> = Vec::new();
        let code = doctor(&paths, &load, &registry, &audit, &[], false, &mut out).expect("write");
        let report = String::from_utf8(out).expect("utf-8");
        assert!(
            report.contains("PROBLEM") && report.contains("truncated or replaced"),
            "a log with its last row removed was not reported: {report}"
        );
        assert!(
            !report.contains("chain intact"),
            "a truncated log must not also be described as intact: {report}"
        );
        assert_eq!(code, 1, "{report}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_stores_is_reported_as_a_problem() {
        let paths = Paths::under(Path::new("/nonexistent/keyless-doctor"));
        let load = Config::load(&paths.config);
        let registry = Registry::new(Vec::new());
        let audit = AuditLog::new(PathBuf::from("/nonexistent/keyless-doctor/audit.jsonl"));
        let mut out: Vec<u8> = Vec::new();
        let code = doctor(&paths, &load, &registry, &audit, &[], false, &mut out).expect("write");
        assert_eq!(code, 1);
        assert!(String::from_utf8_lossy(&out).contains("none configured"));
    }
}
