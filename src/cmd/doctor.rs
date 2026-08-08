//! `keyless doctor` — is anything wrong, and which layer.
//!
//! Answers the questions a degraded run raises: does the config parse, is the
//! backend reachable, does the audit log still chain. With `--probe` it also
//! asks each declared name whether it resolves — and prints only `ok`,
//! `missing` or the backend's error. Never a value, never a length, because a
//! length is still information about a secret.

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
                Resolution::Found { .. } => writeln!(out, "name     {name} ok")?,
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

    writeln!(
        out,
        "\n{} problem(s). A problem here degrades a run; it never blocks one.",
        problems
    )?;

    Ok(i32::from(problems > 0))
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

        assert!(report.contains("name     DECOY ok"));
        assert!(
            !report.contains("decoy-doctor-value"),
            "doctor leaked a value"
        );
        assert_eq!(code, 0);
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
        assert!(probed.contains("name     DECOY ok"), "{probed}");
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
