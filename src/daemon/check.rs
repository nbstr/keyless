//! The report `keylessd check` prints, and whether it is a report of health.
//!
//! # Why it lives here and not in the binary
//!
//! It is the only thing an operator runs to find out whether an install worked,
//! and everything that makes it worth running is a property of the WHOLE
//! report: that every row is printed even when an early one is a fault, and
//! that the verdict at the end agrees with the rows above it. Both of those are
//! testable against a writer and a config; neither is testable through a
//! process boundary without a scratch prefix and a spawn.
//!
//! # One fault does not end the report
//!
//! Every row is rendered and every fault is remembered. A bad pin used to
//! return where it stood, so the identity row and every store row went
//! unprinted — during an install, which is exactly when a pin is most likely to
//! be wrong and when those rows are what somebody is standing there to read.
//!
//! # A PROBLEM row and a green verdict cannot both be right
//!
//! [`report`] answers one question — is there anything wrong here — and it
//! answers it from the same rows it printed. The config's warnings used to be
//! the only input to that answer, so a report naming a store that can serve
//! nothing came back sound, and anything reading the verdict rather than the
//! rows was told the install was healthy while the report beneath it said it
//! was not.

use std::io::{self, Write};
use std::path::Path;

use super::config::DaemonConfig;
use super::credential;

/// Render the whole report, and say whether it found anything wrong.
///
/// `false` means at least one row above says `PROBLEM`, or the config carries a
/// warning. It is the caller's exit code and nothing else.
///
/// # Errors
///
/// Whatever `out` returns. Nothing here abandons a row because an earlier one
/// failed to render, so a truncated stream still costs at most the rows it
/// could not carry.
pub fn report(config: &DaemonConfig, config_path: &Path, out: &mut dyn Write) -> io::Result<bool> {
    writeln!(out, "config   {}", config_path.display())?;
    writeln!(out, "socket   {}", config.socket.display())?;
    writeln!(out, "audit    {}", config.audit.display())?;
    writeln!(
        out,
        "cache    {}s in memory, never on disk",
        config.cache_ttl_seconds
    )?;

    let mut sound = true;

    match config.policy() {
        Ok(policy) => writeln!(
            out,
            "policy   {} uid(s), {} pinned image(s), interpreted callers refused",
            config.peer.allow_uids.len(),
            policy.image_count()
        )?,
        Err(error) => {
            writeln!(out, "policy   PROBLEM {error}")?;
            sound = false;
        }
    }

    // Before the stores, because a store row that says PROBLEM because the
    // daemon cannot read its own login is a symptom, and this is the cause. The
    // two questions are different: this one asks whether the credential is
    // where it must be and shut to everyone else; the `infisical` row below
    // asks whether Infisical accepts it.
    sound &= credential::report(config, out)?;

    for store in config.registry().stores() {
        match store.health() {
            Ok(()) => writeln!(out, "store    {} ok", store.id())?,
            Err(error) => {
                writeln!(out, "store    {} PROBLEM {error}", store.id())?;
                sound = false;
            }
        }
    }

    // A healthy store is not a store that will be asked. With two enabled,
    // which one answers a name is decided here and nowhere else, so the
    // decision is printed beside them rather than left to be inferred from a
    // run that degrades later.
    writeln!(
        out,
        "routing  {} policy, default {}, {} name(s) pinned",
        match config.stores.policy {
            crate::config::Policy::Explicit => "explicit",
            crate::config::Policy::Ordered => "ordered",
        },
        config.stores.default_store.as_deref().unwrap_or("unset"),
        config
            .secrets
            .values()
            .filter(|route| route.store.is_some())
            .count()
    )?;

    let warnings = config.warnings();
    for warning in &warnings {
        writeln!(out, "warning  {warning}")?;
    }

    Ok(sound && warnings.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pin that decodes: 40 characters, the length of a code hash.
    const WELL_FORMED_PIN: &str = "0000000000000000000000000000000000000000";

    /// What the installer's dry run prints in place of a hash, and therefore
    /// the exact string somebody pastes into a config by mistake.
    const PLACEHOLDER_PIN: &str = "<keylessd pin --path /usr/local/bin/keyless>";

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-check-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// A store at the mode the daemon insists on. A store any other user could
    /// read is refused before its contents are looked at, so a fixture left at
    /// the umask's mode would be exercising that refusal instead.
    fn write_store(dir: &Path, body: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("secrets.json");
        std::fs::write(&path, body).expect("store");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    fn config_with(dir: &Path, pin: &str) -> DaemonConfig {
        serde_json::from_str(&format!(
            r#"{{
                 "socket": "{dir}/keylessd.sock",
                 "audit": "{dir}/audit.jsonl",
                 "peer": {{ "allow_uids": [1], "allow_images": ["{pin}"] }},
                 "stores": {{ "file": {{ "enabled": true, "path": "{dir}/secrets.json" }} }}
               }}"#,
            dir = dir.display(),
        ))
        .expect("a valid daemon config")
    }

    fn rendered(config: &DaemonConfig, dir: &Path) -> (String, bool) {
        let mut out: Vec<u8> = Vec::new();
        let sound = report(config, &dir.join("keylessd.json"), &mut out).expect("a Vec");
        (String::from_utf8(out).expect("ASCII rows"), sound)
    }

    /// The word after `subject` on the row it opens. Read as a whole word: `ok`
    /// is a substring of the sentences printed beside `PROBLEM`, so a
    /// `contains` here would be satisfied by the state it exists to exclude.
    fn word_after<'a>(rows: &'a str, subject: &str) -> Option<&'a str> {
        rows.lines()
            .find(|line| line.split_whitespace().next() == Some(subject))
            .and_then(|line| line.split_whitespace().nth(1))
    }

    fn store_state<'a>(rows: &'a str, id: &str) -> Option<&'a str> {
        rows.lines()
            .filter(|line| line.split_whitespace().next() == Some("store"))
            .find(|line| line.split_whitespace().nth(1) == Some(id))
            .and_then(|line| line.split_whitespace().nth(2))
    }

    #[test]
    fn a_sound_install_reports_sound() {
        // The control for both tests below. Without it, an assertion that a
        // broken install is reported broken is satisfied by a report that is
        // never sound about anything.
        let dir = scratch("sound");
        write_store(&dir, br#"{"DECOY":"decoy-check-0181"}"#);
        let (rows, sound) = rendered(&config_with(&dir, WELL_FORMED_PIN), &dir);

        assert_ne!(word_after(&rows, "policy"), Some("PROBLEM"), "{rows}");
        assert_eq!(store_state(&rows, "file"), Some("ok"), "{rows}");
        assert!(sound, "{rows}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_pin_does_not_hide_the_rows_underneath_it() {
        let dir = scratch("pin");
        write_store(&dir, br#"{"DECOY":"decoy-check-0182"}"#);
        let (rows, sound) = rendered(&config_with(&dir, PLACEHOLDER_PIN), &dir);

        assert_eq!(word_after(&rows, "policy"), Some("PROBLEM"), "{rows}");
        assert_eq!(
            store_state(&rows, "file"),
            Some("ok"),
            "the store rows were suppressed by the policy fault above them: {rows}"
        );
        assert!(
            word_after(&rows, "routing").is_some(),
            "the report stopped at the first fault: {rows}"
        );
        assert!(!sound, "{rows}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_store_that_was_emptied_is_a_problem_row_and_not_a_sound_report() {
        // The state `install -m 0600 /dev/null` over a full store leaves
        // behind: right mode, right owner, nothing in it. Every permission
        // check passes and no name can resolve. Green here is the whole hazard
        // — losing the store is bad, and reporting healthy afterwards is what
        // makes it unnoticeable.
        let dir = scratch("emptied");
        write_store(&dir, b"");
        let (rows, sound) = rendered(&config_with(&dir, WELL_FORMED_PIN), &dir);

        assert_eq!(store_state(&rows, "file"), Some("PROBLEM"), "{rows}");
        assert!(rows.contains("holds no names"), "{rows}");
        assert!(
            !sound,
            "a store that can serve nothing was reported sound: {rows}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
