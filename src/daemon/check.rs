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
use super::shadow::{self, Client};

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
pub fn report(
    config: &DaemonConfig,
    config_path: &Path,
    client: &Client,
    out: &mut dyn Write,
) -> io::Result<bool> {
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

    // Directly under the policy row, because it is the same subject one step
    // further on: `policy` says how many images this daemon accepts, and this
    // says whether the one a shell reaches is among them. A `client` fault is
    // the cause of symptoms that surface as refusals everywhere else, so it is
    // printed where it cannot be reached by scrolling past them.
    sound &= client_row(client, out)?;

    // Before the stores, because a store row that says PROBLEM because the
    // daemon cannot read its own login is a symptom, and this is the cause. The
    // two questions are different: this one asks whether the credential is
    // where it must be and shut to everyone else; the vendor's own `store` row
    // below asks whether the vendor accepts it.
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

/// Whether the `keyless` a shell reaches is the one this daemon pins.
///
/// # Why the report says this at all
///
/// Everything else here is about the daemon's own side of the socket. This is
/// the one row about the other side, and it is the only place the two halves
/// are compared: `peer.allow_images` names an image, `PATH` names a file, and
/// nothing until now asked whether they were the same file. When they are not,
/// every symptom appears somewhere else — a refusal that names a missing pin, a
/// subcommand that does not exist, a run that degrades — and none of them names
/// the cause.
///
/// # Only one verdict is a fault, and it is the one that cannot be a guess
///
/// [`Client::Shadowed`] and [`Client::NonePinned`] are faults: in both, the
/// binary a shell runs is refused by this daemon, which is a broken install
/// whatever the reason. Everything else is a question that could not be asked —
/// no pins, no `PATH`, no client on it — and prints `unproven`, because a
/// comparison nobody could make must not read as one that passed.
///
/// # What the remedy may say
///
/// For a shadow it names both files and stops. Which of the two should go is
/// the operator's call and not this daemon's: the file being reached is not the
/// pinned image, and that is the whole of what has been established about it —
/// it is equally consistent with a stale build of ours and with somebody else's
/// program of the same name. The one exception is a file cargo's own ledger
/// records as its own install of this package, where there is a correct verb
/// that is not `rm`, and [`shadow::cargo_installed`] is what establishes it.
fn client_row(client: &Client, out: &mut dyn Write) -> io::Result<bool> {
    match client {
        Client::NoPins { reason } => {
            writeln!(
                out,
                "client   unproven {reason}, so nothing can be compared to it"
            )?;
            Ok(true)
        }
        Client::NoPath => {
            writeln!(
                out,
                "client   unproven PATH is unset here, so which keyless a shell reaches cannot be asked"
            )?;
            Ok(true)
        }
        Client::NotOnPath => {
            writeln!(
                out,
                "client   unproven no keyless on the PATH this ran with. That is one process's \
                 PATH and never the next shell's, so this is a gap and not a finding"
            )?;
            Ok(true)
        }
        Client::Pinned { reached } => {
            writeln!(
                out,
                "client   ok {} is first on PATH and its code hash is pinned here",
                reached.display()
            )?;
            Ok(true)
        }
        Client::Shadowed { reached, pinned } => {
            writeln!(
                out,
                "client   PROBLEM {} is first on PATH and is NOT pinned here, while {} further \
                 along it is. Every request from the one your shell reaches is refused as \
                 `unknown-image`, which reads as a broken pin and is not one",
                reached.display(),
                pinned.display()
            )?;
            writeln!(out, "         {}", remedy(reached))?;
            Ok(false)
        }
        Client::NonePinned { reached, examined } => {
            writeln!(
                out,
                "client   PROBLEM none of the {examined} keyless on PATH is pinned here; {} is \
                 the one a shell reaches. Either this config pins a client that was replaced, or \
                 the pinned one is not on PATH at all",
                reached.display()
            )?;
            writeln!(
                out,
                "         keylessd pin --path <the installed keyless>, then put that hash in \
                 peer.allow_images and kickstart the daemon"
            )?;
            Ok(false)
        }
    }
}

/// The one action to take about a file that is being reached and should not be.
///
/// Two answers, and which one applies is a fact about provenance rather than a
/// preference. A file cargo installed is removed by cargo, because deleting it
/// by hand leaves cargo's ledger claiming it is still there. A file with no
/// such record is not identified, so nothing here proposes touching it: the
/// action that is right whatever it turns out to be is to stop reaching it
/// first.
fn remedy(reached: &Path) -> String {
    if shadow::cargo_installed(reached) {
        format!(
            "cargo uninstall keyless   removes {} and the keylessd beside it, and tells \
             cargo it is gone. Then `hash -r` — a shell keeps resolving a path it has \
             already looked up",
            reached.display()
        )
    } else {
        format!(
            "nothing here can say what {} is, so nothing here proposes deleting it: put the \
             pinned client's directory ahead of {} on PATH, then `hash -r`",
            reached.display(),
            reached.parent().unwrap_or(reached).display()
        )
    }
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

    /// Render the report with the client question deliberately unanswerable.
    ///
    /// Every case below is about a row other than `client`, and a walk of the
    /// real `PATH` would make each of them a statement about the machine the
    /// suite runs on. [`super::super::shadow`] has its own tests for the walk.
    fn rendered(config: &DaemonConfig, dir: &Path) -> (String, bool) {
        rendered_for(config, dir, &Client::NoPath)
    }

    fn rendered_for(config: &DaemonConfig, dir: &Path, client: &Client) -> (String, bool) {
        let mut out: Vec<u8> = Vec::new();
        let sound = report(config, &dir.join("keylessd.json"), client, &mut out).expect("a Vec");
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
