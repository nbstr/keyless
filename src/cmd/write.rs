//! `keyless new` and `keyless put` — getting a value INTO a store.
//!
//! Two verbs in one file because they are one behaviour with two sources for the
//! value: `new` generates it, `put` reads it. Everything after that — the manager
//! identity, the config address, the store call, what is printed — is shared, and
//! two copies of it would eventually disagree about which identity writes.
//!
//! # There is still no verb that prints a value
//!
//! `new` generates a credential and never shows it. That is not an oversight, it
//! is the whole point: the value exists in this process and in the store, and
//! nowhere else. A caller that needs it runs the command that needs it under
//! `keyless run`.
//!
//! So there is no `--show`, no `--print`, no "here is what I made" line, and
//! `put` echoes nothing. If a human genuinely needs to see a generated
//! credential — pasting it into a provider's web form, say — they generate it in
//! that provider's UI and `put` it, which is the flow that never has a plaintext
//! in a terminal at all.
//!
//! # `put` refuses a value in an argument, and there is no flag for it
//!
//! No `--value`, no `--secret`, no positional value. An argument is readable
//! from the process table for as long as the process lives — the CLI-flag
//! shape, one of the four the README's *Why this exists* names.
//! Offering the flag guarantees it gets used, so the flag does not exist —
//! structurally, the same way `run` has no `--reveal`.
//!
//! Stdin is the only input. When stdin is a terminal, the value is prompted for
//! with echo off; when it is a pipe, it is read whole. One trailing newline is
//! stripped, exactly as the read adapters do for `printenv` and `security -w`,
//! because `printf '%s\n'` and a heredoc both add one and a credential whose own
//! last byte is a newline is not distinguishable from one without.
//!
//! # These verbs may refuse. `run` may not
//!
//! See [`crate::store::manage`] for the argument. Briefly: `run` never blocks
//! because blocking somebody's work gets the tool removed, after which the
//! plaintext comes back. `new` and `put` are setup steps with a person watching,
//! nothing downstream waits on them, and a write that "degraded" would report
//! success with nothing stored — which the next `run` would report as a missing
//! name for a reason nobody can find.

use std::io::{self, BufRead, Read, Write};

use zeroize::Zeroize;

use crate::config::SecretRoute;
use crate::random;
use crate::secret::Secret;
use crate::store::manage::{Manage, ManageError};

/// The longest value `put` will read from stdin.
///
/// A credential is not a file. Without a cap, `keyless put NAME < big.iso` reads
/// until memory runs out, and every byte of it is treated as sensitive on the way.
const MAX_INPUT_BYTES: usize = 64 * 1024;

/// What a write ended as.
pub struct Written {
    /// Process exit code: 0 on success, otherwise [`ManageError::exit_code`].
    pub exit_code: i32,
}

/// Generate a value and store it. Never prints it.
///
/// # Errors
///
/// Fails only when `out` cannot be written. Everything else is reported on
/// `notes` and in the exit code.
pub fn new(
    manager: &dyn Manage,
    name: &str,
    route: &SecretRoute,
    length: usize,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> io::Result<Written> {
    let value = match random::generate(length) {
        Ok(value) => value,
        Err(error) => {
            writeln!(notes, "{}: {error}", crate::NAME)?;
            // EX_DATAERR when the length was refused, EX_OSERR when the kernel's
            // generator could not be read; both are "nothing was written".
            let code = if error.kind() == io::ErrorKind::InvalidInput {
                65
            } else {
                71
            };
            return Ok(Written { exit_code: code });
        }
    };
    store(manager, name, route, &value, out, notes)
}

/// Read a value from `input` and store it. Never echoes it.
///
/// `interactive` says whether `input` is a terminal. It is a parameter rather
/// than a call to [`std::io::IsTerminal`] here so a test drives both paths, and
/// so the caller — which already knows — is the one that decides.
///
/// # Errors
///
/// Fails only when `out` cannot be written.
pub fn put(
    manager: &dyn Manage,
    name: &str,
    route: &SecretRoute,
    input: &mut dyn Read,
    interactive: bool,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> io::Result<Written> {
    if interactive {
        // The prompt goes to stderr, not to `out`: stdout is where a caller
        // redirects a machine-readable result, and a prompt in that stream would
        // land in a file.
        write!(notes, "{}: value for {name} (not echoed): ", crate::NAME)?;
        notes.flush()?;
    }

    let value = match read_value(input, interactive) {
        Ok(value) => value,
        Err(error) => {
            if interactive {
                writeln!(notes)?;
            }
            writeln!(notes, "{}: {error}", crate::NAME)?;
            return Ok(Written { exit_code: 65 });
        }
    };
    if interactive {
        // Echo was off, so the user's Enter produced no newline on the terminal.
        writeln!(notes)?;
    }

    store(manager, name, route, &value, out, notes)
}

/// The half both verbs share: hand the value to the manager and report.
fn store(
    manager: &dyn Manage,
    name: &str,
    route: &SecretRoute,
    value: &Secret,
    out: &mut dyn Write,
    notes: &mut dyn Write,
) -> io::Result<Written> {
    match manager.store(name, route, value) {
        Ok(stored) => {
            // The one line printed on success. It names the destination and the
            // identity that wrote it, and it is the whole output — there is
            // nothing here that could carry the value.
            writeln!(
                out,
                "stored\t{name}\t{}\t{}",
                stored.location,
                manager.identity()
            )?;
            Ok(Written { exit_code: 0 })
        }
        Err(error) => {
            writeln!(notes, "{}: {error}", crate::NAME)?;
            Ok(Written {
                exit_code: error.exit_code(),
            })
        }
    }
}

/// Read at most [`MAX_INPUT_BYTES`] and wrap it, scrubbing the buffer.
///
/// A terminal contributes one line — the user pressed Enter and meant it — while a
/// pipe contributes everything, because `printf '%s' "$v" | keyless put` and a
/// heredoc are both legitimate and a multi-line credential (a PEM key, say) is
/// real. In both cases exactly one trailing newline is removed.
///
/// Public because `keylessd credential` reads its value under exactly these
/// rules. A second reader beside this one would drift, and the two verbs would
/// then disagree about what a trailing newline means in a credential.
///
/// # Errors
///
/// [`ManageError::Value`] when the read failed, when more than
/// [`MAX_INPUT_BYTES`] arrived, or when nothing arrived at all.
pub fn read_value(input: &mut dyn Read, interactive: bool) -> Result<Secret, ManageError> {
    let value = |detail: &str| ManageError::Value {
        store: "stdin".to_owned(),
        detail: detail.to_owned(),
    };

    let mut bytes: Vec<u8> = Vec::new();
    // One byte over the cap, so a payload exactly at the cap is accepted and one
    // above it is refused rather than silently truncated.
    let mut capped = input.take((MAX_INPUT_BYTES + 1) as u64);
    // A prompt ends at Enter; a pipe ends at EOF. Reading to EOF in both cases
    // leaves somebody who has already typed the value at a terminal that asks
    // for nothing more, with Ctrl-D the only way out and nothing on screen
    // saying so. `put` above assumes the other thing — its "the user's Enter
    // produced no newline" echo only makes sense once Enter has ended the read.
    let read = if interactive {
        // Stops AT the first newline, so a second line is never read rather
        // than read and then discarded.
        io::BufReader::new(&mut capped).read_until(b'\n', &mut bytes)
    } else {
        capped.read_to_end(&mut bytes)
    };

    if let Err(error) = read {
        bytes.zeroize();
        return Err(value(&format!("cannot read the value: {error}")));
    }
    if bytes.len() > MAX_INPUT_BYTES {
        bytes.zeroize();
        return Err(value(&format!(
            "more than {MAX_INPUT_BYTES} bytes arrived; a credential is not a file"
        )));
    }

    crate::store::exec::strip_one_newline(&mut bytes);
    // A trailing carriage return survives `strip_one_newline` on CRLF input, and
    // a credential with an invisible `\r` on the end fails much later, somewhere
    // else. Removed here rather than left to be debugged.
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }

    if bytes.is_empty() {
        return Err(value(
            "nothing arrived on stdin. Pipe the value in, or run this at a terminal to be \
             prompted for it — there is deliberately no flag that takes a value as an argument",
        ));
    }

    Secret::from_bytes(bytes).ok_or_else(|| value("the value is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::{MAX_INPUT_BYTES, new, put, read_value};
    use crate::config::SecretRoute;
    use crate::secret::Secret;
    use crate::store::manage::{Manage, ManageError, Stored};
    use std::sync::Mutex;

    /// A manager that records what it was handed, so a test can check the value
    /// arrived whole without printing it.
    struct Recorder {
        seen: Mutex<Vec<(String, usize, String)>>,
    }

    impl Recorder {
        fn new() -> Self {
            Recorder {
                seen: Mutex::new(Vec::new()),
            }
        }
        fn last(&self) -> Option<(String, usize, String)> {
            self.seen.lock().expect("not poisoned").last().cloned()
        }
    }

    impl Manage for Recorder {
        fn id(&self) -> &str {
            "recorder"
        }
        fn store(
            &self,
            name: &str,
            _route: &SecretRoute,
            value: &Secret,
        ) -> Result<Stored, ManageError> {
            self.seen.lock().expect("not poisoned").push((
                name.to_owned(),
                value.len(),
                value.expose().to_owned(),
            ));
            Ok(Stored {
                location: "somewhere/decoy".to_owned(),
            })
        }
    }

    struct Refuses;

    impl Manage for Refuses {
        fn id(&self) -> &str {
            "refuses"
        }
        fn store(
            &self,
            _name: &str,
            _route: &SecretRoute,
            _value: &Secret,
        ) -> Result<Stored, ManageError> {
            Err(ManageError::NoIdentity {
                store: "refuses".to_owned(),
                detail: "mint an editor token".to_owned(),
            })
        }
    }

    fn route() -> SecretRoute {
        SecretRoute::default()
    }

    fn run_put(input: &str, interactive: bool) -> (String, String, i32, Option<String>) {
        let recorder = Recorder::new();
        let mut source = input.as_bytes();
        let mut out: Vec<u8> = Vec::new();
        let mut notes: Vec<u8> = Vec::new();
        let written = put(
            &recorder,
            "DECOY",
            &route(),
            &mut source,
            interactive,
            &mut out,
            &mut notes,
        )
        .expect("writing to a Vec");
        (
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&notes).into_owned(),
            written.exit_code,
            recorder.last().map(|(_, _, value)| value),
        )
    }

    #[test]
    fn put_reads_the_value_from_stdin_and_never_echoes_it() {
        let (out, notes, code, stored) = run_put("decoy-piped-in-1234\n", false);
        assert_eq!(code, 0);
        assert_eq!(stored.as_deref(), Some("decoy-piped-in-1234"));
        assert!(
            !out.contains("decoy-piped-in-1234"),
            "put echoed the value on stdout: {out}"
        );
        assert!(
            !notes.contains("decoy-piped-in-1234"),
            "put echoed the value on stderr: {notes}"
        );
        assert!(out.starts_with("stored\tDECOY"), "{out}");
    }

    /// A reader that hands over one line and then behaves like a terminal with
    /// nobody typing at it: the next `read` would block forever. Panicking
    /// stands in for that, because a test cannot wait forever to prove a hang.
    struct OneLineThenSilence {
        line: Option<Vec<u8>>,
    }

    impl std::io::Read for OneLineThenSilence {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.line.take() {
                Some(line) => {
                    let n = line.len().min(buf.len());
                    buf[..n].copy_from_slice(&line[..n]);
                    Ok(n)
                }
                None => panic!(
                    "read_value asked for input again after a whole line arrived; on a \
                     terminal that call blocks until Ctrl-D"
                ),
            }
        }
    }

    #[test]
    fn an_interactive_read_ends_at_the_newline_and_not_at_eof() {
        // A terminal sends no EOF when somebody presses Enter. A read that waits
        // for one hangs with the value already typed, the prompt gone, and
        // nothing on screen naming Ctrl-D as the way out.
        let mut source = OneLineThenSilence {
            line: Some(b"decoy-first-line\n".to_vec()),
        };
        let value = read_value(&mut source, true).expect("a value");
        assert_eq!(value.expose(), "decoy-first-line");
    }

    #[test]
    fn a_piped_read_still_takes_every_line() {
        // The other half of the branch: a pipe carries whatever the writer sent,
        // newlines included, and only the one trailing newline comes off.
        let (_, _, _, stored) = run_put("decoy-line-one\ndecoy-line-two\n", false);
        assert_eq!(stored.as_deref(), Some("decoy-line-one\ndecoy-line-two"));
    }

    #[test]
    fn one_trailing_newline_is_stripped_and_a_second_survives_a_pipe() {
        // Same rule the read adapters follow. `printf '%s\n'` adds one; a value
        // whose own last byte is a newline is not distinguishable from one
        // without, and that ambiguity belongs to the interface, not here.
        let (_, _, _, stored) = run_put("decoy-value\n\n", false);
        assert_eq!(stored.as_deref(), Some("decoy-value\n"));

        let (_, _, _, stored) = run_put("decoy-value", false);
        assert_eq!(stored.as_deref(), Some("decoy-value"));

        // CRLF, which a Windows-authored heredoc or a clipboard paste produces.
        let (_, _, _, stored) = run_put("decoy-value\r\n", false);
        assert_eq!(stored.as_deref(), Some("decoy-value"));
    }

    #[test]
    fn a_multi_line_value_survives_a_pipe_but_a_prompt_takes_one_line() {
        // A PEM key is a real multi-line credential, so a pipe must carry one.
        let (_, _, _, piped) = run_put("line-one\nline-two\n", false);
        assert_eq!(piped.as_deref(), Some("line-one\nline-two"));

        // At a prompt, a second line is a mistake. Storing both would store
        // something the user did not type.
        let (_, _, _, prompted) = run_put("line-one\nline-two\n", true);
        assert_eq!(prompted.as_deref(), Some("line-one"));
    }

    #[test]
    fn empty_input_is_refused_and_says_there_is_no_value_flag() {
        let (out, notes, code, stored) = run_put("", false);
        assert_eq!(code, 65);
        assert!(stored.is_none(), "an empty value reached the store");
        assert!(out.is_empty());
        assert!(notes.contains("no flag that takes a value"), "{notes}");
    }

    #[test]
    fn an_oversized_value_is_refused_rather_than_truncated() {
        let huge = "x".repeat(MAX_INPUT_BYTES + 1);
        let (_, notes, code, stored) = run_put(&huge, false);
        assert_eq!(code, 65);
        assert!(stored.is_none());
        assert!(notes.contains("not a file"), "{notes}");

        // Exactly at the cap is accepted, so the boundary is the cap and not one
        // byte below it.
        let (_, _, code, stored) = run_put(&"y".repeat(MAX_INPUT_BYTES), false);
        assert_eq!(code, 0);
        assert_eq!(stored.map(|value| value.len()), Some(MAX_INPUT_BYTES));
    }

    #[test]
    fn invalid_utf8_is_refused_rather_than_stored_lossily() {
        let mut source: &[u8] = &[0xff, 0xfe, 0xfd];
        assert!(read_value(&mut source, false).is_err());
    }

    #[test]
    fn new_generates_a_value_stores_it_and_prints_nothing_but_the_destination() {
        let recorder = Recorder::new();
        let mut out: Vec<u8> = Vec::new();
        let mut notes: Vec<u8> = Vec::new();
        let written =
            new(&recorder, "DECOY", &route(), 32, &mut out, &mut notes).expect("writing to a Vec");

        assert_eq!(written.exit_code, 0);
        let (name, length, value) = recorder.last().expect("something must have been stored");
        assert_eq!(name, "DECOY");
        assert_eq!(length, 32);

        let printed = String::from_utf8_lossy(&out).into_owned();
        assert!(printed.starts_with("stored\tDECOY"), "{printed}");
        assert!(
            !printed.contains(&value),
            "`new` printed the value it generated: {printed}"
        );
        assert!(
            !String::from_utf8_lossy(&notes).contains(&value),
            "`new` printed the value on stderr"
        );
        // The identity that wrote it is on the line, which is what makes a
        // transcript answer "was that the manager?".
        assert!(printed.contains("recorder"), "{printed}");
    }

    #[test]
    fn new_refuses_an_unsafe_length_and_stores_nothing() {
        let recorder = Recorder::new();
        let mut out: Vec<u8> = Vec::new();
        let mut notes: Vec<u8> = Vec::new();
        let written =
            new(&recorder, "DECOY", &route(), 4, &mut out, &mut notes).expect("writing to a Vec");
        assert_eq!(written.exit_code, 65);
        assert!(recorder.last().is_none(), "a 4-character value was stored");
        assert!(String::from_utf8_lossy(&notes).contains("characters"));
    }

    #[test]
    fn a_refusal_from_the_manager_is_forwarded_with_its_exit_code() {
        let mut out: Vec<u8> = Vec::new();
        let mut notes: Vec<u8> = Vec::new();
        let written =
            new(&Refuses, "DECOY", &route(), 32, &mut out, &mut notes).expect("writing to a Vec");
        // EX_CONFIG: nothing was attempted and a file needs editing.
        assert_eq!(written.exit_code, 78);
        assert!(out.is_empty(), "a refusal printed a success line");
        assert!(
            String::from_utf8_lossy(&notes).contains("editor token"),
            "the fix must reach the operator"
        );
    }
}
