//! The names in an environment, without the values — one format, two ends.
//!
//! # What this is for
//!
//! Infisical has no verb that lists keys. Every verb that names a secret also
//! prints it: `infisical secrets`, `infisical secrets get`, `infisical export`.
//! The one verb that prints nothing is `infisical run`, which puts the secrets
//! into a child process's environment and execs.
//!
//! So the listing is taken from the CHILD. `keyless` spawns `infisical run`
//! with itself as the child, the child reads its own environment, and it writes
//! back the NAMES. The values are in that child's memory for the length of one
//! `execve` and reach no pipe, no file and no terminal.
//!
//! # Why this cannot pass a value off as a name
//!
//! Two structural facts do the work, and neither is a filter that could be
//! nearly right:
//!
//! 1. **The environment is not text.** It is an array of NUL-terminated C
//!    strings, and libc splits each one at its FIRST `=`. A value containing a
//!    newline, a tab, a further `=`, a JSON brace or an ANSI escape is still one
//!    entry with one split point, so no part of it can become a name. This is
//!    what makes the approach different in kind from stripping the values off a
//!    vendor's text output: there, a value containing a newline produces a
//!    following line with no `=` in it and a filter passes that fragment
//!    straight through.
//! 2. **The value is never emitted.** [`names`] destructures each pair and drops
//!    the value immediately; nothing downstream of it holds one. A leak would
//!    have to be a new line of code here, in a file this short.
//!
//! # Why the wire format is NUL-separated
//!
//! Because a name cannot contain a NUL. An environment entry is a
//! NUL-TERMINATED C string, so the byte is the one thing the kernel guarantees
//! is absent from every name it hands back. A newline separator would be a
//! guess about what names look like; this is a consequence of what they are.
//!
//! # Why the payload is framed
//!
//! The child does not own the stream it writes to. `infisical run` forks the
//! child and keeps its own stdout, so a banner, a tip or a progress line from
//! the VENDOR lands on the same pipe — and without a frame, a banner printed
//! before the first name fuses with it and becomes a row. [`OPEN`] and
//! [`CLOSE`] mean the parser reads what the child wrote and discards the rest,
//! rather than trying to recognise noise it has never seen.
//!
//! A missing frame is an ERROR and never an empty listing. "The child never
//! ran" and "the coordinate is empty" are different answers, and only one of
//! them means the tool is broken.
//!
//! The emitter and the parser live in one file so the two ends cannot drift.

use std::ffi::OsString;
use std::io::{self, Write};

/// The byte between two names on the wire.
///
/// See the module docs: it is the one byte a name provably cannot contain.
const SEPARATOR: u8 = 0;

/// Written before the first name. Everything before it is somebody else's.
const OPEN: &[u8] = b"keyless-envnames-1-begin";

/// Written after the last name. Everything after it is somebody else's.
///
/// Present as well as [`OPEN`] because the vendor writes on both sides: it
/// prints before it forks the child, and it is still running afterwards.
const CLOSE: &[u8] = b"keyless-envnames-1-end";

/// Every environment variable NAME of the current process.
///
/// `vars_os` rather than `vars`, and that is not a style choice: `vars` PANICS
/// on a variable whose value is not valid UTF-8, and this crate's release
/// profile sets `panic = "abort"`. A single binary secret in the environment
/// would end the probe with no output, no exit code and no message.
///
/// The value of each pair is dropped at the destructuring and is never bound to
/// a name that outlives the iteration step.
#[must_use]
pub fn names() -> Vec<OsString> {
    std::env::vars_os().map(|(name, _value)| name).collect()
}

/// Write `names` to `out`, one per NUL.
///
/// Takes names rather than pairs. A caller cannot hand this function a value,
/// because the parameter has nowhere to put one.
///
/// # Errors
///
/// Propagates a write failure from `out`.
pub fn emit<I>(names: I, out: &mut dyn Write) -> io::Result<()>
where
    I: IntoIterator<Item = OsString>,
{
    out.write_all(OPEN)?;
    out.write_all(&[SEPARATOR])?;
    for name in names {
        out.write_all(as_bytes(&name))?;
        out.write_all(&[SEPARATOR])?;
    }
    out.write_all(CLOSE)?;
    out.write_all(&[SEPARATOR])?;
    out.flush()
}

/// The names in a payload written by [`emit`], with anything outside the frame
/// discarded.
///
/// Lossy on the UTF-8 boundary rather than fallible: a name this build cannot
/// represent must still be listed, because a name that is invisible here is a
/// config entry somebody writes and cannot understand the failure of.
///
/// An empty run between two separators is dropped, so the separator that
/// terminates every name does not produce a nameless row.
///
/// # Errors
///
/// A sentence naming what is missing, when either marker is absent. That is the
/// only way this build tells "the probe never ran" from "the coordinate holds
/// nothing", and the two call for opposite actions.
///
/// # Why the markers are found in the BYTES, not among the NUL-separated chunks
///
/// The vendor's last write before it forks the child usually ends in a newline
/// and never in a NUL, so its banner and the probe's opening marker land in the
/// SAME chunk: `b"Injecting 172 secrets\nkeyless-envnames-1-begin"`. Looking for
/// a chunk EQUAL to the marker therefore fails on exactly the case the frame
/// exists for, and reports "the probe did not run" about a probe that ran
/// perfectly. Searching the byte stream finds the marker wherever the noise left
/// it.
pub fn parse(payload: &[u8]) -> Result<Vec<String>, &'static str> {
    let opens_at =
        find(payload, OPEN).ok_or("the listing probe wrote no opening frame, so it did not run")?;
    let body_from = opens_at + OPEN.len();

    // Searched from the body only, so an ordering check is not a separate branch
    // — a CLOSE that precedes OPEN is simply not found.
    let closes_at = rfind(&payload[body_from..], CLOSE)
        .map(|at| body_from + at)
        .ok_or("the listing probe wrote no closing frame, so its output was cut short")?;

    Ok(payload[body_from..closes_at]
        .split(|byte| *byte == SEPARATOR)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect())
}

/// The first offset at which `needle` occurs in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The LAST offset at which `needle` occurs in `haystack`.
///
/// Last rather than first, so a name that happens to contain the closing marker
/// cannot end the listing early — the marker the probe wrote is always the one
/// furthest right.
fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

#[cfg(unix)]
fn as_bytes(name: &OsString) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    name.as_os_str().as_bytes()
}

#[cfg(not(unix))]
fn as_bytes(name: &OsString) -> &[u8] {
    // Unreachable while this crate is Unix-only; present so the file states its
    // own portability rather than failing to compile with no explanation.
    name.to_str().map(str::as_bytes).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{CLOSE, emit, names, parse};
    use std::ffi::OsString;

    fn wire_of(input: &[&str]) -> Vec<u8> {
        let mut wire = Vec::new();
        emit(input.iter().map(OsString::from), &mut wire).expect("writing to a Vec");
        wire
    }

    fn round_trip(input: &[&str]) -> Vec<String> {
        parse(&wire_of(input)).expect("the emitter always writes a complete frame")
    }

    #[test]
    fn a_name_survives_the_round_trip_unchanged() {
        assert_eq!(
            round_trip(&["PATH", "DATABASE_URL"]),
            ["PATH", "DATABASE_URL"]
        );
    }

    #[test]
    fn an_empty_environment_is_an_empty_list_and_not_one_blank_row() {
        assert!(round_trip(&[]).is_empty());
        // A separator terminates every name, so the parser must not turn the
        // last one into a nameless entry a listing would print as a blank line.
        assert_eq!(round_trip(&["A", "B"]), ["A", "B"]);
    }

    /// The property the frame exists for.
    ///
    /// The child does not own the stream: `infisical run` writes to the same
    /// pipe before it forks and while it waits. Unframed, a banner printed
    /// before the first name FUSES with that name and becomes a row — so the
    /// first name of every listing would be wrong, which is worse than a
    /// listing that fails.
    #[test]
    fn noise_on_either_side_of_the_frame_is_not_a_name() {
        // The banner ends in a NEWLINE and not a NUL, which is what fuses it to
        // the opening marker. A version of this test that put a separator
        // between them tested nothing: it is the ABSENCE of one that is real.
        let mut wire = b"Injecting 172 Infisical secrets\n".to_vec();
        wire.extend_from_slice(&wire_of(&["A", "B"]));
        wire.extend_from_slice(b"warning: a tip nobody asked for\n");
        assert_eq!(
            parse(&wire).expect("the frame is intact"),
            ["A", "B"],
            "vendor noise outside the frame became a row"
        );
    }

    /// A frameless payload is an ERROR, never an empty listing.
    ///
    /// "The probe never ran" and "this coordinate holds nothing" are opposite
    /// diagnoses, and a build that answered both with zero rows would report a
    /// broken install as a tidy empty vault.
    #[test]
    fn a_missing_frame_is_told_apart_from_an_empty_coordinate() {
        assert!(parse(b"").is_err());
        assert!(parse(b"A\0B\0").is_err());
        // Cut short: the child was killed between the first name and the end.
        let truncated = {
            let full = wire_of(&["A", "B"]);
            full[..full.len() - CLOSE.len() - 1].to_vec()
        };
        assert!(parse(&truncated).is_err());
        // And the empty coordinate really is empty, rather than an error.
        assert!(
            parse(&wire_of(&[]))
                .expect("an empty frame is a complete frame")
                .is_empty()
        );
    }

    /// The property the whole design rests on.
    ///
    /// Every byte class that breaks a line-based filter is put in a VALUE here,
    /// and the assertion is that none of them reaches the wire. The emitter is
    /// handed names only — which is the point: a value has no parameter to
    /// arrive through.
    #[test]
    fn no_byte_of_a_value_can_reach_the_wire() {
        // Each of these is a real value shape that defeats "keep what is left of
        // the first `=`" applied to text: a newline invents a line with no `=`,
        // an `=` invents a second field, a brace and an escape defeat a parser
        // that guesses at structure, and the last one is a value that IS shaped
        // like a key name.
        let hostile = [
            "line-one\nSMUGGLED_BY_NEWLINE=x",
            "tab\there",
            "a=b=c",
            "{\"secretKey\":\"SMUGGLED_BY_JSON\"}",
            "\u{1b}[31mSMUGGLED_BY_ANSI\u{1b}[0m",
            "SMUGGLED_BY_LOOKING_LIKE_A_NAME",
        ];

        let wire = wire_of(&["REAL_NAME_ONE", "REAL_NAME_TWO"]);
        let text = String::from_utf8_lossy(&wire).into_owned();
        for value in hostile {
            assert!(
                !text.contains(value),
                "a value reached the wire: {value:?} in {text:?}"
            );
        }
        for fragment in [
            "SMUGGLED_BY_NEWLINE",
            "SMUGGLED_BY_JSON",
            "SMUGGLED_BY_ANSI",
            "SMUGGLED_BY_LOOKING_LIKE_A_NAME",
            "\u{1b}",
        ] {
            assert!(
                !text.contains(fragment),
                "a fragment of a value reached the wire: {fragment:?} in {text:?}"
            );
        }
        assert_eq!(
            parse(&wire).expect("the frame is intact"),
            ["REAL_NAME_ONE", "REAL_NAME_TWO"]
        );
    }

    /// The negative control for the two tests above.
    ///
    /// Both would also pass if `emit` wrote nothing whatever. This one proves
    /// the pipeline carries a name that is really in the environment — and it
    /// reads the environment rather than writing to it, because `set_var` races
    /// every other thread of a parallel test binary.
    #[test]
    fn the_real_environment_reaches_the_wire() {
        let mut wire = Vec::new();
        emit(names(), &mut wire).expect("writing to a Vec");
        let listed = parse(&wire).expect("the emitter always writes a complete frame");
        assert!(
            listed.iter().any(|name| name == "PATH"),
            "PATH is set for every `cargo test` process; its absence means the \
             pipeline carried nothing: {listed:?}"
        );
    }
}
