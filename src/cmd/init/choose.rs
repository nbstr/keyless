//! Deciding which backend becomes `stores.default`.

use std::io::{self, BufRead, Write};

use super::{EXIT_NEEDS_AN_ANSWER, Finding, InitRequest, KNOWN};
use crate::cmd::status::{heading, note};

/// What `choose` concluded.
pub(super) enum Choice {
    /// Write this backend as the default.
    Backend(&'static str),
    /// Stop, with this exit code. Everything worth saying has been said.
    Stop(i32),
}

/// Decide which backend becomes `stores.default`, asking at most once.
///
/// The order is deliberate: an explicit `--store` wins outright, then a single
/// usable backend needs no question at all, then — and only then — a terminal is
/// asked. Every branch that would need an answer and cannot get one exits with
/// [`EXIT_NEEDS_AN_ANSWER`] and names the flag that supplies it.
pub(super) fn choose(
    request: &InitRequest<'_>,
    usable: &[&Finding],
    stdin: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<Choice> {
    let style = request.style;

    if let Some(id) = request.only {
        let Some(known) = KNOWN.iter().find(|known| **known == id) else {
            writeln!(
                err,
                "{}: `--store {id}` names no backend. This build has: {}",
                crate::NAME,
                KNOWN.join(", ")
            )?;
            return Ok(Choice::Stop(EXIT_NEEDS_AN_ANSWER));
        };
        // Written even when it did not prove, on purpose: `--store proton` from
        // somebody who is about to log in is a legitimate thing to ask for, and
        // refusing it would send them to a text editor to write the same six
        // lines by hand.
        return Ok(Choice::Backend(known));
    }

    match usable {
        [] => {
            heading(out, style, "NOTHING TO WRITE")?;
            note(
                out,
                style,
                "No backend proved a read path, so any config written now would \
                 describe a store that cannot answer.",
            )?;
            note(
                out,
                style,
                "Every row above says what it is waiting for. Take one of those \
                 steps and run this again,",
            )?;
            note(
                out,
                style,
                &format!(
                    "or write the config anyway with `{} setup --store <backend>`.",
                    crate::NAME
                ),
            )?;
            Ok(Choice::Stop(1))
        }
        [only] => Ok(Choice::Backend(only.store)),
        several => {
            let ids: Vec<&str> = several.iter().map(|f| f.store).collect();
            if request.assume_yes {
                // The detection order is the preference order, and `KNOWN` is
                // that order: the backend needing least of the user comes first.
                return Ok(Choice::Backend(several[0].store));
            }
            if !request.interactive {
                // Never a hang, never a guess. The one place this verb could
                // block is closed by a check, not by a timeout — a timeout
                // cannot tell "nobody is there" from "somebody is reading".
                writeln!(
                    err,
                    "{}: {} backends are usable ({}) and there is no terminal to ask on. \
                     Pass `--store <backend>` to pick one, or `--yes` to take `{}`.",
                    crate::NAME,
                    ids.len(),
                    ids.join(", "),
                    several[0].store
                )?;
                return Ok(Choice::Stop(EXIT_NEEDS_AN_ANSWER));
            }
            heading(out, style, "ONE QUESTION")?;
            note(
                out,
                style,
                "Which store should a name resolve against when it pins none?",
            )?;
            write!(out, "\n  [{}] > ", ids.join(" / "))?;
            out.flush()?;
            let mut answer = String::new();
            // A closed stdin returns 0 bytes rather than blocking, so the
            // `is_empty` branch below is the EOF case and not a silent default.
            if stdin.read_line(&mut answer)? == 0 {
                writeln!(
                    err,
                    "\n{}: stdin ended without an answer. Pass `--store <backend>` or `--yes`.",
                    crate::NAME
                )?;
                return Ok(Choice::Stop(EXIT_NEEDS_AN_ANSWER));
            }
            let answer = answer.trim();
            match several.iter().find(|f| f.store == answer) {
                Some(found) => Ok(Choice::Backend(found.store)),
                None if answer.is_empty() => Ok(Choice::Backend(several[0].store)),
                None => {
                    writeln!(
                        err,
                        "{}: `{answer}` is not one of {}. Nothing was written.",
                        crate::NAME,
                        ids.join(", ")
                    )?;
                    Ok(Choice::Stop(EXIT_NEEDS_AN_ANSWER))
                }
            }
        }
    }
}
