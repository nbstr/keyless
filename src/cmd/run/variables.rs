//! Which variables each request sets, and the quoting mistake that leaves them unread.

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use super::Binding;
use crate::NAME;

/// Which variables each request may set, once two requests that would have
/// landed in the same one have been separated.
///
/// # The one case the tool cannot decide, and therefore does not
///
/// A declaration says which variable its credential answers to, so two
/// declarations can name the SAME variable — which is the ordinary shape of one
/// credential per environment, all read by the same program under one name. Ask
/// for both in one run and something has to give, and "the last one wins" is
/// decided by the order the flags happen to be in. That is the failure this
/// whole area exists to remove, aimed at a target where it would be far worse:
/// the value that arrives is a real, working credential from the wrong side of a
/// boundary, and nothing anywhere reports it.
///
/// So a variable two requests both derive is set from NEITHER. Each value is
/// still injected under its own declared name, which is unique by construction —
/// nothing is lost, and the run is not blocked. This is the one place a message
/// is written, because it is the one case where the right answer is genuinely
/// not knowable from what was asked.
///
/// Programs whose argument is itself a program, so a `$VAR` inside it is
/// expanded by the CHILD and is correct.
///
/// `sh -c 'psql "$DATABASE_URL"'` is the sanctioned form and must never be
/// warned about, which is the whole reason this list exists. Anything not on it
/// receives its arguments already expanded, by the shell that typed them.
const EXPANDS_ITS_OWN_ARGUMENTS: [&str; 12] = [
    "sh", "bash", "zsh", "dash", "ksh", "fish", "env", "eval", "ssh", "docker", "make", "just",
];

/// The quoting mistake, caught at the moment it is made rather than taught in
/// advance.
///
/// # The wall this removes
///
/// A variable this tool injects exists in the CHILD's environment. Two spellings
/// look right and send nothing:
///
/// ```text
/// keyless run -s TOKEN -- curl -H "Authorization: Bearer $TOKEN" …
///     expanded by the CALLING shell, where TOKEN is unset — an EMPTY header
/// keyless run -s TOKEN -- curl -H 'Authorization: Bearer $TOKEN' …
///     never expanded by anybody — the literal five characters reach curl
/// ```
///
/// The second is visible from inside this process: the argument arrives holding
/// `$TOKEN` verbatim, and `curl` does not expand anything. So it is reported,
/// with the corrected line, instead of living in a document somebody has to have
/// read first.
///
/// **The first is NOT visible and that is stated rather than papered over.** By
/// the time this process starts, the calling shell has already replaced it with
/// the empty string, and an empty argument is a legitimate thing to pass. There
/// is no measurement that distinguishes them, so nothing here guesses.
///
/// It is a warning and never a refusal: the never-block invariant has no
/// exceptions, and a literal `$TOKEN` is occasionally what somebody means.
pub(super) fn quoting_warnings(
    program: &OsString,
    args: &[OsString],
    plans: &[Vec<String>],
) -> Vec<String> {
    let head = Path::new(program)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if EXPANDS_ITS_OWN_ARGUMENTS.contains(&head.as_str()) {
        return Vec::new();
    }

    let mut warnings = Vec::new();
    for variable in plans.iter().flatten() {
        let needle = format!("${variable}");
        let braced = format!("${{{variable}}}");
        if args.iter().any(|argument| {
            let text = argument.to_string_lossy();
            text.contains(&needle) || text.contains(&braced)
        }) {
            warnings.push(format!(
                "`{needle}` reached `{head}` unexpanded — it is a literal, not the \
                 credential. `{head}` does not expand variables; only a shell does, \
                 and the variable is set in the CHILD. Wrap the command: \
                 `-- sh -c '{head} … {needle} …'`, with the body in SINGLE quotes"
            ));
        }
    }
    warnings
}

/// A variable the caller SPELLED is never displaced either. `-s VAR=NAME` is an
/// instruction, and a derived variable is an inference; an inference that
/// overwrote an instruction would make the typed form unreliable, and the typed
/// form is the escape hatch everything else here depends on.
pub(super) fn deconflict(bindings: &[Binding], notes: &mut dyn Write) -> Vec<Vec<String>> {
    use std::collections::{BTreeMap, BTreeSet};

    let spelled: BTreeSet<&str> = bindings
        .iter()
        .map(|binding| binding.env.as_str())
        .collect();

    // Names rather than a count: two `-s NAME` for the same name are one
    // credential asked for twice, which collides with nothing.
    let mut claimants: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for binding in bindings {
        for variable in &binding.also {
            claimants
                .entry(variable.as_str())
                .or_default()
                .insert(binding.name.as_str());
        }
    }

    for (variable, names) in &claimants {
        if spelled.contains(variable) {
            let _ = writeln!(
                notes,
                "{NAME}: `{variable}` was named on the command line, so it keeps that value; \
                 {} also answers to it and is in its own variable instead",
                names.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        } else if names.len() > 1 {
            let _ = writeln!(
                notes,
                "{NAME}: {} all answer to `{variable}`, so nothing sets it — which one you \
                 meant is not in the command. Each value is in its own variable; spell the \
                 one you want with `-s {variable}=<name>`",
                names.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }

    bindings
        .iter()
        .map(|binding| {
            let mut targets = binding.targets();
            targets.retain(|variable| {
                variable == &binding.env
                    || claimants.get(variable.as_str()).is_some_and(|names| {
                        names.len() == 1 && !spelled.contains(variable.as_str())
                    })
            });
            targets
        })
        .collect()
}
