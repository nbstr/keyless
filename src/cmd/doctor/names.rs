//! The NAMES section: one row per declared name — asked only under `--probe`,
//! and never asked through a store already known to be down.
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

use std::collections::BTreeMap;
use std::io::{self, Write};

use crate::cmd::run::Binding;
use crate::cmd::status::{Mark, Style, action, heading, note, row, verbatim};
use crate::config::Config;
use crate::store::{self, Registry, Resolution};

use super::stores::StoreRow;

/// The NAMES section. Returns how many rows are problems.
pub(super) fn report_names(
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
