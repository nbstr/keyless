//! The NEXT section printed after a config is written.

use std::io::{self, Write};

use super::Finding;
use crate::cmd::status::{Mark, Style, command, heading, note};

/// The path from a written config to a name that resolves.
///
/// Named commands rather than prose. The `secrets` half is handed to `items` and
/// `fields` because those are the verbs that discover coordinates without ever
/// reading a value — which is the same reason they exist at all.
pub(super) fn next_steps(
    chosen: &str,
    findings: &[Finding],
    style: Style,
    out: &mut dyn Write,
) -> io::Result<()> {
    let name = crate::NAME;
    heading(out, style, "NEXT")?;
    if chosen == "keychain" {
        command(
            out,
            style,
            &format!("{name} new FIRST_SECRET"),
            "generates a credential and stores it, showing it to nobody",
        )?;
    } else if chosen == "infisical" {
        // Two differences from a vault backend, and both would waste somebody's
        // first five minutes: an Infisical coordinate is never defaulted, so a
        // bare `items` against a config with no declared name has nothing to
        // list; and a secret there is one value, so `fields` has no answer.
        command(
            out,
            style,
            &format!("{name} items infisical --env <SLUG>"),
            "lists the keys at one environment: names and coordinates, never a value",
        )?;
    } else {
        // Proton and 1Password are both vault backends: items have titles and
        // several fields, and both verbs answer.
        command(
            out,
            style,
            &format!("{name} items"),
            "lists what the store holds: titles and states, never a value",
        )?;
        command(
            out,
            style,
            &format!("{name} fields --item <TITLE>"),
            "lists that item's field names: never a value, never a length",
        )?;
    }
    command(
        out,
        style,
        &format!("{name} run -s NAME -- <cmd>"),
        "the only way a value ever leaves a store",
    )?;
    command(
        out,
        style,
        &format!("{name} doctor"),
        "what is proven right now, and what is not",
    )?;

    // The half no config can supply, said once, at the moment it becomes the
    // reader's next obstacle rather than buried in a README they have closed.
    let waiting: Vec<&str> = findings
        .iter()
        .filter(|f| !f.is_usable() && f.mark != Mark::Off)
        .map(|f| f.store)
        .collect();
    if !waiting.is_empty() {
        let subject = match waiting.as_slice() {
            [one] => format!("`{one}` is"),
            several => format!("`{}` are", several.join("` and `")),
        };
        note(
            out,
            style,
            &format!(
                "{subject} still waiting on a login only you can perform. \
                 Run `{name} setup` again afterwards."
            ),
        )?;
    }
    Ok(())
}
