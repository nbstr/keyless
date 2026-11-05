//! The config body `init` writes.

use super::KNOWN;

/// The smallest config that makes `chosen` the store an unpinned name uses.
///
/// `secrets` is written empty rather than omitted, because the empty object is
/// the thing a reader edits next and an absent key is a thing they have to know
/// to add. There is no field here a value fits in; see [`crate::config`].
pub(super) fn render(chosen: &str) -> String {
    let others: Vec<String> = KNOWN
        .iter()
        .filter(|id| **id != chosen)
        .map(|id| format!("    \"{id}\": {{ \"enabled\": false }},\n"))
        .collect();
    format!(
        "{{\n  \"stores\": {{\n{}    \"{chosen}\": {{ \"enabled\": true }},\n    \"default\": \"{chosen}\"\n  }},\n  \"secrets\": {{}}\n}}\n",
        others.concat()
    )
}

/// Splice previously-declared names into a freshly rendered config body.
///
/// `render` always produces `"secrets": {}` because it has no way to know
/// what a fresh install should declare. A `--force` re-run is different: a
/// config already exists, and whatever names it declared are real facts about
/// the account this machine reaches, not template output — replacing the
/// store choice must not erase them. `preserved` empty (the fresh-install
/// case, or a replaced file that declared nothing) leaves `body` untouched.
///
/// A raw substring swap rather than a parse-mutate-reserialize round trip:
/// the latter reorders and reformats the whole `stores` object too, which is
/// exactly the kind of incidental reshuffle `render`'s own tests, and every
/// caller that greps the written file, do not expect from a flag that only
/// changes which backend is default.
pub(super) fn with_preserved_secrets(
    body: &str,
    preserved: &std::collections::BTreeMap<String, crate::config::SecretRoute>,
) -> String {
    if preserved.is_empty() {
        return body.to_owned();
    }
    let secrets_json =
        serde_json::to_string(preserved).expect("a loaded config's secrets always serialize");
    let spliced = body.replacen(
        "\"secrets\": {}",
        &format!("\"secrets\": {secrets_json}"),
        1,
    );
    debug_assert_ne!(
        spliced, body,
        "render()'s own \"secrets\": {{}} literal moved"
    );
    spliced
}
