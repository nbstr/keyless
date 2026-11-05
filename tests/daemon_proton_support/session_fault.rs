use std::path::Path;

use super::session_verbs::parse_verbs;

/// A vendor sentence that means nothing to the transport allowlist and
/// matches no phrase measured anywhere in this crate — the shape "the
/// account said something about this read" takes when nobody has a more
/// specific idea what. Used identically across every case below, so what
/// changes between them is only whether the session answers, never the
/// words — which is the property this whole slice exists to prove.
pub const SESSION_FAULT_SENTENCE: &str =
    "some arbitrary Proton failure text this build has never measured before";

/// How many times `pass-cli info` ran, read out of
/// [`stub_with_session_verbs`]'s own verb log — the coalesced probe's own
/// tally, kept separate from [`vendor_call_count`] (the value-reading `run`
/// verb) and [`listing_count`] (`item list`) for the same reason those two
/// are kept apart from each other: each is a different claim about a
/// different verb.
pub fn info_call_count(dir: &Path) -> usize {
    let verbs = std::fs::read_to_string(dir.join("pass-cli.verbs")).unwrap_or_default();
    parse_verbs(&verbs)
        .into_iter()
        .filter(|line| line.verb == "info")
        .count()
}
