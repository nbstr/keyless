use std::path::Path;

/// The vendor's cap on that justification.
pub(super) const REASON_MAX: usize = 300;

/// The justification recorded, end-to-end encrypted, against every read.
///
/// # Why this is not the command line
///
/// The obvious reason to record is "what the user ran". It is also the one
/// thing that must not be recorded. An argument vector is where every shape
/// this tool exists to remove ends up — a credential in a URL, in a `--token=`
/// flag, in a header. A reason is assembled *before* any name has
/// resolved, so `keyless` has nothing to redact those with yet, and it is then
/// sent to a vendor and kept. Putting argv in it would take the exact class of
/// leak this tool exists to prevent and forward it to a third party under a
/// field labelled "reason".
///
/// So the reason carries the verb, the program's base name, how many arguments
/// it had, and the name being resolved — enough to answer "which run was this,
/// and what did it want?" while carrying no argument value at all. The base
/// name of a program is not a credential; an argument routinely is.
#[derive(Debug, Clone)]
pub struct Reason {
    prefix: String,
}

impl Reason {
    /// The reason for a `keyless run` of `argv`.
    ///
    /// Only `argv[0]`'s final path component is used, and only the *count* of
    /// the rest.
    #[must_use]
    pub fn for_run(argv: &[std::ffi::OsString]) -> Self {
        let program = argv
            .first()
            .map(Path::new)
            .and_then(Path::file_name)
            .map_or_else(
                || "?".to_owned(),
                |name| name.to_string_lossy().into_owned(),
            );
        let arguments = argv.len().saturating_sub(1);
        Reason {
            prefix: format!("{} run {program} ({arguments} args)", crate::NAME),
        }
    }

    /// The reason for a command that has no child, such as `doctor --probe`.
    #[must_use]
    pub fn for_verb(verb: &str) -> Self {
        Reason {
            prefix: format!("{} {verb}", crate::NAME),
        }
    }

    /// The value of `PROTON_PASS_AGENT_REASON` for one lookup.
    #[must_use]
    pub fn for_name(&self, name: &str) -> String {
        self.for_action("resolving", name)
    }

    /// The same sentence for something other than a read.
    ///
    /// `action` is a verb this crate chooses — `resolving`, `listing`,
    /// `inspecting`, `creating` — and `subject` is a coordinate: a secret's name,
    /// a vault name, an item title. **Neither may ever be an argument value**,
    /// which is the rule the whole type exists for; see the type documentation.
    ///
    /// Truncated on a character boundary so a multi-byte subject cannot produce a
    /// string the vendor rejects, and never empty — an empty reason is refused
    /// by the API, which would turn every read into a failure.
    #[must_use]
    pub fn for_action(&self, action: &str, subject: &str) -> String {
        let mut reason = format!("{}: {action} {subject}", self.prefix);
        if reason.len() > REASON_MAX {
            let mut cut = REASON_MAX;
            while cut > 0 && !reason.is_char_boundary(cut) {
                cut -= 1;
            }
            reason.truncate(cut);
        }
        if reason.trim().is_empty() {
            reason = crate::NAME.to_owned();
        }
        reason
    }
}

impl Default for Reason {
    fn default() -> Self {
        Reason {
            prefix: crate::NAME.to_owned(),
        }
    }
}
