use std::path::Path;
use std::path::PathBuf;

use super::backend::Backend;
use super::{ONEPASSWORD_CONCEALED, write_stub};

// ---------------------------------------------------------------------------
// 1Password fixtures
// ---------------------------------------------------------------------------

/// How the `op` stub answers the verbs that need a login.
///
/// The shapes are the vendor's DOCUMENTED ones — see `src/store/onepassword.rs`
/// for what was measured against `op` 2.39.0 and what was not. The two error
/// spellings are measured: `account is not signed in` and the `[ERROR] <date>
/// <time> <message>` log prefix are what the real binary printed.
pub enum OnePasswordListing {
    /// `item list` prints this JSON; `vault get` answers with the vault.
    Json(&'static str),
    /// Every authenticated verb fails as the real CLI does with no sign-in.
    NotSignedIn,
    /// `vault get` and `item list` fail as they do for a vault the login
    /// cannot see. Wording documented, not measured.
    NoSuchVault,
    /// `vault get` ANSWERS and `item list` is refused.
    ///
    /// The split a health check must not read as health. It is what the
    /// vendor's own grant syntax produces — `--vault <name>:read_items` is an
    /// **item** permission, and the vault RECORD is a different object — so a
    /// login can see the vault it cannot list. Wording documented, not
    /// measured.
    ItemsRefused,
}

impl OnePasswordListing {
    /// One live Password item titled `DECOY`, in the pinned vault. The
    /// default for fixtures that are about the lookup rather than the listing.
    pub const ONE_ITEM: OnePasswordListing = OnePasswordListing::Json(
        r#"[{"id":"It3mL1v3","title":"DECOY","category":"PASSWORD",
             "vault":{"id":"V1","name":"company"}}]"#,
    );

    /// What `vault get` does.
    fn vault_body(&self) -> String {
        match self {
            // `ItemsRefused` answers here on purpose: the vault record is
            // readable and the items are not, which is the whole case.
            OnePasswordListing::Json(_) | OnePasswordListing::ItemsRefused => {
                r#"printf '%s' '{"id":"V1","name":"company","items":1}'; exit 0"#.to_owned()
            }
            OnePasswordListing::NotSignedIn => NOT_SIGNED_IN.to_owned(),
            OnePasswordListing::NoSuchVault => NO_SUCH_VAULT.to_owned(),
        }
    }

    /// What `item list` does. The JSON goes through a file rather than a
    /// single-quoted shell string, for the reason `stub_pass_cli_discovery`
    /// gives.
    fn list_body(&self, listing_file: &Path) -> String {
        match self {
            OnePasswordListing::Json(_) => format!("cat '{}'; exit 0", listing_file.display()),
            OnePasswordListing::NotSignedIn => NOT_SIGNED_IN.to_owned(),
            OnePasswordListing::NoSuchVault => NO_SUCH_VAULT.to_owned(),
            OnePasswordListing::ItemsRefused => NO_ITEM_PERMISSION.to_owned(),
        }
    }
}

/// The measured refusal, in the measured log format. The date is a fixture.
const NOT_SIGNED_IN: &str =
    "printf '%s\\n' '[ERROR] 2001/01/01 00:00:00 account is not signed in' >&2; exit 1";

/// A vault the login cannot see. No apostrophe, so it survives single quotes.
const NO_SUCH_VAULT: &str = "printf '%s\\n' '[ERROR] 2001/01/01 00:00:00 no vault named that is \
     visible to this account' >&2; exit 1";

/// A vault the login can SEE and may not LIST. No apostrophe, same reason.
const NO_ITEM_PERMISSION: &str = "printf '%s\\n' '[ERROR] 2001/01/01 00:00:00 you do not have \
     permission to list items in this vault' >&2; exit 1";

/// The shell fragment that runs, or declines to run, the probe under `op run`.
///
/// `$child` and `$key` are set by the stub's preamble. The real CLI replaces
/// the variable that HELD the reference, so the injection is into
/// `KEYLESS_PROBE` rather than into a variable named after the key.
fn op_run_body(behaviour: &Backend) -> String {
    match behaviour {
        Backend::Injects(value) => {
            format!("exec /usr/bin/env \"KEYLESS_PROBE={value}\" \"$child\" \"$key\"\n")
        }
        Backend::InjectsWholeVault => "exec \"$@\"\n".to_owned(),
        Backend::Concealed => format!(
            "exec /usr/bin/env \"KEYLESS_PROBE={ONEPASSWORD_CONCEALED}\" \"$child\" \"$key\"\n"
        ),
        Backend::Empty => "exec /usr/bin/env \"KEYLESS_PROBE=\" \"$child\" \"$key\"\n".to_owned(),
        // The reference passes through unresolved: what `printenv` prints is
        // the `op://` string the adapter set. Measured, this is what the real
        // CLI does with a child when it has nothing to resolve.
        Backend::Unset => "exec \"$child\" \"$key\"\n".to_owned(),
        Backend::OwnFailure => format!("{NOT_SIGNED_IN}\n"),
        Backend::Hangs => "sleep 60\n".to_owned(),
        // Declined out loud rather than answered. `op run` injects into
        // `KEYLESS_PROBE` rather than into a variable named after the key, so
        // the controlled body above is not the body this vendor would need —
        // and no case drives a 1Password vendor across several calls. A second
        // cursor written for nobody would be a fixture whose first user finds
        // it already wrong.
        Backend::Controlled => {
            "echo 'stub: this fixture answers no per-call script' >&2\nexit 1\n".to_owned()
        }
    }
}

/// Write a stand-in for the `op` binary, backed by one live item.
pub fn stub_op(dir: &Path, behaviour: &Backend) -> PathBuf {
    stub_op_listing(dir, behaviour, &OnePasswordListing::ONE_ITEM, "{}")
}

/// Write a stand-in for the `op` binary.
///
/// Records its argv at `<dir>/op.argv` (every invocation, overwritten), the
/// NAMES of the environment it was handed at `<dir>/op.env`, the reference it
/// found in `KEYLESS_PROBE` at `<dir>/op.probe` (the literal `<unset>` when
/// none arrived), and the service-account token at `<dir>/op.token` (again
/// `<unset>` when absent). `item list` records its own argv at
/// `<dir>/op.list.argv` and appends one line per invocation to
/// `<dir>/op.list.count`. `item get` prints `view`.
///
/// So every fact a test asserts is read from the OTHER side of the interface —
/// what the vendor received — rather than from the adapter's own account of
/// what it sent.
pub fn stub_op_listing(
    dir: &Path,
    behaviour: &Backend,
    listing: &OnePasswordListing,
    view: &str,
) -> PathBuf {
    let listing_file = dir.join("op-listing.json");
    let view_file = dir.join("op-view.json");
    if let OnePasswordListing::Json(json) = listing {
        std::fs::write(&listing_file, json).expect("write the listing fixture");
    }
    std::fs::write(&view_file, view).expect("write the view fixture");

    let body = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         /usr/bin/env | sed 's/=.*//' | sort > '{env}'\n\
         printf '%s' \"${{KEYLESS_PROBE-<unset>}}\" > '{probe}'\n\
         printf '%s' \"${{OP_SERVICE_ACCOUNT_TOKEN-<unset>}}\" > '{token}'\n\
         if [ \"$1\" = 'vault' ] && [ \"$2\" = 'get' ]; then {vault}; fi\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'list' ]; then\n\
         \x20 printf '%s\\n' \"$@\" > '{list_argv}'\n\
         \x20 echo one >> '{list_count}'\n\
         \x20 {list}\n\
         fi\n\
         if [ \"$1\" = 'item' ] && [ \"$2\" = 'get' ]; then cat '{view}'; exit 0; fi\n\
         if [ \"$1\" = 'run' ]; then\n\
         \x20 while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         \x20 shift\n\
         \x20 child=\"$1\"\n\
         \x20 key=\"$2\"\n\
         \x20 {run}\
         fi\n\
         echo 'stub: this fixture does not answer that verb' >&2\n\
         exit 1\n",
        argv = dir.join("op.argv").display(),
        env = dir.join("op.env").display(),
        probe = dir.join("op.probe").display(),
        token = dir.join("op.token").display(),
        vault = listing.vault_body(),
        list_argv = dir.join("op.list.argv").display(),
        list_count = dir.join("op.list.count").display(),
        list = listing.list_body(&listing_file),
        view = view_file.display(),
        run = op_run_body(behaviour),
    );
    write_stub(dir, "op-stub", &body)
}

/// How many times the `op` stub's `item list` ran. Zero when it never did.
pub fn op_listing_count(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("op.list.count"))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}
