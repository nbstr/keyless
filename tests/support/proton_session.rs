use std::path::Path;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// The vendor's store semantics, as a stand-in.
//
// Every fixture above answers a VERB. This one models what `pass-cli` does to
// the session directory around the verb — which key it resolves, what it
// deletes, and which of those deletions happen on a plain read. Those are the
// facts this crate's session design is correct BECAUSE of, and until this
// fixture existed the suite held none of them: a vendor release that changed
// one broke the daemon in production with every test still green.
//
// # Where each behaviour was read from
//
// `pass-cli` 2.3.3. Three sources were available and they agree here:
//
// - the public repository `protonpass/pass-cli` at tag `2.3.3`, which resolves
//   to commit `51a4c9b`. Every line number below is that commit's.
// - the installed binary, `/usr/local/libexec/pass-cli --version` reporting
//   `2.3.3 (0d7235d)`. That second hash is a build id and resolves to no
//   commit in the public repository, so the TAG is what ties the two together.
// - a local clone, whose `HEAD` was confirmed to be the commit `2.3.3` points
//   at rather than trusted to be current.
//
// A behaviour that could not be read is modelled anyway and SAYS SO at the
// line that models it, so a reader never has to assume a citation was checked.
// The one place that bites: the SDK crate the CLI depends on is not in that
// repository, so anything happening inside a `client.*` call is inferred from
// the CLI's own handling of what comes back.
//
// # A disagreement between this fixture and the real binary is a finding
//
// The other Proton fixtures carry the opposite rule — a disagreement there is a
// bug in the fixture. Here it is the point: this file is the written-down half
// of the vendor's contract, so a case going red against a new `pass-cli` means
// the contract moved, and the diff that makes it green again is the record of
// what moved.
// ---------------------------------------------------------------------------

/// How long each of the vendor's own spans lasts, in the stand-in.
///
/// Every field is a real span in `pass-cli` with a real duration — a server
/// round trip, an `unlink` sweep, an encrypt-and-rename — and every one of them
/// is a window another process can act inside. Production hits them at whatever
/// width the machine gives them; a case that needs a particular interleaving
/// sets them so the ordering is arithmetic rather than luck.
///
/// All zero by default, which is a vendor with no windows at all: the fixture
/// that does not care about concurrency pays nothing for these.
pub struct VendorStore {
    /// `login` holds the directory open this long before writing
    /// `session.json` — the server round trip.
    pub login_delay: std::time::Duration,

    /// `logout` waits this long between revoking the session AT THE ACCOUNT and
    /// deleting anything locally.
    ///
    /// Those are two separate acts in `commands/logout.rs:46-67`: `client
    /// .logout()` first, then `remove_key()`, then `remove_local_data()`. From
    /// the instant the first returns, every other child holding that session is
    /// answered "logged out" by the server — so this is the window in which a
    /// concurrent reader turns into a deleter.
    pub logout_delay: std::time::Duration,

    /// How long `remove_dir_all` takes between listing the directory and the
    /// final `rmdir`.
    ///
    /// `tokio::fs::remove_dir_all` (`commands/logout.rs:34`) lists once and
    /// unlinks by name, so an entry created after the listing survives and the
    /// final `rmdir` fails with `ENOTEMPTY`. That failure is the fingerprint
    /// this crate's own incident began with, and it is only reachable because
    /// the two steps are not one atomic act.
    pub rmdir_window: std::time::Duration,

    /// How long the invalidation-time `session.json` write waits before it
    /// resolves the key.
    ///
    /// A read whose session the account revoked does two things and they are
    /// not ordered with respect to each other: the SDK's callback deletes the
    /// store, and the store schedules its own `session.json` write on a
    /// background task. This is when that task starts.
    pub persist_key_delay: std::time::Duration,

    /// How long that write takes between resolving the key and the rename
    /// landing — the encrypt.
    ///
    /// This is the span that makes a mismatch possible at all: the key is read
    /// at one instant and the file it encrypts is renamed into place at a
    /// later one, and a deleter working in between leaves a `session.json` on
    /// disk under a key no surviving `local.key` holds. That state is terminal
    /// — the next child mints a fresh key and cannot decrypt it.
    pub persist_write_delay: std::time::Duration,
}

impl VendorStore {
    /// A vendor with no windows: every span above is instant.
    pub const INSTANT: VendorStore = VendorStore {
        login_delay: std::time::Duration::ZERO,
        logout_delay: std::time::Duration::ZERO,
        rmdir_window: std::time::Duration::ZERO,
        persist_key_delay: std::time::Duration::ZERO,
        persist_write_delay: std::time::Duration::ZERO,
    };
}

/// The state a fixture puts the vendor's own session record into.
///
/// Two of `pass-cli`'s three paths to `remove_dir_all` are decided from the
/// PERSISTED session before the command runs, so a case that wants one of them
/// sets the session's own fields rather than arranging a server answer — which
/// is also what the vendor reads: `main.rs:337` and `main.rs:354` both ask the
/// session it just loaded.
pub enum VendorSession {
    /// `!session.is_authenticated()` — `main.rs:337-341`.
    NotAuthenticated,
    /// `store.needs_extra_password()` — `main.rs:354-358`.
    NeedsExtraPassword,
}

/// Put the session the stand-in wrote into a state its dispatch refuses.
///
/// `generation` is the directory `PROTON_PASS_SESSION_DIR` names — the
/// vendor's own `.session` subdirectory is appended here, the way
/// `utils.rs:53-85` appends it.
pub fn degrade_vendor_session(generation: &Path, state: &VendorSession) {
    let session = generation.join(".session").join("session.json");
    let text = std::fs::read_to_string(&session)
        .unwrap_or_else(|error| panic!("no session at {}: {error}", session.display()));
    let (field, was) = match state {
        VendorSession::NotAuthenticated => ("auth", "auth=yes"),
        VendorSession::NeedsExtraPassword => ("extra", "extra=no"),
    };
    assert!(
        text.contains(was),
        "the session at {} does not carry `{was}`, so this fixture would be degrading nothing: \
         {text:?}",
        session.display()
    );
    let degraded = match state {
        VendorSession::NotAuthenticated => text.replace("auth=yes", "auth=no"),
        VendorSession::NeedsExtraPassword => text.replace("extra=no", "extra=yes"),
    };
    std::fs::write(&session, degraded)
        .unwrap_or_else(|error| panic!("cannot rewrite {} ({field}): {error}", session.display()));
}

/// Revoke, at the account, the session the stand-in wrote into `generation`.
///
/// `client.logout()` is one act and the local deletion is another
/// (`commands/logout.rs:46-67`), and the window between them is where a
/// concurrent reader turns into a deleter. A case that wants a reader in that
/// state can wait out the window, or it can say so directly — which is what
/// this does, so the case is arithmetic rather than a race it has to win.
///
/// `dir` is the stand-in's own directory, `generation` the one
/// `PROTON_PASS_SESSION_DIR` names.
pub fn revoke_vendor_session(dir: &Path, generation: &Path) {
    let session = generation.join(".session").join("session.json");
    let text = std::fs::read_to_string(&session)
        .unwrap_or_else(|error| panic!("no session at {}: {error}", session.display()));
    let id = text
        .lines()
        .find_map(|line| line.strip_prefix("session="))
        .unwrap_or_else(|| panic!("no session id in {}: {text:?}", session.display()));
    let account = dir.join("pass-cli.store.revoked");
    let mut held = std::fs::read_to_string(&account).unwrap_or_default();
    held.push_str(id);
    held.push('\n');
    std::fs::write(&account, held).expect("record the revocation at the account");
}

/// Every call the store stand-in has answered, one line each, oldest first.
///
/// The line is `<verb> <session directory> <outcome>`, where the outcome is one
/// of the stand-in's own words for which branch of the vendor it took —
/// `minted-key`, `revoked-cleanup`, `not-authenticated`, `undecryptable` and
/// the rest. That is what lets a case assert WHICH vendor path ran, rather
/// than inferring it from an exit status three paths share.
///
/// It carries no key, no token and no value: the two credentials in play here
/// are the agent token and the local key, and neither the id the stand-in mints
/// nor the fingerprint it derives is ever written to this file.
pub fn vendor_store_trace(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(vendor_store_trace_path(dir))
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

pub(super) fn vendor_store_trace_path(dir: &Path) -> PathBuf {
    dir.join("pass-cli.store.trace")
}
