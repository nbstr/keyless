use std::collections::BTreeMap;
use std::path::Path;

use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;

use super::STORE_ID;
use super::environment::{ENCRYPTION_KEY_VAR, SESSION_DIR_VAR};
use super::session_dir::{SESSION_DIR_PLACEHOLDER, scoped_command, shell_word};

/// The environment variable an agent token travels in, at login.
///
/// Read out of `pass-cli agent instructions` on 2026-08-11 — the vendor's own
/// text, printed by the vendor's own binary, which is the only reason this crate
/// states it. The alternative spelling `pass-cli login --pat <TOKEN>` exists and
/// is **not** what this crate ever recommends: an argument is readable from the
/// process table for as long as the process lives, which is the exact leak
/// `keyless` exists to remove, and this crate does not get to make an exception
/// for its own setup instructions.
pub const TOKEN_VAR: &str = "PROTON_PASS_PERSONAL_ACCESS_TOKEN";

/// How a minted agent token becomes the identity in ONE session directory.
///
/// # The step that was missing entirely, not merely under-specified
///
/// `agent create` prints a token and writes nothing to any session directory.
/// Until that token is logged in somewhere, the directory named in the config is
/// empty — so an operator who follows a recipe ending at `agent access grant`
/// has a token, a config pointing at nothing, and a store that fails
/// authentication. That was true of this crate's own manager-token recipe and of
/// its README.
///
/// The token is a value, so it goes in the child's environment and never in an
/// argument. It does land in shell history, which is the vendor's design and not
/// something `keyless` can route around: say so rather than pretend the line is
/// free.
/// `None` when the directory is the one the operator is being told to invent —
/// [`SESSION_DIR_PLACEHOLDER`] stands in for it, because a path that does not
/// exist yet cannot be quoted as a shell word and a tilde that got quoted would
/// stop expanding.
#[must_use]
pub fn login_with_token(session_dir: Option<&Path>) -> String {
    let dir = session_dir.map_or_else(|| SESSION_DIR_PLACEHOLDER.to_owned(), shell_word);
    format!("{SESSION_DIR_VAR}={dir} {TOKEN_VAR}=<the token `agent create` printed> pass-cli login")
}

/// The login command for ONE session directory, ready to paste.
#[must_use]
pub fn login_into(session_dir: &Path) -> String {
    scoped_command(session_dir, "login")
}

/// Whether the vendor's refusal is about the personal access token itself.
///
/// # Why this reads the vendor's words rather than asking it something
///
/// There is no verb that answers "is my token still good?" separately from
/// using it, and the vendor's own message is one sentence for three causes —
/// `This personal access token is invalid, expired or has been deleted`, read
/// out of the 2.3.2 binary. So the most this can establish is WHICH SIDE the
/// fault is on: the token, or the session directory. That is the distinction
/// that decides where somebody goes to fix it, and it is the one the generic
/// message loses.
///
/// Matched on the vendor's own noun rather than on a whole sentence, so a
/// reworded release still lands in the right branch. Failing to match costs the
/// generic message, which is the message that was already there — a miss is a
/// worse sentence, never a wrong verdict.
pub(super) fn refused_the_token(vendor_said: &str) -> bool {
    let lowered = vendor_said.to_ascii_lowercase();
    lowered.contains("personal access token") || lowered.contains("agent token")
}

/// The separator between the two halves of a personal access token.
///
/// The token is `pst_<token>::<key>` — the encryption key rides INSIDE the
/// token, which is why one string is the whole login and why there is no
/// second file beside it.
const TOKEN_SEPARATOR: &str = "::";

/// The prefix every personal access token carries.
const TOKEN_PREFIX: &str = "pst_";

/// Whether a value is shaped like a personal access token, without saying what
/// it is.
///
/// # Why a shape check exists at all
///
/// The daemon's credential file has four states worth telling apart, and three
/// of them are about the FILE — absent, shut to the wrong people, unparseable.
/// A file that is present, `0600`, the daemon's, and holds one entry passes
/// every one of those and still cannot log anything in, if what somebody put in
/// it was the token's NAME, or an agent id, or the whole line the vendor
/// printed. Every one of those is a plausible paste.
///
/// Left unchecked, that arrives as the vendor's own refusal, which is one
/// sentence for three causes — `This personal access token is invalid, expired
/// or has been deleted`, read out of the 2.3.2 binary — so the reader is sent
/// to the vendor's dashboard to look for a token that was never wrong.
///
/// # What it may say
///
/// Structure, never content. The two refusals below are the vendor's own,
/// quoted because they are the reason these are the rules: `Invalid personal
/// access token token format. Expected format: pst_<token>::<key>` and `Failed
/// to decode personal access token key. Must be base64-urlsafe encoded`.
///
/// A pass is not a claim that the vendor will accept it — only that what is in
/// the file is the kind of thing a login is made of. Whether the account
/// accepts it is the `store proton` row's question.
///
/// # Errors
///
/// A sentence naming the structural fault. No part of the value appears in it.
pub fn classify_token(value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err("the entry is empty".to_owned());
    }
    if value.trim() != value {
        // A paste that picked up a newline authenticates as a different string
        // and fails as though it were the wrong token.
        return Err(
            "the entry has whitespace around it, which the vendor reads as part of \
                    the token"
                .to_owned(),
        );
    }
    if !value.starts_with(TOKEN_PREFIX) {
        return Err(format!(
            "the entry does not begin with `{TOKEN_PREFIX}`, so it is not a personal access \
             token. The vendor's format is `{TOKEN_PREFIX}<token>{TOKEN_SEPARATOR}<key>` — \
             this looks like a token's NAME, an agent id, or a line copied around one"
        ));
    }
    let Some((token, key)) = value.split_once(TOKEN_SEPARATOR) else {
        return Err(format!(
            "the entry carries no `{TOKEN_SEPARATOR}`, so it is only the first half of a \
             token. The encryption key travels after it, and without that half nothing can \
             be decrypted"
        ));
    };
    if token.len() <= TOKEN_PREFIX.len() {
        return Err(format!(
            "the entry is `{TOKEN_PREFIX}{TOKEN_SEPARATOR}…` with nothing between them"
        ));
    }
    if key.is_empty() {
        return Err(format!(
            "the entry ends at `{TOKEN_SEPARATOR}` with no encryption key after it"
        ));
    }
    if !key.bytes().all(is_base64url) {
        return Err(
            "the half after the separator is not base64-urlsafe, so the vendor cannot decode \
             the encryption key"
                .to_owned(),
        );
    }
    Ok(())
}

/// Whether a byte may appear in a base64url encoding, padding included.
const fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'=')
}

/// The daemon's own Proton login, read out of a file only the daemon can open.
///
/// # Why the daemon needs one at all, when a session does not
///
/// A session spawns `pass-cli` and inherits whatever login the caller already
/// established — a session store the caller owns, encrypted with a key in the
/// caller's keyring. A daemon inherits neither half. It is given a session
/// directory of its own, and it must be able to put that session back when the
/// vendor drops it. Two different things drop it, and they do not heal alike.
///
/// - The directory is **emptied** — a probe run under a stripped environment
///   reinitialises it, which is the measured behaviour recorded in
///   [`remove_ambient_references`]. The token lives outside the session
///   database, so with it in the environment the next command re-establishes
///   the session and nothing has to notice.
/// - The session **expires**. Proton caps a personal-access-token session at
///   two hours and publishes no renewal verb, so logging in again IS the
///   renewal. Expiry leaves the store populated and INVALID, and `pass-cli`
///   answers a login over it with `Client is already authenticated` — so the
///   case above does not reach this one, and nothing re-establishes it on its
///   own. [`crate::daemon::session`] is the loop that does, switched on with
///   `stores.proton.session.auto_login`.
///
/// Without the token in the environment neither heals: every Proton name stops
/// resolving until somebody notices and logs it back in by hand.
///
/// Under [`KeyProvider::Env`] it carries the local encryption key too, which is
/// the other half of the session and is a secret in exactly the same sense.
///
/// # Where it comes from, and everywhere it must not be
///
/// **Not the launchd plist**, whose `EnvironmentVariables` are readable by
/// every user on the machine. **Not `keylessd.json`**, which names coordinates
/// and has no field a value fits in. **Not the file the `file` store serves**,
/// because everything in that file is a name an attested client can ask for
/// over the socket — a vault-unlocking token kept there is handed to any
/// session that guesses its label, which is the hole this project exists to
/// close, reopened by its own installer.
///
/// So it comes from a [`Store`] the daemon reads under its own uid: a
/// mode-`0600` file [`crate::store::file::FileStore`] refuses to read if
/// anybody else could. The config names the variable and the entry; the value
/// never appears in anything an operator opens.
///
/// # One token, and it is a viewer
///
/// [`crate::config::ProtonConfig`] carries a second, editor-role identity for
/// the write verbs. The daemon deliberately has no counterpart: with
/// `daemon.enabled`, [`crate::store::manage`] refuses every write for every
/// store, so an editor token here would be a strictly larger prize with no
/// ability whatsoever to be used.
///
/// The vendor enforces the rest in its crypto layer rather than by policy —
/// `Personal access tokens and agent sessions cannot perform user key
/// operations`, read out of the 2.3.2 binary — so a viewer-role token scoped to
/// one vault is narrower than anything a login could be talked into.
///
/// # Read per lookup, not held
///
/// Resolved when a lookup is about to spawn the vendor, and dropped with the
/// [`Secret`]s that carry it. A rotated token therefore takes effect without
/// restarting the daemon, and nothing keeps a plaintext copy between calls. The
/// same residency as the forwarded variables beside it: one copy lives as long
/// as the [`Command`] holding it.
pub struct AgentToken {
    source: Box<dyn Store>,
    names: BTreeMap<String, String>,
}

impl AgentToken {
    /// Read the values for `names` — vendor variable to entry name — out of
    /// `source`.
    #[must_use]
    pub fn new(source: Box<dyn Store>, names: BTreeMap<String, String>) -> Self {
        AgentToken { source, names }
    }

    /// The named variables this adapter will not set, in the order it reads them.
    ///
    /// An **allowlist of exactly two**, and deliberately narrower than the
    /// `INFISICAL_*` prefix rule the sibling adapter uses. A prefix rule works
    /// there because every `INFISICAL_*` variable is a credential. It does not
    /// work here: the two variables that decide whether this adapter is safe
    /// are both `PROTON_PASS_*`. [`SESSION_DIR_VAR`] chooses which identity
    /// answers — the difference between reading one vault and reading a whole
    /// account — and [`KEY_PROVIDER_VAR`] chooses whether the session store
    /// survives being read. A credential entry able to set either would
    /// silently overrule the two settings this store's own config exists to
    /// state.
    ///
    /// An associated function on the map rather than a method, so a config can
    /// be checked before a store is built from it.
    #[must_use]
    pub fn refused(names: &BTreeMap<String, String>) -> Vec<String> {
        names
            .keys()
            .filter(|variable| {
                variable.as_str() != TOKEN_VAR && variable.as_str() != ENCRYPTION_KEY_VAR
            })
            .cloned()
            .collect()
    }

    /// Every named value, or the sentence saying which one could not be read.
    pub(super) fn resolve(&self) -> Result<Vec<(String, Secret)>, StoreError> {
        if let Some(variable) = Self::refused(&self.names).first() {
            return Err(StoreError::Misconfigured {
                store: STORE_ID.to_owned(),
                detail: format!(
                    "`{variable}` is named as a Proton credential and is neither \
                     `{TOKEN_VAR}` nor `{ENCRYPTION_KEY_VAR}`. Only those two may be set \
                     this way: every other `PROTON_PASS_*` variable is one this adapter \
                     sets itself, and one named here would choose which identity answers \
                     or where its encryption key is looked for"
                ),
            });
        }

        let mut resolved = Vec::with_capacity(self.names.len());
        for (variable, name) in &self.names {
            match self.source.resolve(name) {
                Ok(Some(secret)) => resolved.push((variable.clone(), secret)),
                // Named and missing is a misconfiguration, not an absence: the
                // operator wrote down where the token lives and it is not
                // there, so every Proton name degrades and the message says
                // which entry to write rather than which vault to search.
                Ok(None) => {
                    return Err(StoreError::Misconfigured {
                        store: STORE_ID.to_owned(),
                        detail: format!(
                            "the Proton credential `{variable}` is declared to live in \
                             `{name}` of the `{}` store, which holds no such entry",
                            self.source.id()
                        ),
                    });
                }
                Err(error) => {
                    return Err(StoreError::Misconfigured {
                        store: STORE_ID.to_owned(),
                        detail: format!(
                            "the Proton credential `{variable}` could not be read: {error}"
                        ),
                    });
                }
            }
        }
        Ok(resolved)
    }
}
