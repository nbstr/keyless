use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;
use crate::store::exec::{capture, strip_one_newline, summarise};
use crate::store::proton_session;

use super::STORE_ID;
use super::commands::TempEnvFile;
use super::environment::REFERENCE_SCHEME;
use super::listing::{Matched, match_title};
use super::routing::{Address, ItemAddress};
use super::session_dir::{interrupted_write, interrupted_write_detail};
use super::store::{ProtonStore, resolve_executable};
use super::token::{login_into, refused_the_token};

/// What the vendor's masking substitutes for a value.
///
/// Taken from the documentation rather than observed. If the real text differs,
/// the guard that uses it does not fire — so the guard is a second line of
/// defence behind `--no-masking`, never the only one.
const CONCEALED_MARKER: &str = "concealed by proton pass";

impl Store for ProtonStore {
    fn id(&self) -> &str {
        STORE_ID
    }

    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        let Some(address) = self.routing.route(name) else {
            return Ok(None);
        };

        // One pass spans every child this lookup may spawn — the listing
        // inside `reference_for`, the probe below, and a session-health
        // `info` should the probe fail — so a retirement waits for at most
        // one reader's worth of vendor children rather than treating each
        // spawn as its own pass.
        let pass = self.enter()?;

        // Resolved every time, never stored: a share id belongs to one session.
        let reference = match address.as_ref() {
            Address::Reference(reference) => reference.clone(),
            Address::Named(address) => self.reference_for(&pass, name, address)?,
            Address::Unusable(detail) => return Err(self.backend(detail.clone())),
        };
        let reference = reference.as_str();

        let directory = std::env::temp_dir();
        let env_file = TempEnvFile::create(&directory, reference).map_err(|source| {
            self.unavailable(format!("cannot write a probe env file: {source}"))
        })?;

        let mut captured = capture(
            self.probe_command(
                pass.dir(),
                &env_file.path,
                name,
                &self.vendor_login()?,
                std::env::vars_os(),
            ),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            let said = summarise(&captured.stderr);
            let error = self.vendor_failed(&pass, said.clone(), &said);
            drop(pass);
            return Err(error);
        }
        drop(pass);

        let mut bytes = std::mem::take(&mut captured.stdout);
        strip_one_newline(&mut bytes);

        if bytes.is_empty() {
            return Err(self.backend(format!("`{reference}` resolved to an empty value")));
        }

        if looks_concealed(&bytes) {
            // `--no-masking` did not take effect. Injecting the mask token
            // would hand the child a string that is not the credential and
            // looks like one, which fails later and somewhere else.
            return Err(self.backend(
                "the value came back concealed; `--no-masking` was not honoured".to_owned(),
            ));
        }

        Secret::from_bytes(bytes)
            .map(Some)
            .ok_or_else(|| self.backend(format!("`{reference}` is not valid UTF-8")))
    }

    /// Local preconditions, then one round trip that proves the session is alive.
    ///
    /// # Why this asks the vendor something
    ///
    /// It used to check the session DIRECTORY and the binary and stop, on the
    /// reasoning that reachability and authentication "can be observed for free
    /// at the first real lookup, which degrades". Measured on 2026-08-08, that
    /// reasoning produces the exact failure this whole tool exists to kill:
    /// with the agent session expired, `doctor` printed `store proton ok` and
    /// `0 problem(s)` while EVERY Proton name was degrading, and the child ran
    /// with an empty bearer and came back HTTP 400 at exit 0.
    ///
    /// The premise was wrong in one word: **free**. A degraded lookup is only
    /// observable to somebody already reading stderr of a run that is failing
    /// for a reason they do not yet know. `doctor` is the command they are told
    /// to run to find that reason out, and `keyless run` never blocks on a
    /// store's failure, so a dead session has no other alarm anywhere on the
    /// machine. A health check
    /// that cannot see the single most common way this backend dies is not a
    /// cheaper check, it is a check of something else.
    ///
    /// One directory away, [`crate::store::infisical`] already pays this cost
    /// and documents why. This is that idiom, not a second one.
    ///
    /// # What the round trip costs, and what bounds it
    ///
    /// `vault list` prints vault names, ids and counts — no item content of any
    /// kind — so no credential is read and no item's audit trail gains an entry
    /// for a read nobody asked for. It is the same verb `keyless items` already
    /// spends when no vault is named.
    ///
    /// It cannot hang and it cannot prompt: [`capture`] gives the child
    /// `/dev/null` on stdin, so a vendor that decided to ask for a password gets
    /// end-of-file instead, and the configured timeout plus the output cap bound
    /// it either way.
    ///
    /// # Why a failure is a PROBLEM and not a third state
    ///
    /// Because it is one. A session this call cannot use is a session no lookup
    /// can use, so every Proton name in the config will degrade. Saying so is
    /// `doctor`'s whole job, and it stays inside `doctor`'s contract: a problem
    /// here degrades a run, it never blocks one. Nothing in `run` consults this.
    fn health(&self) -> Result<(), StoreError> {
        // Local facts first, so the message names the closest cause. Both are
        // preconditions of the round trip below: with no session directory there
        // is no identity to ask as, and with no binary there is nothing to ask.
        // The value itself is not kept — every message below names the
        // directory the round trip actually read, off `pass`, not this
        // configured root; see the two remedies further down for why.
        self.session_dir()?;

        if resolve_executable(&self.binary).is_none() {
            return Err(self.unavailable(format!(
                "`{}` is not on PATH or is not executable",
                self.binary.display()
            )));
        }

        let pass = self.enter()?;
        let captured = capture(
            self.vault_list_command(pass.dir(), &self.vendor_login()?, std::env::vars_os()),
            self.timeout,
        )
        .map_err(|error| self.unreachable(&error))?;

        if captured.status.success() {
            // Deliberately no forensics on the success path. An orphan temp file
            // beside a session that ANSWERED is debris, not a fault, and a health
            // check that reports a problem on a working store is how a health
            // check gets ignored.
            return Ok(());
        }

        // stderr only, as everywhere else in this adapter, and with the fix
        // attached: the vendor says what is wrong, not what to do about it.
        let vendor = summarise(&captured.stderr);

        // Asked only once the round trip has already failed, so a working store
        // never pays for it and a passing report never depends on it. Scoped at
        // the directory this pass actually read — the generation on the daemon
        // side, the configured directory itself on the session side.
        if let Some(write) = interrupted_write(pass.dir()) {
            return Err(self.unavailable(interrupted_write_detail(pass.dir(), &write, &vendor)));
        }

        // The one refusal that must not be reported as "the session is
        // broken": the vendor REFUSED THE TOKEN. The remedy is at the vendor
        // and not on this filesystem, and a reader told to re-mint a session
        // will re-mint it with the same rejected token and watch it fail again.
        if refused_the_token(&vendor) {
            return Err(self.unavailable(format!(
                "Proton refused this daemon's agent token. This is a LOGIN failure and not a \
                 missing secret, and the vendor cannot say which of three causes it is — its \
                 words cover an expired token, a revoked one and a mistyped one alike. Check \
                 `stores.proton.token_expires` first, then whether the token still exists at \
                 the vendor; mint a fresh one, log the session at {} in with it, and write it \
                 with `{} credential --store {STORE_ID}`. The vendor said: {vendor}",
                pass.dir().display(),
                crate::DAEMON_NAME,
            )));
        }

        // Two audiences, two remedies, and `session_dir` (the configured
        // ROOT) serves neither. A generation-backed store reads through
        // `Generations`, and the raw vendor command an operator would paste
        // by hand — `PROTON_PASS_SESSION_DIR=<root> pass-cli login` — writes
        // into `<root>/.session`, the LEGACY layout: `current` never moves to
        // name it, the next sweep treats it as the retirement candidate it
        // looks like, and it is gone before the operator's next `check`. The
        // daemon's own verb is the one that actually publishes a generation
        // `current` can name. A session-side store has no generations to
        // publish and the raw command is exactly right there, so it keeps
        // the one it always had.
        let remedy = if self.generations.is_some() {
            format!("{} login --store {STORE_ID}", crate::DAEMON_NAME)
        } else {
            login_into(pass.dir())
        };
        Err(self.unavailable(format!(
            "the session at {} cannot be used: {vendor}; re-mint it with `{remedy}` \
             (or re-issue the agent token) and check `stores.proton.session_dir`",
            pass.dir().display(),
        )))
    }
}

/// Whether the bytes look like the vendor's concealment placeholder.
pub(super) fn looks_concealed(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes)
        .to_ascii_lowercase()
        .contains(CONCEALED_MARKER)
}

impl ProtonStore {
    /// Turn a stable address into a reference this session can resolve.
    ///
    /// Everything named in an error here is a coordinate — a vault name, an item
    /// title, an item id. None of them is a value, and the listing this reads
    /// cannot carry one.
    fn reference_for(
        &self,
        pass: &proton_session::Pass<'_>,
        name: &str,
        address: &ItemAddress,
    ) -> Result<String, StoreError> {
        let items = self.cached_items(pass, &address.vault, name)?;

        match match_title(&items, &address.item) {
            Matched::One(only) => Ok(format!(
                "{REFERENCE_SCHEME}{}/{}/{}",
                only.share_id, only.id, address.field
            )),
            Matched::None => Err(self.not_held(format!(
                "vault `{}` holds no item titled `{}`",
                address.vault, address.item
            ))),
            Matched::OnlyTrashed => Err(self.not_held(format!(
                "the only item titled `{}` in vault `{}` is in the trash; \
                 restore it, or point `{name}` at a live item",
                address.item, address.vault
            ))),
            Matched::Several(several) => Err(self.backend(format!(
                "{} live items in vault `{}` are titled `{}`, so `{name}` names no one item; \
                 pin one with \"reference\": \"pass://<share id>/<item id>/{}\" — candidates: {}",
                several.len(),
                address.vault,
                address.item,
                address.field,
                several
                    .iter()
                    .map(|record| record.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    fn not_held(&self, detail: String) -> StoreError {
        StoreError::Refused {
            store: Store::id(self).to_owned(),
            detail,
        }
    }
}
