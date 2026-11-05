use std::path::Path;
use std::process::Command;

use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::exec::capture;
use crate::store::proton_session;

use super::environment::{KEY_PROVIDER_VAR, REASON_VAR, SESSION_DIR_VAR, set_vendor_switch_offs};
use super::session_dir::{
    NO_SESSION_DIR, SESSION_PROBE_CEILING, SESSION_PROBE_WINDOW, relative_session_dir,
    session_file_present,
};
use super::store::ProtonStore;

impl ProtonStore {
    /// Take a pass on the directory this store's next vendor child should be
    /// scoped at, and say which directory that is.
    ///
    /// On the daemon side this reads `<root>/current` under
    /// [`Generations::enter`], which never waits — there is no gate here to
    /// close, so a renewal in progress never makes a read pause and never makes
    /// it fail. What a fresh root without a published generation yet, or a
    /// pointer a renewal has not caught up with, produces instead is
    /// [`StoreError::Unavailable`] with the fault named — a degraded read the
    /// cache keeps what it holds against, exactly as an unreachable backend
    /// does. On every one of [`proton_session::CurrentFault`]'s three shapes
    /// that reaches this branch, the read also files a
    /// [`proton_session::Generations::report_pointer_fault`] before it
    /// returns, so the renewal loop replaces the broken pointer within its
    /// fault backoff rather than waiting out its next ordinary probe.
    ///
    /// On the session side, which carries no [`Generations`] at all, this
    /// returns a pass over [`ProtonStore::session_dir`] directly, holding no
    /// count — there is nothing here for a renewal to race, because a session
    /// has no renewal loop.
    ///
    /// # The one fallback on the daemon side: a root that has never published
    ///
    /// An install with `stores.proton.session.auto_login` off runs no
    /// renewal loop, so nothing ever writes `<root>/current` — and a
    /// pre-upgrade install's real, working session sits in `<root>/.session`,
    /// the layout this crate wrote before generations existed. Reading that
    /// as an outage rather than as an unmigrated identity is exactly the
    /// silent break this fallback exists to close: `current()` reporting
    /// [`proton_session::CurrentFault::Absent`] — never `Malformed`, never
    /// `Missing`, both of which stay refusals — with the legacy directory
    /// present as a directory hands out a pass scoped at the ROOT, which is
    /// what the vendor reads as the legacy layout on its own (it appends
    /// `.session` itself).
    ///
    /// This is the one daemon-side case where reading past `current` is
    /// safe: `<root>/.session` is what every pre-generations install already
    /// depended on, and [`proton_session::Generations::candidates`] never
    /// treats it as retirable until a generation has actually published —
    /// see that method's own doc. So a root that never publishes keeps
    /// serving the legacy directory forever, and a root that DOES publish
    /// serves the new generation from that instant and retires the legacy
    /// one after its grace, exactly as an ordinary generation would.
    ///
    /// # The pass this hands out is counted like any other
    ///
    /// [`proton_session::Generations::enter_legacy`] credits the same pass
    /// table [`proton_session::Generations::drain`] waits on, under
    /// [`proton_session::GenerationName::legacy`] — a reserved key the
    /// legacy candidate's own retirement now drains by, through
    /// [`proton_session::Candidate::drain_key`], before
    /// [`crate::daemon::login::retire`] spawns a single `pass-cli logout`
    /// against `<root>`. So a vendor child this fallback spawned, still
    /// running against `<root>` at the exact instant a first generation
    /// publishes and the next sweep retires the legacy directory, is waited
    /// out before that logout and the `remove_dir_all` behind it ever run —
    /// the same serialisation an ordinary generation's readers already get.
    pub(super) fn enter(&self) -> Result<proton_session::Pass<'_>, StoreError> {
        match &self.generations {
            Some(generations) => match generations.enter() {
                Ok(pass) => Ok(pass),
                Err(fault @ proton_session::CurrentFault::Absent) => generations
                    .enter_legacy()
                    .map_or_else(|| Err(self.pointer_fault(generations, fault)), Ok),
                Err(fault) => Err(self.pointer_fault(generations, fault)),
            },
            None => {
                let dir = self.session_dir()?.to_path_buf();
                Ok(proton_session::Pass::without_generation(dir))
            }
        }
    }

    /// Is this failure about the daemon's own session rather than about the
    /// name the vendor was asked for?
    ///
    /// Two checks, cheapest first:
    ///
    /// 1. **`stat` the current generation's `session.json`.** The vendor's
    ///    own invalidation cleanup removes it from inside a READ — see the
    ///    behaviours this crate's RCA reads out of the vendor's source — so
    ///    its absence is a session fault this process can establish with no
    ///    vendor call and no text involved at all.
    /// 2. **Present → one coalesced `pass-cli info`** against the same
    ///    generation, through
    ///    [`proton_session::Generations::probe_once_per_window`]. A read that
    ///    fails while `info` REFUSES is a session failure whatever the
    ///    vendor's stderr said; a read that fails while `info` answers is
    ///    about the name, and falls through to [`ProtonStore::backend`].
    ///
    /// # A probe that could not run is not a verdict
    ///
    /// The two wrong answers here do not cost the same. Reading a name's
    /// verdict as a session fault means the daemon KEEPS SERVING a credential
    /// its owner revoked, for the whole cached window; reading a session
    /// fault as a name's verdict evicts a good value and the next read
    /// degrades. So an inconclusive probe — the machine out of process slots,
    /// the deadline hit — answers `false` here and lets the eviction stand,
    /// which is the safe direction for a credential and is what this call
    /// did before the classification existed. It still REPORTS the fault, so
    /// a renewal loop repairs the session either way: refusing to decide
    /// about the name is not the same as declining to fix the session.
    ///
    /// `false` on a `keyless` SESSION, which carries no
    /// [`proton_session::Generations`] and no renewal loop to wake — there is
    /// no daemon-owned identity here for a structural check to ask about,
    /// and inheriting whatever is already logged in is that side's whole
    /// contract. Only a daemon-hosted store, mid-[`ProtonStore::enter`], ever
    /// reaches the two checks above.
    ///
    /// # What this does NOT depend on
    ///
    /// Whether a renewal loop is running. The classification answers what the
    /// failure was ABOUT, and an install whose operator maintains the session
    /// by hand gets the same answer as one running the loop — what differs is
    /// only who performs the repair, which is why
    /// [`session_fault_detail`] promises a replacement is due rather than
    /// that a loop has been woken. On an install with no loop the kept value
    /// still expires on the cache's own `ttl + stale`, so the exposure is the
    /// warm cache's ordinary one rather than an unbounded new one.
    pub(super) fn session_is_at_fault(&self, pass: &proton_session::Pass<'_>) -> bool {
        let (Some(name), Some(generations)) = (pass.generation(), self.generations.as_ref()) else {
            return false;
        };

        if !session_file_present(pass.dir()) {
            generations.report_session_fault(name);
            return true;
        }

        let answered = generations.probe_once_per_window(name, SESSION_PROBE_WINDOW, || {
            self.info_probe_answers(pass.dir())
        });
        match answered {
            // The session refused: this failure is about the session.
            Some(false) => {
                generations.report_session_fault(name);
                true
            }
            // The session answered: the vendor's failure was about the name.
            Some(true) => false,
            // No answer at all. Repair the session, decide nothing about the
            // name — see this function's own doc.
            None => {
                generations.report_session_fault(name);
                false
            }
        }
    }

    /// One `pass-cli info` against `dir`. `Some(true)` the session answered,
    /// `Some(false)` it refused, `None` the probe could not be run at all.
    ///
    /// # Why a failure to run is `None` rather than `false`
    ///
    /// `capture` answers `Err` for a spawn that never happened and for a
    /// deadline hit, and neither is evidence about the session: this crate
    /// already records `EAGAIN` from `fork` under a process-table limit, and
    /// a vendor child that spends hundredths of a second of CPU against a
    /// wall-clock ceiling under memory pressure. Collapsing those into "the
    /// session refused" would turn a loaded machine into a verdict that keeps
    /// a revoked credential alive — see [`ProtonStore::session_is_at_fault`]
    /// for which way the two wrong answers cost.
    fn info_probe_answers(&self, dir: &Path) -> Option<bool> {
        match capture(
            self.info_probe_command(dir, std::env::vars_os()),
            self.timeout.min(SESSION_PROBE_CEILING),
        ) {
            Ok(captured) => Some(captured.status.success()),
            Err(_) => None,
        }
    }

    /// The configured session directory, or the reason there will be no lookup.
    ///
    /// # Why an unset `session_dir` degrades rather than inheriting
    ///
    /// Three answers were available and two of them are worse.
    ///
    /// **Inherit the ambient session** is how the bug this replaces existed at
    /// all. It resolves every name, exactly as a correct configuration does,
    /// while reading an identity nobody chose — so the failure is invisible by
    /// construction and shows up as a full-account credential in a child that
    /// asked for a scoped one. A default whose failure mode is "everything
    /// works" cannot be audited.
    ///
    /// **Inherit and warn** keeps that leak and adds a line to every single
    /// run. This crate already holds the position that a warning printed on
    /// every invocation of a working setup is how a reader learns to skip
    /// stderr — see [`crate::store::Built`]. It would buy nothing: the wrong
    /// vault is still read, the remote audit entry is still written, and the
    /// value still reaches the child. A warning is not a control.
    ///
    /// **Refuse to register the backend** removes the store from the registry,
    /// which turns a `"store": "proton"` pin into `routed store is not
    /// configured` — a message pointing at a backend the user's own config
    /// plainly enables. Same objection as the daemon's dropped pins in
    /// [`crate::store::build`], and it also hides the store from `doctor`,
    /// which is the one place someone has come to ask.
    ///
    /// So the store registers, `doctor` reports it unhealthy with the fix in
    /// the message, and each lookup fails as [`StoreError::Unavailable`]. That
    /// is a **degraded name, never a refused command**: `run` treats an
    /// unavailable store exactly as it treats an unreachable one — it names the
    /// name it could not resolve and spawns the child anyway. The never-block
    /// invariant has no exception here and does not acquire one.
    pub(super) fn session_dir(&self) -> Result<&Path, StoreError> {
        let dir = self
            .session_dir
            .as_deref()
            .ok_or_else(|| self.unavailable(NO_SESSION_DIR))?;
        if !dir.is_absolute() {
            // A relative session directory is the tilde defect wearing different
            // clothes — see `relative_session_dir` for why it degrades here and
            // refuses in the write verbs.
            return Err(self.unavailable(relative_session_dir("stores.proton.session_dir", dir)));
        }
        Ok(dir)
    }

    /// Put the things every child of this adapter needs on one command.
    ///
    /// Written once and called from all five builders, because the set is not
    /// obviously complete and a builder that quietly lacked one of them would
    /// fail in a way nobody reads as a missing variable:
    ///
    /// - **The session directory** decides which logged-in identity answers. A
    ///   verb that inherited the ambient one would enumerate a different set of
    ///   vaults than the verb beside it, which reads as a missing item.
    /// - **The key provider** decides whether that identity survives being
    ///   read. A verb that left it unset under a uid with no keyring would
    ///   reinitialise the session store — see [`KeyProvider`] — so the next
    ///   verb, correctly written, would find nothing. One missing call here is
    ///   enough to make this adapter destroy its own login.
    /// - **The reason** is required by the vendor and is what the remote audit
    ///   entry is filed under.
    /// - **The two vendor switch-offs**, so a `run`, a listing or a view
    ///   writes no telemetry row, and asks about no update even if a later
    ///   release stops skipping that check for a child whose stderr is a
    ///   pipe. See [`set_vendor_switch_offs`].
    ///
    /// Deliberately NOT `env_clear` followed by a rebuild: `pass-cli` may
    /// rewrite its session store on any invocation and must never be handed an
    /// environment somebody stripped. See [`remove_ambient_references`], which
    /// removes exactly what is known to cause a problem and leaves the rest.
    pub(super) fn scope(
        &self,
        command: &mut Command,
        session_dir: &Path,
        login: &[(String, Secret)],
        reason: String,
    ) {
        if let Some((uid, gid)) = self.run_as {
            use std::os::unix::process::CommandExt;
            // gid before uid: dropping the uid first would give up the
            // privilege needed to set the gid.
            command.gid(gid);
            command.uid(uid);
        }
        command.env(SESSION_DIR_VAR, session_dir);
        if let Some(provider) = self.key_provider {
            command.env(KEY_PROVIDER_VAR, provider.as_str());
        }
        for (variable, secret) in login {
            command.env(variable, secret.expose());
        }
        command.env(REASON_VAR, reason);
        set_vendor_switch_offs(command);
    }

    /// The daemon's login, resolved for one lookup, or nothing on a session.
    ///
    /// # Errors
    ///
    /// Whatever [`AgentToken::resolve`] could not read. Never an absence: a
    /// lookup that could not read its own login has not established that a
    /// name is missing.
    pub(super) fn vendor_login(&self) -> Result<Vec<(String, Secret)>, StoreError> {
        match &self.credentials {
            Some(credentials) => credentials.resolve(),
            None => Ok(Vec::new()),
        }
    }
}
