use crate::error::StoreError;
use crate::store::Store;
use crate::store::exec::{self, CaptureError};
use crate::store::proton_session;

use super::session_dir::session_fault_detail;
use super::store::ProtonStore;

/// Words in a vendor failure that mean the request never reached Proton's
/// service, or lost it before an answer came back.
///
/// The first two are `pass-cli`'s own, observed verbatim in the daemon's log on
/// 2026-09-09 during a network outage: `failed to connect to host: error
/// resolving destination: unknown error errno=None`. The rest are this
/// platform's `strerror` text, read from libc rather than recalled, for
/// `ECONNREFUSED`, `ENETUNREACH`, `EHOSTUNREACH`, `ECONNRESET`, `ETIMEDOUT` and
/// `ECONNABORTED` — which the vendor passes through as `std` renders an
/// `io::Error`, `<strerror> (os error <n>)`.
///
/// A connection lost mid-command belongs here too: nothing came back, so
/// nothing was decided.
const UNREACHABLE: &[&str] = &[
    "failed to connect to host",
    "error resolving destination",
    "connection refused",
    "network is unreachable",
    "no route to host",
    "connection reset by peer",
    "operation timed out",
    "software caused connection abort",
];

/// Did a vendor failure happen because nothing reached the service?
///
/// # Why this is an allowlist, and why it must stay one
///
/// The two readings of a vendor failure are not symmetric, and the daemon's
/// cache is what makes the asymmetry expensive. A verdict read as transport
/// means a value the account has disowned keeps being served for the whole
/// stale window. Transport read as a verdict costs one eviction and a cold
/// lookup — today's behaviour, on a path that already works.
///
/// So the recognised set is the measured phrases and nothing else, and every
/// sentence outside it is a verdict. A new phrase joins the list only after it
/// has been seen, which is the direction the `Active` filter takes too.
#[must_use]
pub fn reached_no_service(said: &str) -> bool {
    let lowered = said.to_ascii_lowercase();
    UNREACHABLE.iter().any(|words| lowered.contains(words))
}

impl ProtonStore {
    /// File a [`proton_session::Generations::report_pointer_fault`] and build
    /// the [`StoreError::Unavailable`] both `enter` error arms return —
    /// carried once so the two arms cannot drift out of the reporting `enter`
    /// itself promises in its own doc.
    pub(super) fn pointer_fault(
        &self,
        generations: &proton_session::Generations,
        fault: proton_session::CurrentFault,
    ) -> StoreError {
        generations.report_pointer_fault();
        self.unavailable(format!("{fault} (root {})", generations.root().display()))
    }

    /// What a vendor child's failure says about the item.
    ///
    /// [`StoreError::Unavailable`] where its own words name a transport
    /// failure, because nothing was decided; the same where the failure is
    /// about the daemon's OWN session rather than about `name` — see
    /// [`ProtonStore::session_is_at_fault`], the structural check below.
    /// [`StoreError::Backend`] otherwise, which is the vendor answering
    /// about this name. The daemon's cache reads the variant: a `Backend`
    /// evicts the value, an `Unavailable` keeps it.
    ///
    /// # Why the session check is structural, not a second phrase in the
    /// # allowlist
    ///
    /// [`UNREACHABLE`] is measured phrases, joined only once seen — the right
    /// discipline for a fault that is genuinely about wording. A session
    /// fault has no phrase to measure: the vendor's own sentence for "this
    /// session store cannot be decrypted",
    /// `Error decrypting local session(Error decrypting session: aead::Error)`,
    /// is one string for a key mismatch, an interrupted write, and a
    /// concurrent deleter alike, so matching it would classify every failure
    /// like it correctly until the vendor rewords it, then wrongly for good.
    /// [`ProtonStore::session_is_at_fault`] asks the session itself instead —
    /// a question this crate owns — which survives a reword because it
    /// depends on no words at all.
    pub(super) fn vendor_failed(
        &self,
        pass: &proton_session::Pass<'_>,
        detail: String,
        said: &str,
    ) -> StoreError {
        if reached_no_service(said) {
            return self.unavailable(detail);
        }
        if self.session_is_at_fault(pass) {
            return self.unavailable(session_fault_detail(&detail, pass.dir()));
        }
        self.backend(detail)
    }

    pub(super) fn unavailable(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Unavailable {
            store: Store::id(self).to_owned(),
            detail: detail.into(),
        }
    }

    pub(super) fn backend(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Backend {
            store: Store::id(self).to_owned(),
            detail: detail.into(),
        }
    }

    pub(super) fn unreachable(&self, error: &CaptureError) -> StoreError {
        exec::unavailable(Store::id(self), &self.binary, error)
    }
}
