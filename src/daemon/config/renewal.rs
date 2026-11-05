use serde::{Deserialize, Serialize};

use super::DaemonConfig;

/// The renewal loop's settings — how the daemon puts its own session back
/// before the vendor takes it away.
///
/// # Why a loop is needed at all
///
/// A session opened with a personal access token lasts **two hours**, and the
/// vendor publishes no renewal verb: "Sessions established with a personal
/// access token have a lifetime of 2 hours, so you need to log in again once it
/// expires" — <https://protonpass.github.io/pass-cli/commands/personal-access-token/>.
/// Logging in again IS the renewal, and it is unattended and free.
///
/// So expiry every two hours is the design working, and the only question is
/// what runs the loop. Until this struct existed, nothing here did:
/// [`DaemonProtonConfig::session_dir`] already says that a daemon "must be able
/// to put that session back when the vendor drops it", and the daemon shipped
/// with no code that ever did. Every Proton name degraded on a clock nobody
/// chose, with nobody awake to read it.
///
/// # Why it is opt-in
///
/// The loop still ends every generation it replaces with a real,
/// account-level `pass-cli logout` — see [`crate::daemon::login::retire`] —
/// even though a read is never made to wait for the replacement itself (see
/// [`SessionRenewal::login_after_minutes`]). Switching it on for the first
/// time on an existing install therefore still changes what happens to a
/// session directory an operator may be managing by hand, from outside this
/// process — later, and never on a lookup's own time, but a real logout all
/// the same. A default that started rotating and logging out sessions on
/// upgrade would be a surprising thing for a patch release to do to a
/// working install.
///
/// # The shape is Vault Agent's, minus one field
///
/// HashiCorp's Vault Agent solves the same problem with the same three parts —
/// a bootstrap credential on the agent's own disk, a renewal loop, and a sink —
/// and its `auto_auth` block carries `min_backoff`, `max_backoff` and
/// `exit_on_err`. The two backoffs are mirrored here.
///
/// `exit_on_err` is deliberately NOT: Vault Agent brokers one identity, so
/// exiting takes away only what was already broken. This daemon serves several
/// stores, and a Proton login that keeps failing would take Infisical, the file
/// store and the keychain down with it. The loop latches instead — it keeps
/// trying at [`SessionRenewal::max_backoff_seconds`] forever, and the names
/// from every other store keep resolving.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct SessionRenewal {
    /// Off unless asked for.
    #[serde(default)]
    pub auto_login: bool,
    /// How old a session may get before the loop replaces it, in minutes.
    ///
    /// Under the vendor's 120-minute cap by a margin wide enough to absorb a
    /// failed attempt and a backoff, so a session is never renewed at the edge
    /// of the cliff it exists to stay off.
    ///
    /// The replacement establishes a fresh generation, verifies it, and swaps
    /// the current pointer to it — see
    /// [`crate::daemon::login::establish`] — so the generation the daemon was
    /// already serving from keeps answering, unmodified, for the whole
    /// duration of the replacement. A read is never made to wait for it.
    #[serde(default = "default_login_after_minutes")]
    pub login_after_minutes: u64,
    /// How often the loop wakes to check the session's age.
    ///
    /// It also decides how fast an unhealthy session is noticed, so it is well
    /// under [`SessionRenewal::login_after_minutes`] rather than equal to it.
    #[serde(default = "default_probe_interval_seconds")]
    pub probe_interval_seconds: u64,
    /// The first wait after a failed login.
    #[serde(default = "default_min_backoff_seconds")]
    pub min_backoff_seconds: u64,
    /// The longest wait between failed logins. The loop never stops trying.
    #[serde(default = "default_max_backoff_seconds")]
    pub max_backoff_seconds: u64,
}

impl Default for SessionRenewal {
    fn default() -> Self {
        SessionRenewal {
            auto_login: false,
            login_after_minutes: default_login_after_minutes(),
            probe_interval_seconds: default_probe_interval_seconds(),
            min_backoff_seconds: default_min_backoff_seconds(),
            max_backoff_seconds: default_max_backoff_seconds(),
        }
    }
}

/// The vendor's cap on a personal-access-token session, in minutes.
///
/// Not configurable and not discovered: it is Proton's, documented at
/// <https://protonpass.github.io/pass-cli/commands/personal-access-token/>, and
/// it is here so a mistuned `login_after_minutes` can be judged against the
/// number it has to stay under.
pub(super) const PROTON_SESSION_CAP_MINUTES: u64 = 120;

const fn default_login_after_minutes() -> u64 {
    90
}

const fn default_probe_interval_seconds() -> u64 {
    300
}

const fn default_min_backoff_seconds() -> u64 {
    1
}

const fn default_max_backoff_seconds() -> u64 {
    300
}

impl DaemonConfig {
    /// What is wrong with `stores.proton.session`, in sentences an operator can act on.
    ///
    /// Warnings rather than refusals: every one of these leaves a daemon that
    /// serves every other store correctly, and a Proton renewal that is merely
    /// mistuned is worth saying out loud rather than worth refusing to start
    /// four other stores over. The one arrangement that DOES refuse — asking
    /// for the loop with a config that cannot support a login — is refused by
    /// [`super::session::spawn`], because there the operator has said the
    /// session matters and starting anyway reproduces the silent outage.
    pub(super) fn session_warnings(&self) -> Vec<String> {
        let settings = self.stores.proton.session;
        if !settings.auto_login {
            return Vec::new();
        }
        let mut warnings = Vec::new();
        if !self.stores.proton.enabled {
            warnings.push(
                "`stores.proton.session.auto_login` is true while `stores.proton.enabled` is                  false, so no session is kept alive and no Proton name resolves"
                    .to_owned(),
            );
        }
        if settings.login_after_minutes >= PROTON_SESSION_CAP_MINUTES {
            warnings.push(format!(
                "`stores.proton.session.login_after_minutes` is {}, at or past the vendor's                  {PROTON_SESSION_CAP_MINUTES}-minute cap on a personal-access-token session, so                  the session expires before the loop replaces it and every Proton name degrades                  in between",
                settings.login_after_minutes
            ));
        }
        if settings.probe_interval_seconds >= settings.login_after_minutes.saturating_mul(60) {
            warnings.push(format!(
                "`stores.proton.session.probe_interval_seconds` is {}, which is not shorter than                  the {}-minute renewal age, so the loop can only notice a session is due after                  it already expired",
                settings.probe_interval_seconds, settings.login_after_minutes
            ));
        }
        if settings.max_backoff_seconds < settings.min_backoff_seconds {
            warnings.push(format!(
                "`stores.proton.session.max_backoff_seconds` ({}) is below `min_backoff_seconds`                  ({}), so the backoff never grows and a failing login retries at the minimum                  forever",
                settings.max_backoff_seconds, settings.min_backoff_seconds
            ));
        }
        warnings
    }
}
