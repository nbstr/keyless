use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::config::{Config, KeychainItem};
use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;
use crate::store::exec::{capture, summarise};
use crate::store::keychain::KeychainStore;

use super::STORE_ID;
use super::environment::remove_ambient_references;
use super::session_dir::{SESSION_SUBDIR, session_file_present, shell_word};
use super::store::ProtonStore;
use super::token::{TOKEN_VAR, refused_the_token};

/// What `build` warns when `auto_login` is on and names no token.
const NO_TOKEN_ITEM: &str = "`stores.proton.session.auto_login` is on but \
     `stores.proton.session.token` names no keychain item, so a session Proton ends \
     stays ended. Add {\"service\": …, \"account\": …} for the item holding the agent \
     token";

/// `stores.proton.session.auto_login`: log a session back in once Proton has
/// ended it, with the agent token kept in the login keychain.
///
/// Proton ends an agent session (two hours, says `pass-cli` 2.7.0's
/// `docs/commands/agent.md`), and the read that finds it ended deletes
/// `<session_dir>/.session` while the keychain key survives. The daemon renews its own session; a session had
/// nothing, so every Proton name degraded until somebody logged in by hand.
///
/// The token is read when a login needs it, put in that one child's
/// environment, and dropped with it.
pub struct AutoLogin {
    keychain: KeychainStore,
    token: KeychainItem,
    /// New sessions this process has seen, its own logins and another
    /// process's alike. A read that began before the latest one failed against
    /// the session it replaced, and is retried rather than logged in again.
    logins: AtomicU64,
    /// One login per process at a time; [`lock_directory`] is the same across
    /// processes.
    in_flight: Mutex<()>,
    /// The first failed login, handed to every later read in this process: a
    /// run of 33 names would otherwise spend 33 logins failing the same way.
    gave_up: OnceLock<StoreError>,
}

impl AutoLogin {
    /// The auto-login `config` asks for, or `None` when it asks for none.
    ///
    /// # Errors
    ///
    /// The sentence to warn with when what it asks for cannot be used: no token
    /// item, or one `keyless run -s` could hand out — see [`servable_by_name`].
    pub fn from_config(config: &Config) -> Result<Option<Self>, String> {
        let Some(session) = config
            .stores
            .proton
            .session
            .as_ref()
            .filter(|session| session.auto_login)
        else {
            return Ok(None);
        };
        let Some(token) = session.token.clone() else {
            return Err(NO_TOKEN_ITEM.to_owned());
        };
        if let Some(problem) = servable_by_name(config, &token) {
            return Err(problem);
        }
        let keychain = &config.stores.keychain;
        Ok(Some(AutoLogin {
            keychain: KeychainStore::new(keychain.binary.to_path_buf(), token.service.clone())
                .with_timeout(crate::config::bounded_timeout(keychain.timeout_ms)),
            token,
            logins: AtomicU64::new(0),
            in_flight: Mutex::new(()),
            gave_up: OnceLock::new(),
        }))
    }

    fn logins(&self) -> u64 {
        self.logins.load(Ordering::SeqCst)
    }

    /// Log `session_dir` in again, unless somebody did while this caller
    /// waited, and say whether the session is back.
    ///
    /// `ended` is the caller's own finding, made before the lock so that
    /// readers failing together do not ask the vendor one after another. What
    /// that finding cannot settle is decided here, under the lock. A login
    /// writes its session BEFORE it is counted — it is counted once `info` has
    /// confirmed it — and a reader that asked inside that moment found the
    /// session answering, so it took its own failure, met on the ended
    /// session, for the name's. Taking the lock waits that login out, and the
    /// count then says the session was replaced.
    fn log_in_again(
        &self,
        store: &ProtonStore,
        session_dir: &Path,
        logins_before: u64,
        ended: bool,
    ) -> Result<bool, StoreError> {
        let _this_process = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.logins() != logins_before {
            return Ok(true);
        }
        if !ended {
            return Ok(false);
        }
        if let Some(error) = self.gave_up.get() {
            return Err(error.clone());
        }
        self.log_in(store, session_dir).inspect_err(|error| {
            self.gave_up.get_or_init(|| error.clone());
        })?;
        Ok(true)
    }

    /// Return once no login is running in this process.
    fn after_a_login_in_flight(&self) {
        drop(
            self.in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    fn log_in(&self, store: &ProtonStore, session_dir: &Path) -> Result<(), StoreError> {
        let _every_process = lock_directory(store, session_dir)?;
        // Before the check below: an open store refuses `info` too, so a
        // session another process just logged in would read as ended.
        shut_session_store(store, session_dir)?;
        // Another process logged in while this one waited for the lock.
        if !store.session_ended(session_dir) {
            self.logins.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }

        let token = [(TOKEN_VAR.to_owned(), self.read_token()?)];
        let captured = capture(store.login_command(session_dir, &token), store.timeout)
            .map_err(|error| store.unreachable(&error))?;
        shut_session_store(store, session_dir)?;
        // The exit status alone is not the proof: a login that left no live
        // session would leave the retry failing exactly as the first read did.
        if captured.status.success() && !store.session_ended(session_dir) {
            self.logins.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        if captured.status.success() {
            return Err(store.unavailable(format!(
                "Proton ended this session, and the login reported success but left a session \
                 at {} that is still refused",
                session_dir.display()
            )));
        }

        let said = summarise(&captured.stderr);
        if refused_the_token(&said) {
            return Err(store.unavailable(format!(
                "Proton ended this session and refused the agent token in keychain item {} — \
                 invalid, expired or deleted. Mint a new one and replace the item with `{}`. \
                 The vendor said: {said}",
                self.item(),
                self.store_command()
            )));
        }
        Err(store.unavailable(format!(
            "Proton ended this session and logging it in again failed: {said}"
        )))
    }

    fn read_token(&self) -> Result<Secret, StoreError> {
        match self.keychain.resolve(&self.token.account) {
            Ok(Some(token)) => Ok(token),
            Ok(None) => Err(StoreError::Misconfigured {
                store: STORE_ID.to_owned(),
                detail: format!(
                    "Proton ended this session and keychain item {} holds no agent token to \
                     log it in again with. Store one with `{}`",
                    self.item(),
                    self.store_command()
                ),
            }),
            Err(error) => Err(StoreError::Unavailable {
                store: STORE_ID.to_owned(),
                detail: format!(
                    "Proton ended this session and the agent token could not be read from \
                     keychain item {}: {error}",
                    self.item()
                ),
            }),
        }
    }

    fn item(&self) -> String {
        format!("`{}`/`{}`", self.token.service, self.token.account)
    }

    /// `-w` comes last so `security` prompts for the token rather than taking
    /// it from the command line, where the shell history would keep it.
    fn store_command(&self) -> String {
        format!(
            "security add-generic-password -U -s {} -a {} -w",
            shell_word(Path::new(&self.token.service)),
            shell_word(Path::new(&self.token.account))
        )
    }
}

/// Why `keyless run -s` could hand the token to a command, if it could.
///
/// The keychain store answers an undeclared name as an account under its own
/// service, and a declared one at its own coordinates. Either way the token
/// that opens the vault would be one more name any command can ask for.
fn servable_by_name(config: &Config, token: &KeychainItem) -> Option<String> {
    let service = &config.stores.keychain.service;
    if &token.service == service {
        return Some(format!(
            "`stores.proton.session.token` sits under `{service}`, the keychain store's own \
             service, so `keyless run -s {}` would hand the agent token to any command. Give \
             the item a service of its own; auto-login is off until then",
            token.account
        ));
    }
    config
        .secrets
        .iter()
        .find(|(name, route)| {
            route
                .store
                .as_deref()
                .is_none_or(|store| store == "keychain")
                && route.service.as_ref().unwrap_or(service) == &token.service
                && route.account.as_ref().unwrap_or(name) == &token.account
        })
        .map(|(name, _)| {
            format!(
                "`{name}` under `secrets` points at the keychain item \
                 `stores.proton.session.token` names, so `keyless run -s {name}` would hand \
                 the agent token to any command. Remove it; auto-login is off until then"
            )
        })
}

/// Hold `dir` for one login across every process, until the handle drops.
///
/// Two runs that find the session ended together would otherwise both log in,
/// the second over the session the first just wrote. The wait is bounded: the
/// holder's login runs under [`capture`]'s deadline.
fn lock_directory(store: &ProtonStore, dir: &Path) -> Result<File, StoreError> {
    let handle = File::open(dir).map_err(|error| {
        store.unavailable(format!(
            "cannot open {} to log in again: {error}",
            dir.display()
        ))
    })?;
    handle.lock().map_err(|error| {
        store.unavailable(format!(
            "cannot lock {} to log in again: {error}",
            dir.display()
        ))
    })?;
    Ok(handle)
}

/// Take group and others off `<dir>/.session`, which every `pass-cli` verb
/// refuses otherwise, `login` included: `Session directory is accessible by
/// group or others`.
///
/// `pass-cli` 2.7.0 makes the directory 0700 itself, from `info` and from
/// `login` alike (measured 2026-11-24). What leaves it open is the race this
/// login runs in: a read still running finds the session ended and deletes
/// `.session`, and the login then writes its files back into a directory made
/// at the process umask. Seen twice that day on a dev session of 31 names —
/// once refusing the login outright, once letting it succeed and refusing the
/// `info` that checks it — and each time every name degraded until a `chmod`
/// by hand. The daemon re-asserts its own directory before each login for the
/// same reason (`ensure_session_dir`).
///
/// Only bits are taken away, and only from a real directory: a symlink is left
/// for the vendor to refuse, never followed.
#[cfg(unix)]
fn shut_session_store(store: &ProtonStore, dir: &Path) -> Result<(), StoreError> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let session_store = dir.join(SESSION_SUBDIR);
    let meta = match fs::symlink_metadata(&session_store) {
        Ok(meta) if meta.is_dir() => meta,
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(store.unavailable(format!(
                "cannot examine {} to log in again: {error}",
                session_store.display()
            )));
        }
    };
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 == 0 {
        return Ok(());
    }
    fs::set_permissions(&session_store, fs::Permissions::from_mode(mode & !0o077)).map_err(
        |error| {
            store.unavailable(format!(
                "{} is open to group or others, which `pass-cli` refuses, and cannot be shut: \
                 {error}",
                session_store.display()
            ))
        },
    )
}

#[cfg(not(unix))]
fn shut_session_store(_store: &ProtonStore, _dir: &Path) -> Result<(), StoreError> {
    Ok(())
}

impl ProtonStore {
    /// Turn on [`AutoLogin`]; `None` leaves an ended session for a person to
    /// log in again.
    #[must_use]
    pub fn with_auto_login(mut self, auto_login: Option<AutoLogin>) -> Self {
        self.auto_login = auto_login;
        self
    }

    /// Logins made so far, to hand back to [`ProtonStore::logged_in_again`]
    /// once a read has failed.
    pub(super) fn logins_so_far(&self) -> u64 {
        self.auto_login.as_ref().map_or(0, AutoLogin::logins)
    }

    /// After a failed read: whether the session is back, so the read is worth
    /// one more try.
    ///
    /// `true` when this call logged in again, or a sibling thread did since the
    /// read began — including one still checking its login when this read
    /// asked, see [`AutoLogin::log_in_again`]. `false` when auto-login is off,
    /// or the session still answers — then the failure was about the name.
    pub(super) fn logged_in_again(&self, logins_before: u64) -> Result<bool, StoreError> {
        let Some(auto_login) = &self.auto_login else {
            return Ok(false);
        };
        let Ok(dir) = self.session_dir() else {
            return Ok(false);
        };
        if auto_login.logins() != logins_before {
            return Ok(true);
        }
        let ended = dir.is_dir() && self.session_ended(dir);
        auto_login.log_in_again(self, dir, logins_before, ended)
    }

    /// Wait out a login this process has running, so that what is fetched next
    /// belongs to the session it puts in place. Free when none is running.
    pub(super) fn after_any_login_in_flight(&self) {
        if let Some(auto_login) = &self.auto_login {
            auto_login.after_a_login_in_flight();
        }
    }

    /// Whether Proton has ended the session at `dir`.
    ///
    /// `session.json` gone is enough; present proves nothing. On a real
    /// expiry (2026-11-11) the file stayed while every read answered `there is
    /// no session`, so a file-only check let the dead session through and no
    /// login ran: the read Proton refuses deletes `.session` while a background
    /// write can put an empty `session.json` back. A present file is therefore
    /// asked with `info`, as the daemon asks its own; a probe that could not
    /// run is no verdict.
    fn session_ended(&self, dir: &Path) -> bool {
        !session_file_present(dir) || self.info_probe_answers(dir) == Some(false)
    }

    fn login_command(&self, session_dir: &Path, token: &[(String, Secret)]) -> Command {
        let mut command = Command::new(&self.binary);
        command.arg("login");
        remove_ambient_references(&mut command, std::env::vars_os());
        self.scope(
            &mut command,
            session_dir,
            token,
            self.reason
                .for_action("logging in", "again after Proton ended the session"),
        );
        command
    }
}
