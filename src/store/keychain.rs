//! macOS Keychain, via the `security` command-line tool.
//!
//! Shelling out rather than linking the Security framework, on purpose: the
//! `security` binary is present on every macOS install, needs no `unsafe`, no
//! FFI and no build-time SDK, and the keychain access prompt it triggers is the
//! one the user already recognises. The cost is one process spawn per lookup,
//! which is irrelevant next to the process we are about to spawn anyway.
//!
//! # The value's path through memory
//!
//! `security -w` writes the plaintext to its stdout. That buffer is read into a
//! `Vec<u8>`, handed to [`Secret::from_bytes`], and zeroized there. What cannot
//! be scrubbed is the copy the kernel held in the pipe and the copy the
//! `security` process itself had — those belong to processes we do not own.
//! Written down rather than implied: this reduces the plaintext's residency, it
//! does not eliminate it.

use std::path::PathBuf;
use std::process::Command;

use zeroize::Zeroize;

use crate::config::{Config, SecretRoute};
use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;
use crate::store::exec::{capture, capture_with_input, first_line, strip_one_newline, unavailable};
use crate::store::manage::{Manage, ManageError, Stored};

/// `errSecItemNotFound`. `security` exits with this when the item is simply
/// absent, which is an answer rather than a failure.
const EXIT_ITEM_NOT_FOUND: i32 = 44;

/// Reads generic passwords out of the login keychain.
pub struct KeychainStore {
    binary: PathBuf,
    default_service: String,
    /// Which keychain file to search, when not the caller's default list.
    keychain: Option<PathBuf>,
    /// name -> (service, account) overrides taken from config.
    routes: std::collections::BTreeMap<String, (String, String)>,
    /// How long one lookup gets. See [`crate::store::exec::capture`].
    timeout: std::time::Duration,
}

impl KeychainStore {
    /// Construct with an explicit binary and default service.
    #[must_use]
    pub fn new(binary: PathBuf, default_service: String) -> Self {
        KeychainStore {
            binary,
            default_service,
            keychain: None,
            routes: std::collections::BTreeMap::new(),
            timeout: crate::config::bounded_timeout(crate::config::DEFAULT_TIMEOUT_MS),
        }
    }

    /// Use a different deadline than the default.
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Search one specific keychain file rather than the caller's default list.
    ///
    /// A launchd daemon has no login keychain and no GUI session, so its
    /// default search list is empty in practice and every lookup finds nothing
    /// — which is indistinguishable from the item being absent. Naming the file
    /// is what makes the daemon able to read a keychain at all.
    #[must_use]
    pub fn in_keychain(mut self, keychain: Option<PathBuf>) -> Self {
        self.keychain = keychain;
        self
    }

    /// Construct from a parsed config, including per-name service and account
    /// overrides.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let keychain = &config.stores.keychain;
        let routes = config
            .secrets
            .iter()
            .map(|(name, route)| {
                let service = route
                    .service
                    .clone()
                    .unwrap_or_else(|| keychain.service.clone());
                let account = route.account.clone().unwrap_or_else(|| name.clone());
                (name.clone(), (service, account))
            })
            .collect();
        KeychainStore {
            binary: keychain.binary.to_path_buf(),
            default_service: keychain.service.clone(),
            keychain: None,
            routes,
            timeout: crate::config::bounded_timeout(keychain.timeout_ms),
        }
    }

    /// The keychain coordinates for a name. An undeclared name looks itself up
    /// as the account under the default service.
    fn coordinates(&self, name: &str) -> (String, String) {
        self.routes
            .get(name)
            .cloned()
            .unwrap_or_else(|| (self.default_service.clone(), name.to_owned()))
    }

    fn unavailable(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Unavailable {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }

    fn backend(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Backend {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }
}

impl Store for KeychainStore {
    fn id(&self) -> &str {
        "keychain"
    }

    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        let (service, account) = self.coordinates(name);
        let mut command = Command::new(&self.binary);
        command
            .arg("find-generic-password")
            .arg("-s")
            .arg(&service)
            .arg("-a")
            .arg(&account)
            .arg("-w");
        // Trailing positional argument, which is how `security` names the
        // keychain to search.
        if let Some(keychain) = &self.keychain {
            command.arg(keychain);
        }
        // Through `capture` rather than `Command::output`, which waits forever
        // and reads without a bound. Both matter here and neither is theory: a
        // `security` that never answers wedges the terminal with no child and no
        // message, and a `security` that streams `/dev/zero` grows this process
        // until the kernel ends it. `binary` is a config field, so neither
        // requires a compromised system tool.
        let mut output = capture(command, self.timeout)
            .map_err(|error| unavailable(self.id(), &self.binary, &error))?;

        if !output.status.success() {
            if output.status.code() == Some(EXIT_ITEM_NOT_FOUND) {
                return Ok(None);
            }
            // stderr only. stdout is where the plaintext would be, so it is
            // never read on an error path.
            return Err(self.backend(first_line(&output.stderr)));
        }

        // Moved out rather than borrowed: `Captured::drop` zeroizes whatever is
        // still there, and the value is about to become a `Secret` that owns the
        // same duty.
        let mut bytes = std::mem::take(&mut output.stdout);
        strip_one_newline(&mut bytes);

        if bytes.is_empty() {
            return Err(self.backend(format!(
                "item {service}/{account} exists but its value is empty"
            )));
        }

        Secret::from_bytes(bytes)
            .map(Some)
            .ok_or_else(|| self.backend(format!("item {service}/{account} is not valid UTF-8")))
    }

    fn health(&self) -> Result<(), StoreError> {
        // The guard comes before the spawn, and it is a `stat` rather than a
        // process, because the failure it prevents is not an error — it is a
        // MODAL DIALOG. See `default_keychain_is_reachable`.
        self.default_keychain_is_reachable()?;

        // A search for an item that is not there. This is the whole fix: the
        // old check ran `security list-keychains`, which proves the binary
        // answered and touches no item, and then printed `ok` — so a locked
        // keychain and a working one were the same report. Measured with the
        // suite's own `Stub::Errors`, which exits 0 for `list-keychains` and 51
        // for every lookup: the store was reported healthy while every name
        // under it failed.
        //
        // `errSecItemNotFound` is the SUCCESS case here. It is what a keychain
        // says when the search reached the item database and the item is
        // genuinely absent, so it proves the whole read path — the binary, the
        // default keychain list, and the search itself — with no item touched,
        // no value read and no access prompt, because an item that does not
        // exist has no ACL to consult.
        //
        // No `-w` and no `-g`. Without them `security` prints ATTRIBUTES and
        // never a password, so there is no path by which this check can hold a
        // value; `stdout` is therefore never read here, on any branch.
        let mut command = Command::new(&self.binary);
        command
            .arg("find-generic-password")
            .arg("-s")
            .arg(&self.default_service)
            .arg(HEALTH_ACCOUNT);
        if let Some(keychain) = &self.keychain {
            command.arg(keychain);
        }
        let output = capture(command, self.timeout)
            .map_err(|error| unavailable(self.id(), &self.binary, &error))?;

        match output.status.code() {
            // The item is absent: the read path answered. Proven.
            Some(EXIT_ITEM_NOT_FOUND) => Ok(()),
            // Someone really has an item at the probe's coordinates. Still a
            // proof of the read path, and still no value read — this branch
            // does not look at stdout either.
            Some(0) => Ok(()),
            // Reached and refused: a locked keychain, a denied ACL, a keychain
            // that cannot be opened. `Backend`, so `doctor` paints it red and
            // sends the reader to the keychain rather than to an install.
            _ => Err(self.backend(first_line(&output.stderr))),
        }
    }
}

/// The account the health probe searches for, and deliberately never creates.
///
/// A sentinel rather than a real item, because the check must not WRITE. The
/// name is improbable enough that a collision is a curiosity rather than a bug —
/// and a collision is harmless anyway, since the probe reads no value either
/// way.
const HEALTH_ACCOUNT: &str = "keyless-health-probe-never-created";

impl KeychainStore {
    /// Refuse to spawn `security` when this HOME has no keychain to search.
    ///
    /// 🚨 **This is not politeness, it is the guard against a GUI dialog.** With
    /// `HOME` pointed at a directory holding no keychain, macOS cannot resolve a
    /// default keychain and the Security framework puts a MODAL window on the
    /// user's screen — one whose buttons include **Reset To Defaults**. That is
    /// what a cold start produces, from a command nobody thought could do
    /// anything but print.
    ///
    /// A `stat` cannot open a window. So the check is a filesystem test that
    /// runs BEFORE any process exists, and the report degrades to "not set up"
    /// with a sentence naming HOME — which is the true answer in that state
    /// anyway.
    ///
    /// It applies only to the stock `/usr/bin/security`. A config that points
    /// `binary` somewhere else is a stub or an unusual install, and its owner —
    /// not this guard — decides what reaching it means.
    fn default_keychain_is_reachable(&self) -> Result<(), StoreError> {
        if self.binary.as_path() != std::path::Path::new(STOCK_SECURITY) {
            return Ok(());
        }
        let Some(home) = crate::paths::home() else {
            return Err(self.unavailable(
                "HOME is not set, so there is no login keychain to search. \
                 The keychain backend needs a real home directory",
            ));
        };
        let keychains = home.join("Library").join("Keychains");
        if keychains.is_dir() {
            return Ok(());
        }
        Err(self.unavailable(format!(
            "{} does not exist, so this HOME has no login keychain. \
             `keyless` will not run `security` against it, because macOS answers \
             a missing default keychain with a modal dialog rather than an error",
            keychains.display()
        )))
    }
}

/// The stock macOS `security`, and the only binary the HOME guard applies to.
const STOCK_SECURITY: &str = "/usr/bin/security";

/// Writes generic passwords into the keychain, on stdin.
///
/// # The value is never an argument, and this is why that took work
///
/// `security add-generic-password -w <VALUE>` exists and is not used: an argument
/// is readable from the process table for as long as the child lives, which is
/// the CLI-flag shape this tool exists to remove.
///
/// Measured 2026-08-08 on macOS 15: `-w` with **no** argument prompts
/// `password data for new item:` and then `retype password for new item:`, and it
/// reads both from **stdin** when stdin is a pipe. So the value is written twice
/// and never appears in an argument list. A single line makes the retype read end
/// of input, the two disagree, and — this is the part worth knowing —
/// `security` then prompts again, accepts two empty answers and **exits 0 having
/// stored an empty value**. A write that reports success and stores nothing is
/// exactly the failure this adapter has to not have, which is why the payload is
/// `value \n value \n` and why an embedded newline is refused below rather than
/// silently splitting the value in half.
///
/// # Reader and manager are the same identity here, and that is stated not hidden
///
/// Proton Pass has two tokens; the login keychain has one owner. Every process
/// running as this uid can already read and write it with `security`, so there is
/// no second identity to act as and nothing this type could enforce. It is
/// therefore not gated behind a `manager` block: a gate that protects nothing
/// teaches a reader that the other one protects nothing either.
pub struct KeychainManager {
    binary: PathBuf,
    default_service: String,
    keychain: Option<PathBuf>,
    timeout: std::time::Duration,
}

impl KeychainManager {
    /// Build from a parsed config.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        KeychainManager {
            binary: config.stores.keychain.binary.to_path_buf(),
            default_service: config.stores.keychain.service.clone(),
            keychain: None,
            timeout: std::time::Duration::from_secs(30),
        }
    }

    /// Write into one specific keychain file rather than the default.
    #[must_use]
    pub fn in_keychain(mut self, keychain: Option<PathBuf>) -> Self {
        self.keychain = keychain;
        self
    }

    /// Build the `add-generic-password` invocation.
    ///
    /// `-U` updates an existing item rather than failing, which is what makes this
    /// backend able to rotate a value where Proton's `item create` cannot. `-w`
    /// carries **no argument**; see the type documentation.
    fn add_command(&self, service: &str, account: &str) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .arg("add-generic-password")
            .arg("-s")
            .arg(service)
            .arg("-a")
            .arg(account)
            // Update in place instead of refusing, so this verb can rotate.
            .arg("-U")
            // No value: `security` asks for it twice on stdin.
            .arg("-w");
        if let Some(keychain) = &self.keychain {
            command.arg(keychain);
        }
        command
    }
}

impl Manage for KeychainManager {
    fn id(&self) -> &str {
        "keychain"
    }

    /// Named as it is because it is the truth: there is one keychain identity and
    /// every session already has it.
    fn identity(&self) -> String {
        "keychain (this user, no separate manager exists)".to_owned()
    }

    fn store(
        &self,
        name: &str,
        route: &SecretRoute,
        value: &Secret,
    ) -> Result<Stored, ManageError> {
        let service = route
            .service
            .clone()
            .unwrap_or_else(|| self.default_service.clone());
        let account = route.account.clone().unwrap_or_else(|| name.to_owned());

        if value.is_empty() {
            return Err(ManageError::Value {
                store: self.id().to_owned(),
                detail: "the value is empty, and the resolver treats an empty keychain item as a \
                         misconfiguration rather than a credential"
                    .to_owned(),
            });
        }

        // Refused rather than mangled. `security` reads the value as one line and
        // asks for it twice, so a value containing a newline would be stored as
        // its first line — a credential silently cut in half, which fails later
        // and somewhere else.
        if value.expose().contains('\n') || value.expose().contains('\r') {
            return Err(ManageError::Value {
                store: self.id().to_owned(),
                detail: "it contains a line break, and `security` reads a password as a single \
                         line; storing it would keep only the first line. Put a multi-line \
                         credential in a store that takes it whole"
                    .to_owned(),
            });
        }

        // Twice, because `security` asks twice and a mismatch stores nothing while
        // still exiting 0. See the type documentation.
        let mut payload = Vec::with_capacity(value.len() * 2 + 2);
        payload.extend_from_slice(value.expose().as_bytes());
        payload.push(b'\n');
        payload.extend_from_slice(value.expose().as_bytes());
        payload.push(b'\n');

        let captured =
            capture_with_input(self.add_command(&service, &account), self.timeout, &payload);
        payload.zeroize();
        let captured = captured.map_err(|error| ManageError::Unavailable {
            store: self.id().to_owned(),
            detail: format!("{} {error}", self.binary.display()),
        })?;

        if !captured.status.success() {
            return Err(ManageError::Backend {
                store: self.id().to_owned(),
                detail: first_line(&captured.stderr),
            });
        }

        // `security` exits 0 for a mismatch that stored nothing, so the one thing
        // that proves the write landed is its own prompt count — and it does not
        // report one. What it does report on a mismatch is `passwords don't
        // match`, on stderr, before asking again. Refusing on that is the only
        // signal available.
        let complaint = String::from_utf8_lossy(&captured.stderr).to_ascii_lowercase();
        if complaint.contains("don't match") || complaint.contains("do not match") {
            return Err(ManageError::Backend {
                store: self.id().to_owned(),
                detail: "`security` read the two confirmations as different, so the item may hold \
                         an empty value; check it and write it again"
                    .to_owned(),
            });
        }

        Ok(Stored {
            location: format!("keychain {service}/{account}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{KeychainManager, KeychainStore};
    use crate::config::{Config, SecretRoute};
    use crate::secret::Secret;
    use crate::store::Store;
    use crate::store::manage::Manage;
    use std::path::PathBuf;

    #[test]
    fn an_undeclared_name_uses_itself_as_the_account() {
        let store = KeychainStore::new(PathBuf::from("/usr/bin/security"), "keyless".to_owned());
        assert_eq!(
            store.coordinates("GITHUB_TOKEN"),
            ("keyless".to_owned(), "GITHUB_TOKEN".to_owned())
        );
    }

    #[test]
    fn config_overrides_service_and_account() {
        let config: Config = serde_json::from_str(
            r#"{"stores":{"keychain":{"service":"base"}},
                "secrets":{"A":{"account":"acct"},"B":{"service":"other"}}}"#,
        )
        .expect("valid config");
        let store = KeychainStore::from_config(&config);
        assert_eq!(
            store.coordinates("A"),
            ("base".to_owned(), "acct".to_owned())
        );
        assert_eq!(store.coordinates("B"), ("other".to_owned(), "B".to_owned()));
    }

    #[test]
    fn a_missing_binary_is_unavailable_not_a_panic() {
        let store = KeychainStore::new(
            PathBuf::from("/nonexistent/keyless-test/security"),
            "keyless".to_owned(),
        );
        let error = store
            .resolve("ANY")
            .expect_err("a missing binary must error");
        assert!(error.to_string().contains("unavailable"));
        assert!(store.health().is_err());
    }

    // -----------------------------------------------------------------------
    // Writing. The value goes on stdin, twice, and never into an argument.
    // -----------------------------------------------------------------------

    fn manager_from(json: &str) -> KeychainManager {
        let config: Config = serde_json::from_str(json).expect("valid config");
        KeychainManager::from_config(&config)
    }

    fn route(json: &str) -> SecretRoute {
        serde_json::from_str(json).expect("valid route")
    }

    /// A `security` stand-in that records its argv and its stdin.
    fn stub_security(dir: &std::path::Path, exit: i32, complaint: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).expect("mkdir");
        let stub = dir.join("security-record");
        // The complaint goes through a file rather than into the script body:
        // `security`'s real wording is `passwords don't match`, and an apostrophe
        // inside a single-quoted shell string is a syntax error. Inlining it made
        // this stub fail to parse, and the adapter then reported the shell's error
        // instead of the vendor's — a fixture bug that reads as a real refusal.
        let complaint_file = dir.join("complaint");
        std::fs::write(&complaint_file, complaint).expect("write the complaint");
        let body = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" > '{argv}'\n\
             cat > '{stdin}'\n\
             cat '{complaint}' >&2\n\
             exit {exit}\n",
            argv = dir.join("argv").display(),
            stdin = dir.join("stdin").display(),
            complaint = complaint_file.display(),
        );
        std::fs::write(&stub, body).expect("write stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        stub
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-kcw-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn the_value_reaches_stdin_twice_and_never_an_argument() {
        // Both halves matter. `security` asks for the password and then asks
        // again; a single line makes it read end of input for the second, the two
        // disagree, and it exits 0 having stored an empty value.
        let dir = scratch("stdin");
        let stub = stub_security(&dir, 0, "");
        let manager = manager_from(&format!(
            r#"{{"stores":{{"keychain":{{"service":"svc","binary":"{}"}}}}}}"#,
            stub.display()
        ));

        let value = "decoy-keychain-write-3131";
        let stored = manager
            .store("DECOY", &route("{}"), &Secret::new(value.to_owned()))
            .expect("the stub must accept the write");
        assert_eq!(stored.location, "keychain svc/DECOY");

        let seen = std::fs::read_to_string(dir.join("stdin")).expect("the stub read stdin");
        assert_eq!(
            seen,
            format!("{value}\n{value}\n"),
            "the value must arrive twice, because `security` asks twice"
        );

        let argv = std::fs::read_to_string(dir.join("argv")).expect("the stub recorded its argv");
        assert!(
            !argv.contains(value),
            "the value reached the command line: {argv}"
        );
        assert!(argv.lines().any(|arg| arg == "-w"), "{argv}");
        assert!(
            argv.lines().any(|arg| arg == "-U"),
            "without -U a second write fails instead of rotating: {argv}"
        );
        // `-w` must be the LAST argument: `security` reads its value from the next
        // one, so anything after it would be taken as the password.
        assert_eq!(argv.lines().last(), Some("-w"), "{argv}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_identity_says_there_is_no_separate_manager_here() {
        // Honest rather than symmetrical. The login keychain has one owner and
        // every session already has it, so claiming a manager identity would be a
        // claim about a boundary that does not exist.
        let identity = manager_from("{}").identity();
        assert!(identity.contains("no separate manager"), "{identity}");
        assert!(!identity.contains("(manager)"), "{identity}");
    }

    #[test]
    fn a_value_with_a_line_break_is_refused_rather_than_cut_in_half() {
        // `security` reads one line, so storing this would keep only the first —
        // a credential silently truncated, which fails later and somewhere else.
        let dir = scratch("newline");
        let stub = stub_security(&dir, 0, "");
        let manager = manager_from(&format!(
            r#"{{"stores":{{"keychain":{{"binary":"{}"}}}}}}"#,
            stub.display()
        ));
        for awkward in ["first\nsecond", "trailing\r"] {
            let error = manager
                .store("DECOY", &route("{}"), &Secret::new(awkward.to_owned()))
                .map(|_| String::new())
                .unwrap_or_else(|error| error.to_string());
            assert!(error.contains("line break"), "{error}");
        }
        assert!(
            !dir.join("stdin").exists(),
            "the refusal still spawned `security`"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_value_is_refused_before_anything_is_spawned() {
        let dir = scratch("empty");
        let stub = stub_security(&dir, 0, "");
        let manager = manager_from(&format!(
            r#"{{"stores":{{"keychain":{{"binary":"{}"}}}}}}"#,
            stub.display()
        ));
        let error = manager
            .store("DECOY", &route("{}"), &Secret::new(String::new()))
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("empty"), "{error}");
        assert!(!dir.join("stdin").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_confirmation_mismatch_is_refused_even_though_security_exits_zero() {
        // Measured 2026-08-08: fed one line, `security` complains, re-prompts,
        // accepts two empty answers and exits 0 with an EMPTY item stored. Exit
        // status alone is therefore not evidence that anything was written.
        let dir = scratch("mismatch");
        // The vendor's exact wording, apostrophe included.
        let stub = stub_security(&dir, 0, "passwords don't match");
        assert!(dir.join("complaint").exists());
        let manager = manager_from(&format!(
            r#"{{"stores":{{"keychain":{{"binary":"{}"}}}}}}"#,
            stub.display()
        ));
        let error = manager
            .store(
                "DECOY",
                &route("{}"),
                &Secret::new("decoy-value-77".to_owned()),
            )
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("different"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_route_overrides_the_service_and_the_account_on_a_write_too() {
        let dir = scratch("routed");
        let stub = stub_security(&dir, 0, "");
        let manager = manager_from(&format!(
            r#"{{"stores":{{"keychain":{{"service":"base","binary":"{}"}}}}}}"#,
            stub.display()
        ));
        let stored = manager
            .store(
                "DECOY",
                &route(r#"{"service":"other","account":"acct"}"#),
                &Secret::new("decoy-value-88".to_owned()),
            )
            .expect("write");
        assert_eq!(stored.location, "keychain other/acct");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_backend_failure_is_reported_from_stderr_only() {
        let dir = scratch("failure");
        let stub = stub_security(&dir, 51, "security: User interaction is not allowed.");
        let manager = manager_from(&format!(
            r#"{{"stores":{{"keychain":{{"binary":"{}"}}}}}}"#,
            stub.display()
        ));
        let error = manager
            .store(
                "DECOY",
                &route("{}"),
                &Secret::new("decoy-value-99".to_owned()),
            )
            .map(|_| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(error.contains("User interaction"), "{error}");
        assert!(
            !error.contains("decoy-value-99"),
            "the error carried the value: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_named_keychain_reaches_the_security_command_line() {
        // A daemon has no login keychain, so the file has to be named or every
        // lookup finds nothing and looks exactly like an absent item. The stub
        // echoes its final argument, so what comes back proves what was passed.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("keyless-kc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let stub = dir.join("security-echo-last");
        std::fs::write(
            &stub,
            "#!/bin/sh\nfor a in \"$@\"; do last=\"$a\"; done\nprintf '%s\\n' \"$last\"\n",
        )
        .expect("write stub");
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let store = KeychainStore::new(stub, "svc".to_owned())
            .in_keychain(Some(PathBuf::from("/daemon/owned.keychain-db")));
        let secret = store.resolve("ANY").expect("resolve").expect("a value");
        assert_eq!(secret.expose(), "/daemon/owned.keychain-db");

        // The negative control: with no keychain named, the last argument is
        // `-w`, so the assertion above is about the keychain and not about the
        // stub echoing something either way.
        let plain = KeychainStore::new(dir.join("security-echo-last"), "svc".to_owned());
        assert_eq!(
            plain
                .resolve("ANY")
                .expect("resolve")
                .expect("a value")
                .expose(),
            "-w"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
