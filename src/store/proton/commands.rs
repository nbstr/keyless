use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::secret::Secret;

use super::environment::remove_ambient_references;
use super::listing::ItemRecord;
use super::store::ProtonStore;

/// The variable the probe reads out of the child environment.
///
/// Fixed rather than derived from the secret's name: the name is `keyless`'s,
/// while this is an implementation detail of one probe that lives for one
/// process. Fixing it also keeps a name with awkward characters from having to
/// be a valid environment variable on the way through.
pub(super) const PROBE_VAR: &str = "KEYLESS_PROBE";

/// Distinguishes concurrent probes within one process.
static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Attach `--flag=value` as ONE argument, because a value may begin with `-`.
///
/// # The failure this exists to stop
///
/// `pass-cli` parses with clap, and clap reads any standalone argument starting
/// with a single `-` as a short-flag cluster — whatever option preceded it.
/// Measured against `pass-cli` 2.2.5 on 2026-08-08:
///
/// ```text
/// $ pass-cli item list --vault-name -dashvault --output json
/// error: unexpected argument '-d' found
///   tip: to pass '-d' as a value, use '-- -d'
/// exit 2
/// ```
///
/// That is not a corner case here. Proton item and share ids are **base64url**,
/// whose alphabet includes `-`, so roughly one id in 64 begins with one. This
/// was found on a real item, not reasoned about: an id beginning `-` meant
/// `keyless fields` could not inspect that item at all.
///
/// # Why the `=` form and not the alternatives
///
/// - **A `--` separator** ends option parsing, so it protects a POSITIONAL. Every
///   coordinate here is an option VALUE, which is on the wrong side of that
///   separator. It fixes nothing.
/// - **The vendor's by-name flags** (`--item-title`, `--vault-name`) address by
///   title, which is exactly what this adapter refuses to do: the ids come from a
///   listing it just read, so `fields` and `run` see the same item even when two
///   share a title.
/// - **Shell quoting** does not enter into it — [`Command`] passes an argument
///   vector to `execvp` and no shell is involved. The receiving parser is what
///   rejects the value, so the fix has to be in the argument it receives.
///
/// `--flag=value` is accepted by clap for every long option, verified against the
/// same binary and the same value that fails above. It carries no ambiguity: clap
/// splits on the FIRST `=`, so a value containing one arrives whole.
///
/// This is the only way this adapter and [`crate::store::proton_manager`] pass a
/// value that a vault, an item, a share or a path decides. There is deliberately
/// no second idiom.
pub(crate) fn flag_value(command: &mut Command, flag: &str, value: impl AsRef<std::ffi::OsStr>) {
    let mut joined = std::ffi::OsString::from(flag);
    joined.push("=");
    joined.push(value);
    command.arg(joined);
}

/// Deletes the env file it names, on every exit path including a panic.
pub(super) struct TempEnvFile {
    pub(super) path: PathBuf,
}

impl TempEnvFile {
    /// Write `KEYLESS_PROBE=<reference>` to a fresh 0600 file.
    ///
    /// The contents are a reference — vault, item and field names — never a
    /// value. It is still written 0600, because those names describe where a
    /// credential lives and a directory shared with every other process on the
    /// machine is no place to publish that.
    pub(super) fn create(directory: &Path, reference: &str) -> io::Result<Self> {
        let unique = format!(
            "{}-probe-{}-{}.env",
            crate::NAME,
            std::process::id(),
            PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let path = directory.join(unique);
        let body = format!("{PROBE_VAR}={reference}\n");

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            // Created with the mode rather than chmod'd after: between a create
            // and a chmod there is a window in which the file is world-readable.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(body.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&path, body)?;
        }

        Ok(TempEnvFile { path })
    }
}

impl Drop for TempEnvFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl ProtonStore {
    /// Build one `pass-cli info` invocation, scoped at `dir` — the
    /// structural probe [`ProtonStore::session_is_at_fault`] uses.
    ///
    /// # Why it carries the login every other builder carries
    ///
    /// `info` asks nothing about an item and needs no account token to do
    /// it — but under [`KeyProvider::Env`] the login also carries
    /// [`ENCRYPTION_KEY_VAR`], which is what lets the vendor OPEN the local
    /// session store at all. A probe built without it would name the `env`
    /// provider with nothing for it to read, fail for that reason on every
    /// call, and latch every vendor verdict into a session fault for as long
    /// as the install ran. The credential is scoped to the child's
    /// environment by [`ProtonStore::scope`] like every other vendor call.
    ///
    /// This is not `crate::daemon::login::info_command` because that takes a
    /// `Coordinates`, which is daemon-side state this type does not hold, and
    /// because the two scopes differ deliberately — the loop's drops
    /// privilege unconditionally and carries no reason, this one drops only
    /// where `run_as` is set and names why it ran.
    pub(super) fn info_probe_command<I>(&self, session_dir: &Path, ambient: I) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("info");
        remove_ambient_references(&mut command, ambient);
        self.scope(
            &mut command,
            session_dir,
            &self.vendor_login().unwrap_or_default(),
            self.reason
                .for_action("checking", "whether the session answers"),
        );
        command
    }

    /// Build one `pass-cli run --env-file … -- printenv KEYLESS_PROBE` invocation.
    ///
    /// `ambient` is the environment the child would otherwise inherit whole.
    /// It is a parameter rather than a call to [`std::env::vars_os`] inside
    /// this function so a test can prove the filtering is **wired in here**,
    /// not merely that the filter works when called directly. That distinction
    /// is not academic: with the filter tested on its own, deleting this call
    /// left the suite green.
    pub(super) fn probe_command<I>(
        &self,
        session_dir: &Path,
        env_file: &Path,
        name: &str,
        login: &[(String, Secret)],
        ambient: I,
    ) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("run");
        // `--flag=value`, like every other value this adapter passes: `TMPDIR`
        // decides this path and nothing here may assume it does not start with
        // `-`. See `flag_value`.
        flag_value(&mut command, "--env-file", env_file);
        // Required: the vendor's masking would otherwise replace the value in
        // the probe's own output, and this adapter would inject the mask token.
        command.arg("--no-masking");
        // Before the two variables below are set, so a caller who exported one
        // of them holding a `pass://` string cannot have it removed again.
        remove_ambient_references(&mut command, ambient);
        // Passed rather than inherited: the ambient session is a different
        // identity with a different set of vaults. See `session_dir`.
        self.scope(&mut command, session_dir, login, self.reason.for_name(name));
        command.arg("--");
        command.arg(&self.probe_binary);
        command.arg(PROBE_VAR);
        command
    }

    /// Build one `pass-cli item list --vault-name … --output json` invocation.
    ///
    /// Deliberately the same shape as [`ProtonStore::probe_command`], including
    /// the ambient filter and the two exported variables:
    ///
    /// - The **session directory** decides which identity enumerates the vault.
    ///   A listing read as the full account would find items the scoped agent
    ///   cannot read, so the failure would move from "no such item" to a
    ///   confusing denial at the value read.
    /// - The **reason** is not required by `item list` — measured 2026-08-08,
    ///   the verb succeeds with the variable unset and with it empty — but the
    ///   read is part of resolving one name and is recorded under the same
    ///   sentence, which is what makes an audit trail answer "which run was
    ///   this?". It carries no argument value, exactly as [`Reason`] describes.
    /// - The **ambient filter** applies for the same reason it does on the
    ///   probe: `pass-cli` resolves `pass://` strings it finds in the
    ///   environment, and an unrelated one costs a read nobody asked for.
    ///
    /// No value can come back from this verb: it prints ids, titles, states and
    /// timestamps. `--show-secrets` is what would print content, it is refused
    /// for agent sessions, and it is not passed here.
    pub(super) fn list_command<I>(
        &self,
        session_dir: &Path,
        vault: &str,
        name: &str,
        login: &[(String, Secret)],
        ambient: I,
    ) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("item");
        command.arg("list");
        // `--vault-name=<vault>` as one argument. Naming the flag is what stops
        // the vault being taken as the wrong positional; joining the value with
        // `=` is what stops a vault whose name starts with `-` being read as a
        // flag. Passing them as two arguments does only the first, and the
        // vendor refuses it — see `flag_value`.
        flag_value(&mut command, "--vault-name", vault);
        command.arg("--output");
        command.arg("json");
        remove_ambient_references(&mut command, ambient);
        self.scope(&mut command, session_dir, login, self.reason.for_name(name));
        command
    }

    /// Build one `pass-cli vault list --output json` invocation.
    ///
    /// Same shape as the other two: the session directory decides which identity
    /// answers, the reason is recorded, and an ambient `pass://` is removed. The
    /// verb prints vault names, ids and counts — no item content of any kind.
    pub(super) fn vault_list_command<I>(
        &self,
        session_dir: &Path,
        login: &[(String, Secret)],
        ambient: I,
    ) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("vault");
        command.arg("list");
        command.arg("--output");
        command.arg("json");
        remove_ambient_references(&mut command, ambient);
        self.scope(
            &mut command,
            session_dir,
            login,
            self.reason.for_action("listing", "vaults"),
        );
        command
    }

    /// Build one `pass-cli item view --output json` invocation.
    ///
    /// # This is the one verb in the whole crate that prints a value
    ///
    /// It is here because it is the only way to learn an item's field NAMES, and
    /// the alternative — guessing them — costs one vault read and one permanent
    /// off-machine audit entry per guess. The value comes back on stdout, is
    /// captured into a buffer that zeroizes on drop, is parsed into
    /// [`ItemView`] which zeroizes on drop, and only field names built from key
    /// positions leave that type. Nothing on this path writes to this process's
    /// stdout, and no error message here is built from stdout.
    ///
    /// Addressed by `--item-id` rather than by title: the id comes from a listing
    /// this adapter just read, so `fields` and `run` are looking at the same item
    /// even if two share a title.
    ///
    /// Both ids are joined to their flags with `=`. Item and share ids are
    /// base64url, so about one in 64 begins with `-`, and passed as a separate
    /// argument the vendor's parser reads it as a short-flag cluster and refuses
    /// the whole command. See [`flag_value`].
    pub(super) fn view_command<I>(
        &self,
        session_dir: &Path,
        item: &ItemRecord,
        login: &[(String, Secret)],
        ambient: I,
    ) -> Command
    where
        I: IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    {
        let mut command = Command::new(&self.binary);
        command.arg("item");
        command.arg("view");
        flag_value(&mut command, "--share-id", &item.share_id);
        flag_value(&mut command, "--item-id", &item.id);
        command.arg("--output");
        command.arg("json");
        remove_ambient_references(&mut command, ambient);
        self.scope(
            &mut command,
            session_dir,
            login,
            self.reason
                .for_action("inspecting the fields of", &item.title),
        );
        command
    }
}
