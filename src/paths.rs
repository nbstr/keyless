//! Where the config and the audit log live.
//!
//! Every path is derived from [`crate::NAME`] at runtime rather than written
//! out, so the tool's name appears in exactly one place in the source.

use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

use crate::NAME;

/// The calling user's home directory, or `None` when `HOME` says nothing.
///
/// **The only place in this crate that reads `HOME`.** Two callers want
/// different things when it is absent — [`Paths::discover`] falls back to the
/// working directory so a command still runs, [`ConfigPath`] refuses so a `~`
/// cannot become a literal — and a second reader would eventually disagree with
/// this one about what an EMPTY `HOME` means. It means "unset": an empty string
/// is not a directory, and joining onto it yields a relative path, which is the
/// exact failure this module now exists to prevent.
#[must_use]
pub fn home() -> Option<PathBuf> {
    match env::var_os("HOME") {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
}

/// A filesystem path read from a config file, with `~` already resolved.
///
/// # The defect this type exists to make impossible
///
/// `"session_dir": "~/.keyless-pass-session"` was taken literally, so `pass-cli`
/// created a directory whose NAME is `~` under whatever the working directory
/// happened to be. One config therefore minted a fresh, empty session per
/// directory the user stood in, and `keyless doctor` reported `0 problem(s)`
/// throughout: the path existed, the store answered, nothing was wrong to see.
/// A config that looks configured and silently acts differently in each
/// directory is the worst available shape for this class of bug.
///
/// # Why a type rather than a `deserialize_with`
///
/// `#[serde(deserialize_with = "…")]` has to be spelled on each field, so it
/// protects the fields somebody remembered and no others — and the field added
/// next year is the one nobody remembers. A type carries the behaviour with it,
/// so a new field declared `ConfigPath` inherits expansion with nothing to
/// remember.
///
/// **It is not a proof, and the difference matters.** Nothing stops the next
/// field being declared `PathBuf`; the compiler is perfectly happy with one and
/// says nothing. What closes that is a test that enumerates the path-typed
/// fields of the config from OUTSIDE the config — see
/// `every_config_path_field_expands` in `tests/config_paths.rs`, which walks a
/// config holding `~` in every path field and asserts each one came out
/// absolute. A new `PathBuf` field is invisible to it too, which is why that
/// test asserts the field COUNT it covered as well.
///
/// # What it does, and what it deliberately refuses
///
/// | written | result |
/// |---|---|
/// | `~` | the home directory |
/// | `~/foo` | home, then `foo` |
/// | `/foo` or `foo` or `pass-cli` | unchanged — no `~`, nothing to do |
/// | `~user/foo` | **refused at parse time** |
/// | `$HOME/foo` | **refused at parse time** |
/// | `~/foo` with no `HOME` | **refused at parse time** |
///
/// A refusal is a `serde` error, which [`crate::config::Config::load`] turns
/// into a reported problem plus the default config: every name degrades, `run`
/// prints the reason on stderr before it spawns the child, and `doctor` prints
/// it as `PROBLEM`. That is loud and it still runs the command, which is this
/// crate's rule. The rejected alternative was to keep the literal and warn —
/// that leaves the wrong directory being created, which is the whole defect,
/// merely narrated.
///
/// `~user` is refused rather than resolved because the standard library cannot
/// read the passwd database and shelling out to `getent` from a secrets tool
/// buys a subprocess to save a keystroke. `$HOME` is refused because a config
/// file is not a shell: expanding one variable invites the next, and a config
/// that decides which vault answers a name should not be steerable by the
/// environment it is read in. Both are refused rather than passed through
/// because passing them through is the original bug under a different spelling.
///
/// A path that genuinely begins with those characters is still reachable as
/// `./~odd` or `./$odd`.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ConfigPath(PathBuf);

impl ConfigPath {
    /// The resolved path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Expand `raw`, or say why it cannot be.
    ///
    /// Public so a test can drive the rule directly. It is **not** the thing to
    /// test on its own: the defect was at the parse boundary, so proving this
    /// function correct proves nothing about whether a config field calls it.
    ///
    /// # Errors
    ///
    /// A sentence naming the written path and the fix, for the three refused
    /// forms in the type documentation.
    pub fn expand(raw: &str) -> Result<Self, String> {
        let rest = match raw.as_bytes().first() {
            Some(b'~') => &raw[1..],
            Some(b'$') => {
                return Err(format!(
                    "`{raw}` starts with `$`, and a config file is not a shell — no variable is \
                     expanded here, so this would be taken as a directory literally named \
                     `{}`. Write `~/…` or an absolute path",
                    raw.split('/').next().unwrap_or(raw)
                ));
            }
            // No leading `~`, so there is nothing to resolve. Absolute paths and
            // bare binary names (`pass-cli`, `infisical`) both land here, and
            // both must arrive at the call site byte-for-byte as written.
            _ => return Ok(ConfigPath(PathBuf::from(raw))),
        };

        if !(rest.is_empty() || rest.starts_with('/')) {
            return Err(format!(
                "`{raw}` names another user's home directory, which this build does not resolve: \
                 it would need the passwd database, and a secrets tool should not spawn `getent` \
                 to save a keystroke. Write that user's home directory in full"
            ));
        }

        let Some(home) = home() else {
            return Err(format!(
                "`{raw}` begins with `~` and `HOME` is unset or empty, so there is no home \
                 directory to resolve it against. Taken literally it would create a directory \
                 named `~` under whatever the working directory happens to be — a different one \
                 per directory. Write an absolute path"
            ));
        };

        Ok(ConfigPath(match rest.strip_prefix('/') {
            // `home.join("")` appends a trailing separator, and `join` on an
            // absolute `rest` would DISCARD the home entirely, so the prefix is
            // stripped rather than joined.
            Some(tail) => home.join(tail),
            None => home,
        }))
    }
}

impl<'de> Deserialize<'de> for ConfigPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // A `String` rather than a `PathBuf`: this crate's only config format is
        // JSON, whose strings are UTF-8 by definition, so there is no
        // non-UTF-8 branch here to leave untested.
        let raw = String::deserialize(deserializer)?;
        ConfigPath::expand(&raw).map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for ConfigPath {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for ConfigPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<std::ffi::OsStr> for ConfigPath {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.as_os_str()
    }
}

impl From<PathBuf> for ConfigPath {
    /// For defaults and tests. **Nothing is expanded**: a value that never went
    /// through a config file never contained a `~` to expand.
    fn from(path: PathBuf) -> Self {
        ConfigPath(path)
    }
}

impl From<&str> for ConfigPath {
    fn from(path: &str) -> Self {
        ConfigPath(PathBuf::from(path))
    }
}

impl std::fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.display().fmt(f)
    }
}

/// Resolved filesystem locations for one invocation.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The config file. May not exist; an absent config is a valid config.
    pub config: PathBuf,
    /// The append-only audit log.
    pub audit: PathBuf,
}

impl Paths {
    /// Resolve from the environment, following XDG with a `~/.config` fallback.
    ///
    /// Overrides, highest precedence first:
    /// `KEYLESS_CONFIG` / `KEYLESS_AUDIT` (exact file paths), then
    /// `XDG_CONFIG_HOME` / `XDG_STATE_HOME`, then `$HOME`.
    ///
    /// Never fails. A machine with no `HOME` gets paths under the current
    /// directory, because refusing to resolve a path would mean refusing to
    /// run a command, and that is the one thing this tool must never do.
    #[must_use]
    pub fn discover() -> Self {
        let prefix = NAME.to_uppercase();
        let home = env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);

        let config = env::var_os(format!("{prefix}_CONFIG"))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dir_from_env("XDG_CONFIG_HOME", home.join(".config"))
                    .join(NAME)
                    .join("config.json")
            });

        let audit = env::var_os(format!("{prefix}_AUDIT"))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                dir_from_env("XDG_STATE_HOME", home.join(".local").join("state"))
                    .join(NAME)
                    .join("audit.jsonl")
            });

        Paths { config, audit }
    }

    /// Both files under one directory. Used by tests and by anyone who wants a
    /// self-contained profile.
    #[must_use]
    pub fn under(root: &Path) -> Self {
        Paths {
            config: root.join("config.json"),
            audit: root.join("audit.jsonl"),
        }
    }
}

fn dir_from_env(var: &str, fallback: PathBuf) -> PathBuf {
    match env::var_os(var) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::Paths;
    use std::path::Path;

    #[test]
    fn under_places_both_files_in_one_directory() {
        let paths = Paths::under(Path::new("/tmp/example"));
        assert_eq!(paths.config, Path::new("/tmp/example/config.json"));
        assert_eq!(paths.audit, Path::new("/tmp/example/audit.jsonl"));
    }

    #[test]
    fn discover_never_panics_and_yields_absolute_or_relative_paths() {
        let paths = Paths::discover();
        assert!(paths.config.ends_with("config.json"));
        assert!(paths.audit.ends_with("audit.jsonl"));
    }
}
