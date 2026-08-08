//! Where the config and the audit log live.
//!
//! Every path is derived from [`crate::NAME`] at runtime rather than written
//! out, so the tool's name appears in exactly one place in the source.

use std::env;
use std::path::{Path, PathBuf};

use crate::NAME;

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
