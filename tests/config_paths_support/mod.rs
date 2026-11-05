#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::support::backend::Backend;
use crate::support::proton::{Listing, stub_pass_cli_listing};
use crate::support::{PROTON_DECOY, recorded, scratch};

pub const BIN: &str = env!("CARGO_BIN_EXE_keyless");

/// One live item, so the name form resolves without a real vault.
pub const ONE_LIVE_ITEM: &str = r#"{"items":[{"id":"ITEM1","share_id":"SHARE1",
     "state":"Active","title":"Router","item_type":"login"}]}"#;

/// A scratch directory plus the fake home every child is given.
pub struct Fixture {
    pub dir: PathBuf,
    pub home: PathBuf,
    pub binary: PathBuf,
}

impl Fixture {
    pub fn new(tag: &str) -> Self {
        let dir = scratch(tag);
        let home = dir.join("home");
        std::fs::create_dir_all(&home).expect("create the fake home");
        let binary = stub_pass_cli_listing(
            &dir,
            &Backend::Injects(PROTON_DECOY),
            &Listing::Json(ONE_LIVE_ITEM),
        );
        Fixture { dir, home, binary }
    }

    /// Write a config whose Proton session directory is `session_dir`, verbatim.
    pub fn config(&self, session_dir: &str) -> PathBuf {
        let path = self.dir.join("config.json");
        let body = format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "proton":{{"enabled":true,"binary":"{binary}","session_dir":"{session_dir}",
                            "timeout_ms":60000}}}},
               "secrets":{{"HOME_WIFI":{{"vault":"Personal","item":"Router","field":"password"}}}}}}"#,
            binary = self.binary.display()
        );
        std::fs::write(&path, body).expect("write config");
        path
    }

    /// Run the real binary with this fixture's home, or with none at all.
    pub fn keyless(&self, config: &Path, home: Option<&Path>, args: &[&str]) -> Output {
        let mut command = Command::new(BIN);
        command
            .arg("--config")
            .arg(config)
            .arg("--no-audit")
            .args(args);
        match home {
            Some(path) => command.env("HOME", path),
            None => command.env_remove("HOME"),
        };
        command.output().expect("the binary must run")
    }

    /// What `PROTON_PASS_SESSION_DIR` the stub was handed, if it ran at all.
    pub fn session_seen(&self) -> Option<String> {
        let path = self.dir.join("pass-cli.session");
        path.exists().then(|| recorded(&path))
    }
}

pub fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}
