use std::path::Path;

use super::LISTING;
use crate::support::PROTON_DECOY;
use crate::support::backend::Backend;
use crate::support::proton::{Listing, stub_pass_cli_listing};

/// One directory a vendor child is pointed at, holding nothing yet.
pub fn vendor_scope(dir: &Path, tag: &str) -> std::path::PathBuf {
    let scope = dir.join(tag);
    std::fs::create_dir_all(&scope).expect("create the directory the variable names");
    scope
}

/// What `PROTON_PASS_KEY_PROVIDER` and `PROTON_PASS_ENCRYPTION_KEY` are set to
/// for one invocation — or deliberately not set, which is a third answer the
/// vendor reads differently from either.
pub enum Keying {
    /// `key_provider: fs`, the arrangement that keeps the key in a file.
    Fs,
    /// `key_provider: env` with a key, the arrangement this daemon ships.
    Env(&'static str),
    /// `key_provider: env` with the key variable left off entirely.
    EnvWithoutKey,
    /// `key_provider: env` with the key variable present and EMPTY.
    EnvWithEmptyKey,
    /// Neither variable set at all — what a call site that forgot the scope
    /// hands the vendor.
    Unset,
    /// The provider variable present and empty, which is not the same
    /// omission and, per the vendor, not a different one either.
    Empty,
}

/// Run the store stand-in once, exactly as a child of the daemon would be run.
///
/// The environment is CLEARED rather than inherited, so a variable the
/// developer happens to export cannot decide which arm the stand-in takes —
/// which is the whole subject of several cases below.
pub fn run_vendor(
    vendor: &Path,
    scope: &Path,
    keying: &Keying,
    args: &[&str],
) -> std::process::Output {
    let mut command = std::process::Command::new(vendor);
    command.args(args);
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    command.env("PROTON_PASS_SESSION_DIR", scope);
    match keying {
        Keying::Fs => {
            command.env("PROTON_PASS_KEY_PROVIDER", "fs");
        }
        Keying::Env(key) => {
            command.env("PROTON_PASS_KEY_PROVIDER", "env");
            command.env("PROTON_PASS_ENCRYPTION_KEY", key);
        }
        Keying::EnvWithoutKey => {
            command.env("PROTON_PASS_KEY_PROVIDER", "env");
        }
        Keying::EnvWithEmptyKey => {
            command.env("PROTON_PASS_KEY_PROVIDER", "env");
            command.env("PROTON_PASS_ENCRYPTION_KEY", "");
        }
        Keying::Unset => {}
        Keying::Empty => {
            command.env("PROTON_PASS_KEY_PROVIDER", "");
        }
    }
    command
        .output()
        .unwrap_or_else(|error| panic!("cannot run the vendor stand-in: {error}"))
}

pub fn said(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn store_stub(
    dir: &Path,
    behaviour: &crate::support::proton_session::VendorStore,
) -> std::path::PathBuf {
    let inner = stub_pass_cli_listing(
        dir,
        &Backend::Injects(PROTON_DECOY),
        &Listing::Json(LISTING),
    );
    crate::support::proton_store::stub_pass_cli_store(dir, &inner, behaviour)
}
