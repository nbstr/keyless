//! Test fixtures.
//!
//! Every secret value used anywhere in this suite is a decoy invented here.
//! Nothing reads a real `.env`, a real credential file, or a real keychain
//! item: the `security` backend is exercised against a shell stub, which is why
//! [`crate::support::keychain::stub_security`] exists at all.

// Each integration test file is its own crate and uses a different subset.
#![allow(dead_code)]

/// The bound that turns a hang into a red test. Its own file so a unit test in
/// `src/` can `include!` the same source rather than keep a second copy.
mod within;
// Only the suites that drive a child or a terminal need the bound, and each
// integration test file is its own crate — same reason as the `dead_code` allow
// above, which does not cover a re-export.
#[allow(unused_imports)]
pub use within::{PATIENCE, within};

/// A socket path that fits in `sockaddr_un`. Its own file for the same reason
/// as `within` above: the unit tests in `src/` bind sockets too, they cannot
/// see `tests/`, and a second copy of this would be free to drift from this one
/// — which is how three of them ended up depending on `TMPDIR` being short.
mod short_socket;
#[allow(unused_imports)]
pub use short_socket::short_socket_path;

/// Creating a file a case is going to execute. Its own file for the same reason
/// as the two above: `tests/` builds executables in several binaries, and the
/// shape it replaces — write it, then `chmod` it — is the one anybody writes
/// from memory, so a second copy would drift straight back into it.
mod executable;
#[allow(unused_imports)]
pub use executable::{install_executable, install_executable_copy};

/// A real pty for a test that must confirm a prompt at a terminal. Its own
/// file for the same reason as the three above: only the suites that drive a
/// verb asking a person need it.
pub mod terminal;

pub mod always_errors;
pub mod audit_rows;
pub mod backend;
pub mod child_witness;
pub mod client;
pub mod generations;
pub mod infisical;
pub mod keychain;
pub mod onepassword;
pub mod proton;
pub mod proton_session;
pub mod proton_store;

// The daemon is macOS-only (see `src/lib.rs`), so every fixture that binds
// one, or that asks the kernel who this process is, is gated with it. The
// portable fixtures in `client` are NOT gated: they describe a session's side
// of the socket, which is what `daemon_degraded.rs` exercises without a daemon
// anywhere.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub mod daemon;

#[allow(unused_imports)]
pub use backend::Backend;
#[allow(unused_imports)]
pub use child_witness::{
    echoes, run_with, run_with_tty, witness, witness_env, witnessed, witnessed_env,
};
#[allow(unused_imports)]
pub use client::{client_config, example_binary, write_secrets};
#[cfg(any(target_os = "macos", keyless_force_xnu))]
#[allow(unused_imports)]
pub use daemon::{daemon_config, own_identity, policy_allowing_self, start_daemon};
#[allow(unused_imports)]
pub use generations::{current_generation, publish_generation};
#[allow(unused_imports)]
pub use infisical::stub_infisical;
#[allow(unused_imports)]
pub use keychain::{Stub, keychain_stub_config, slow_store_stub, stub_security};
#[allow(unused_imports)]
pub use onepassword::{OnePasswordListing, op_listing_count, stub_op, stub_op_listing};
#[allow(unused_imports)]
pub use proton::{
    Listing, SCOPED_SESSION_DIR, listing_count, stub_pass_cli, stub_pass_cli_dead_session,
    stub_pass_cli_discovery, stub_pass_cli_listing,
};

use std::path::Path;
use std::path::PathBuf;

/// A decoy long enough to survive the minimum-needle filter and distinctive
/// enough that a grep for it in test output means a real leak.
pub const DECOY_VALUE: &str = "decoy-Zx91-nEVEr-a-REAL-secret-0042";

/// A decoy that only the fake Infisical CLI hands out.
///
/// Distinct from [`PROTON_DECOY`] on purpose: "which store answered?" is a
/// question the resolution-policy tests have to be able to ask, and two stores
/// returning the same string would make a wrong answer invisible.
pub const INFISICAL_DECOY: &str = "decoy-Inf7-company-vault-value-0101";

/// A decoy that only the fake Proton Pass CLI hands out.
pub const PROTON_DECOY: &str = "decoy-Pro9-personal-vault-value-0202";

/// A decoy that only the fake 1Password CLI hands out.
pub const ONEPASSWORD_DECOY: &str = "decoy-1Pw3-company-vault-value-0505";

/// What the 1Password CLI's output masking substitutes for a value.
///
/// Measured: the literal is in the `op` 2.39.0 binary.
pub const ONEPASSWORD_CONCEALED: &str = "<concealed by 1Password>";

/// The name of a second secret sitting at the same Infisical path as `DECOY`.
///
/// Nothing ever asks for it. It exists so that "only the names that were asked
/// for reach the child" has something to be FALSE about: against a vault
/// holding one name, a tool that narrows and a tool that does not look
/// identical.
pub const NEIGHBOUR_KEY: &str = "NEIGHBOUR";

/// The value behind [`NEIGHBOUR_KEY`]. Distinct from every other decoy here, so
/// an assertion that names it cannot be satisfied by another store's answer.
pub const NEIGHBOUR_DECOY: &str = "decoy-Nb42-the-name-nobody-asked-for-0303";

/// What the vendor CLIs' output masking substitutes for a value.
pub const CONCEALED: &str = "<concealed by Proton Pass>";

/// A fresh, empty directory for one test.
pub fn scratch(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("keyless-tests-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("cannot create the scratch directory");
    path
}

/// What a stub recorded, one element per line, with the trailing blank dropped.
pub fn recorded_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} was never written ({error})", path.display()))
        .lines()
        .map(str::to_owned)
        .collect()
}

/// What a stub recorded as a single string.
pub fn recorded(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} was never written ({error})", path.display()))
}

fn write_stub(dir: &Path, name: &str, body: &str) -> PathBuf {
    install_executable(&dir.join(name), body)
}
