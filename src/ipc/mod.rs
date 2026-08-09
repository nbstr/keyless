//! The socket between a session and the daemon.
//!
//! Four pieces, deliberately separate:
//!
//! - [`ffi`] — every `unsafe` line in the privilege boundary, in one file.
//! - [`peer`] — who is on the other end, cross-checked.
//! - [`protocol`] — what crosses: a name, and a result.
//! - [`client`] — the session's side, with a deadline it cannot overrun.
//!
//! The daemon's side is [`crate::daemon`], and the decision is
//! [`crate::attest`]. Splitting "who is it" from "may they" is not tidiness:
//! the identification is kernel facts and is the same everywhere, while the
//! policy is an operator's choice and changes per install.
//!
//! # The platform line runs through this module
//!
//! [`ffi`] is XNU and nothing else. It is compiled on macOS only, and
//! `keyless_force_xnu` compiles it anywhere so CI can run the link and require
//! it to fail — see the header of `.github/workflows/ci.yml`.
//!
//! [`client`] and [`protocol`] are portable, and so is the half of [`peer`]
//! that is plain data. What is macOS-only is exactly what asks the kernel a
//! question: nothing here degrades to a weaker answer off macOS, it ceases to
//! exist, and a caller that wanted it fails to compile.

pub mod client;
#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub mod ffi;
pub mod peer;
pub mod protocol;

use std::path::PathBuf;

use crate::NAME;

/// Where the socket lives when nothing says otherwise.
///
/// Under `/usr/local/var`, not under `$HOME`: the socket belongs to the daemon
/// user, and a path inside the calling user's home directory is a path the
/// calling user can replace with a socket of their own. Putting a fake daemon
/// where the real one should be is the cheapest attack on this whole design,
/// and a directory the session cannot write is what stops it.
///
/// `KEYLESS_SOCKET` overrides it. **That override is a convenience for tests
/// and for a second daemon, and it is not a boundary** — a caller who can set
/// the environment of a `keyless run` can already point it at a socket of their
/// own. What that buys an attacker is the ability to feed a *wrong* value to a
/// command they were already running; it does not reveal anything the daemon
/// holds.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os(format!("{}_SOCKET", NAME.to_uppercase()))
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }
    PathBuf::from("/usr/local/var/run")
        .join(NAME)
        .join(format!("{NAME}d.sock"))
}

#[cfg(test)]
mod tests {
    use super::default_socket_path;

    #[test]
    fn the_default_socket_is_outside_any_home_directory() {
        // Guarding the property rather than the string: a socket under $HOME
        // could be replaced by the calling user with one of their own.
        // SAFETY-of-test: this reads the environment only.
        let path = default_socket_path();
        if std::env::var_os("KEYLESS_SOCKET").is_none() {
            assert!(path.starts_with("/usr/local/var"), "{}", path.display());
            assert!(path.ends_with("keylessd.sock"));
        }
    }
}
