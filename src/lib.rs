//! `keyless` — use a secret without ever holding one.
//!
//! A session names a credential; it never receives one. The value is read from
//! a store, placed in a child process's environment, and scrubbed from the
//! child's stdout and stderr on the way back out.
//!
//! # The invariant that outranks everything else
//!
//! There is no code path in which `keyless run` exits without spawning the
//! child. Not on a missing store, not on an unknown name, not on a corrupt
//! config, not on a store that errors. It warns on stderr and execs anyway
//! with the environment unchanged. A tool that blocks the work gets removed,
//! and then the plaintext comes back.
//!
//! Two states exist and there is no third:
//!
//! - [`State::Injected`] — every requested name resolved, was injected, and is masked.
//! - [`State::Degraded`] — anything else. The child runs with an unmodified environment.
//!
//! # The verb that does not exist
//!
//! There is no `get`, no `read`, no `export`, no `--reveal`. A single verb that
//! writes a plaintext value to stdout voids the whole design, because a caller
//! takes the shortest path and that verb would always be the shortest path.
//! This is a structural property of the CLI, not a policy toggle.
//!
//! # The privilege boundary
//!
//! Everything above is a wrapper around a store the calling user can read
//! directly, which makes it a good habit and not a gate. [`daemon`] is what
//! makes it a gate: the store lives behind a second uid, sessions ask over a
//! Unix socket, and the socket carries names and results but never the store
//! credential. [`ipc`] is the wire and the kernel facts about who is on it;
//! [`attest`] is the decision.
//!
//! The boundary does not change the rule above it. A daemon that is absent,
//! wedged, refusing or slow is a [`State::Degraded`] like any other store
//! failure, and the child still runs.
//!
//! # The daemon is macOS-only, and that is a compile-time fact
//!
//! Attestation rests on four XNU calls — `csops`, `getpeereid`, `proc_pidinfo`
//! and `proc_pidpath` — so [`daemon`] is compiled on macOS only. Everything a
//! session needs is not: the client, the stores, the masking, the PTY and the
//! never-block invariant are portable, and `store::daemon` still speaks to a
//! socket on any Unix.
//!
//! Nothing is stubbed. There is no non-macOS [`daemon`] that attests weakly —
//! there is no non-macOS [`daemon`] at all, so code that reaches for one fails
//! to compile rather than getting a weaker answer. A session on a platform with
//! no daemon behaves exactly as a session whose daemon is absent already does:
//! it degrades, and the child runs.
//!
//! `keyless_force_xnu` compiles the macOS-only half anywhere, so CI can run the
//! link on Linux and require it to fail on exactly those four names. See
//! `Cargo.toml` and `.github/workflows/ci.yml`.

pub mod attest;
pub mod audit;
pub mod cmd;
pub mod config;
#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub mod daemon;
pub mod error;
pub mod freshness;
pub mod ipc;
pub mod mask;
pub mod paths;
pub mod random;
pub mod secret;
pub mod store;
pub mod time;
pub mod tty;

/// The tool's own name, used for the stderr prefix, the mask token, the
/// environment-variable prefix and the config/state directory names.
///
/// It is a constant so a rename touches this line, the `[package] name`, and
/// nothing else.
pub const NAME: &str = "keyless";

/// The outcome of a `run`, from the caller's point of view.
///
/// Deliberately two-valued. A third state ("partially injected") would mean the
/// child sometimes sees a subset of what was asked for, which is harder to
/// reason about than either all or nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Every requested name resolved. The child's environment carries them and
    /// its output is masked.
    Injected,
    /// At least one requested name did not resolve. The child's environment is
    /// untouched and nothing is masked, because there is nothing to mask.
    Degraded,
}

impl State {
    /// The wire form written to the audit log and printed by the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            State::Injected => "INJECTED",
            State::Degraded => "DEGRADED",
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
