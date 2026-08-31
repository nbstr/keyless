//! Deciding whether a peer may ask for a value.
//!
//! # What is being decided
//!
//! Not "is this user allowed" — the socket's own permissions settle that, and
//! the kernel enforces them before this code runs. What is decided here is
//! **which program** on the other end. That is a narrower claim than it sounds,
//! and the narrowness is the honest part of this module.
//!
//! # The interpreter problem, stated rather than dodged
//!
//! The kernel can tell you the code identity of a process's *loaded image*.
//! When that image is `node`, `python3` or `/bin/sh`, the identity you get is
//! the interpreter's — identical for every program that interpreter will ever
//! run. Allowlisting `node` allowlists every Node program on the machine,
//! including whatever `npx` fetched five minutes ago.
//!
//! There is no way around this. The script's path is not a code identity: it is
//! read from the interpreter's own argv, which the process may rewrite, and
//! hashing it means hashing a file at a path — the exact race this design
//! exists to avoid.
//!
//! So `keyless` **refuses interpreted callers outright**, and the refusal costs
//! nothing, because of how the pieces fit together:
//!
//! - An AI agent — Claude Code among them — is a Node program. It is never the
//!   peer on this socket.
//! - The peer is always `keyless run`, a compiled binary with one code identity.
//! - The agent asks for a secret by *running* `keyless run`, which is the only
//!   supported path and the one the whole tool is built around.
//!
//! A Node process that connects to the socket directly is therefore not a user
//! being inconvenienced; it is something that should not be there. It is
//! refused by name, with a message saying to go through `keyless run`, rather
//! than being silently attested as "the node binary" and trusted.
//!
//! The check is belt and braces: it runs **before** the allowlist, so an
//! interpreter cannot be authorised even by an operator who pins its hash by
//! mistake. And `keylessd pin` refuses to emit a pin for one in the first
//! place.
//!
//! # Fail closed
//!
//! An empty allowlist authorises nothing. A peer whose identity cannot be
//! established authorises nothing. There is no "could not check, so allow"
//! branch anywhere in this module — and there must not be one, because the
//! caller's response to a refusal is to degrade, which is safe, while the
//! response to a wrong allow is to hand over a credential, which is not.

//! # Where the platform line falls, and why it is ONE line
//!
//! Everything in this file decides, and all of it is portable: [`Policy`],
//! [`Denial`], [`Attestation`] and [`Policy::judge`] are pure functions of a
//! [`PeerIdentity`]. There is no `#[cfg]` anywhere among them, on purpose —
//! conditional compilation inside the code that grants access is how a second,
//! unexercised state gets built by accident.
//!
//! Exactly one thing is platform-bound: taking a socket and asking the kernel
//! who is on it. That lives in [`live`], a module compiled on macOS only, and
//! it is the ONLY constructor of an [`Attestation`] anywhere in the crate.
//!
//! # Why a module and not a trait
//!
//! A trait would be the reflex, and it would be worse. A trait is an invitation
//! to write a second implementation, and the second implementation of "who is
//! on this socket?" on a platform that cannot answer is a stub that returns
//! *something* — which is precisely the hole that must not exist. There is one
//! implementation because there is one honest answer, and a module says that
//! where a trait would quietly solicit the opposite.
//!
//! # The stub is not discouraged, it is impossible
//!
//! [`Attestation`]'s fields are private and no constructor is exported. Off
//! macOS the only constructor is not compiled, so no code — in this crate, in a
//! test, or downstream — can produce a value that reports `is_allowed()`. A
//! Linux "attested" is not a shortcut somebody is asked not to take; there is
//! no expression that evaluates to one.

use std::collections::BTreeSet;
use std::fmt;

use crate::ipc::peer::{CDHASH_LEN, PeerError, PeerIdentity};

/// Programs whose code identity is the identity of an interpreter rather than
/// of the thing being run.
///
/// Matched on the loaded image's file name. A version suffix counts, so
/// `python3.12` and `ruby2.7` are caught alongside `python` and `ruby`.
///
/// This list is a **diagnostic**, not the gate. The gate is the allowlist: an
/// interpreter that is not pinned is refused by the allowlist regardless of
/// whether its name appears here. What the list adds is that an interpreter
/// which *is* pinned — by an operator who did not realise what pinning `node`
/// means — is still refused, and refused with a message that explains why.
const INTERPRETERS: &[&str] = &[
    "awk",
    "bash",
    "bun",
    "csh",
    "dash",
    "deno",
    "elixir",
    "erl",
    "expect",
    "fish",
    "gawk",
    "ksh",
    "lua",
    "mawk",
    "node",
    "nu",
    "osascript",
    "perl",
    "php",
    "pwsh",
    "python",
    "rscript",
    "ruby",
    "sh",
    "tclsh",
    "tcsh",
    "wish",
    "zsh",
];

/// Whether an image name is an interpreter.
///
/// Case-insensitive, because `Rscript` and `rscript` are the same program, and
/// a case-sensitive check would be a bypass consisting of one keystroke.
#[must_use]
pub fn is_interpreter(image_name: &str) -> bool {
    let name = image_name.to_ascii_lowercase();
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.contains(&stem) || INTERPRETERS.contains(&name.as_str())
}

/// Who may ask.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    uids: BTreeSet<u32>,
    images: BTreeSet<[u8; CDHASH_LEN]>,
    refuse_interpreters: bool,
}

impl Policy {
    /// An empty policy, which authorises nothing.
    #[must_use]
    pub fn new() -> Self {
        Policy {
            uids: BTreeSet::new(),
            images: BTreeSet::new(),
            // Default-on. A `Default::default()` that turned this off would
            // make the safe configuration the one you have to remember.
            refuse_interpreters: true,
        }
    }

    /// Authorise a uid.
    #[must_use]
    pub fn allow_uid(mut self, uid: u32) -> Self {
        self.uids.insert(uid);
        self
    }

    /// Authorise one code identity.
    #[must_use]
    pub fn allow_image(mut self, code_hash: [u8; CDHASH_LEN]) -> Self {
        self.images.insert(code_hash);
        self
    }

    /// Turn the interpreter refusal off.
    ///
    /// Exists so the refusal has a negative control in the test suite — a rule
    /// that cannot be turned off cannot be shown to be doing anything. Not
    /// reachable from the daemon's config: see `daemon::config`.
    #[must_use]
    pub fn permitting_interpreters(mut self) -> Self {
        self.refuse_interpreters = false;
        self
    }

    /// Whether any image is authorised at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.images.is_empty() || self.uids.is_empty()
    }

    /// How many images are pinned.
    #[must_use]
    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Whether this code identity is one of the pinned images.
    ///
    /// A narrower question than [`Policy::judge`], and deliberately so: that
    /// one decides about a live peer, which has a uid and may be an
    /// interpreter. This one is asked about a FILE — by
    /// [`crate::daemon::shadow`], which wants to know whether a binary sitting
    /// on `PATH` is the image this daemon accepts. A file has no uid to judge
    /// and is not running, so applying the rest of the policy to it would
    /// answer a question nobody asked.
    ///
    /// It reads the same set `judge` reads, so the two cannot drift.
    #[must_use]
    pub fn pins_image(&self, code_hash: &[u8; CDHASH_LEN]) -> bool {
        self.images.contains(code_hash)
    }

    /// Apply the policy to an identified peer.
    #[must_use]
    pub fn judge(&self, peer: &PeerIdentity) -> Option<Denial> {
        if !self.uids.contains(&peer.uid) {
            return Some(Denial::Uid(peer.uid));
        }
        if self.refuse_interpreters && is_interpreter(peer.image_name()) {
            return Some(Denial::Interpreter {
                image: peer.image_name().to_owned(),
            });
        }
        if self.images.is_empty() {
            return Some(Denial::NothingPinned);
        }
        if !self.images.contains(&peer.code_hash) {
            return Some(Denial::UnknownImage {
                code_hash: peer.code_hash_hex(),
                // The PATH, not the file name. A second copy of this program
                // earlier on the caller's PATH is refused exactly here, and a
                // message naming only `keyless` describes the program the
                // operator believes they installed — so it reads as a broken
                // pin and sends somebody to re-pin a file that was already
                // pinned correctly. The path is the peer's own, already known
                // to the peer, and the audit row carries `kind()` rather than
                // this sentence, so naming it discloses nothing.
                image: peer.image.display().to_string(),
            });
        }
        None
    }
}

/// Why a peer was refused.
#[derive(Debug)]
pub enum Denial {
    /// The peer could not be identified at all.
    Unidentified(PeerError),
    /// The peer's uid is not authorised.
    Uid(u32),
    /// The peer is an interpreter, so its code identity is not its own.
    Interpreter {
        /// The interpreter's file name, for the message.
        image: String,
    },
    /// No image is pinned, so nothing can be authorised.
    NothingPinned,
    /// The peer is a program this daemon does not know.
    UnknownImage {
        /// The peer's code hash, in hex.
        code_hash: String,
        /// The path of the peer's loaded image.
        image: String,
    },
}

impl Denial {
    /// A short, fixed reason word for the audit log and the wire.
    ///
    /// Fixed vocabulary on purpose: an operator greps the audit log for
    /// `unknown-image`, and a free-text reason makes that impossible.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Denial::Unidentified(error) => error.kind(),
            Denial::Uid(_) => "uid-not-allowed",
            Denial::Interpreter { .. } => "interpreted-caller",
            Denial::NothingPinned => "no-image-pinned",
            Denial::UnknownImage { .. } => "unknown-image",
        }
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denial::Unidentified(error) => write!(f, "{error}"),
            Denial::Uid(uid) => write!(f, "uid {uid} is not authorised to use this daemon"),
            Denial::Interpreter { image } => write!(
                f,
                "`{image}` is an interpreter, so its code identity belongs to the interpreter \
                 rather than to the program it is running; run `keyless run` instead of \
                 connecting to the socket directly"
            ),
            Denial::NothingPinned => f.write_str(
                "no client image is pinned, so this daemon can authorise nothing; \
                 run `keylessd pin` and add the hash to the daemon's config",
            ),
            Denial::UnknownImage { code_hash, image } => write!(
                f,
                "{image} is not a pinned client (code hash {code_hash}); if that is not \
                 the path this daemon's client was installed at, a second copy of it is \
                 what your shell reaches"
            ),
        }
    }
}

/// The result of attesting one request.
///
/// Both halves are kept, including on a refusal, because the audit row for a
/// denial is worth more than the row for a success and it needs the identity
/// that was refused.
/// # Private fields, deliberately
///
/// A caller cannot build one. That is the whole mechanism behind "there is no
/// Linux stub": the sole constructor is [`live::attest`], which is compiled on
/// macOS only, so off macOS the type is inhabited by nothing at all. Public
/// fields would have made an allowed attestation a struct literal away on every
/// platform, which is a hole no `#[cfg]` can close.
#[derive(Debug)]
pub struct Attestation {
    peer: Option<PeerIdentity>,
    denial: Option<Denial>,
}

impl Attestation {
    /// Whether the request may proceed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.denial.is_none()
    }

    /// The peer, when it could be identified at all.
    ///
    /// Kept on a refusal too: the audit row for a denial is worth more than the
    /// row for a success, and it needs the identity that was refused.
    #[must_use]
    pub const fn peer(&self) -> Option<&PeerIdentity> {
        self.peer.as_ref()
    }

    /// The refusal, when there was one.
    #[must_use]
    pub const fn denial(&self) -> Option<&Denial> {
        self.denial.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{Denial, Policy, is_interpreter};
    use crate::ipc::peer::{CDHASH_LEN, PeerIdentity};

    /// A peer this daemon could be asked about, at a path of its own.
    ///
    /// Built by hand rather than off a socket. [`PeerIdentity`]'s fields are
    /// public precisely because it is a set of facts and not a decision — the
    /// decision is [`Attestation`], which no test can construct.
    fn peer_at(image: &str, code_hash: [u8; CDHASH_LEN]) -> PeerIdentity {
        PeerIdentity {
            uid: 501,
            gid: 20,
            groups: Vec::new(),
            pid: 4242,
            generation: 1,
            unique_id: 7,
            code_hash,
            image: std::path::PathBuf::from(image),
        }
    }

    #[test]
    fn refusing_an_unpinned_client_names_the_path_and_not_only_the_program() {
        // The measured failure: a second copy of this program earlier on PATH
        // is refused exactly here. A message reading "`keyless` is not a pinned
        // client" names the program the operator believes they installed, so it
        // reads as a broken pin — and re-pinning does not help, because the
        // file being run is not the file being pinned. The path is the one fact
        // that separates those two readings.
        let policy = Policy::new().allow_uid(501).allow_image([1u8; CDHASH_LEN]);
        let elsewhere = "/somewhere/else/bin/keyless";

        let denial = policy
            .judge(&peer_at(elsewhere, [2u8; CDHASH_LEN]))
            .expect("an unpinned image is refused");

        assert!(matches!(denial, Denial::UnknownImage { .. }), "{denial:?}");
        assert!(
            denial.to_string().contains(elsewhere),
            "the refusal did not say which file was refused: {denial}"
        );
        // The reason word is what an operator greps the audit log for, and it
        // must not move because the sentence beside it did.
        assert_eq!(denial.kind(), "unknown-image");
    }

    #[test]
    fn a_pinned_client_at_any_path_is_not_refused() {
        // The control. Without it, an assertion that an unpinned image is
        // refused is satisfied by a policy that refuses everything.
        let policy = Policy::new().allow_uid(501).allow_image([1u8; CDHASH_LEN]);
        assert!(
            policy
                .judge(&peer_at("/somewhere/else/bin/keyless", [1u8; CDHASH_LEN]))
                .is_none()
        );
    }

    #[test]
    fn interpreters_are_recognised_including_versioned_names() {
        for name in [
            "node",
            "python3",
            "python3.12",
            "Rscript",
            "ZSH",
            "bun",
            "sh",
        ] {
            assert!(is_interpreter(name), "{name} should be an interpreter");
        }
        for name in ["keyless", "gh", "psql", "curl", "nodemon", "shell-thing"] {
            assert!(!is_interpreter(name), "{name} is not an interpreter");
        }
    }
}

/// Asking the kernel who is on a socket. macOS only.
///
/// The single `#[cfg]` in this file's decision path, and the single constructor
/// of an [`Attestation`]. See the module header for why this is a module rather
/// than a trait, and why nothing stands in for it off macOS.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub mod live {
    use std::os::fd::BorrowedFd;

    use super::{Attestation, Denial, Policy};
    use crate::ipc::peer;

    /// Identify the peer on `fd` and apply `policy`.
    ///
    /// Called once per request rather than once per connection: a process may
    /// `exec` a different image without closing its sockets, so a per-connection
    /// decision authorises a program that may no longer be running.
    #[must_use]
    pub fn attest(fd: BorrowedFd<'_>, policy: &Policy) -> Attestation {
        match peer::identify(fd) {
            Ok(peer) => {
                let denial = policy.judge(&peer);
                Attestation {
                    peer: Some(peer),
                    denial,
                }
            }
            Err(error) => Attestation {
                peer: None,
                denial: Some(Denial::Unidentified(error)),
            },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::attest;
        use crate::attest::{Denial, Policy};
        use crate::ipc::peer;
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;
        use std::path::PathBuf;

        /// A REAL attested peer, not a hand-built one.
        ///
        /// That is why every test below it is macOS-only even though
        /// [`crate::attest::Policy::judge`] is pure: the fixture is the point. Judging a
        /// `PeerIdentity` written out field by field would test the policy against
        /// a shape this crate invented, where this tests it against the shape the
        /// kernel actually produces. Swapping in a synthetic peer to buy a Linux
        /// test run would weaken the macOS one, so it is not done.
        fn me() -> crate::ipc::peer::PeerIdentity {
            let (a, _b) = UnixStream::pair().expect("socketpair");
            peer::identify(a.as_fd()).expect("this process attests")
        }

        #[test]
        fn an_empty_policy_authorises_nothing() {
            let peer = me();
            let denial = Policy::new().judge(&peer).expect("an empty policy denies");
            assert_eq!(denial.kind(), "uid-not-allowed");
        }

        #[test]
        fn a_uid_alone_is_not_enough() {
            let peer = me();
            let denial = Policy::new()
                .allow_uid(peer.uid)
                .judge(&peer)
                .expect("no image pinned");
            assert_eq!(denial.kind(), "no-image-pinned");
        }

        #[test]
        fn the_right_uid_and_the_right_image_pass() {
            let peer = me();
            let policy = Policy::new()
                .allow_uid(peer.uid)
                .allow_image(peer.code_hash);
            assert!(policy.judge(&peer).is_none());
        }

        #[test]
        fn a_pinned_image_under_the_wrong_uid_is_refused() {
            let peer = me();
            let policy = Policy::new()
                .allow_uid(peer.uid.wrapping_add(1))
                .allow_image(peer.code_hash);
            assert!(matches!(policy.judge(&peer), Some(Denial::Uid(_))));
        }

        #[test]
        fn a_different_image_is_refused_even_with_the_right_uid() {
            let peer = me();
            let mut other = peer.code_hash;
            other[0] ^= 0xff;
            let policy = Policy::new().allow_uid(peer.uid).allow_image(other);
            assert!(matches!(
                policy.judge(&peer),
                Some(Denial::UnknownImage { .. })
            ));
        }

        #[test]
        fn pinning_an_interpreter_does_not_authorise_it() {
            // The belt-and-braces claim, exercised: an operator pins the hash of
            // an interpreter, and it is still refused.
            let mut peer = me();
            peer.image = PathBuf::from("/opt/homebrew/bin/node");
            let policy = Policy::new()
                .allow_uid(peer.uid)
                .allow_image(peer.code_hash);
            let denial = policy.judge(&peer).expect("an interpreter is refused");
            assert_eq!(denial.kind(), "interpreted-caller");
            assert!(denial.to_string().contains("keyless run"));
        }

        #[test]
        fn the_interpreter_refusal_has_a_negative_control() {
            // Without this the previous test could pass because of the allowlist
            // rather than because of the interpreter rule.
            let mut peer = me();
            peer.image = PathBuf::from("/opt/homebrew/bin/node");
            let policy = Policy::new()
                .allow_uid(peer.uid)
                .allow_image(peer.code_hash)
                .permitting_interpreters();
            assert!(
                policy.judge(&peer).is_none(),
                "with the rule off, the same peer must pass — otherwise the rule is not what refused it"
            );
        }

        #[test]
        fn attesting_a_live_socket_yields_this_process() {
            let (a, _b) = UnixStream::pair().expect("socketpair");
            let peer = me();
            let policy = Policy::new()
                .allow_uid(peer.uid)
                .allow_image(peer.code_hash);
            let attestation = attest(a.as_fd(), &policy);
            assert!(attestation.is_allowed());
            assert_eq!(
                attestation.peer.map(|p| p.pid),
                Some(std::process::id().cast_signed())
            );
        }
    }
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
pub use live::attest;
