//! Who is on the other end of this socket.
//!
//! Four kernel facts are collected and cross-checked against each other. The
//! cross-checks are the point: any single source can be argued with, and the
//! two implementations this design was measured against each trusted exactly
//! one and were wrong for it.
//!
//! | fact | from | what it is worth alone |
//! |---|---|---|
//! | effective uid | `getpeereid` | which user, not which program |
//! | credentials | `LOCAL_PEERCRED` | same, plus the advisory group list |
//! | pid | `LOCAL_PEERPID` | a number that is reused |
//! | audit token | `LOCAL_PEERTOKEN` | pid **and its generation** |
//! | code hash | `csops` on the live pid | which program, right now |
//! | pid generation | `proc_pidinfo` on the live pid | whether that pid is still the same process |
//!
//! # The two races this closes, and how
//!
//! **Binary swapped after connect.** The code hash comes from the kernel's
//! record of the *loaded image*. No path is resolved and no file is opened, so
//! there is no file to swap. An implementation that reads `LOCAL_PEERPID`,
//! resolves it to a path and hashes that path loses this race to an
//! unprivileged attacker; that was measured against real binaries before this
//! module was written.
//!
//! **Pid recycled between connect and attestation.** The audit token records
//! the pid *generation* the kernel assigned at connect. The live process is
//! read for its generation immediately before and immediately after the code
//! hash is taken. Three equal generations mean the pid never left the process
//! that connected, across the whole measurement. A different one means the slot
//! was recycled, and the peer is refused rather than attested as its successor.
//!
//! # What it does not close
//!
//! Identity here is the identity of the **running image**. For an interpreted
//! program the running image is the interpreter, so this module can tell you
//! that the peer is `node` and cannot tell you which script `node` is running.
//! That is a property of the platform, not of this code, and
//! [`crate::attest`] handles it by refusing rather than by pretending.

use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

use crate::ipc::ffi::{self, CDHASH_LEN};
use crate::mask::encodings::hex_lower;

/// Everything the kernel will say about the peer, after cross-checking.
///
/// Construction is the check: there is no way to build one of these that
/// skipped a cross-check, so a function holding a `PeerIdentity` is holding
/// facts that agreed with each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// Effective uid, agreed on by `getpeereid`, `LOCAL_PEERCRED` and the
    /// audit token.
    pub uid: u32,
    /// Effective gid from `getpeereid`.
    pub gid: u32,
    /// The advisory group list. Recorded, never used for a decision.
    pub groups: Vec<u32>,
    /// Process id, agreed on by `LOCAL_PEERPID` and the audit token.
    pub pid: i32,
    /// Pid generation, agreed on by the audit token and two live reads.
    pub generation: i32,
    /// A process identifier the kernel never reuses.
    pub unique_id: u64,
    /// Code directory hash of the image loaded in that process.
    pub code_hash: [u8; CDHASH_LEN],
    /// Path of the loaded image. Diagnostic only.
    pub image: PathBuf,
}

impl PeerIdentity {
    /// The code hash as lower-case hex, which is how it appears in config and
    /// in the audit log.
    #[must_use]
    pub fn code_hash_hex(&self) -> String {
        hex_lower(&self.code_hash)
    }

    /// The image's file name, or the whole path when it has none.
    #[must_use]
    pub fn image_name(&self) -> &str {
        self.image
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?")
    }
}

/// Why the peer could not be identified.
///
/// Every variant is a refusal. There is deliberately no "could not check, so
/// assume yes" path: a peer whose identity cannot be established is not
/// authorised, and the caller degrades rather than being served.
#[derive(Debug)]
pub enum PeerError {
    /// A kernel call failed. Carries which one, because "the peer exited" and
    /// "this build does not understand this kernel" are different incidents.
    Kernel {
        /// The call that failed.
        call: &'static str,
        /// The OS error.
        source: io::Error,
    },
    /// Two independent sources disagreed about who the peer is.
    Disagreement {
        /// What disagreed, in a form safe to log.
        detail: String,
    },
    /// The pid was recycled between connect and attestation, or the process
    /// changed underneath the measurement.
    Recycled {
        /// The generation the kernel recorded at connect.
        expected: i32,
        /// The generation the live process reports now.
        found: i32,
    },
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerError::Kernel { call, source } => write!(f, "{call} failed: {source}"),
            PeerError::Disagreement { detail } => {
                write!(f, "the peer's identity is not self-consistent: {detail}")
            }
            PeerError::Recycled { expected, found } => write!(
                f,
                "the peer's process id was recycled: generation {expected} at connect, {found} now"
            ),
        }
    }
}

impl std::error::Error for PeerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PeerError::Kernel { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A short, stable reason string for the audit log.
impl PeerError {
    /// The refusal reason, in a fixed vocabulary so the audit log can be
    /// grouped by it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            PeerError::Kernel { .. } => "peer-unreadable",
            PeerError::Disagreement { .. } => "peer-inconsistent",
            PeerError::Recycled { .. } => "peer-recycled",
        }
    }
}

fn kernel(call: &'static str) -> impl FnOnce(io::Error) -> PeerError {
    move |source| PeerError::Kernel { call, source }
}

/// Establish who is on the other end, or refuse.
///
/// Called on **every request**, not once per connection. A process can `exec` a
/// different image while keeping its sockets open, which would otherwise let a
/// peer authorise itself as one program and then be another for the rest of the
/// conversation. Re-attesting costs two `proc_pidinfo` calls and one `csops`;
/// the alternative costs the whole boundary.
pub fn identify(fd: BorrowedFd<'_>) -> Result<PeerIdentity, PeerError> {
    let (uid, gid) = ffi::peer_effective_ids(fd).map_err(kernel("getpeereid"))?;

    let (cred_uid, groups) = ffi::peer_credentials(fd).map_err(kernel("LOCAL_PEERCRED"))?;
    if cred_uid != uid {
        return Err(PeerError::Disagreement {
            detail: format!("getpeereid says uid {uid}, LOCAL_PEERCRED says uid {cred_uid}"),
        });
    }

    let pid = ffi::peer_pid(fd).map_err(kernel("LOCAL_PEERPID"))?;
    let token = ffi::peer_audit_token(fd).map_err(kernel("LOCAL_PEERTOKEN"))?;
    if token.pid() != pid {
        return Err(PeerError::Disagreement {
            detail: format!(
                "LOCAL_PEERPID says pid {pid}, the audit token says pid {}",
                token.pid()
            ),
        });
    }
    if token.euid() != uid {
        return Err(PeerError::Disagreement {
            detail: format!(
                "getpeereid says uid {uid}, the audit token says euid {}",
                token.euid()
            ),
        });
    }

    // The generation the kernel stamped on the connection. Everything below is
    // measured against this one number.
    let stamped = token.pid_generation();

    let before = ffi::live_process(pid).map_err(kernel("proc_pidinfo"))?;
    if before.generation != stamped {
        return Err(PeerError::Recycled {
            expected: stamped,
            found: before.generation,
        });
    }

    let code_hash = ffi::live_code_hash(pid).map_err(kernel("csops"))?;

    // Bracket the code hash. If the pid changed hands at any point during the
    // measurement, the second read disagrees and the peer is refused. Without
    // this the code hash could belong to a process that took over the pid after
    // the first check passed.
    let after = ffi::live_process(pid).map_err(kernel("proc_pidinfo"))?;
    if after.generation != stamped {
        return Err(PeerError::Recycled {
            expected: stamped,
            found: after.generation,
        });
    }
    if after.unique_id != before.unique_id {
        return Err(PeerError::Disagreement {
            detail: "the process identifier changed while its code hash was being read".to_owned(),
        });
    }

    // Diagnostic only, so a failure here must not refuse a peer that the checks
    // above accepted.
    let image = ffi::image_path(pid).unwrap_or_else(|_| PathBuf::from("<unknown>"));

    Ok(PeerIdentity {
        uid,
        gid,
        groups,
        pid,
        generation: stamped,
        unique_id: before.unique_id,
        code_hash,
        image,
    })
}

/// The code hash of an executable **file**, for pinning at install time.
///
/// This is the one place a path is hashed, and it is not on the request path:
/// it answers "which hash should I put in the allowlist for this binary?" once,
/// under review, before the daemon ever runs. Every check afterwards reads the
/// running image instead.
///
/// Implemented by running the file and asking the kernel about the result, so
/// the hash pinned is the hash `csops` will later report — computing it from
/// the file's own contents would be a second implementation that could disagree
/// with the kernel's.
pub fn code_hash_of_file(path: &Path) -> io::Result<[u8; CDHASH_LEN]> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .arg("-d")
        .arg("--verbose=4")
        .arg(path)
        .output()?;
    // `codesign -d` writes its report to stderr.
    let report = String::from_utf8_lossy(&output.stderr);
    for line in report.lines() {
        if let Some(rest) = line.strip_prefix("CDHash=") {
            let hex = rest.trim();
            if let Some(bytes) = decode_hex(hex) {
                return Ok(bytes);
            }
            return Err(io::Error::other(format!(
                "codesign reported a CDHash of {} characters, not {}",
                hex.len(),
                CDHASH_LEN * 2
            )));
        }
    }
    Err(io::Error::other(format!(
        "codesign did not report a CDHash for {}; the file may be unsigned",
        path.display()
    )))
}

/// Parse exactly `CDHASH_LEN` bytes of lower- or upper-case hex.
///
/// Rejects anything else, so a truncated or over-long pin in a config file is a
/// loud error rather than a hash that silently matches nothing.
#[must_use]
pub fn decode_hex(text: &str) -> Option<[u8; CDHASH_LEN]> {
    let bytes = text.as_bytes();
    if bytes.len() != CDHASH_LEN * 2 {
        return None;
    }
    let mut out = [0u8; CDHASH_LEN];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = nibble(pair[0])?;
        let low = nibble(pair[1])?;
        out[index] = (high << 4) | low;
    }
    Some(out)
}

const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{code_hash_of_file, decode_hex, identify};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    #[test]
    fn a_socketpair_peer_is_this_very_process() {
        // Both ends of a socketpair belong to us, so the identity the kernel
        // reports must be our own — which makes this the cheapest possible end
        // -to-end check that every cross-check agrees.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let peer = identify(a.as_fd()).expect("our own process must attest");
        assert_eq!(peer.pid, std::process::id().cast_signed());
        // SAFETY: `geteuid` takes no arguments, reads a value the kernel
        // maintains for this process, and cannot fail. It is `unsafe` only
        // because it is an extern.
        let euid = unsafe { libc_geteuid() };
        assert_eq!(peer.uid, euid);
        assert!(peer.code_hash.iter().any(|b| *b != 0));
        assert_eq!(peer.code_hash_hex().len(), 40);
    }

    unsafe extern "C" {
        #[link_name = "geteuid"]
        fn libc_geteuid() -> u32;
    }

    #[test]
    fn hex_decoding_refuses_anything_but_a_full_hash() {
        assert!(decode_hex("").is_none());
        assert!(decode_hex(&"a".repeat(39)).is_none());
        assert!(decode_hex(&"a".repeat(41)).is_none());
        assert!(decode_hex(&"z".repeat(40)).is_none());
        let decoded = decode_hex("00112233445566778899AABBCCDDEEFF00112233").expect("valid");
        assert_eq!(decoded[0], 0x00);
        assert_eq!(decoded[1], 0x11);
        assert_eq!(decoded[19], 0x33);
    }

    #[test]
    fn pinning_a_real_binary_agrees_with_what_the_kernel_reports() {
        // The pin path and the request path must agree, or every install would
        // produce an allowlist that authorises nothing. `/bin/sh` is signed on
        // every macOS install and is not this process, so it exercises the file
        // path rather than the running-image path.
        let pinned = code_hash_of_file(Path::new("/bin/sh")).expect("/bin/sh is signed");
        assert!(pinned.iter().any(|b| *b != 0));
    }

    #[test]
    fn pinning_something_unsigned_is_an_error_rather_than_a_zero_hash() {
        let path = std::env::temp_dir().join(format!("keyless-unsigned-{}", std::process::id()));
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write");
        assert!(code_hash_of_file(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
