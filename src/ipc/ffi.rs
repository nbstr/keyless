//! The libSystem calls the privilege boundary rests on.
//!
//! Every `unsafe` block in the daemon is in this file, so "what does keyless
//! trust the kernel for?" is answered by reading one screen rather than by
//! grepping the crate. Each wrapper is safe to call from anywhere; each returns
//! [`io::Result`] rather than panicking, because a syscall failing is a reason
//! to refuse a peer, never a reason to abort a process.
//!
//! # Why these five and not a crate
//!
//! `nix` covers none of them. `LOCAL_PEERTOKEN` is not in `nix`, `csops` is not
//! in `libc` (it is a private XNU entry point exported by libSystem), and
//! `proc_pidinfo`'s uniq-identifier flavour is not in the public SDK header.
//! Wrapping them by hand is therefore not a preference; it is the only option
//! that reaches the primitives at all.
//!
//! # The one thing that would silently break this file
//!
//! A wrong `#[repr(C)]` layout compiles, links, and then reads the wrong bytes.
//! So every wrapper that fills a struct **checks the length the kernel reports
//! against `size_of` and refuses on a mismatch**. That turns a layout error
//! from silent misattestation into a loud refusal, which is the direction a
//! security boundary must fail in.
//!
//! # This file is the whole of the platform boundary
//!
//! Four of the symbols declared below — `csops`, `getpeereid`, `proc_pidinfo`
//! and `proc_pidpath` — exist on macOS and nowhere else, so this module is
//! compiled on macOS only. Nothing in the crate stubs it: a caller that needs
//! a kernel fact off macOS does not get a weaker fact, it fails to compile.
//!
//! CI defeats the gate with `--cfg keyless_force_xnu`, runs the link on Linux
//! and requires it to fail on exactly those four names. That is what keeps the
//! porting table in `install/README.md` honest, and it is why the gate is
//! written as `any(target_os = "macos", keyless_force_xnu)` rather than as a
//! bare `target_os`.

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;

/// `SOL_LOCAL` from `<sys/un.h>`. Not a protocol number — the local domain's
/// own option level.
const SOL_LOCAL: c_int = 0;
/// `LOCAL_PEERCRED`: the connecting process's credentials, captured by the
/// kernel at connect time.
const LOCAL_PEERCRED: c_int = 0x001;
/// `LOCAL_PEERPID`: the connecting process's pid, likewise captured at connect.
const LOCAL_PEERPID: c_int = 0x002;
/// `LOCAL_PEERTOKEN`: the connecting process's `audit_token_t`. This is the one
/// that matters — it carries the **pid generation**, which is what makes pid
/// reuse detectable.
const LOCAL_PEERTOKEN: c_int = 0x006;

/// `CS_OPS_CDHASH` from XNU's private `<sys/codesign.h>`.
///
/// Measured rather than assumed: `csops` with this operation returns the code
/// directory hash of the **running image**, cross-UID, without privilege. The
/// value 5 was confirmed against a live process before this file was written;
/// the neighbouring value 20 returns `EINVAL`, so a wrong constant fails loudly.
const CS_OPS_CDHASH: c_uint = 5;

/// `PROC_PIDUNIQIDENTIFIERINFO` from XNU's private `<sys/proc_info.h>`.
///
/// The public SDK header stops at flavour 13. This flavour is readable
/// cross-UID without privilege, which the flavours that carry a start time
/// (`PROC_PIDTBSDINFO`) are **not** — measured `EPERM` from an unprivileged
/// caller against another user's process. That measurement is why this crate
/// anchors on the pid generation rather than on a start time.
const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;

/// `PROC_PIDPATHINFO_MAXSIZE` from `<sys/proc_info.h>`.
const PROC_PIDPATHINFO_MAXSIZE: usize = 4 * 1024;

/// Length of a truncated code directory hash, as `csops` returns it.
///
/// Defined in [`crate::ipc::peer`], which is portable, and re-exported here so
/// this module still reads as the description of what the kernel returns. The
/// length is a fact about the hash rather than about the syscall, and
/// [`crate::attest::Policy`] needs it on every platform.
pub use crate::ipc::peer::CDHASH_LEN;

/// `struct xucred` from `<sys/ucred.h>`.
///
/// Layout is `u_int`, `uid_t`, `short`, `gid_t[NGROUPS]` with `NGROUPS` = 16,
/// which the C compiler pads to 76 bytes. The wrapper below refuses any reply
/// whose length is not exactly that.
#[repr(C)]
#[derive(Clone, Copy)]
struct XUcred {
    cr_version: c_uint,
    cr_uid: u32,
    cr_ngroups: i16,
    cr_groups: [u32; 16],
}

/// `XUCRED_VERSION`. A reply carrying any other version is a kernel this code
/// has not been checked against.
const XUCRED_VERSION: c_uint = 0;

/// `audit_token_t` from `<bsm/audit.h>`: eight opaque words.
///
/// The accessor functions live in `libbsm`, which is not linked into a plain
/// Rust binary. Rather than add a link directive for six one-line getters, the
/// two fields this crate needs are read by index — and the pid index is
/// **cross-checked against `LOCAL_PEERPID`** on every call, so a wrong index
/// would make attestation fail rather than succeed.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuditToken {
    val: [u32; 8],
}

impl AuditToken {
    /// `audit_token_to_pid`: word 5.
    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.val[5].cast_signed()
    }

    /// `audit_token_to_pidversion`: word 7.
    ///
    /// The kernel bumps this every time a proc slot is allocated, so a pid that
    /// has been recycled never carries the generation it carried before. This
    /// is the anchor that makes pid reuse a detected condition rather than a
    /// hoped-against one.
    #[must_use]
    pub const fn pid_generation(&self) -> i32 {
        self.val[7].cast_signed()
    }

    /// `audit_token_to_euid`: word 1.
    #[must_use]
    pub const fn euid(&self) -> u32 {
        self.val[1]
    }

    /// `audit_token_to_ruid`: word 3.
    #[must_use]
    pub const fn ruid(&self) -> u32 {
        self.val[3]
    }
}

/// `struct proc_uniqidentifierinfo` from XNU's `<sys/proc_info.h>`.
///
/// 56 bytes. The kernel returns the number of bytes it filled, and the wrapper
/// refuses anything but 56 — so a layout drift in a future macOS becomes a
/// refusal instead of a misread field.
#[repr(C)]
#[derive(Clone, Copy)]
struct ProcUniqIdentifierInfo {
    p_uuid: [u8; 16],
    p_uniqueid: u64,
    p_puniqueid: u64,
    p_idversion: i32,
    p_reserve2: u32,
    p_reserve3: u64,
    p_reserve4: u64,
}

unsafe extern "C" {
    fn getpeereid(fd: c_int, euid: *mut u32, egid: *mut u32) -> c_int;
    fn getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        value: *mut c_void,
        len: *mut c_uint,
    ) -> c_int;
    fn csops(pid: c_int, ops: c_uint, useraddr: *mut c_void, usersize: usize) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
}

/// The connected peer's effective uid and gid.
pub fn peer_effective_ids(fd: BorrowedFd<'_>) -> io::Result<(u32, u32)> {
    let mut euid: u32 = u32::MAX;
    let mut egid: u32 = u32::MAX;
    // SAFETY: `fd` is a live descriptor for the lifetime of the borrow, and
    // both out-pointers address initialised local `u32`s that outlive the call.
    let rc = unsafe { getpeereid(fd.as_raw_fd(), &raw mut euid, &raw mut egid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((euid, egid))
}

/// The connected peer's credentials as the kernel recorded them at connect.
///
/// Returns the uid and the advisory group list. The group list is not used for
/// an access decision — group membership is checked by the filesystem when the
/// peer opens the socket — but it is recorded, because "which groups did the
/// caller hold" is the first question asked after an incident.
pub fn peer_credentials(fd: BorrowedFd<'_>) -> io::Result<(u32, Vec<u32>)> {
    let mut cred = XUcred {
        cr_version: u32::MAX,
        cr_uid: u32::MAX,
        cr_ngroups: -1,
        cr_groups: [0; 16],
    };
    let mut len = c_uint::try_from(size_of::<XUcred>()).unwrap_or(0);
    // SAFETY: `value` points at a live, fully initialised `XUcred` and `len`
    // says how many bytes the kernel may write, which is exactly its size. The
    // kernel writes at most that and updates `len` with what it wrote.
    let rc = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERCRED,
            (&raw mut cred).cast::<c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<XUcred>() {
        return Err(io::Error::other(format!(
            "LOCAL_PEERCRED returned {len} bytes, not {}",
            size_of::<XUcred>()
        )));
    }
    if cred.cr_version != XUCRED_VERSION {
        return Err(io::Error::other(format!(
            "LOCAL_PEERCRED version {} is not the layout this build understands",
            cred.cr_version
        )));
    }
    let count = usize::try_from(cred.cr_ngroups.max(0)).unwrap_or(0).min(16);
    Ok((cred.cr_uid, cred.cr_groups[..count].to_vec()))
}

/// The connected peer's pid, as recorded at connect time.
pub fn peer_pid(fd: BorrowedFd<'_>) -> io::Result<i32> {
    let mut pid: c_int = -1;
    let mut len = c_uint::try_from(size_of::<c_int>()).unwrap_or(0);
    // SAFETY: `value` points at a live `c_int` and `len` is its size; the
    // kernel writes at most that many bytes.
    let rc = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERPID,
            (&raw mut pid).cast::<c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<c_int>() {
        return Err(io::Error::other(format!(
            "LOCAL_PEERPID returned {len} bytes, not {}",
            size_of::<c_int>()
        )));
    }
    Ok(pid)
}

/// The connected peer's audit token, as recorded at connect time.
pub fn peer_audit_token(fd: BorrowedFd<'_>) -> io::Result<AuditToken> {
    let mut token = AuditToken { val: [0; 8] };
    let mut len = c_uint::try_from(size_of::<AuditToken>()).unwrap_or(0);
    // SAFETY: `value` points at a live, fully initialised 32-byte struct and
    // `len` is its size.
    let rc = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            (&raw mut token).cast::<c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<AuditToken>() {
        return Err(io::Error::other(format!(
            "LOCAL_PEERTOKEN returned {len} bytes, not {}",
            size_of::<AuditToken>()
        )));
    }
    Ok(token)
}

/// The code directory hash of the image **currently loaded** in `pid`.
///
/// This is the whole reason the daemon can be honest about identity. The kernel
/// answers from the process's loaded code signature; nothing on the filesystem
/// is consulted, no path is resolved, and no file is opened. Replacing the
/// binary on disk after the process started changes nothing here, which is
/// exactly the race that a resolve-then-hash-by-path implementation loses.
pub fn live_code_hash(pid: i32) -> io::Result<[u8; CDHASH_LEN]> {
    let mut hash = [0u8; CDHASH_LEN];
    // SAFETY: `useraddr` points at a live 20-byte array and `usersize` is its
    // length, which is the size `CS_OPS_CDHASH` writes.
    let rc = unsafe {
        csops(
            pid,
            CS_OPS_CDHASH,
            hash.as_mut_ptr().cast::<c_void>(),
            CDHASH_LEN,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(hash)
}

/// What the kernel says about a live process's identity in the pid table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveProcess {
    /// The pid generation. Compared against the audit token's, this is what
    /// makes a recycled pid detectable.
    pub generation: i32,
    /// A 64-bit identifier that is never reused for the life of the boot.
    /// Recorded in the audit log so two rows can be tied to one process with
    /// certainty.
    pub unique_id: u64,
}

/// Read the live pid-table identity of `pid`.
pub fn live_process(pid: i32) -> io::Result<LiveProcess> {
    let mut info = ProcUniqIdentifierInfo {
        p_uuid: [0; 16],
        p_uniqueid: 0,
        p_puniqueid: 0,
        p_idversion: -1,
        p_reserve2: 0,
        p_reserve3: 0,
        p_reserve4: 0,
    };
    let size = c_int::try_from(size_of::<ProcUniqIdentifierInfo>()).unwrap_or(0);
    // SAFETY: `buffer` points at a live, fully initialised struct and
    // `buffersize` is its size. `proc_pidinfo` writes at most that many bytes
    // and returns the count it wrote.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDUNIQIDENTIFIERINFO,
            0,
            (&raw mut info).cast::<c_void>(),
            size,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if written != size {
        return Err(io::Error::other(format!(
            "PROC_PIDUNIQIDENTIFIERINFO returned {written} bytes, not {size}"
        )));
    }
    Ok(LiveProcess {
        generation: info.p_idversion,
        unique_id: info.p_uniqueid,
    })
}

/// The filesystem path of the image loaded in `pid`.
///
/// **Never used for a trust decision.** A path is a label, not an identity: it
/// can be moved, and two paths can name one image. It is read so that a refusal
/// can say *what* was refused, and so the audit row is legible to a person.
pub fn image_path(pid: i32) -> io::Result<PathBuf> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let size = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `buffer` points at `size` writable bytes owned by `buf`, which
    // outlives the call. `proc_pidpath` writes a NUL-terminated path of at most
    // `size` bytes and returns its length.
    let written = unsafe { proc_pidpath(pid, buf.as_mut_ptr().cast::<c_void>(), size) };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    let len = usize::try_from(written).unwrap_or(0).min(buf.len());
    buf.truncate(len);
    Ok(PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
}

/// Silence the unused-field warnings on layout-only fields.
///
/// These fields exist so the struct matches the kernel's byte-for-byte. They
/// are never read, and deleting them would corrupt every field after them.
const _: () = {
    let _ = |c: XUcred| c.cr_version;
    let _ = |i: ProcUniqIdentifierInfo| i.p_uuid;
    let _: Option<*const c_char> = None;
};

#[cfg(test)]
mod tests {
    use super::{
        AuditToken, CDHASH_LEN, ProcUniqIdentifierInfo, XUcred, live_code_hash, live_process,
    };

    #[test]
    fn the_struct_layouts_match_the_kernels() {
        // These three numbers were read out of a running kernel before this
        // file existed. A future macOS that changes one will fail the runtime
        // length checks; this test catches a change made *here* by mistake.
        assert_eq!(size_of::<XUcred>(), 76);
        assert_eq!(size_of::<AuditToken>(), 32);
        assert_eq!(size_of::<ProcUniqIdentifierInfo>(), 56);
    }

    #[test]
    fn this_process_can_read_its_own_live_identity() {
        let pid = std::process::id().cast_signed();
        let hash = live_code_hash(pid).expect("a running process always has a loaded image");
        assert_eq!(hash.len(), CDHASH_LEN);
        assert!(
            hash.iter().any(|b| *b != 0),
            "an all-zero code hash means csops silently did nothing"
        );

        let live = live_process(pid).expect("a running process is always in the pid table");
        assert!(live.generation > 0);
        assert!(live.unique_id > 0);
    }

    #[test]
    fn a_pid_that_cannot_exist_is_an_error_rather_than_a_zero_hash() {
        // Anchoring on a bogus pid must fail, not return a default. A wrapper
        // that returned `Ok([0; 20])` here would make every peer attest.
        assert!(live_code_hash(-1).is_err());
        assert!(live_process(-1).is_err());
    }

    #[test]
    fn audit_token_accessors_read_the_documented_words() {
        let token = AuditToken {
            val: [10, 11, 12, 13, 14, 15, 16, 17],
        };
        assert_eq!(token.euid(), 11);
        assert_eq!(token.ruid(), 13);
        assert_eq!(token.pid(), 15);
        assert_eq!(token.pid_generation(), 17);
    }
}
