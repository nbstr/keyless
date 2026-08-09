// A unix socket path that fits in `sockaddr_un`.
//
// Deliberately written with `//` and not `//!`, and deliberately carrying no
// `use` statements — same constraints as `within.rs`, for the same reason.
// An inner doc comment has to be the first thing in its module, and a `use`
// would collide with an identical one already in whichever `mod tests { … }`
// includes this file. Every path below is spelled in full so the file can be
// dropped anywhere.
//
// SHARED ON PURPOSE, and there are two ways in. Integration tests take it
// through `mod support;`:
//
//     mod support;
//     use support::short_socket_path;
//
// A unit test inside `src/` cannot see `tests/`, so it includes this one file
// rather than growing a second copy of the same idea:
//
//     #[cfg(test)]
//     mod tests {
//         include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/short_socket.rs"));
//     }

/// A short, unique socket path belonging to `dir`.
///
/// # Why a socket cannot live in the scratch directory that owns it
///
/// `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on Linux, and it is not
/// a path buffer that grows — `bind(2)` refuses anything longer with
/// `InvalidInput` / `path must be shorter than SUN_LEN`. The platform temp
/// directory already spends about half of that: a stock macOS `TMPDIR` is 49
/// bytes, and the longest socket this suite builds under one is 93. **That is
/// three bytes of headroom on a default machine**, and the margin is spent by
/// whatever the enclosing directory happens to be called.
///
/// Measured on macOS 15 against `cargo test --lib`, varying only `TMPDIR`:
///
/// ```text
/// TMPDIR bytes   result
///           49   289 passed                     (the stock value)
///           52   289 passed
///           57   287 passed, 2 failed
///           82   286 passed, 3 failed
/// ```
///
/// Nothing about the code under test changes across those rows. A suite that
/// builds socket paths from `std::env::temp_dir()` is therefore asserting a
/// property of the machine's `TMPDIR`, not a property of the daemon — and it
/// fails in a shape (`InvalidInput`) that reads as a bug in the thing being
/// tested rather than as the platform constraint it is.
///
/// So the socket goes somewhere short and is named by a hash of the directory
/// it belongs to, while everything else that test owns stays in the scratch
/// directory. The daemon removes the socket on shutdown.
///
/// # `/tmp` is hardcoded, and that is the point
///
/// It is the one directory that is short on both platforms and is not
/// `TMPDIR`. Honouring `TMPDIR` here would reintroduce exactly the dependency
/// this function exists to remove.
pub fn short_socket_path(dir: &std::path::Path) -> std::path::PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dir.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    std::path::PathBuf::from("/tmp").join(format!("kl{:x}.sock", hasher.finish()))
}
