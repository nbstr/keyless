//! The body of the two test peers.
//!
//! Lives in a subdirectory so Cargo does not treat it as an example of its
//! own: auto-discovery picks up `examples/*.rs` and `examples/*/main.rs`, and
//! this is neither.
//!
//! # Why there are two peers at all
//!
//! Attestation is about *which program* is on the socket, so testing it needs
//! at least two programs that differ only in identity. `keyless_peer_alpha` and
//! `keyless_peer_beta` are byte-different — each passes its own tag through to
//! the output, so the compiler cannot fold them into one — and therefore carry
//! different code hashes. One is pinned, the other is not.
//!
//! # No value is ever printed
//!
//! A test peer that printed the plaintext it received would be a `get` verb
//! wearing a false moustache, and it would end up in somebody's shell history.
//! It prints the SHA-256 of the value instead, computed with this crate's own
//! implementation. The test seeds a decoy and compares digests, which proves
//! the exact bytes arrived without any of them reaching a terminal.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use keyless::audit::sha256;
use keyless::ipc::client::Client;
use keyless::ipc::protocol::{Reply, Request, read_frame, write_frame};
use keyless::mask::encodings::hex_lower;

/// The descriptor an `exec`ed successor finds its inherited socket on.
const INHERITED_FD: i32 = 3;

unsafe extern "C" {
    fn dup2(from: i32, to: i32) -> i32;
    /// Declared **variadic**, which it is.
    ///
    /// On Apple ARM64 a variadic argument is passed on the stack while a fixed
    /// one is passed in a register, so declaring `fcntl` as
    /// `fn(i32, i32, i32)` compiles, links, and then hands the callee whatever
    /// happened to be on the stack. The observed result was `FD_SETFD` being
    /// set from garbage, close-on-exec staying on, and the successor getting
    /// `EBADF` — a failure with no error anywhere near the mistake.
    fn fcntl(fd: std::ffi::c_int, cmd: std::ffi::c_int, ...) -> std::ffi::c_int;
    fn execv(path: *const std::ffi::c_char, argv: *const *const std::ffi::c_char) -> i32;
}

/// `F_SETFD` from `<fcntl.h>`.
const F_SETFD: std::ffi::c_int = 2;

/// Run whichever mode the environment asks for.
///
/// - `once` (default) — connect, resolve, report.
/// - `exec` — connect, resolve, report, then **`exec` a different binary in
///   place** with the socket still open on fd 3. Same pid, same connection,
///   different loaded image. This is what proves attestation happens per
///   request rather than once per connection.
/// - `inherited` — use the socket already on fd 3.
pub fn run(tag: &str) {
    let mode = std::env::var("KLP_MODE").unwrap_or_else(|_| "once".to_owned());
    let name = std::env::var("KLP_NAME").unwrap_or_else(|_| "DECOY".to_owned());

    match mode.as_str() {
        "inherited" => {
            // SAFETY: fd 3 was placed by the `exec` mode below with `dup2`,
            // which clears close-on-exec, so it is a live connected socket that
            // this process now owns.
            let stream =
                unsafe { <UnixStream as std::os::fd::FromRawFd>::from_raw_fd(INHERITED_FD) };
            report(tag, exchange_on(&stream, &name));
        }
        // Connect, wait, then send. The wait is the window an attacker needs:
        // it is the interval in which the executable can be replaced on disk
        // between the connection being made and the daemon deciding who made
        // it. Without a knob for it the swap attack cannot be built at all,
        // only reasoned about.
        "delay" => {
            let stream = match UnixStream::connect(socket_path()) {
                Ok(stream) => stream,
                Err(error) => {
                    report(tag, Err(format!("connect: {error}")));
                    return;
                }
            };
            let _ = writeln!(std::io::stderr(), "{tag} connected");
            let _ = std::io::stderr().flush();
            let millis: u64 = std::env::var("KLP_DELAY_MS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(400);
            std::thread::sleep(Duration::from_millis(millis));
            report(tag, exchange_on(&stream, &name));
        }
        "exec" => {
            let socket = socket_path();
            let stream = match UnixStream::connect(&socket) {
                Ok(stream) => stream,
                Err(error) => {
                    report(tag, Err(format!("connect: {error}")));
                    return;
                }
            };
            report(tag, exchange_on(&stream, &name));
            exec_successor(&stream);
        }
        _ => {
            let client = Client::new(socket_path(), Duration::from_secs(5));
            let outcome = match client.request(&Request::resolve(&name)) {
                Ok(reply) => Ok(reply),
                Err(error) => Err(error.to_string()),
            };
            report(tag, outcome);
        }
    }
}

fn socket_path() -> std::path::PathBuf {
    std::env::var_os("KLP_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(keyless::ipc::default_socket_path)
}

/// One request and one reply on an already-connected socket.
fn exchange_on(stream: &UnixStream, name: &str) -> Result<Reply, String> {
    let frame = Request::resolve(name)
        .encode()
        .map_err(|error| error.to_string())?;
    write_frame(&mut { stream }, &frame).map_err(|error| error.to_string())?;
    let mut reader = std::io::BufReader::new(stream);
    match read_frame(&mut reader) {
        Ok(Some(raw)) => Reply::decode(&raw).map_err(|error| error.to_string()),
        Ok(None) => Err("the daemon closed the connection".to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

/// Replace this process's image, keeping the connection open on fd 3.
fn exec_successor(stream: &UnixStream) -> ! {
    let successor = std::env::var("KLP_EXEC").unwrap_or_else(|_| "/bin/sh".to_owned());

    // SAFETY: `stream`'s descriptor is live and owned by this process.
    // `dup2` duplicates it onto fd 3, and a duplicate never carries
    // close-on-exec — which is the whole point, since the successor must
    // inherit an open socket.
    let duped = unsafe { dup2(stream.as_raw_fd(), INHERITED_FD) };
    if duped < 0 {
        let _ = writeln!(std::io::stderr(), "peer: dup2 failed");
        std::process::exit(70);
    }

    // `dup2(fd, fd)` is defined to be a no-op that returns `fd`, and a no-op
    // does NOT clear close-on-exec. The socket here is usually already fd 3 —
    // it is the first descriptor this process opens after stdio — so the dup2
    // above frequently does nothing at all and the successor inherits nothing.
    // That failure is invisible from this side: dup2 returns 3 and reports
    // success, and the successor gets EBADF.
    //
    // SAFETY: `INHERITED_FD` is open, having just been returned by `dup2`.
    // Clearing the descriptor flags is the documented way to allow it across
    // an exec.
    if unsafe { fcntl(INHERITED_FD, F_SETFD, 0 as std::ffi::c_int) } < 0 {
        let _ = writeln!(std::io::stderr(), "peer: cannot clear close-on-exec");
        std::process::exit(70);
    }

    unsafe { std::env::set_var("KLP_MODE", "inherited") };

    let Ok(path) = std::ffi::CString::new(successor.clone()) else {
        std::process::exit(70);
    };
    let Ok(arg0) = std::ffi::CString::new(successor) else {
        std::process::exit(70);
    };
    let argv: [*const std::ffi::c_char; 2] = [arg0.as_ptr(), std::ptr::null()];

    // SAFETY: `path` and `argv` are NUL-terminated and live until `execv`
    // returns, which it only does on failure. `argv` is NULL-terminated as
    // `execv` requires.
    unsafe { execv(path.as_ptr(), argv.as_ptr()) };

    let _ = writeln!(std::io::stderr(), "peer: execv failed");
    std::process::exit(70);
}

/// One line, machine-readable, never carrying a value.
fn report(tag: &str, outcome: Result<Reply, String>) {
    let line = match outcome {
        Ok(Reply::Value(secret)) => {
            let digest = hex_lower(&sha256::digest(secret.expose().as_bytes()));
            format!("{tag} status=ok digest={digest}")
        }
        Ok(Reply::Absent) => format!("{tag} status=absent"),
        Ok(Reply::Denied(reason)) => format!("{tag} status=denied reason={reason}"),
        Ok(Reply::Failed(reason)) => format!("{tag} status=failed reason={reason}"),
        Ok(Reply::Info { .. }) => format!("{tag} status=info"),
        Err(error) => format!("{tag} status=error reason={error}"),
    };
    let _ = writeln!(std::io::stdout(), "{line}");
    let _ = std::io::stdout().flush();
}
