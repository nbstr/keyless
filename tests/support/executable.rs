//! Creating a file this suite is going to execute.
//!
//! Its own file for the same reason as `within` and `short_socket`: several
//! test binaries build executables of their own, and a second copy of this
//! would be free to drift back into the shape it exists to replace.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The script both installers run. `$1` and `$2` are handed in as arguments.
///
/// The body and the paths travel as ARGUMENTS rather than inside the text. A
/// stub body in this suite carries newlines, tabs, quotes, dollars and escape
/// bytes on purpose — that is what several of them are testing — and a scratch
/// path can carry a space. Interpolating either into a shell string makes the
/// fixture a test of the quoting rather than of the code.
const WRITE: &str = r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#;
const COPY: &str = r#"cp -- "$1" "$2" && chmod 755 "$2""#;

/// Create `path` as an executable holding `body`, and hand back `path`.
///
/// # Why this is not `fs::write` followed by a `chmod`
///
/// `execve` refuses a file with `ETXTBSY` for as long as ANY process anywhere
/// holds it open for writing. `fs::write` closes its own descriptor before it
/// returns, and that is not enough on its own. A test binary runs its cases on
/// many threads at once, and a `fork` on any of them copies the WHOLE
/// descriptor table — including the one another thread is writing a stub
/// through at that instant. The copy survives in that child until its own
/// `exec` clears it, and for that interval the stub is busy for everybody:
/// including the thread that wrote it and is now handing it to a child of its
/// own, which is the failure this closes.
///
/// This is the class `tests/pty.rs` closed for a terminal and
/// `keyless::store::exec` serialises for a pipe, in an ordinary file's shape
/// — a descriptor that is inheritable at the instant another thread forks.
/// Dropping the handle earlier does not close it, because by then the leaked
/// copy is already somewhere this process cannot reach.
///
/// So no writable descriptor to the file is ever created in THIS process.
/// `/bin/sh` opens it, in a process whose descriptor table no thread here can
/// fork a copy of. That closes the window at its origin rather than narrowing
/// it: there is no ordering to get right, no lock for a spawn site to remember
/// to take, and no window left that a slower machine can widen.
///
/// Measured on the pinned Linux under the memory cap, sixteen threads each
/// writing a stub and then reaching it through a spawned child, sixty-four
/// thousand execs per arm: the write-then-`chmod` shape is refused on a
/// fraction of a percent of them, and this one on none of them.
pub fn install_executable(path: &Path, body: &str) -> PathBuf {
    run(WRITE, body.as_ref(), path);
    path.to_path_buf()
}

/// Copy `from` to `to` and make `to` executable, holding no descriptor to it.
///
/// `fs::copy` has the window described on [`install_executable`] and holds it
/// far longer, because the descriptor stays open for the whole copy rather than
/// for one small write — and what this suite copies is a built binary.
pub fn install_executable_copy(from: &Path, to: &Path) -> PathBuf {
    run(COPY, from.as_os_str(), to);
    to.to_path_buf()
}

fn run(script: &str, first: &std::ffi::OsStr, path: &Path) {
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        // `$0`, which a shell reports in its own diagnostics rather than
        // treating as an argument.
        .arg("sh")
        .arg(first)
        .arg(path)
        .status()
        .unwrap_or_else(|error| panic!("cannot install {}: {error}", path.display()));
    assert!(
        status.success(),
        "installing {} ended {status}",
        path.display()
    );
}
