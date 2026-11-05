use std::os::unix::fs::PermissionsExt;

use super::{scratch, short_socket_path};
use crate::attest::Policy;
use crate::daemon::config::DaemonConfig;
use crate::daemon::{Daemon, SOCKET_MODE, remove_stale_socket};

#[test]
fn the_socket_is_group_writable_and_nothing_more() {
    // Connecting needs write, not read. A `0640` socket would be
    // unreachable by the very group it was created for, and a `0666` one
    // would let any user on the machine talk to the daemon.
    let dir = scratch("mode");
    let socket = short_socket_path(&dir);
    let config = DaemonConfig {
        socket: socket.clone().into(),
        audit: dir.join("audit.jsonl").into(),
        ..DaemonConfig::default()
    };
    let daemon = Daemon::bind(&config, Policy::new()).expect("bind");
    let mode = std::fs::metadata(daemon.socket())
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, SOCKET_MODE, "mode was {mode:04o}");
    assert_eq!(mode & 0o007, 0, "other must not be able to connect");
    drop(daemon);
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stale_socket_is_replaced() {
    let dir = scratch("stale");
    let socket = short_socket_path(&dir);
    let config = DaemonConfig {
        socket: socket.clone().into(),
        audit: dir.join("audit.jsonl").into(),
        ..DaemonConfig::default()
    };
    let first = Daemon::bind(&config, Policy::new()).expect("first bind");
    drop(first);
    // The inode is still there; binding again must work.
    let second = Daemon::bind(&config, Policy::new()).expect("second bind over a stale socket");
    drop(second);
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_regular_file_at_the_socket_path_is_refused_rather_than_deleted() {
    // Otherwise a mistyped `socket` field is a delete-any-file primitive
    // running as the daemon's uid.
    let dir = scratch("notasocket");
    let path = dir.join("important.txt");
    std::fs::write(&path, b"not a socket").expect("write");
    assert!(remove_stale_socket(&path).is_err());
    assert!(path.exists(), "the file must still be there");
    let _ = std::fs::remove_dir_all(&dir);
}
