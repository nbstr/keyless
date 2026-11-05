mod heartbeat;
mod socket;

use std::path::PathBuf;

// The socket cannot live in the scratch directory below: read the file for
// the measurement, and for why `TMPDIR` decided whether these tests passed.
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/support/short_socket.rs"
));

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyless-daemon-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}
