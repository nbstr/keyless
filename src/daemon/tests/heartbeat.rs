use super::{scratch, short_socket_path};
use crate::attest::Policy;
use crate::daemon::config::DaemonConfig;
use crate::daemon::{Daemon, Running};

#[test]
fn a_denied_request_still_hears_the_daemon_while_its_audit_row_waits_on_the_lock() {
    // A denial's audit row is written under the same exclusive lock as an
    // allow's, and a heartbeat scoped to the lookup never covered it: a
    // refused client waiting on a busy log heard nothing and reported a
    // wedge, not a refusal. Held from outside for longer than the
    // deadline, the lock stands in for any other connection thread inside
    // a slow append.
    use crate::ipc::client::Client;
    use crate::ipc::protocol::{Reply, Request};
    use std::time::Duration;

    let dir = scratch("denied-under-held-lock");
    let socket = short_socket_path(&dir);
    let config = DaemonConfig {
        socket: socket.clone().into(),
        audit: dir.join("audit.jsonl").into(),
        idle_timeout_seconds: 5,
        stores: crate::daemon::config::DaemonStores {
            file: crate::daemon::config::FileStoreConfig {
                enabled: true,
                path: dir.join("secrets.json").into(),
            },
            ..Default::default()
        },
        ..DaemonConfig::default()
    };
    std::fs::write(&*config.stores.file.path, b"{}").expect("write secrets");
    // Nothing pinned, so this process is refused, and refused BEFORE any
    // store is asked: the only slow step on this path is the daemon's own
    // audit append.
    let daemon = Daemon::bind(&config, Policy::new()).expect("bind");
    let running = Running::spawn(daemon, &config).expect("start the accept loop");

    let silence = Duration::from_secs(1);
    let client = Client::new(running.socket().to_path_buf(), silence);

    // The control: an unheld log answers the refusal at once.
    match client.request(&Request::resolve("DECOY")) {
        Ok(Reply::Denied(_)) => {}
        other => panic!("an unpinned daemon must refuse at once, got {other:?}"),
    }

    let hold = Duration::from_millis(2_500);
    let log = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .open(&config.audit)
        .expect("open the daemon's audit log");
    log.lock().expect("hold the audit log's lock");
    let holder = std::thread::spawn(move || {
        std::thread::sleep(hold);
        log.unlock().expect("release the audit log's lock");
    });

    let started = std::time::Instant::now();
    let reply = client.request(&Request::resolve("DECOY"));
    holder.join().expect("the lock holder");
    assert!(
        started.elapsed() >= hold - Duration::from_millis(100),
        "the reply came back before the lock was released, so the denial row was \
         never behind it and this proves nothing: {:?}",
        started.elapsed()
    );
    match reply {
        Ok(Reply::Denied(_)) => {}
        other => panic!(
            "a daemon that has refused and is waiting on its own log must keep the \
             client waiting with it, got {other:?}"
        ),
    }

    drop(running);
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_dir_all(&dir);
}
