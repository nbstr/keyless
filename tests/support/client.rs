use std::path::Path;
use std::path::PathBuf;

/// Write a daemon-side secrets file at mode 0600.
pub fn write_secrets(path: &Path, entries: &[(&str, &str)]) {
    let body: std::collections::BTreeMap<&str, &str> = entries.iter().copied().collect();
    std::fs::write(path, serde_json::to_vec(&body).expect("encode")).expect("write secrets");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

/// A session config that routes through `socket` and has no local fallback.
pub fn client_config(socket: &Path, timeout_ms: u64) -> keyless::config::Config {
    serde_json::from_str(&format!(
        r#"{{"stores":{{"daemon":{{"enabled":true,"socket":"{}","timeout_ms":{timeout_ms}}}}}}}"#,
        socket.display()
    ))
    .expect("valid client config")
}

/// Locate one of the `examples/` binaries that `cargo test` has built.
///
/// The test binary lives at `target/<profile>/deps/<name>-<hash>`, so the
/// examples are two directories up and one across. Asserted rather than
/// assumed: a silently missing peer would make an adversarial test pass by
/// never running the attack.
pub fn example_binary(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary knows its own path");
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile>/deps/<test>");
    let path = profile_dir.join("examples").join(name);
    assert!(
        path.is_file(),
        "example `{name}` was not built; expected it at {}",
        path.display()
    );
    assert_not_stale(&path);
    path
}

/// Refuse to run an attack against a peer built from older source.
///
/// `cargo test --test <name>` does **not** rebuild examples. So editing a peer
/// and re-running one test file exercises the previous binary, and every
/// adversarial test passes or fails for reasons that have nothing to do with
/// the change being made. That is not hypothetical — it cost two debugging
/// cycles on this suite, during which two correct fixes read as no-ops.
///
/// The whole run is aborted rather than the test skipped: a skipped security
/// test is a green one.
fn assert_not_stale(binary: &Path) {
    let built = match std::fs::metadata(binary).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(_) => return,
    };
    let sources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    let newest = newest_mtime(&sources);
    if let Some(newest) = newest
        && newest > built
    {
        panic!(
            "{} is older than the sources in {}. `cargo test --test <name>` does not \
             rebuild examples — run `cargo build --examples` first, or `cargo test` \
             with no --test filter.",
            binary.display(),
            sources.display()
        );
    }
}

fn newest_mtime(dir: &Path) -> Option<std::time::SystemTime> {
    let mut newest = None;
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let candidate = if path.is_dir() {
            newest_mtime(&path)
        } else {
            entry.metadata().and_then(|m| m.modified()).ok()
        };
        if let Some(candidate) = candidate
            && newest.is_none_or(|current| candidate > current)
        {
            newest = Some(candidate);
        }
    }
    newest
}
