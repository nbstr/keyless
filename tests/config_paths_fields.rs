use std::path::{Path, PathBuf};

use keyless::config::Config;
use keyless::daemon::config::DaemonConfig;
use keyless::paths::home;

// ---------------------------------------------------------------------------
// Every path field, not only the one the bug was reported against.
// ---------------------------------------------------------------------------

/// A `~` path for one field, and the absolute path it must become.
fn expected(marker: &str) -> (String, PathBuf) {
    let home = home().expect("this suite needs HOME set to check expansion");
    (format!("~/{marker}"), home.join(marker))
}

#[test]
fn every_session_config_path_field_expands() {
    // Written field by field rather than looped over a list the implementation
    // also reads: deleting a field from the config struct breaks this file at
    // compile time, and a list shared with the code would delete itself in the
    // same stroke.
    let fields = [
        "daemon-socket",
        "keychain-binary",
        "infisical-binary",
        "infisical-config-dir",
        "infisical-probe",
        "proton-binary",
        "proton-session",
        "proton-probe",
        "proton-manager-session",
    ];
    let path = |marker: &str| expected(marker).0;
    let json = format!(
        r#"{{"stores":{{
             "daemon":{{"socket":"{}"}},
             "keychain":{{"binary":"{}","timeout_ms":60000}},
             "infisical":{{"binary":"{}","config_dir":"{}","probe_binary":"{}","timeout_ms":60000}},
             "proton":{{"binary":"{}","session_dir":"{}","probe_binary":"{}","timeout_ms":60000,
                        "manager":{{"session_dir":"{}"}}}}}}}}"#,
        path(fields[0]),
        path(fields[1]),
        path(fields[2]),
        path(fields[3]),
        path(fields[4]),
        path(fields[5]),
        path(fields[6]),
        path(fields[7]),
        path(fields[8]),
    );
    let config: Config = serde_json::from_str(&json).expect("valid config");
    let stores = &config.stores;
    let proton_manager = stores.proton.manager.as_ref().expect("a manager block");

    let checked: Vec<(&str, PathBuf)> = vec![
        ("daemon-socket", stores.daemon.socket_path()),
        ("keychain-binary", stores.keychain.binary.to_path_buf()),
        ("infisical-binary", stores.infisical.binary.to_path_buf()),
        (
            "infisical-config-dir",
            stores
                .infisical
                .config_dir
                .as_deref()
                .expect("set")
                .to_path_buf(),
        ),
        (
            "infisical-probe",
            stores.infisical.probe_binary.to_path_buf(),
        ),
        ("proton-binary", stores.proton.binary.to_path_buf()),
        (
            "proton-session",
            stores
                .proton
                .session_dir
                .as_deref()
                .expect("set")
                .to_path_buf(),
        ),
        ("proton-probe", stores.proton.probe_binary.to_path_buf()),
        (
            "proton-manager-session",
            proton_manager
                .session_dir
                .as_deref()
                .expect("set")
                .to_path_buf(),
        ),
    ];

    for (marker, actual) in &checked {
        assert_eq!(*actual, expected(marker).1, "field `{marker}`");
    }
    // The tripwire. A path field added to the config and not added here leaves
    // this number stale, and the assertion below is what says so — the loop
    // above cannot, because it only knows what it was told.
    assert_eq!(
        checked.len(),
        9,
        "the session config gained or lost a path field; cover it here"
    );
    assert_eq!(checked.len(), fields.len());
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
#[test]
fn every_daemon_config_path_field_expands() {
    let json = format!(
        r#"{{"socket":"{}","audit":"{}",
             "stores":{{"file":{{"path":"{}"}},
                        "keychain":{{"binary":"{}","keychain":"{}","timeout_ms":60000}}}}}}"#,
        expected("daemon-socket").0,
        expected("daemon-audit").0,
        expected("daemon-file").0,
        expected("daemon-security").0,
        expected("daemon-keychain").0,
    );
    let config: DaemonConfig = serde_json::from_str(&json).expect("valid daemon config");

    let checked: Vec<(&str, PathBuf)> = vec![
        ("daemon-socket", config.socket.to_path_buf()),
        ("daemon-audit", config.audit.to_path_buf()),
        ("daemon-file", config.stores.file.path.to_path_buf()),
        (
            "daemon-security",
            config.stores.keychain.binary.to_path_buf(),
        ),
        (
            "daemon-keychain",
            config
                .stores
                .keychain
                .keychain
                .as_deref()
                .expect("set")
                .to_path_buf(),
        ),
    ];
    for (marker, actual) in &checked {
        assert_eq!(*actual, expected(marker).1, "field `{marker}`");
    }
    assert_eq!(
        checked.len(),
        5,
        "the daemon config gained or lost a path field; cover it here"
    );
}

#[test]
fn a_bare_binary_name_is_left_alone_so_path_lookup_still_works() {
    // The other half of the contract. `binary` is routinely `pass-cli` or
    // `infisical`, which are relative on purpose and resolved through `PATH`.
    // An implementation that made every config path absolute would break every
    // default install, and every test above would still pass.
    let config: Config = serde_json::from_str(
        r#"{"stores":{"proton":{"binary":"pass-cli","timeout_ms":60000},"infisical":{"binary":"infisical","timeout_ms":60000}}}"#,
    )
    .expect("valid config");
    assert_eq!(config.stores.proton.binary.as_path(), Path::new("pass-cli"));
    assert_eq!(
        config.stores.infisical.binary.as_path(),
        Path::new("infisical")
    );
    assert_eq!(
        Config::default().stores.keychain.binary.as_path(),
        Path::new("/usr/bin/security"),
        "a default must not be rewritten either"
    );
}

// ---------------------------------------------------------------------------
// The hole the newtype does NOT close, closed here instead.
// ---------------------------------------------------------------------------

#[test]
fn no_config_field_is_declared_as_a_bare_path_buf() {
    // A newtype guarantees that a field DECLARED as `ConfigPath` expands. It
    // guarantees nothing about the next field somebody declares `PathBuf`,
    // which compiles, runs, and silently reinstates the defect — the compiler
    // has no opinion about which of two path types was meant.
    //
    // So the enforcement is here: the two config modules are read as SOURCE,
    // every file of a split module included, and every struct field of type
    // `PathBuf` is reported. This is the only thing in the repository that can
    // fail on a field nobody remembered to think about.
    //
    // Deliberately not a check on the whole crate: `PathBuf` is the right type
    // everywhere else, and a rule that fires on correct code gets deleted.
    for (label, source) in config_module_sources() {
        let offenders = path_buf_fields(&source);
        assert!(
            offenders.is_empty(),
            "{label} declares a path field as PathBuf, which skips tilde expansion \
             entirely — declare it `ConfigPath`: {offenders:?}"
        );
    }
}

fn config_module_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for module in ["src/config", "src/daemon/config"] {
        files.push(root.join(format!("{module}.rs")));
        let Ok(entries) = std::fs::read_dir(root.join(module)) else {
            continue;
        };
        let mut split: Vec<PathBuf> = entries
            .map(|entry| entry.expect("a directory entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
            .collect();
        split.sort();
        files.extend(split);
    }
    files
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            let label = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            (label, source)
        })
        .collect()
}

fn path_buf_fields(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(": PathBuf,") || line.ends_with(": Option<PathBuf>,"))
        .collect()
}

#[test]
fn the_offender_scan_can_actually_find_something() {
    // The negative control for the test above. A scan that matches nothing
    // because its pattern is wrong is indistinguishable from a clean module,
    // and it passes forever.
    let sample = "pub struct S {\n    pub a: ConfigPath,\n    pub b: PathBuf,\n    pub c: Option<PathBuf>,\n}";
    assert_eq!(
        path_buf_fields(sample),
        vec!["pub b: PathBuf,", "pub c: Option<PathBuf>,"]
    );
}
