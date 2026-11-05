use super::fixtures::{request, scratch};
use super::init;
use crate::config::Config;
use crate::paths::Paths;
use std::io::Cursor;

#[test]
fn force_replaces_the_store_choice_but_keeps_declared_secrets() {
    // The defect: `render` always writes `"secrets": {}`, and `--force` was
    // the only path that reaches it with a config already on disk — so
    // switching the default backend silently discarded every declared
    // name. `--force` promises to replace the store choice, not the
    // account facts recorded under it.
    let dir = scratch("force-preserves-secrets");
    let paths = Paths::under(&dir);
    std::fs::create_dir_all(paths.config.parent().expect("a parent")).expect("mkdir");
    std::fs::write(
        &paths.config,
        r#"{"stores":{"proton":{"enabled":true},"default":"proton"},
            "secrets":{"HOME_WIFI":{"store":"proton","vault":"Personal",
                                     "item":"Router","field":"password"}}}"#,
    )
    .expect("write");

    let mut request = request(&paths, false);
    request.force = true;
    request.only = Some("keychain");

    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let code = init(&request, &mut Cursor::new(Vec::new()), &mut out, &mut err).expect("write");
    assert_eq!(code, 0);

    let written: Config =
        serde_json::from_str(&std::fs::read_to_string(&paths.config).expect("read"))
            .expect("valid");
    assert!(
        written.stores.keychain.enabled,
        "the store choice did not switch"
    );
    assert!(
        written.secrets.contains_key("HOME_WIFI"),
        "the declared name was lost across --force"
    );
    assert_eq!(
        written.secrets["HOME_WIFI"].item.as_deref(),
        Some("Router"),
        "the coordinate on the preserved name was not carried over intact"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn force_on_a_config_with_no_declared_secrets_writes_the_same_empty_map() {
    // `with_preserved_secrets` takes a different code path than a plain
    // `render()` the moment anything is preserved. Nothing to preserve
    // must still land on the same `"secrets": {}` a fresh install gets.
    let dir = scratch("force-nothing-to-preserve");
    let paths = Paths::under(&dir);
    std::fs::create_dir_all(paths.config.parent().expect("a parent")).expect("mkdir");
    std::fs::write(&paths.config, r#"{"stores":{"proton":{"enabled":true}}}"#).expect("write");

    let mut request = request(&paths, false);
    request.force = true;
    request.only = Some("keychain");

    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let code = init(&request, &mut Cursor::new(Vec::new()), &mut out, &mut err).expect("write");
    assert_eq!(code, 0);

    let written: Config =
        serde_json::from_str(&std::fs::read_to_string(&paths.config).expect("read"))
            .expect("valid");
    assert!(written.secrets.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_existing_config_is_never_clobbered_and_says_so() {
    let dir = scratch("idempotent");
    let paths = Paths::under(&dir);
    std::fs::create_dir_all(paths.config.parent().expect("a parent")).expect("mkdir");
    std::fs::write(&paths.config, "{\"secrets\":{\"MINE\":{}}}").expect("write");

    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    let code = init(
        &request(&paths, false),
        &mut Cursor::new(Vec::new()),
        &mut out,
        &mut err,
    )
    .expect("write");

    assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
    assert_eq!(
        std::fs::read_to_string(&paths.config).expect("read"),
        "{\"secrets\":{\"MINE\":{}}}",
        "init overwrote a config it was not asked to touch"
    );
    let text = String::from_utf8(out).expect("utf-8");
    assert!(text.contains("already exists"), "{text}");
    assert!(text.contains("--force"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
