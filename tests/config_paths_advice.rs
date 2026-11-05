mod config_paths_support;
mod support;

use std::path::Path;

use keyless::paths::ConfigPath;

use config_paths_support::{Fixture, stderr_of, stdout_of};

// ---------------------------------------------------------------------------
// The advice must be advice this build accepts.
// ---------------------------------------------------------------------------

/// Every `"key": "value"` a piece of text hands somebody to paste into a config.
///
/// Backslashes are stripped first so the same scan reads a Rust string literal
/// (`\"session_dir\": \"~/…\"`) and a Markdown code block identically.
fn config_values_advised(text: &str) -> Vec<String> {
    let text = text.replace('\\', "");
    let mut found = Vec::new();
    let mut rest = text.as_str();
    while let Some(at) = rest.find("\": \"") {
        rest = &rest[at + 4..];
        if let Some(end) = rest.find('"') {
            let value = &rest[..end];
            if !value.is_empty() {
                found.push(value.to_owned());
            }
            rest = &rest[end..];
        }
    }
    found
}

/// The whole point: this build must never print, or document, a path it refuses.
fn assert_advice_is_accepted(label: &str, text: &str, least: usize) {
    let advised = config_values_advised(text);
    for value in &advised {
        assert!(
            ConfigPath::expand(value).is_ok(),
            "{label} tells the reader to write `{value}`, which this build REFUSES: {:?}",
            ConfigPath::expand(value).err()
        );
    }
    // Without this, a scan whose pattern stopped matching passes forever — the
    // exact shape of false green a filtered test run has.
    assert!(
        advised.len() >= least,
        "{label}: the scan found only {} config values, so it has stopped reading the text",
        advised.len()
    );
}

#[test]
fn the_advice_scan_can_actually_find_something() {
    // The negative control. A refused value has to be detectable by this scan,
    // or every assertion built on it is vacuous.
    let sample = r#"set \"session_dir\": \"~bob/x\" and \"binary\": \"pass-cli\""#;
    let advised = config_values_advised(sample);
    assert_eq!(advised, vec!["~bob/x".to_owned(), "pass-cli".to_owned()]);
    assert!(ConfigPath::expand(&advised[0]).is_err());
    assert!(ConfigPath::expand(&advised[1]).is_ok());
}

#[test]
fn the_missing_session_dir_remedy_advises_a_path_this_build_accepts() {
    // The message a `doctor` reader is handed. It carried `~/.keyless-pass-session`
    // while `~` was taken literally, so following it produced the defect.
    let fixture = Fixture::new("remedy-session");
    let path = fixture.dir.join("no-session.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "proton":{{"enabled":true,"binary":"{}","timeout_ms":60000}}}}}}"#,
            fixture.binary.display()
        ),
    )
    .expect("write config");

    let report = stdout_of(&fixture.keyless(&path, Some(&fixture.home), &["doctor"]));
    assert!(report.contains("session_dir` is not set"), "{report}");
    assert_advice_is_accepted("the missing-session_dir remedy", &report, 1);
    assert!(
        report.contains("expanded"),
        "the remedy must say a leading `~` is expanded, or a reader has no reason \
         to trust a tilde inside JSON: {report}"
    );
}

#[test]
fn the_manager_remedy_advises_a_path_this_build_accepts() {
    let fixture = Fixture::new("remedy-manager");
    let path = fixture.dir.join("no-manager.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "proton":{{"enabled":true,"binary":"{}","timeout_ms":60000,
                            "session_dir":"/tmp/keyless-reader"}}}},
               "secrets":{{"HOME_WIFI":{{"vault":"V","item":"I","field":"password"}}}}}}"#,
            fixture.binary.display()
        ),
    )
    .expect("write config");

    let stderr = stderr_of(&fixture.keyless(&path, Some(&fixture.home), &["new", "HOME_WIFI"]));
    assert!(stderr.contains("agent access grant"), "{stderr}");
    assert_advice_is_accepted("the mint-a-manager-token remedy", &stderr, 1);
    assert!(stderr.contains("expanded"), "{stderr}");
    assert!(
        stderr.contains("must not be relative"),
        "the remedy must rule out the other spelling of the same defect: {stderr}"
    );
}

#[test]
fn the_readme_never_advises_a_config_path_this_build_refuses() {
    // The documentation is read far more often than either message above, and
    // it is the one surface no runtime check can reach. Bound to the parser
    // here, so a `~user/…` or `$HOME/…` written into an example fails the suite
    // rather than teaching somebody the defect.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut pages = vec![root.join("README.md")];
    for entry in std::fs::read_dir(root.join("docs/guide")).expect("docs/guide is readable") {
        pages.push(entry.expect("a directory entry").path());
    }
    let mut advised = 0;
    for page in &pages {
        let text = std::fs::read_to_string(page)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", page.display()));
        assert_advice_is_accepted(&page.display().to_string(), &text, 0);
        advised += config_values_advised(&text).len();
    }
    assert!(
        advised >= 20,
        "the README and its guide pages hold only {advised} config values, so the scan has \
         stopped reading them"
    );
}
