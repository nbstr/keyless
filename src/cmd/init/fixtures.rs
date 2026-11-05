use super::InitRequest;
use crate::cmd::status::Style;
use crate::paths::Paths;

pub(super) fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyless-init-{}-{tag}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

pub(super) fn request<'a>(paths: &'a Paths, interactive: bool) -> InitRequest<'a> {
    InitRequest {
        paths,
        force: false,
        assume_yes: false,
        only: None,
        interactive,
        install_hooks: false,
        report_guards: true,
        style: Style::PLAIN,
    }
}
