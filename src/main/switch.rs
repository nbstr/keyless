//! `disable` and `enable`: confirming, switching the guards, and recording
//! every switch whether it ran or was refused.

use std::io::{self, IsTerminal};

use keyless::audit::AuditLog;
use keyless::cmd::setup::switch::{EXIT_REFUSED, confirm_switch, explain_refusal, switch_guards};
use keyless::cmd::status::Style;
use keyless::paths::Paths;
use keyless::{NAME, State};

use crate::args::ScopeArgs;

/// `disable` and `enable`, which are the same write with the bit flipped.
/// `disable` confirms at a terminal first and `enable` never asks — the
/// module doc of [`keyless::cmd::setup`] says why the switch is shaped so.
pub(crate) fn switch(scope: &ScopeArgs, enable: bool, paths: &Paths) -> i32 {
    let verb = if enable { "enable" } else { "disable" };
    let asked = if enable {
        None
    } else {
        confirm_or_refuse(verb, paths)
    };
    match asked {
        Some(code) => code,
        None => match switch_guards(
            &setup_paths(scope),
            Style::detect(io::stdout().is_terminal()),
            enable,
            &mut io::stdout(),
        ) {
            Ok(code) => {
                record_switch(
                    paths,
                    verb,
                    if enable { "guards-on" } else { "guards-off" },
                    code,
                );
                code
            }
            Err(error) => {
                eprintln!("{NAME}: {error}");
                record_switch(paths, verb, "failed", 1);
                1
            }
        },
    }
}

/// Ask before `verb` — `disable` or `uninstall` — is allowed to run.
///
/// `Some(code)` means the caller must stop here: the refusal is already on
/// stderr and already recorded. `None` means confirmed, and the caller
/// proceeds exactly as it would have before this existed. `enable` never
/// calls this at all — there is nothing here for it to confirm.
pub(crate) fn confirm_or_refuse(verb: &str, paths: &Paths) -> Option<i32> {
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let confirmation = match confirm_switch(verb, interactive, &mut stdin, &mut io::stdout()) {
        Ok(confirmation) => confirmation,
        Err(error) => {
            eprintln!("{NAME}: {error}");
            return Some(1);
        }
    };
    match confirmation {
        Ok(()) => None,
        Err(refusal) => {
            let _ = explain_refusal(verb, refusal, &mut io::stderr());
            record_switch(paths, verb, refusal.decision(), EXIT_REFUSED);
            Some(EXIT_REFUSED)
        }
    }
}

/// Record one switch-verb invocation — confirmed and done, or refused —
/// ignoring `--no-audit`; see that flag's own doc for why.
pub(crate) fn record_switch(paths: &Paths, verb: &str, decision: &str, code: i32) {
    let state = if code == 0 {
        State::Injected
    } else {
        State::Degraded
    };
    let event = keyless::audit::Event::new(
        verb,
        state,
        Vec::new(),
        &std::env::args().collect::<Vec<_>>(),
        &keyless::mask::Masker::new(),
    )
    .with_decision(decision)
    .with_exit_code(code);
    if let Err(error) = AuditLog::new(paths.audit.clone()).append(&event) {
        eprintln!("{NAME}: warning: {error}");
    }
}

/// Resolve the setup paths from the environment and the flags on top of it.
pub(crate) fn setup_paths(scope: &ScopeArgs) -> keyless::paths::SetupPaths {
    let mut resolved = keyless::paths::SetupPaths::discover();
    if let Some(dir) = &scope.claude_dir {
        resolved.claude_dir = dir.clone();
    }
    if let Some(path) = &scope.receipt {
        resolved.receipt = path.clone();
    }
    resolved
}
