//! What `new` and `put` share: choosing the writer, recording the write, and
//! saying so when the name written is one nothing else will mention.

use std::io;

use keyless::audit::AuditLog;
use keyless::config::Config;
use keyless::paths::Paths;
use keyless::store::manage::manager;
use keyless::store::proton::Reason;
use keyless::{NAME, State, store};

/// Say so when a stored name is one nothing else in the tool will ever mention.
///
/// `put` and `new` accept an undeclared name on purpose — it routes to its own
/// account in the default store, and requiring a config edit before a first
/// write would put a text editor in front of the shortest safe path. But `ls`
/// and `doctor --probe` read the CONFIG, so an undeclared name is invisible to
/// both: `put` reports `stored`, and the two verbs a person then reaches for to
/// confirm it print nothing about it at all.
///
/// Three outputs that each look like a working tool, describing a name that is
/// really there. The write is fine; the silence afterwards is what needs a
/// sentence. On stderr, so `stored` stays the only thing on stdout.
pub(crate) fn warn_if_undeclared(config: &Config, name: &str) {
    if !config.secrets.contains_key(name) {
        eprintln!(
            "{NAME}: `{name}` is not declared in your config, so `{NAME} ls` will not list it \
             and `{NAME} doctor --probe` will not check it. The value is stored either way."
        );
    }
}

/// The writer for one name, or `None` after saying why there is not one.
///
/// Separate from the verb bodies because `new` and `put` must resolve the identity
/// by exactly the same rule: an explicit `--store`, then the name's own `store`
/// pin, then `stores.default`, then the single configured backend. Two copies of
/// that would eventually disagree about which identity writes.
pub(crate) fn writer_for(
    config: &Config,
    name: &str,
    requested: Option<&str>,
    verb: &str,
) -> Option<Box<dyn keyless::store::manage::Manage>> {
    let store = match store::choose_store(config, Some(name), requested) {
        Ok(store) => store,
        Err(problem) => {
            eprintln!("{NAME}: {problem}");
            return None;
        }
    };
    match manager(config, &store, &Reason::for_verb(verb)) {
        Ok(writer) => Some(writer),
        Err(error) => {
            eprintln!("{NAME}: {error}");
            None
        }
    }
}

/// Record the write and return its exit code.
///
/// The row carries the verb, the name, and the IDENTITY that wrote it — which is
/// the point of recording it at all. A row saying `proton (manager)` can only have
/// come from a write verb, and a `run` row can only ever say `(reader)`, so "did a
/// session ever act as the editor?" is answerable from the log rather than from
/// trust.
///
/// No value can be in the row: the masker is empty because this process no longer
/// holds the value by the time it is written, and there is no flag by which one
/// could have reached argv in the first place.
pub(crate) fn finish_write(
    verb: &str,
    name: &str,
    writer: &dyn keyless::store::manage::Manage,
    written: io::Result<keyless::cmd::write::Written>,
    paths: &Paths,
    no_audit: bool,
) -> i32 {
    let code = match written {
        Ok(written) => written.exit_code,
        Err(error) => {
            eprintln!("{NAME}: {error}");
            return 1;
        }
    };

    if !no_audit {
        let state = if code == 0 {
            State::Injected
        } else {
            State::Degraded
        };
        let names = vec![name.to_owned()];
        let unresolved = if code == 0 { Vec::new() } else { names.clone() };
        let event = keyless::audit::Event::new(
            verb,
            state,
            names,
            &std::env::args().collect::<Vec<_>>(),
            &keyless::mask::Masker::new(),
        )
        .with_unresolved(unresolved)
        .with_identities(vec![writer.identity()])
        .with_exit_code(code);
        if let Err(error) = AuditLog::new(paths.audit.clone()).append(&event) {
            eprintln!("{NAME}: warning: {error}");
        }
    }
    code
}
