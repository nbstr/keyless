//! Asking the stores for every requested name, and sorting what came back by
//! what each answer does to the run.

use std::io::Write;
use std::thread;

use super::{Binding, RunRequest};
use crate::NAME;
use crate::secret::Secret;
use crate::store::{Registry, Resolution};

/// What a run does about one name, read off the store's verdict on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// The value goes into the child's environment.
    Inject,
    /// The child runs without the value: nothing was decided about the name.
    Degrade,
    /// The child never starts: a store declined the request, or holds no such
    /// name.
    Refuse,
}

/// The one place a verdict becomes a fate.
///
/// A store's own position on the request refuses: a name it does not hold, a
/// name it will not look up, or a caller it will not serve. Failing to get a
/// position degrades instead — silence, a store or daemon that errors, and an
/// ambiguity in routing, which is this machine's config rather than the name.
fn fate(resolution: &Resolution) -> Fate {
    match resolution {
        Resolution::Found { .. } => Fate::Inject,
        Resolution::Refused { .. } | Resolution::NotFound { .. } => Fate::Refuse,
        Resolution::Failed(_) | Resolution::Ambiguous { .. } => Fate::Degrade,
    }
}

/// What the stores answered, split into what injects, what degrades and what
/// refuses.
pub(super) struct Gathered {
    pub(super) resolved: Vec<(Vec<String>, Secret)>,
    pub(super) injected_names: Vec<String>,
    pub(super) unresolved: Vec<String>,
    pub(super) reasons: Vec<String>,
    pub(super) identities: Vec<String>,
    /// One line per refused request, as the caller spelled it. Any entry
    /// refuses the whole run.
    pub(super) refusals: Vec<String>,
}

/// Resolve every request and sort each answer by whether it can be injected.
pub(super) fn gather(
    request: &RunRequest<'_>,
    plans: Vec<Vec<String>>,
    notes: &mut dyn Write,
) -> Gathered {
    let mut resolved: Vec<(Vec<String>, Secret)> = Vec::new();
    let mut injected_names: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = request.unusable.to_vec();
    let mut reasons: Vec<String> = Vec::new();
    // Which backends answered, for the audit row. A `run` can only ever reach a
    // reader — the write identities are not in a `Registry` and cannot be —
    // so the row says `<store> (reader)` and a row that ever said `(manager)`
    // could not have come from here.
    let mut identities: Vec<String> = Vec::new();
    let mut refusals: Vec<String> = Vec::new();

    for ((binding, plan), resolution) in request.bindings.iter().zip(plans).zip(resolve_all(
        request.registry,
        request.bindings,
        notes,
    )) {
        if fate(&resolution) == Fate::Refuse {
            refusals.push(format!("`{}`: {}", binding.spelled(), resolution.reason()));
            continue;
        }
        match resolution {
            Resolution::Found { store, secret } => {
                let usable = !secret.expose().as_bytes().contains(&0);
                // Kept in `resolved` either way, because `resolved` is what the
                // masker is compiled from and a value that resolved is a value
                // worth redacting whether or not it can be injected.
                injected_names.push(binding.name.clone());
                resolved.push((plan, secret));
                if usable {
                    let identity = format!("{store} (reader)");
                    if !identities.contains(&identity) {
                        identities.push(identity);
                    }
                } else {
                    // An environment value is a NUL-terminated C string, so a
                    // value containing a NUL cannot be one. Reaching `execve`
                    // with it is not a degrade, it is `RunError::SpawnFailed`
                    // and exit 127 — the child never runs. Refused here, where
                    // it costs the documented degrade instead.
                    unresolved.push(binding.name.clone());
                    reasons.push(format!(
                        "{}: the value contains a NUL byte, which no environment variable can hold",
                        binding.name
                    ));
                }
            }
            other => {
                unresolved.push(binding.name.clone());
                reasons.push(format!("{}: {}", binding.name, other.reason()));
            }
        }
    }

    Gathered {
        resolved,
        injected_names,
        unresolved,
        reasons,
        identities,
        refusals,
    }
}

/// Ask every backend for every name at once.
///
/// # Why this is not a loop
///
/// A lookup's deadline is per-lookup, so sequentially N names that each hit it
/// cost N × the deadline. Measured 2026-08-08 against a backend that never
/// answers: **three names took 36.03 seconds before the child ran.** Thirty
/// names is five minutes of a terminal doing nothing, and the run does still
/// happen at the end of it — which is worse than failing, because nothing on
/// screen says waiting is the correct thing to do.
///
/// Concurrently, N names cost one deadline. That is the difference between a
/// pause and a hang, and the never-block invariant is about the second.
///
/// A backend that the OS will not give a thread for is resolved on this thread
/// instead: slower is not a failure, and [`thread::Builder`] is what makes that
/// a branch rather than a panic.
fn resolve_all(
    registry: &Registry,
    bindings: &[Binding],
    notes: &mut dyn Write,
) -> Vec<Resolution> {
    if bindings.len() < 2 {
        return bindings
            .iter()
            .map(|binding| registry.resolve(&binding.name))
            .collect();
    }

    let mut slots: Vec<Option<Resolution>> = bindings.iter().map(|_| None).collect();
    thread::scope(|scope| {
        let mut running = Vec::new();
        for (index, binding) in bindings.iter().enumerate() {
            let started = thread::Builder::new()
                .name(format!("keyless-resolve-{index}"))
                .spawn_scoped(scope, || registry.resolve(&binding.name));
            match started {
                Ok(handle) => running.push((index, handle)),
                Err(error) => {
                    let _ = writeln!(
                        notes,
                        "{NAME}: warning: cannot look `{}` up concurrently ({error}); \
                         doing it in turn",
                        binding.name
                    );
                    slots[index] = Some(registry.resolve(&binding.name));
                }
            }
        }
        for (index, handle) in running {
            slots[index] = Some(handle.join().unwrap_or_else(|_| {
                Resolution::Failed(vec![crate::error::StoreError::Unavailable {
                    store: "keyless".to_owned(),
                    detail: "the lookup ended unexpectedly".to_owned(),
                }])
            }));
        }
    });

    slots
        .into_iter()
        // Every slot is filled by one of the two arms above; this is the
        // expression that says so without an `unwrap`. `undeclared: false`
        // claims nothing about a config this expression never saw.
        .map(|slot| slot.unwrap_or(Resolution::NotFound { undeclared: false }))
        .collect()
}
