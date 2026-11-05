use std::path::Path;
use std::path::PathBuf;

use super::{CONCEALED, INFISICAL_DECOY, NEIGHBOUR_DECOY, NEIGHBOUR_KEY};

/// How a fake network-backed CLI should behave.
///
/// The Infisical fake reproduces behaviour **measured** against `infisical`
/// 0.43.114 on 2026-08-06, including the exact stderr wording the adapter reads
/// to tell "the variable is unset" from "the CLI itself failed". The Proton
/// fake reproduces the shapes measured against `pass-cli` 2.2.5 on 2026-08-08
/// and recorded in `src/store/proton.rs` — the record keys, the reference
/// format and the coloured stderr — and, where nothing was measured, the
/// vendor's documented contract. A disagreement between this fake and the real
/// CLI is a bug in this fake, never a finding about the adapter.
pub enum Backend {
    /// Inject the value and exec the probe, as a working `run` does.
    Injects(&'static str),
    /// Inject the WHOLE path's worth of secrets — [`INFISICAL_DECOY`] under
    /// `DECOY` and [`NEIGHBOUR_DECOY`] under [`NEIGHBOUR_KEY`], which nobody
    /// asks for — and then run whatever follows `--`, verbatim.
    ///
    /// That is what `infisical run` does, and [`Backend::Injects`] does not
    /// model it: it sets exactly the one name the probe named, so a tool that
    /// handed its child an entire vault would look identical against it.
    InjectsWholeVault,
    /// Exec the probe with nothing injected, then report the child's status the
    /// way the CLI does.
    Unset,
    /// Inject an empty value.
    Empty,
    /// Fail before the probe ever runs — no project, bad token, no network.
    OwnFailure,
    /// Never answer. Stands in for a black-holed connection.
    Hangs,
    /// Honour neither `--no-masking` nor the value: hand back the concealment
    /// placeholder. Only reachable on the Proton path.
    Concealed,
    /// Read what to do from a control file beside the stub, on every call, and
    /// hand out a value that is different on each one.
    ///
    /// # Why the other variants cannot stand in
    ///
    /// Every arm above is fixed when the stub is written, so one test gets one
    /// behaviour for its whole run. The daemon's cache is only observable
    /// ACROSS calls — a value held while the vendor is slow, a value kept while
    /// it cannot connect, a value evicted when it answers about the item — so a
    /// case about it needs the vendor to answer one way and then another,
    /// against a daemon that keeps running in between. The two timings on offer
    /// are also instant and [`Backend::Hangs`]'s sixty seconds, and neither is a
    /// vendor that is merely slower than a window.
    ///
    /// So this arm reads [`set_next_call`]'s file each time it runs, and
    /// [`vendor_call_count`] is the tally it appends to. Which value came back
    /// then answers "was the store asked?" on its own — see [`vendor_decoy`].
    Controlled,
}

impl Backend {
    /// The shell fragment that runs, or declines to run, the probe.
    ///
    /// `$child` and `$key` are already set by the caller's preamble. `dir` is
    /// the stub's own directory, which only [`Backend::Controlled`] reads —
    /// every other arm decides everything when the stub is written.
    pub(super) fn body(&self, dir: &Path) -> String {
        match self {
            Backend::Injects(value) => {
                format!("exec /usr/bin/env \"$key={value}\" \"$child\" \"$key\"\n")
            }
            // Two deliberate differences from the arm above, and both are the
            // point. Both names are LITERAL, because what a vault holds does
            // not depend on what was asked for — `"$key"` would make the
            // fixture's contents follow the request, which is the coupling the
            // case using this exists to deny. And `"$@"` rather than `"$child"
            // "$key"`, because the vendor runs whatever it was handed after
            // `--`: a fixture that re-spells the probe's two arguments could
            // not show a longer command nested under it. For the two-argument
            // probe the two spellings are identical.
            Backend::InjectsWholeVault => format!(
                "exec /usr/bin/env \"DECOY={INFISICAL_DECOY}\" \
                 \"{NEIGHBOUR_KEY}={NEIGHBOUR_DECOY}\" \"$@\"\n"
            ),
            Backend::Concealed => {
                format!("exec /usr/bin/env \"$key={CONCEALED}\" \"$child\" \"$key\"\n")
            }
            Backend::Empty => "exec /usr/bin/env \"$key=\" \"$child\" \"$key\"\n".to_owned(),
            // The wording is the vendor's, quoted because the adapter reads it.
            Backend::Unset => "\"$child\" \"$key\"\n\
                 status=$?\n\
                 if [ $status -ne 0 ]; then\n\
                 \x20 echo \"failed to wait for command termination: exit status $status\" >&2\n\
                 fi\n\
                 exit $status\n"
                .to_owned(),
            Backend::OwnFailure => "echo 'Please either run infisical init to connect to a \
                 project or pass in project id with --projectId flag' >&2\nexit 1\n"
                .to_owned(),
            Backend::Hangs => "sleep 60\n".to_owned(),
            // The tally is appended BEFORE anything else this call does, so a
            // vendor that is sleeping or about to fail is still counted as
            // having been asked. A test that waits for the count to move is
            // therefore waiting for the spawn, never for the answer.
            //
            // `wc -l` is left-padded on this platform, hence the `tr`.
            Backend::Controlled => format!(
                "echo one >> '{calls}'\n\
                 call=$(wc -l < '{calls}' | tr -d ' ')\n\
                 next=$(cat '{next}' 2>/dev/null || echo answers)\n\
                 case \"$next\" in\n\
                 \x20 slow:*) sleep \"${{next#slow:}}\" ;;\n\
                 \x20 fails:*) printf '%s\\n' \"${{next#fails:}}\" >&2; exit 1 ;;\n\
                 esac\n\
                 value=$(printf '%s%03d' '{stem}' \"$call\")\n\
                 exec /usr/bin/env \"$key=$value\" \"$child\" \"$key\"\n",
                calls = vendor_calls_path(dir).display(),
                next = next_call_path(dir).display(),
                stem = CONTROLLED_STEM,
            ),
        }
    }
}

/// What the controlled stand-in does on its next call.
///
/// A separate type from [`Backend`], because it names a MOMENT rather than a
/// fixture: one stub meets several of these while one daemon keeps running.
pub enum NextCall {
    /// Answer at once, with this call's own decoy.
    Answers,
    /// Sleep this long, then answer. For a vendor that has to lose a race
    /// against one of the daemon's windows.
    Slow(std::time::Duration),
    /// Print this on stderr and exit 1, having run no child. The adapter reads
    /// the sentence to decide whether the vendor answered ABOUT the item or
    /// never reached the service, so the wording is the input under test.
    Fails(&'static str),
}

/// The stem every controlled decoy is built on.
///
/// Long and distinctive for the reason every other decoy here is: a grep for it
/// in output that should hold no value means a real leak.
const CONTROLLED_STEM: &str = "decoy-Wrm4-controlled-vendor-answer-";

/// The decoy [`Backend::Controlled`] hands out on its `call`th call.
///
/// Different on every call, which is what lets a case assert "the store was not
/// asked" by comparing a string rather than by timing anything: a value from
/// call 1 coming back a second time cannot have been fetched.
///
/// Two calls in flight at once may read the same tally and hand out the same
/// decoy. A case that overlaps two calls asserts on [`vendor_call_count`]
/// instead.
#[must_use]
pub fn vendor_decoy(call: usize) -> String {
    format!("{CONTROLLED_STEM}{call:03}")
}

/// Tell the controlled stand-in what to do from now on.
///
/// Takes effect on the next call to START. A call already running has read the
/// file already, so a test that needs the change to bite waits for the running
/// one first — [`vendor_call_count`] is how.
pub fn set_next_call(dir: &Path, next: &NextCall) {
    let encoded = match next {
        NextCall::Answers => "answers".to_owned(),
        NextCall::Slow(delay) => format!("slow:{}", delay.as_secs_f64()),
        NextCall::Fails(said) => {
            assert!(
                !said.contains('\n'),
                "a refusal is one line: the stub reads this file with `cat` and matches on \
                 its prefix, so a second line would arrive as part of the sentence"
            );
            format!("fails:{said}")
        }
    };
    std::fs::write(next_call_path(dir), encoded).expect("write the vendor's next call");
}

/// How many times the controlled stand-in has been asked for a value.
///
/// Counts the value-reading verb only. `item list` has its own tally — see
/// [`listing_count`] — because a listing is memoised for its own window and a
/// combined count could not say which verb moved.
#[must_use]
pub fn vendor_call_count(dir: &Path) -> usize {
    std::fs::read_to_string(vendor_calls_path(dir))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

fn vendor_calls_path(dir: &Path) -> PathBuf {
    dir.join("vendor.calls")
}

fn next_call_path(dir: &Path) -> PathBuf {
    dir.join("vendor.next")
}
