//! The mutation baseline must send people through the queue, not straight at
//! their machine.
//!
//! `.github/mutants-baseline.txt` opened for a long time with a runnable bare
//! `cargo mutants` command under the word REGENERATE, and people ran it, because
//! that is what the file said to do. The campaign is about forty minutes of
//! saturated CPU; on a shared workstation it starves every other job behind one
//! queue. The command became a CI dispatch, and when the workflows were deleted
//! -- the account has no Actions billing, so every run was red for reasons that
//! had nothing to do with the code -- it became `scripts/mutants.sh`.
//!
//! The destination changed twice; the thing being defended never did. It was
//! never "run it on a server". It was "do not let one command eat the machine".
//! `scripts/mutants.sh` runs the campaign inside a pinned Linux container with
//! a memory limit, so a mutant that allocates without end is killed by the
//! kernel rather than by the operator noticing. A queue cap was tried first and
//! is NOT the guard: admission is decided when a job asks, and a job already
//! running is not made smaller by a limit it already passed.
//!
//! That fix is one comment block, and a comment block is exactly the kind of
//! thing somebody restores while being helpful. This is the ratchet that stops
//! it going back. It is narrow because it has to be: nothing checked into a git
//! tree can refuse a `cargo mutants` typed into a shell. Refusing the command
//! itself is a job for a tool that sits in front of the shell -- which on this
//! machine exists, and is exactly what the script routes through.
//!
//! So the guard is narrow on purpose. It does not ban discussing the tool — the
//! file has to name it to explain itself, and both documents do. It bans the one
//! shape a reader COPIES: an indented, runnable command line.

use std::path::{Path, PathBuf};

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn baseline_path() -> PathBuf {
    manifest_dir().join(".github").join("mutants-baseline.txt")
}

/// A line that a reader can copy and run, as opposed to prose that names the
/// tool. Commands in these comment files are written indented under a blank
/// comment line; prose keeps the tool in backticks mid-sentence.
fn runnable_local_campaign_lines(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| {
            let body = line.trim_start().trim_start_matches('#').trim_start();
            // Indented under the comment marker is what makes it a command
            // block rather than a sentence.
            let indented = line.trim_start().starts_with("#  ");
            indented && body.starts_with("cargo mutants")
        })
        .collect()
}

#[test]
fn the_baseline_sends_a_regeneration_to_the_capped_campaign() {
    let text = std::fs::read_to_string(baseline_path()).expect("the baseline is readable");
    assert!(
        text.contains("scripts/mutants.sh"),
        "`.github/mutants-baseline.txt` no longer tells anyone HOW to regenerate \
         itself. A baseline nobody can re-derive gets hand-edited, and a \
         hand-edited baseline is a gate that agrees with whatever somebody typed."
    );
}

#[test]
fn the_baseline_hands_nobody_a_local_campaign_to_copy() {
    let text = std::fs::read_to_string(baseline_path()).expect("the baseline is readable");
    let found = runnable_local_campaign_lines(&text);
    assert!(
        found.is_empty(),
        "`.github/mutants-baseline.txt` carries a bare runnable campaign again:\n  {}\n\
         The campaign of record is `scripts/mutants.sh`, which runs inside a \
         memory-capped Linux container; a bare invocation has no limit on it at \
         all, and a campaign deliberately compiles programs that are WRONG — a \
         wrong program is entitled to allocate until something stops it, and \
         without the cap nothing does. It also cannot regenerate \
         this file, whose survivors were measured on Linux. Point at the script \
         instead. Naming the tool in prose is fine — this only refuses an \
         indented command line.",
        found.join("\n  ")
    );
}

#[test]
fn the_detector_reads_a_command_block_and_not_a_sentence() {
    // The control, and the reason the case above is not vacuous. Both documents
    // legitimately name the tool in prose, so a detector that matched any
    // mention would fire on correct text — and one that matched nothing would
    // pass forever. This pins both directions against planted samples rather
    // than against the live file, which is expected to contain only the second.
    let command_block = "#\n#     cargo mutants -f 'src/mask/**' --jobs 2\n#\n";
    assert_eq!(
        runnable_local_campaign_lines(command_block).len(),
        1,
        "the detector did not see a runnable command block, so the guard above \
         would pass no matter what the baseline said"
    );

    let prose = "# This used to be a local `cargo mutants` invocation, and that\n\
                 # is why the line is now a dispatch.\n";
    assert!(
        runnable_local_campaign_lines(prose).is_empty(),
        "the detector fired on prose that merely names the tool. A guard that \
         refuses the explanation of itself is one somebody deletes."
    );
}
