#!/usr/bin/env bash
# The mutation campaign over the Rust crate's security core.
#
# ---------------------------------------------------------------------------
# Why this runs on Linux, in a container, and never on the host
# ---------------------------------------------------------------------------
#
# Two independent reasons. Either one alone would be enough.
#
# 1. THE BASELINE IS LINUX-DERIVED. `.github/mutants-baseline.txt` records the
#    survivors of a campaign that ran `runs-on: ubuntu-latest`. Which mutants
#    survive depends on which tests RUN, and this suite ignores a different set
#    per platform. A macOS campaign diffed against that file reports differences
#    of PLATFORM rather than of coverage, every time, for as long as anyone
#    leaves it running -- and a gate that reds for a reason nobody can act on is
#    a gate that gets deleted.
#
# 2. ONLY A CGROUP CAN BOUND THE MEMORY. A campaign deliberately compiles wrong
#    programs, and a wrong program may allocate without end. Measured on
#    2026-08-22: `replace += with -= in Masker::scan` turned a loop counter
#    around and allocates until something stops it. Uncapped, the thing that
#    stops it is the operator noticing.
#
# ---------------------------------------------------------------------------
# What does NOT protect the machine, since both were tried
# ---------------------------------------------------------------------------
#
# cargo-mutants' own timeout does not. It was working correctly that day -- it
# had auto-set 390 seconds and was enforcing it. A timeout bounds TIME. Nothing
# about 390 seconds prevents allocating every page in the machine first.
#
# `cq` does not, and an earlier version of this file wrongly said it did. The
# queue decides admission when a job ASKS; a job already running is not made
# smaller by the cap it already passed. Being in the queue is still worth having
# -- it stops two campaigns starting at once -- but it is not the guard.
#
# `--memory` on the container IS the guard: the kernel kills the offending
# process at the limit, cargo-mutants records the outcome, the campaign carries
# on, and the host never participates. Verified on 2026-08-22 by deliberately
# allocating past the cap inside the image: exit 137, host untouched.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib.sh
source scripts/linux.sh

# The one scope .github/mutants-baseline.txt describes. Any other scope is
# REPORTED and never diffed -- a baseline describes one scope, and checking it
# against a different one would red every time and mean nothing.
DEFAULT_SCOPE='src/mask/** src/secret.rs src/audit/**'
# A floor on the DEFAULT scope only, and it is checked nowhere else. This number
# describes one glob set against one baseline: it says "the campaign the baseline
# was recorded from still generates about as much as it did". Applied to a scope
# somebody chose in order to look at one module, it is a number about a different
# question, and it aborted every such run BEFORE the survivor list was written --
# which made the only reporting an exploratory run produces unreachable from the
# exploratory runs the scope argument exists for.
MUTANT_FLOOR=280
BASELINE=.github/mutants-baseline.txt
# The scope travels in an ENVIRONMENT VARIABLE across the container boundary,
# never as argv. It is a list of GLOBS, and cargo-mutants is the thing meant to
# interpret them -- a shell that expands `src/mask/**` first hands the campaign
# an explicit file list, which is a different string from DEFAULT_SCOPE, which
# silently turns the baseline diff off. Measured 2026-08-22: a full 320-mutant
# campaign ran and reported "scope is not the default, so there is no baseline
# to diff against", so the gate produced no verdict while looking like it had.
SCOPE="${KEYLESS_SCOPE-${*:-$DEFAULT_SCOPE}}"
OUT=mutants-run

# Not already inside the pinned Linux? Go there and re-enter this same file, so
# there is exactly one copy of every assertion below.
if [ -z "${KEYLESS_IN_LINUX_GATE-}" ]; then
  if ! linux_available; then
    echo "no container runtime is answering, so there is no capped Linux to" >&2
    echo "run this on. Uncapped is not an option here: a runaway mutant took" >&2
    echo "take every page this machine has, and a timeout will not stop it." >&2
    echo "Start a container runtime and try again." >&2
    exit 1
  fi
  linux_image_ready || exit 1
  # Through the queue as well, where one answers: the cgroup keeps the campaign
  # from eating the machine, and the queue keeps two campaigns from starting.
  # Different jobs, both worth doing, neither a substitute for the other.
  export KEYLESS_SCOPE="$SCOPE"
  if command -v cq > /dev/null 2>&1; then
    cq run --kind mutants -- bash -c \
      'source scripts/linux.sh && linux_run "keyless-mutants-$$" \
         env KEYLESS_IN_LINUX_GATE=1 KEYLESS_SCOPE="$KEYLESS_SCOPE" \
         bash scripts/mutants.sh'
  else
    linux_run "keyless-mutants-$$" \
      env KEYLESS_IN_LINUX_GATE=1 KEYLESS_SCOPE="$SCOPE" bash scripts/mutants.sh
  fi
  exit $?
fi

if ! command -v cargo-mutants > /dev/null 2>&1; then
  echo "cargo-mutants is not in the image. Rebuild it: docker build -f docker/Dockerfile docker" >&2
  exit 1
fi

# The campaign gets its OWN target directories, one per copied tree, which is
# cargo-mutants' default and is why this unsets rather than sets.
#
# `CARGO_TARGET_DIR` is set image-wide to a cache volume, which is right for
# every other job here because their source is always /work. It is WRONG for
# this one: cargo-mutants builds each mutant in its own copy under /tmp, and a
# shared target directory hands them each other's artifacts. `CARGO_MANIFEST_DIR`
# is baked in by `env!` at COMPILE time, so binaries cached from one copied tree
# carry a path that no longer exists. Measured 2026-08-22: 31 tests failed
# against `/tmp/cargo-mutants-work-au0dHI.tmp`, a directory deleted hours
# earlier, and clearing the volume alone took it back to 1.
unset CARGO_TARGET_DIR

# An ARRAY, not a string. A string of arguments has to be re-expanded at the
# call site to become arguments again, and that second expansion globs: measured
# 2026-08-22, `-f src/mask/**` became `-f src/mask/encodings.rs src/mask/mod.rs`
# and cargo-mutants refused with `unexpected argument`. `set -f` around the loop
# alone does not help, because the damage happens where the string is USED.
# Array expansion is never globbed, so the globs reach cargo-mutants intact --
# which is the point, since interpreting them is its job and not the shell's.
files=()
set -f
for glob in $SCOPE; do files+=(-f "$glob"); done
set +f
echo "${BOLD}mutants${OFF} ${DIM}scope: $SCOPE${OFF}"
echo "${DIM}~40 minutes for the default scope, inside the pinned Linux, memory capped.${OFF}"
echo "${DIM}The python hook pack is a SEPARATE campaign: hooks/tests/mutate.py${OFF}"

# THE FLAGS ARE PART OF THE MEASUREMENT. The survivor set is a property of the
# method as much as of the code: change `--jobs` or the timeout multiplier and
# mutants move between "timed out" and "caught" for reasons that have nothing to
# do with a test.
#
# This file is the only thing that records `.github/mutants-baseline.txt` and
# the only thing that checks it. There is no second runner to disagree with, so
# nothing outside this file constrains what is written below -- and nothing
# outside it will notice a flag that moves the survivor set either. A flag
# changed here is paid for by re-recording the baseline in the SAME commit.
#
# `--no-fail-fast` is not one of those flags, and that is worth writing down
# because it looks obviously right and gets proposed again. cargo-mutants
# classifies a mutant by the EXIT STATUS of `cargo test`, and fail-fast decides
# only what runs AFTER something has already failed -- that is, only when the
# status is already non-zero. The status is therefore invariant under it, and so
# is the survivor set. Measured 2026-08-23 on a crate built for the question:
# with one test failing for a reason unrelated to any mutation, the campaign
# reports every mutant caught and exits 0, hiding three real survivors --
# identically with the flag and without it. What the flag WOULD buy is every
# caught mutant running the whole remaining suite after the failure that already
# caught it, several hundred times over. It does not close the hole below.
#
# The output directory is DESTROYED first, and this is the most important line
# in the file. cargo-mutants refused its arguments on 2026-08-22 and tested
# nothing, and the checks below then read the PREVIOUS run's `outcomes.json`,
# still on disk, and reported "the surviving mutants are exactly the 2 recorded
# in the baseline". A campaign that never ran had produced a passing verdict.
#
# Every guard downstream asks "is there an outcomes.json and what does it say".
# None of them can tell last week's answer from this minute's. Removing it is
# what makes "the file exists" mean "this run wrote it".
rm -rf "$OUT"

# Redirected, never piped: a pipeline reports its last stage's status.
cargo mutants "${files[@]}" \
  --copy-vcs true \
  --jobs 2 \
  --timeout-multiplier 8 \
  --output "$OUT" \
  > "$GATE_LOG_DIR/mutants.log" 2>&1
status=$?
echo "cargo-mutants exited $status"
tail -n 40 "$GATE_LOG_DIR/mutants.log"

out="$OUT/mutants.out"

# ---------------------------------------------------------------------------
# A campaign that tested nothing: THREE causes, three different places to look
# ---------------------------------------------------------------------------
#
# They are told apart by which file cargo-mutants got as far as writing, because
# that is a fact about how far it ran rather than a sentence that can be reworded
# in the next release:
#
#   `mutants.json`   is the list it GENERATED. Written as soon as the source has
#                    been parsed, before a single test runs.
#   `outcomes.json`  is what it TESTED, baseline included. Written at the end.
#
# So: no `mutants.json` means it never parsed the tree; an empty one means the
# scope matched nothing mutable; a full one with no green baseline means the
# suite was already red before anything was mutated.
#
# That last case is the one this block exists for. Measured, cargo-mutants
# 27.1.0: with one deliberately failing test in the UNMUTATED tree it exits 4,
# generates its mutants, tests none of them, and writes an `outcomes.json` whose
# only entry is `{"scenario": "Baseline", "summary": "Failure"}` with
# `total_mutants: 0`. Read as a mutant count alone, that is indistinguishable
# from a glob that matched nothing -- and it was reported as one, which sent the
# reader to edit a scope that was correct while a failing test sat in the tree.
# A glob matching nothing exits 0 and writes no `outcomes.json` at all, so the
# count was never the thing that separated them.
generated=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))))' \
  "$out/mutants.json" 2> /dev/null) || generated=-1

if [ "$generated" -lt 0 ]; then
  fail "cargo-mutants wrote no list of mutants (exit $status). It never got as far as reading the source, so this is neither a scope nor a test failure; the whole log is at $GATE_LOG_DIR/mutants.log"
  gate_summary; exit 1
fi

if [ "$generated" -eq 0 ]; then
  fail "the scope matched no mutable source, so nothing was generated and nothing ran (exit $status). THE TESTS ARE NOT INVOLVED. Fix the globs: scope was '$SCOPE'"
  gate_summary; exit 1
fi

if [ ! -f "$out/outcomes.json" ]; then
  fail "cargo-mutants generated $generated mutants and then wrote no outcomes.json (exit $status). It died between reading the source and finishing the run; the whole log is at $GATE_LOG_DIR/mutants.log"
  gate_summary; exit 1
fi

baseline=$(python3 - "$out/outcomes.json" <<'BASELINE'
import json, sys

for outcome in json.load(open(sys.argv[1]))['outcomes']:
    if outcome.get('scenario') == 'Baseline':
        print(outcome.get('summary', 'unknown'))
        break
else:
    print('absent')
BASELINE
)

if [ "$baseline" != "Success" ]; then
  fail "the baseline never went green, so none of the $generated mutants was tested (cargo-mutants exit $status, baseline $baseline). THE SCOPE IS NOT THE PROBLEM: the suite fails in the UNMUTATED tree."
  cat >&2 <<'REDBASE'
  The log names the FIRST failing target and no others -- cargo-mutants runs a
  fail-fast `cargo test`, so a break spanning four targets reads as one and
  costs a fresh campaign per fix. Get the whole list in one pass instead, in
  this same container:

      scripts/linux.sh cargo test --locked --no-fail-fast

  Fix what that names, then re-run this.
REDBASE
  gate_summary; exit 1
fi

field() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$out/outcomes.json" "$1"; }
total=$(field total_mutants); caught=$(field caught); missed=$(field missed)
timeout=$(field timeout); unviable=$(field unviable)
echo "generated=$generated tested=$total caught=$caught missed=$missed timeout=$timeout unviable=$unviable"

# The floor is a statement about the DEFAULT scope's baseline and is checked for
# no other scope. See MUTANT_FLOOR above.
if [ "$SCOPE" = "$DEFAULT_SCOPE" ] && [ "$total" -lt "$MUTANT_FLOOR" ]; then
  fail "only $total mutants were generated from the default scope; the floor is $MUTANT_FLOOR. The baseline was green, so this is the scope shrinking under the globs in DEFAULT_SCOPE -- a file renamed, moved, or deleted."
  gate_summary; exit 1
fi

python3 - "$out/outcomes.json" $SCOPE <<'SCOPED' || { fail "a scope root contributed nothing"; gate_summary; exit 1; }
import json, sys

data = json.load(open(sys.argv[1]))
roots = [glob.split('*')[0].rstrip('/') for glob in sys.argv[2:]]
seen = set()
for outcome in data['outcomes']:
    scenario = outcome.get('scenario')
    if isinstance(scenario, dict) and isinstance(scenario.get('Mutant'), dict):
        name = scenario['Mutant'].get('file')
        if name:
            seen.add(name)
missing = [r for r in roots if not any(f == r or f.startswith(r + '/') for f in seen)]
if missing:
    for root in missing:
        print('no mutants were generated under %s' % root)
    print('That path is in the scope and contributed nothing. It was renamed,')
    print('deleted, or the glob stopped matching.')
    sys.exit(1)
print('every scope root produced mutants: %s' % ', '.join(roots))
SCOPED

# Normalise: strip line:column and let a COUNT replace them. A key carrying a
# line number reds on a comment, and a gate that reds on a comment gets deleted.
python3 - "$out/missed.txt" "$GATE_LOG_DIR/survivors.txt" <<'NORMALISE'
import collections, re, sys

keys = collections.Counter()
for raw in open(sys.argv[1]):
    raw = raw.strip()
    if raw:
        keys[re.sub(r'^(.*?):[0-9]+:[0-9]+: ', r'\1: ', raw)] += 1
with open(sys.argv[2], 'w') as fh:
    for key in sorted(keys):
        fh.write('%d\t%s\n' % (keys[key], key))
NORMALISE

if [ "$SCOPE" != "$DEFAULT_SCOPE" ]; then
  echo "scope is not the default, so there is no baseline to diff against."
  echo "the survivors of this run, for a person to read:"
  cat "$GATE_LOG_DIR/survivors.txt"
  exit 0
fi

grep -vE '^[[:space:]]*(#|$)' "$BASELINE" > "$GATE_LOG_DIR/expected.txt" || true

if [ -s "$out/timeout.txt" ]; then
  echo "mutants that TIMED OUT (reported, never judged -- a timeout on a loaded"
  echo "machine measures the neighbours):"
  cat "$out/timeout.txt"
fi

if diff -u "$GATE_LOG_DIR/expected.txt" "$GATE_LOG_DIR/survivors.txt"; then
  pass "the surviving mutants are exactly the $(wc -l < "$GATE_LOG_DIR/expected.txt" | tr -d ' ') recorded in $BASELINE"
  exit 0
fi

fail "the set of surviving mutants changed."
cat >&2 <<'WHY'
  A line only in survivors is a mutation NO TEST NOTICES: the code was changed
  and the suite stayed green. Write the guard, or -- if the mutant is genuinely
  equivalent -- add it to the baseline WITH a comment saying why.
  A line only in expected STOPPED surviving, which has two opposite causes and
  they are named below with the evidence that separates them. Do not delete the
  line until you have read that.
  A changed COUNT on an otherwise identical line means one of several identical
  mutations in that function was closed, or a new one appeared.
WHY

# A baseline entry that stops surviving is EITHER a gap somebody closed OR a
# test that failed for a reason having nothing to do with the mutation -- a
# catch cargo-mutants recorded and did not earn. It judges a mutant by the EXIT
# STATUS of `cargo test` and cannot tell those apart. Nothing about the diff can
# either: both are the same missing line.
#
# WHICH TEST FAILED is the thing that separates them, and it is already on disk
# in the mutant's own scenario log. Measured 2026-08-23: one test failing for an
# environmental reason turned every survivor in a crate into a catch, and the
# campaign exited 0. A reader told only "delete that line" deletes a true record
# of an open gap and blinds this gate permanently, which is why the sentence
# above no longer says it.
python3 - "$out" "$GATE_LOG_DIR/expected.txt" "$GATE_LOG_DIR/survivors.txt" >&2 <<'WHOCAUGHT'
import json, os, re, sys

out, expected_path, survivors_path = sys.argv[1:4]
ANSI = re.compile(r'\x1b\[[0-9;]*m')


def keys(path):
    found = set()
    for raw in open(path):
        raw = raw.strip()
        if raw:
            found.add(raw.split('\t', 1)[-1])
    return found


vanished = keys(expected_path) - keys(survivors_path)
if not vanished:
    sys.exit(0)

print('  the entries that STOPPED surviving, and what failed in each run:')
outcomes = json.load(open(os.path.join(out, 'outcomes.json')))['outcomes']
reported = set()
for outcome in outcomes:
    scenario = outcome.get('scenario')
    if not (isinstance(scenario, dict) and isinstance(scenario.get('Mutant'), dict)):
        continue
    if outcome.get('summary') != 'CaughtMutant':
        continue
    key = re.sub(r'^(.*?):[0-9]+:[0-9]+: ', r'\1: ',
                 scenario['Mutant'].get('name', ''))
    if key not in vanished:
        continue
    failed = []
    try:
        for line in open(os.path.join(out, outcome.get('log_path', '')),
                         errors='replace'):
            hit = re.match(r'^test (\S+) \.\.\. FAILED', ANSI.sub('', line).strip())
            if hit and hit.group(1) not in failed:
                failed.append(hit.group(1))
    except OSError:
        pass
    reported.add(key)
    print('    %s' % key)
    print('      failing test: %s' % (', '.join(failed) if failed else
          'none named -- the BUILD or the runner failed, not a test'))

for key in sorted(vanished - reported):
    print('    %s' % key)
    print('      not tested at all this run -- it is neither a survivor nor a catch')

print('  A test that plausibly covers that code means the gap really was closed:')
print('  delete the line. A test in an unrelated module means this campaign was')
print('  poisoned by a failure that is not about the mutation -- fix that test')
print('  and re-run. The baseline is not the thing that is wrong in that case.')
WHOCAUGHT

echo "the survivors of this run are at $GATE_LOG_DIR/survivors.txt" >&2
exit 1
