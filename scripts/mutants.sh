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

# Flags IDENTICAL to the workflow that produced the baseline. The survivor set
# is a property of the method as much as of the code: change `--jobs` or the
# timeout multiplier and mutants move between "timed out" and "caught" for
# reasons that have nothing to do with a test.
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

if [ ! -f "$OUT/mutants.out/outcomes.json" ]; then
  fail "cargo-mutants produced no outcomes.json (exit $status). It never got as far as testing mutants; the whole log is at $GATE_LOG_DIR/mutants.log"
  gate_summary; exit 1
fi

out="$OUT/mutants.out"
field() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$out/outcomes.json" "$1"; }
total=$(field total_mutants); caught=$(field caught); missed=$(field missed)
timeout=$(field timeout); unviable=$(field unviable)
echo "tested=$total caught=$caught missed=$missed timeout=$timeout unviable=$unviable"

# A --file glob that matches nothing produces zero survivors and exits 0.
if [ "$total" -lt "$MUTANT_FLOOR" ]; then
  fail "only $total mutants were generated; the floor is $MUTANT_FLOOR. Check the scope, not the tests."
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
  A line only in expected is the opposite: a gap somebody closed while the
  baseline still claims it is open. Delete that line.
  A changed COUNT on an otherwise identical line means one of several identical
  mutations in that function was closed, or a new one appeared.
WHY
echo "the survivors of this run are at $GATE_LOG_DIR/survivors.txt" >&2
exit 1
