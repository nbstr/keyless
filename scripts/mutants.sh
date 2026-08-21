#!/usr/bin/env bash
# The mutation campaign over the Rust crate's security core.
#
# ---------------------------------------------------------------------------
# Why this is a script now, and why that is not the mistake it looks like
# ---------------------------------------------------------------------------
#
# `.github/mutants-baseline.txt` used to open with a runnable `cargo mutants`
# line. People ran it, because that is what the file said to do, and the
# campaign is about forty minutes of saturated CPU -- on a workstation running
# many concurrent sessions it starves every other job. So the line was replaced
# with a `gh workflow run` dispatch, and `tests/mutants_guidance.rs` was written
# as the ratchet that stops the local command coming back.
#
# The workflows are gone: the account has no Actions billing. The dispatch is
# now the dead link, and the ratchet points at nothing.
#
# What the ratchet was actually defending was never "run it on a server" -- it
# was "do not let one command eat the machine". That objection has a local
# answer here: codeine's queue. `cq run` holds the campaign behind the same
# admission cap every other heavy job on this machine waits in, so it takes a
# slot instead of taking the machine. The ratchet stays, with its teeth: the
# baseline still must not hand anyone a bare `cargo mutants` to paste. It now
# hands them this file, which is the same command with the cap in front of it.
#
# Where no `cq` answers there IS no cap, and this script says so and refuses
# rather than starting a forty-minute run on an unbounded machine.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib.sh

# The one scope .github/mutants-baseline.txt describes. Any other scope is
# REPORTED and never diffed -- a baseline describes one scope, and checking it
# against a different one would red every time and mean nothing.
DEFAULT_SCOPE='src/mask/** src/secret.rs src/audit/**'
MUTANT_FLOOR=280
BASELINE=.github/mutants-baseline.txt
SCOPE="${*:-$DEFAULT_SCOPE}"
OUT=mutants-run

if ! command -v cargo-mutants > /dev/null 2>&1; then
  echo "cargo-mutants is not installed. Install it with:" >&2
  echo "    cargo install cargo-mutants --locked" >&2
  exit 1
fi

# The cap is the whole reason this is allowed to run locally. Without a queue
# answering, a forty-minute saturating campaign is exactly what the guidance
# test exists to prevent, so refuse instead of degrading.
if ! command -v cq > /dev/null 2>&1; then
  echo "no cq on PATH, so there is no admission cap to hold this campaign." >&2
  echo "It saturates the CPU for roughly forty minutes. Run it deliberately," >&2
  echo "on a machine you are not using, or install the queue first." >&2
  exit 1
fi

files=""
for glob in $SCOPE; do files="$files -f $glob"; done
echo "${BOLD}mutants${OFF} ${DIM}scope: $SCOPE${OFF}"
echo "${DIM}~40 minutes for the default scope, queued behind cq's admission cap.${OFF}"
echo "${DIM}The python hook pack is a SEPARATE campaign: hooks/tests/mutate.py${OFF}"

# Redirected, never piped: a pipeline reports its last stage's status.
cq run --kind mutants -- cargo mutants $files \
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
