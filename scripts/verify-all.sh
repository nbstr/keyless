#!/usr/bin/env bash
# Everything the fast gate skips. Run it before pushing, or before a release.
#
# The pre-commit gate has to stay under about two minutes or it gets bypassed,
# and a gate that gets bypassed protects nothing. So the expensive checks live
# here: the suite re-run in an environment it did not grow up in, and the
# dependency audit. The mutation campaign is separate again -- scripts/mutants.sh
# -- because forty minutes is not something to bundle into a command someone
# runs on the way to a push.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib.sh

echo "${BOLD}verify-all${OFF} ${DIM}fast gate, then the environment and the advisories${OFF}"
echo

# ---- the fast gate, whole ------------------------------------------------
bash scripts/verify.sh || GATE_FAILURES=$((GATE_FAILURES + 1))
echo

# ---- the suite, somewhere it did not grow up ------------------------------
#
# Two axes a developer machine cannot vary by accident:
#
# 1. A LONG TMPDIR. `sockaddr_un.sun_path` is 104 bytes on macOS and 108 on
#    Linux, so a socket named inside a deep scratch directory binds on one
#    machine and fails with InvalidInput on another, with nothing about the code
#    having changed. Measured on macOS 15 on 2026-08-09: 49 bytes green, 57
#    bytes two failures, 97 bytes twelve. Three bytes of headroom on a stock
#    Mac. Every socket now comes from `support::short_socket_path`; this is what
#    stops a thirteenth appearing.
#
# 2. AN EMPTY HOME. A suite that reads a real dotfile, a real config or a real
#    keychain item is one whose green belongs to the machine. CARGO_HOME and
#    RUSTUP_HOME stay pinned to the real ones on purpose: the subject is the
#    SUITE's dependence on $HOME, never cargo's.
#
# The tree is a `git clone --local`, not a `git archive` extract. The workflow
# this replaced used an archive, and that is why fifteen of its tests could
# never pass: `tests/publication.rs` and `tests/session_coordinate.rs` read the
# published history with `git ls-files` and `git rev-list`, and they fail rather
# than skip when there is no repository -- deliberately, because a walk that
# read nothing and a clean history are the same empty result. An archive has no
# `.git`, so those fifteen were red in every run the workflow ever made. A local
# clone carries the same tracked files at HEAD, still with no `target/` and no
# uncommitted changes, and lets them actually run.
#
# It tests HEAD, not the working tree. That is the honest reading of "no
# uncommitted changes", and it is why this is a pre-push gate rather than a
# pre-commit one.
HOSTILE_ROOT="${TMPDIR:-/tmp}/keyless-hostile.$$"
case "$(uname -s)" in
  Darwin) HOSTILE_FLOOR=420 ;;
  Linux)  HOSTILE_FLOOR=360 ;;
  *)      HOSTILE_FLOOR=0 ;;
esac

hostile_tree() {
  rm -rf "$HOSTILE_ROOT"
  # 72 'a's, so any socket named under it exceeds sun_path (104) whatever it is
  # called. Asserted below rather than assumed: a TMPDIR that quietly stopped
  # being long would make this green for the wrong reason.
  local long="$HOSTILE_ROOT/$(printf 'a%.0s' $(seq 1 72))/T"
  mkdir -p "$long" "$HOSTILE_ROOT/empty-home" || return 1
  git clone --local --no-hardlinks . "$HOSTILE_ROOT/tree" > /dev/null 2>&1 || return 1
  local files; files=$(find "$HOSTILE_ROOT/tree" -type f -not -path '*/.git/*' | wc -l | tr -d ' ')
  echo "files=$files"
  [ "$files" -ge 50 ] || { echo "the clone produced $files files; a tree this small cannot be this repository"; return 1; }
  [ -f "$HOSTILE_ROOT/tree/Cargo.lock" ] || { echo "no Cargo.lock in the clone"; return 1; }
  [ -d "$HOSTILE_ROOT/tree/tests" ] || { echo "no tests/ in the clone"; return 1; }
  [ ! -e "$HOSTILE_ROOT/tree/target" ] || { echo "the clone carried a target/; something that should be build output is tracked"; return 1; }
  local bytes; bytes=$(printf %s "$long" | wc -c | tr -d ' ')
  echo "TMPDIR bytes=$bytes"
  [ "$bytes" -ge 90 ] || { echo "TMPDIR is only $bytes bytes; this is just the fast gate again"; return 1; }
}

if run_step "build a hostile tree (clone, empty HOME, long TMPDIR)" hostile_tree; then
  long="$HOSTILE_ROOT/$(printf 'a%.0s' $(seq 1 72))/T"
  cmd="cd '$HOSTILE_ROOT/tree' && env HOME='$HOSTILE_ROOT/empty-home' TMPDIR='$long' \
       CARGO_HOME='${CARGO_HOME:-$HOME/.cargo}' RUSTUP_HOME='${RUSTUP_HOME:-$HOME/.rustup}' \
       cargo test --locked --no-fail-fast"
  # --no-fail-fast because the whole subject here is a failure that hits MANY
  # tests at once for one environmental reason. Without it cargo stops after the
  # first failing target and a break spanning four files reports as one.
  if run_step "suite from the hostile tree" heavy "$cmd"; then
    log="$GATE_LOG_DIR/$(printf '%02d' "$GATE_STEP").log"
    passed=$(count_result "$log" 'passed;'); failed=$(count_result "$log" 'failed;')
    if [ "$passed" -lt "$HOSTILE_FLOOR" ]; then
      fail "only $passed tests ran in the hostile tree; the floor is $HOSTILE_FLOOR"
    elif [ "$failed" -ne 0 ]; then
      fail "$failed tests failed in the hostile tree. This differs from the fast gate only by HOME, TMPDIR and the absence of a build cache, so a failure here that the fast gate does not have is a test resting on one of those."
    else
      pass "hostile suite size ${DIM}passed=$passed failed=$failed${OFF}"
    fi
  fi
  rm -rf "$HOSTILE_ROOT"
fi

# ---- the advisory database ------------------------------------------------
#
# --deny warnings promotes unmaintained and yanked crates to failures. For a
# five-dependency tool that is affordable; on a large tree it would be the noise
# that gets the check disabled.
if ! command -v cargo-audit > /dev/null 2>&1; then
  fail "cargo-audit is not installed, so the advisory database was never read. Install it: cargo install cargo-audit --locked"
elif run_step "cargo audit" heavy 'cargo audit --deny warnings'; then
  log="$GATE_LOG_DIR/$(printf '%02d' "$GATE_STEP").log"
  # Exit 0 with an empty database reads exactly like a clean tree, so assert it
  # actually saw the lock file.
  if ! grep -qE 'Scanning Cargo.lock for vulnerabilities \([0-9]+ crate dependencies\)' "$log"; then
    fail "cargo audit did not report scanning any crates. A database that failed to load exits 0 and reads exactly like a clean tree."
  else
    pass "advisories ${DIM}$(grep -oE '[0-9]+ crate dependencies' "$log" | head -1)${OFF}"
  fi
fi

echo
echo "${DIM}not covered here: the mutation campaign (scripts/mutants.sh, ~40 min)${OFF}"
echo "${DIM}and the three Linux-only gates (scripts/linux-gates.sh, needs Linux).${OFF}"
gate_summary
