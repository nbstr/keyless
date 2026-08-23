#!/usr/bin/env bash
# The gate that runs before every commit. Roughly a minute on a warm tree.
#
# ---------------------------------------------------------------------------
# What this is
# ---------------------------------------------------------------------------
#
# This repository used to be checked by four GitHub Actions workflows. They were
# deleted: the account has no Actions billing, so every run since 2026-08-09 was
# red for reasons that had nothing to do with the code, and a permanently red
# check is a check nobody reads.
#
# Every ASSERTION those workflows made survives, here and in the two scripts
# beside this one. What changed is where they run, not what they prove -- with
# three exceptions, which are named in scripts/linux-gates.sh because a Mac
# cannot perform them and pretending otherwise would be the exact false green
# the originals were written to prevent.
#
# ---------------------------------------------------------------------------
# Why the counts, when the exit code is right there
# ---------------------------------------------------------------------------
#
# Exit 0 is not evidence that anything ran. A filtered run matching zero tests
# exits 0. A suite whose harness failed to link exits 0 in some shapes. Both
# read exactly like a pass. So each step below asserts the SIZE of what it did,
# and the floors are set below the measured count so they catch a suite that
# collapsed rather than a suite that lost one case.
#
# ---------------------------------------------------------------------------
# What it is pointed at
# ---------------------------------------------------------------------------
#
# Run by hand, this gates the tree it is standing in, which is what somebody
# checking their own work in progress means by it.
#
# Run as `--staged`, it gates the tree a commit would create instead, in a copy
# of that tree materialised somewhere else. That is the form the pre-commit
# hook uses, and it is the difference between a green gate and a green COMMIT:
# a checkout still holding the unstaged half of a `git add -p` compiles when
# the commit does not. `gate_staged_tree` in scripts/staged-tree.sh does that
# work, and says there why it copies the tree rather than stashing around it.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib.sh

if [ "${1:-}" = "--staged" ]; then
  # Sourced here rather than from lib.sh: this is the only caller, and the
  # other gates have no index to gate.
  source scripts/staged-tree.sh || exit 1
  gate_staged_tree; staged_code=$?
  # A failure counted here is one of the assertions made BEFORE the copy was
  # gated; the run inside the copy prints its own summary and must not be given
  # a second one reading this shell's untouched counter.
  [ "$GATE_FAILURES" -eq 0 ] || gate_summary
  exit "$staged_code"
fi

# Measured on macOS 2026-08-21: 714 passed, 15 ignored. Set below the measured
# count, per above. The ignored figure is asserted EXACTLY -- it counts the
# Proton live suite, which needs a real account, and nothing else. A sixteenth
# means a test went quiet.
case "$(uname -s)" in
  Darwin) TEST_FLOOR=480; IGNORED_EXACTLY=15 ;;
  Linux)  TEST_FLOOR=420; IGNORED_EXACTLY=15 ;;
  *)      echo "unknown platform $(uname -s); no floors are recorded for it." >&2; exit 1 ;;
esac
HOOK_CHECK_FLOOR=500

echo "${BOLD}gate${OFF} ${DIM}$(uname -s), $(rustc -V 2>/dev/null || echo 'no rustc')${OFF}"

run_step "format"  cargo fmt --check
run_step "clippy"  heavy 'cargo clippy --locked --all-targets -- -D warnings'

# Named binaries, not a bare `cargo build`. On Linux a bare build exits 101 for
# the daemon while the client is already linked and on disk.
# Double quotes, and the path expanded HERE. `heavy` hands its argument to a
# fresh `bash -c`, which has none of this file's functions -- a `$(target_dir)`
# left for that shell to evaluate is an empty string and a path of `/release/...`.
TARGET="$(target_dir)"
run_step "build keyless (debug + release)" heavy "
  cargo build --locked --bin keyless \
    && cargo build --locked --release --bin keyless \
    && '$TARGET/release/keyless' --version"

if [ "$(uname -s)" = "Darwin" ]; then
  run_step "build keylessd (debug + release)" heavy "
    cargo build --locked --bin keylessd \
      && cargo build --locked --release --bin keylessd \
      && '$TARGET/release/keylessd' --version"
fi

# ---- the suite, with no vendor CLI within reach ---------------------------
#
# The runner proved stub-independence by not having `infisical` or `pass-cli`
# installed. This machine has both, so the PATH is scrubbed instead. See
# scripts/vendorless_path.py.
CLEAN_PATH="$(vendorless_path)" || fail "could not build a vendor-free PATH"
if [ -n "${CLEAN_PATH:-}" ]; then
  for cli in infisical pass-cli; do
    if PATH="$CLEAN_PATH" command -v "$cli" > /dev/null 2>&1; then
      fail "$cli is still reachable on the scrubbed PATH, so a green suite no longer proves the stubs are what it used"
    fi
  done

  # --no-fail-fast costs NOTHING on the path this gate spends its life on: when
  # nothing fails, every target runs either way and the counts below are the
  # same numbers. It is only the red path that differs, and there it is the
  # difference between one failing target named and all of them. This is the
  # pre-commit gate, so the alternative is a developer paying the whole gate
  # again per failing file to learn what one run already knew.
  if run_step "test suite" heavy "PATH='$CLEAN_PATH' cargo test --locked --no-fail-fast"; then
    log="$GATE_LOG_DIR/$(printf '%02d' "$GATE_STEP").log"
    passed=$(count_result "$log" 'passed;')
    ignored=$(count_result "$log" 'ignored;')
    failed=$(count_result "$log" 'failed;')
    if [ "$passed" -lt "$TEST_FLOOR" ]; then
      fail "only $passed tests ran; the floor is $TEST_FLOOR. A suite that exercised nothing exits 0 and reads exactly like a pass."
    elif [ "$ignored" -ne "$IGNORED_EXACTLY" ]; then
      fail "expected exactly $IGNORED_EXACTLY ignored tests; saw $ignored. Each ignored test says why in the log -- read them."
    elif [ "$failed" -ne 0 ]; then
      fail "$failed tests failed"
    else
      pass "suite size ${DIM}passed=$passed ignored=$ignored failed=$failed${OFF}"
    fi
  fi

  # ---- the hook pack ------------------------------------------------------
  #
  # Stdlib-only by design, so the thing worth asserting is that it stayed that
  # way. `--fast` drops the latency layer, which cannot be a gate on a machine
  # with other work running on it.
  no_third_party() {
    python3 -c 'import sys; print(sys.version)' \
      && test ! -e hooks/requirements.txt \
      && test ! -e hooks/pyproject.toml \
      && test ! -e hooks/setup.py
  }
  run_step "hook pack has no third-party imports" no_third_party

  if run_step "hook pack suite" \
       env PATH="$CLEAN_PATH" python3 hooks/tests/run.py --fast; then
    log="$GATE_LOG_DIR/$(printf '%02d' "$GATE_STEP").log"
    checks=$(awk '/^[0-9]+ checks\./ { print $1 }' "$log")
    if [ "${checks:-0}" -lt "$HOOK_CHECK_FLOOR" ]; then
      fail "only ${checks:-0} hook checks ran; the floor is $HOOK_CHECK_FLOOR. A suite that ran nothing prints ALL GREEN and exits 0."
    else
      pass "hook pack size ${DIM}checks=$checks${OFF}"
    fi
  fi
fi

gate_summary
