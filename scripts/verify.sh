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
# debt: this gate reads the WORKING TREE, not the staged tree. A commit made
#       with `git add -p` can therefore be green here and broken as committed.
#       Fixing it properly means a stash dance around a hook, which can lose
#       work when it goes wrong -- a worse failure than the one it prevents.
#       Upgrade trigger: the first time a partial commit lands broken.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib.sh

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
run_step "build keyless (debug + release)" heavy '
  cargo build --locked --bin keyless \
    && cargo build --locked --release --bin keyless \
    && ./target/release/keyless --version'

if [ "$(uname -s)" = "Darwin" ]; then
  run_step "build keylessd (debug + release)" heavy '
    cargo build --locked --bin keylessd \
      && cargo build --locked --release --bin keylessd \
      && ./target/release/keylessd --version'
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

  if run_step "test suite" heavy "PATH='$CLEAN_PATH' cargo test --locked"; then
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
