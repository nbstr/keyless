#!/usr/bin/env bash
# The three checks a Mac physically cannot perform. Run this on a Linux box.
#
# ---------------------------------------------------------------------------
# Why these are not in the other two scripts
# ---------------------------------------------------------------------------
#
# `keylessd` is macOS-only, and this repository does not merely say so -- it
# MEASURES it. Two of the checks below are the measurement, and they only mean
# anything on a machine where the daemon genuinely cannot run. On macOS they
# would either be skipped, which reads as a pass, or rewritten into something
# weaker that reads as the same pass. Both are the false green the rest of this
# gate is built to refuse, so they are here instead, in a file that says out
# loud it needs a machine this one is not.
#
# The third is the hook pack under a second interpreter. The pack is stdlib-only
# and supports 3.7 upward; a single-interpreter run cannot see a version-shaped
# break. This machine has one Python, so that axis lives here too.
#
# NOTHING RUNS THESE AUTOMATICALLY. That is a real reduction in coverage against
# the workflows they came from, and pretending otherwise would be worse than the
# gap. Run it when `src/ipc/ffi.rs` changes, when the porting table in
# install/README.md changes, and before a release.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib.sh

if [ "$(uname -s)" != "Linux" ]; then
  echo "This is $(uname -s). These three gates need Linux:" >&2
  echo "  * keylessd must BUILD and then REFUSE to run, naming why" >&2
  echo "  * the daemon's unportable surface must be exactly four XNU symbols," >&2
  echo "    which is read out of a Linux linker's undefined-reference output" >&2
  echo "  * the hook pack under a second Python interpreter" >&2
  echo >&2
  echo "Copy the checkout to a Linux machine and run this there. It is not" >&2
  echo "skippable here: a skip and a pass look identical afterwards." >&2
  exit 1
fi

echo "${BOLD}linux gates${OFF} ${DIM}$(uname -sm)${OFF}"

# ---- 1. the daemon builds, and refuses -----------------------------------
#
# Asserted POSITIVELY -- run it and require a non-zero exit AND a message that
# names the real reason -- because "the binary is missing" is a fact no check
# can tell apart from a build that quietly broke.
keylessd_refuses() {
  cargo build --locked --bin keylessd || return 1
  ./target/debug/keylessd run > refusal.log 2>&1
  local code=$?
  cat refusal.log
  if [ "$code" -eq 0 ]; then
    echo "keylessd exited 0 on Linux. There is no daemon on this platform, so a"
    echo "success here means something is pretending."
    return 1
  fi
  for word in macOS csops proc_pidinfo install/README.md; do
    if ! grep -qF "$word" refusal.log; then
      echo "the refusal never mentions '$word'. It is the only thing an operator"
      echo "on this platform will read, so it has to name the interface and"
      echo "point at the porting table."
      return 1
    fi
  done
  echo "keylessd refuses on Linux, with exit $code, and says why."
  rm -f refusal.log
}
run_step "keylessd builds on Linux and refuses to run, naming why" keylessd_refuses

# ---- 2. the unportable surface is exactly four XNU symbols ----------------
xnu_surface() {
  if RUSTFLAGS='--cfg keyless_force_xnu' cargo build --locked --bin keylessd > keylessd-link.log 2>&1; then
    cat keylessd-link.log
    echo "keylessd LINKED on Linux with the XNU modules forced on. That is good"
    echo "news and this file is now wrong: give Linux a real daemon gate, and"
    echo "update the porting table in install/README.md."
    return 1
  fi
  cat keylessd-link.log
  sed -nE "s/.*undefined reference to \`([A-Za-z0-9_]+)'.*/\1/p" keylessd-link.log | sort -u > got.txt
  if [ ! -s got.txt ]; then
    echo "the forced build failed BEFORE linking, so the unportable surface was"
    echo "never measured. Read keylessd-link.log: this is a compile error under"
    echo "--cfg keyless_force_xnu, not a portability finding."
    return 1
  fi
  printf '%s\n' csops getpeereid proc_pidinfo proc_pidpath > want.txt
  if ! diff -u want.txt got.txt; then
    echo "the daemon's unportable surface changed. It is meant to be exactly the"
    echo "four XNU calls in src/ipc/ffi.rs. A new name in this list is a new"
    echo "macOS-only dependency, and it belongs in the porting table in"
    echo "install/README.md."
    return 1
  fi
  echo "keylessd is macOS-only on exactly the four documented XNU symbols."
  rm -f keylessd-link.log got.txt want.txt
}
run_step "the daemon's unportable surface is exactly four XNU symbols" xnu_surface

# ---- 3. the hook pack under this machine's interpreter --------------------
#
# The floor was measured by running the suite, not by reading it: 3.7 through
# 3.13 are green. 3.6 fails one fail-open case under a broken locale, where it
# degrades to `silent` and every later version denies.
hookpack() {
  python3 -c 'import sys; print(sys.version)'
  python3 hooks/tests/run.py --fast
}
if run_step "hook pack on $(python3 -V 2>&1)" hookpack; then
  log="$GATE_LOG_DIR/$(printf '%02d' "$GATE_STEP").log"
  checks=$(awk '/^[0-9]+ checks\./ { print $1 }' "$log")
  if [ "${checks:-0}" -lt 500 ]; then
    fail "only ${checks:-0} hook checks ran; the floor is 500. A suite that ran nothing prints ALL GREEN and exits 0."
  else
    pass "hook pack size ${DIM}checks=$checks${OFF}"
  fi
fi

gate_summary
