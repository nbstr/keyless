# Shared plumbing for the local gates. Sourced, never executed.
#
# Reporting only: the step runner, the counters, the summary, and the few
# helpers every gate needs to find its toolchain. Every gate script sources
# this. What gates the INDEX rather than the checkout lives in
# scripts/staged-tree.sh, sourced on top of this by its one caller.
#
# ---------------------------------------------------------------------------
# Why nothing here uses `set -e`
# ---------------------------------------------------------------------------
#
# The GitHub workflows this replaced were written as though `-e` were off. They
# ran a command, redirected its log, and read `$?` on the NEXT line:
#
#     cargo test --locked > test.log 2>&1
#     code=$?
#     cat test.log
#
# GitHub runs every `run:` block as `bash -e {0}`, so the shell died on the
# first line and `code=$?` was never reached. The log was never printed and the
# assertions below it never ran. That is why CI showed `exit code 101` and not
# one failing test name, for twelve days.
#
# So: `set -u` and `pipefail`, never `-e`. Every command's status is read on its
# own line, deliberately, and `run_step` below is the only place that decides
# what a non-zero status means.
set -uo pipefail

RED=$'\033[31m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
CLEAR_LINE=$'\r\033[K'
# Not a terminal: no colour, and no in-place progress line either. A `\033[K`
# written to a log file is noise a reader has to decode, and the whole point of
# these logs is that someone reads them after a failure.
[ -t 1 ] || { RED=''; GREEN=''; DIM=''; BOLD=''; OFF=''; CLEAR_LINE=''; }

GATE_LOG_DIR="${GATE_LOG_DIR:-$(mktemp -d)}"
GATE_FAILURES=0
GATE_STEP=0

# run_step <name> <command...>
#
# Runs the command with its output captured, prints one line, and on failure
# prints the captured log in full. The log is REDIRECTED, never piped: a
# pipeline reports its last stage's status, so `cargo test | tail` reports
# `tail`'s, which always succeeds.
run_step() {
  local name="$1"; shift
  GATE_STEP=$((GATE_STEP + 1))
  local log="$GATE_LOG_DIR/$(printf '%02d' "$GATE_STEP").log"
  local start; start=$(date +%s)
  [ -n "$CLEAR_LINE" ] && printf '%s' "  ${DIM}...${OFF} $name"
  "$@" > "$log" 2>&1
  local code=$?
  local took=$(( $(date +%s) - start ))
  printf '%s' "$CLEAR_LINE"
  if [ "$code" -eq 0 ]; then
    printf '  %s✓%s %s %s(%ss)%s\n' "$GREEN" "$OFF" "$name" "$DIM" "$took" "$OFF"
  else
    printf '  %s✗%s %s %s(%ss, exit %s)%s\n' "$RED" "$OFF" "$name" "$DIM" "$took" "$code" "$OFF"
    echo "$DIM--- $log ---$OFF"
    cat "$log"
    echo "$DIM--- end $log ---$OFF"
    GATE_FAILURES=$((GATE_FAILURES + 1))
  fi
  return "$code"
}

# fail <message...> -- record a failed assertion without running a command.
fail() {
  printf '  %s✗%s %s\n' "$RED" "$OFF" "$*"
  GATE_FAILURES=$((GATE_FAILURES + 1))
}

pass() { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$*"; }

# count_result <log> <field> -- sum a libtest summary field across every target.
#
# `cargo test` prints one `test result:` line per target. Summing them is the
# only way to get a suite-wide number, and the number is what catches a run that
# exited 0 having executed nothing.
count_result() {
  awk -v want="$2" '/^test result:/ {
                      for (i = 1; i <= NF; i++)
                        if ($(i+1) == want) n += $i
                    }
                    END { print n + 0 }' "$1"
}

gate_summary() {
  echo
  if [ "$GATE_FAILURES" -eq 0 ]; then
    printf '%s%s all green%s  %s(logs: %s)%s\n' "$BOLD" "$GREEN" "$OFF" "$DIM" "$GATE_LOG_DIR" "$OFF"
    return 0
  fi
  printf '%s%s %s check(s) failed%s  %s(logs: %s)%s\n' \
    "$BOLD" "$RED" "$GATE_FAILURES" "$OFF" "$DIM" "$GATE_LOG_DIR" "$OFF"
  return 1
}

# heavy <command...> -- route a build or test through codeine's queue if one is
# installed, and run it raw if not.
#
# The queue bounds how many builds start at once across every session on this
# machine; without it, twenty sessions start twenty typechecks. `cq run` already
# blocks until the job finishes and forwards the real exit code, so this stays
# in the foreground and simply waits for its slot. Where no `cq` exists the
# command runs unchanged, because the gate has to work on a machine that never
# installed it.
# It takes ONE shell string rather than an argv, because most steps here are
# several commands joined by `&&` and because `cq` execs a binary -- handed a
# bash function name it reports `No such file or directory`, which reads as a
# missing toolchain rather than as the plumbing mistake it is.
heavy() {
  if command -v cq > /dev/null 2>&1; then
    cq run --kind test -- bash -c "$1"
  else
    bash -c "$1"
  fi
}

# target_dir -- where cargo actually put the binaries.
#
# NOT the literal `target/`. When `CARGO_TARGET_DIR` is set -- which it is inside
# the pinned Linux image, pointing at a cache volume -- cargo builds there and
# `./target/` still holds whatever the HOST last built. Measured: the Linux gate
# built keylessd into /target and then executed the mounted macOS binary from
# ./target/debug, and Docker reported `Exec format error`. A gate that runs the
# wrong binary is worse than one that does not run.
target_dir() {
  echo "${CARGO_TARGET_DIR:-target}"
}

# vendorless_path -- a PATH that cannot reach `infisical`, `pass-cli` or `op`.
#
# Built once per gate run and cached in GATE_LOG_DIR. See
# scripts/vendorless_path.py for why this is manufactured rather than observed.
vendorless_path() {
  local dir="$GATE_LOG_DIR/vendorless"
  if [ ! -d "$dir" ]; then
    python3 "$(dirname "${BASH_SOURCE[0]}")/vendorless_path.py" "$dir" \
      > "$GATE_LOG_DIR/vendorless.path" 2> "$GATE_LOG_DIR/vendorless.err" || {
        cat "$GATE_LOG_DIR/vendorless.err" >&2
        return 1
      }
  fi
  cat "$GATE_LOG_DIR/vendorless.path"
}
