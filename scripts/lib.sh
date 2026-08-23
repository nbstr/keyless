# Shared plumbing for the local gates. Sourced, never executed.
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

# ---------------------------------------------------------------------------
# gate_staged_tree -- run the gate over what the commit will contain
# ---------------------------------------------------------------------------
#
# A pre-commit gate that reads the checkout is gating the wrong tree. `git add
# -p` stages half a file and leaves the other half in the working tree, where
# the compiler can still see it: the checkout builds, the gate is green, and
# the commit that lands is missing the half that made it build. The subject of
# a pre-commit gate is the index, and only the index.
#
# WHY NOT `git stash --keep-index`, which is the obvious way to do this:
#
#   It takes the developer's unstaged work OUT of the checkout for the minutes
#   the gate runs, and every way that run can end badly leaves that work in a
#   stash entry they did not make and will not think to look for -- a failing
#   step, a ^C, a SIGKILL, a machine that loses power mid-write. A trap covers
#   the first two and cannot cover the last two, and the ones it cannot cover
#   are the expensive ones. Nothing here writes to the checkout at all.
#   `git write-tree` NAMES the tree the index already describes, and the copy
#   is materialised somewhere else. Kill this function at any point, in any
#   way, and the developer's files are where they were, because nothing ever
#   moved them.
#
# WHY A LINKED WORKTREE, and not `git archive` into a scratch directory:
#
#   Because fifteen of the tests need a repository. `tests/publication.rs` and
#   `tests/session_coordinate.rs` ask git for the corpus they scan and FAIL
#   rather than skip when there is none -- deliberately, since a walk that read
#   nothing and a clean history are the same empty result. An extract has no
#   `.git`, so gating one runs the suite with those fifteen red; that is the
#   mistake the deleted workflows made, and scripts/verify-all.sh clones rather
#   than extracts for the same reason. A linked worktree shares the object
#   database and the refs, so those cases run -- against the staged tree, and
#   against a history that already contains it.
#
# The tree and its build cache are kept between runs under the common git
# directory. Rebuilding every dependency on every commit is what gets a gate
# bypassed, and checking out a commit rewrites only the files that actually
# differ, so cargo rebuilds what changed and nothing else. Both are disposable:
# the tree is a checkout of a scaffold commit, the cache is an ordinary cargo
# target directory of the same order of size as the one in the checkout, and
# deleting either costs one slower run.
gate_staged_tree() {
  local root="$PWD"

  # The tree the commit would carry. `git write-tree` reads GIT_INDEX_FILE,
  # which git sets for `git commit -a` and for `git commit -- <paths>`: both
  # build a temporary index and hand it to the hook, and reading the
  # repository's own index instead would gate a tree neither is about to write.
  local tree
  tree=$(git write-tree) || {
    fail "git write-tree could not name the staged tree, so there is nothing to gate"
    return 1
  }

  # Everything after this line runs git somewhere ELSE, and a hook's
  # environment carries GIT_DIR and GIT_INDEX_FILE pointing here. Inherited,
  # they aim a worktree checkout -- and the suite's own `git ls-files` calls --
  # straight back at the checkout this function exists to stop reading, and
  # GIT_INDEX_FILE aims a WRITE at the temporary index git is about to commit
  # from. Unset the whole family. Which variables are in it is git's to change,
  # so match the prefix rather than keeping a list that goes stale.
  local var
  for var in $(compgen -e); do
    case "$var" in GIT_*) unset "$var" ;; esac
  done

  local common
  common=$(git rev-parse --git-common-dir) || {
    fail "git rev-parse --git-common-dir failed, so there is nowhere to put the copy"
    return 1
  }
  case "$common" in /*) ;; *) common="$root/$common" ;; esac

  local gate="$common/keyless-gate"
  local work="$gate/tree"
  local log="$GATE_LOG_DIR/staged-tree.log"
  GATE_LOCK="$gate/lock"

  mkdir -p "$gate" || { fail "could not create $gate"; return 1; }

  # One gate per clone at a time. Two commits gating at once would each check
  # out over the other's source tree mid-build, and the answer that came back
  # would be about neither tree. `mkdir` is the atomic part; the pid is what
  # keeps a lock from outliving its holder, because a run killed before its
  # trap fires would otherwise jam every later commit shut. Refusing while
  # another gate really is running is fail-closed; refusing forever is not.
  if ! mkdir "$GATE_LOCK" 2> /dev/null; then
    local holder; holder=$(cat "$GATE_LOCK/pid" 2> /dev/null)
    if [ -n "$holder" ] && kill -0 "$holder" 2> /dev/null; then
      fail "another gate is already running in this clone (pid $holder). Wait for it, then commit again."
      return 1
    fi
    rm -rf "$GATE_LOCK"
    mkdir "$GATE_LOCK" 2> /dev/null || {
      fail "could not take the gate lock. If nothing is running, remove $GATE_LOCK."
      return 1
    }
  fi
  echo $$ > "$GATE_LOCK/pid"
  trap 'rm -rf "$GATE_LOCK"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # A real commit object, because the suite reads history and a tree alone
  # cannot be checked out. The identity is fixed here rather than read from the
  # developer's configuration: this object is scaffolding for one gate run, it
  # is never pushed, and it is unreachable the moment the copy moves off it.
  local commit
  if git rev-parse --verify --quiet HEAD > /dev/null 2>&1; then
    commit=$(git -c user.name=gate -c user.email=gate@invalid \
               commit-tree "$tree" -p HEAD -m 'the staged tree, gated' 2> "$log")
  else
    commit=$(git -c user.name=gate -c user.email=gate@invalid \
               commit-tree "$tree" -m 'the staged tree, gated' 2> "$log")
  fi
  if [ -z "${commit:-}" ]; then
    fail "could not write a commit for the staged tree"
    cat "$log"
    return 1
  fi

  # A copy left half-made by a killed run is a checkout of a commit and nobody's
  # work, so it can simply go.
  if [ -e "$work" ] && ! git -C "$work" rev-parse --git-dir > /dev/null 2>&1; then
    rm -rf "$work"
    git worktree prune > /dev/null 2>&1
  fi

  local placed=0
  if [ -d "$work" ]; then
    git -c advice.detachedHead=false -C "$work" checkout --detach --force --quiet "$commit" \
      && git -C "$work" clean -qfdx \
      && placed=1
  else
    git -c advice.detachedHead=false worktree add --detach --quiet "$work" "$commit" \
      && placed=1
  fi > "$log" 2>&1
  if [ "$placed" -ne 1 ]; then
    fail "could not materialise the staged tree in $work"
    cat "$log"
    return 1
  fi

  # Three assertions, for the same reason every step in verify.sh asserts a
  # size: a gate that ran against the wrong tree, or against half of one, exits
  # 0 and reads exactly like a pass.
  local got; got=$(git -C "$work" rev-parse 'HEAD^{tree}' 2> /dev/null)
  if [ "$got" != "$tree" ]; then
    fail "the copy holds tree ${got:-none}, and the commit would carry $tree"
    return 1
  fi
  local files; files=$(git -C "$work" ls-files | wc -l | tr -d ' ')
  if [ "$files" -lt 50 ]; then
    fail "the staged tree materialised as $files files; a tree that small is not this repository"
    return 1
  fi
  local dirty; dirty=$(git -C "$work" status --porcelain)
  if [ -n "$dirty" ]; then
    fail "the copy is not a clean checkout of the staged tree:"
    echo "$dirty"
    return 1
  fi

  printf '  %sthe subject is the index: %s files, tree %s%s\n' \
    "$DIM" "$files" "${tree:0:12}" "$OFF"
  printf '  %sgated in %s%s\n' "$DIM" "$work" "$OFF"

  # Its own build cache, so a gate run never invalidates the fingerprints in
  # the developer's target/ -- two source paths sharing one cache means each
  # rebuilds what the other just built.
  CARGO_TARGET_DIR="$gate/target" bash "$work/scripts/verify.sh"
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

# vendorless_path -- a PATH that cannot reach `infisical` or `pass-cli`.
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
