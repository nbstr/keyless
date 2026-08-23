# Gating the index rather than the checkout. Sourced, never executed.
#
# One caller: scripts/verify.sh, on `--staged`, which is the form the pre-commit
# hook runs. It reports through scripts/lib.sh -- `fail`, `GATE_LOG_DIR`, the
# colours -- so lib.sh has to be sourced first. Sourced alone, this would define
# a function that dies on its first error path, at the moment it finally has
# something to say, so refuse at source time instead.
if ! declare -F fail > /dev/null 2>&1; then
  echo "scripts/staged-tree.sh reports through scripts/lib.sh; source that first." >&2
  return 1 2> /dev/null || exit 1
fi

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
