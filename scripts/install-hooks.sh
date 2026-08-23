#!/usr/bin/env bash
# Put the git hooks in place. Safe to re-run.
#
# Git hooks live in `.git/hooks/`, which is not part of the repository, so a
# fresh clone has none of this. Running this script is the one manual step
# between cloning and being gated.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

root=$(git rev-parse --show-toplevel) || exit 1
hook="$root/.git/hooks/pre-commit"

if [ -e "$hook" ] && ! grep -q 'scripts/verify.sh' "$hook" 2>/dev/null; then
  echo "$hook already exists and is not this one. Move it aside first:" >&2
  echo "    mv '$hook' '$hook.bak'" >&2
  exit 1
fi

cat > "$hook" <<'HOOK'
#!/usr/bin/env bash
set -uo pipefail
root=$(git rev-parse --show-toplevel) || exit 1
gate="$root/scripts/verify.sh"
if [ ! -x "$gate" ]; then
  echo "pre-commit: $gate is missing or not executable." >&2
  echo "Either restore it or remove this hook -- a gate that cannot run must" >&2
  echo "not pass silently." >&2
  exit 1
fi
# --staged, because the subject of a pre-commit gate is the index. Without it
# this reads the checkout, where the unstaged half of a `git add -p` is still
# sitting -- and a checkout that compiles is not a commit that compiles.
bash "$gate" --staged
code=$?
if [ "$code" -ne 0 ]; then
  echo >&2
  echo "pre-commit: the gate failed, so nothing was committed." >&2
  echo "It gated what you STAGED, in a copy of that tree. A working tree that" >&2
  echo "builds does not answer this: stage the rest, or fix what you staged." >&2
  echo "Reproduce it with: bash scripts/verify.sh --staged" >&2
fi
exit "$code"
HOOK
chmod +x "$hook"
echo "installed $hook"
echo "it runs scripts/verify.sh --staged: the gate, over the tree the commit"
echo "would create rather than over the checkout. About 90 seconds on a warm"
echo "tree, and the copy it gates keeps its own build cache under"
echo "$(git rev-parse --git-common-dir)/keyless-gate -- disposable, at the cost of one slower run."

# The second hook, and the reason it is a symlink rather than a copy: it is
# TRACKED, at install/commit-msg.sh, so a copy would be a second version to
# forget. It refuses a number standing next to a word that makes it a
# measurement of one machine -- in a commit message, which is the one place the
# publication guards in tests/publication.rs cannot reach, because a message is
# not a file in the tree.
msg="$root/.git/hooks/commit-msg"
if [ -e "$msg" ] && [ ! -L "$msg" ]; then
  echo "$msg exists and is not a symlink. Move it aside first." >&2
  exit 1
fi
ln -sf ../../install/commit-msg.sh "$msg"
echo "installed $msg -> install/commit-msg.sh"
