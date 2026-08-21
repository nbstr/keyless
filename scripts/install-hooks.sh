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
bash "$gate"
code=$?
if [ "$code" -ne 0 ]; then
  echo >&2
  echo "pre-commit: the gate failed, so nothing was committed." >&2
  echo "Fix it, or commit with --no-verify if you know why you are bypassing." >&2
fi
exit "$code"
HOOK
chmod +x "$hook"
echo "installed $hook"
echo "it runs scripts/verify.sh, about 90 seconds on a warm tree."
