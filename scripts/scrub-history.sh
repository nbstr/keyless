#!/usr/bin/env bash
# Rewrite commit MESSAGES that describe one machine, and repair what that breaks.
#
# ---------------------------------------------------------------------------
# Read this before running it
# ---------------------------------------------------------------------------
#
# This rewrites published history. Every commit from the earliest match onward
# gets a new hash, so anyone holding a clone must RESET to the new history
# rather than merge -- a merge reintroduces the old commits alongside the new
# ones, and the scrubbed text is then present twice.
#
# It does NOT push. A rewrite is reversible while it is local: a backup ref is
# made first and named at the end. It stops being reversible once it is
# published, so that step is a human's to take with the command printed below.
#
# ---------------------------------------------------------------------------
# What it changes, and what it repairs
# ---------------------------------------------------------------------------
#
# Only the message text in the table below. No tree, no author, no date.
#
# Then it repairs what the rewrite breaks: `src/checkout.rs` cites two commits
# by hash to explain a real incident, and both are after the first rewritten
# commit, so both hashes change. A citation that resolves to nothing is worse
# than the prose it was added to support, so the new hashes are read out of
# filter-repo's own commit map and written back.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The substitutions, as two parallel arrays. Keep each OLD long enough to be
# unambiguous: a short string matches somewhere nobody intended, and a commit
# message is not a thing to edit by accident.
OLD=(
  "and reached 41 GB resident on ten cores"
  "held the queue eighty minutes with no"
)
NEW=(
  "and allocated until something stopped it"
  "held the queue far past its own runtime with no"
)

APPLY=0
[ "${1-}" = "--apply" ] && APPLY=1

red=$'\033[31m'; grn=$'\033[32m'; dim=$'\033[2m'; off=$'\033[0m'
[ -t 1 ] || { red=''; grn=''; dim=''; off=''; }

# ---- preconditions -------------------------------------------------------
if ! command -v git-filter-repo > /dev/null 2>&1; then
  echo "git-filter-repo is not installed. It is the supported tool for this;" >&2
  echo "git filter-branch is deprecated and mishandles encodings." >&2
  echo "    brew install git-filter-repo" >&2
  exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "the working tree is dirty. Commit or stash first -- an irreversible git" >&2
  echo "command run against a dirty tree is the easiest way to destroy work" >&2
  echo "that was never wrong to begin with." >&2
  exit 1
fi

branch=$(git rev-parse --abbrev-ref HEAD)
head_now=$(git rev-parse --short HEAD)
remote_url=$(git remote get-url origin 2>/dev/null || echo "")

# ---- what would change ---------------------------------------------------
echo "${dim}scanning $(git rev-list --count HEAD) commits on ${branch}...${off}"
matched=0
oldest=""
for sha in $(git rev-list HEAD); do
  msg=$(git log -1 --format='%B' "$sha")
  i=0
  while [ "$i" -lt "${#OLD[@]}" ]; do
    case "$msg" in
      *"${OLD[$i]}"*)
        echo "  ${red}-${off} $(git rev-parse --short "$sha") $(git log -1 --format='%s' "$sha")"
        echo "      ${dim}${OLD[$i]}${off}"
        echo "      ${grn}${NEW[$i]}${off}"
        matched=$((matched + 1))
        oldest="$sha"
        ;;
    esac
    i=$((i + 1))
  done
done

if [ "$matched" -eq 0 ]; then
  echo "${grn}nothing matches. History is already clean.${off}"
  exit 0
fi
echo "${matched} message(s) would change."

# Every commit from the OLDEST match onward gets a new hash, not only the ones
# that matched: a commit's hash covers its parent's.
affected=$(git rev-list --count "${oldest}^..HEAD" 2>/dev/null || git rev-list --count HEAD)
echo "${dim}${affected} commit(s) will get new hashes, from $(git rev-parse --short "$oldest") onward.${off}"

if [ "$APPLY" -eq 0 ]; then
  echo
  echo "This was a DRY RUN. Nothing changed."
  echo "Run it for real with:  scripts/scrub-history.sh --apply"
  exit 0
fi

# ---- backup, then rewrite ------------------------------------------------
backup="refs/backup/pre-scrub-${head_now}"
git update-ref "$backup" HEAD
echo "${grn}backup ref:${off} ${backup} -> ${head_now}"

callback="m = message"$'\n'
i=0
while [ "$i" -lt "${#OLD[@]}" ]; do
  callback+="m = m.replace(${OLD[$i]@Q}.encode(), ${NEW[$i]@Q}.encode())"$'\n'
  i=$((i + 1))
done
callback+="return m"

git filter-repo --force --message-callback "$callback" || {
  echo "${red}filter-repo failed. History is unchanged; the backup ref is ${backup}.${off}" >&2
  exit 1
}

# filter-repo drops the remote on purpose, so a rewritten repo cannot be pushed
# from muscle memory. Restored here because the push is the point -- and it is
# still a separate, deliberate command, printed at the end and never run.
if [ -n "$remote_url" ] && ! git remote get-url origin > /dev/null 2>&1; then
  git remote add origin "$remote_url"
  echo "${dim}restored remote origin -> ${remote_url}${off}"
fi

# ---- repair the citations the rewrite invalidated -------------------------
map=.git/filter-repo/commit-map
if [ ! -f "$map" ]; then
  echo "${red}no commit map at ${map}, so the hashes cited in tracked files" >&2
  echo "cannot be repaired. Check them by hand before pushing.${off}" >&2
  exit 1
fi

changed=0
for old_short in $(git ls-files | xargs grep -ohE '`[0-9a-f]{7,12}`' 2>/dev/null | tr -d '`' | sort -u); do
  old_full=$(awk -v p="^${old_short}" '$1 ~ p {print $1; exit}' "$map")
  [ -n "$old_full" ] || continue
  new_full=$(awk -v o="$old_full" '$1 == o {print $2; exit}' "$map")
  # All-zero would mean the commit was dropped, which this rewrite never does.
  [ -n "$new_full" ] || continue
  [ "$new_full" = "0000000000000000000000000000000000000000" ] && continue
  new_short=$(git rev-parse --short "$new_full")
  [ "$new_short" = "$old_short" ] && continue
  for f in $(git ls-files | xargs grep -l "\`${old_short}\`" 2>/dev/null); do
    perl -pi -e "s/\`\Q${old_short}\E\`/\`${new_short}\`/g" "$f"
    echo "  ${grn}+${off} ${f}: \`${old_short}\` -> \`${new_short}\`"
    changed=1
  done
done

if [ "$changed" -eq 1 ]; then
  git add -A
  # --no-verify because the gate takes about ninety seconds and this commit is
  # a mechanical hash substitution. The gate runs below instead, so its result
  # is reported rather than skipped.
  git commit -q --no-verify -F - <<'MSG'
docs: the commit hashes cited in src/checkout.rs follow the rewrite

A message rewrite moved every commit from the first scrubbed message onward, and
the two hashes this module cites to explain a real incident were both after that
point. A citation that resolves to nothing is worse than no citation, so they are
re-derived from filter-repo's commit map rather than re-typed.
MSG
  echo "${grn}citations repaired and committed.${off}"
fi

echo
echo "${dim}running the gate over the rewritten tree...${off}"
if bash scripts/verify.sh; then
  echo "${grn}gate green.${off}"
else
  echo "${red}the gate failed. Do NOT push. Inspect, or restore with:${off}" >&2
  echo "    git reset --hard ${backup}" >&2
  exit 1
fi

cat <<EOF

${grn}Done, locally.${off} Nothing has been pushed.

  Review     git range-diff ${backup}...HEAD
  Publish    git push --force-with-lease origin ${branch}
  Undo       git reset --hard ${backup}

Publishing OVERWRITES the remote branch and is not reversible once anyone
fetches it. Anyone else holding a clone must reset, never merge:

    git fetch origin && git reset --hard origin/${branch}
EOF
