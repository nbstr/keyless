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
# It does NOT push. A rewrite is reversible while it is local, and what makes it
# reversible is a BUNDLE written outside the repository before anything moves.
# A ref cannot do that job: `git filter-repo` rewrites every ref under `refs/`,
# `refs/backup/*` included, so a backup ref made by this script is rewritten by
# the very rewrite it exists to undo and ends up naming a commit in the NEW
# history. That is not a broken undo, it is a WORSE one: `git reset --hard` onto
# it succeeds, rewinds a commit or two, and leaves the scrub in place while
# reporting success. This repository already carries five `refs/backup/pre-scrub-*`
# refs from earlier passes and three of them name objects that no longer exist.
# So the safety net is a bundle, the stale refs are captured into it and then
# deleted, and the undo printed at the end is one that was tested by running it.
#
# ---------------------------------------------------------------------------
# This script is not interactive and `git filter-repo` is
# ---------------------------------------------------------------------------
#
# Every run of filter-repo leaves `.git/filter-repo/`, and a later run that
# finds it does one of two things WITHOUT being asked to: under a day old, it
# silently treats the new run as a CONTINUATION of the old one; older than that,
# it stops and prompts on stdin. There is no terminal here, so the prompt is an
# `EOFError` traceback out of filter-repo's sanity check -- which is how a real
# run of this script died, after the bundle was written and the stale backup
# refs were dropped.
#
# `--force` does not cover it. It is passed below, it was passed then, and the
# prompt fired anyway: the Already-Ran branch runs before `--force` is consulted
# and is not guarded by it.
#
# The traceback was the SAFE half of that behaviour. It refused, at the sanity
# check, before a ref had moved. The continuation is the dangerous half, and it
# exits 0 -- see the note above the rewrite for what it does to the commit map
# and therefore to the citation repair below.
#
# ---------------------------------------------------------------------------
# What it changes, and what it repairs
# ---------------------------------------------------------------------------
#
# Only the message text in the table below. No tree, no author, no date.
#
# Then it repairs the two things the rewrite breaks.
#
#   HASHES CITED IN TRACKED FILES. `src/checkout.rs` cites one commit and
#   `tests/state_vocabulary.rs` cites another five times, all to explain real
#   incidents, and all of them after the first rewritten commit. A citation that
#   resolves to nothing is worse than the prose it was added to support, so the
#   new hashes are read out of filter-repo's own commit map and written back.
#   The search is generic -- any backticked 7-to-12 hex string in any tracked
#   file that resolves through the map -- so a citation added later is repaired
#   without this comment having to be right about where it lives.
#
#   THE RATCHET. `KNOWN_UNSCRUBBED` in `hooks/tests/test_publication.py` names
#   every commit whose message this gate judges guilty and cannot fix, and it is
#   asserted in three directions: an entry that stops carrying a claim fails the
#   gate, and so does an entry whose sha stops being reachable. A rewrite does
#   both to every entry at once. So the rewrite that fixes those messages is
#   also what empties that list, and this script does it rather than leaving a
#   red gate for somebody to interpret.
#
# ---------------------------------------------------------------------------
# Why the ratchet is emptied AFTER the rewrite and never before
# ---------------------------------------------------------------------------
#
# Emptying it first would be the smaller diff and it is the wrong order. The
# list is what makes the gate fail on a NEW message carrying a figure; emptied
# while the six messages still carry theirs, it forgives nothing that is gone
# and guards nothing that is left -- a green gate over an unfixed history, which
# is the exact class of false green this repository is built to refuse.
#
# The ordering alone is not the guarantee, because an ordering is a thing a
# later edit can quietly reverse. The guarantee is `reconcile` below, which runs
# BEFORE anything is rewritten and refuses unless the grammar and the list agree
# exactly on which commits are guilty AND this table is proven to clear every
# one of them. The list is emptied because each entry has been shown fixed, not
# because the script reached that line.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The substitutions, as two parallel arrays. Keep each OLD long enough to be
# unambiguous: a short string matches somewhere nobody intended, and a commit
# message is not a thing to edit by accident.
# Longest first: these are applied in order, and a short pattern that is a
# SUBSTRING of a longer one fires inside it and leaves the longer one unable
# to match. The result is not a missed scrub, which would be visible -- it is
# a sentence rewritten into something that reads fine and says the wrong thing.
#
# Each entry keeps the REASONING of the sentence it replaces and drops only the
# magnitude: what the check was measured against, and what it concluded, survive
# as a property of the check. These are engineering records and the argument in
# them is the thing worth publishing.
#
# ⚠️ GENERATE THIS BLOCK, DO NOT TYPE IT. Four replacements contain an
# apostrophe, and a bash single-quoted string cannot hold one -- it needs the
# `'\''` dance, per entry, in the middle of a multi-paragraph string. Hand-typing
# that is how a pattern silently becomes a different pattern. It was emitted from
# python `repr`-style quoting and read back under `/bin/bash` 3.2 and compared
# byte for byte against the source table before it was pasted here.
OLD=(
  # d244c42
  '- Dropped machine-specific telemetry that read as a general fact. "307
  keychain items" and "~20 concurrent sessions" describe one machine; the
  points they carried are general and are kept without the numbers — a
  keychain answers any process running as you, and many sessions share one
  audit log. The 20-session figure stays where it is a test parameter.'
  # d244c42
  'Verified against the tree rather than restated: cargo test is 415 pass and 15
ignored, the verb set and exit codes match main.rs and store::manage, the
masker carries 20 encodings, the lookup timeout is 10s, and every internal
anchor and file link in the README resolves.'
  # a77db6a
  'Registered at BLOCK on measurement rather than confidence. Over 86,117 real
agent Bash calls and 1,791 interactive commands, 50,638 of which contain an
equals sign, it denies 326: connection-string passwords, credential-named
opaque values, JWTs, cloud keys, across 20 distinct variables. Zero denials on
anything else.'
  # 801de39
  'Four qualified spellings are now listed, plus PGPASSWORD, which appears 33
times in the corpus against 51 for every other glued spelling combined, all of
which are code.'
  # 801de39
  'The URL floor moves 6 to 8, proven neutral: identical counts, zero items
differing across 86,126 commands.'
  # 801de39
  'check, so 25,086 Write and Edit payloads were scanned alongside the commands.
53 new findings on commands, 8 on writes, zero lost anywhere. Hand-read all 53:
38 true, 7 ambiguous, 8 artifacts of a shell pipeline being captured as a
value — a class already present at the same rate before this change. At the
deployed block: 39 new denials, zero false positives, because a pipeline is
not a literal in assignment position.'
  # 801de39
  'NOT FIXED, and larger than what is fixed here: on the write corpus, 52 of 287
name-keyed findings are code references — a property assignment, an
environment read — which is the correct usage this pack asks people to write,
and the write check rewrites them on the way to disk. That is a deployed
rewrite corrupting source at roughly 18 percent. This change is neutral on'
  # 3bb7c07
  'MEASURED AT 70 PERCENT, NOT THE 18 IT WAS FILED AT. The earlier figure rested
on a corpus that had silently lost 2,569 of 3,296 transcript files: the glob
walked one directory level, and every subagent transcript sat one level below
it. Against the whole corpus — 191,651 commands, 51,384 write payloads, 95 MB
— 378 of 540 name-keyed findings are code references, and 233 of the 434
payloads that tripped the check carried at least one corrupting rewrite. It
was the majority behaviour, not an accident.'
  # 3bb7c07
  'Of the findings that survive this change, 34 of 259 sit in a file type whose
reader expands it — so in 87 percent of cases the substitution resolves to
nothing and the printed remediation does not apply.'
  # a40c37c
  'THE REWRITE WAS DOING THE WRONG THING IN 160 OF 216 CASES. Its whole
justification is that the placeholder is what the file'\''s own reader resolves —
and measured per payload over 51,848 write calls, 197 of the 216 that carried a
finding were in a file whose reader expands nothing. A TypeScript file holding a'
  # a40c37c
  'Measured: that tool has been invoked ZERO times in 334,477 calls, so it'
  # c0b74f0
  'Measured: two tokens written down as a two-permission pair each carry 383
permission groups, including the right to mint further tokens and to change
billing. Two sessions planned around a restriction that did not exist.'
)
NEW=(
  # d244c42
  '- Dropped machine-specific telemetry that read as a general fact. A keychain
  item count and a concurrent-session count describe one machine; the points
  they carried are general and are kept without the numbers — a keychain
  answers any process running as you, and many sessions share one audit log.
  The session figure stays where it is a test parameter.'
  # d244c42
  'Verified against the tree rather than restated: the suite is green with the
ignored count the gate asserts, the verb set and exit codes match main.rs and
store::manage, the masker'\''s encoding set matches the module, the lookup
timeout matches config.rs, and every internal anchor and file link in the
README resolves.'
  # a77db6a
  'Registered at BLOCK on measurement rather than confidence. Replayed over a
corpus of real agent Bash calls and interactive commands, it denies only
credential literals in assignment position: connection-string passwords,
credential-named opaque values, JWTs, cloud keys. Zero denials on
anything else.'
  # 801de39
  'Four qualified spellings are now listed, plus PGPASSWORD, whose share of the
corpus is comparable to every other glued spelling combined, all of which are
code.'
  # 801de39
  'The URL floor moves 6 to 8, proven neutral: identical counts, zero items
differing across the whole command corpus.'
  # 801de39
  'check, so the Write and Edit payloads were scanned alongside the commands.
New findings on both surfaces, none lost anywhere. Every new command finding
was hand-read: most are true, a few ambiguous, and the rest artifacts of a
shell pipeline being captured as a value — a class already present at the same
rate before this change. At the deployed block the new denials carry zero
false positives, because a pipeline is not a literal in assignment position.'
  # 801de39
  'NOT FIXED, and larger than what is fixed here: on the write corpus, name-keyed
findings that are code references — a property assignment, an environment read
— are the correct usage this pack asks people to write, and the write check
rewrites them on the way to disk. That is a deployed rewrite corrupting source
at a substantial fraction of everything it touches. This change is neutral on'
  # 3bb7c07
  'MEASURED AS THE MAJORITY CASE, NOT THE MINORITY IT WAS FILED AT. The earlier
figure rested on a corpus that had silently lost most of its transcript files:
the glob walked one directory level, and every subagent transcript sat one
level below it. Against the whole corpus, most name-keyed findings are code
references, and most of the payloads that tripped the check carried at least
one corrupting rewrite. It was the majority behaviour, not an accident.'
  # 3bb7c07
  'Of the findings that survive this change, only a small minority sit in a file
type whose reader expands it — so in most cases the substitution resolves to
nothing and the printed remediation does not apply.'
  # a40c37c
  'THE REWRITE WAS DOING THE WRONG THING IN MOST CASES. Its whole justification
is that the placeholder is what the file'\''s own reader resolves — and measured
per payload over the write corpus, nearly every payload that carried a finding
was in a file whose reader expands nothing. A TypeScript file holding a'
  # a40c37c
  'Measured: that tool has been invoked ZERO times in the corpus, so it'
  # c0b74f0
  'Measured: two tokens written down as a two-permission pair each carry the
provider'\''s full permission-group set, including the right to mint further
tokens and to change billing. Sessions planned around a restriction that did
not exist.'
)

# SINGLE quotes above, and that is not style. A double-quoted string runs
# backticks as a command: `"`m.replace(x)`"` became the empty string plus a
# syntax error on stderr, and an EMPTY pattern matches every commit ever made.
# It was harmless only because its replacement was emptied the same way, making
# it replace("", "") -- had one survived and the other not, the rewrite would
# have inserted text between every character of every message in the repository.
#
# The guard below is what makes that structural rather than remembered.

# debt: one machine's timing survives this table, because both grammars call it
#       legal. A latency figure carries a UNIT, and a number with a unit is
#       exempt from the census rule by a decision that is load-bearing
#       elsewhere -- `MESSAGE_EXEMPT` in `hooks/tests/test_publication.py`
#       asserts that a millisecond cost stated in a commit body is correct
#       writing, and a grammar widened to catch a latency reading would refuse
#       that fixture and every honest performance note after it. So the reading
#       stays, and this marker is the record that it was seen rather than
#       missed. Ceiling: this rewrite removes what the gate refuses; a timing
#       reading is not that, and two of the messages state a per-command cost
#       measured on whatever machine ran it.
#       Upgrade trigger: the unit exemption is narrowed -- a timing-specific
#       provenance rule lands in the census grammar, or `MESSAGE_EXEMPT` loses
#       its millisecond entry. Either makes those messages guilty, and they go
#       through this table in the same pass.
if [ "${#OLD[@]}" -ne "${#NEW[@]}" ]; then
  echo "the substitution table is uneven: ${#OLD[@]} patterns, ${#NEW[@]} replacements." >&2
  exit 1
fi
i=0
while [ "$i" -lt "${#OLD[@]}" ]; do
  if [ -z "${OLD[$i]}" ]; then
    echo "pattern ${i} is EMPTY, which matches every commit message in the" >&2
    echo "repository. Refusing to rewrite anything. The usual cause is a" >&2
    echo "double-quoted entry containing a backtick, which the shell ran as a" >&2
    echo "command and replaced with nothing." >&2
    exit 1
  fi
  i=$((i + 1))
done

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
bundle="$(cd .. && pwd)/keyless-pre-scrub-${head_now}.bundle"

# The table, in the environment, for every python step below. Exported once
# because python is the only thing here that quotes a python literal correctly.
i=0
while [ "$i" -lt "${#OLD[@]}" ]; do
  export "SCRUB_OLD_${i}=${OLD[$i]}"
  export "SCRUB_NEW_${i}=${NEW[$i]}"
  i=$((i + 1))
done
export SCRUB_COUNT="${#OLD[@]}"

# ---- reconcile the table against the gate that judges the result ----------
#
# This is the step that decides whether the rewrite is allowed to empty the
# ratchet, and it runs before anything moves. It asks the repository's own
# grammar which messages are guilty, and refuses on any disagreement:
#
#   a guilty message this table does not clear   the scrub is incomplete, and
#                                                emptying the list would forgive
#                                                a claim that is still there
#   a guilty message not on the list             the gate is already red; fix
#                                                that first, this cannot
#   a listed sha that is not guilty              the list is stale; the gate is
#                                                already red for that too
#
# A table can also go SPENT -- every pattern already applied by an earlier pass,
# so nothing matches and the run reports a clean history it never read. That is
# not hypothetical: this script's table was spent and it printed exactly that,
# green and exit 0, while six messages the gate refuses sat in published
# history. The grammar is asked first for that reason, so "nothing matches" can
# only ever be printed over a history the gate agrees is clean.
echo "${dim}reconciling the table against the census grammar...${off}"
reconcile=$(python3 - <<'PY'
import importlib.util, os, sys

# The module is loaded, not run, so `sys.path[0]` is not its own directory and
# its sibling `harness` is not importable without saying so. Loading it is the
# point: the grammar that judges the result has to be the SAME code, never a
# second copy of it living here.
GATE = "hooks/tests/test_publication.py"
sys.path.insert(0, os.path.dirname(os.path.abspath(GATE)))
spec = importlib.util.spec_from_file_location("keyless_publication", GATE)
tp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tp)

pairs = [(os.environ["SCRUB_OLD_%d" % i], os.environ["SCRUB_NEW_%d" % i])
         for i in range(int(os.environ["SCRUB_COUNT"]))]

messages = tp.commit_messages()
if len(messages) < 25:
    print("REFUSE\tthe history walk read %d commits, which is not a full "
          "checkout. A shallow clone reads exactly like a clean history."
          % len(messages))
    raise SystemExit(0)

guilty = [(sha, body) for sha, body in messages if tp.claims_in_message(body)]
guilty_shas = set(sha for sha, _ in guilty)
listed = set(tp.KNOWN_UNSCRUBBED)

problems = []
for sha in sorted(guilty_shas - listed):
    problems.append("%s carries a census claim and is not in KNOWN_UNSCRUBBED, "
                    "so the gate is red before this script runs" % sha[:12])
for sha in sorted(listed - guilty_shas):
    problems.append("%s is in KNOWN_UNSCRUBBED and carries no claim, so the "
                    "list is stale and the gate is red before this script runs"
                    % sha[:12])

unfixed = []
for sha, body in guilty:
    m = body
    for old, new in pairs:
        m = m.replace(old, new)
    hits = tp.claims_in_message(m)
    if hits:
        unfixed.append((sha, len(hits)))
for sha, n in unfixed:
    problems.append("%s still carries %d census claim(s) after this table is "
                    "applied, so the ratchet may not be emptied" % (sha[:12], n))

# A pattern that matches nothing anywhere is a spent entry, and a table that is
# PART spent is a table that disagrees with this history about what is in it.
joined = "\n".join(body for _, body in messages)
spent = [i for i, (old, _) in enumerate(pairs) if old not in joined]
if spent and len(spent) != len(pairs):
    problems.append("pattern(s) %s match nothing in this history while others "
                    "do, so the table and the history disagree about what is "
                    "here" % ", ".join(str(i) for i in spent))

if problems:
    for p in problems:
        print("REFUSE\t%s" % p)
elif not guilty_shas:
    print("CLEAN\tno commit message carries a census claim")
else:
    print("READY\t%d" % len(guilty_shas))
    for sha, _ in guilty:
        print("GUILTY\t%s" % sha)
PY
) || { echo "${red}the reconciliation could not run.${off}" >&2; exit 1; }

if printf '%s\n' "$reconcile" | grep -q '^REFUSE'; then
  echo "${red}refusing to rewrite anything:${off}" >&2
  printf '%s\n' "$reconcile" | sed -n 's/^REFUSE\t/  - /p' >&2
  exit 1
fi
if printf '%s\n' "$reconcile" | grep -q '^CLEAN'; then
  echo "${grn}no commit message carries a census claim, and the ratchet is empty."
  echo "History is already clean.${off}"
  exit 0
fi
guilty_count=$(printf '%s\n' "$reconcile" | sed -n 's/^READY\t//p')
echo "${grn}the table clears every one of the ${guilty_count} guilty message(s).${off}"

# ---- what would change ---------------------------------------------------
echo "${dim}scanning $(git rev-list --count HEAD) commits on ${branch}...${off}"
matched=0
hits=0
oldest=""
for sha in $(git rev-list HEAD); do
  msg=$(git log -1 --format='%B' "$sha")
  shown=0
  i=0
  while [ "$i" -lt "${#OLD[@]}" ]; do
    case "$msg" in
      *"${OLD[$i]}"*)
        # One header per COMMIT. The count a human reads to decide has to be
        # the number of messages that change, and a message routinely matches
        # several patterns -- counting per hit reported twelve for six commits.
        if [ "$shown" -eq 0 ]; then
          echo "  ${red}-${off} $(git rev-parse --short "$sha") $(git log -1 --format='%s' "$sha")"
          shown=1
          matched=$((matched + 1))
          oldest="$sha"
        fi
        echo "      ${dim}$(printf '%s' "${OLD[$i]}" | head -1 | cut -c1-72)...${off}"
        echo "      ${grn}$(printf '%s' "${NEW[$i]}" | head -1 | cut -c1-72)...${off}"
        hits=$((hits + 1))
        ;;
    esac
    i=$((i + 1))
  done
done

if [ "$matched" -eq 0 ]; then
  # Unreachable while `reconcile` agrees, and kept because the two read the
  # history by different means. They disagreeing is a fact, not a no-op.
  echo "${red}the grammar names ${guilty_count} guilty message(s) and this table" >&2
  echo "matched none of them. Refusing to rewrite nothing and report success.${off}" >&2
  exit 1
fi
echo "${matched} message(s) would change, across ${hits} substitution(s)."

# Every commit from the OLDEST match onward gets a new hash, not only the ones
# that matched: a commit's hash covers its parent's.
affected=$(git rev-list --count "${oldest}^..HEAD" 2>/dev/null || git rev-list --count HEAD)
echo "${dim}${affected} commit(s) will get new hashes, from $(git rev-parse --short "$oldest") onward.${off}"
echo "${dim}KNOWN_UNSCRUBBED in hooks/tests/test_publication.py will be emptied,"
echo "because every sha it names is one of the ${matched} above.${off}"

if [ "$APPLY" -eq 0 ]; then
  echo
  echo "This was a DRY RUN. Nothing changed."
  echo "Run it for real with:  scripts/scrub-history.sh --apply"
  exit 0
fi

# ---- the one check `--force` waives that this script still needs ----------
#
# `--force` on the rewrite below is not optional. filter-repo refuses any
# repository that does not look freshly cloned, and this one has its own
# history, more than one pack and hundreds of loose objects. But `--force`
# waives the WHOLE sanity check -- a dozen separate refusals -- not the one
# standing in the way, so each of them has to be accounted for here rather than
# dropped quietly.
#
# Most are already covered or turned out not to be hazards. The dirty-tree,
# untracked-file and staged-change refusals are subsumed by the
# `git status --porcelain` check above, which is stricter and fires earlier.
# The freshly-packed, one-remote and single-reflog-entry refusals are the
# fresh-clone heuristic itself, which is exactly what `--force` exists to waive.
# A second worktree and a stash were both checked by running the rewrite with
# each present: filter-repo maps them onto the new history like any other ref,
# the worktree stays usable and the stash still pops, so neither earns a refusal
# here.
#
# One is not covered, and what it guards is a promise this script PRINTS. The
# undo at the end offers `git reset --hard origin/<branch>` as the convenient
# alternative to the bundle, and that is an undo only while origin still holds
# this history. On a branch ahead of its remote it succeeds, reports success,
# and silently discards every commit origin never saw -- including, the first
# time anyone runs this, the commit that fixed this script.
#
# So the answer is not to refuse the rewrite. The rewrite is fine either way,
# because the bundle holds every ref. The answer is to stop printing an
# instruction that is wrong here: the shortcut is emitted only when origin
# really does hold what is about to be rewritten, and the reader is told why it
# is missing when it is. A warning beside a wrong command is not a fix; removing
# the command is.
origin_undo=""
if [ -n "$remote_url" ] && git rev-parse --verify --quiet "refs/remotes/origin/${branch}" > /dev/null; then
  ahead=$(git rev-list --count "refs/remotes/origin/${branch}..HEAD")
  if [ "" -eq 0 ]; then
    origin_undo=$'\n             or, while origin still holds the old history:\n             git fetch origin && git reset --hard origin/'"${branch}"
  else
    echo "${red}note: ${branch} is ${ahead} commit(s) ahead of origin/${branch}.${off}"
    echo "${dim}  The bundle below is the ONLY undo for this run. The usual"
    echo "  'git reset --hard origin/${branch}' shortcut is not printed at the end,"
    echo "  because running it would discard those ${ahead} commit(s) as well as"
    echo "  the rewrite.${off}"
  fi
else
  echo "${dim}note: no origin/${branch} to fall back on. The bundle below is the"
  echo "  only undo for this run.${off}"
fi

# ---- the safety net, which has to survive the rewrite --------------------
#
# Deleted first. A stale bundle from an earlier run is a file that makes a
# restore LOOK available while restoring the wrong history.
rm -f "$bundle"
git bundle create "$bundle" --all || {
  echo "${red}could not write the bundle. Nothing has been rewritten.${off}" >&2
  exit 1
}
git bundle verify "$bundle" > /dev/null || {
  echo "${red}the bundle does not verify. Nothing has been rewritten.${off}" >&2
  rm -f "$bundle"
  exit 1
}
echo "${grn}safety net:${off} ${bundle}"
echo "${dim}  it holds every ref including refs/remotes/origin/*, which filter-repo"
echo "  deletes, and it is outside the repository so the rewrite cannot reach it.${off}"

# The backup refs earlier passes of THIS script left behind, captured above and
# removed here. filter-repo maps them faithfully onto the new history, which is
# the problem: `refs/backup/pre-scrub-<X>` then names a commit in the rewritten
# history while its name promises the state before a scrub, and `git reset
# --hard` onto it succeeds, rewinds the repair commit and leaves the scrub in
# place. Three of the ones sitting here are already named for a short hash that
# no longer resolves.
#
# Only `pre-scrub-*` goes. Any other ref under `refs/backup/` marks something
# this script did not do and did not promise to undo, and filter-repo carries it
# across correctly. They are all in the bundle either way.
for ref in $(git for-each-ref --format='%(refname)' 'refs/backup/pre-scrub-*'); do
  echo "${dim}  dropping ${ref} -- it names a scrub it cannot undo${off}"
  git update-ref -d "$ref"
done

# ---- rewrite -------------------------------------------------------------
#
# The callback is Python, and PYTHON does the quoting -- not the shell.
#
# This used to interpolate with bash's `${var@Q}`. macOS ships bash 3.2, where
# `${x@Q}` is a hard error but `${ARRAY[$i]@Q}` SILENTLY yields the raw value:
# the subscript is parsed as arithmetic and the `@Q` is swallowed. The generated
# code was therefore `m.replace(and reached 41 GB...)` with no quotes at all,
# and filter-repo died on a SyntaxError from inside an exec. A quoting bug that
# announces itself is fine; one that only announces itself on the OTHER shell is
# how a rewrite of published history goes wrong.
#
# So: repr() from python3, which is the only thing that knows how to quote a
# python literal, and no bash version to be wrong about.
callback=$(python3 -c '
import os
lines = ["m = message"]
for i in range(int(os.environ["SCRUB_COUNT"])):
    old = os.environ["SCRUB_OLD_%d" % i].encode()
    new = os.environ["SCRUB_NEW_%d" % i].encode()
    lines.append("m = m.replace(%r, %r)" % (old, new))
lines.append("return m")
print("\n".join(lines))
') || { echo "${red}could not build the callback.${off}" >&2; exit 1; }

# Compiled before it is trusted. filter-repo execs this inside a function body,
# so a syntax error surfaces as a traceback from its internals rather than as
# anything naming this script.
python3 -c '
import sys
body = sys.stdin.read()
src = "def _cb(message):\n" + "\n".join("  " + l for l in body.splitlines())
compile(src, "<callback>", "exec")
' <<< "$callback" || {
  echo "${red}the generated callback is not valid python. Refusing to rewrite.${off}" >&2
  echo "$callback" >&2
  exit 1
}

# FRESH, never a continuation -- and the difference is silent, so it is decided
# here rather than left to filter-repo's own default.
#
# `.git/filter-repo/already_ran` is left by every earlier run. Finding it,
# filter-repo either prompts (an EOFError here) or, when it is under a day old,
# treats this run as a CONTINUATION without asking. A continuation COMPOSES the
# stored map with this run's, so `commit-map` comes back keyed by the hashes
# history had before the EARLIER run.
#
# Nothing downstream speaks those hashes. The citations in tracked files and the
# shas in `KNOWN_UNSCRUBBED` all name commits in the history that is here now.
# The repair below looks each cited hash up as a KEY of the map, and under a
# continuation there is no such key, so it `continue`s: no repair printed, exit
# 0, and a citation left resolving to nothing in published history. Measured by
# replaying this repository's own filter-repo state into a clone: 97 of the 124
# map keys named objects the repository did not contain, and the hash cited in
# `src/checkout.rs` was not a key at all.
#
# Removing the file is precisely what filter-repo does when a human answers N --
# `os.remove(ran_path)`, and nothing else. The other metadata files stay: a
# fresh run opens each of them 'bw' and rewrites it, so no part of the old map
# can reach the repair step.
ran=.git/filter-repo/already_ran
if [ -f "$ran" ]; then
  echo "${dim}dropping ${ran}: this is a fresh rewrite of the history that is"
  echo "  here, not a continuation of an earlier one.${off}"
  rm -f "$ran" || {
    echo "${red}could not remove ${ran}. Nothing has been rewritten.${off}" >&2
    exit 1
  }
fi

# stdin closed on purpose. Every prompt filter-repo can reach is a hang in a
# script with no terminal; with no stdin they fail fast instead. The only other
# prompt in this version needs --sensitive-data-removal, which is never passed
# here, so with `already_ran` gone there is no reachable prompt left at all.
git filter-repo --force --message-callback "$callback" < /dev/null || {
  echo "${red}filter-repo failed. Restore with the bundle:${off}" >&2
  echo "    git fetch \"${bundle}\" 'refs/heads/${branch}:refs/restore/${branch}'" >&2
  echo "    git reset --hard refs/restore/${branch}" >&2
  echo "${dim}    The bundle is kept rather than cleaned up: a failure here can land" >&2
  echo "    either side of the first ref moving, and it is the only copy of the" >&2
  echo "    refs/backup/* entries dropped above. It is spent once ${head_now} is no" >&2
  echo "    longer this repository's HEAD.${off}" >&2
  exit 1
}

# filter-repo drops the remote on purpose, so a rewritten repo cannot be pushed
# from muscle memory. Restored here because the push is the point -- and it is
# still a separate, deliberate command, printed at the end and never run.
if [ -n "$remote_url" ] && ! git remote get-url origin > /dev/null 2>&1; then
  git remote add origin "$remote_url"
  echo "${dim}restored remote origin -> ${remote_url}${off}"
fi

# ---- repair what the rewrite invalidated ----------------------------------
map=.git/filter-repo/commit-map
if [ ! -f "$map" ]; then
  echo "${red}no commit map at ${map}, so the hashes cited in tracked files" >&2
  echo "cannot be repaired. Check them by hand before pushing.${off}" >&2
  exit 1
fi

repaired=""
for old_short in $(git ls-files | xargs grep -ohE '`[0-9a-f]{7,12}`' | tr -d '`' | sort -u); do
  old_full=$(awk -v p="^${old_short}" '$1 ~ p {print $1; exit}' "$map")
  [ -n "$old_full" ] || continue
  new_full=$(awk -v o="$old_full" '$1 == o {print $2; exit}' "$map")
  # All-zero would mean the commit was dropped, which this rewrite never does.
  [ -n "$new_full" ] || continue
  [ "$new_full" = "0000000000000000000000000000000000000000" ] && continue
  new_short=$(git rev-parse --short "$new_full")
  [ "$new_short" = "$old_short" ] && continue
  for f in $(git ls-files | xargs grep -l "\`${old_short}\`"); do
    perl -pi -e "s/\`\Q${old_short}\E\`/\`${new_short}\`/g" "$f"
    echo "  ${grn}+${off} ${f}: \`${old_short}\` -> \`${new_short}\`"
    repaired="${repaired}${f}"$'\n'
  done
done

# The ratchet, emptied only now: every sha it named was proven fixed by
# `reconcile` above, and the rewrite that fixed them has landed.
ratchet=hooks/tests/test_publication.py
python3 - "$ratchet" <<'PY' || { echo "${red}could not empty the ratchet. Do NOT push.${off}" >&2; exit 1; }
import os, re, sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    src = fh.read()

new, n = re.subn(r"(?ms)^KNOWN_UNSCRUBBED = \[.*?^\]\n",
                 "KNOWN_UNSCRUBBED = []\n", src)
if n != 1:
    sys.stderr.write("KNOWN_UNSCRUBBED is not spelled the way this step reads "
                     "it (%d matches). Empty it by hand.\n" % n)
    raise SystemExit(1)
compile(new, path, "exec")
with open(path, "w", encoding="utf-8") as fh:
    fh.write(new)

# Read back from disk rather than trusting the write, and through the module's
# own loader rather than a regex: what the gate imports is what has to be empty.
import importlib.util
sys.path.insert(0, os.path.dirname(os.path.abspath(path)))
spec = importlib.util.spec_from_file_location("keyless_publication_after", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
if mod.KNOWN_UNSCRUBBED != []:
    sys.stderr.write("the ratchet is still not empty after the edit.\n")
    raise SystemExit(1)
PY
echo "  ${grn}+${off} ${ratchet}: KNOWN_UNSCRUBBED emptied"
repaired="${repaired}${ratchet}"$'\n'

# One commit, not two. Splitting it would create an intermediate revision whose
# citations resolve to nothing OR whose ratchet guards nothing, and this
# repository does not keep a red commit as a step.
msg=$(mktemp -t keyless-scrub-msg)
cat > "$msg" <<'MSG'
docs: the tree follows the message rewrite that just landed

Rewriting the guilty commit messages moved every commit from the first of them
onward, which breaks two things in the tree at once.

The commit hashes cited in tracked files to explain real incidents all sat after
that point. A citation that resolves to nothing is worse than no citation, so
they are re-derived from filter-repo's commit map rather than re-typed.

KNOWN_UNSCRUBBED named the messages the census gate judged guilty and could not
fix, and it is asserted in three directions -- an entry that stops carrying a
claim fails, and so does an entry whose sha stops being reachable. The rewrite
did both to every entry, so the list is emptied here, after the fix and never
before it: emptied first it would have forgiven nothing and guarded nothing.
MSG
python3 "$ratchet" --message-file "$msg" || {
  echo "${red}this script's own commit message fails the census gate.${off}" >&2
  rm -f "$msg"
  exit 1
}
# --no-verify because the gate takes about ninety seconds and this commit is a
# mechanical substitution. The gate runs below instead, so its result is
# reported rather than skipped -- and the message was just judged by hand above,
# which is the half of the hook a rewrite cannot afford to skip.
# --only, never `add -A`: this is the one commit in the run and it says exactly
# which paths it carries.
printf '%s' "$repaired" | sort -u | tr '\n' '\0' \
  | xargs -0 git commit -q --no-verify -F "$msg" --only -- || {
  echo "${red}could not commit the repairs. Do NOT push.${off}" >&2
  rm -f "$msg"
  exit 1
}
rm -f "$msg"
echo "${grn}citations and ratchet committed.${off}"

echo
echo "${dim}running the gate over the rewritten tree...${off}"
if bash scripts/verify.sh; then
  echo "${grn}gate green.${off}"
else
  echo "${red}the gate failed. Do NOT push. Inspect, or restore with the undo below.${off}" >&2
  gate=1
fi

cat <<EOF

${grn}Done, locally.${off} Nothing has been pushed.

  Review     git log --oneline | head
  Publish    git push --force-with-lease origin ${branch}

  Undo       git fetch "${bundle}" 'refs/heads/${branch}:refs/restore/${branch}' \\
               && git reset --hard refs/restore/${branch}
${origin_undo}
There is deliberately NO backup ref to reset onto. filter-repo rewrites
refs/backup/* along with everything else, so one would name a commit in the
NEW history and undo nothing while appearing to work.

Keep ${bundle}
until the push is confirmed. It is the only copy of the old history once the
remote is overwritten.

Publishing OVERWRITES the remote branch and is not reversible once anyone
fetches it. Anyone else holding a clone must reset, never merge:

    git fetch origin && git reset --hard origin/${branch}
EOF
exit "${gate:-0}"
