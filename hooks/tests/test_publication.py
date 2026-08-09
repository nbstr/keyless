"""The census class, made mechanically impossible rather than merely cleaned up.

This repository publishes. Two kinds of private detail were spread through it and
both were scrubbed by hand once, in `src/`, `tests/` and the top-level README:

    IDENTITY   who built it, with what judgement, and what they got wrong.
               KEPT. An unsigned security tool is less trustworthy than a signed
               one, and this guard must never touch it.
    CENSUS     what is inside the author's machine and accounts — transcripts
               held, credential sites found, secrets in a vault, and how often
               their own guard fired and on what.

**The census scrub has already failed once, and it failed for a reason that has
nothing to do with care.** It was carried out as a list of line numbers, and one
commit later a scrubbed claim was back, because a list of line numbers describes
where a class WAS rather than what the class IS. `hooks/` was left out of that
pass entirely, and by the time anyone returned to it the line numbers were stale
and the class had spread to roughly thirty sites across nine files.

So this is a grammar, not a list, and it names no real coordinate in order to
forbid one — the same reason `tests/publication.rs` is an allowlist of decoys.

    A NUMBER MAY NOT STAND NEAR A WORD THAT MAKES IT AN OBSERVATION.

That is the whole rule. `700 checks` is a property of this repository and passes
anywhere. `7 of 24 organic denies` is a measurement of one machine's traffic and
fails, and so does the next one, whatever it counts and whoever writes it. A
number carrying a UNIT, a VERSION or a DATE is exempt, because those describe the
product or its environment rather than a population that was counted.

Both directions are asserted, because a scanner that quietly stopped matching
would report a clean tree exactly like a clean tree does:

    the tree is clean            no prose in hooks/ carries a census claim
    a planted claim is caught    each of six shapes, one per real site scrubbed
    the exemptions are real      a unit, a version and a date each survive

**Commit messages are scanned here too, and they are the surface every other
guard in this repository is blind to.** The Rust guard next door reads `src/`,
`tests/`, `hooks/`, `site/` and the README; nothing read a commit body, and five
messages in this history carry a transcript total, a corpus size or a
keychain-item count. A commit body is prose, and this is the only prose grammar
in the repository — a second copy in Rust would be two graders that drift apart.
See `KNOWN_UNSCRUBBED` for the ratchet that empties as the queued history
rewrite lands, and `check_message_file` for the same grammar as a `commit-msg`
hook body, which stops the next one being written at all.

`PROVENANCE` is deliberately the list somebody has to extend. Adding a word is
free; adding a NUMBER next to one is the moment a person has to answer out loud
whether they are describing the product or their own machine.
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import Suite  # noqa: E402

HOOKS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(HOOKS)

# Words that turn a number into a claim about an observed population. Each one
# below is taken from a site that was really scrubbed out of this pack.
PROVENANCE = [
    "corpus", "organic", "transcript", "transcripts", "estate", "estates",
    "decision log", "this machine", "genuine save", "genuine saves",
    "real command", "real commands", "real agent", "real file", "real files",
    "payload", "payloads", "denial", "denials", "denies", "warns",
    "false positive", "false positives", "in production", "live production",
    "measured over", "replayed over", "in the wild",
    "sessions", "agent bash", "shell command", "shell commands",
]

# `symlink` is deliberately NOT in that list, and the omission is reasoned.
# It appeared in one scrubbed site — an estate with N real files behind N
# symlinks — where `estate` and `real files` are both present and both catch it
# (`PLANTS` asserts exactly that sentence is still caught). On its own it is an
# ordinary filesystem noun that this pack's own attack list uses to name a
# technique, so carrying it would refuse true writing to catch nothing new.

# Words that turn a provenance word back into a product noun. `attack corpus` is
# a table in `tests/test_adversarial.py`; `command corpus` is somebody's shell
# history. Both end in the same word and only one of them is private, so the
# qualifier is the discrimination and it has to be read.
#
# Without this the guard refuses `the 87 attacks in the attack corpus`, which is
# a true statement about this repository — and a gate that refuses correct work
# gets removed, taking every other guarantee with it.
PRODUCT_QUALIFIERS = ("attack", "fixture", "decoy", "test", "mutation", "vendor")

# How close is "near". A comment paragraph is the unit a person writes in, and
# every scrubbed site had its number and its provenance word inside one.
WINDOW = 160

# A number that is exempt from the rule, tried BEFORE the rule runs.
#
#   version   `0.43.114`, `2.1.223`, `3.13` — names a build, not a population
#   date      `2026-08-08`
#   unit      `+6 ms`, `100 KB`, `2.5x`, `64 characters`, `12 bytes`
#
# Units are enumerated rather than open, and the list holds only dimensions this
# repository legitimately reports: time, size, multiples, and lengths inside a
# pattern. There is no unit for "commands I have seen".
_UNITS = (r"ms|milliseconds?|s|seconds?|minutes?|KB|MB|GB|bytes?|characters?|"
          r"chars?|lines?|x|%|columns?|deep|levels?")
#
#   exit code `exit 127`, `exits 1`, `exit code 0`
#
# An exit code is a protocol constant, exactly like a unit: 127 is what a shell
# returns when it cannot find a command, and it means the same thing on every
# machine. It earned its place by measurement rather than by taste — over this
# repository's own commit messages it is the ONLY false positive the provenance
# rule produced, from a sentence reading `exit 127 with no child at all — which
# on a machine running twenty concurrent sessions`.
_EXEMPT = re.compile(
    r"\d{4}-\d{2}-\d{2}"                        # a date
    r"|\d[\d,]*\.\d+(?:\.\d+)*"                 # a version
    r"|\bPython\s*\d[\d.]*"                     # `Python 3.6`
    r"|\bexits?(?:\s+code|\s+status|ed)?\s+\d+" # an exit code
    r"|\+?\d[\d,]*(?:\.\d+)?\s*(?:" + _UNITS + r")\b")   # a number with a unit

# A number that could be a census claim near a provenance word: two digits or
# more, or a grouped thousand. A bare single digit is not enough on its own —
# "one of the four shapes" is prose, not a measurement.
_NUMBER = re.compile(r"\b\d[\d,]{1,}\b")

# A RATIO in figures is a census claim on its own, with no provenance word
# needed. `9 of 26` and `dropped one out of 511` are statements about a
# population that was counted, and the population is always somebody's machine —
# there is no property of this repository that is naturally written as a ratio of
# two measured integers.
#
# This is the rule that catches the sites where the sentence describes the
# MECHANISM well enough that no provenance word appears in it at all. One such
# site sat in `checks/file_read.py` and the provenance rule alone did not see it.
#
# Spelling the ratio in words — "five of ten bypass spellings" — is untouched and
# stays legal, which is what this pack's own prose already does where the ratio is
# a property of a harness rather than of a corpus.
_RATIO = re.compile(r"\b\d+\s+of\s+(?:the\s+)?\d[\d,]*\b|\bout of\s+\d[\d,]*\b")

_SKIP_DIRS = ("__pycache__",)

# EVERY text extension in `hooks/`, not the ones that seemed likely. A guard that
# scans a subset reports the unscanned part clean, which is the same failure as
# not having a guard at all — and it is the failure the Rust scanner next door
# still has, since its walk filters on `.rs` and would find nothing here even
# after `hooks` were added to its roots.
#
# `run` asserts this list against what the directory actually contains, so a file
# type appearing for the first time fails loudly instead of being skipped.
_EXTS = (".py", ".json", ".md", ".sh")

# A fenced code block in markdown, and an inline code span. Code is not prose:
# `{12,256}` is a quantifier and `[:200]` is a slice.
_FENCE = re.compile(r"```.*?```", re.S)
_INLINE = re.compile(r"`[^`\n]*`")


def _clean(units):
    """Strip code spans from each unit and normalise its whitespace.

    ⚠️ CODE SPANS ARE STRIPPED PER UNIT, BEFORE THE JOIN — and every branch of
    `prose_of` comes through here so none of them can get that order wrong
    separately.

    `_INLINE` deletes a backtick pair and everything between it, and its class
    excludes newlines, so in raw text a span can never run past a line. Collapsing
    whitespace FIRST removes that guard: the text becomes one line, a backtick
    near the top pairs with one hundreds of lines below, and the whole span goes.
    Measured on this file: 12,664 characters of prose became 9,926, and the
    deleted middle held the planted census sentences the suite proves itself with.
    The guard read its own plants as absent and reported the tree clean.

    That was found in the Python branch. The JSON and shell branches had the same
    ordering and had simply not met an unbalanced backtick yet — a latent version
    of a bug that had already fired twice, which is not a thing to leave in a file
    whose entire job is to not under-read.
    """
    return [re.sub(r"\s+", " ", _INLINE.sub(" ", u)) for u in units]


def _files():
    out = []
    for dirpath, dirs, files in os.walk(HOOKS):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in sorted(files):
            if name.endswith(_EXTS):
                out.append(os.path.join(dirpath, name))
    return sorted(out)


def prose_of(text, path):
    """Every human-written part of a file, as a LIST of units.

    ⚠️ A UNIT IS THE SEARCH SCOPE, and that is a correctness property rather than
    a formatting choice. Joining a whole file into one string puts a fixture's
    `"export PORT=3000"` within a hundred characters of a comment saying *the bulk
    of every `=` in the corpus`, and the guard reports a census claim that nobody
    wrote — measured, on this pack's own false-positive suite. A number and the
    word that makes it an observation have to be in the SAME piece of writing.

    A paragraph of consecutive comment lines is ONE unit, so a sentence wrapped
    across a comment block is still one sentence.

    **Undoing the wrap is the point of this function, not a tidy-up.** A phrase
    split across two comment lines — `read on this` / `# machine` — is invisible
    to any line-based search, and a line-based search is exactly what a person
    reaches for. Two separate sweeps of this pack missed the same site that way,
    one of them written while this file was being written.
    """
    if path.endswith(".sh"):
        # Shell: `#` comments, rejoined across consecutive lines for the same
        # reason the Python branch rejoins them.
        paras, last = [], None
        for n, line in enumerate(text.split("\n"), 1):
            stripped = line.strip()
            if not stripped.startswith("#"):
                continue
            body = stripped.lstrip("#")
            if last is not None and n == last + 1:
                paras[-1] += " " + body
            else:
                paras.append(body)
            last = n
        return paras

    if path.endswith(".md"):
        return _FENCE.sub(" ", text).split("\n")

    if path.endswith(".json"):
        # Only the human fields. A JSON `find`/`replace` pair is source code.
        import json
        try:
            data = json.loads(text)
        except ValueError:
            # Unparseable is not clean. Scan the raw bytes instead: noisier,
            # never blinder — the same rule as the tokenizer fallback below.
            return [text]
        out = []

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in ("why", "_keylessComment", "note", "comment"):
                        out.append(v if isinstance(v, str) else " ".join(map(str, v)))
                    else:
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(data)
        return out

    # Python: every comment and every string literal, via the real tokenizer.
    #
    # ⚠️ DO NOT REPLACE THIS WITH A REGEX. The first version of this function did
    # exactly that — fold `\n\s*#` into a space, then keep the lines that start
    # with `#` — and it silently dropped every comment block that follows a line
    # of code, because folding the block's FIRST line onto the code line means the
    # paragraph no longer starts with a `#`. It read a fifth of this pack's prose
    # and reported the tree clean. Measured against the pre-scrub tree it found 25
    # census claims in 7 files where the tokenizer finds many more across 13.
    #
    # A scanner that under-reads and a clean tree produce the same empty list,
    # which is the whole failure mode this file exists to prevent. `run` asserts a
    # prose FLOOR and a specific deep inline comment for that reason.
    import io
    import tokenize

    units = []
    last_line = None
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                body = tok.string.lstrip("#")
                # Rejoin comments on CONSECUTIVE lines into one paragraph. A
                # sentence wrapped across a comment block is one sentence, and
                # reading it as two is how `read on this` / `# machine` survived
                # two separate sweeps of this pack.
                if last_line is not None and tok.start[0] == last_line + 1 and units:
                    units[-1] += " " + body
                else:
                    units.append(body)
                last_line = tok.start[0]
            elif tok.type == tokenize.STRING:
                units.append(tok.string)
                last_line = None
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # A file this tokenizer cannot read is not a file this guard may pass in
        # silence. Fall back to the whole text: noisier, never blinder.
        return [text]

    return units


def census_claims(text, ratios=True):
    """Every (number, provenance word) pair standing within WINDOW of each other.

    `ratios=False` drops the bare-ratio rule and keeps the provenance rule.

    ⚠️ THAT SWITCH IS A MEASUREMENT, NOT A PREFERENCE, and turning it back on
    for commit messages would delete this gate within a week. The ratio rule
    earns its keep over `hooks/` prose, where a ratio of two measured integers
    is always somebody's machine. A commit BODY is a different genre: it reports
    what a change did to a test suite, and that is naturally written as a ratio
    of two product counts. Measured over this repository's own 29 messages, the
    rule fired five times and every one was a product count — `14 of 14`,
    `13 of 13`, `71 of 71`, `64 of the 464 tests`, `0 of 415 tests run there`.
    Five for five is not a threshold worth tuning; it is the wrong rule for the
    genre.

    The provenance rule alone flags five messages over the same history, and all
    five are real: transcript totals, corpus sizes, a keychain-item count. So
    dropping the ratio rule costs nothing measurable here and buys a gate whose
    refusals a person will believe.
    """
    found = []
    exempt = list(_EXEMPT.finditer(text))

    def _is_exempt(m):
        return any(e.start() <= m.start() and m.end() <= e.end() for e in exempt)

    for m in _RATIO.finditer(text) if ratios else []:
        if not _is_exempt(m):
            found.append((m.group(0), "a ratio in figures"))

    low = text.lower()
    marks = []
    for word in PROVENANCE:
        start = 0
        while True:
            i = low.find(word, start)
            if i < 0:
                break
            before = low[max(0, i - 14):i].strip().split()
            if before and before[-1].rstrip("s") in PRODUCT_QUALIFIERS:
                start = i + 1
                continue
            marks.append((i, i + len(word), word))
            start = i + 1
    if not marks:
        return found

    for m in _NUMBER.finditer(text):
        if _is_exempt(m):
            continue
        for a, b, word in marks:
            if m.start() < b + WINDOW and a < m.end() + WINDOW:
                found.append((m.group(0), word))
                break
    return found


# This file, and only this file, is allowed to contain census sentences: they are
# the planted controls that prove the scanner can fail. Every magnitude in them is
# INVENTED — carrying a real one in order to forbid it is the disclosure this
# guard exists to prevent, which is the same reason the Rust scanner next door is
# an allowlist of decoys rather than a denylist of real coordinates.
#
# The exemption is asserted rather than assumed: `run` checks that this file DOES
# produce claims when scanned. An exemption nobody tests is a blind spot, and a
# blind spot here reports the whole tree clean.
SELF = os.path.join("tests", "test_publication.py")


def claims_in(units, ratios=True):
    """Every census claim, searched WITHIN each unit and never across two."""
    found = []
    for unit in _clean(units):
        found.extend(census_claims(unit, ratios=ratios))
    return found


# ── commit messages ─────────────────────────────────────────────────────────
#
# A commit message publishes exactly as much as a source file does, and nothing
# else in this repository reads one. The Rust guard next door scans `src/`,
# `tests/`, `hooks/`, `site/` and the README for store coordinates and for prose
# about the author's own machine — and every one of its checks was green while
# five messages in this history carried a transcript total, a corpus size and a
# keychain-item count.
#
# The gate lives HERE rather than in Rust because a commit body is PROSE, and
# this file already owns the only prose grammar in the repository, with its
# plants, its exemptions and its false-positive controls. A second copy in Rust
# would be two graders that drift apart, and the one that drifts is always the
# one nobody is reading.


def _git(*args):
    """Run git in the repository, or return None if that is not possible."""
    try:
        done = subprocess.run(("git", "-C", REPO) + args,
                              capture_output=True, text=True)
    except (OSError, ValueError):
        return None
    return done.stdout if done.returncode == 0 else None


def is_this_repository():
    """True when REPO is the keyless checkout, not some host repo.

    `hooks/` installs into other repositories, and its suite can be run from
    there. Scanning THAT repository's commit messages would refuse work this
    gate has no standing to judge — the exact way a gate earns its removal.
    """
    manifest = os.path.join(REPO, "Cargo.toml")
    if not os.path.exists(manifest) or _git("rev-parse", "--git-dir") is None:
        return False
    with open(manifest, errors="replace") as fh:
        return 'name = "keyless"' in fh.read()


def published_ref():
    """The ref that says what has been pushed, or None if nothing says.

    Tried in order: the current branch's upstream, then `origin/HEAD`, then
    `origin/master`. A checkout with none of the three cannot answer whether a
    commit is still amendable, and says so on its own row rather than passing.
    """
    for ref in ("@{upstream}", "origin/HEAD", "origin/master"):
        if _git("rev-parse", "--verify", "--quiet", ref) is not None:
            return ref
    return None


def _is_published(sha, ref):
    """True when `sha` is reachable from `ref`, so amending it means a rewrite.

    `git merge-base --is-ancestor` answers with its exit code and prints
    nothing, so the empty string it yields on success is a PASS. Comparing
    truthiness here would read every published commit as unpublished and turn
    this guard into a permanent red.
    """
    return _git("merge-base", "--is-ancestor", sha, ref) is not None


def commit_messages():
    """[(sha, body)] for every commit reachable from HEAD, newest first."""
    raw = _git("log", "--format=%H%x1e%B%x1f")
    if raw is None:
        return []
    out = []
    for record in raw.split("\x1f"):
        record = record.strip()
        if record:
            sha, body = record.split("\x1e", 1)
            out.append((sha, body))
    return out


def claims_in_message(body):
    """Every census claim in one commit body.

    A blank line separates paragraphs in a commit body the way it does in prose,
    so a paragraph is the unit — the same choice `prose_of` makes, and for the
    same reason: a number and the word that makes it an observation have to be
    in the same piece of writing.
    """
    return claims_in(body.split("\n\n"), ratios=False)


# The commit messages this gate judges guilty and cannot fix.
#
# ⚠️ A SHA IS ADMITTED HERE FOR ONE REASON: THE MESSAGE IS ALREADY PUBLISHED.
# A published message cannot be edited without rewriting history other people
# have pulled, so the gate has nothing left to ask for. A message that is still
# local is a different case entirely — `git commit --amend` is right there, and
# amending it is the fix. `_is_published` enforces that, so "it is too late" is
# a fact the suite checks rather than a sentence somebody types.
#
# ⚠️ THIS LIST IS A RATCHET AND IT IS CHECKED IN THREE DIRECTIONS. A commit that
# is not on it and carries a claim fails the gate. A commit that IS on it and no
# longer carries one — or whose sha is no longer reachable, which is what a
# history rewrite does to every sha below — ALSO fails the gate. And a sha the
# remote has never seen fails it too. So the list cannot rot into a permanent
# exemption, and whoever rewrites the history is told, by a red test, to empty
# it.
#
# It holds shas and nothing else, and no per-entry reason. Naming the figures
# here in order to forgive them would republish the inventory this file exists
# to remove, which is the same reason the Rust guard next door is an allowlist
# of decoys. The collective reason is this comment; the admission test is code.
#
# Emptying the list needs the remedy this file's own `check_message_file`
# prints — keep the reasoning and drop the number, or say what the number is a
# property OF — applied by hand to each engineering record, during a history
# rewrite. A machine cannot choose which figure is a property of the check and
# which is a census of the machine that ran it.
#
# 🔴 THIS LIST GREW AFTER THE GATE EXISTED, AND THE MECHANISM THAT ALLOWED IT IS
# STILL IN PLACE. `install/commit-msg.sh` is the same grammar as a hook that
# fires BEFORE the message is written, and it is installed by hand or not at
# all — a clone's `.git/hooks/` starts empty, so the default posture of this
# repository is a gate that can only speak once the message is unrewritable.
# Install it in every clone that commits:
#
#     ln -sf ../../install/commit-msg.sh .git/hooks/commit-msg
KNOWN_UNSCRUBBED = [
    "a40c37c0a65fcda37879393e71206ca2807a539c",
    "3bb7c07ce850a0740b4b6610bb45dc14e4d6e701",
    "801de39bd6279073f708933a4fb1f7a6c93d5492",
    "a77db6a39a6309bda186b608ccbc5f8fdd7ff03c",
    "d244c42ab946415dcf6d3929be27e918136c8816",
    "c0b74f09302dd4389c4963123d34af1a2972c0a1",
]

# One planted message per shape that was really written into this history.
# Invented magnitudes, for the reason PLANTS gives above.
MESSAGE_PLANTS = [
    "replayed over 12,345 real agent commands, the check admits three more shapes",
    "the decision log shows 47 organic denies across 9 sessions",
    "an estate of 415 files, 12 of them credential-bearing",
    "measured over the corpus: 2,569 payloads, 70 of them rewritten",
]

# What a commit body legitimately says, and must never be refused for saying.
#
# The last entry is TWO PARAGRAPHS and it is the one that proves the search
# scope. Its number and its provenance word are in different paragraphs, so
# paragraph-by-paragraph they are two ordinary sentences — and joined into one
# string they stand 40 characters apart and read as a measurement nobody wrote.
# A commit body is the genre where that is most likely: a subject line carries a
# count, and a paragraph far below happens to say "sessions".
MESSAGE_EXEMPT = [
    "the suite is 509 tests and 15 ignored on both platforms",
    "a missing binary makes the wrapper exit 127 with no child, in every session",
    "measured against infisical 0.43.114 on 2026-08-06",
    "the drain is bounded at 100 KB and costs +6 ms",
    "14 of 14 required contexts reported, and 13 of 13 claims corrected",
    # ⚠️ The number here must carry NO UNIT. `200 lines` was the first spelling
    # and it is exempt as a number-with-a-unit, so the control could never fire
    # in either direction — a fixture that reads exactly like a passing one.
    "the retry budget is now 200.\n\nSessions that share one log are unaffected.",
]


def scan_tree(include_self=False):
    """(path, number, provenance word) for every census claim in hooks/."""
    hits = []
    for path in _files():
        if not include_self and os.path.relpath(path, HOOKS) == SELF:
            continue
        with open(path, "r", errors="replace") as fh:
            text = fh.read()
        for number, word in claims_in(prose_of(text, path)):
            hits.append((os.path.relpath(path, HOOKS), number, word))
    return hits


# One planted sentence per site class that was really removed from this pack.
# Spelled with invented magnitudes, because a guard must not carry the real ones
# in order to forbid them — that would publish the inventory it exists to remove.
PLANTS = [
    "measured on the pack's own decision log, 7 of 11 organic warns fired here",
    "an estate with 4 real files behind 123 symlinks is normal",
    "replayed over 12,345 real agent commands, this admits three more shapes",
    "those two shapes are 13 of the pack's 21 genuine saves",
    "it put 55 live production credentials into one transcript",
    "7 of 8 scripts in one estate crashed on valid JSON",
    # A sentence carrying no provenance word at all — the ratio is the only
    # signal, and one real site was written exactly this way.
    "expanding it there made the largest block category refuse 9 of 26",
]

# The exemptions, each of which must SURVIVE a scan even standing beside a
# provenance word. Without these the guard would refuse correct writing and be
# removed, which is how a gate stops protecting anything.
EXEMPT_CONTROL = [
    "measured over the corpus at version 0.43.114 with no local binary",
    "measured on this machine 2026-08-08, a busy one",
    "the corpus scan costs +32 ms and a 100 KB payload stays under 60 ms",
    "organic traffic bounded at 64 characters, 256 bytes deep",
    # The qualifier that makes a corpus this repository's own.
    "the 87 attacks in the attack corpus are all blocked",
    "52 rows in the mutation corpus, each diffed",
]

# The other half of the qualifier rule, and the reason it is not just a hole: the
# SAME sentence without the product qualifier must still be caught. A guard whose
# exemption is untested is an exemption that quietly swallows the rule.
QUALIFIER_CONTROL = [
    "the 87 denials in the command corpus were all real",
    "52 rows in the write corpus, each measured",
]


def run():
    s = Suite("publication")

    # ── direction 1: the tree is clean ──────────────────────────────────────
    hits = scan_tree()
    s.check("no census claim survives in hooks/", hits, [])
    if hits:
        for path, number, word in hits[:12]:
            sys.stderr.write("      census claim  %s: %r near %r\n"
                             % (path, number, word))

    # ── direction 2: a planted claim is caught, one per real site class ─────
    for text in PLANTS:
        s.check("plant is caught: %s" % text[:44],
                bool(claims_in([text])), True)

    # ── direction 3: the exemptions are real ────────────────────────────────
    for text in EXEMPT_CONTROL:
        s.check("exempt survives: %s" % text[:44],
                claims_in([text]), [])
    for text in QUALIFIER_CONTROL:
        s.check("unqualified corpus is still caught: %s" % text[:40],
                bool(claims_in([text])), True)

    # ── direction 4: the scanner is actually reading the tree ───────────────
    #
    # A clean result and a scanner that reads nothing are the same empty list.
    # These three assert the machinery works on real content, so "clean" means
    # clean rather than "the walk found no files" or "prose_of returned ''".
    files = _files()
    s.check("the walk finds the pack's own modules", len(files) >= 20, True)

    # Every text file in the pack is scanned, not a subset. This is the assertion
    # that fails when somebody adds a `.yml`, a `.toml` or a `.txt` — rather than
    # the new file type being silently exempt, which is how an unscanned root
    # reports clean forever.
    present = set()
    for dirpath, dirs, names in os.walk(HOOKS):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in names:
            ext = os.path.splitext(name)[1]
            if ext and not name.startswith("."):
                present.add(ext)
    s.check("no text extension in hooks/ is left unscanned",
            sorted(present - set(_EXTS)), [])

    total = 0
    for path in files:
        total += sum(len(u) for u in
                     _clean(prose_of(open(path, errors="replace").read(), path)))
    # The floor that catches an extractor which quietly under-reads. The first
    # version of `prose_of` read roughly a fifth of this and reported the tree
    # clean; a floor is the only assertion that can tell those two apart.
    s.check("the tree yields a substantial body of prose", total > 120000, True)

    sample = os.path.join(HOOKS, "keyless_hooks", "checks", "env_dump.py")
    prose = " ".join(_clean(prose_of(open(sample).read(), sample)))
    s.check("prose_of reads a module docstring", "environment" in prose, True)

    # A comment block that follows a LINE OF CODE, deep in a file. This is the
    # exact shape the regex extractor dropped, and the only assertion here that
    # would have failed against it.
    cfg = os.path.join(HOOKS, "keyless_hooks", "config.py")
    cfg_prose = " ".join(_clean(prose_of(open(cfg).read(), cfg)))
    s.check("prose_of reads an inline comment block after code",
            "closed side of the allowlist" in cfg_prose, True)
    s.check("prose_of reads a comment inside a list literal",
            "object-spread spelling" in cfg_prose, True)

    # ── direction 5: the self-exemption is a real exemption ─────────────────
    #
    # This file carries planted census sentences on purpose. If scanning it finds
    # NOTHING, the extractor is under-reading and every clean verdict above is
    # worthless — which is exactly what happened twice while this was written:
    # once from a regex extractor that dropped comment blocks after code, once
    # from stripping inline code spans on the JOINED text, where a backtick paired
    # across two tokens and deleted 2,738 characters including these plants.
    self_prose = " ".join(_clean(prose_of(open(os.path.join(HOOKS, SELF)).read(),
                                          os.path.join(HOOKS, SELF))))
    s.check("the guard's own plants survive extraction",
            "7 of 11 organic warns" in self_prose, True)
    s.check("the guard's own file DOES produce claims when scanned",
            len([h for h in scan_tree(include_self=True) if h[0] == SELF]) > 5, True)
    s.check("and it is the only file exempted",
            [h[0] for h in scan_tree(include_self=True) if h[0] != SELF], [])

    # ── direction 6: the wrap is undone ─────────────────────────────────────
    #
    # The regression that beat two sweeps of this pack in one session: a phrase
    # split across two comment lines is invisible to a line-based search. This
    # asserts the fold, in the exact shape that survived.
    wrapped = "# `measured` means the tool's own help was read on this\n# machine, at 42 sites\n"
    s.check("a wrapped census claim is still caught",
            bool(claims_in(prose_of(wrapped, "x.py"))), True)

    # ── direction 7: no commit message carries a census claim ───────────────
    _check_commit_messages(s)

    return s


def _check_commit_messages(s):
    # ⚠️ WHAT THE MUTATION CAMPAIGN CANNOT REACH, said here so its green is never
    # read as covering it. `mutate.py` copies `hooks/` ALONE into a temporary
    # directory and runs the suite from there, so `REPO` is that temporary
    # directory, `is_this_repository()` is always False under mutation, and every
    # assertion below the early return is skipped. Breaking one of them on
    # purpose produces a SURVIVING mutant that is really an unreachable one.
    #
    # The grammar half is deliberately placed ABOVE that gate for exactly this
    # reason, so the part a mutation can reach is the part that decides what
    # counts as a claim. The tree-scanning half is proved instead against a real
    # clone with history: a new commit carrying a figure fails the walk, a sha
    # removed from KNOWN_UNSCRUBBED fails it, an unreachable sha on the list
    # fails it, and a shallow checkout fails it rather than reading as clean.
    #
    # The scanner is proved FIRST and unconditionally, so that a checkout with
    # no readable history can never leave the grammar untested. A gate whose
    # only evidence is "the tree came back empty" is the failure this whole file
    # exists to prevent.
    for text in MESSAGE_PLANTS:
        s.check("message plant is caught: %s" % text[:40],
                bool(claims_in_message(text)), True)
    for text in MESSAGE_EXEMPT:
        s.check("message exempt survives: %s" % text[:40],
                claims_in_message(text), [])

    if not is_this_repository():
        # Not a silent skip: a visible row saying which repository was judged.
        # `hooks/` installs elsewhere, and refusing another project's commit
        # messages would be a gate acting outside its standing.
        s.check("the history gate applies only in the keyless checkout",
                True, True)
        return

    # A shallow clone reads exactly like a clean history: one commit, nothing
    # to flag, exit 0. CI checks out with `fetch-depth: 0` for this reason, and
    # this turns a missing depth into a failure instead of a green line.
    s.check("the checkout is not shallow",
            (_git("rev-parse", "--is-shallow-repository") or "").strip(),
            "false")

    messages = commit_messages()
    s.check("the history walk reads a substantial number of commits",
            len(messages) >= 25, True)

    known = set(KNOWN_UNSCRUBBED)
    reachable = set(sha for sha, _ in messages)
    flagged = set(sha for sha, body in messages if claims_in_message(body))

    s.check("no commit message outside the known-unscrubbed set carries a claim",
            sorted(sha[:12] for sha in flagged - known), [])
    for sha, body in messages:
        if sha in flagged and sha not in known:
            for number, word in claims_in_message(body)[:6]:
                sys.stderr.write("      census claim  %s: %r near %r\n"
                                 % (sha[:12], number, word))

    # The directions that stop the list becoming a permanent exemption.
    s.check("every known-unscrubbed sha is still reachable",
            sorted(sha[:12] for sha in known - reachable), [])
    s.check("every known-unscrubbed sha still carries a claim",
            sorted(sha[:12] for sha in (known & reachable) - flagged), [])

    # And the direction that stops it growing on an excuse. An allowlist anyone
    # may append to is a gate that decays one row at a time, and the only reason
    # this one accepts is "the message is published, so no edit can reach it".
    # That is a property of the repository, not a claim in a diff: a commit the
    # remote has never seen is amendable, and amending it is the fix.
    ref = published_ref()
    if ref is None:
        # Visible, never silent. A clone with no remote cannot tell an
        # unrewritable message from a lazy one, and must not imply it can.
        s.check("no ref names what is published, so admission is unproven",
                True, True)
    else:
        s.check("every known-unscrubbed sha is published, so no edit can reach it",
                sorted(sha[:12] for sha in known if not _is_published(sha, ref)),
                [])


def check_message_file(path):
    """Judge one commit message file. A `commit-msg` hook body.

    Exit 0 when the message is clean, 1 when it carries a census claim. Prints
    the claim's shape, never a value.
    """
    with open(path, errors="replace") as fh:
        body = "\n".join(line for line in fh.read().split("\n")
                         if not line.startswith("#"))
    hits = claims_in_message(body)
    if not hits:
        return 0
    sys.stderr.write(
        "\nThis commit message states a measurement of one machine or account:\n")
    for number, word in hits:
        sys.stderr.write("  %r stands near %r\n" % (number, word))
    sys.stderr.write(
        "\nA figure nobody else can reproduce is an inventory, not evidence. Keep the\n"
        "reasoning and drop the number, or say what the number is a property OF.\n")
    return 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--message-file":
        raise SystemExit(check_message_file(sys.argv[2]))
    ok = run().report()
    raise SystemExit(0 if ok else 1)
