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

Two directions are asserted, because a scanner that quietly stopped matching
would report a clean tree exactly like a clean tree does:

    the tree is clean            no prose in hooks/ carries a census claim
    a planted claim is caught    each of six shapes, one per real site scrubbed
    the exemptions are real      a unit, a version and a date each survive

`PROVENANCE` is deliberately the list somebody has to extend. Adding a word is
free; adding a NUMBER next to one is the moment a person has to answer out loud
whether they are describing the product or their own machine.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import Suite  # noqa: E402

HOOKS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
_EXEMPT = re.compile(
    r"\d{4}-\d{2}-\d{2}"                        # a date
    r"|\d[\d,]*\.\d+(?:\.\d+)*"                 # a version
    r"|\bPython\s*\d[\d.]*"                     # `Python 3.6`
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


def census_claims(text):
    """Every (number, provenance word) pair standing within WINDOW of each other."""
    found = []
    exempt = list(_EXEMPT.finditer(text))

    def _is_exempt(m):
        return any(e.start() <= m.start() and m.end() <= e.end() for e in exempt)

    for m in _RATIO.finditer(text):
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


def claims_in(units):
    """Every census claim, searched WITHIN each unit and never across two."""
    found = []
    for unit in _clean(units):
        found.extend(census_claims(unit))
    return found


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

    return s


if __name__ == "__main__":
    ok = run().report()
    raise SystemExit(0 if ok else 1)
