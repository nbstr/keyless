"""Does this string name a file whose content is a credential — and what NAMES
does that file declare?

Two jobs, one module, because they share the same hard rule: **a name may leave
this file, a value may not.** `names_in` exists so a block can answer the
question the agent actually had ("what is configured here?") without anyone
reading a value — but it is also the single place in the pack where bytes from a
secret file are copied into output, so it is written to make that impossible
rather than unlikely.
"""

import os
import re
from fnmatch import fnmatch

__all__ = ["is_protected", "names_in", "expansions"]

# A key in an env / ini / JSON / YAML file. Bounded at 64 characters and anchored
# whole: the bound is what stops a base64 line ending in `=` from being read as a
# key whose "name" is a slice of key material.
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_PATHY_KEY = re.compile(r"^//[A-Za-z0-9_.:@/-]{1,63}$")
_JSONISH_KEY = re.compile(r"^[\"']?([A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?$")

_HOME_VAR = re.compile(r"^\$\{?HOME\}?/")

# Read caps. A protected file is a config file; anything past these bounds is not
# one, and a hook must not read an endless character device to find that out.
_MAX_BYTES = 256 * 1024
_MAX_NAMES = 200
_KV_LINE_RATIO = 0.6

_GLOB_CHARS = re.compile(r"[*?\[]")
_MAX_GLOB = 64

# There is deliberately NO "a weak glob is not a glob" rule here. A stem-length
# threshold looks like the way to stop `.*` expanding, and it fails on the one
# command that matters: `cat .*` really does dump every dotfile in the directory,
# `.env` included, and a threshold allows it. The exemption belongs to the pattern
# ARGUMENT of a pattern tool, not to the shape of the string — see
# `checks/file_read`.

# A shell-typed path does not contain `==`. A jq filter does, and one was read as
# a credential file because it happened to end in `.env`.
_NOT_A_PATH = ("==",)

# NO RULE HERE MAY DEPEND ON WHETHER THE FILE EXISTS.
#
# Requiring a `*.env` match to be corroborated by `os.path.lexists` looks like the
# obvious way to tell `process.env` from `prod.env`, and it is wrong twice over.
# Replayed against the pack's own decision log it turned 5 of 34 genuine saves
# into silence, because a gitignored `prod.env` had been deleted since. Worse, the
# hook resolves against the payload's cwd and the shell may have left it: in
# `cd /elsewhere && cat prod.env` the existence test asks the wrong directory,
# answers no, and allows a read of a file that is right there.
#
# So every rule in this module is a decision about the STRING, and a name that is
# genuinely not a path goes in `allowed` instead — an exact entry, no filesystem
# question asked.


def expansions(candidate, cwd, expand_globs=True):
    """Every filesystem path a candidate string could denote.

    A union rather than a single answer, because a deny must consider the path as
    requested AND the path as resolved: an estate with 5 real files behind 179
    symlinks is normal, and matching only one of the two forms leaves the other
    open.

    `expand_globs=False` keeps a weak glob from being expanded against the real
    filesystem. The caller sets it for a tool whose first argument is a PATTERN
    rather than a path — see `checks/file_read`. Literal matching is unaffected in
    both directions, so `grep TOKEN .env` is still refused either way; only the
    filesystem expansion of a metacharacter blob is withheld.
    """
    if not candidate:
        return []
    cand = candidate.strip().strip("'\"")
    if not cand or cand in (".", "..", "/"):
        return []
    if any(mark in cand for mark in _NOT_A_PATH):
        return []
    if cand.endswith("/"):
        # A trailing separator names a directory, and a directory holds no
        # credential of its own. `.env/` cannot open the file `.env` — the kernel
        # answers ENOTDIR — so treating it as that file is a refusal of something
        # that was never a read.
        return []
    if cand.startswith("~"):
        cand = os.path.expanduser(cand)
    elif _HOME_VAR.match(cand):
        cand = os.path.join(os.path.expanduser("~"), cand.split("/", 1)[1])
    if "$" in cand:
        # An unexpanded substitution. Keep the literal — a glob may still match a
        # protected basename inside it — but do not pretend to resolve it.
        return [cand]

    out = [cand]
    base = cwd if cwd and os.path.isabs(cwd) else os.getcwd()
    absolute = cand if os.path.isabs(cand) else os.path.normpath(os.path.join(base, cand))
    if absolute not in out:
        out.append(absolute)
    try:
        if os.path.lexists(absolute):
            real = os.path.realpath(absolute)
            if real not in out:
                out.append(real)
        elif _GLOB_CHARS.search(cand) and expand_globs:
            # `cat .e*v` never reaches the matcher as `.env`, because the shell
            # expands it and the hook sees the pattern. Expanding it here is the
            # only way the two agree — and it is bounded, because a glob that
            # matches nothing yields nothing.
            import glob as _glob
            for hit in _glob.glob(absolute)[:_MAX_GLOB]:
                if hit not in out:
                    out.append(hit)
                real = os.path.realpath(hit)
                if real not in out:
                    out.append(real)
    except (OSError, ValueError):
        # An unresolvable path is not a protected path we can name; the literal
        # forms above still get their glob test.
        pass
    return out


def _matches(path, pattern):
    """One glob against one path. A pattern with a separator is anchored; a bare
    pattern matches the basename at any depth."""
    if not pattern:
        return False
    if pattern.startswith("~"):
        pattern = os.path.expanduser(pattern)
    if "/" in pattern:
        return fnmatch(path, pattern)
    return fnmatch(os.path.basename(path), pattern)


def is_protected(candidate, cwd, cfg, expand_globs=True):
    """The pattern that protects this candidate, or None.

    Exclusions win. `.env.example` is matched by `.env.*` and must still be
    readable, so the allow list is tested first and cannot be shadowed by a
    broader protected glob added later.
    """
    forms = expansions(candidate, cwd, expand_globs)
    if not forms:
        return None
    for form in forms:
        for allowed in cfg.allowed:
            if _matches(form, allowed):
                return None
    for form in forms:
        for pattern in cfg.protected:
            if _matches(form, pattern):
                return pattern
    return None


def _key_of(line):
    """The name on the left of a key/value line, or None.

    None for anything that is not unambiguously a key/value pair. Every path that
    returns a string returns a substring of the LEFT side only, validated whole
    against a bounded identifier pattern — so no byte of a value can reach a
    caller through here even if the file is shaped nothing like the caller
    expects.
    """
    text = line.strip()
    if not text or text[0] in "#;[":
        return None
    for sep in ("=", ":"):
        if sep not in text:
            continue
        left, _, right = text.partition(sep)
        if not right.strip():
            return None
        left = left.strip().rstrip(",").strip()
        if left.lower().startswith("export "):
            left = left[7:].strip()
        if _ENV_KEY.match(left) or _PATHY_KEY.match(left):
            return left
        m = _JSONISH_KEY.match(left)
        if m:
            return m.group(1)
        return None
    return None


def names_in(path):
    """The names a protected file declares. Never a value, under any input.

    Returns (names, note). `note` explains an empty list, because "this file
    declares nothing" and "this file is not key/value shaped" lead the reader to
    different next actions.

    The whole-file shape test is the safety property: names are extracted only
    from a file where a majority of content lines are key/value pairs. A PEM key
    has one such line in thirty, so it yields no names at all rather than a
    plausible-looking fragment of key material.
    """
    try:
        with open(path, "r", errors="replace") as fh:
            blob = fh.read(_MAX_BYTES)
    except (OSError, ValueError, UnicodeError):
        return [], "unreadable"

    lines = blob.split("\n")
    content = [ln for ln in lines if ln.strip() and not ln.strip().startswith(("#", ";"))]
    if not content:
        return [], "empty"

    keys = []
    for ln in content:
        k = _key_of(ln)
        if k is not None:
            keys.append(k)

    if len(keys) < _KV_LINE_RATIO * len(content):
        return [], "not key/value shaped"

    seen = set()
    out = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
        if len(out) >= _MAX_NAMES:
            break
    return out, ""
