"""Does this string name a file whose content is a credential — and what NAMES
does that file declare?

Two jobs, one module, because they share the same hard rule: **a name may leave
this file, a value may not.** `names_in` exists so a block can answer the
question the agent actually had ("what is configured here?") without anyone
reading a value — but it is also the single place in the pack where bytes from a
secret file are copied into output, so it is written to make that impossible
rather than unlikely.
"""

import collections
import os
import re
from fnmatch import fnmatch

__all__ = ["is_protected", "is_allowed", "names_in", "expansions",
           "expansions_spanned", "resolve", "Form", "Protection",
           "match_sentence"]

# HOW a candidate string reached the filesystem path that matched a pattern.
#
# A refusal that prints only the candidate and the pattern cannot tell its reader
# which of two opposite situations it is in: an operand that IS a protected path,
# or a string that merely EXPANDED onto one. The first is a credential read and
# re-spelling it is the wrong move; the second is a regex, a quantifier or a
# slice that globbed onto a real file, and the command has to be rewritten. The
# information that separates them is produced here, inside `expansions`, and was
# discarded before the message was built.
#
# `via` is the intermediate string this form came through, and it is a different
# thing per origin — the base directory for `CWD`, the pattern handed to `glob`
# for `GLOB`, the path whose realpath this is for `SYMLINK`. `match_sentence`
# below is the one place that reads it, so the per-origin meaning stays next to
# the per-origin sentence.
Form = collections.namedtuple("Form", "path origin via")

LITERAL = "literal"
HOME = "home"
CWD = "cwd"
SYMLINK = "symlink"
GLOB = "glob"
GLOB_SYMLINK = "glob-symlink"

# The two origins where the candidate did not NAME the matched path. Every other
# origin reached it by expanding a `~`, joining a working directory or following
# a symlink — each of which a shell would have done to the same string.
EXPANDED_ORIGINS = frozenset([GLOB, GLOB_SYMLINK])

# What `is_protected` answers with. A namedtuple holding fields is always truthy,
# so the no-match answer stays `None` and every caller's `if not protection`
# remains the test it was before this carried provenance.
Protection = collections.namedtuple("Protection", "pattern path origin via")

# A key in an env / ini / JSON / YAML file. Bounded at 64 characters and anchored
# whole: the bound is what stops a base64 line ending in `=` from being read as a
# key whose "name" is a slice of key material.
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_PATHY_KEY = re.compile(r"^//[A-Za-z0-9_.:@/-]{1,63}$")
_JSONISH_KEY = re.compile(r"^[\"']?([A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?$")

_HOME_VAR = re.compile(r"^\$\{?HOME\}?/")

# A line that is nothing but structural punctuation. `{`, `},`, `]` and friends
# are SYNTAX, not content — they declare no name and hold no value, so counting
# them against the key/value ratio below is counting a file's braces as evidence
# that it is not a config file.
#
# This is why no JSON file yielded a single name. A nested `.json` — a credential
# store, a `.claude.json`, a docker config — is roughly one brace line for every
# two key lines, which drags the ratio under the threshold on structure alone. So
# `names: 0` was reported for the exact files the deny message most needed to
# describe, and the tilde bug hid it: the file was never opened, so nobody saw
# that opening it would not have helped either.
#
# The PEM property this ratio exists to protect is untouched: a private key's
# body is base64, not punctuation, so every one of its lines still counts in the
# denominator and it still yields no names at all.
_STRUCTURE_ONLY = re.compile(r"^[\s{}\[\](),]*$")

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
# Replayed against real decisions this pack had already made, it turned genuine
# saves into silence, because a gitignored `prod.env` named in a refused command
# had been deleted between the refusal and the replay. Worse, the
# hook resolves against the payload's cwd and the shell may have left it: in
# `cd /elsewhere && cat prod.env` the existence test asks the wrong directory,
# answers no, and allows a read of a file that is right there.
#
# So every rule in this module is a decision about the STRING, and a name that is
# genuinely not a path goes in `allowed` instead — an exact entry, no filesystem
# question asked.


def expansions_spanned(candidate, cwd, expand_globs=True):
    """Every filesystem path a candidate string could denote, each with its
    ORIGIN — how the candidate reached it.

    A union rather than a single answer, because a deny must consider the path as
    requested AND the path as resolved: a checkout where most `.env` paths are
    symlinks onto a handful of real files is an ordinary layout, and matching only
    one of the two forms leaves the other open.

    `expand_globs=False` keeps a weak glob from being expanded against the real
    filesystem. The caller sets it for a tool whose first argument is a PATTERN
    rather than a path — see `checks/file_read`. Literal matching is unaffected in
    both directions, so `grep TOKEN .env` is still refused either way; only the
    filesystem expansion of a metacharacter blob is withheld.

    The ORIGIN decides no verdict. It is produced alongside the same set of forms
    this function has always produced, in the same order, and it exists so a
    refusal can say which form matched and how — see `Form` above.
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
    # A leading `~` or `$HOME` is expanded in place, so the form below is no
    # longer the candidate as typed and the message must not claim it is.
    written = LITERAL
    if cand.startswith("~"):
        cand = os.path.expanduser(cand)
        written = HOME
    elif _HOME_VAR.match(cand):
        cand = os.path.join(os.path.expanduser("~"), cand.split("/", 1)[1])
        written = HOME
    if "$" in cand:
        # An unexpanded substitution. Keep the literal — a glob may still match a
        # protected basename inside it — but do not pretend to resolve it.
        return [Form(cand, written, None)]

    out = [Form(cand, written, None)]
    seen = set([cand])
    base = cwd if cwd and os.path.isabs(cwd) else os.getcwd()
    absolute = cand if os.path.isabs(cand) else os.path.normpath(os.path.join(base, cand))
    if absolute not in seen:
        seen.add(absolute)
        # An absolute candidate only got NORMALISED here; a relative one was
        # joined onto a working directory the hook was told about, which is a
        # claim worth printing when it is what produced the match.
        if os.path.isabs(cand):
            out.append(Form(absolute, written, None))
        else:
            out.append(Form(absolute, CWD, base))
    try:
        if os.path.lexists(absolute):
            real = os.path.realpath(absolute)
            if real not in seen:
                seen.add(real)
                out.append(Form(real, SYMLINK, absolute))
        elif _GLOB_CHARS.search(cand) and expand_globs:
            # `cat .e*v` never reaches the matcher as `.env`, because the shell
            # expands it and the hook sees the pattern. Expanding it here is the
            # only way the two agree — and it is bounded, because a glob that
            # matches nothing yields nothing.
            import glob as _glob
            for hit in _glob.glob(absolute)[:_MAX_GLOB]:
                if hit not in seen:
                    seen.add(hit)
                    out.append(Form(hit, GLOB, absolute))
                real = os.path.realpath(hit)
                if real not in seen:
                    seen.add(real)
                    out.append(Form(real, GLOB_SYMLINK, absolute))
    except (OSError, ValueError):
        # An unresolvable path is not a protected path we can name; the literal
        # forms above still get their glob test.
        pass
    return out


def expansions(candidate, cwd, expand_globs=True):
    """The paths of `expansions_spanned`, in the same order, without origins.

    The two must never disagree about the SET, which is why one is derived from
    the other rather than written twice.
    """
    return [form.path for form in
            expansions_spanned(candidate, cwd, expand_globs)]


def match_sentence(protection, candidate):
    """One sentence saying how `candidate` reached `protection.pattern`.

    LITERAL or not is the distinction the sentence exists to carry, and it is
    stated in the first clause rather than left to be inferred from the rest: an
    operand that names a credential file and a regex fragment that globbed onto
    one are the same refusal today, and they prescribe opposite next actions.
    """
    cand = (candidate or "").strip().strip("'\"")
    # One test draws the literal / not-literal line, so a new expanded origin
    # cannot be reported as literal by being forgotten in a branch below.
    if protection.origin in EXPANDED_ORIGINS:
        tail = ("a match of that expansion resolves to `%s`"
                if protection.origin == GLOB_SYMLINK
                else "that expansion matched `%s`") % protection.path
        return ("`%s` did NOT match `%s` literally. It was expanded as a glob — "
                "`%s` — and %s."
                % (cand, protection.pattern, protection.via, tail))
    if protection.origin == HOME:
        return ("`%s` matched `%s` literally, once its leading home directory "
                "was expanded: it names `%s`."
                % (cand, protection.pattern, protection.path))
    if protection.origin == CWD:
        return ("`%s` matched `%s` literally, as `%s` — resolved against the "
                "working directory `%s`."
                % (cand, protection.pattern, protection.path, protection.via))
    if protection.origin == SYMLINK:
        return ("`%s` matched `%s` literally, through a symlink: `%s` resolves "
                "to `%s`."
                % (cand, protection.pattern, protection.via, protection.path))
    return ("`%s` matched `%s` literally, as written."
            % (cand, protection.pattern))


def resolve(candidate, cwd):
    """The ONE filesystem path a candidate denotes, or None when it cannot be
    resolved with confidence.

    **None does not mean "the file is absent". It means "do not ask the
    filesystem".** That distinction is the whole reason this function exists. A
    caller that joins `~/.cckeys.json` onto a working directory gets
    `<cwd>/~/.cckeys.json`, which no `os.path.isfile` will ever find — and both
    the `Read` rewrite and the `Grep` deny read that absence as *nothing to
    protect here* and allowed the read outright. The block, not just its list of
    names, was lost to a literal tilde.

    So a failure to expand must never become a failure to BLOCK. `is_protected`
    is deliberately not routed through this function: it matches on the STRING and
    keeps its own broader expansion, so a path this function refuses is still
    matched by a basename glob and still refused.

    What is refused rather than silently resolved, and why:

    - **another user's home** (`~someone/.env`). The standard library reads it out
      of the password database; a hook on a machine's critical path should not.
      The candidate stays protected, it simply yields no names.
    - **an unexpanded substitution** (`$HOME/.env`, `$W/prod.env`). The hook holds
      no model of shell state, so any value it invented would be a guess about a
      variable it never saw assigned.
    - **an absent or empty HOME.** The one case where expansion is impossible
      rather than merely unwise.

    Those three are the same refusals the Rust config parser makes for a leading
    tilde, and for the same reason: a component that resolves a home directory
    must have exactly one way to do it and must say so when it cannot.
    """
    if not candidate:
        return None
    cand = candidate.strip().strip("'\"")
    if not cand or cand in (".", "..", "/"):
        return None
    if "$" in cand:
        return None
    if cand.startswith("~"):
        if not cand.startswith("~/") and cand != "~":
            # `~user/...`. Refused, never guessed.
            return None
        home = os.environ.get("HOME") or ""
        if not home:
            return None
        cand = home if cand == "~" else os.path.join(home, cand[2:])
    if os.path.isabs(cand):
        return os.path.normpath(cand)
    base = cwd if cwd and os.path.isabs(cwd) else os.getcwd()
    return os.path.normpath(os.path.join(base, cand))


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


def is_allowed(candidate, cwd, cfg, expand_globs=True):
    """The `allowed` pattern that exempts this candidate, or None.

    Public because two checks need the SAME answer for different reasons. A read
    of `.env.example` is not a credential read, and a credential-shaped literal
    written into one is an example rather than a leak — one list, one meaning:
    *this path is not treated as holding a real secret*. Deriving a second list
    for the second question would let the two drift, and the message both checks
    print names this one.
    """
    forms = expansions(candidate, cwd, expand_globs)
    for form in forms:
        for allowed in cfg.allowed:
            if _matches(form, allowed):
                return allowed
    return None


def is_protected(candidate, cwd, cfg, expand_globs=True):
    """The `Protection` covering this candidate, or None.

    Exclusions win. `.env.example` is matched by `.env.*` and must still be
    readable, so the allow list is tested first and cannot be shadowed by a
    broader protected glob added later.

    The answer carries the matched FORM and its ORIGIN beside the pattern,
    because a refusal that prints only the pattern cannot say whether the
    candidate NAMED that file or merely expanded onto it. Nothing about WHICH
    candidates are protected changed when that was added: the forms, their order
    and the pattern order are untouched, so the pattern in the returned tuple is
    the same string this used to return on its own.
    """
    forms = expansions_spanned(candidate, cwd, expand_globs)
    if not forms:
        return None
    if is_allowed(candidate, cwd, cfg, expand_globs) is not None:
        return None
    for form in forms:
        for pattern in cfg.protected:
            if _matches(form.path, pattern):
                return Protection(pattern, form.path, form.origin, form.via)
    return None


# Every `"name":` on one line of a COMPACT JSON document. A quoted string
# followed by a colon is a KEY in JSON and cannot be anything else — a value
# is followed by `,` or a closing brace — and the capture class excludes `:`
# and quotes, so the only thing this can yield is a whole bounded identifier
# from the left of a separator. The same property `_key_of` rests on.
_JSON_KEYS = re.compile(r"[\"']([A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']\s*:")


def _keys_of(line):
    """Every name a line declares, left-hand sides only.

    A list rather than one name, because a credential store written on ONE line —
    `{"github": {"key": …}, "linear": {"key": …}}` — declares many and the
    single-key reader saw only the first. That is not a corner case: a JSON file
    is the shape most of the protected list is made of.
    """
    text = line.strip()
    if not text or text[0] in "#;[":
        return []
    if '":' in text or "':" in text:
        out = []
        for m in _JSON_KEYS.finditer(text):
            if m.group(1) not in out:
                out.append(m.group(1))
        if out:
            return out
    one = _key_of(line)
    return [one] if one is not None else []


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
        # An opening brace or bracket glued to the first key of a COMPACT JSON
        # document — `{"github": {…}}` written on one line. Stripping it is safe
        # because what remains is still validated WHOLE against a bounded
        # identifier pattern below, which is the property that keeps a byte of a
        # value from ever reaching a caller through here.
        left = left.lstrip("{[").strip()
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
    content = [ln for ln in lines
               if ln.strip()
               and not ln.strip().startswith(("#", ";"))
               and not _STRUCTURE_ONLY.match(ln)]
    if not content:
        return [], "empty"

    keys = []
    declaring = 0
    for ln in content:
        found = _keys_of(ln)
        if found:
            declaring += 1
            keys.extend(found)

    # The ratio counts LINES that declare something, not names. A compact JSON
    # document is one line holding twenty pairs, and counting names against lines
    # would let a single line clear a threshold no matter what the rest of the
    # file is — which is precisely the property that keeps a PEM silent.
    if declaring < _KV_LINE_RATIO * len(content):
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
