"""Does this write only DECLARE a name in keyless's own `config.json`?

One question, answered for one caller — `checks/switch`, which owns the
threat model and the reasoning for why a gained name is inert. This module owns
the mechanics, and it is a module of its own for `served`'s reason rather than a
tidiness one: the act it judges is a JSON document compared against its
successor, which shares nothing with shell parsing, verb tables or path
classification, and a check carrying all four is a check nobody can re-read.

── the answer is a permission, so every uncertainty is a NO ────────────────

`adds_only_names` returns True only where this process has established the
whole of its claim. Every other outcome is False, and the list is not a set of
edge cases — it is most of the function:

    the file is absent            there is no document to be additive to, and
                                  a created file could declare `stores`, where
                                  a backend's binary path lives
    either side will not parse    a document the CLI cannot read either
    either side is not an object  same
    `secrets` is not a map        the loader refuses it, so it must not be
                                  read here as "no names declared"
    the result is too large       past the loader's own bound it reads NO
                                  config, which takes every declared name
                                  away rather than adding one
    the write cannot be computed  a shell redirect, an `old_string` that is
                                  absent or matches more than once, a bulk
                                  entry this process does not understand

── what it compares, and what that misses ─────────────────────────────────

PARSED documents, not bytes. That is the honest way and it has to be said
plainly, because "byte-identical apart from the new names" is a claim this
cannot make:

  * KEY ORDER is not compared. Reordering a JSON object changes no meaning to
    any reader either side of this hook.
  * WHITESPACE, indentation and a trailing newline are not compared.
  * A COMMENT cannot exist: neither reader accepts one, so a document carrying
    one fails to parse and is refused above.

A DUPLICATE key is not in that list, and the reason is the whole discipline of
this module. It looks like the same harmless case — both readers keep the last
one, so the parsed document is the document the CLI reads — and that is TRUE
inside the `secrets` map and FALSE at the top level, where the crate's loader
refuses the document and falls back to declaring nothing. `_no_duplicate_keys`
carries the measurement. Read as harmless, a write carrying one would be judged
additive here and would take every declaration away there.

That is the general rule the two guards below exist for: parsed comparison is
only sound where both readers agree on what the document IS. Where they do not,
this module refuses rather than picking one. The other such axis is a non-finite
constant, which Python takes and the crate does not.

What is compared is compared STRICTLY. `_same` refuses one JSON type standing
in for another, because Python reads a boolean as equal to the integer beside
it and the crate's loader answers that substitution by reading no config at
all — so a plain `==` would pass a document whose `enabled` had been retyped
into one the CLI cannot load.

── no value passes through here, and that is structural ────────────────────

This module READS a file, which no other part of this pack does for the purpose
of judging content, so the invariant its siblings state has to be stated here
too. The file it reads holds coordinates and never a value — `src/config.rs` has
no field one fits in — and independently of that, nothing read here can escape:
every function returns a BOOLEAN or a string this module keeps to itself, no
caller is handed the content, and the refusal `checks/switch` prints is a
constant with no substitution in it. The only bytes that leave are `True` and
`False`.
"""

import json
import os
import stat

__all__ = ["MAX_CONFIG_BYTES", "adds_only_names", "read_bounded",
           "written_content"]

# `MAX_CONFIG_BYTES` in `src/config.rs`, mirrored rather than imported because
# nothing here links the two languages. One mebibyte, and it is load-bearing in
# both directions: past it the CLI's own loader reads no config at all, and it
# is also the bound on what this module will read on a path every write tool
# call reaches.
MAX_CONFIG_BYTES = 1024 * 1024

_SECRETS = "secrets"

# How much is read per call into the kernel. Nothing depends on the value; it
# only keeps a whole config off the stack in one go.
_CHUNK = 65536


def read_bounded(path):
    """The file's text, or None — and never a call that can block or grow
    without bound.

    `KEYLESS_CONFIG` is an ordinary environment variable, so this path need not
    lead to a regular file, and `src/config.rs` records what the other two kinds
    cost its own loader: a FIFO with no writer makes `open` wait for a writer
    that never arrives, and a character device such as `/dev/zero` reads
    successfully until memory runs out. Neither is an error a bounded read would
    catch, and both would hang a hook that runs in front of every tool call.

    So the descriptor is opened non-blocking and its TYPE is read off the
    descriptor itself before a byte is taken — the same order, and for the same
    reason, as the loader next door: a `stat` on the path can be invalidated by
    a rename before the `open`. Regular files ignore `O_NONBLOCK` for reads, so
    the ordinary path pays nothing for it.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        blob = b""
        while len(blob) <= MAX_CONFIG_BYTES:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            blob += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(blob) > MAX_CONFIG_BYTES:
        return None
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError:
        return None


def written_content(payload, before):
    """The content this call would leave on disk, or None where this process
    cannot compute it.

    `Write` carries the whole of it. An edit tool carries a TRANSFORMATION
    instead, applied here to the bytes just read.

    Four shapes return None rather than a guess, and each is a shape the host
    itself refuses: an `old_string` that is absent, one that matches more than
    once without `replace_all`, an empty one, and one identical to its
    replacement. Resolving any of them one way would judge content no tool was
    ever going to write.
    """
    if payload.tool == "Write":
        content = payload.tool_input.get("content")
        return content if isinstance(content, str) else None
    edits = _edit_operations(payload)
    if not edits:
        return None
    text = before
    for old, new, every in edits:
        if not isinstance(old, str) or not isinstance(new, str):
            return None
        if not old or old == new:
            return None
        occurrences = text.count(old)
        if occurrences == 0 or (occurrences > 1 and not every):
            return None
        text = text.replace(old, new) if every else text.replace(old, new, 1)
    return text


def _edit_operations(payload):
    """`[(old_string, new_string, replace_all), ...]`, or None for a tool whose
    result is not computable from a document and a list of replacements.

    A bulk edit's entry that is not a mapping ends the whole answer rather than
    being skipped: skipping one would judge the result of the OTHER edits and
    report it as the result of all of them.
    """
    ti = payload.tool_input
    if payload.tool == "Edit":
        return [(ti.get("old_string"), ti.get("new_string"),
                 ti.get("replace_all") is True)]
    if payload.tool != "MultiEdit":
        return None
    edits = ti.get("edits")
    if not isinstance(edits, list) or not edits:
        return None
    out = []
    for entry in edits:
        if not isinstance(entry, dict):
            return None
        out.append((entry.get("old_string"), entry.get("new_string"),
                    entry.get("replace_all") is True))
    return out


def adds_only_names(before_text, after_text):
    """True only where `after_text` is `before_text` plus one or more NEW keys
    under `secrets`, and the same document in every other respect."""
    if len(after_text.encode("utf-8", "surrogatepass")) > MAX_CONFIG_BYTES:
        return False
    before = _object(before_text)
    after = _object(after_text)
    if before is None or after is None:
        return False
    declared = _names(before)
    gained = _names(after)
    if declared is None or gained is None:
        return False
    if not _same(_without_names(before), _without_names(after)):
        return False
    for name, route in declared.items():
        # Present, and pointing exactly where it pointed. A route that moved is
        # a credential read from somewhere else, which is the act this refuses.
        if name not in gained or not _same(route, gained[name]):
            return False
    for name, route in gained.items():
        # A route deserializes from an OBJECT. Anything else makes the whole
        # document unreadable to the CLI, so it is a declaration lost rather
        # than one gained.
        if name not in declared and not isinstance(route, dict):
            return False
    return True


def _no_duplicate_keys(pairs):
    """The mapping those pairs build, refusing any key that appears twice.

    The two readers disagree here, and not symmetrically. Measured against the
    CLI itself, with one config per row:

        a duplicate key INSIDE `secrets`    both keep the LAST — they agree
        a duplicate key at the TOP LEVEL    the crate's loader refuses the
                                            document and falls back to a config
                                            declaring NOTHING, while Python
                                            keeps the last and sees every name

    So a write carrying the second shape reads as additive here and takes every
    declaration away there — and it reads that way precisely because the
    comparison believes both readers see one document.

    Refused at EVERY level, not only at the one where they differ: a duplicate
    key in a config is never intended, and a rule that has to know which level
    it is looking at is a rule that goes wrong the day the struct grows a field.
    """
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key %r" % key)
        seen[key] = value
    return seen


def _refuse_constant(name):
    """`NaN`, `Infinity`, `-Infinity`.

    The one axis on which the two readers that matter disagree about what a JSON
    document even IS: Python's takes these and the crate's refuses them. Left
    alone, the comparison above could be between two documents the CLI cannot
    read, and could report one of them as additive.
    """
    raise ValueError("%s is not a value this document may hold" % name)


def _object(text):
    """The document as a mapping, or None when it is not one this can read."""
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicate_keys,
                          parse_constant=_refuse_constant)
    except (ValueError, RecursionError):
        # RecursionError: a deeply nested document is a hostile input, and the
        # answer to one is the same refusal as to a malformed one.
        return None
    return data if isinstance(data, dict) else None


def _names(doc):
    """The `secrets` map, `{}` where the document declares none, or None where
    that key holds something that is not a map."""
    value = doc.get(_SECRETS, {})
    return value if isinstance(value, dict) else None


def _without_names(doc):
    return {key: value for key, value in doc.items() if key != _SECRETS}


def _same(left, right):
    """Deep equality in which no JSON type may stand in for another.

    `type(...) is not type(...)` first, which is what separates a boolean from
    the integer Python reads as its equal, and a whole number from the float
    spelling of it. The crate's loader answers either substitution with a type
    error and then reads no config at all, so treating them as equal here would
    pass a document that takes every declared name away.
    """
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return len(left) == len(right) and all(
            key in right and _same(value, right[key])
            for key, value in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same(a, b) for a, b in zip(left, right))
    return left == right
