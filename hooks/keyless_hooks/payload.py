"""Untrusted JSON in, typed values out. The only place a payload is read.

A PreToolUse hook that raises exits 1, and exit 1 does NOT block — so a crash is
a guard that silently was not there. The defence is coercion here rather than a
blanket try/except around the checks: a blanket wrapper turns a crash into a
silent skip, which is the same absence wearing a disguise, and you cannot write
an assertion about a swallowed exception. You can write one about
`{"file_path": ["/etc/passwd"]}` producing no opinion.

Every field is optional in practice. A missing or wrongly-typed field becomes
the empty value of its declared type, never a fabricated default a check might
act on.
"""

import json

__all__ = ["Payload", "parse"]

# The text keys a write tool can carry, at the top level and inside a bulk edit's
# list entries. One tuple, so the two readers below cannot drift apart.
_TEXT_KEYS = ("content", "new_string", "new_source", "old_string")


def _s(obj, key, default=""):
    """A string field, or the default. Never raises, whatever `obj` is."""
    if not isinstance(obj, dict):
        return default
    v = obj.get(key)
    return v if isinstance(v, str) else default


def _d(obj, key):
    """A mapping field, or {}. Never raises."""
    if not isinstance(obj, dict):
        return {}
    v = obj.get(key)
    return v if isinstance(v, dict) else {}


class Payload(object):
    """A hook payload whose every field is guaranteed to be the type it claims.

    __slots__ rather than a dict: this is built on every tool call in every
    session and the attribute set is closed, so the dict-per-instance is pure
    overhead on the hottest path in the pack.
    """

    __slots__ = ("event", "tool", "tool_input", "command", "file_path",
                 "content", "cwd", "session_id", "permission_mode", "raw")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k, "" if k != "tool_input" and k != "raw" else {}))

    def __repr__(self):
        return "Payload(event=%r, tool=%r, cmd=%r)" % (
            self.event, self.tool, (self.command or "")[:40])

    def text_fields(self):
        """Every tool_input field that can carry a credential literal.

        Named explicitly rather than "every string in tool_input": a check that
        walks the whole object rewrites fields it does not understand, and the
        rewrite is the dangerous half of this pack.
        """
        ti = self.tool_input
        out = []
        for key in _TEXT_KEYS:
            v = ti.get(key)
            if isinstance(v, str) and v:
                out.append((key, v))
        return out

    def text_slots(self):
        """Every credential-carrying string, with an ADDRESS that can be written back.

        `text_fields` answers "what text is here" and cannot answer "where does a
        replacement go", because one of the write tools does not keep its text at
        the top level. A bulk edit carries a LIST of edits, each a mapping with
        its own `old_string` and `new_string`, and a check reading only the named
        top-level keys sees an empty payload — a tool listed as covered, scanning
        nothing, which is the shape of coverage that is worse than none.

        An address is a top-level key (`"content"`), or the triple
        `("edits", index, key)`. `rebuild` is the only thing that consumes one, so
        the nesting is described in exactly one place.
        """
        out = list(self.text_fields())
        edits = self.tool_input.get("edits")
        if not isinstance(edits, list):
            return out
        for index, entry in enumerate(edits):
            # A non-mapping entry is not addressable and is never rewritten. It is
            # skipped rather than coerced: a list this check does not understand
            # must survive it byte-for-byte.
            if not isinstance(entry, dict):
                continue
            for key in _TEXT_KEYS:
                v = entry.get(key)
                if isinstance(v, str) and v:
                    out.append((("edits", index, key), v))
        return out

    def rebuild(self, changes):
        """The `updatedInput` fragment that applies `changes` — and nothing else.

        `changes` maps an address from `text_slots` to its replacement string.
        The guarantees, in order of how much damage their absence would do:

          * A nested change rewrites ONE value inside ONE entry. Every other key
            of that entry, every other entry, the list's length and the list's
            order are carried over unchanged.
          * An entry that is not a mapping is copied by reference and never read.
          * An address that no longer resolves — an index past the end, a list
            that is not a list — contributes nothing rather than raising. A
            rewrite that raises is a guard that silently was not there.
          * The fragment names only the top-level keys that actually changed, so
            the engine's merge cannot carry a field this check never looked at.
        """
        fragment = {}
        edit_changes = {}
        for addr, value in changes.items():
            if isinstance(addr, str):
                fragment[addr] = value
            elif (isinstance(addr, tuple) and len(addr) == 3
                    and addr[0] == "edits" and isinstance(addr[1], int)):
                edit_changes.setdefault(addr[1], {})[addr[2]] = value
        if edit_changes:
            edits = self.tool_input.get("edits")
            if isinstance(edits, list):
                rebuilt = []
                for index, entry in enumerate(edits):
                    patch = edit_changes.get(index)
                    if patch and isinstance(entry, dict):
                        merged = dict(entry)
                        merged.update(patch)
                        rebuilt.append(merged)
                    else:
                        rebuilt.append(entry)
                fragment["edits"] = rebuilt
        return fragment


def parse(raw):
    """Parse hook stdin. Returns a Payload, or None when there is nothing to judge.

    None means "no opinion" and the caller exits 0 silently. Anything that is
    not a JSON object — a list, a bare string, truncated bytes, empty stdin —
    lands here.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        # RecursionError: a deeply nested object is a hostile payload, not a
        # reason to take down the tool call it describes.
        return None
    if not isinstance(data, dict):
        return None

    ti = _d(data, "tool_input")
    return Payload(
        event=_s(data, "hook_event_name"),
        tool=_s(data, "tool_name"),
        tool_input=ti,
        command=_s(ti, "command"),
        file_path=_s(ti, "file_path") or _s(ti, "notebook_path") or _s(ti, "path"),
        content=_s(ti, "content"),
        cwd=_s(data, "cwd"),
        session_id=_s(data, "session_id"),
        permission_mode=_s(data, "permission_mode"),
        raw=data,
    )
