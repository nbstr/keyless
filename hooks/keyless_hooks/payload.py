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
        for key in ("content", "new_string", "new_source", "old_string"):
            v = ti.get(key)
            if isinstance(v, str) and v:
                out.append((key, v))
        return out


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
