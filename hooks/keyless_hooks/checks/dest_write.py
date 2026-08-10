"""KL-DEST — a credential file is not written through a tool that copies it first.

`KL-WRITE` asks what is IN the text being written. This asks what the text is
being written TO, and they are different holes. Rewriting a hostname inside a
`.env` carries no credential literal at all, so `KL-WRITE` is correctly silent —
and the edit still burns every OTHER line of that file, untouched, into a
plaintext copy on disk.

── the failure, stated without the word "should" ───────────────────────────────
Before an `Edit` / `Write` / `MultiEdit` / `NotebookEdit` applies, the host copies
the destination's CURRENT on-disk content into

    ~/.claude/file-history/<session id>/<sha256(abs path)[:16]>@v<N>

verbatim. Nothing redacts it, it survives the file being deleted, and it is
duplicated into a NEW session directory every time a session is resumed. One
edit is enough to copy a whole environment file at once — every name in it, with
every value — out of a file the session itself may be forbidden to read.

── why this is not a second list ───────────────────────────────────────────────
The classification is `secretpaths.is_protected`, unchanged and unextended: the
same call, the same `protected`/`allowed` config, that already decides `KL-FILE`
on `Read`, `Grep` and `Bash`. A path this pack refuses to READ is now also a path
it refuses to OVERWRITE. Two lists would drift silently; there is one.

── it fires only where a copy actually happens: the file must EXIST ────────────
There is nothing to copy out of a file that is not there, so a write CREATING a
protected path is not this check's business and is left alone.

That boundary is not a nicety. `KL-WRITE` REWRITES a credential literal headed
for a `.env` — `STRIPE_KEY=sk_live_…` becomes `STRIPE_KEY=${STRIPE_KEY}`, the
write lands, the secret does not, and it is one `keyless run` from working. The
engine returns on the FIRST deny, above every check still to run, so a deny here
would have discarded that repair and handed back a refusal instead of a working
redacted file. The contract battery caught exactly that, in eight vendor shapes.

The two checks therefore divide cleanly, and neither covers the other:

    KL-WRITE   what is IN the text            content     rewrite / deny / warn
    KL-DEST    what the text LANDS ON, when   the copy    deny
               there is content to copy

An existence test in a CHECK is the pack's existing idiom, not a departure from
it: `file_read._read_rewrite` and `_grep_deny` both return no opinion on a path
that is not a file. What `secretpaths` forbids is an existence test inside the
CLASSIFIER — whether a STRING names a credential file — and both reasons it
gives are absent here. There is no `cd` to move the working directory out from
under a write tool's own destination, and nothing was deleted between a decision
and its replay.

An UNRESOLVABLE path is still refused. "I could not look" and "there is nothing
there" are the same empty answer from a filesystem test and only one of them is
safe — the tilde bug that cost `file_read` a whole block is the same shape.

── the escape hatch is real, and the message names it ──────────────────────────
The copy is taken by the write TOOL, not by the filesystem: every blob in that
store belongs to a path some write tool aimed at, and a path only ever read, or
only ever modified from a shell, has none. So an in-place shell edit is the
working route for changing a value that is not itself a secret, and the refusal
prints it rather than leaving the author with no move.

Every OTHER route into one of these files is already refused — `cp
.env.example .env`, `printf … > prod.env` and `cat > .env <<EOF` are each denied
today by `KL-FILE` or `KL-HEREDOC`, because `cp` and `mv` are deliberately absent
from `non_readers`. The write TOOL was the one door left open, and it is the only
one of them that also takes a plaintext copy on the way through.
"""

import os

from ..secretpaths import is_protected, names_in, resolve

CHECK = "KL-DEST"

_TOOLS = frozenset(["Write", "Edit", "MultiEdit", "NotebookEdit"])

# The verb each tool performs, for a message that reads as one sentence rather
# than as a template with a tool name dropped into it.
_VERB = {"Write": "Write", "Edit": "Edit", "MultiEdit": "MultiEdit",
         "NotebookEdit": "NotebookEdit"}


def run(payload, cfg):
    if payload.event != "PreToolUse":
        return None
    if payload.tool not in _TOOLS:
        return None

    path = payload.file_path
    if not path:
        # No destination in the payload. An empty parse is "I do not know",
        # never "it is safe" — but there is also nothing to name, so this is the
        # one shape with genuinely no opinion to give.
        return None

    pattern = is_protected(path, payload.cwd, cfg)
    if not pattern:
        return None

    verb = _VERB.get(payload.tool, "write")
    resolved = resolve(path, payload.cwd)
    if resolved is None:
        # Protected, and this process cannot say WHICH file it is — so it cannot
        # say whether a copy will be taken either. Refuse rather than guess.
        return ("deny", _deny_text(path, pattern, [], "unresolvable path", verb),
                {"path": path[:160], "pattern": pattern, "names": 0,
                 "tool": payload.tool, "resolved": False})

    try:
        exists = os.path.isfile(resolved)
    except OSError:
        # Unreadable is not absent. Same direction as an unresolvable path.
        exists = True
    if not exists:
        # Nothing on disk, so nothing is copied. A credential literal in the text
        # of this same call is KL-WRITE's to rewrite, and returning a deny here
        # would throw that rewrite away.
        return None

    names, note = _names_for(resolved)
    return ("deny", _deny_text(resolved, pattern, names, note, verb),
            {"path": resolved[:160], "pattern": pattern, "names": len(names),
             "tool": payload.tool, "resolved": True})


def _names_for(target):
    try:
        return names_in(target)
    except OSError:
        return [], "unreadable"


def _deny_text(target, pattern, names, note, verb):
    """The refusal. Fact, consequence, a runnable action, and how to switch it off.

    Every byte here is a literal from this file or a name `names_in` validated
    whole against a bounded identifier pattern. No value can reach it.
    """
    if names:
        listed = ", ".join(names[:25])
        more = " …and %d more" % (len(names) - 25) if len(names) > 25 else ""
        inventory = ("The %d name(s) that copy would contain — no values: %s%s"
                     % (len(names), listed, more))
    else:
        inventory = "Names could not be read from it (%s)." % (note or "unknown")

    return (
        "[%s] %s matched the protected pattern `%s`. Its content is a credential, "
        "so this %s is refused.\n\n"
        "The refusal is about the COPY, not about the edit. Before a write tool "
        "applies, the host writes the destination's current on-disk content, "
        "verbatim and unredacted, to\n"
        "    ~/.claude/file-history/<session id>/<sha256 of the path>@v<N>\n"
        "That copy outlives the file, it is never redacted, and a resumed session "
        "duplicates it into a new directory. One edit copies the whole file.\n\n"
        "%s\n\n"
        "What still works:\n"
        "  * Change a value that is NOT itself a secret, in place, from the "
        "shell — an in-place shell edit is not copied:\n"
        "        sed -i '' 's|^SOME_HOST=.*|SOME_HOST=new.example|' %s\n"
        "  * Use a value without reading it:\n"
        "        keyless run -s <NAME> -- <the command that needs it>\n"
        "  * `keyless ls` lists every name keyless can resolve.\n\n"
        "If this path holds no real secret — a fixture, a template, an example — "
        "add it to `allowed` in ~/.config/keyless/hooks.json and this refusal "
        "stops for it. An operator can disable the whole pack for a session with "
        "KEYLESS_HOOKS_DISABLE=1 in the settings file's `env` block. A session "
        "cannot set its own environment, which is the point. Re-issuing this "
        "write in another spelling will not produce a different answer."
        % (CHECK, target, pattern, verb, inventory, target))
