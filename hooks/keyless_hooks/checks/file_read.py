"""KL-FILE — a file whose content is a credential is not read in plaintext.

Two behaviours, chosen by what the host will let us substitute:

    Read / NotebookRead   REWRITE. The read is redirected to a names-only view
                          of the same file. The agent gets what it was actually
                          after — which names are configured — and no value.
    Bash / Grep           DENY. A shell command cannot be safely rewritten, so
                          the block carries the names inline instead, which
                          answers the same question in the same turn.

The deny is where the interesting engineering is. A path deny in the permission
system already reaches into Bash and stops `cat`, `head`, `grep` and `awk` on a
denied path — but it leaks two reproducible forms, `bash -c "cat <path>"` and
`$(echo cat) <path>`, because in both the path is not where a tokenizer looks.
Closing those is this check's job, and it is done by reading operands out of the
raw text per statement rather than by matching a binary name: five of ten bypass
spellings walk straight past a `Bash(cat:*)` deny.
"""

import os
import time

from ..secretpaths import is_protected, names_in, resolve
from ..shellview import (expand_local_assignments, file_operands,
                         first_positional, flatten_substitutions, head_of,
                         statements, strip_heredocs, substitution_payloads)

CHECK = "KL-FILE"
_RENDER_TTL = 6 * 3600
_RENDER_MAX = 200


def run(payload, cfg):
    if payload.event != "PreToolUse":
        return None
    tool = payload.tool
    if tool in ("Read", "NotebookRead"):
        return _read_rewrite(payload, cfg)
    if tool in ("Grep",):
        return _grep_deny(payload, cfg)
    if tool == "Bash":
        return _bash_deny(payload, cfg)
    return None


# ── the names-only rendering ────────────────────────────────────────────────

def _render_dir():
    base = os.environ.get("KEYLESS_HOOKS_STATE") or os.environ.get("TMPDIR") or "/tmp"
    return os.path.join(base, "keyless-hook-views")


def _prune(directory):
    """Drop renderings older than the TTL. Bounded, and never fatal.

    Housekeeping runs beside a verdict and must never change one, so every
    failure here is swallowed — a full temp directory is not a reason to let a
    secret through, and it is not a reason to block a read either.
    """
    try:
        now = time.time()
        entries = os.listdir(directory)[:_RENDER_MAX]
        for name in entries:
            p = os.path.join(directory, name)
            try:
                if now - os.stat(p).st_mtime > _RENDER_TTL:
                    os.unlink(p)
            except OSError:
                continue
    except OSError:
        pass


def _write_view(path, names, note):
    """Write the names-only view and return its path, or None.

    Every byte written here is either a literal from this source file or a name
    that `names_in` validated whole against a bounded identifier pattern. There
    is no code path on which a value reaches this file.
    """
    header = [
        "# keyless: %s holds credentials." % path,
        "# This is a NAMES-ONLY view. No value from that file appears below,",
        "# and no value from it is available to this session.",
        "#",
        "# Use one without reading it:   keyless run -s <NAME> -- <your command>",
        "# See what keyless can resolve: keyless ls",
        "",
    ]
    if names:
        body = ["%s=[keyless:redacted]" % n for n in names]
    else:
        body = ["# no names could be read from this file (%s)." % (note or "unknown"),
                "# its content is withheld in full."]
    blob = "\n".join(header + body) + "\n"

    # Imported here rather than at module scope: `hashlib` costs ~1.9 ms to
    # import and is reachable only on a protected Read, which is rare, while the
    # import would be paid on every tool call in every session.
    import hashlib

    directory = _render_dir()
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        _prune(directory)
        digest = hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:16]
        target = os.path.join(directory, "%s.env" % digest)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, blob.encode("utf-8"))
        finally:
            os.close(fd)
        return target
    except OSError:
        return None


def _read_rewrite(payload, cfg):
    path = payload.file_path
    if not path:
        return None
    pattern = is_protected(path, payload.cwd, cfg)
    if not pattern:
        return None

    resolved = resolve(path, payload.cwd)
    if resolved is None:
        # Protected, and this process cannot say which file it is. Refuse.
        #
        # The old spelling joined the raw string onto the cwd, so `~/.cckeys.json`
        # became `<cwd>/~/.cckeys.json`, `isfile` said no, and the read was
        # ALLOWED. "The file is not there" and "I could not look" are the same
        # empty answer from a filesystem test, and only one of them is safe.
        return ("deny", _deny_text(path, pattern, [], "unresolvable path", "Read"),
                {"path": path[:120], "pattern": pattern, "names": 0})
    if not os.path.isfile(resolved):
        # Nothing to redact and nothing to leak. No opinion.
        return None

    names, note = names_in(resolved)
    view = _write_view(resolved, names, note)
    if view is None:
        # The rewrite could not be produced. Fall back to a deny rather than
        # letting the read through: a rewrite that silently does not happen is
        # the one failure mode of this design that leaks.
        return ("deny", _deny_text(resolved, pattern, names, note, "Read"),
                {"path": resolved, "pattern": pattern, "names": len(names)})

    message = (
        "[%s] %s matched the protected pattern `%s`, so this Read was redirected "
        "to a names-only view at %s. The %d name(s) it declares are listed there; "
        "no value is. To use one, run the consuming command under keyless: "
        "`keyless run -s <NAME> -- <your command>`. Nothing else is needed and the "
        "plaintext is not obtainable in this session."
        % (CHECK, resolved, pattern, view, len(names)))
    return ("rewrite", message, {"file_path": view})


def _deny_text(target, pattern, names, note, how):
    listed = ", ".join(names[:25]) if names else "(none readable: %s)" % (note or "unknown")
    more = " …and %d more" % (len(names) - 25) if len(names) > 25 else ""
    return (
        "[%s] %s matched the protected pattern `%s`. Its content is a credential, "
        "so this %s is refused.\n\n"
        "The names it declares — no values: %s%s\n\n"
        "Use one without reading it:\n"
        "    keyless run -s <NAME> -- <the command you were going to run>\n"
        "`keyless ls` lists every name keyless can resolve. There is no verb that "
        "prints a value, so re-issuing this read in another spelling will not "
        "produce one.\n\n"
        "An operator can exempt a path by adding it to `allowed` in "
        "~/.config/keyless/hooks.json, or disable this pack for a session by "
        "setting KEYLESS_HOOKS_DISABLE=1 in the settings file's `env` block. "
        "A session cannot set its own environment, which is the point."
        % (CHECK, target, pattern, how, listed, more))


def _names_for(target):
    try:
        if os.path.isfile(target):
            return names_in(target)
    except OSError:
        pass
    return [], "unreadable"


# ── Grep ────────────────────────────────────────────────────────────────────

def _grep_deny(payload, cfg):
    path = payload.tool_input.get("path")
    if not isinstance(path, str) or not path:
        return None
    pattern = is_protected(path, payload.cwd, cfg)
    if not pattern:
        return None
    resolved = resolve(path, payload.cwd)
    if resolved is None:
        # Same trap as the Read path above: unresolvable is not absent.
        return ("deny", _deny_text(path, pattern, [], "unresolvable path", "Grep"),
                {"path": path[:120], "pattern": pattern, "names": 0})
    if not os.path.isfile(resolved):
        # A directory is not a protected file; the per-file gate covers whatever
        # inside it is protected when it is actually read.
        return None
    names, note = _names_for(resolved)
    return ("deny", _deny_text(resolved, pattern, names, note, "Grep"),
            {"path": resolved, "pattern": pattern, "names": len(names)})


# ── Bash ────────────────────────────────────────────────────────────────────

def _bash_deny(payload, cfg):
    cmd = payload.command
    if not cmd or not cmd.strip():
        return None

    # Four views of the same command, because each closes a bypass the others
    # cannot see:
    #
    #   as written                the ordinary case
    #   assignments expanded      `F=.env; cat $F`
    #   substitutions flattened   `cat $(echo .env)` — the path reaches `cat`
    #                             while living in a statement headed by `echo`
    #   substitution bodies       `echo "$(cat .env)"` — a command inside quotes,
    #                             which every quote-aware view blanks out
    #
    # Redundant on purpose. A safety net built from the same tokenizer inherits
    # the same blind spot and is therefore not a net.
    # Heredoc bodies are blanked ONCE, here, before any view is derived.
    #
    # They were already blanked for ACT detection and read raw for OPERAND
    # detection, and that inconsistency is a false positive: `strip_heredocs`
    # blanks a body line's characters but not its newline, so `statements()` cuts
    # at every line inside the body and hands back the RAW slice. A commit message
    # written through a heredoc that mentions `.env` therefore arrives as a
    # statement headed by whatever word the prose starts with — measured, this
    # refused a `git commit` whose message quoted `grep TOKEN .env`.
    #
    # The module already holds that a heredoc body is text ABOUT commands rather
    # than commands. This makes the two halves agree.
    base = strip_heredocs(cmd)
    texts = [base, expand_local_assignments(base), flatten_substitutions(base)]
    texts.extend(substitution_payloads(base))
    seen = set()
    for text in texts:
        if text in seen:
            continue
        seen.add(text)
        hit = _scan_statements(text, payload, cfg)
        if hit:
            return hit
    return None


def _scan_statements(text, payload, cfg):
    for stmt in statements(text):
        head = head_of(stmt)
        if head and head in cfg.non_readers:
            # A command that cannot put a file's content on stdout. This is the
            # closed side of the allowlist: small, enumerable, and it fails
            # toward blocking when a name is missing from it.
            continue
        # For a tool whose first argument is a PATTERN, that one operand is not a
        # path and its metacharacters are not a glob. `grep -rn '.*' src/` is a
        # regex; expanding it against the real directory matched every dotfile
        # there, which made this — the pack's largest block category — refuse a
        # large fraction of the commands it saw for no reason at all.
        #
        # Positional rather than a blanket rule for the whole command, because the
        # blanket version fails in both directions: `grep TOKEN prod.*` is a real
        # read through a glob, and `cat .*` really does dump every dotfile. Only
        # the pattern ARGUMENT is exempt, and only when no `-e`/`-f` flag supplied
        # the pattern from elsewhere.
        skip_glob = first_positional(stmt) if head in cfg.pattern_tools else ""
        # Nothing inside an interpreter's code is glob-expanded, because no shell
        # ever expanded it — `python3 -c "re.findall('.*', s)"` hands the
        # interpreter that string verbatim. The code arrives as a FLAG value, not
        # a positional, so the rule above cannot reach it.
        #
        # The shell case keeps its expansion by another road: `bash -c "cat .e*v"`
        # is re-scanned as its own command, where the head is `cat` and this test
        # is false. Only python/node/ruby payloads lose it, and a glob-shaped
        # string in those is a regex, not a path.
        in_code = head in cfg.interpreters
        for cand in file_operands(stmt, head, cfg.interpreters):
            pattern = is_protected(cand, payload.cwd, cfg,
                                   expand_globs=(not in_code and cand != skip_glob))
            if not pattern:
                continue
            # The deny fires either way — a Bash operand is refused on the
            # STRING. Resolution only decides whether the refusal can also name
            # what is configured in the file, which is the half that makes the
            # block useful instead of merely obstructive.
            resolved = resolve(cand, payload.cwd)
            names, note = _names_for(resolved) if resolved else ([], "unresolvable path")
            return ("deny",
                    _deny_text(cand, pattern, names, note,
                               "command (`%s`)" % (head or "unrecognised")),
                    {"operand": cand[:120], "pattern": pattern,
                     "head": head[:40], "names": len(names)})
    return None
