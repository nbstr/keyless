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
import re
import time

from .. import served as served_mod
from ..secretpaths import is_protected, match_sentence, names_in, resolve
from ..pattern_token import is_unmistakable_regex, pattern_token_start
from ..shellview import (delegated_head, expand_local_assignments,
                         file_operands_spanned, flatten_substitutions,
                         head_of, statements, strip_heredocs,
                         substitution_payloads)

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
    ]
    if names:
        served_result = served_mod.served()
        header.extend("# %s" % line
                       for line in served_mod.advice_lines(names, served_result))
        header.append("")
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
    protection = is_protected(path, payload.cwd, cfg)
    if not protection:
        return None
    pattern = protection.pattern
    provenance = _provenance(protection, path)

    resolved = resolve(path, payload.cwd)
    if resolved is None:
        # Protected, and this process cannot say which file it is. Refuse.
        #
        # The old spelling joined the raw string onto the cwd, so `~/.cckeys.json`
        # became `<cwd>/~/.cckeys.json`, `isfile` said no, and the read was
        # ALLOWED. "The file is not there" and "I could not look" are the same
        # empty answer from a filesystem test, and only one of them is safe.
        return ("deny", _deny_text(path, pattern, [], "unresolvable path", "Read",
                                   provenance),
                {"path": path[:120], "pattern": pattern, "names": 0,
                 "origin": protection.origin})
    if not os.path.isfile(resolved):
        # Nothing to redact and nothing to leak. No opinion.
        return None

    names, note = names_in(resolved)
    view = _write_view(resolved, names, note)
    if view is None:
        # The rewrite could not be produced. Fall back to a deny rather than
        # letting the read through: a rewrite that silently does not happen is
        # the one failure mode of this design that leaks.
        return ("deny", _deny_text(resolved, pattern, names, note, "Read",
                                   provenance),
                {"path": resolved, "pattern": pattern, "names": len(names),
                 "origin": protection.origin})

    message = (
        "[%s] %s matched the protected pattern `%s`, so this Read was redirected "
        "to a names-only view at %s. The %d name(s) it declares are listed there, "
        "each with what keyless will actually do for it; no value is, and the "
        "plaintext is not obtainable in this session."
        % (CHECK, resolved, pattern, view, len(names)))
    # A rewrite's extra is the tool-input PATCH the engine merges, never a log
    # record, so nothing descriptive belongs in it.
    return ("rewrite", message, {"file_path": view})


def _deny_text(target, pattern, names, note, how, provenance=None):
    """The refusal. `provenance` is the clause that says HOW the match was
    reached, and it changes no verdict — see `_provenance` below."""
    listed = ", ".join(names[:25]) if names else "(none readable: %s)" % (note or "unknown")
    more = " …and %d more" % (len(names) - 25) if len(names) > 25 else ""
    if names:
        served_result = served_mod.served()
        remedy = "\n".join("    %s" % line
                           for line in served_mod.advice_lines(names[:25], served_result))
    else:
        remedy = "    keyless run -s <NAME> -- <the command you were going to run>"
    return (
        "[%s] %s matched the protected pattern `%s`. Its content is a credential, "
        "so this %s is refused.\n\n"
        "%s"
        "The names it declares — no values: %s%s\n\n"
        "What keyless will do for each name above:\n"
        "%s\n"
        "There is no verb that prints a value, so re-issuing this read in "
        "another spelling will not produce one.\n\n"
        "The person running this session can exempt a path by adding it to "
        "`allowed` in ~/.config/keyless/hooks.json, or disable this pack for a "
        "session by setting KEYLESS_HOOKS_DISABLE=1 in the settings file's "
        "`env` block. A session cannot set its own environment, which is the "
        "point."
        % (CHECK, target, pattern, how,
           ("How that match was reached: %s\n\n" % provenance) if provenance else "",
           listed, more, remedy))


# A head holding one of these is not spelled like a program name. It is the
# tell that a statement was carved out of a REGEX rather than out of a command
# line, which is the whole discrimination this clause exists to carry.
_NOT_A_COMMAND_WORD = re.compile(r"[*?\[\]+|()^$\\]")


def _statement_sentence(view, head, cfg):
    """WHICH view of the command the operand came out of, and what that
    statement's head says about whether it was a command line at all.

    The config's own word lists are consulted before the metacharacter test,
    because several real commands are spelled with one — `[` and `[[` are both
    on `non_readers` — and calling one of those "not a command name" would be a
    false claim in a message whose whole job is to be trusted. The claim is made
    only about a head this pack has never heard of AND that carries a
    metacharacter.
    """
    where = "The operand was read out of %s" % view
    if not head:
        return "%s, in a statement with no recognised head." % where
    if (head not in cfg.non_readers and head not in cfg.interpreters
            and head not in cfg.pattern_tools
            and _NOT_A_COMMAND_WORD.search(head)):
        return ("%s, in a statement whose head `%s` carries a regex or glob "
                "metacharacter rather than being spelled like a command name."
                % (where, head))
    return "%s, as an argument of `%s`." % (where, head)


def _provenance(protection, candidate, statement=None):
    """One paragraph separating a credential path from a string that globbed
    onto one.

    It decides nothing. Every verdict is reached before this is called, and this
    is the only thing a reader has to tell a TRUE refusal — an operand that names
    a credential file — from one whose operand was a regex fragment the matcher
    expanded against a real directory. The two prescribe opposite next actions
    and were byte-identical in this message.
    """
    sentence = match_sentence(protection, candidate)
    return "%s %s" % (sentence, statement) if statement else sentence


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
    protection = is_protected(path, payload.cwd, cfg)
    if not protection:
        return None
    pattern = protection.pattern
    provenance = _provenance(protection, path)
    resolved = resolve(path, payload.cwd)
    if resolved is None:
        # Same trap as the Read path above: unresolvable is not absent.
        return ("deny", _deny_text(path, pattern, [], "unresolvable path", "Grep",
                                   provenance),
                {"path": path[:120], "pattern": pattern, "names": 0,
                 "origin": protection.origin})
    if not os.path.isfile(resolved):
        # A directory is not a protected file; the per-file gate covers whatever
        # inside it is protected when it is actually read.
        return None
    names, note = _names_for(resolved)
    return ("deny", _deny_text(resolved, pattern, names, note, "Grep", provenance),
            {"path": resolved, "pattern": pattern, "names": len(names),
             "origin": protection.origin})


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
    #
    # Each view is LABELLED, because which one fired is the other half of the
    # answer to "was this operand ever a path": a candidate carved out of a
    # substitution BODY reached the matcher through a view that reads raw text
    # and ignores quoting, and that is exactly where a regex fragment arrives
    # looking like a statement.
    base = strip_heredocs(cmd)
    views = [
        ("the command as written", base),
        ("the command with its local variable assignments expanded",
         expand_local_assignments(base)),
        ("the command with its `$( … )` substitutions flattened",
         flatten_substitutions(base)),
    ]
    views.extend(("the body of a `$( … )` command substitution", payload_text)
                 for payload_text in substitution_payloads(base))
    seen = set()
    for label, text in views:
        if text in seen:
            continue
        seen.add(text)
        hit = _scan_statements(text, payload, cfg, label)
        if hit:
            return hit
    return None


def _scan_statements(text, payload, cfg, view=None):
    for stmt in statements(text):
        head = head_of(stmt)
        if head and head in cfg.non_readers:
            # A command that cannot put a file's content on stdout. This is the
            # closed side of the allowlist: small, enumerable, and it fails
            # toward blocking when a name is missing from it.
            #
            # Unless it RUNS one. `find` earns its place on that list because
            # `find -name .netrc` prints a path, and loses it the moment an
            # `-exec` hands every match to a program: `find . -name .env -exec cat
            # {} \;` printed the file with this check silent. The statement is
            # then judged by what it actually runs, so `-exec ls` and `-exec rm`
            # stay silent on the same rule that always covered them.
            delegate = delegated_head(stmt)
            if not delegate or delegate in cfg.non_readers:
                continue
            head = delegate
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
        #
        # The exemption covers the whole TOKEN, identified by OFFSET rather than
        # by text. Matching the candidate's STRING against the pattern exempted
        # only the candidate that equalled the whole of it, and
        # `candidate_operands` carves fragments out of every token: the pattern
        # `"(if|\?).*\b(x|y)\b"` yields the candidate `.*`, which is not equal to
        # the pattern, so it expanded against the cwd and matched `.npmrc`. That
        # is an ordinary `grep`/`git grep` invocation, and it was refused.
        #
        # An offset also settles `grep .env .env`, where the same string is a
        # pattern in one position and a real read in the other. A string
        # comparison exempts both.
        pattern_start = pattern_token_start(stmt, head, cfg)
        # And where the pattern token is UNMISTAKABLY a regex — wholly quoted and
        # still carrying a backslash when it reaches the program — no candidate
        # carved from it is a path at all, literal or expanded. `grep -E
        # 'mirror|vibe-agent\.env' log` was refused on the fragment `.env`. The
        # safety argument lives on `is_unmistakable_regex`: a mis-identified token
        # of that shape opens a file whose NAME holds a backslash, which is not
        # the protected file the fragment spells.
        regex_only = is_unmistakable_regex(stmt, pattern_start)
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
        for cand, tok_start in file_operands_spanned(stmt, head, cfg.interpreters):
            # For an ordinary pattern token ONLY the glob expansion is withheld,
            # never the literal match, and that asymmetry is the safety property
            # of this exemption.
            #
            # Dropping every candidate of the pattern token was tried and it
            # opened a real hole: `grep EMAIL= /tmp/e2e.env` has a PATTERN shaped
            # like an assignment, `positional_span` skips it as one, and the FILE
            # is then identified as the pattern and exempted — a genuine
            # credential read, silently allowed. Replayed against real traffic,
            # that is not a contrived spelling; it is how a shell script reads one
            # value out of an env file.
            #
            # Withholding only the expansion keeps the mis-identification a NOISE
            # bug instead of a LEAK: whatever token this picks, a literal
            # protected path in it is still matched and still refused. The one
            # token whose literal match is dropped is `regex_only`, and it holds
            # under the same mis-identification for the reason given above.
            from_pattern = pattern_start >= 0 and tok_start == pattern_start
            if from_pattern and regex_only:
                continue
            protection = is_protected(cand, payload.cwd, cfg,
                                      expand_globs=(not in_code and not from_pattern))
            if not protection:
                continue
            pattern = protection.pattern
            # The deny fires either way — a Bash operand is refused on the
            # STRING. Resolution only decides whether the refusal can also name
            # what is configured in the file, which is the half that makes the
            # block useful instead of merely obstructive.
            resolved = resolve(cand, payload.cwd)
            names, note = _names_for(resolved) if resolved else ([], "unresolvable path")
            return ("deny",
                    _deny_text(cand, pattern, names, note,
                               "command (`%s`)" % (head or "unrecognised"),
                               _provenance(protection, cand,
                                           _statement_sentence(view, head, cfg)
                                           if view else None)),
                    {"operand": cand[:120], "pattern": pattern,
                     "head": head[:40], "names": len(names),
                     "origin": protection.origin, "view": view})
    return None
