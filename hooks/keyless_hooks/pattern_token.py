"""Which token of a statement is a PATTERN, and when that pattern cannot be a path.

`checks/file_read` asks both questions of every pattern tool — `grep`, `sed`,
`jq`, `git grep` — and the answers decide how far a protected-path match inside
the pattern is trusted. They live here because they are about shell WORDS, not
about credentials.
"""

import re

from .shellview import positional_span, strip_heredocs, words

__all__ = ["pattern_token_start", "is_unmistakable_regex"]


def pattern_token_start(stmt, head, cfg):
    """Offset of the token holding this statement's PATTERN argument, or -1.

    -1 means "exempt nothing", and every path that cannot answer the question
    returns it — an unrecognised head, a pattern supplied by `-e`/`-f`, a
    statement with no positional at all. That is the direction that fails toward
    blocking.

    An INTERPRETER is refused the exemption because its first positional is a
    script path it opens and executes rather than a pattern — it sits on
    `pattern_tools` for its `-c`/`-e` payload alone. The caller already forces
    expansion off for interpreters, so today this is belt-and-braces rather than
    the only thing holding `python3 .env`.
    """
    if not head or head in cfg.interpreters:
        return -1
    if head in cfg.pattern_tools:
        return positional_span(stmt, 0)[1]
    # A head whose own first positional is a subcommand — `git grep <re>`. The
    # pair must be on the list; `git` alone never earns the exemption, or
    # `git show HEAD:.npmrc` would earn it too.
    sub = positional_span(stmt, 0)[0]
    if sub and ("%s %s" % (head, sub)) in cfg.pattern_subcommands:
        return positional_span(stmt, 1)[1]
    return -1


# Inside double quotes a backslash is REMOVED only before these characters; before
# any other it reaches the program as a backslash.
_DQ_ESCAPED = re.compile(r'\\([$`"\\\n])')


def _received(tok):
    """The text a program receives for a WHOLLY quoted token, or None.

    None for anything else — unquoted, partly quoted (`'a'b`), or a quote that
    closes early (`'a'b'c'`) — because only a wholly quoted token has one answer
    that does not depend on how the shell splices its pieces.
    """
    if len(tok) < 2 or tok[0] != tok[-1] or tok[0] not in ("'", '"'):
        return None
    inner = tok[1:-1]
    if tok[0] == "'":
        return None if "'" in inner else inner
    if re.search(r'(?<!\\)"', inner):
        return None
    return _DQ_ESCAPED.sub(r"\1", inner)


def is_unmistakable_regex(stmt, start):
    """True when the token at `start` reaches its program carrying a BACKSLASH.

    `grep 'vibe-agent\\.env' log` hands grep the six characters `\\.env` at the
    end of its pattern, and a candidate carved out of it — `.env` — names no
    file the call opens. If the positional walk had mis-identified that token and
    it were really a path, the file it opens is named with a literal backslash:
    `vibe-agent\\.env`, never `vibe-agent.env`. Either way no protected file
    reaches the program through this token.

    The test is on what the program RECEIVES, which is why it is a quoting
    question. Unquoted, the shell removes the backslash — `grep EMAIL= e2e\\.env`
    opens `e2e.env` — so an unquoted token never qualifies, and neither does a
    partly quoted one.
    """
    if start < 0:
        return False
    body = strip_heredocs(stmt)
    for a, b in words(body):
        if a == start:
            received = _received(body[a:b])
            return received is not None and "\\" in received
    return False
