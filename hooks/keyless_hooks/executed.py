"""What the shell will EXECUTE, as opposed to what a command merely mentions.

`shellview` answers "which statement is this, and what is its head". This module
answers the question every command-shaped check asks before that one: which texts
inside a tool call are command lines at all. A substitution the shell runs, a
string handed to an interpreter, and a here-document body fed to one are each a
command line; the same characters in single quotes, a quoted heredoc, or behind a
backslash are prose.

KL-SWITCH answered that privately first. KL-VAULT kept reading the raw command,
so it refused a heredoc whose JSON quoted a vault verb in markdown backticks, and
it missed `echo "$(sh -c '<verb>')"` and `bash <<EOF` outright. One answer, shared,
is what makes the gates agree. KL-FILE and KL-ENV do not read through it yet —
KL-FILE also flattens substitutions into their enclosing statement, so the move
is not a swap — and that is tracked as nbstr/keyless#82.
"""

from .shellview import heredocs, head_of, interpreter_payloads, statements, substitution_spans

__all__ = ["executed_view", "fed_bodies", "command_texts"]


def executed_view(cmd, docs=None):
    """The command with every span the shell will NOT execute blanked: single-
    quoted strings, backslash-escaped characters, and the bodies of here-documents
    opened with a quoted delimiter. Length is preserved.

    Only this view is searched for `$( … )` and backticks. Prose written into a
    file — a report, an issue body, a prompt, a commit message — spells a verb as
    markdown code, `` `op read` ``, and inside single quotes, a quoted heredoc, or
    as `` \\` `` inside double quotes those backticks are characters. Replayed over
    real sessions, that was the whole of KL-SWITCH's false positives on its verb,
    and it was the reason KL-VAULT refused a heredoc carrying a JSON mission
    description. Inside double quotes, and inside an unquoted heredoc body, the
    same backticks DO run, so those stay visible — and quote characters inside an
    unquoted body are literal text, so no quote tracking happens there.
    """
    if docs is None:
        docs = heredocs(cmd)
    out = list(cmd)
    literal_body = set()
    live_body = set()
    for doc in docs:
        for start, end in doc.spans:
            (literal_body if doc.quoted else live_body).update(range(start, end))
    for k in literal_body:
        out[k] = " "
    n = len(cmd)
    i = 0
    in_double = False
    while i < n:
        if i in literal_body or i in live_body:
            i += 1
            continue
        c = cmd[i]
        if c == "\\":
            # An escaped character is literal, and blanking it is what keeps
            # `git commit -m "the \`op read\` verb"` from reading as a
            # substitution. A backslash-newline is a continuation; blanking both
            # characters joins nothing the statement scan relies on here.
            for k in range(i, min(i + 2, n)):
                out[k] = " "
            i += 2
            continue
        if c == '"':
            in_double = not in_double
        elif c == "'" and not in_double:
            close = cmd.find("'", i + 1)
            close = n if close < 0 else close
            for k in range(i, min(close + 1, n)):
                out[k] = " "
            i = close + 1
            continue
        i += 1
    return "".join(out)


def fed_bodies(docs, interpreters):
    """Here-document bodies handed to a program that runs them as code —
    `bash <<EOF`, `ssh host <<EOF`. Every line there is a command, whether or
    not the delimiter was quoted: quoting stops EXPANSION, never execution."""
    out = []
    for doc in docs:
        if any(head_of(stmt) in interpreters for stmt in statements(doc.opener)):
            out.append(doc.body)
    return out


# debt: `command_texts` follows at most _TEXT_DEPTH levels of nesting and returns
#       at most _TEXT_LIMIT texts, so a command nesting a verb four interpreters or
#       substitutions deep, or burying it past sixty-four other payloads, is read
#       as its outer layers only. Measured against the checks' own adversarial
#       corpus, the deepest real spelling is three levels.
#       Upgrade trigger: an adversarial case or a replayed session reaches a verb
#       at depth four, or KL-VAULT/KL-RUNNER decisions log a call whose text count
#       hit the limit.
_TEXT_DEPTH = 3
_TEXT_LIMIT = 64


def command_texts(cmd, interpreters):
    """Every text the shell will RUN as a command line, starting from `cmd`.

    Three extractors, applied to each other's output until nothing new appears:
    a substitution the shell executes, a string handed to an interpreter, and a
    here-document body fed to one. Applying them once each to the outer command
    was not enough in either direction:

    * `echo "$(sh -c 'op read x')"` — the substitution body is an interpreter
      call, and the verb is inside ITS quoted payload. Neither extractor alone
      reaches it.
    * `sh -c 'echo "$(op read x)"'` — the payload holds a double-quoted
      substitution, which the statement scan blanks with the rest of the quote.

    Substitutions are looked for on `executed_view`, so markdown backticks in
    single quotes, a quoted heredoc or an escaped backtick are not read as
    commands. The body is sliced from the RAW text at the offsets the view found.
    """
    out = []
    seen = set()
    frontier = [cmd or ""]
    for level in range(_TEXT_DEPTH + 1):
        nxt = []
        for text in frontier:
            if not text.strip() or text in seen or len(out) >= _TEXT_LIMIT:
                continue
            seen.add(text)
            out.append(text)
            if level == _TEXT_DEPTH:
                continue
            docs = heredocs(text)
            nxt.extend(text[a:b] for a, b, _ in substitution_spans(executed_view(text, docs)))
            nxt.extend(interpreter_payloads(text, interpreters, depth=1))
            nxt.extend(fed_bodies(docs, interpreters))
        frontier = nxt
    return out
