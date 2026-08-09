"""Three views of a shell command, and the statement/head primitives.

Every trigger in this pack answers two questions that look like one: *is this an
act, or a mention of the act*, and *what exactly is it acting on*. Those need
different views of the same string.

    both-stripped   quoted spans and heredoc bodies blanked  -> detect the ACT
    raw             nothing blanked                          -> read the OPERANDS

Stripping replaces characters with spaces rather than deleting them, so every
offset in a stripped view indexes the same character in the raw string. That is
what lets a check match on one view and slice the other.

`bash -c "cat .env"` is the case that decides the design: on the both-stripped
view the statement head is `bash`, and the operand `.env` exists only in the raw
text. A check reading one view sees a harmless `bash` invocation; a check reading
the other sees `.env` with no idea what touches it. It takes both.
"""

import re

__all__ = [
    "strip_quoted", "strip_heredocs", "stripped",
    "statement_spans", "statements", "head_of", "head_or_wrapper", "words",
    "candidate_operands", "file_operands", "expand_local_assignments",
    "interpreter_payloads", "rest_after_head", "first_positional",
    "flatten_substitutions", "substitution_payloads",
    "assignment_split", "is_wrapper",
]

# Wrapper words that TAKE a command as their argument. The head of
# `sudo -u x env FOO=1 timeout 5 cat f` is `cat`, not `sudo`. Absorbing these is
# what stops every gate in the pack being walked past by one prefix word.
_WRAPPERS = frozenset([
    "sudo", "doas", "env", "nohup", "time", "timeout", "nice", "ionice",
    "stdbuf", "command", "builtin", "exec", "xargs", "setsid", "caffeinate",
    "script", "watch", "unbuffer",
])

# Shell keywords after which a COMMAND begins. Omitting these is the classic
# hole: `for f in *; do cat .env; done` puts the real verb after `do`.
_KEYWORDS = frozenset(["do", "then", "else", "elif", "in", "while", "until", "if"])

_ASSIGN_PREFIX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_REDIRECT_TOKEN = re.compile(r"^\d*(?:>>|>&|>\||&>>|&>|>|<<<|<<|<&|<)")

# A candidate operand: the character set a filesystem path can be spelled with,
# plus the substitution characters a path can arrive through, plus the glob
# metacharacters — without those, `cat .e*v` is extracted as `.e` and `v` and the
# glob is invisible before the matcher ever gets a chance to expand it.
# Deliberately one quantifier over one class: no adjacent quantifiers over
# overlapping sets, so there is no backtracking cliff on a long command.
_OPERAND = re.compile(r"[A-Za-z0-9_.~$@{}\[\]*?/+:=-]+")

_HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def strip_quoted(cmd):
    """Blank the interior of quoted spans, preserving length and the quote marks.

    Single quotes are literal in every shell. Double quotes still interpolate,
    but for ACT detection the distinction does not matter: text inside either is
    an argument, not a command position.
    """
    if not cmd:
        return ""
    out = list(cmd)
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c == "\\":
            i += 2
            continue
        if c in ("'", '"'):
            quote = c
            j = i + 1
            while j < n:
                if cmd[j] == "\\" and quote == '"':
                    j += 2
                    continue
                if cmd[j] == quote:
                    break
                out[j] = " "
                j += 1
            i = j + 1
            continue
        i += 1
    return "".join(out)


def strip_heredocs(cmd):
    """Blank here-document bodies, preserving length.

    A runbook, a README or a generated script written through a heredoc is text
    ABOUT commands. Seven advisory checks in one estate fired on heredoc bodies
    because they read the raw command; this is that class closed once.
    """
    if not cmd or "<<" not in cmd:
        return cmd or ""
    out = list(cmd)
    lines = cmd.split("\n")
    pos = 0
    pending = []
    for line in lines:
        line_start = pos
        pos += len(line) + 1
        if pending:
            tag = pending[0]
            if line.strip() == tag:
                pending.pop(0)
            else:
                for k in range(line_start, min(line_start + len(line), len(out))):
                    out[k] = " "
            continue
        for m in _HEREDOC_OPEN.finditer(line):
            pending.append(m.group(2))
    return "".join(out)


def stripped(cmd):
    """The both-stripped view: quotes blanked, heredoc bodies blanked."""
    return strip_quoted(strip_heredocs(cmd))


def _separator_positions(view):
    """Offsets where a shell would begin reading a new COMMAND, over a stripped view.

    Returns a sorted list of offsets. Offset 0 is included only for a non-empty
    string: an empty command has no command positions at all, which is different
    from having one at 0.
    """
    if not view.strip():
        return []
    pos = [0]
    n = len(view)
    i = 0
    while i < n:
        c = view[i]
        # `{` opens a group only when a space follows, and `}` closes one only
        # when a space precedes. Without that test `cat ${F}` is cut into `cat $`
        # and `F}`, which destroys the operand this whole module exists to read.
        if c == "{" and not (i + 1 < n and view[i + 1].isspace()):
            i += 1
            continue
        if c == "}" and not (i > 0 and (view[i - 1].isspace() or view[i - 1] == ";")):
            i += 1
            continue
        if c in ";\n&|(){}":
            j = i + 1
            # Absorb a two-character operator so the position lands past it.
            if j < n and view[j] in "&|":
                j += 1
            pos.append(j)
            i = j
            continue
        i += 1
    # After a shell keyword, a command begins.
    for m in re.finditer(r"(?:^|[\s;&|(){}\n])(%s)(?=[\s\n])" % "|".join(_KEYWORDS), view):
        pos.append(m.end(1))
    return sorted(set(p for p in pos if p <= n))


def statement_spans(cmd):
    """(start, end) spans of each statement, as offsets into the RAW command."""
    if not cmd:
        return []
    view = stripped(cmd)
    cuts = _separator_positions(view)
    if not cuts:
        return []
    spans = []
    for idx, start in enumerate(cuts):
        end = cuts[idx + 1] if idx + 1 < len(cuts) else len(cmd)
        # Trim the separator characters themselves off the front of the slice.
        while start < end and (view[start] in ";&|(){}\n" or view[start].isspace()):
            start += 1
        # And off the back — but only a closer with no opener of its own inside
        # the slice, so `$(env)` yields the statement `env` while `cat ${F}`
        # keeps its brace. A statement carrying a trailing `)` is not the same
        # token as the command it names, and every downstream verb test fails on
        # the difference.
        while end > start:
            last = view[end - 1]
            if last.isspace() or last in ";&|\n":
                end -= 1
                continue
            if last in ")}":
                slice_ = view[start:end]
                opener = "(" if last == ")" else "{"
                if slice_.count(last) > slice_.count(opener):
                    end -= 1
                    continue
            break
        if start < end and cmd[start:end].strip():
            spans.append((start, end))
    return spans


def statements(cmd):
    """The raw text of each statement."""
    return [cmd[a:b] for a, b in statement_spans(cmd)]


def words(text):
    """(start, end) spans of shell words, quotes grouping rather than splitting.

    Offsets index `text`. A quoted span is one word even when it contains spaces,
    which is what makes `-c "cat .env"` two words and not three.
    """
    out = []
    n = len(text)
    i = 0
    while i < n:
        if text[i].isspace():
            i += 1
            continue
        start = i
        while i < n and not text[i].isspace():
            c = text[i]
            if c == "\\":
                i += 2
                continue
            if c in ("'", '"'):
                quote = c
                i += 1
                while i < n:
                    if text[i] == "\\" and quote == '"':
                        i += 2
                        continue
                    if text[i] == quote:
                        i += 1
                        break
                    i += 1
                continue
            i += 1
        out.append((start, min(i, n)))
    return out


def _unquote(tok):
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        return tok[1:-1]
    return tok


def assignment_split(token, declared=False):
    """`(name, raw_value)` for a shell assignment word, or None.

    The value is returned EXACTLY as written — quotes, expansions and all —
    because the caller's whole question is whether it is a literal, and
    unquoting here would delete the evidence.

    Built on `_ASSIGN_PREFIX`, the same regex `_walk_head` and `file_operands`
    use to decide that a leading word is an assignment rather than a command.
    A second copy of that pattern in a check module drifts the first time this
    one is corrected, and the two would then disagree about where a statement's
    assignment prefix ends.

    `declared` collapses quotes and backslashes out of the NAME before matching,
    and it exists because the two positions genuinely behave differently. Run on
    bash, zsh and sh:

        FOO""_BAR=hello              -> command not found; FOO_BAR is UNSET
        export FOO""_BAR=hello       -> FOO_BAR is hello
        env FOO""_BAR=hello sh -c …  -> FOO_BAR is hello

    In assignment-prefix position the name must be unquoted or the word is a
    COMMAND, so collapsing there would invent an assignment the shell never
    makes. After `export`, `declare`, `local`, `readonly` or a wrapper the word
    is an ARGUMENT: quote removal happens first and the builtin then parses
    `NAME=value` out of the result. The pack already collapses both marks on the
    VALUE side, where `gh""p_<literal>` is caught; a name a tokenizer cannot read
    was the same six-character bypass wearing the other hat.
    """
    if not token:
        return None
    m = _ASSIGN_PREFIX.match(token)
    if m:
        return token[:m.end() - 1], token[m.end():]
    if not declared:
        return None
    eq = token.find("=")
    if eq <= 0:
        return None
    name = token[:eq].replace("'", "").replace('"', "").replace("\\", "")
    if not _ASSIGN_PREFIX.match(name + "="):
        return None
    return name, token[eq + 1:]


def is_wrapper(name):
    """True when `name` TAKES a command as its argument — `env`, `sudo`, `timeout`.

    Public because a check that needs to know where a statement's assignment
    PREFIX ends walks the same list `head_of` does: in `env FOO=1 cmd` the
    assignment sits AFTER `env` and before the real head, so a walk that treats
    `env` as the command reads `FOO=1` as an argument and stops looking.
    """
    return name in _WRAPPERS


# A wrapper's own positional argument: `timeout 5 cmd`, `nice 10 cmd`,
# `timeout 1m cmd`. Without this the head of `timeout 5 op read …` is `5`, and
# every check that looks up a binary name misses — measured, `timeout 5 op read`
# walked past the vault gate while the bare form was blocked.
_WRAPPER_ARG = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")


def _walk_head(stmt):
    """(name, end_offset, last_wrapper) — the shared head walk.

    `last_wrapper` matters because a wrapper word standing alone IS a command:
    `env` on its own dumps the environment, while `env FOO=1 cmd` runs `cmd`.
    A caller that needs to tell those apart cannot use the absorbed answer.
    """
    last_wrapper = ("", -1)
    skip_next = False
    for start, end in words(stmt):
        tok = stmt[start:end]
        if not tok:
            continue
        if skip_next:
            # The operand of a bare redirect operator. Without this, the head of
            # `env > /tmp/e` is `e` — the redirect's TARGET read as the command —
            # and the gate on `env` goes silent on the one spelling that captures
            # every value to disk.
            skip_next = False
            continue
        if _REDIRECT_TOKEN.match(tok):
            if not tok.strip("<>&|0123456789"):
                skip_next = True
            continue
        if _ASSIGN_PREFIX.match(tok):
            continue
        if tok.startswith("-"):
            # A flag belonging to a wrapper already absorbed. A statement that
            # starts with a flag has no head we can name.
            continue
        name = _unquote(tok)
        if name.startswith("\\"):
            name = name[1:]
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        if not name:
            continue
        if last_wrapper[1] >= 0 and _WRAPPER_ARG.match(name):
            continue
        if name in _WRAPPERS:
            last_wrapper = (name, end)
            continue
        return name, end, last_wrapper
    return "", -1, last_wrapper


def head_of(stmt):
    """The command name a statement actually invokes, or "" when undecidable.

    Assignment prefixes, wrapper words, wrapper flags, wrapper positional
    arguments and redirections are absorbed. A leading path and a leading
    backslash are stripped, so `/usr/bin/cat`, `\\cat` and `cat` are one name.

    "" means "I could not tell", never "it is safe" — every caller treats it as
    no opinion about the head and falls back to the operand evidence.
    """
    if not stmt or not stmt.strip():
        return ""
    return _walk_head(stmt)[0]


def head_or_wrapper(stmt):
    """(name, end_offset), where a lone wrapper counts as the command.

    For a check whose subject IS a wrapper word — `env` printing the
    environment — the absorbed head is the wrong answer and the raw first token
    is also the wrong answer, because `sudo env printenv` runs `printenv`. This
    absorbs everything and then falls back to the last wrapper only when nothing
    followed it.
    """
    if not stmt or not stmt.strip():
        return "", -1
    name, end, last_wrapper = _walk_head(stmt)
    if name:
        return name, end
    return last_wrapper


def candidate_operands(text):
    """Every substring of the RAW text that could name a file.

    Deliberately generous. It runs over raw text, so an operand inside quotes,
    after a `<` redirect, or inside `$(...)` is found — those are exactly the
    forms that walk past a tokenizer. Precision is the protected-path matcher's
    job, not this one's; a candidate that names nothing costs one dict lookup.
    """
    if not text:
        return []
    return [m.group(0) for m in _OPERAND.finditer(text)]


def file_operands(stmt, head, interpreters):
    """Candidate filenames a statement touches, with quoted spans judged by role.

    A quoted span is DATA everywhere except as the argument of a program whose
    argument is a program. That single distinction settles four cases a simpler
    rule gets wrong in one direction or the other:

        cat "$HOME/.aws/credentials"     quoted, one word    -> an operand
        git commit -m "fix .env load"    quoted, a sentence  -> a mention
        bash -c "cat .env"               quoted, a sentence, head executes it -> an operand
        echo .env                         unquoted           -> an operand, and `echo`
                                                                cannot print a file anyway

    Blanking quotes for the whole scan loses the first case, which is how most
    real paths are spelled. Keeping them loses the second, and a guard that fires
    on a commit message about `.env` is a guard people uninstall.

    Two spellings get their own handling because both defeat tokenization:

      *quote splicing* — `.en''v` is `.env` to the shell and two fragments to any
      tokenizer. Collapsing the quotes out of a token recovers it, but only when
      the result has no whitespace, or `"fix .env"` collapses into an operand and
      every commit message about a dotfile becomes a block.

      *flag-attached operands* — `dd if=.env` carries the path on the right of an
      `=`. Splitting there is only safe AFTER the head word: before it, `X=.env
      docker compose up` is an environment assignment for a program that has
      every right to read it.
    """
    if not stmt:
        return []
    body = strip_heredocs(stmt)
    out = []
    executes = head in interpreters
    past_head = False
    for start, end in words(body):
        tok = body[start:end]
        quoted = ("'" in tok) or ('"' in tok)
        collapsed = tok.replace("'", "").replace('"', "")
        if quoted:
            inner = tok.replace("'", " ").replace('"', " ")
            if executes or len(inner.split()) == 1:
                out.extend(candidate_operands(inner))
            if collapsed and not any(c.isspace() for c in collapsed):
                out.extend(candidate_operands(collapsed))
        else:
            out.extend(candidate_operands(tok))
        if past_head and "=" in collapsed and "==" not in collapsed:
            # `==` is a COMPARISON, never a flag assignment. Splitting on it turns
            # the jq filter `.name=="staging.env"` into the operand `staging.env`,
            # which matches `*.env` and refuses a filter as a credential file.
            # `dd if=.env` and `--file=.env` have a single `=` and are unaffected.
            out.extend(candidate_operands(collapsed.rsplit("=", 1)[1]))
        if not past_head and not _REDIRECT_TOKEN.match(tok) and \
                not _ASSIGN_PREFIX.match(tok) and not tok.startswith("-"):
            past_head = True
    return out


_SUBST_OPEN = "$("


def flatten_substitutions(cmd):
    """The command with substitution delimiters blanked, length preserved.

    `cat $(echo .env)` puts the path in a statement whose head is `echo`, which
    cannot read a file — so the per-statement rule correctly clears it and the
    path still reaches `cat`. Blanking the delimiters inlines the inner words
    into the enclosing statement, where the head is the program that gets the
    result.

    Quotes are NOT touched here. Removing them would inline every commit message
    into its own command, which is the false positive this module spends most of
    its length avoiding.
    """
    if not cmd or ("$(" not in cmd and "`" not in cmd):
        return cmd or ""
    out = list(cmd)
    for i, c in enumerate(cmd):
        if c == "`" or c == ")":
            out[i] = " "
        elif c == "$" and i + 1 < len(cmd) and cmd[i + 1] == "(":
            out[i] = " "
            out[i + 1] = " "
    return "".join(out)


def substitution_payloads(cmd, depth=2):
    """The inner text of every `$( … )` and back-quoted span.

    A command substitution is a COMMAND, including inside double quotes where the
    quote-stripping view blanks it out of existence. `echo "$(cat .env)"` is a
    read of `.env` performed by `cat`, and every view that treats the quoted span
    as one word disagrees.
    """
    out = []
    if not cmd or depth <= 0:
        return out
    n = len(cmd)
    i = 0
    while i < n:
        if cmd[i] == "$" and i + 1 < n and cmd[i + 1] == "(":
            depth_paren = 1
            j = i + 2
            while j < n and depth_paren:
                if cmd[j] == "(":
                    depth_paren += 1
                elif cmd[j] == ")":
                    depth_paren -= 1
                j += 1
            inner = cmd[i + 2:j - 1] if depth_paren == 0 else cmd[i + 2:]
            if inner.strip():
                out.append(inner)
                out.extend(substitution_payloads(inner, depth - 1))
            i = j
            continue
        if cmd[i] == "`":
            j = cmd.find("`", i + 1)
            inner = cmd[i + 1:j] if j != -1 else cmd[i + 1:]
            if inner.strip():
                out.append(inner)
            i = (j + 1) if j != -1 else n
            continue
        i += 1
    return out


def interpreter_payloads(cmd, interpreters, depth=2):
    """Quoted strings that a statement hands to a program which EXECUTES them.

    `bash -c "op read op://vault/item"` is an `op read`, and a check anchored on
    the statement head sees only `bash`. Returning the inner text lets every
    command-shaped check re-scan it as what it is, at one level of nesting per
    call and a bounded total.
    """
    out = []
    if not cmd or depth <= 0:
        return out
    for stmt in statements(cmd):
        if head_of(stmt) not in interpreters:
            continue
        for start, end in words(stmt):
            tok = stmt[start:end]
            if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
                inner = tok[1:-1]
                if inner.strip():
                    out.append(inner)
                    out.extend(interpreter_payloads(inner, interpreters, depth - 1))
    return out


# Flags that supply a pattern from somewhere ELSE, so no positional is the
# pattern and every positional is a path. `grep -f patterns.txt secrets.env` reads
# both files, and skipping the first one would be a hole rather than a fix.
_PATTERN_FROM_FLAG = re.compile(
    r"(?:^|\s)(?:-[A-Za-z]*[ef]|--regexp|--file|--from-file)(?:[= ]|$)")


def first_positional(stmt):
    """The first non-flag word after the head, or "" when there is none.

    For a tool whose first argument is a PATTERN — `grep`, `sed`, `awk`, `jq` —
    this is the regex, the script or the filter, and it is the one operand that
    is never a path. Everything after it is.

    "" when a flag supplies the pattern instead, because then every positional is
    a path and there is nothing to skip. "" is also the answer when the statement
    has no positional at all; both mean "skip nothing", which is the safe default.
    """
    if not stmt:
        return ""
    rest = rest_after_head(stmt)
    if not rest or _PATTERN_FROM_FLAG.search(rest):
        return ""
    for start, end in words(rest):
        tok = rest[start:end]
        if tok.startswith("-") or _ASSIGN_PREFIX.match(tok) or _REDIRECT_TOKEN.match(tok):
            continue
        return _unquote(tok)
    return ""


def rest_after_head(stmt):
    """The statement text following its head word, wrappers and assignments gone.

    A check that reads a subcommand needs the arguments as written — flags
    included, quotes intact — because `security find-generic-password -w` and the
    same command without `-w` print entirely different things.

    It shares `_walk_head`, and that sharing is the point: a private walk here
    disagreed with `head_of` about `timeout 5 op read`, so the table was keyed on
    `op` while the subcommand text still began with `5`. Nothing matched, and the
    gate was silent on a command it had correctly identified.
    """
    if not stmt:
        return ""
    _name, end, _wrapper = _walk_head(stmt)
    if end < 0:
        return ""
    return stmt[end:].strip()


_SIMPLE_ASSIGN = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"$`]*\"|'[^']*'|[A-Za-z0-9_.~/@+-]*)$")
_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def expand_local_assignments(cmd, limit=64):
    """Substitute variables assigned by literals EARLIER IN THE SAME command.

    `F=.env; cat $F` is the same act as `cat .env` and every naive operand
    scanner misses it. Only literal assignments are followed — no substitution,
    no other variable — so this can resolve a path but can never invent one.

    Returns the expanded text. The caller scans BOTH this and the raw command,
    because expansion is best-effort: a variable set in an earlier tool call is
    not visible here and never will be.
    """
    if not cmd or "$" not in cmd:
        return cmd
    env = {}
    out = []
    for stmt in statements(cmd):
        text = stmt
        for name in _VAR_REF.finditer(stmt):
            key = name.group(1) or name.group(2)
            if key in env:
                text = text.replace(name.group(0), env[key])
        out.append(text)
        for start, end in words(stmt):
            m = _SIMPLE_ASSIGN.match(stmt[start:end])
            if m and len(env) < limit:
                env[m.group(1)] = _unquote(m.group(2))
    return "\n".join(out)
