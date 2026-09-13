"""KL-SWITCH — turning the pack off, or rewriting the files that configure it,
is not something a tool call inside this session reaches.

Every other check in this pack answers "does this call touch a credential".
This one answers a question one level up: could the call in front of us
change whether any check answers that question at all — this call, or every
call after it. The adversary here is not a leaked value; it is a session that
routes around every other check by turning them off first.

Three shapes, one refusal:

    the disable/uninstall verb    `keyless disable`, `keyless uninstall`,
                                   and the pack's own uninstall scripts —
                                   whatever they are asked to do, they end
                                   with `enabled` no longer true
    a tool write                  Write/Edit/MultiEdit/NotebookEdit aimed at
                                   this pack's own config
    a shell write                 the same files, reached from Bash — a
                                   redirect, `tee`, `cp`, `sed -i`, a payload
                                   handed to an interpreter

A *read* of the config is not this check's business; the reader heads below
are the ones a person or an agent legitimately reaches for to see what is
configured, and refusing them would make the pack harder to operate without
making it any harder to switch off. Anything not on that closed list is
refused — including every write-shaped command — because the set of programs
that can rewrite a file is unbounded and a name missing from an allowlist
must fail toward blocking, the same call `secretpaths` makes for the
credential list this pack already protects.

The refusal below names none of `keyless enable`, `KEYLESS_HOOKS_DISABLE`, an
edit to `hooks.json`, or any other way around it. Those exist and they work —
they are how a person, not this session, puts the pack back where they want
it — and printing the sentence that does it hands an agent a recipe for
undoing every other guard in one line. What the message says instead is where
that decision is made: outside the session, by someone at a terminal.
"""

import os
import re

from .. import secretpaths
from ..shellview import (delegated_head, expand_local_assignments,
                         file_operands_spanned, flatten_substitutions, head_of,
                         head_or_wrapper, heredocs, interpreter_payloads,
                         positional_span, rest_after_head, statements,
                         strip_heredocs, substitution_payloads, tokens, unquote,
                         words)

CHECK = "KL-SWITCH"

_WRITE_TOOLS = frozenset(["Write", "Edit", "MultiEdit", "NotebookEdit"])

# The two files this pack itself reads: its own `hooks.json`, and the CLI's
# `config.json` that `served.py` already reads back out under `KEYLESS_CONFIG`
# / `XDG_CONFIG_HOME`. Kept as one pair rather than two separate lists because
# every location either file can live at is the same directory, one basename
# apart.
_GUARD_BASENAMES = ("hooks.json", "config.json")

# The project-layer file `config.py` merges on top of the user's own — matched
# by basename alone, at any depth, because a project checkout can put it
# anywhere.
_PROJECT_GUARD_BASENAME = ".keyless-hooks.json"

# Programs that cannot rewrite a file's content, only report on it — the
# closed side of the allowlist, same discipline as `config.DEFAULT_NON_READERS`
# and for the same reason: the set of programs that CAN write is unbounded, so
# naming the readers is what fails toward blocking rather than toward allowing.
_READ_HEADS = frozenset([
    "cat", "less", "more", "head", "tail", "jq", "grep", "egrep", "fgrep", "rg",
    "wc", "diff", "cmp", "ls", "stat", "file", "bat", "test", "[", "[[",
    "md5", "shasum", "sha256sum", "echo", "printf",
])

# `git`'s own read-only subcommands. `git show`, `git log -p` and friends
# print a file's content the same way `cat` does and belong on the list above
# in spirit; they are kept as a pair with the binary name because `git reset`
# and `git checkout` sit one word away and DO write.
_GIT_READ_SUBCOMMANDS = frozenset([
    "add", "diff", "log", "show", "status", "blame", "ls-files", "commit", "grep",
])

_DIR_SAFE_HEADS = frozenset(["cd", "pushd", "mkdir"])

_HELP_TOKENS = frozenset(["--help", "-h", "-?"])

# Flags `keyless` accepts before the verb. `--config`/`--audit` consume the
# word after them; `--no-audit` and every other dashed token are skipped in
# place, so a flag this table has never heard of still does not stop the walk
# from reaching the verb.
_TAKES_VALUE = frozenset(["--config", "--audit"])

# Output redirects only. `<`, `<<<` and `<&` read a file rather than write one,
# and are deliberately absent — a guard file named after one of those is a
# read, judged by the reader-head rule below like any other.
_REDIRECT_OUT = re.compile(r"^\d*(?:>>|>\||&>>|&>|>)")


def run(payload, cfg):
    if payload.event != "PreToolUse":
        return None
    if payload.tool in _WRITE_TOOLS:
        return _tool_write_hit(payload)
    if payload.tool != "Bash":
        return None
    cmd = payload.command
    if not cmd or not cmd.strip():
        return None

    # Every Bash call reaches this check, and nearly none of them can name the
    # switch or a guard file. A substring test on the command with quotes and
    # backslashes collapsed — the spellings `key''less` and `hooks.j\son` the
    # shell reads as the plain words — settles those before any tokenizing.
    # It only ever skips; whenever a needle is present both scans run in full.
    flat = _collapse(cmd)
    targets = _guard_targets()
    dirs = {os.path.dirname(target) for target in targets}
    docs = heredocs(cmd)
    base = strip_heredocs(cmd)

    if "keyless" in flat or "uninstall" in flat:
        hit = _scan_disable_and_uninstall(cmd, base, docs, cfg)
        if hit:
            return hit
    needles = {os.path.basename(path) for path in targets | dirs}
    needles.add(_PROJECT_GUARD_BASENAME)
    if any(needle in flat for needle in needles):
        return _scan_guard_writes(base, payload, cfg, targets, dirs)
    return None


def _collapse(text):
    return text.replace("'", "").replace('"', "").replace("\\", "")


# ── the off-switch verb, and the pack's own uninstallers ───────────────────

def _keyless_verb(rest):
    """The word `keyless` acts on, past every global flag — or "" for none.

    "" also covers a bare `keyless` with no verb at all, which prints its own
    help and is not this check's business.
    """
    toks = tokens(rest)
    i, n = 0, len(toks)
    while i < n:
        tok = toks[i]
        if tok in _TAKES_VALUE:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return tok
    return ""


def _is_keyless_help(rest):
    toks = tokens(rest)
    if any(tok in _HELP_TOKENS for tok in toks):
        return True
    return _keyless_verb(rest) == "help"


def _keyless_disable_hit(stmt):
    if _collapse(head_of(stmt)) != "keyless":
        return False
    rest = rest_after_head(stmt)
    if _is_keyless_help(rest):
        return False
    return _collapse(_keyless_verb(rest)) in ("disable", "uninstall")


def _raw_head(stmt):
    """The head token exactly as written — leading path and all.

    `head_of` deliberately strips a leading path so `/usr/bin/keyless` and
    `keyless` compare equal; recovering the path here is for the one question
    that needs it — telling `hooks/uninstall.sh` apart from any other script
    that happens to share its basename. Rebuilt from the offset `head_of`'s own
    walk already computed, so this never re-derives the wrapper/assignment
    skipping it depends on.
    """
    name, end = head_or_wrapper(stmt)
    if not name or end < 0:
        return ""
    for start, stop in words(stmt):
        if stop == end:
            return stmt[start:stop]
    return ""


def _first_operand(rest):
    """The first non-flag word, unquoted — for the argument after an
    interpreter's own name, which is the script it is about to run."""
    for start, end in words(rest):
        tok = rest[start:end]
        if tok.startswith("-"):
            continue
        return unquote(tok)
    return ""


def _uninstaller_hit(stmt, head, cfg):
    """True for a statement that runs `hooks/uninstall.sh`, or `install.py` /
    `install.sh` with `--uninstall` — the pack's own removal path, run
    directly or handed to a shell/language interpreter."""
    rest = rest_after_head(stmt)
    if head in cfg.interpreters:
        target = _first_operand(rest)
    else:
        target = unquote(_raw_head(stmt))
    target = target.replace("\\", "")
    if not target:
        return False
    if target.endswith("hooks/uninstall.sh"):
        return True
    base = target.rsplit("/", 1)[-1]
    if base in ("install.py", "install.sh"):
        return "--uninstall" in tokens(rest)
    return False


def _executed_view(cmd, docs):
    """The command with every span the shell will NOT execute blanked: single-
    quoted strings, and the bodies of here-documents opened with a quoted
    delimiter. Length is preserved.

    Only this view is searched for `$( … )` and backticks. Prose written into a
    file — a report, an issue body, a prompt — spells the verb as markdown code,
    `` `keyless disable` ``, and inside single quotes or a quoted heredoc those
    backticks are characters. Replayed over real sessions, that was the whole of
    this check's false positives on the verb. Inside double quotes, and inside
    an unquoted heredoc body, the same backticks DO run, so those stay visible —
    and quote characters inside an unquoted body are literal text, so no quote
    tracking happens there.
    """
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


def _fed_bodies(docs, cfg):
    """Here-document bodies handed to a program that runs them as code —
    `bash <<EOF`, `ssh host <<EOF`. Every line there is a command."""
    out = []
    for doc in docs:
        if any(head_of(stmt) in cfg.interpreters for stmt in statements(doc.opener)):
            out.append(doc.body)
    return out


def _scan_disable_and_uninstall(cmd, base, docs, cfg):
    # `bash -c "…"`, `$(…)` and backticks are re-parsed as their own commands,
    # the way KL-VAULT already reads a subcommand handed to an interpreter —
    # a statement-level act, not an operand, so it needs its own head rather
    # than a candidate string pulled out of the payload. Heredoc bodies are
    # blanked for the statement scan, as KL-FILE blanks them, and read back in
    # only where the body is fed to something that executes it.
    texts = [base, expand_local_assignments(base)]
    texts += interpreter_payloads(base, cfg.interpreters)
    texts += substitution_payloads(_executed_view(cmd, docs))
    texts += _fed_bodies(docs, cfg)
    for text in texts:
        for stmt in statements(text):
            if _keyless_disable_hit(stmt):
                return ("deny", _message("switch"), {"shape": "keyless-verb"})
            head = head_of(stmt)
            if _uninstaller_hit(stmt, head, cfg):
                return ("deny", _message("uninstall"), {"shape": "uninstaller"})
    return None


# ── the pack's own config files, read or written ───────────────────────────

def _guard_targets():
    """Every literal path this session's guard files could resolve to.

    Not tested against the filesystem — a target absent right now is still a
    target the call in front of us would create, and `secretpaths` states the
    same rule for the credential list this pack already protects.
    """
    home = os.path.expanduser("~")
    targets = set()
    if home:
        base = os.path.join(home, ".config", "keyless")
        targets.update(os.path.normpath(os.path.join(base, name))
                       for name in _GUARD_BASENAMES)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        base = os.path.join(xdg, "keyless")
        targets.update(os.path.normpath(os.path.join(base, name))
                       for name in _GUARD_BASENAMES)
    hooks_override = os.environ.get("KEYLESS_HOOKS_CONFIG")
    if hooks_override:
        targets.add(os.path.normpath(hooks_override))
    config_override = os.environ.get("KEYLESS_CONFIG")
    if config_override:
        targets.add(os.path.normpath(config_override))
    return targets


def _is_guard_path(candidate, cwd, targets):
    if not candidate:
        return False
    stripped = candidate.strip().strip("'\"")
    if not stripped:
        return False
    if os.path.basename(stripped) == _PROJECT_GUARD_BASENAME:
        return True
    forms = set(secretpaths.expansions(candidate, cwd))
    resolved = secretpaths.resolve(candidate, cwd)
    if resolved:
        forms.add(resolved)
    return any(os.path.normpath(form) in targets for form in forms)


def _tool_write_hit(payload):
    path = payload.file_path
    if not path or not _is_guard_path(path, payload.cwd, _guard_targets()):
        return None
    return ("deny", _message("tool-write"), {"tool": payload.tool})


def _redirect_targets(stmt):
    """Every raw token this statement's output is redirected onto."""
    toks = [stmt[a:b] for a, b in words(stmt)]
    out = []
    for i, tok in enumerate(toks):
        m = _REDIRECT_OUT.match(tok)
        if not m:
            continue
        remainder = tok[m.end():]
        if remainder:
            out.append(unquote(remainder))
        elif i + 1 < len(toks):
            out.append(unquote(toks[i + 1]))
    return out


def _is_reader(head, stmt):
    if head in _READ_HEADS:
        return True
    if head == "find":
        # A path lister, until it is told to delete or to run something on
        # what it matched.
        return "-delete" not in tokens(stmt) and not delegated_head(stmt)
    if head == "git":
        sub, _offset = positional_span(stmt, 0)
        return sub in _GIT_READ_SUBCOMMANDS
    return False


def _scan_guard_writes(base, payload, cfg, targets, dirs):
    # The same four views KL-FILE reads a Bash command through: as written, an
    # assignment resolved (`F=~/.config/keyless/hooks.json; echo x > $F`), a
    # substitution flattened into its enclosing statement, and a substitution
    # body scanned on its own. `base` arrives with heredoc bodies blanked, for
    # the same reason KL-FILE blanks them: a runbook that quotes one of these
    # paths in prose is not an act on it.
    #
    # `dirs` are the directories the guard files live in. Naming one of these
    # to a program that is not a reader reaches every file inside it: a
    # recursive copy into the directory, a recursive delete of it, or a rename
    # of it never spells a basename at all.
    texts = [base, expand_local_assignments(base), flatten_substitutions(base)]
    texts.extend(substitution_payloads(base))
    seen = set()
    for text in texts:
        if text in seen:
            continue
        seen.add(text)
        hit = _scan_statements_for_guard(text, payload, cfg, targets, dirs)
        if hit:
            return hit
    return None


def _cd_target(stmt, head, cwd):
    """Where a `cd`/`pushd` statement leaves the shell, or None when it is not
    one or its operand cannot be resolved with confidence."""
    if head not in ("cd", "pushd"):
        return None
    operand, _offset = positional_span(stmt, 0)
    if not operand:
        return None
    return secretpaths.resolve(operand, cwd)


def _scan_statements_for_guard(text, payload, cfg, targets, dirs):
    # The working directory is followed through the command, because
    # `cd ~/.config/keyless && echo '{}' > hooks.json` names the file only
    # relative to a directory the payload's own `cwd` never mentions.
    cwd = payload.cwd
    for stmt in statements(text):
        head = head_of(stmt)
        moved = _cd_target(stmt, head, cwd)
        if moved is not None:
            cwd = moved
            continue
        redirected = _redirect_targets(stmt)
        reader = _is_reader(head, stmt)
        for cand, _tok_start in file_operands_spanned(stmt, head, cfg.interpreters):
            if _is_guard_path(cand, cwd, targets):
                if cand in redirected or not reader:
                    return ("deny", _message("shell-write"), {"head": head})
                continue
            # Entering or creating the directory writes nothing in it; whatever
            # writes a guard file there afterwards is judged on its own statement.
            if (not reader and head not in _DIR_SAFE_HEADS
                    and secretpaths.resolve(cand, cwd) in dirs):
                return ("deny", _message("shell-write"), {"head": head, "dir": True})
    return None


# ── the message ─────────────────────────────────────────────────────────────

_WHAT = {
    "switch": "This command turns the pack's guards off.",
    "uninstall": "This command runs the pack's own uninstaller.",
    "tool-write": "This edit targets one of the files that configure the guards.",
    "shell-write": "This command writes to one of the files that configure the guards.",
}


# Said only where the refused call named a file: a script handed the path is
# refused because it could write, whether or not it meant to, and the reader
# that wanted to see the configuration has a door that is not refused.
_READS = ("\n\nReading those files is not refused — `cat` or `jq` show what is "
          "configured, and `keyless ls` and `keyless doctor` report it.")


def _message(kind):
    return (
        "[%s] %s Refused.\n\n"
        "Switching the guards off, or changing the files that configure them, "
        "is a person's decision, made at a terminal outside this session — it "
        "is not something an agent session reaches from in here, whatever the "
        "call is spelled as.\n\n"
        "This refusal does not name another way to do it, because there is not "
        "meant to be one this session can reach.%s"
        % (CHECK, _WHAT.get(kind, "This call reaches the pack's own switch."),
           _READS if kind in ("tool-write", "shell-write") else ""))
