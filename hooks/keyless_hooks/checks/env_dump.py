"""KL-ENV / KL-ENVVAR — the process environment is not printed in plaintext.

`env` is the cheapest bypass there is. Nothing needs to be read, no vault needs
to answer, and every secret the user's shell profile exported is one word away.

This check is the pack's worked example of **rewrite over deny**, because the
question an agent asks with a bare `env` is almost always *which names are set*,
not *what are the values* — and that question can be answered in full:

    env                  ->  env | sed -E 's/=.*/=[keyless:redacted]/'
    env | grep -i token  ->  env | sed -E 's/=.*/=[keyless:redacted]/' | grep -i token

The filter still filters, the names still print, the call is never refused, and
no value crosses the boundary. The rewrite is a span substitution on the dump
statement alone, so everything downstream of the pipe is untouched.

A dump that REDIRECTS is a different act — `env > /tmp/e` and `env | base64` are
capture, not inspection, and a sed spliced after the verb would not even be in
the data path. Those are denied.
"""

import re

from ..shellview import head_or_wrapper, statement_spans, statements, words

CHECK = "KL-ENV"
CHECK_VAR = "KL-ENVVAR"

_MASK = "sed -E 's/=.*/=[keyless:redacted]/'"

# The dump verbs, and what counts as "no arguments" for each. `set` prints the
# whole environment plus every function only when bare; `set -e` is the idiom
# every script starts with and must never fire.
_DUMP = {
    "env": ("-0",),
    "printenv": ("-0",),
    "export": ("-p",),
    "set": (),
    "declare": ("-x", "-p"),
    "typeset": ("-x", "-p"),
}

_REDIRECT = re.compile(r"^\d*(?:>>|>&|>\||&>>|&>|>|<<<|<<|<&|<)")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# Whole-environment expressions inside an interpreter's argument. Each excludes
# the single-key form: `process.env.FOO` is one variable and is the same act as
# `echo $FOO`, which is KL-ENVVAR's business, not this gate's.
_WHOLE_ENV = re.compile(
    r"process\.env(?!\s*[.\[])"
    r"|os\.environ(?!\s*[.\[(])"
    r"|os\.environ\.copy\(\)"
    r"|dict\(os\.environ\)"
    r"|\bENV\.(?:to_h|to_a|inspect|each)"
    r"|%ENV\b"
    r"|System\.getenv\(\s*\)")

_INTERPRETER_HEADS = frozenset([
    "node", "deno", "bun", "python", "python2", "python3", "ruby", "perl",
    "php", "irb", "osascript",
])

_VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_PRINTERS = frozenset(["echo", "printf", "printenv", "cat", "tee", "pbcopy", "curl"])


def _first_word(stmt):
    """(verb, _, end) — the verb this check is about.

    `head_of` alone is wrong here: it absorbs `env`, which is correct for
    `env FOO=1 cmd` and wrong for a bare `env`, whose whole point is that the
    wrapper IS the command. The raw first token is wrong the other way, because
    `sudo env printenv` runs `printenv`. `head_or_wrapper` is the walk that gets
    both — measured, `sudo env printenv` walked past this gate until it did.
    """
    name, end = head_or_wrapper(stmt)
    return name, -1, end


def _classify(stmt):
    """(verb, is_bare, has_redirect) for a statement, or (None, False, False).

    `is_bare` is the whole discrimination. `set` bare prints the environment and
    every function; `set -e` opens most shell scripts ever written. Reading the
    argument rather than the verb is the difference between a gate and a tax.
    """
    verb, _vs, ve = _first_word(stmt)
    if verb not in _DUMP:
        return None, False, False
    allowed_flags = _DUMP[verb]
    bare = True
    redirect = False
    skip_next = False
    for start, end in words(stmt):
        if end <= ve:
            continue
        tok = stmt[start:end]
        if skip_next:
            skip_next = False
            continue
        if _REDIRECT.match(tok):
            redirect = True
            # `> file` is two tokens, `>file` is one. Only the two-token form has
            # a following operand to skip.
            if not tok.strip("<>&|0123456789"):
                skip_next = True
            continue
        if tok in allowed_flags:
            continue
        bare = False
    return verb, bare, redirect


def run(payload, cfg):
    if payload.event != "PreToolUse" or payload.tool != "Bash":
        return None
    cmd = payload.command
    if not cmd or not cmd.strip():
        return None

    interpreted = _interpreter_dump(cmd, cfg)
    if interpreted:
        return interpreted

    for start, end in statement_spans(cmd):
        stmt = cmd[start:end]
        verb, bare, redirect = _classify(stmt)
        if verb is None:
            continue
        if not bare:
            # `env FOO=1 cmd` and `set -e` land here: not a dump.
            continue
        if redirect:
            return ("deny", _capture_message(verb, stmt),
                    {"verb": verb, "shape": "redirect"})
        rewritten = cmd[:start] + stmt.rstrip() + " | " + _MASK + cmd[end:]
        return ("rewrite", _rewrite_message(verb, rewritten),
                {"command": rewritten})
    return None


def _interpreter_dump(cmd, cfg):
    for stmt in statements(cmd):
        first, _s, _e = _first_word(stmt)
        if first not in _INTERPRETER_HEADS:
            continue
        m = _WHOLE_ENV.search(stmt)
        if not m:
            continue
        return ("deny", _whole_env_message(first, m.group(0)),
                {"verb": first, "expr": m.group(0)})
    return None


def _rewrite_message(verb, rewritten):
    return (
        "[%s] `%s` prints every environment variable's value, and this session's "
        "environment carries whatever the shell profile exported. The command was "
        "rewritten to print the NAMES with values masked; the pipeline after it is "
        "unchanged:\n\n    %s\n\n"
        "If a value is needed, it does not have to be seen: "
        "`keyless run -s <NAME> -- <your command>` puts it in the child process's "
        "environment and nowhere else."
        % (CHECK, verb, rewritten))


def _capture_message(verb, stmt):
    return (
        "[%s] `%s` here redirects the whole environment into a file or another "
        "program, which captures every value rather than inspecting the names. "
        "Matched: `%s`. Refused.\n\n"
        "To see what is set:\n"
        "    %s | %s\n"
        "To use a value without printing it:\n"
        "    keyless run -s <NAME> -- <the command you were going to run>\n\n"
        "An operator can disable this pack for a session with "
        "KEYLESS_HOOKS_DISABLE=1 in the settings file's `env` block."
        % (CHECK, verb, stmt.strip()[:100], verb, _MASK))


def _whole_env_message(binary, expr):
    return (
        "[%s] `%s` is being asked to print the whole environment object (`%s`), "
        "which serialises every value including credentials. Refused.\n\n"
        "For the names only:\n"
        "    env | %s\n"
        "For one value, without printing it:\n"
        "    keyless run -s <NAME> -- <the command you were going to run>\n\n"
        "Reading a single key — `process.env.FOO`, `os.environ.get(\"FOO\")` — is "
        "not blocked; only the whole-object form is."
        % (CHECK, binary, expr, _MASK))


# ── KL-ENVVAR: advisory ─────────────────────────────────────────────────────

def _is_secret_name(name, cfg):
    # An environment variable holding a credential is spelled in upper case. That
    # is not a style preference here, it is the discrimination the check rests on:
    # measured on the pack's own decision log, 6 of 9 organic KL-ENVVAR warns
    # fired on a lower-case `pat`, which was a PATTERN variable in a session doing
    # 167 `re.*` calls. A real token is `GITHUB_PAT` or `GH_PAT`.
    #
    # This is the same `pat` substring class that the original forensic scan had
    # to exclude to stop its counts inflating from 2,096 to 8,752. Dropping the
    # segment would fix `pat` alone; requiring upper case fixes the whole class,
    # including the next English word somebody adds to the list.
    #
    # The cost is a lower-case assignment of a genuine credential, which loses one
    # ADVISORY nudge and blocks nothing. That is the cheap direction.
    if name != name.upper():
        return False
    parts = [p for p in re.split(r"[_\-]+", name.lower()) if p]
    if any(p in cfg.secret_segments for p in parts):
        return True
    for a, b in cfg.secret_pairs:
        if a in parts and b in parts:
            return True
    return False


def run_named_var(payload, cfg):
    """Advisory. A single credential-named variable being printed.

    Advisory rather than blocking, deliberately and on the record: the trigger is
    a NAME shape, and a name shape is a guess. `echo $SSH_KEY_PATH` is a path and
    would be blocked by a gate built on this predicate. It ships as a nudge with
    its rows in the decision log, and it earns promotion on that data or it does
    not get promoted.
    """
    if payload.event != "PreToolUse" or payload.tool != "Bash":
        return None
    cmd = payload.command
    if not cmd:
        return None

    for stmt in statements(cmd):
        first, _s, ve = _first_word(stmt)
        if first not in _PRINTERS:
            continue
        if first == "printenv":
            # `printenv NAME` takes the name bare, with no `$`. Same act, and the
            # spelling with the sigil is the one everybody thinks of.
            for start, end in words(stmt):
                if end <= ve:
                    continue
                tok = stmt[start:end].strip("'\"")
                if tok.startswith("-"):
                    continue
                if _is_secret_name(tok, cfg):
                    return ("warn", _var_message(first, tok), {"var": tok})
        for m in _VAR_REF.finditer(stmt):
            name = m.group(1) or m.group(2)
            if _is_secret_name(name, cfg):
                return ("warn", _var_message(first, name), {"var": name})
    return None


def _var_message(printer, name):
    return (
        "[%s] `%s` is printing $%s, whose name marks it as a credential. The value "
        "lands in this transcript and in the scrollback. If the goal is to USE it "
        "rather than to see it, `keyless run -s %s -- <your command>` passes it to "
        "the child process and leaves it out of the output. If $%s is not actually "
        "a secret — a path, an identifier, a flag — take no action and do not "
        "mention this."
        % (CHECK_VAR, printer, name, name, name))
