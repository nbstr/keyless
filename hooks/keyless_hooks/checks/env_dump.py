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

from ..shellview import (head_or_wrapper, interpreter_payloads, statement_spans,
                         statements, words)

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

# Whole-environment expressions inside an interpreter's argument. Each excludes
# the single-key form: `process.env.FOO` is one variable and is the same act as
# `echo $FOO`, which is KL-ENVVAR's business, not this gate's.
#
# ⚠️ MATCHING ONE OF THESE IS NOT THE ACT. Naming the environment object is not
# reading it out loud, and this gate used to deny on the mention alone:
#
#     env = dict(os.environ)          denied
#     env = os.environ.copy()         denied
#     const env = { ...process.env }  denied
#
# All three are the standard way a program builds an environment for a CHILD
# process — the very thing `keyless run` does — and refusing them taxed ordinary
# work every day while protecting nothing, because nothing was printed. The
# dangerous act is the environment being PRINTED, SERIALISED or SENT.
#
# So the gate is aimed one step later now: see `_dump_position`.
_WHOLE_ENV = re.compile(
    r"process\.env(?!\s*[.\[])"
    r"|os\.environ(?!\s*[.\[(])"
    r"|os\.environ\.copy\(\)"
    r"|dict\(os\.environ\)"
    r"|\bENV\.(?:to_h|to_a|inspect|each)"
    r"|%ENV\b"
    # PHP. `php` has been in `_INTERPRETER_HEADS` from the start with no pattern
    # to match, so a PHP environment dump was never seen by this gate at all —
    # the head was recognised and then nothing looked for the act. `$_ENV` and a
    # bare `getenv()` are the whole-environment forms; `getenv("NAME")` is the
    # single-key read this gate deliberately ignores.
    r"|\$_ENV\b"
    r"|\bgetenv\(\s*\)"
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


# ── where a whole-environment expression is a DUMP, and where it is a copy ──
#
# Words that put their argument somewhere a human or another program can read it.
# The list is the OPEN side, and that is deliberate: the default below is still to
# deny, so a sink nobody enumerated is denied anyway. Only the narrow, provably
# inert shape — assignment, with the name never reaching a sink — is exempt.
_SINK_WORDS = frozenset([
    "print", "pprint", "puts", "pp", "echo", "warn", "die", "raise",
    "log", "table", "dump", "dumps", "stringify", "inspect", "format",
    "write", "writelines", "str", "repr", "send", "post", "put", "output",
    "stdout", "stderr", "console", "json", "util", "marshal", "pickle",
    "printf", "sprintf", "var_dump", "print_r", "json_encode", "var_export",
])

# Sinks that are a printer in ONE language and an ordinary variable name in every
# other, so they are scoped to the interpreter that makes them an act.
#
# Ruby's `p` is the case that forced this. It is a full printer — `p env` dumps
# the object — and a bare `p` is also the most ordinary variable name there is.
# Listed globally it would refuse `e = dict(os.environ); p = subprocess.run(c,
# env=e)`, an inert Python line, on the strength of a one-letter coincidence.
#
# Found by an adversarial sweep, not by review: moving this gate from the
# EXPRESSION to the ACT quietly reopened `ruby -e "env = ENV.to_h; p env"`, which
# the old mention-based rule had refused. A loosening has to be swept for what it
# lets out, and the sweep is the only thing that finds a hole this shape.
_SINKS_BY_LANGUAGE = {
    "ruby": frozenset(["p"]),
    "irb": frozenset(["p"]),
    "perl": frozenset(["say"]),
}

_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

# `NAME = <the expression>` or `NAME: <the expression>`, reading the text that
# ENDS at the expression.
#
# `:` is in there because the JavaScript idiom is not an assignment at all —
# `spawn(cmd, { env: { ...process.env } })` binds the copy to an option KEY, and
# a rule that only knew `=` refused exactly the call the whole exemption exists
# to allow. It is safe to admit only because `_has_sink` has already run on the
# same prefix: `console.log({ env: process.env })` and `res.json({ env: ... })`
# are refused by the sink standing in front of the key, not by this pattern.
#
# The lookbehind keeps `myenv` from being read as `env`. `(?![=~:])` keeps `==`,
# `=~` and `::` out — a comparison and a namespace are not a binding.
_COPY_LHS = re.compile(
    r"(?<![A-Za-z0-9_$])(?:const|let|var|my|our)?\s*"
    r"([A-Za-z_$][A-Za-z0-9_$]*)\s*[=:]\s*(?![=~:])[^;&\n]*$")

# Statement separators inside an interpreter's own code. Crude on purpose: a
# python/node payload is not parsed here, and a window that is too wide only ever
# makes this gate deny more.
_CODE_SEP = re.compile(r"[;\n]")


def _segments(code):
    """(start, end) of each `;`/newline-delimited chunk of an interpreter payload."""
    out = []
    pos = 0
    for m in _CODE_SEP.finditer(code):
        out.append((pos, m.start()))
        pos = m.end()
    out.append((pos, len(code)))
    return out


def _has_sink(text, lang=""):
    extra = _SINKS_BY_LANGUAGE.get(lang, frozenset())
    for m in _WORD.finditer(text):
        w = m.group(0).lower()
        if w in _SINK_WORDS or w in extra:
            return True
    return False


def _dump_position(code, lang=""):
    """The whole-environment expression that is actually DUMPED, or None.

    Three questions per match, in order, and the order is the design:

    1. **Is a sink already open around it?** `print(dict(os.environ))`,
       `json.dumps(os.environ)`, `console.log(process.env)`. Deny.
    2. **Is it the right-hand side of an assignment?** Then it is a COPY. Hold the
       name and keep looking; a copy is not an act.
    3. **Anything else.** Deny. The default stays deny, so a sink that nobody
       thought to enumerate costs nothing — it is only the enumerated *copy* shape
       that is let through.

    Then one hop of dataflow, and exactly one: a name that held a copy and later
    turns up beside a sink in the same payload is a dump written in two statements.
    `e = dict(os.environ); print(e)` is caught by this and by nothing else.

    Two hops (`e = dict(os.environ); f = e; print(f)`) is out of reach and stays
    out of reach; a hook sees one command string and holds no model of shell or
    interpreter state. That limit is cheap to accept because it was never the
    boundary: this gate is a guard against the shortcut, not against an agent that
    has decided to exfiltrate.
    """
    copies = []
    for seg_start, seg_end in _segments(code):
        seg = code[seg_start:seg_end]
        for m in _WHOLE_ENV.finditer(seg):
            if _has_sink(seg[:m.start()], lang):
                return m.group(0)
            lhs = _COPY_LHS.search(seg[:m.start()])
            if lhs is None:
                return m.group(0)
            copies.append((lhs.group(1), seg_end, m.group(0)))
    for name, after, expr in copies:
        pattern = re.compile(r"(?<![A-Za-z0-9_$])%s(?![A-Za-z0-9_$])"
                             % re.escape(name))
        for seg_start, seg_end in _segments(code):
            if seg_start < after:
                continue
            seg = code[seg_start:seg_end]
            if _has_sink(seg, lang) and pattern.search(seg):
                # Report the EXPRESSION, not the variable. The refusal has to
                # name the act the author will recognise; `e` names nothing.
                #
                # No backticks in here: the caller already wraps this whole
                # string in a pair, and nesting them renders as a broken span in
                # the one message an agent reads to decide what to do next.
                return "%s, held in %s" % (expr, name)
    return None


def _interpreter_dump(cmd, cfg):
    """Every view of the command, because an interpreter can be nested in a shell.

    `bash -c 'python3 -c "import os; print(os.environ)"'` was SILENT — the outer
    head is `bash`, which is not an interpreter this gate reads, and nothing
    looked inside the quoted argument. KL-VAULT and KL-ASSIGN have both re-scanned
    interpreter payloads from the start; this check simply never did, so the
    cheapest wrapper in existence walked past it.

    Measured on the pre-branch pack, so this is a hole being closed rather than
    one being introduced: `bash -c` and `sh -c` both got through before and after
    the gate was re-aimed.
    """
    texts = [cmd] + interpreter_payloads(cmd, cfg.interpreters)
    seen = set()
    for text in texts:
        if not text or text in seen:
            continue
        seen.add(text)
        for stmt in statements(text):
            first, _s, _e = _first_word(stmt)
            if first not in _INTERPRETER_HEADS:
                continue
            expr = _dump_position(stmt, first)
            if not expr:
                continue
            return ("deny", _whole_env_message(first, expr),
                    {"verb": first, "expr": expr})
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
        "not blocked, and neither is COPYING the environment for a child process: "
        "`env = dict(os.environ)`, `{ ...process.env }` and `ENV.to_h` all pass, "
        "including when the copy is handed straight to `subprocess.run(..., "
        "env=env)`. What is refused is the whole environment reaching something "
        "that prints, serialises or sends it."
        % (CHECK, binary, expr, _MASK))


# ── KL-ENVVAR: advisory ─────────────────────────────────────────────────────

def _is_secret_name(name, cfg):
    # An environment variable holding a credential is spelled in upper case. That
    # is not a style preference here, it is the discrimination the check rests on.
    # Before the case test, most of what this check warned on was a lower-case
    # `pat` — a PATTERN variable in a session writing regular expressions, not a
    # personal access token. A real token is `GITHUB_PAT` or `GH_PAT`.
    #
    # `pat` is one member of a class, and that is why the case test is the fix:
    # several entries in the secret-segment list are also ordinary lower-case
    # words. Dropping `pat` from the list fixes `pat` alone; requiring upper case
    # fixes the whole class, including the next English word somebody adds.
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
