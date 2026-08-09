"""KL-ASSIGN — a credential literal typed into a shell assignment.

    export ANTHROPIC_API_KEY=<literal>
    STRIPE_SECRET_KEY=<literal> ./deploy.sh
    env GITHUB_TOKEN=<literal> gh release create

Nothing else in this pack sees this shape. `KL-WRITE` rewrites a literal on its
way into a FILE and never reads a command. `KL-ENVVAR` warns when a
credential-NAMED variable is printed, which is the opposite direction — a value
that is already in the environment, on its way out. This is the one act where the
agent introduces the value itself, in command position, on the tool that runs
most often.

── the discrimination is the VALUE, never the NAME ─────────────────────────────
`export SECRET_KEY="$SECRET_KEY"` is the correct usage this pack asks people to
write, and a gate keyed on the variable's name refuses exactly the sessions doing
it right. `export FOO=<a live-looking key>` is the leak whatever it is called. So
the name is used for one thing — naming the variable back in the refusal — and
every verdict comes from `fingerprint`, the scanner that already licenses
KL-WRITE to rewrite a file unilaterally.

Three narrowings sit on top of it, because a false positive on `Bash` costs far
more than one on `Write`:

  *assignment position only.* A word matching `NAME=…` counts in the statement's
  assignment PREFIX or after a declaration verb. Past the head it is an argument
  and is ignored — `make BUILD=release`, `dd if=.env`, `jq '.name=="a.env"'`.

  *literal values only.* Every expansion is blanked before the scan, so a value
  built from `$VAR`, `${VAR}` or `$(cmd)` has nothing left to match. That single
  rule is what keeps `export PATH="$HOME/.local/bin:$PATH"`, `export
  TOKEN="$TOKEN"` and `export FOO=$(vault-get)` silent, with no special case for
  any of them.

  *no name-keyed match inside prose.* Every credential alphabet in `fingerprint`
  is whitespace-free, so where the literal carries whitespace the generic
  `NAME=<opaque>` rule is withheld and only a VENDOR shape is honoured. A
  sentence is not a credential, and a gate that denies a sentence is a gate that
  gets uninstalled.

── why deny, and why NOT rewrite ───────────────────────────────────────────────
The substitution KL-WRITE performs is wrong here, and wrong in the dangerous
direction. `export STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}` is a self-reference
that expands to nothing, and `STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}
./deploy.sh` would then run a deploy against production with an EMPTY
credential — the exact silent-empty failure this pack's own remediation text
warns about. A file is read before it is used; a command runs the instant the
rewrite lands, so there is no moment in which anyone notices.

── what this does not see ──────────────────────────────────────────────────────
A heredoc BODY. `cat > .env <<EOF` … `EOF` writes a credential through `Bash`
rather than through `Write`, and it is a real and separate surface — but a
heredoc body is text, the pack blanks it everywhere else for exactly that reason,
and the remediation for authoring a `.env` is not this message. It is published
as a survivor in the adversarial table rather than half-covered here.

`set -x` is not an assignment and is not judged. It is worth knowing that it
AMPLIFIES this leak: with tracing on, the shell echoes every later assignment,
including ones this hook already refused in their direct spelling.

A value below `fingerprint`'s own floors. Those floors are shared with KL-WRITE
and are not this check's to move: a vendor body shorter than its pattern's
minimum, a name-keyed value under 12 characters, a URL password under 8. So
`export GITHUB_TOKEN=ghp_SHORT` and `postgres://u:hunter2@h/d` are silent here
and are silent in a `Write` too — measured, not assumed. Lowering a floor buys
this check nothing and costs every other check its precision, so the right place
to argue about it is `fingerprint`, with the corpus in hand.
"""

import re

from .. import fingerprint
from ..shellview import (assignment_split, interpreter_payloads, is_wrapper,
                         statements, strip_heredocs, words)

CHECK = "KL-ASSIGN"

# Verbs after which every remaining word is a declaration rather than an
# argument, so `export A=1 B=2` yields two assignments and not one.
_DECLARE = frozenset(["export", "declare", "typeset", "local", "readonly"])

_REDIRECT = re.compile(r"^\d*(?:>>|>&|>\||&>>|&>|>|<<<|<<|<&|<)")

# Everything a shell would EXPAND. Blanked before the scan, because a value that
# is assembled at run time was never typed and cannot be in the transcript. The
# unterminated forms are matched too: `FOO=$(broken` is still not a literal.
_EXPANSION = re.compile(
    r"\$\([^)]*\)?|`[^`]*`?|\$\{[^}]*\}?|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?!$-]")

# The finding kinds `fingerprint` produces from the variable's NAME plus an
# opaque value, rather than from the value's own shape. Withheld inside prose.
_NAME_KEYED = frozenset(["named_credential"])


def _normalise(token):
    """A word as a command name: quotes, a leading backslash and a path removed."""
    name = token.strip("'\"")
    if name.startswith("\\"):
        name = name[1:]
    if "/" in name:
        name = name.rsplit("/", 1)[-1]
    return name


def assignments(stmt):
    """Every `NAME=value` word standing in an ASSIGNMENT position.

    Returns (name, raw_value) pairs with the value exactly as written. The walk
    is the whole precision of this check: the same token is an assignment before
    the statement's head and an argument after it, and only one of those two is
    a shell variable being set.

    The walk also decides whether a quote inside the NAME counts. After a
    declaration verb or a wrapper the word is an ARGUMENT and the shell removes
    the quotes before setting the variable, so `export SECRET''_KEY=<literal>`
    sets SECRET_KEY; in assignment-PREFIX position the same word is a command
    name and sets nothing. `assignment_split` carries the measurement.
    """
    out = []
    decl = False
    wrapped = False
    past_head = False
    skip_next = False
    for start, end in words(stmt):
        tok = stmt[start:end]
        if skip_next:
            skip_next = False
            continue
        if _REDIRECT.match(tok):
            # `> file` is two tokens and `>file` is one; only the first has an
            # operand to step over.
            if not tok.strip("<>&|0123456789"):
                skip_next = True
            continue
        pair = assignment_split(tok, declared=decl or wrapped)
        if pair is not None:
            if decl or not past_head:
                out.append(pair)
            continue
        if tok.startswith("-"):
            continue
        word = _normalise(tok)
        if not word:
            continue
        if not past_head and word in _DECLARE:
            decl = True
            continue
        if not past_head and is_wrapper(word):
            # `env FOO=1 cmd` puts the assignment AFTER the wrapper. Treating
            # `env` as the head would read `FOO=1` as its argument.
            #
            # It also moves the word out of assignment-PREFIX position and into
            # argument position, where the shell removes quotes from the NAME
            # before setting the variable — so `declared` goes on here for the
            # same reason it goes on after `export`.
            wrapped = True
            continue
        if decl:
            # `export FOO` — a name already set is being re-exported, no value.
            continue
        past_head = True
    return out


def literal_part(raw_value):
    """The part of a value that was actually SPELLED, expansions gone.

    Two steps, and each closes a different spelling. Blanking the expansions is
    what makes `export TOKEN=$(cat ~/.token)` silent without a rule naming
    `cat` or `$(`.

    Collapsing the quotes AND the backslashes is what makes `gh""p_<literal>`
    and `gh\\p_<literal>` — one word to the shell, several fragments to any
    tokenizer — scan as what they run as. Both marks are removed by the shell
    before the value exists, so neither is part of the value; leaving either in
    place is a bypass six characters long.
    """
    spelled = _EXPANSION.sub(" ", raw_value)
    return spelled.replace("'", "").replace('"', "").replace("\\", "")


def credential_findings(name, raw_value):
    """`fingerprint`'s verdict on one assignment. Public so a test can prove that
    a silent case is silent because of the VALUE and not because the walk that
    finds the assignment quietly stopped reaching it."""
    literal = literal_part(raw_value)
    if not literal.strip():
        return []
    found = fingerprint.scan("%s=%s" % (name, literal), limit=8)
    if not found:
        return found
    if any(c.isspace() for c in literal.strip()):
        return [f for f in found if f.kind not in _NAME_KEYED]
    return found


def run(payload, cfg):
    if payload.event != "PreToolUse" or payload.tool != "Bash":
        return None
    cmd = payload.command
    # An assignment needs an `=`. Most commands have none, and this check runs on
    # every Bash call in every session, so the cheapest possible exit comes first.
    if not cmd or "=" not in cmd:
        return None

    texts = [strip_heredocs(cmd)]
    texts.extend(interpreter_payloads(cmd, cfg.interpreters))

    names = []
    shapes = []
    for text in texts:
        for stmt in statements(text):
            for name, raw_value in assignments(stmt):
                for finding in credential_findings(name, raw_value):
                    if name not in names:
                        names.append(name)
                    if finding.kind not in shapes:
                        shapes.append(finding.kind)
    if not names:
        return None
    return ("deny", _message(names, shapes),
            {"vars": names[:8], "shapes": sorted(shapes)[:8]})


def _message(names, shapes):
    """The refusal. It carries variable NAMES and shape labels, never a value."""
    var = names[0]
    return (
        "[%s] A credential-shaped literal is being assigned to a shell variable "
        "(%s). Shape(s) matched: %s. Refused.\n\n"
        "Refusing does not un-print it: the value is already in this transcript, "
        "and no hook can remove it from one. What it still prevents is the value "
        "reaching the shell's history file, the process table, this command's "
        "child process, and anything that command writes or sends. If the "
        "credential is real, treat it as exposed and rotate it.\n\n"
        "To USE it without spelling it:\n\n"
        "    keyless run -s %s -- sh -c '<the command you were going to run>'\n\n"
        "Keep the body inside `sh -c` and SINGLE-QUOTE it. Two spellings look "
        "right and silently pass an EMPTY credential: `-- cmd \"$%s\"` is expanded "
        "by the CALLING shell, where the name is unset, and `-- cmd '$%s'` arrives "
        "as a literal because keyless does not expand its arguments. Only the "
        "inner shell expands from the environment.\n\n"
        "`keyless ls` names what it can resolve. If this value is not a "
        "credential — a fixture, a public identifier, a test vector — spell it so "
        "it is not credential-shaped. An operator can disable this pack for a "
        "session with KEYLESS_HOOKS_DISABLE=1 in the settings file's `env` block."
        % (CHECK, ", ".join(names[:4]), ", ".join(sorted(shapes)), var, var, var))
