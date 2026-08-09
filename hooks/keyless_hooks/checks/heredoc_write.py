"""KL-HEREDOC — a credential literal written into a file through a here-document.

    cat > .env <<EOF
    API_KEY=<a real key>
    EOF

This is the `KL-WRITE` act performed through `Bash`, and until now nothing in the
pack saw it. `KL-WRITE` reads a write tool's payload and never reads a command.
`KL-ASSIGN` reads a command and blanks every here-document body before it looks,
because a body is text and reading it would fire on prose ABOUT commands. So the
one shape that is a file write spelled as a command fell between them, and it was
published as an adversarial survivor rather than half-covered.

── why the bodies are blanked, and why reading one here is not a reversal ──────
`shellview.strip_heredocs` exists for ACT detection: *is this a command, or a
mention of one*. A runbook written through a heredoc contains the words `cat
.env`, and a trigger reading the raw text refuses the runbook. That blanking
stays exactly as it was — this check does not unblank anything, and every other
check still sees a blanked body.

What it does instead is read the body through `shellview.heredocs()`, which walks
the SAME spans `strip_heredocs` blanks. Content scanning is not act detection: the
body of a redirected heredoc is not text about a command, it IS the bytes of the
file being written, and scanning it is the same question `KL-WRITE` asks of
`content`. Sharing one walk is what keeps "the bodies one check may read" and
"the bodies every other check must not read" from becoming two different sets.

── deny, never rewrite ─────────────────────────────────────────────────────────
`KL-WRITE` can substitute because it rewrites a file's CONTENT and the file is
read later. A command runs the instant the rewrite lands, and the substitution is
not even stable here: inside `<<'EOF'` a `${NAME}` reaches the file literally,
while inside `<<EOF` the shell expands it first — from an environment where the
name is usually unset — so the same rewrite writes a reference in one spelling
and an EMPTY value in the other, with nobody looking. That is the silent-empty
failure this pack's own remediation warns about, and it is `KL-ASSIGN`'s reason
for refusing rather than substituting.

── the tiers are `KL-WRITE`'s, with the gentlest rung removed ──────────────────
`targets.py` decides what the destination file's reader does with a reference, and
`fingerprint` decides whether the shape alone proves a credential:

    the reader expands `${NAME}`, or the file is prose   ->  DENY (rewrite is
                                                               unavailable here)
    it does not, and a VENDOR shape matched              ->  DENY
    it does not, and only a NAME-keyed rule matched      ->  WARN

The first row is where the two checks diverge, and the divergence is the whole
remediation: through `Write` the pack can repair a `.env` for you, and through
`Bash` it cannot — so it refuses and says which tool to use instead.

── what this does not see ──────────────────────────────────────────────────────
A heredoc that is NOT redirected into a file — `psql <<EOF`, `python3 <<EOF`,
`kubectl apply -f -`. The body still carries the literal into a process's stdin,
so it is a real leak, but the destination is not a file and the remediation
differs; it is a WARN here rather than a refusal, because the body of a heredoc
fed to an interpreter is a program or a query and refusing one on a name-keyed
match would refuse ordinary work.

A body reaching a file through a PIPE — `cat <<EOF | tee f` — names its
destination in a command rather than in a redirect. It is published as a
survivor: the operand belongs to another program, and resolving it would mean
modelling what every filter in a pipeline does with its arguments.
"""

import re

from .. import fingerprint, secretpaths, targets
from ..shellview import heredocs, words

CHECK = "KL-HEREDOC"

# The operator that opens a here-document, so it is not read as a redirect by the
# pattern below. `<<` and `<<-` both open one; `<<<` is a here-STRING and carries
# its text inline, where every other check already sees it.
_OPEN = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

# A token that redirects STDOUT, with the operand glued on or not: `>`, `>>`,
# `>f`, `1>`, `1>>f`. The descriptor is restricted to an absent one or `1` on
# purpose — `2> err.log` names where the errors go, not where the body goes, and
# reading it as the destination classifies the write by the wrong file. `>&` and
# `&>` duplicate a descriptor and name no file at all.
#
# The lookahead excludes `>` as well as `&` and `|`, so a malformed `>>&1` cannot
# be rescued by backtracking to a single `>` and handing back `>&1` as a path.
_REDIRECT_TOKEN = re.compile(r"^1?>>?(?![&|>])")


def _destination(opener):
    """The file the heredoc's own line redirects into, or "".

    Read off the opener LINE rather than the whole command: a here-document is
    opened and redirected in one breath — `cat > f <<EOF`, `cat <<EOF > f` — and
    a later line's redirect belongs to a later command.

    Tokenised rather than pattern-matched, because both mistakes a pattern makes
    here are silent. `words()` groups a quoted span into ONE word, so a `>` sitting
    inside an argument is never read as an operator and a destination spelled
    `> "my file.conf"` comes back whole instead of stopping at the space. The
    heredoc operator is blanked first so its own `<` cannot be tokenised into the
    operand of a redirect standing next to it.
    """
    view = _OPEN.sub(lambda m: " " * len(m.group(0)), opener)
    spans = words(view)
    for index, (start, end) in enumerate(spans):
        token = view[start:end]
        match = _REDIRECT_TOKEN.match(token)
        if not match:
            continue
        glued = token[match.end():]
        if glued:
            return _unquote(glued)
        if index + 1 < len(spans):
            nxt = spans[index + 1]
            return _unquote(view[nxt[0]:nxt[1]])
        return ""
    return ""


def _unquote(token):
    """A shell word as the path it names. Quotes are removed by the shell."""
    return token.replace("'", "").replace('"', "").replace("\\", "").strip()


def run(payload, cfg):
    if payload.event != "PreToolUse" or payload.tool != "Bash":
        return None
    cmd = payload.command
    # Every command without `<<` exits here. This runs on every Bash call in
    # every session, so the cheapest possible rejection comes first.
    if not cmd or "<<" not in cmd:
        return None

    worst = None
    for doc in heredocs(cmd):
        if not doc.body.strip():
            continue
        findings = fingerprint.scan(doc.body, limit=8)
        if not findings:
            continue
        verdict = _judge(doc, findings, payload, cfg)
        if verdict is None:
            continue
        # A deny outranks a warn, so a command holding both is refused. The first
        # deny is kept rather than the last: it names the earliest heredoc, which
        # is the one a reader will look at first.
        if verdict[0] == "deny":
            return verdict
        if worst is None:
            worst = verdict
    return worst


def _judge(doc, findings, payload, cfg):
    shapes = sorted(set(f.kind for f in findings))
    target = _destination(doc.opener)
    if not target:
        return ("warn", _stdin_message(shapes), {"shapes": shapes[:8],
                                                 "destination": "stdin"})
    detail = {"shapes": shapes[:8], "reader": targets.reader_class(target)}
    if not targets.rewritable(target) and not any(
            fingerprint.is_vendor(f.kind) for f in findings):
        return ("warn", _opaque_message(target, shapes), detail)
    allowed = secretpaths.is_allowed(target, payload.cwd, cfg)
    if allowed is not None:
        detail["allowed_by"] = allowed
        return ("warn", _allowed_message(target, shapes, allowed), detail)
    return ("deny", _deny_message(target, shapes), detail)


def _deny_message(target, shapes):
    return (
        "[%s] A credential-shaped literal is being written into %s through a "
        "here-document. Shape(s) matched: %s. Refused.\n\n"
        "Refusing does not un-print it: the value is already in this transcript, "
        "and no hook can remove it from one. What it still prevents is the value "
        "reaching disk, the repository, and everything that reads that file. If "
        "the credential is real, treat it as exposed and rotate it.\n\n"
        "The answer here is NOT to pass the value in another way — it is that the "
        "file should not hold the literal at all:\n\n"
        "  * write the file with a REFERENCE where the secret was, and supply the "
        "value when the file is read:\n\n"
        "        keyless run -s <NAME> -- <the command that reads this file>\n\n"
        "  * if you want that reference written for you, use the `Write` tool "
        "instead of a here-document. This pack substitutes the literal there and "
        "lets the write through; it cannot do that to a command, because a "
        "command runs the moment it is rewritten and `${NAME}` inside an "
        "unquoted here-document expands to an EMPTY value before it reaches "
        "the file.\n\n"
        "`keyless ls` names what it can resolve. If this value is not a "
        "credential — a fixture, a decoy, a public identifier — spell it so it is "
        "not credential-shaped, or add this path to `allowed` in "
        "~/.config/keyless/hooks.json (or `.keyless-hooks.json` in the project), "
        "which downgrades this refusal to a note. An operator can disable the "
        "pack for a session with KEYLESS_HOOKS_DISABLE=1 in the settings file's "
        "`env` block."
        % (CHECK, target, ", ".join(shapes)))


def _opaque_message(target, shapes):
    return (
        "[%s] A credential-shaped value is being written into %s through a "
        "here-document. Shape(s) matched: %s. The command was NOT refused.\n\n"
        "That match came from the value's NAME rather than from its own shape, "
        "and that rule cannot tell a literal from an identifier that merely looks "
        "opaque — so this is a question rather than a verdict. If it IS a "
        "credential it is now on disk and in this transcript: remove it from the "
        "file, read it at run time instead, and rotate it."
        % (CHECK, target, ", ".join(shapes)))


def _stdin_message(shapes):
    return (
        "[%s] A here-document carrying a credential-shaped literal is being fed "
        "to a command's standard input. Shape(s) matched: %s. Nothing was "
        "refused: the body is not being redirected into a file, so it is a "
        "program, a query or a manifest rather than a file's content, and the "
        "destination is not something a hook can name.\n\n"
        "It is still a leak. The value is in this transcript, in that process's "
        "input, and in whatever the process does with it. Supply it from the "
        "environment instead:\n\n"
        "    keyless run -s <NAME> -- sh -c '<the command you were going to run>'\n\n"
        "Keep the body inside `sh -c` and SINGLE-QUOTE it: only the inner shell "
        "expands from the environment."
        % (CHECK, ", ".join(shapes)))


def _allowed_message(target, shapes, allowed):
    return (
        "[%s] A credential-shaped literal is being written into %s through a "
        "here-document. Shape(s) matched: %s. This would be refused, and is not: "
        "the path matches `%s` in the `allowed` list, which marks it as a place "
        "examples live.\n\n"
        "If this value is real rather than an example, the allow list is wrong "
        "for this file — remove the value, and rotate it."
        % (CHECK, target, ", ".join(shapes), allowed))
