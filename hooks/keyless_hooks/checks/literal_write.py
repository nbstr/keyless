"""KL-WRITE — a credential literal in a file being written.

This covers the widest hole there is: a plaintext credential typed straight into
a file, where every later gate can only report it after the fact.

── the instrument depends on the FILE, and that is the whole design ────────────
Substituting `${NAME}` for the literal is a repair only where the file's own
reader resolves it:

    STRIPE_KEY=sk_live_<a real key>   ->   STRIPE_KEY=${STRIPE_KEY}

In a `.env`, a shell script, a compose file or a CI job that is exactly right:
the write proceeds, the file does not carry the secret, and it is one
`keyless run` away from working.

In a source file it is not right at all. `const key = ${STRIPE_KEY}` is a syntax
error, and the remediation the message prints does not apply — the author is
handed a broken file instead of a secret, which is a different problem rather
than a smaller one. Replayed over real payloads, source files are the large
majority of what this check acts on, so the substitution was wrong far more often
than it was right. A check that is wrong most of the time gets uninstalled, and
then the writes it was right about flow too.

So there are three instruments, and `targets.py` decides which applies:

    the reader expands `${NAME}`, or the file is prose   ->  REWRITE
    it does not, and a VENDOR shape matched              ->  DENY
    it does not, and only a NAME-keyed rule matched      ->  WARN

**Why the vendor split decides the refusal.** A vendor prefix is proof on its
own; nothing but an AWS key is spelled `AKIA` plus sixteen upper alphanumerics.
The name-keyed rule is the one `fingerprint` documents as unable to separate a
literal from an identifier that merely looks opaque — `password`:
`E2E_LOGIN_PASSWORD` — so refusing on it would refuse ordinary source edits, and
rewriting on it would corrupt them. Telling the author is the only act that is
right whichever of the two it was.

**Why WARN and not a quieter rewrite.** The alternative for that class is to keep
substituting, which is what this check used to do everywhere: it removed the
secret AND broke the file, silently, including in a test fixture — where a decoy
turned into `${NAME}` is a control that no longer controls anything and still
looks like one.

── the allow list is the escape hatch, and it is now real ──────────────────────
The refusal names `allowed`, and consults it. It did not before: the message
offered a remedy that changed nothing, which is worse than offering none. An
allowed path downgrades a DENY to a WARN — never to silence, because a path being
an ordinary place for an example is not evidence that this particular value is
one.

`updatedInput` carries the substitution. Measured on Claude Code 2.1.223 it is
honoured with no `permissionDecision` field at all, so a rewrite grants nothing
and cannot suppress any other guard's opinion on the same call.
"""

from .. import fingerprint, secretpaths, targets

CHECK = "KL-WRITE"
CHECK_POST = "KL-SEEN"

_TOOLS = frozenset(["Write", "Edit", "NotebookEdit", "MultiEdit"])

_RUN_LINE = "    keyless run -s <NAME> -- <the command that reads this file>"


def _slot_key(addr):
    """The field NAME an address points at, whatever it is nested inside."""
    return addr if isinstance(addr, str) else addr[-1]


def _line_preserved(before, after):
    """A substitution replaces a VALUE. It never changes the shape of the file.

    The one structural claim a rewrite makes that nothing else here checks: the
    text that comes back has the same lines as the text that went in. A finding
    whose span ran past the end of its own line broke it — the substitution
    landed on the NEXT line's key and replaced a key NAME with a reference to a
    different variable, and the message called that a repair.

    `fingerprint` closes that class twice over. This is the third place, and it
    is the one that does not have to be right about WHY: whatever a future
    pattern does, if the rewrite would not preserve the line structure it is not
    a rewrite this check is allowed to make, and the call is refused instead.

    Refused, never dropped. A silent skip here would let the write through with
    the literal intact, which is the one direction this check must never fail in.
    """
    return before.count("\n") == after.count("\n")


def run(payload, cfg):
    if payload.event != "PreToolUse" or payload.tool not in _TOOLS:
        return None

    changes = {}
    kinds = []
    sites = []
    unsafe = []
    for addr, value in payload.text_slots():
        if _slot_key(addr) == "old_string":
            # `old_string` must keep matching what is on disk. Rewriting it makes
            # the edit fail to apply — a rewrite that breaks the caller is a deny
            # wearing a helpful face, and this check is not allowed to be one. It
            # is not scanned for a verdict either: the text is already in the file
            # and in the transcript, so refusing the edit that REMOVES it would
            # refuse the repair.
            continue
        new_value, findings = fingerprint.redact(value)
        if not findings:
            continue
        if not _line_preserved(value, new_value):
            unsafe.append(_slot_key(addr))
            continue
        changes[addr] = new_value
        kinds.extend(f.kind for f in findings)
        for f in findings:
            sites.append("%s line %d" % (_slot_key(addr),
                                         value.count("\n", 0, f.start) + 1))

    if unsafe:
        return ("deny", _unsound_message(payload.file_path, sorted(set(unsafe))),
                {"reason": "rewrite_would_not_preserve_lines",
                 "fields": sorted(set(unsafe))})

    if not changes:
        return None

    target = payload.file_path
    fields = sorted(set(_slot_key(a) for a in changes))
    shapes = sorted(set(kinds))

    if targets.rewritable(target):
        return ("rewrite", _rewrite_message(target, kinds, shapes, fields, sites),
                payload.rebuild(changes))

    detail = {"shapes": shapes[:8], "fields": fields,
              "reader": targets.reader_class(target)}
    if any(fingerprint.is_vendor(k) for k in kinds):
        allowed = secretpaths.is_allowed(target, payload.cwd, cfg)
        if allowed is None:
            return ("deny", _deny_message(target, kinds, shapes), detail)
        detail["allowed_by"] = allowed
        return ("warn", _allowed_message(target, shapes, allowed), detail)
    return ("warn", _warn_message(target, kinds, shapes), detail)


def _named(target):
    return target or "the file being written"


def _rewrite_message(target, kinds, shapes, fields, sites):
    return (
        "[%s] This write was CHANGED before it reached disk: %d credential-shaped "
        "literal(s) were replaced with `${NAME}` references. You did not ask for "
        "that substitution — read it before you build on it.\n\n"
        "  file      %s\n"
        "  shapes    %s\n"
        "  fields    %s\n"
        "  at        %s\n\n"
        "%s now holds `${NAME}` where those values were. To make it work, supply "
        "the value at run time instead of storing it:\n"
        "%s\n\n"
        "If a match was NOT a credential — a variable NAME, a fixture, a test "
        "vector, a public identifier — then the substitution is wrong and the file "
        "on disk is now wrong. Re-write it with that value spelled so it is not "
        "credential-shaped, or add its path to `allowed` in "
        "~/.config/keyless/hooks.json, which stops the substitution for that file."
        % (CHECK, len(kinds), _named(target), ", ".join(shapes), ", ".join(fields),
           "; ".join(sites) if sites else "unknown", _named(target), _RUN_LINE))


def _unsound_message(target, fields):
    return (
        "[%s] Refused. A credential-shaped literal is in this write, and the "
        "substitution that would remove it does not preserve the file's line "
        "structure — so applying it would edit text this check did not match.\n\n"
        "  file      %s\n"
        "  fields    %s\n\n"
        "Nothing was written and nothing was changed. This check may rewrite a "
        "VALUE; it may never reshape a file, and it refuses rather than guessing "
        "which of the two it is about to do.\n\n"
        "This is a defect in the scanner, not in your write. What to do now:\n\n"
        "  * if the value IS a credential, supply it at run time instead:\n"
        "%s\n"
        "  * if it is not, spell it so it is not credential-shaped, or add this "
        "path to `allowed` in ~/.config/keyless/hooks.json.\n\n"
        "Either way the scanner should be reported: this message means a pattern "
        "matched across a line boundary, which `fingerprint._one_line` exists to "
        "prevent."
        % (CHECK, _named(target), ", ".join(fields), _RUN_LINE))


def _deny_message(target, kinds, shapes):
    return (
        "[%s] %d credential-shaped literal(s) are being written into %s, and that "
        "file's reader does not expand `${NAME}`. Shape(s) matched: %s. Refused.\n\n"
        "This is refused rather than rewritten because both alternatives are "
        "wrong here. Letting it through puts the credential on disk. Substituting "
        "`${NAME}` puts a reference nothing resolves into a file that has to "
        "parse — you would get a broken file and be told it was repaired.\n\n"
        "Refusing does not un-print it: the value is already in this transcript. "
        "What it still prevents is the value reaching disk, the repository, and "
        "everything that reads the file. If the credential is real, treat it as "
        "exposed and rotate it.\n\n"
        "What to do instead:\n\n"
        "  * read it at run time from the environment, and supply it with\n"
        "%s\n"
        "  * or put the value in a file whose reader DOES expand a reference — a "
        "`.env`, a shell script, a compose or CI file — where this pack "
        "substitutes it for you and the write proceeds.\n\n"
        "`keyless ls` names what it can resolve. If this value is not a "
        "credential — a fixture, a decoy, a public identifier — spell it so it is "
        "not credential-shaped, or add this path to `allowed` in "
        "~/.config/keyless/hooks.json (or `.keyless-hooks.json` in the project), "
        "which downgrades this refusal to a note. An operator can disable the "
        "pack for a session with KEYLESS_HOOKS_DISABLE=1 in the settings file's "
        "`env` block."
        % (CHECK, len(kinds), _named(target), ", ".join(shapes), _RUN_LINE))


def _warn_message(target, kinds, shapes):
    return (
        "[%s] %d value(s) in this write are credential-shaped, and %s does not "
        "expand `${NAME}`. Shape(s) matched: %s. The write proceeded UNCHANGED.\n\n"
        "Nothing was substituted, deliberately: a reference nothing resolves would "
        "break a file that has to parse. Nothing was refused either, because this "
        "match came from the value's NAME rather than from its shape, and that "
        "rule cannot tell a literal from an identifier that merely looks opaque.\n\n"
        "So this is a question rather than a verdict. If it IS a credential, it is "
        "now on disk and in this transcript: remove it from the file, read it at "
        "run time instead, and rotate it. Supply it with\n"
        "%s\n\n"
        "If it is a variable name, a fixture or a public identifier, nothing needs "
        "doing."
        % (CHECK, len(kinds), _named(target), ", ".join(shapes), _RUN_LINE))


def _allowed_message(target, shapes, allowed):
    return (
        "[%s] A credential-shaped literal is being written into %s. Shape(s) "
        "matched: %s. This would be refused, and is not: the path matches "
        "`%s` in the `allowed` list, which marks it as a place examples live.\n\n"
        "The write proceeded unchanged. If this value is real rather than an "
        "example, the allow list is wrong for this file — remove the value, and "
        "rotate it."
        % (CHECK, _named(target), ", ".join(shapes), allowed))


def run_post(payload, cfg):
    """PostToolUse — a detector, never a censor.

    Measured on this harness: a PostToolUse hook cannot redact a tool result.
    `updatedOutput`, `toolResult`, `modifiedResult` and `displayContent` were all
    ignored and the model quoted the canary verbatim; only `additionalContext`
    reaches it. So there is no architecture in which this call removes a secret
    that has already been printed, and pretending otherwise would be the most
    dangerous kind of comfort.

    What it is good for: telling the reader, in the same turn, that the value it
    just received is now in the transcript and what to do about that.
    """
    if payload.event != "PostToolUse":
        return None
    response = payload.raw.get("tool_response") if isinstance(payload.raw, dict) else None
    text = _flatten(response)
    if not text:
        return None
    findings = fingerprint.scan(text, limit=8)
    if not findings:
        return None
    shapes = sorted(set(f.kind for f in findings))
    return ("warn",
            "[%s] The output just returned contains %d credential-shaped value(s) "
            "(%s). That text is now in this transcript and cannot be removed from "
            "it — a hook at this point can report the fact and nothing else. Do "
            "not copy the value into a file, a command, or a message. If the "
            "credential is real, treat it as exposed and rotate it. To use a "
            "secret without it passing through here: "
            "`keyless run -s <NAME> -- <your command>`."
            % (CHECK_POST, len(findings), ", ".join(shapes)),
            {"shapes": shapes})


def _flatten(response):
    """Tool output as text, whatever shape it arrived in.

    The Bash tool has shipped several shapes for this field — a bare string, and
    a dict under `stdout` / `output` / `content` — so a reader that bets on one
    key sees an empty result whenever the host changes, which reads exactly like
    a command that printed nothing.
    """
    if isinstance(response, str):
        return response[:200000]
    if isinstance(response, list):
        return "\n".join(_flatten(x) for x in response)[:200000]
    if isinstance(response, dict):
        parts = []
        for key in ("stdout", "stderr", "output", "content", "result", "text"):
            v = response.get(key)
            if isinstance(v, (str, list, dict)):
                parts.append(_flatten(v))
        return "\n".join(p for p in parts if p)[:200000]
    return ""
