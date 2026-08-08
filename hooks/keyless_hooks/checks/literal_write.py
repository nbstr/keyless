"""KL-WRITE — a credential literal in a file being written becomes a reference.

This is the one check that is a rewrite by design rather than by opportunity, and
it covers the widest hole there is: a plaintext credential typed straight into a
file, where every later gate can only report it after the fact.

Blocking the write would be the wrong instrument. The agent is doing legitimate
work — authoring a `.env`, a compose file, a deploy script — and refusing it
costs a turn and teaches nothing, because the second attempt writes the same
literal in a different file. Substituting it costs nothing:

    STRIPE_KEY=sk_live_DECOYNOTAREALKEY   ->   STRIPE_KEY=${STRIPE_KEY}

The write proceeds. The file simply does not carry the secret, and `${NAME}` is
the form the file's own reader already resolves, so the corrected file is one
`keyless run` away from working rather than being a dead end.

`updatedInput` carries the substitution. Measured on Claude Code 2.1.223 it is
honoured with no `permissionDecision` field at all, so this check grants nothing
and cannot suppress any other guard's opinion on the same call.
"""

from .. import fingerprint

CHECK = "KL-WRITE"
CHECK_POST = "KL-SEEN"

_TOOLS = frozenset(["Write", "Edit", "NotebookEdit", "MultiEdit"])


def run(payload, cfg):
    if payload.event != "PreToolUse" or payload.tool not in _TOOLS:
        return None

    updated = {}
    kinds = []
    for key, value in payload.text_fields():
        if key == "old_string":
            # `old_string` must keep matching what is on disk. Rewriting it makes
            # the edit fail to apply — a rewrite that breaks the caller is a deny
            # wearing a helpful face, and this check is not allowed to be one.
            continue
        new_value, findings = fingerprint.redact(value)
        if not findings:
            continue
        updated[key] = new_value
        kinds.extend(f.kind for f in findings)

    if not updated:
        return None

    return ("rewrite", _message(payload, kinds, sorted(updated)),
            dict(updated, **{}))


def _message(payload, kinds, fields):
    shapes = sorted(set(kinds))
    target = payload.file_path or "the file being written"
    return (
        "[%s] %d credential-shaped literal(s) in this write were replaced with "
        "`${NAME}` references before it reached disk. Shapes matched: %s. Fields "
        "rewritten: %s. The write itself proceeded — %s does not contain the "
        "literal.\n\n"
        "To make the file work, supply the value at run time instead of storing "
        "it:\n"
        "    keyless run -s <NAME> -- <the command that reads this file>\n\n"
        "If a match was not a credential — a fixture, a test vector, a public "
        "identifier — the substitution is wrong and the correct fix is to re-write "
        "the file with that value spelled so it is not credential-shaped, or to "
        "add its file to `allowed` in ~/.config/keyless/hooks.json."
        % (CHECK, len(kinds), ", ".join(shapes), ", ".join(fields), target))


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
