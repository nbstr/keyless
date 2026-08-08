"""One process, every check, one verdict.

Two hooks registered on the same event run in PARALLEL and cannot see each
other's output, so they cannot agree on a single answer — and where the host
merges their JSON, one object can replace the other. The shape that matters is
warn+deny: an advisory from one script and a block from another, on the same
call, where keeping the advisory downgrades the block to a note and the action
runs. One engine makes that class unexpressible.

── the invariant that shapes every line: this never emits `allow` ──────────────
`permissionDecision: "allow"` suppresses the host's own permission prompt AND
overrides other guards' opinions on the same call. A secrets hook that emits it
would silently disarm whatever else the user has registered on PreToolUse.

Measured on Claude Code 2.1.223: `updatedInput` is honoured with NO
`permissionDecision` field at all. A Read was redirected to a redacted copy and
the model quoted the redacted text; the paired control with the hook removed
quoted the canary. So a rewrite costs nothing and grants nothing — this pack
rewrites, denies, or stays silent, and never approves.

── failure direction ──────────────────────────────────────────────────────────
Exit 0 with JSON is the only signalling style. Exit 2 blocks and every other
non-zero exit does not, so a crash fails OPEN. That is chosen: failing closed on
a crash blocks every tool call in every session, which is far worse than one
guard missing. The defence against crashing is coercion at the entry point plus
the per-check isolation below — never a blanket try/except, which converts a
crash into a silent skip.
"""

import json
import os
import sys

from . import decisions
from .config import load as load_config
from .payload import parse
from .registry import BLOCK, OBSERVE, REWRITE, WARN, for_event

# Session-wide record-only mode. The operator's lever, set out of band in the
# settings file's `env` block — an agent cannot set its own environment, which is
# what makes it an operator lever and not an override the agent can reach for.
OBSERVE_ENV = "KEYLESS_HOOKS_OBSERVE"
DISABLE_ENV = "KEYLESS_HOOKS_DISABLE"

_HSO_EVENTS = frozenset(["PreToolUse"])


def _emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))


def evaluate(payload, cfg, observe=False):
    """Run every check for this event.

    Returns (deny_reason, updated_input, advisories). Pure with respect to
    stdout: it decides, the caller emits, which is what lets the battery assert
    on verdicts without parsing a process's output.
    """
    mode = "observe" if observe else "enforce"
    advisories = []
    updated = {}

    for check_id, _event, tier, run in for_event(payload.event):
        try:
            result = run(payload, cfg)
        except Exception:  # noqa: BLE001 - paired with a record, see module docstring
            # `traceback` is imported HERE, not at module scope. It pulls
            # _colorize -> dataclasses -> inspect and cost 8.1 ms of the pack's
            # 16 ms floor, measured with -X importtime — paid on every tool call
            # in every session, for a path that is reachable only when a check
            # is already broken.
            import traceback
            decisions.log(check_id, "error", mode, payload,
                          detail={"trace": traceback.format_exc(limit=3)[-280:]})
            continue

        if not result:
            continue
        verdict, message, extra = result
        if not verdict or not message:
            continue

        if verdict == "deny" and tier in (BLOCK, OBSERVE):
            recording = observe or tier == OBSERVE
            decisions.log(check_id, "deny", "observe" if recording else mode,
                          payload, detail=extra)
            if recording:
                advisories.append("[observe] %s would block this call.\n\n%s"
                                  % (check_id, message))
                continue
            # First deny returns NOW, above every remaining check, so nothing
            # with a side effect runs on a call that is being refused. Obeying a
            # block must never cost the user anything.
            return message, None, advisories

        if verdict == "rewrite" and tier in (REWRITE, BLOCK, OBSERVE):
            # A check licensed to deny is licensed to do the gentler thing. The
            # reverse is not true, which is why a WARN check returning "rewrite"
            # falls through to the advisory branch below.
            if not isinstance(extra, dict):
                continue
            recording = observe or tier == OBSERVE
            decisions.log(check_id, "rewrite", "observe" if recording else mode,
                          payload, detail={"fields": sorted(extra.keys())})
            if recording:
                advisories.append("[observe] %s would rewrite this call.\n\n%s"
                                  % (check_id, message))
                continue
            updated.update(extra)
            advisories.append(message)
            continue

        if verdict in ("warn", "deny"):
            # A non-BLOCK check returning "deny" is a registry error, not a
            # licence to block. Degrade it to advice rather than honour it.
            decisions.log(check_id, "warn", mode, payload, detail=extra)
            advisories.append(message)

    return None, (updated or None), advisories


def _deny_payload(event, reason):
    if event in _HSO_EVENTS:
        return {"hookSpecificOutput": {
            "hookEventName": event,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }}
    return {"decision": "block", "reason": reason}


def main(argv=None):
    if os.environ.get(DISABLE_ENV) == "1":
        return 0

    payload = parse(sys.stdin.read())
    if payload is None or not payload.event:
        return 0

    cfg = load_config(payload.cwd)
    if not cfg.enabled:
        return 0

    observe = os.environ.get(OBSERVE_ENV) == "1" or cfg.observe
    reason, updated, advisories = evaluate(payload, cfg, observe=observe)

    if reason is not None:
        _emit(_deny_payload(payload.event, reason))
        return 0

    if updated or advisories:
        hso = {"hookEventName": payload.event}
        if updated:
            merged = dict(payload.tool_input)
            merged.update(updated)
            hso["updatedInput"] = merged
        if advisories:
            hso["additionalContext"] = "\n\n".join(advisories)
        _emit({"hookSpecificOutput": hso})
    return 0


def cli():
    """Entry point. Any escape from `main` exits 0 — a hook that crashes must
    still let the tool call through, and stdout must carry nothing partial."""
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001 - the fail-open boundary itself
        sys.exit(0)
