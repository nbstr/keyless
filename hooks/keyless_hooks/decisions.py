"""The decision log. One row per fire, and never a value.

With no per-fire record, "this gate has never fired" and "this gate fires wrongly
every day" are the same data, and no observe-to-enforce promotion can ever be
justified. So every verdict writes a row — including `error`, because a check
that crashed is a check that was not there and that has to be visible.

What a row may carry: a check id, a verdict, a mode, a tool name, a file path, a
command's head word, and the NAME of a credential shape. What it may not carry,
under any code path: a secret value, an encoding of one, or a hash of one. The
hash is excluded on purpose — a hash of a low-entropy secret is a value with a
delay, and this pack is not allowed to create a read path of its own.

Writes are appended under an exclusive advisory lock and capped below PIPE_BUF,
because ~20 agent sessions append to this file concurrently and a torn row is
indistinguishable from a forged one.
"""

import json
import os
import time

__all__ = ["log", "path"]

_PIPE_BUF = 4096


def path():
    """The log path. Env override first so a test never writes to a real log."""
    override = os.environ.get("KEYLESS_HOOKS_STATE")
    if override:
        return os.path.join(override, "hook-decisions.jsonl")
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "keyless", "hook-decisions.jsonl")


def _row(check, verdict, mode, payload, detail):
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "check": check,
        "verdict": verdict,
        "mode": mode,
        "tool": (payload.tool or "")[:40] if payload else "",
        "session": (payload.session_id or "")[:64] if payload else "",
        "cwd": (payload.cwd or "")[:200] if payload else "",
    }
    if detail:
        row["detail"] = detail if isinstance(detail, dict) else {"note": str(detail)[:300]}
    return row


def log(check, verdict, mode, payload, detail=None):
    """Append one row. Never raises, never blocks, never fails a verdict.

    Telemetry that can suppress the decision it describes is worse than no
    telemetry, so every failure here is swallowed deliberately — the caller has
    already decided and this is the record, not the mechanism.
    """
    try:
        target = path()
        os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
        line = json.dumps(_row(check, verdict, mode, payload, detail),
                          ensure_ascii=False, separators=(",", ":"))
        blob = (line + "\n").encode("utf-8", "replace")
        if len(blob) > _PIPE_BUF:
            # Truncating the detail is better than interleaving with another
            # session's row: an oversized row corrupts its neighbours, and a row
            # with less detail corrupts nothing.
            trimmed = _row(check, verdict, mode, payload, None)
            trimmed["detail_truncated"] = True
            blob = (json.dumps(trimmed, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            _locked_write(fd, blob)
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001 - see docstring: telemetry never wins over a verdict
        pass


def _locked_write(fd, blob):
    """Append under a bounded exclusive lock, degrading to unlocked on timeout.

    A blocking lock with no deadline puts an unbounded wait on the one path whose
    contract is "must never stall a tool call". The deadline caps the pathological
    case far below the hook timeout; real contention costs a fraction of a
    millisecond.
    """
    try:
        import fcntl
    except ImportError:
        os.write(fd, blob)
        return
    deadline = time.time() + 0.5
    locked = False
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
            break
        except BlockingIOError:
            if time.time() > deadline:
                break
            time.sleep(0.002)
        except OSError:
            break
    try:
        os.write(fd, blob)
    finally:
        if locked:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
