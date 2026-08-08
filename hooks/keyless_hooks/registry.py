"""Every check, its id, its event, and its tier. One table, no discovery.

A check that is not in this table does not run. That is deliberate: an estate
where checks are found by scanning a directory has no answer to "is this gate
enforcing?" that does not involve reading every file.

Tiers:

    BLOCK    may deny a tool call
    REWRITE  may substitute tool input; can never deny
    WARN     may add context; can never deny and never rewrite
    OBSERVE  a BLOCK check held in record-only mode while it earns promotion

`OBSERVE` is the rollout rung. A new gate ships there, its rows are read, and it
is promoted deliberately — not because it looked right in a test.
"""

BLOCK = "block"
REWRITE = "rewrite"
WARN = "warn"
OBSERVE = "observe"

__all__ = ["BLOCK", "REWRITE", "WARN", "OBSERVE", "for_event", "all_checks"]


def _table():
    # Imported inside the function so a broken check module cannot stop the
    # engine from loading the others: the import cost is paid once per process
    # either way, and the failure mode differs.
    from .checks import env_dump, file_read, literal_write, vault_cli

    return [
        # id                event          tier      handler
        ("KL-FILE",   "PreToolUse", BLOCK,   file_read.run),
        ("KL-VAULT",  "PreToolUse", BLOCK,   vault_cli.run),
        ("KL-ENV",    "PreToolUse", BLOCK,   env_dump.run),
        ("KL-ENVVAR", "PreToolUse", WARN,    env_dump.run_named_var),
        ("KL-WRITE",  "PreToolUse", REWRITE, literal_write.run),
        ("KL-SEEN",   "PostToolUse", WARN,   literal_write.run_post),
    ]


_CACHE = None


def all_checks():
    global _CACHE
    if _CACHE is None:
        _CACHE = _table()
    return _CACHE


def for_event(event):
    return [row for row in all_checks() if row[1] == event]
