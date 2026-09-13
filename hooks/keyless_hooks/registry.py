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
    from .checks import (dest_write, env_dump, file_read, heredoc_write,
                         literal_write, shell_assign, switch, vault_cli)

    return [
        # id                event          tier      handler
        ("KL-FILE",   "PreToolUse", BLOCK,   file_read.run),
        ("KL-VAULT",  "PreToolUse", BLOCK,   vault_cli.run),
        ("KL-ENV",    "PreToolUse", BLOCK,   env_dump.run),
        ("KL-ENVVAR", "PreToolUse", WARN,    env_dump.run_named_var),
        # BLOCK rather than OBSERVE, against this file's own rollout rung. The
        # rung exists to gather rows when a predicate is unproven; this one is
        # `fingerprint` — already deployed under KL-WRITE, and narrowed further
        # here to literal values in assignment position. It was replayed over a
        # large body of real agent and interactive shell commands before it was
        # registered, and it denied nothing that was not a credential assignment.
        ("KL-ASSIGN", "PreToolUse", BLOCK,   shell_assign.run),
        # The same predicate again, against the one shape that is a FILE WRITE
        # spelled as a command. It ships at BLOCK for KL-ASSIGN's reason and not
        # by exemption from the rung above: `fingerprint` is already deployed and
        # already licensed to rewrite a file unilaterally, and the only new
        # judgement — does this here-document redirect into a file, and what does
        # that file's reader do with a reference — was replayed over a large body
        # of real commands before it was registered.
        ("KL-HEREDOC", "PreToolUse", BLOCK,  heredoc_write.run),
        # BLOCK rather than REWRITE, and the tier is the decision. This check
        # substitutes `${NAME}` only where the destination's reader resolves it;
        # everywhere else the substitution is a syntax error wearing the face of a
        # repair, so the check needs the licence to refuse instead. A REWRITE-tier
        # check returning "deny" is degraded to advice by the engine, which is the
        # correct treatment of a registry error and the wrong outcome here.
        ("KL-WRITE",  "PreToolUse", BLOCK,   literal_write.run),
        # BLOCK rather than OBSERVE, and the rung is not skipped — it is
        # satisfied in advance, the way KL-ASSIGN's row above was.
        #
        # OBSERVE exists to gather rows when a predicate is unproven. This
        # predicate is `secretpaths.is_protected`, the pack's oldest classifier,
        # already licensed to DENY on Read, Grep and Bash under KL-FILE. Nothing
        # new is judged here; one more surface is told the same answer, and a
        # pack that refuses to READ a file while allowing it to be overwritten
        # wholesale was incoherent in a way an operator could not have guessed.
        #
        # It was replayed against a body of real write-tool calls before it was
        # registered, and every destination it refused was a genuine credential
        # file. The rate is a rounding error against ordinary editing because the
        # predicate names files, not text: an agent that edits source all day
        # never meets it.
        #
        # The failure it prevents is not the edit. It is the plaintext copy the
        # host takes on the way through, into ~/.claude/file-history/, which no
        # later gate can redact and which outlives the file itself.
        ("KL-DEST",   "PreToolUse", BLOCK,   dest_write.run),
        # BLOCK rather than OBSERVE, for two reasons, and the second is the one
        # no replay could supply.
        #
        # It was replayed before it was registered, over a large body of real
        # agent tool calls on the machine that wrote it — sessions that had
        # spent weeks configuring this very tool. It refused about one call in
        # four thousand. A third of those were an agent rewriting config.json
        # or hooks.json, which is the act this row exists to take away. The
        # rest were one-line scripts handed the config path only to read it;
        # a script that names the file is refused because it COULD write it,
        # and the refusal points that reader at the doors that are not refused.
        #
        # And OBSERVE cannot do its job here. OBSERVE records what a call WOULD have done
        # and lets the pack keep running, which only works when the call
        # under test leaves the pack able to record the next one. A switch
        # that succeeds does the opposite: the first agent session that
        # disables the pack, or rewrites its config, silences every check —
        # this one included — for every call after it. A record-only rollout
        # would show one row for the switch that got flipped and nothing at
        # all for what ran once it was off, which is exactly the state an
        # operator promoting the check from its rows would be unable to tell
        # apart from "nothing happened since".
        ("KL-SWITCH", "PreToolUse", BLOCK,   switch.run),
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
