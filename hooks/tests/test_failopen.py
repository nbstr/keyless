"""Fail-open: every malformed, hostile or broken input ALLOWS.

Exit 2 blocks and every other non-zero exit does not, so a hook that crashes
already fails open — but only if it crashes *cleanly*. The failures this suite
exists to catch are the ones where it does not: a partial JSON write that the
host parses as a decision, a coercion gap that raises after the emit, a broken
config that disables the pack silently, a state directory that cannot be written
and takes the verdict down with it.

This is not a theoretical worry. A hook layer audited before this pack was
written had almost every script crashing on VALID JSON that carried an unexpected
field type, and the scripts holding the destructive guards were among them. There
existed payload shapes for which those guards simply did not exist, and nothing
said so.
"""

import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile

import harness
from harness import Suite, bash, drive, fixtures

HOOKS_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HOSTILE_RAW = [
    ("empty stdin", b""),
    ("whitespace only", b"   \n  "),
    ("truncated json", b'{"hook_event_name": "PreToo'),
    ("bare list", b"[1,2,3]"),
    ("bare string", b'"hello"'),
    ("bare int", b"42"),
    ("bare null", b"null"),
    ("bare true", b"true"),
    ("empty object", b"{}"),
    ("nul bytes", b'{"hook_event_name":"PreToolUse\x00","tool_name":"Bash"}'),
    ("invalid utf-8", b'{"hook_event_name":"PreToolUse","tool_input":{"command":"\xff\xfe"}}'),
    ("ansi escapes", b'{"hook_event_name":"PreToolUse","tool_name":"Bash",'
                     b'"tool_input":{"command":"\\u001b[31mcat .env\\u001b[0m"}}'),
    ("rtl + zero width", '{"hook_event_name":"PreToolUse","tool_name":"Bash",'
                         '"tool_input":{"command":"cat​‮.env"}}'.encode("utf-8")),
    ("duplicate keys", b'{"hook_event_name":"PreToolUse","hook_event_name":"Stop"}'),
    ("deep nesting", (b'{"a":' * 400) + b"1" + (b"}" * 400)),
    ("very long input", b'{"hook_event_name":"PreToolUse","tool_name":"Bash",'
                        b'"tool_input":{"command":"' + b"a" * 200000 + b'"}}'),
]

WRONG_TYPES = [
    ("tool_input is a list", {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                              "tool_input": [1, 2, 3]}),
    ("tool_input is a string", {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                "tool_input": "cat .env"}),
    ("tool_input is null", {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                            "tool_input": None}),
    ("command is a list", {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_input": {"command": ["cat", ".env"]}}),
    ("command is an int", {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_input": {"command": 7}}),
    ("command is a dict", {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                           "tool_input": {"command": {"a": 1}}}),
    ("file_path is a list", {"hook_event_name": "PreToolUse", "tool_name": "Read",
                             "tool_input": {"file_path": ["/etc/passwd"]}}),
    ("file_path is an int", {"hook_event_name": "PreToolUse", "tool_name": "Read",
                             "tool_input": {"file_path": 3}}),
    ("tool_name is a list", {"hook_event_name": "PreToolUse", "tool_name": ["Bash"],
                             "tool_input": {"command": "cat .env"}}),
    ("tool_name is null", {"hook_event_name": "PreToolUse", "tool_name": None,
                           "tool_input": {"command": "cat .env"}}),
    ("session_id is a list", {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                              "tool_input": {"command": "ls"}, "session_id": [1]}),
    ("cwd is an int", {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": "ls"}, "cwd": 5}),
    ("content is a list", {"hook_event_name": "PreToolUse", "tool_name": "Write",
                           "tool_input": {"file_path": "/tmp/x", "content": [1, 2]}}),
    # A bulk edit's text lives in a nested LIST, which is new surface for the
    # coercion boundary: every one of these reaches a walk that indexes into
    # structures the sender controls.
    ("edits is a string", {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                           "tool_input": {"file_path": "/tmp/x.conf", "edits": "nope"}}),
    ("edits is a dict", {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                         "tool_input": {"file_path": "/tmp/x.conf", "edits": {"a": 1}}}),
    ("an edit entry is a list", {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                                 "tool_input": {"file_path": "/tmp/x.conf",
                                                "edits": [["old", "new"]]}}),
    ("an edit entry is a string", {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                                   "tool_input": {"file_path": "/tmp/x.conf",
                                                  "edits": ["just a string"]}}),
    ("an edit entry is null", {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                               "tool_input": {"file_path": "/tmp/x.conf",
                                              "edits": [None, {"new_string": "ok"}]}}),
    ("new_string is a dict", {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                              "tool_input": {"file_path": "/tmp/x.conf",
                                             "edits": [{"new_string": {"a": 1}}]}}),
    ("edits is deeply nested", {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                                "tool_input": {"file_path": "/tmp/x.conf",
                                               "edits": [{"new_string": "x",
                                                          "old_string": [[[[1]]]]}]}}),
    ("event missing", {"tool_name": "Bash", "tool_input": {"command": "cat .env"}}),
    ("unknown event", {"hook_event_name": "SomethingNew", "tool_name": "Bash",
                       "tool_input": {"command": "cat .env"}}),
]


def run():
    s = Suite("fail-open")

    for label, raw in HOSTILE_RAW:
        v = drive(None, raw_stdin=raw)
        s.check("hostile exits 0: %s" % label, v.exit_code, 0)
        s.check("hostile never malformed: %s" % label, v.kind == "malformed", False)

    for label, payload in WRONG_TYPES:
        v = drive(payload)
        s.check("wrong type exits 0: %s" % label, v.exit_code, 0)
        s.check("wrong type never malformed: %s" % label, v.kind == "malformed", False)

    # ── exit 0 is NOT evidence that nothing broke ───────────────────────────
    #
    # The engine isolates each check: a handler that raises is recorded and the
    # others still run, so the process exits 0 and prints nothing — exactly what
    # a correctly silent verdict looks like. Every case above would therefore
    # stay green against a check that crashed on every single one of them.
    #
    # The decision log is the only surface that tells the two apart. It carries a
    # row per verdict, and `error` is one of them.
    import json as _json
    import tempfile as _tempfile
    state = _tempfile.mkdtemp(prefix="keyless-failopen-errors-")
    for _label, payload in WRONG_TYPES:
        drive(payload, state=state)
    for _label, raw in HOSTILE_RAW:
        drive(None, raw_stdin=raw, state=state)
    rows = []
    log = os.path.join(state, "hook-decisions.jsonl")
    if os.path.exists(log):
        with open(log) as fh:
            for line in fh:
                try:
                    rows.append(_json.loads(line))
                except ValueError:
                    pass
    s.check("no check CRASHED on a hostile payload",
            sorted(set(r.get("check", "?") for r in rows
                       if r.get("verdict") == "error")), [])
    # ...and the reader is not looking at an empty file, which would satisfy the
    # assertion above whatever happened. At least one of those payloads is a real
    # verdict, so the log must have rows in it.
    s.check("the decision log was actually written and read", bool(rows), True)

    # A wrongly-typed field must not DISABLE a guard whose own field is fine.
    # Without coercion, `cwd` as an int reaches os.path.isabs(), the check
    # raises, the engine records an error row and moves on — and the call the
    # guard exists to stop goes through, silently. Exiting 0 is not the property
    # that matters here; still denying is.
    root0 = fixtures()
    for label, extra in (("cwd is an int", {"cwd": 5}),
                         ("cwd is a list", {"cwd": ["/tmp"]}),
                         ("session_id is a dict", {"session_id": {"a": 1}}),
                         ("permission_mode is an int", {"permission_mode": 3})):
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                   "tool_input": {"command": "cat %s/.env" % root0}}
        payload.update(extra)
        v = drive(payload)
        s.check("a bad sibling field does not disarm the gate: %s" % label,
                v.kind, "deny")

    # ── a raised exception inside one check must not take the others down ────
    s.check("a raising check is isolated", *_raising_check())

    # ── a broken environment ────────────────────────────────────────────────
    #
    # A missing HOME is spelled as a missing NAME INSIDE A DIRECTORY THAT
    # EXISTS, and that is load-bearing rather than tidy. Spelled as a top-level
    # path — "/nonexistent-home-for-keyless-tests" — this loop wrote an empty
    # directory tree into the REPOSITORY ROOT and took a cargo-mutants baseline
    # down twice.
    #
    # The mechanism is in CPython, not here.
    # `importlib._bootstrap_external.SourceLoader.set_data` creates the parents
    # of a bytecode cache with
    #
    #     while parent and not _path_isdir(parent):
    #         parent, part = _path_split(parent)
    #
    # and `_path_split("/x")` returns `("", "x")` — the front is EMPTY, never
    # "/". So when the whole absolute prefix is missing the loop runs off the
    # top, exits with `parent == ""`, and rebuilds each level with
    # `_path_join("", part)`, which is RELATIVE. `os.mkdir` then creates it
    # under the current working directory. Give the path a parent that exists
    # and the loop stops there, so every mkdir stays absolute.
    #
    # It needs Apple's /usr/bin/python3, whose `cache_from_source` redirects
    # caches into `$HOME/Library/Caches/com.apple.python/`. A Homebrew
    # interpreter writes `__pycache__` beside the source and never reads HOME,
    # which is why this fired for some people and not others, and why it kept
    # being misattributed.
    #
    # The tree holds directories and NO FILES, because the .pyc write goes to
    # the absolute path and fails. Git tracks files, so git cannot see it at
    # all — a .gitignore entry would not have helped.
    missing_home = os.path.join(tempfile.gettempdir(), "keyless-tests-missing-home")
    missing_tmpdir = os.path.join(tempfile.gettempdir(), "keyless-tests-missing-tmpdir")

    root = fixtures()
    try:
        for label, env in (
                ("HOME unset", {"HOME": ""}),
                ("HOME missing dir", {"HOME": missing_home}),
                ("TMPDIR missing", {"TMPDIR": missing_tmpdir}),
                ("PATH unset", {"PATH": ""}),
                ("broken locale", {"LC_ALL": "not-a-locale", "LANG": "not-a-locale"})):
            v = drive(bash("cat .env", cwd=root), env=env)
            s.check("broken env exits 0: %s" % label, v.exit_code, 0)
            # The guard must still be a guard. A broken environment is not a
            # reason to stop protecting; it is a reason to keep protecting
            # without state.
            s.check("broken env still denies: %s" % label, v.kind, "deny")
    finally:
        # Whatever the interpreter decided to create under those two names is
        # build output. It is now somewhere it can be removed.
        shutil.rmtree(missing_home, ignore_errors=True)
        shutil.rmtree(missing_tmpdir, ignore_errors=True)

    # ── an unwritable state directory ───────────────────────────────────────
    ro = tempfile.mkdtemp(prefix="keyless-ro-")
    try:
        os.chmod(ro, 0o500)
        v = drive(bash("cat .env", cwd=root), state=ro)
        s.check("unwritable state exits 0", v.exit_code, 0)
        s.check("unwritable state still denies", v.kind, "deny")
    finally:
        os.chmod(ro, 0o700)
        shutil.rmtree(ro, ignore_errors=True)

    # ── a corrupt config ────────────────────────────────────────────────────
    bad = tempfile.mkdtemp(prefix="keyless-badcfg-")
    try:
        cfg = os.path.join(bad, "hooks.json")
        with open(cfg, "w") as fh:
            fh.write("{ this is not json ][")
        v = drive(bash("cat .env", cwd=root), env={"KEYLESS_HOOKS_CONFIG": cfg})
        s.check("corrupt config exits 0", v.exit_code, 0)
        s.check("corrupt config keeps the defaults", v.kind, "deny")

        with open(cfg, "w") as fh:
            json.dump({"protected": "not-a-list", "vault_verbs": [["op"], 3, None]}, fh)
        v = drive(bash("cat .env", cwd=root), env={"KEYLESS_HOOKS_CONFIG": cfg})
        s.check("wrong-typed config keeps the defaults", v.kind, "deny")

        with open(cfg, "w") as fh:
            json.dump({"vault_verbs": [["op", "([unclosed", "x", None]]}, fh)
        v = drive(bash("op read op://a/b", cwd=root), env={"KEYLESS_HOOKS_CONFIG": cfg})
        s.check("uncompilable pattern exits 0", v.exit_code, 0)
    finally:
        shutil.rmtree(bad, ignore_errors=True)

    # ── a physically broken installation ────────────────────────────────────
    s.check("a truncated module fails open", *_broken_tree())

    # ── cost: the curve, not a wall-clock second count ──────────────────────
    growth = _cost_growth()
    # Both directions, because one of them alone passes vacuously. A growth
    # figure that collapsed toward 1x would clear the ceiling while proving
    # nothing at all, and that is what a broken instrument reads as.
    s.check("the 4x workload costs measurably more", growth > 2.0, True)
    s.check("cost stays sub-quadratic", growth < 8.0, True)

    return s


def _raising_check():
    """Drive `evaluate` with a check that raises. The others must still run."""
    sys.path.insert(0, HOOKS_ROOT)
    from keyless_hooks import engine, registry
    from keyless_hooks.config import load
    from keyless_hooks.payload import parse

    def boom(payload, cfg):
        raise RuntimeError("deliberate")

    original = registry._CACHE
    try:
        registry._CACHE = [("KL-BOOM", "PreToolUse", registry.BLOCK, boom)] + list(
            registry.all_checks())
        p = parse(json.dumps(bash("cat .env")))
        reason, updated, advisories = engine.evaluate(p, load(p.cwd))
        return (reason is not None and "KL-FILE" in reason), True
    finally:
        registry._CACHE = original


def _broken_tree():
    """Truncate a check module in a COPY of the tree and drive the real entry point.

    This is the only test that proves the fail-open boundary rather than assuming
    it: an ImportError at module scope is the shape a bad release actually takes,
    and it must reach the host as exit 0 with no output.
    """
    tmp = tempfile.mkdtemp(prefix="keyless-broken-")
    try:
        dst = os.path.join(tmp, "hooks")
        shutil.copytree(HOOKS_ROOT, dst)
        with open(os.path.join(dst, "keyless_hooks", "checks", "vault_cli.py"), "w") as fh:
            fh.write("this is not python (")
        proc = subprocess.run([sys.executable, os.path.join(dst, "keyless_hook.py")],
                              input=json.dumps(bash("cat .env")).encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return (proc.returncode == 0 and not proc.stdout.strip()), True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _cost_growth():
    """How the pack's own work grows when the command it reads gets 4x longer.

    Returned as a multiple, so the two ends of the property are named by the
    figure itself: a linear scan lands near 4x and a quadratic one near 16x. The
    ceiling sits at 8x, a doubling clear of each.

    ⚠️ THE INSTRUMENT IS CPU TIME, NOT WALL CLOCK, AND THAT IS THE WHOLE POINT.

    An absolute second count measures the machine rather than the code, which is
    why this was never written as one. A wall-clock RATIO is the same fault
    wearing a disguise: it holds two separately-taken samples, so on a machine
    with other work on it the figure reports how evenly those two moments were
    scheduled and not how the algorithm grows. The smaller sample swings hardest,
    because a stall of a given length is a larger share of it — so an unchanged
    scan reads well past 6x under ordinary contention, and no ceiling is both
    quiet there and still able to tell 4x from 16x. That is not a threshold that
    needs raising; it is the wrong instrument.

    CPU time cannot be stretched that way. A process that loses the processor
    accrues none of it, so oversubscription that multiplies the wall clock several
    times over moves this figure by a few percent.

    Two further rules, both of which `test_latency` learned first: the MINIMUM
    across rounds is the closest estimate of what the work really costs, because
    noise only ever adds; and the fixed cost of starting an interpreter is
    subtracted, because it belongs to neither term of a growth figure and only
    dilutes it toward 1x.
    """
    unit = "export A=1 && cat notes.txt && grep -n 'x' file && "
    cases = (("floor", bash("ls")),
             ("1x", bash(unit * 200)),
             ("4x", bash(unit * 800)))
    best = {}
    # Interleaved rather than case-after-case, because a machine's load drifts
    # across the rounds and case-after-case hands each case a different era.
    for _ in range(3):
        for label, command in cases:
            spent = _child_cpu(command)
            if label not in best or spent < best[label]:
                best[label] = spent
    one = best["1x"] - best["floor"]
    four = best["4x"] - best["floor"]
    # A runaway at both sizes divides to a NaN, and every comparison against a NaN
    # is false — including the ceiling, which would read as a pass. Say infinite.
    if four == float("inf"):
        return float("inf")
    # A non-positive figure means the instrument broke, not the pack. Hand back a
    # growth the lower bound refuses rather than dividing by it.
    return four / one if one > 0 else 0.0


def _child_cpu(command):
    """User plus system CPU seconds the hook's own process spends on one call.

    `RUSAGE_CHILDREN` accumulates across every child this process has reaped, so
    a delta around one call is that call's alone only while nothing else is being
    reaped beside it. `drive` starts the hook and waits for it, on this thread.

    A call that never returns inside the harness timeout has by definition blown
    past any ceiling a growth figure could carry, and reporting it as an infinite
    cost keeps that a failed ASSERTION rather than a traceback out of the middle
    of the battery. A genuinely quadratic scan reaches the timeout before it
    reaches the ceiling, so this is the path that shape actually takes.
    """
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        drive(command)
    except subprocess.TimeoutExpired:
        return float("inf")
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return ((after.ru_utime - before.ru_utime)
            + (after.ru_stime - before.ru_stime))


if __name__ == "__main__":
    ok = run().report()
    harness.cleanup()
    raise SystemExit(0 if ok else 1)
