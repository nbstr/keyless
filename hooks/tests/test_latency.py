"""Latency: the number that decides whether this stays installed.

A hook sits on the critical path of every tool call. A pack that adds noticeable
delay gets uninstalled, and then it protects nothing — so the per-call cost is a
correctness property, not a nice-to-have.

Two figures are reported, and they answer different questions:

    floor     an interpreter start plus this pack's imports, with a payload that
              matches nothing. This is what a session pays on EVERY call.
    worked    a payload that fires a check, including the file read and the
              names-only rendering. This is what it pays on the rare call.

Both are compared against a bare `python3 -c pass` measured in the SAME loop, so
the reported overhead is this pack's and not the machine's. Measured interleaved
rather than A-then-B, because machine load drifts.
"""

import os
import statistics
import subprocess
import sys
import time

import harness
from harness import Suite, bash, fixtures, read

HOOK = harness.HOOK
ROUNDS = 25


def _time_once(argv, payload):
    t0 = time.perf_counter()
    subprocess.run(argv, input=payload, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, env=_env())
    return time.perf_counter() - t0


def _env():
    e = dict(os.environ)
    e["KEYLESS_HOOKS_STATE"] = harness._state_dir()
    e["KEYLESS_HOOKS_CONFIG"] = os.path.join(e["KEYLESS_HOOKS_STATE"], "absent.json")
    return e


def measure():
    import json
    root = fixtures()
    cases = {
        "baseline (python3 -c pass)": ([sys.executable, "-c", "pass"], b""),
        "floor: unmatched Bash": ([sys.executable, HOOK],
                                  json.dumps(bash("git status --short", cwd=root)).encode()),
        "floor: unmatched Write": ([sys.executable, HOOK], json.dumps({
            "hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/a.ts", "content": "export const x = 1;\n" * 200},
            "cwd": root}).encode()),
        "worked: Bash deny": ([sys.executable, HOOK],
                              json.dumps(bash("cat .env", cwd=root)).encode()),
        "worked: Read rewrite": ([sys.executable, HOOK],
                                 json.dumps(read(os.path.join(root, ".env"))).encode()),
        "worked: 100KB Write scan": ([sys.executable, HOOK], json.dumps({
            "hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/big.md",
                           "content": ("lorem ipsum dolor sit amet " * 3800)},
            "cwd": root}).encode()),
    }
    samples = {k: [] for k in cases}
    # Interleaved: one round of every case, ROUNDS times.
    for _ in range(ROUNDS):
        for label, (argv, payload) in cases.items():
            samples[label].append(_time_once(argv, payload))

    base = statistics.median(samples["baseline (python3 -c pass)"])
    print("")
    print("  %-28s %9s %9s %9s" % ("case", "median", "p90", "over base"))
    print("  " + "-" * 60)
    results = {}
    for label in cases:
        xs = sorted(samples[label])
        med = statistics.median(xs)
        p90 = xs[int(len(xs) * 0.9) - 1]
        results[label] = med
        over = "" if label.startswith("baseline") else "+%.1f ms" % ((med - base) * 1000)
        print("  %-28s %7.1f ms %7.1f ms %9s" % (label, med * 1000, p90 * 1000, over))
    print("")
    return results, base


def run():
    s = Suite("latency")
    results, base = measure()

    # Shape assertions, never a wall-clock second count: an absolute threshold
    # measures the machine. What matters is that the pack's own work is small
    # beside the interpreter start every hook already pays.
    floor = results["floor: unmatched Bash"]
    s.check("floor is within 2.5x a bare interpreter", floor < base * 2.5, True)

    worked = results["worked: Bash deny"]
    s.check("a firing check costs under 2x the floor", worked < floor * 2.0, True)

    big = results["worked: 100KB Write scan"]
    small = results["floor: unmatched Write"]
    s.check("100KB scan stays within 3x a 4KB one", big < small * 3.0, True)

    return s


if __name__ == "__main__":
    ok = run().report()
    harness.cleanup()
    raise SystemExit(0 if ok else 1)
