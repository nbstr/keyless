"""Latency: the number that decides whether this stays installed.

A hook sits on the critical path of every tool call. A pack that adds noticeable
delay gets uninstalled, and then it protects nothing — so the per-call cost is a
correctness property, not a nice-to-have.

Two figures are reported, and they answer different questions:

    floor     an interpreter start plus this pack's imports, with a payload that
              matches nothing. This is what a session pays on EVERY call.
    worked    a payload that fires a check, including the file read and the
              names-only rendering. This is what it pays on the rare call.

TWO baselines are measured, and the difference between them is the whole of what
this file learned the hard way:

    python3 -c pass              what a session pays. The honest user-facing
                                 number, and the one the table leads with.
    python3 -c "import json, re" what this PACK costs. `re` and `json` are the
                                 stdlib it cannot exist without, and whether the
                                 interpreter's own `site` already imported them
                                 moves the first number by 3x with no change to
                                 any code here.

Everything is measured interleaved in the SAME loop rather than A-then-B, because
machine load drifts.

The assertions read a DELTA in milliseconds, against the second baseline. They
deliberately read neither a ratio — an interpreter start sits inside both of its
terms, so a ratio reports the host and calls it a regression — nor a delta over a
bare interpreter, which charges this pack for the host's startup policy. `run`
carries the measurements behind both of those.
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
        # The SECOND baseline, and the one the assertions read. See `run`.
        "baseline + json + re": ([sys.executable, "-c", "import json, re"], b""),
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

    med = {label: statistics.median(xs) for label, xs in samples.items()}
    low = {label: min(xs) for label, xs in samples.items()}
    base = med["baseline (python3 -c pass)"]
    deps = med["baseline + json + re"]
    print("")
    print("  %-28s %9s %9s %10s %10s"
          % ("case", "median", "p90", "over base", "over deps"))
    print("  " + "-" * 72)
    for label in cases:
        xs = sorted(samples[label])
        p90 = xs[int(len(xs) * 0.9) - 1]
        m = med[label]
        if label.startswith("baseline (python3"):
            over = over_deps = ""
        elif label.startswith("baseline"):
            over = "+%.1f ms" % ((m - base) * 1000)
            over_deps = ""
        else:
            over = "+%.1f ms" % ((m - base) * 1000)
            over_deps = "+%.1f ms" % ((m - deps) * 1000)
        print("  %-28s %7.1f ms %7.1f ms %10s %10s"
              % (label, m * 1000, p90 * 1000, over, over_deps))
    print("")
    return med, low


# A macOS-shaped sample and a Linux-shaped one, in seconds, holding the PACK's
# cost fixed and moving only the interpreter start. These are the two hosts, not
# two runs: CPython starts several times faster on Linux, and that is the entire
# difference between them.
_HOSTS = {
    "macos":  {"base": 0.0159, "floor": 0.0216, "small": 0.0213, "big": 0.0487},
    # base a quarter of macOS; every pack cost above it identical to the row above.
    "linux":  {"base": 0.0040, "floor": 0.0097, "small": 0.0094, "big": 0.0368},
}


# (interpreter, bare, deps, hook) in milliseconds. Real medians from one machine,
# 31 interleaved rounds each, taken while the machine was deliberately loaded —
# the pack byte-identical in all three. The spread across these rows is the entire
# reason the assertions read a delta over `import json, re` rather than over a
# bare interpreter: 3.9's `site` imports neither, so the pack pays for both, while
# 3.13's already has them and the baseline pays instead.
_INTERPRETERS = [
    ("3.9",  30.5, 38.9, 51.7),
    ("3.13", 26.7, 27.7, 37.5),
    ("3.14", 26.0, 28.6, 35.6),
]


def _host_control(s):
    """Prove the assertion shape, not just today's numbers on today's machine.

    This suite was red on Linux across every Python from 3.6 to 3.13 while the
    pack was behaving identically on both hosts, and that cannot be reproduced by
    running it here — a macOS box has no way to start CPython at Linux speed. So
    the discrimination is asserted as ARITHMETIC over two host-shaped samples in
    which the pack's own cost is held EQUAL by construction.

    Two directions, and both are needed. A control that only showed the ratio
    failing would still be green if the delta form were broken too.
    """
    for host, r in _HOSTS.items():
        s.check("control: %s pack floor cost is the same +5.7 ms" % host,
                round((r["floor"] - r["base"]) * 1000, 1), 5.7)
        s.check("control: the delta assertion passes on %s" % host,
                (r["floor"] - r["base"]) * 1000 < 25.0, True)
        s.check("control: the scan delta assertion passes on %s" % host,
                (r["big"] - r["small"]) * 1000 < 60.0, True)

    # And the shape that was replaced. Both old assertions read the SAME pack
    # cost differently on the two hosts; only one of them goes red outright, and
    # saying which is the difference between a checked fact and a story.
    mac, lin = _HOSTS["macos"], _HOSTS["linux"]

    # The scan ratio is the one that definitively fails. 2.3x becomes 3.9x on an
    # unchanged pack, against a 3.0 limit.
    s.check("control: the old scan ratio passed on macOS",
            mac["big"] < mac["small"] * 3.0, True)
    s.check("control: the old scan ratio FAILED on Linux",
            lin["big"] < lin["small"] * 3.0, False)

    # The floor ratio is MARGINAL rather than certainly red, and that is worse
    # rather than better: an identical +5.7 ms is reported as 1.4x on one host and
    # 2.4x on the other, a hair inside a 2.5 limit. Whether it goes red is decided
    # by the runner's disk and page cache, which is the definition of a flake.
    s.check("control: the old floor ratio reads 5.7 ms as under 1.5x on macOS",
            mac["floor"] / mac["base"] < 1.5, True)
    s.check("control: the same 5.7 ms reads as over 2.3x on Linux",
            lin["floor"] / lin["base"] > 2.3, True)
    s.check("control: the delta assertion reads both hosts identically",
            round((mac["floor"] - mac["base"]) * 1000, 1)
            == round((lin["floor"] - lin["base"]) * 1000, 1), True)

    # ── and why the delta is taken over the pack's DEPENDENCIES ──────────────
    #
    # Real medians, one machine, 31 interleaved rounds, three interpreters. The
    # pack is byte-identical in all three; only the interpreter changes.
    for name, bare, deps, hook in _INTERPRETERS:
        s.check("control: %s over a bare interpreter is inside a 2x spread" % name,
                6.0 < (hook - bare) < 25.0, True)
        s.check("control: %s over its deps clears the threshold" % name,
                (hook - deps) < 25.0, True)

    # The claim the second baseline rests on, asserted rather than asserted-about:
    # over a BARE interpreter the same pack reads more than twice as expensive on
    # one interpreter as on another, and over its DEPENDENCIES that spread shrinks.
    # If it ever stops shrinking, the second baseline has stopped earning its place.
    bare_spread = (max(h - b for _n, b, _d, h in _INTERPRETERS)
                   / min(h - b for _n, b, _d, h in _INTERPRETERS))
    deps_spread = (max(h - d for _n, _b, d, h in _INTERPRETERS)
                   / min(h - d for _n, _b, d, h in _INTERPRETERS))
    s.check("control: a bare baseline spreads the same pack over 2x",
            bare_spread > 2.0, True)
    s.check("control: the deps baseline narrows that spread",
            deps_spread < bare_spread, True)


class _Controls(object):
    """The arithmetic half of this suite, with no timing in it.

    ⚠️ THIS EXISTS BECAUSE `mutate.py` DRIVES `run.py --fast`, WHICH OMITS THE
    TIMING LAYER ENTIRELY. Before it did, no mutation of this file could ever be
    caught — the whole module was skipped, so a mutation was applied, the suite
    ran without it, and the result was reported as a gate nothing tests. Measured:
    a mutation that broke the two-host control ESCAPED with the suite green.

    The controls are pure arithmetic over recorded samples and cost nothing, so
    they run on every invocation including the fast one. Only the part that spends
    seconds measuring is skipped.
    """

    __name__ = "test_latency_controls"

    @staticmethod
    def run():
        s = Suite("latency-controls")
        _host_control(s)
        return s


CONTROLS = _Controls()


def run():
    s = Suite("latency")
    med, low = measure()

    # ⚠️ THREE RULES, EACH LEARNED FROM A FAILURE THIS SUITE ACTUALLY HAD.
    #
    # 1. ASSERT ON A DELTA, NEVER ON A RATIO.
    #
    # A ratio looks like the machine-independent choice and is the opposite of
    # one, because the interpreter start sits inside BOTH of its terms and is a
    # property of the operating system rather than of this pack. Linux starts
    # CPython roughly four times faster than macOS, so the SAME pack cost divided
    # by a much smaller start reads as a much larger multiple — and this suite was
    # red on Linux on every Python from 3.6 to 3.13 while the pack behaved
    # identically. `_host_control` carries that arithmetic.
    #
    # 2. TAKE THE DELTA OVER THE PACK'S DEPENDENCIES, NOT OVER A BARE INTERPRETER.
    #
    # Same machine, same pack, same payload, three interpreters: the floor is
    # +5.7 ms over `python3 -c pass` on 3.13 and +19.4 ms on 3.9. Nothing about
    # the pack changed — 3.13's `site` imports `re` and `json` at startup so the
    # BASELINE paid for them, and 3.9's does not so the pack paid instead. There
    # is no single number over `-c pass` that is both meaningful at +5.7 and quiet
    # at +19.4. `re` and `json` are stdlib this pack cannot exist without, so
    # charging them to it is charging it for the host's startup policy. The list
    # is FIXED and short: anything a regression drags in beyond those two is still
    # fully visible, which is what the `traceback → dataclasses → inspect`
    # regression was.
    #
    # 3. ASSERT ON THE MINIMUM. REPORT THE MEDIAN.
    #
    # Noise only ever ADDS time, so across 25 interleaved rounds the minimum is
    # the closest estimate of what the work really costs and the median is what a
    # user really waits. They are different questions and this file needs both.
    #
    # The old `a firing check costs under 2x the floor` read medians, and the two
    # "worked" cases are the only ones that touch the filesystem. Measured with
    # the machine deliberately saturated — 5 consecutive runs — that assertion
    # failed 4 times: the worked MEDIAN moved between 30 ms and 200 ms while the
    # floor sat at 24 ms, because I/O contention inflates a file read and a file
    # write and does not inflate an import. In the same runs the two CPU-bound
    # assertions never moved (5.6–6.4 ms against 25, 27.7–30.6 ms against 60).
    #
    # On minima, under that same saturation, the worked cases sit +1.3 ms and
    # +4.6 ms above the floor. That is the pack's own work, which is what this
    # assertion was always trying to say.
    #
    # The thresholds are set from the one regression this suite has had — a
    # module-scope `traceback` import worth +8.1 ms — with room for a slow runner.
    deps = low["baseline + json + re"]
    floor = low["floor: unmatched Bash"]

    floor_cost = (floor - deps) * 1000
    s.check("the pack's own per-call cost stays under 25 ms over its deps",
            floor_cost < 25.0, True)

    worked_cost = (low["worked: Bash deny"] - floor) * 1000
    s.check("a firing check costs under 25 ms more than a silent one",
            worked_cost < 25.0, True)

    read_cost = (low["worked: Read rewrite"] - floor) * 1000
    s.check("a Read rewrite costs under 25 ms more than a silent call",
            read_cost < 25.0, True)

    scan_cost = (low["worked: 100KB Write scan"]
                 - low["floor: unmatched Write"]) * 1000
    s.check("scanning 100KB costs under 60 ms more than 4KB",
            scan_cost < 60.0, True)

    # ⚠️ What no absolute number here can catch, said out loud rather than papered
    # over: an 8 ms creep. 8 ms of regression on 3.14 lands inside 3.9's healthy
    # band, so a threshold tight enough to see it on one interpreter is red on
    # another. Catching that needs a RECORDED baseline per interpreter and
    # operating system — committed, compared against, refreshed as a deliberate
    # act. That is a stored artefact and a policy about who may update it, not an
    # assertion, which is why it is named here instead of faked with a constant.

    print("  minima — pack %.1f ms (< 25), firing %.1f ms (< 25), "
          "read %.1f ms (< 25), scan %.1f ms (< 60)\n"
          % (floor_cost, worked_cost, read_cost, scan_cost))
    return s


if __name__ == "__main__":
    ok = CONTROLS.run().report()
    ok = run().report() and ok
    harness.cleanup()
    raise SystemExit(0 if ok else 1)
