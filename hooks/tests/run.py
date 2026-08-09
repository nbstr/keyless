#!/usr/bin/env python3
"""Run the whole battery. Exit 0 only when every layer is green.

    python3 tests/run.py              contract + fail-open + adversarial + latency
    python3 tests/run.py --fast       skip latency (it spends ~4s timing)

Never pipe this into `tail` when you intend to read the result: a pipeline exits
with its LAST stage's status and `tail` always succeeds, so a failing battery
reports success. Redirect to a file and read `$?` separately.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
import test_adversarial  # noqa: E402
import test_contract  # noqa: E402
import test_failopen  # noqa: E402
import test_false_positive  # noqa: E402
import test_install  # noqa: E402
import test_latency  # noqa: E402
import test_publication  # noqa: E402


# The floor each layer must clear. Deliberately well under the current counts —
# this catches a layer that collapsed to nothing, not a layer that lost one case.
MIN_CHECKS = {
    "test_contract": 120,
    "test_false_positive": 120,
    "test_failopen": 60,
    "test_adversarial": 60,
    "test_install": 8,
    "test_latency": 4,
    "test_latency_controls": 10,
    "test_publication": 18,
}


def main():
    fast = "--fast" in sys.argv
    layers = [test_contract, test_false_positive, test_failopen,
              test_adversarial, test_install, test_publication,
              test_latency.CONTROLS]
    if not fast:
        layers.append(test_latency)

    ok = True
    total = 0
    for module in layers:
        suite = module.run()
        ran = suite.passed + len(suite.failures)
        total += ran
        ok = suite.report() and ok
        # A layer that runs NOTHING reports 0/0 and reads as a pass. That is the
        # shape a previous effort's negative controls failed in: the name filters
        # were wrong, zero tests matched, and the run exited 0. A floor per layer
        # turns "it exercised nothing" into a failure instead of a green line.
        if ran < MIN_CHECKS.get(module.__name__, 1):
            sys.stderr.write("FAIL  %s ran %d checks, floor is %d — the layer "
                             "exercised nothing\n"
                             % (module.__name__, ran, MIN_CHECKS.get(module.__name__, 1)))
            ok = False
    harness.cleanup()
    print("\n%d checks. %s" % (total, "ALL GREEN" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
