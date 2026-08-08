#!/usr/bin/env python3
"""Mutation proof: break each check on purpose and require the battery to notice.

A suite that has never been seen red proves nothing. This runs the whole battery
against fifteen deliberately broken copies of the pack; each must fail, and the
one that does not names a gate nothing is testing.

Two disciplines, both earned:

**Verify the mutation LANDED.** A previous effort's `perl` substitution silently
stopped matching after a formatter rewrapped a line, and it reported exit 0 — a
negative control that never ran, indistinguishable from a passing test. Here the
patched file is diffed against the original: the find text must be gone, the
replacement must be present, and the byte count must differ. A mutation that did
not land is reported as `NOT APPLIED` and counts as a failure, never as a pass.

**Run a baseline control in the SAME copied tree.** If the unmutated copy is not
green, the tree is missing something the suite reads and every "failure" below is
about the copy rather than about the mutation. That is reported as a broken
invocation, with its own exit code, so it can never be read as fifteen successful
mutations.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HOOKS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(HOOKS, "tests", "mutations.json")


def _copy_tree():
    tmp = tempfile.mkdtemp(prefix="keyless-mutate-")
    dst = os.path.join(tmp, "hooks")
    shutil.copytree(HOOKS, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return tmp, dst


def _run_suite(tree):
    proc = subprocess.run(
        [sys.executable, os.path.join(tree, "tests", "run.py"), "--fast"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900,
        cwd=os.path.join(tree, "tests"))
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def _apply(tree, mutation):
    """Patch one file. Returns (applied, note) — never raises, always reports."""
    target = os.path.join(tree, mutation["file"])
    try:
        with open(target, "r") as fh:
            before = fh.read()
    except OSError as exc:
        return False, "cannot read target: %s" % exc

    find = mutation["find"]
    if find not in before:
        return False, "find text is not present (the source moved under the spec)"
    if before.count(find) != 1:
        return False, "find text appears %d times; a mutation must be unambiguous" % \
            before.count(find)

    after = before.replace(find, mutation["replace"], 1)
    with open(target, "w") as fh:
        fh.write(after)

    with open(target, "r") as fh:
        written = fh.read()
    if written == before:
        return False, "file is byte-identical after the write"
    if find in written and find != mutation["replace"]:
        return False, "find text survived the write"
    if mutation["replace"] and mutation["replace"] not in written:
        return False, "replacement text is absent from the written file"
    return True, "%+d bytes" % (len(written) - len(before))


def main():
    with open(SPEC) as fh:
        spec = json.load(fh)

    print("baseline control: the unmutated copy must be green")
    tmp, tree = _copy_tree()
    try:
        code, out = _run_suite(tree)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if code != 0:
        sys.stderr.write(out[-4000:])
        sys.stderr.write(
            "\nTHE INVOCATION IS WRONG: the unmutated copy is not green, so every\n"
            "result below would be about the copy rather than about a mutation.\n"
            "Widen what is copied, or fix the suite in place first.\n")
        return 4
    print("  baseline green\n")

    results = []
    for mutation in spec:
        tmp, tree = _copy_tree()
        try:
            applied, note = _apply(tree, mutation)
            if not applied:
                results.append((mutation["id"], "NOT APPLIED", note))
                continue
            code, out = _run_suite(tree)
            caught = code != 0
            detail = _first_failure(out) if caught else "SUITE STAYED GREEN"
            results.append((mutation["id"], "caught" if caught else "ESCAPED",
                            "%s | %s" % (note, detail)))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("  %-32s %-12s %s" % ("mutation", "result", "landed | first failing check"))
    print("  " + "-" * 96)
    for mid, status, detail in results:
        print("  %-32s %-12s %s" % (mid, status, detail[:60]))
    bad = [r for r in results if r[1] != "caught"]
    print("\n%d/%d mutations caught." % (len(results) - len(bad), len(results)))
    if bad:
        print("Uncaught:")
        for mid, status, detail in bad:
            print("  %s (%s) %s" % (mid, status, detail))
    return 0 if not bad else 1


def _first_failure(out):
    for line in out.splitlines():
        if line.startswith("FAIL  "):
            return line[6:]
    return "(failed with no FAIL line)"


if __name__ == "__main__":
    raise SystemExit(main())
