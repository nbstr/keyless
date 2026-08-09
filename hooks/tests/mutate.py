#!/usr/bin/env python3
"""Mutation proof: break each check on purpose and require the battery to notice.

A suite that has never been seen red proves nothing. This runs the whole battery
against one deliberately broken copy of the pack per mutation; each must fail,
and the one that does not names a gate nothing is testing.

**This gate reads the PYTHON hook pack and nothing else.** It copies `hooks/`
alone into a temporary directory and runs the suite from there, so its verdict
is a statement about the hooks and can never be one about the Rust crate. The
crate has its own campaign — `cargo mutants`, driven by
`.github/workflows/mutants.yml` against `.github/mutants-baseline.txt`.

Two gates, both called "the mutation gate", is how a green from this one gets
quoted as coverage of `src/`. It has happened. So every line this script prints
carries the scope it measured, and the scope is DERIVED from the spec rather
than written here: add a Rust file to `mutations.json` and the printed line
changes by itself, while a sentence claiming Python-only would go quietly wrong.

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
invocation, with its own exit code, so it can never be read as a campaign of
successful mutations.
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


def _scope(spec):
    """What this campaign mutates, read off the spec rather than asserted here.

    A sentence naming the scope is wrong the day the spec moves, and wrong
    silently. This is derived, so a Rust entry in `mutations.json` would show up
    in the extension list on the very next run.
    """
    files = sorted({mutation["file"] for mutation in spec})
    kinds = sorted({os.path.splitext(name)[1] or "(no extension)" for name in files})
    return "%d files under hooks/ (%s)" % (len(files), ", ".join(kinds))


def main():
    with open(SPEC) as fh:
        spec = json.load(fh)

    scope = _scope(spec)
    print("scope: %s" % scope)
    print("       the python hook pack. The rust crate is NOT in this campaign;")
    print("       its coverage is cargo mutants, see .github/workflows/mutants.yml\n")

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
    print("\n%d/%d mutations caught in %s." % (len(results) - len(bad), len(results), scope))
    print("That is the hook pack's coverage and nothing else. The rust crate's")
    print("is a separate campaign: cargo mutants, .github/workflows/mutants.yml.")
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
