"""Installing twice must not undo an estate that folded this pack into a forwarder.

Some estates keep ONE registered handler per hook event and have that handler
invoke every other program that wants the event. This pack installed that way is
fully live — it runs, on every event it asked for — but the registered command is
the forwarder's path and contains no `keyless_hook.py`. The registration test
that decides whether to install therefore said "not installed", and `merge` added
a SECOND registration on the same event. Every re-run of the installer undid the
arrangement and left a rival behind.

The two directions are deliberately NOT symmetric, and this suite pins that:

    merge   skips an event that is registered directly OR reached through a
            forwarder — so a re-run is a no-op on a folded estate.
    unmerge removes ONLY a direct registration — so `--uninstall` never deletes
            a script this pack does not own. Widening it would take the
            forwarder's other passengers down too.

The tempting one-line alternative — write `keyless_hook.py` into the forwarder's
registered command so the existing narrow test matches — stops the re-add and
makes `--uninstall` delete the forwarder. This suite's `uninstall leaves the
forwarder alone` case is the one that fails if anyone tries it.
"""

import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import install  # noqa: E402
from harness import Suite  # noqa: E402

INSTALLER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "install.py")


def _forwarder(body):
    """A registered handler script on disk, carrying `body` as its text."""
    root = tempfile.mkdtemp(prefix="keyless-install-")
    path = os.path.join(root, "forwarder.sh")
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)
    return path


def _settings_with(path, event="PostToolUse"):
    return {"hooks": {event: [{"matcher": "",
                               "hooks": [{"type": "command", "command": path}]}]}}


def _handlers(settings, event):
    out = []
    for group in settings.get("hooks", {}).get(event, []):
        for handler in group.get("hooks", []):
            out.append(handler.get("command", ""))
    return out


FOLDED = _forwarder(
    '#!/bin/bash\n'
    'PAYLOAD="$(cat)"\n'
    '# this estate runs the pack from here rather than registering it beside us\n'
    'printf \'%s\' "$PAYLOAD" | python3 "$HOME/projects/keyless/hooks/keyless_hook.py"\n')

UNRELATED = _forwarder(
    '#!/bin/bash\n'
    'PAYLOAD="$(cat)"\n'
    'printf \'%s\' "$PAYLOAD" | node "$HOME/.some-other/hook.js"\n')


def _everything(fragment):
    """The record an install of the whole fragment would leave behind.

    `unmerge` is driven by a RECORD now rather than by the shipped list, so a
    case that means "this was all installed by us" says so explicitly. The old
    behaviour — remove anything that matches the fragment — is exactly this
    record, which is why every pre-existing case below still reads the same.
    """
    return {"events": list(fragment.get("hooks", {})),
            "allow": list(fragment.get("permissions", {}).get("allow", [])),
            "deny": list(fragment.get("permissions", {}).get("deny", []))}


def run():
    s = Suite("install")
    fragment = install.load_fragment()

    # ── the defect: a re-run must not add a rival beside the fold ───────────
    folded = _settings_with(FOLDED)
    merged, changes, _ = install.merge(folded, fragment)
    s.check("folded estate: no second PostToolUse handler is added",
            len(_handlers(merged, "PostToolUse")), 1)
    s.check("folded estate: the surviving handler is still the forwarder",
            _handlers(merged, "PostToolUse")[0], FOLDED)
    s.check("folded estate: nothing claims a PostToolUse handler was added",
            [c for c in changes if "PostToolUse" in c], [])

    # ── THE CONTROL. A detector that always says "folded" would pass every
    #    case above and install nothing, anywhere, forever. An unrelated
    #    forwarder that never mentions this pack MUST still get a registration.
    unrelated = _settings_with(UNRELATED)
    merged_u, changes_u, _ = install.merge(unrelated, fragment)
    s.check("unrelated forwarder: a PostToolUse handler IS added",
            len(_handlers(merged_u, "PostToolUse")), 2)
    s.check("unrelated forwarder: and the change is reported",
            bool([c for c in changes_u if "PostToolUse" in c]), True)

    # ── per EVENT, not per file. PreToolUse is not folded here, so it still
    #    installs — otherwise one folded event would silently skip the others.
    s.check("folded on one event: the other events still install",
            bool(_handlers(merged, "PreToolUse")), True)

    # ── the trap this asymmetry exists to avoid ─────────────────────────────
    # `--uninstall` must never delete a script this pack does not own. The
    # forwarder has other passengers; removing its registration takes the whole
    # estate's chain for that event down with it.
    unmerged, _ = install.unmerge(folded, _everything(fragment))
    s.check("uninstall leaves the forwarder alone",
            _handlers(unmerged, "PostToolUse"), [FOLDED])

    # ...while a DIRECT registration is still removed, so uninstall still works.
    direct = _settings_with("python3 /somewhere/keyless_hook.py")
    unmerged_d, changes_d = install.unmerge(direct, _everything(fragment))
    s.check("uninstall still removes a direct registration",
            _handlers(unmerged_d, "PostToolUse"), [])
    s.check("uninstall reports that removal",
            bool([c for c in changes_d if "PostToolUse" in c]), True)

    # ── idempotence, end to end: merging the merged file changes nothing ────
    twice, changes_twice, _ = install.merge(merged, fragment)
    s.check("a third run is a no-op", changes_twice, [])
    s.check("and leaves the file byte-identical",
            json.dumps(twice, sort_keys=True), json.dumps(merged, sort_keys=True))

    # ── both permission lists, both directions ─────────────────────────────
    # `allow` was added after `deny` had been handled by a hand-written block
    # per direction. A list merged and never unmerged is a rule an uninstall
    # leaves behind, so the round trip is asserted rather than the addition.
    mine = {"permissions": {"allow": ["Bash(git status:*)"],
                            "deny": ["Read(**/secret.txt)"]},
            "model": "opus"}
    merged_p, changes_p, record_p = install.merge(mine, fragment)
    for verdict in ("allow", "deny"):
        shipped = fragment["permissions"][verdict]
        s.check("every %s rule is installed" % verdict,
                [r for r in shipped if r in merged_p["permissions"][verdict]],
                shipped)
        s.check("the user's own %s rule is kept, and first" % verdict,
                merged_p["permissions"][verdict][0],
                mine["permissions"][verdict][0])
        s.check("the %s addition is reported" % verdict,
                bool([c for c in changes_p if verdict in c]), True)

    restored, _ = install.unmerge(merged_p, record_p)
    s.check("uninstall gives the permissions back exactly as they were",
            json.dumps(restored["permissions"], sort_keys=True),
            json.dumps(mine["permissions"], sort_keys=True))
    s.check("and leaves everything else in the file alone",
            restored.get("model"), "opus")

    # THE CONTROL for the round trip: a settings file that had no `permissions`
    # key at all must get one back to nothing, rather than an empty husk.
    bare, _, record_b = install.merge({}, fragment)
    stripped, _ = install.unmerge(bare, record_b)
    s.check("a file that had no permissions block is not left with an empty one",
            "permissions" in stripped, False)

    # `keyless run` must never ship in the allow list: it matches every command
    # anyone can put after the `--`, so allowing it allows arbitrary execution
    # rather than allowing this tool. Asserted, because it is the entry a
    # well-meaning change would add.
    s.check("no shipped allow rule approves running an arbitrary command",
            [r for r in fragment["permissions"]["allow"]
             if "keyless run" in r or "keyless put" in r or "keyless new" in r],
            [])

    # ── never raises on a handler it cannot read ───────────────────────────
    missing = _settings_with("/nonexistent/path/to/forwarder.sh")
    merged_m, _, _ = install.merge(missing, fragment)
    s.check("an unreadable handler is not treated as a fold",
            len(_handlers(merged_m, "PostToolUse")), 2)

    # ── THE RULE THE USER WROTE FIRST SURVIVES AN UNINSTALL ────────────────
    # The defect the record exists for. A rule the user had already written is
    # correctly NOT added by the install — and used to be removed by the
    # uninstall anyway, because the removal matched the shipped list rather than
    # a record of what was actually added. The install was a no-op and the
    # uninstall was destructive.
    theirs = fragment["permissions"]["allow"][0]
    already = {"permissions": {"allow": [theirs]}}
    merged_a, _, record_a = install.merge(already, fragment)
    s.check("a rule the user already had is not recorded as ours",
            theirs in record_a["allow"], False)
    back, _ = install.unmerge(merged_a, record_a)
    s.check("and it is still there after an uninstall",
            back.get("permissions", {}).get("allow"), [theirs])

    # THE CONTROL: the rules we DID add on that same run are still removed, so
    # the case above cannot pass on an uninstall that removes nothing at all.
    s.check("while the rules we added are gone",
            [r for r in fragment["permissions"]["allow"][1:]
             if r in back.get("permissions", {}).get("allow", [])],
            [])

    # ── A DELETION STAYS DELETED, AND `--restore` IS THE WAY BACK ──────────
    # Without a record, "never installed" and "installed and then thrown out"
    # are the same observation, so every re-run silently overwrites a decision.
    installed, _, record_i = install.merge({}, fragment)
    tilted = json.loads(json.dumps(installed))
    del tilted["permissions"]["allow"]
    again, changes_again, _ = install.merge(tilted, fragment, record_i)
    s.check("a re-run does not put back the allow list you deleted",
            "allow" in again.get("permissions", {}), False)
    s.check("and it says it left it alone rather than saying nothing",
            bool([c for c in changes_again if "left alone" in c]), True)

    restored_r, _, _ = install.merge(tilted, fragment, record_i, restore=True)
    s.check("--restore is what puts it back",
            restored_r["permissions"]["allow"], fragment["permissions"]["allow"])

    # The same rule for a whole event: a handler somebody deleted stays deleted.
    no_hooks = json.loads(json.dumps(installed))
    del no_hooks["hooks"]
    again_h, _, _ = install.merge(no_hooks, fragment, record_i)
    s.check("a handler you removed is not re-registered",
            "hooks" in again_h, False)

    _no_litter(s)
    _write_survives_a_failure(s)

    return s


# ── THE SETTINGS DIRECTORY BELONGS TO ANOTHER PROGRAM ──────────────────────────
# This pack writes one file there and leaves nothing else behind — no timestamped
# copy of the original, no temporary file from a run that failed. The assertion
# is on the DIRECTORY LISTING rather than on a filename, because the failure is
# "a file this pack does not own appeared" and naming the file under suspicion
# only catches the spelling somebody already thought of.
#
# The install's own guarantees are what make a copy of the original unnecessary,
# and each is pinned above or below: an unparseable input is refused, the merge
# carries everything else through, the replace is atomic, and the receipt makes
# the removal exact.


def _install_run(claude_dir, receipt, *extra):
    """One real `install.py` run, as a subprocess. Returns (rc, stdout)."""
    done = subprocess.run(
        [sys.executable, INSTALLER, "--claude-dir", claude_dir,
         "--receipt", receipt, "--report"] + list(extra),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return done.returncode, done.stdout.decode()


def _no_litter(s):
    root = tempfile.mkdtemp(prefix="keyless-litter-")
    claude_dir = os.path.join(root, "claude")
    os.makedirs(claude_dir)
    settings = os.path.join(claude_dir, "settings.json")
    receipt = os.path.join(root, "receipt.json")
    with open(settings, "w") as fh:
        json.dump({"model": "opus"}, fh)

    rc_in, said_in = _install_run(claude_dir, receipt)
    rc_out, _ = _install_run(claude_dir, receipt, "--uninstall")
    rc_again, _ = _install_run(claude_dir, receipt)

    # THE CONTROL. Every listing check below passes just as well on three runs
    # that did nothing at all, so prove the first run actually wrote something.
    s.check("the install run succeeded", (rc_in, rc_out, rc_again), (0, 0, 0))
    s.check("and it reported a change rather than no-opping",
            "added" in said_in, True)

    s.check("setup, uninstall and setup again leave one file in that directory",
            sorted(os.listdir(claude_dir)), ["settings.json"])
    s.check("and the user's own key is still in it",
            json.load(open(settings)).get("model"), "opus")

    # A pin on the mechanism, not only on its effect: the effect above is also
    # produced by a copy written somewhere else, which is not the fix.
    s.check("no function writes a copy of the settings file",
            [n for n in dir(install) if "backup" in n.lower()], [])


def _write_survives_a_failure(s):
    """An interrupted replace leaves the original whole and leaves no scrap.

    `os.replace` is the last act of the write, so failing it is the closest
    reachable stand-in for losing the process mid-write. The original must be
    exactly what it was, and the temporary file must not survive — a scrap left
    in another program's directory is the same defect as a backup left there.
    """
    root = tempfile.mkdtemp(prefix="keyless-atomic-")
    path = os.path.join(root, "settings.json")
    original = '{\n  "model": "opus"\n}\n'
    with open(path, "w") as fh:
        fh.write(original)

    def refuse(*_args, **_kwargs):
        raise OSError("simulated interruption")

    real_replace = os.replace
    os.replace = refuse
    try:
        install.write_atomically(path, {"model": "sonnet"})
        failed = False
    except OSError:
        failed = True
    finally:
        os.replace = real_replace

    s.check("the interrupted write is not reported as success", failed, True)
    s.check("the original file is byte-identical", open(path).read(), original)
    s.check("and no temporary file is left behind",
            sorted(os.listdir(root)), ["settings.json"])


if __name__ == "__main__":
    raise SystemExit(0 if run().report() else 1)
