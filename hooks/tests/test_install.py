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
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import install  # noqa: E402
from harness import Suite  # noqa: E402


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


def run():
    s = Suite("install")
    fragment = install.load_fragment()

    # ── the defect: a re-run must not add a rival beside the fold ───────────
    folded = _settings_with(FOLDED)
    merged, changes = install.merge(folded, fragment)
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
    merged_u, changes_u = install.merge(unrelated, fragment)
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
    unmerged, _ = install.unmerge(folded, fragment)
    s.check("uninstall leaves the forwarder alone",
            _handlers(unmerged, "PostToolUse"), [FOLDED])

    # ...while a DIRECT registration is still removed, so uninstall still works.
    direct = _settings_with("python3 /somewhere/keyless_hook.py")
    unmerged_d, changes_d = install.unmerge(direct, fragment)
    s.check("uninstall still removes a direct registration",
            _handlers(unmerged_d, "PostToolUse"), [])
    s.check("uninstall reports that removal",
            bool([c for c in changes_d if "PostToolUse" in c]), True)

    # ── idempotence, end to end: merging the merged file changes nothing ────
    twice, changes_twice = install.merge(merged, fragment)
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
    merged_p, changes_p = install.merge(mine, fragment)
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

    restored, _ = install.unmerge(merged_p, fragment)
    s.check("uninstall gives the permissions back exactly as they were",
            json.dumps(restored["permissions"], sort_keys=True),
            json.dumps(mine["permissions"], sort_keys=True))
    s.check("and leaves everything else in the file alone",
            restored.get("model"), "opus")

    # THE CONTROL for the round trip: a settings file that had no `permissions`
    # key at all must get one back to nothing, rather than an empty husk.
    bare, _ = install.merge({}, fragment)
    stripped, _ = install.unmerge(bare, fragment)
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
    merged_m, _ = install.merge(missing, fragment)
    s.check("an unreadable handler is not treated as a fold",
            len(_handlers(merged_m, "PostToolUse")), 2)

    return s


if __name__ == "__main__":
    raise SystemExit(0 if run().report() else 1)
