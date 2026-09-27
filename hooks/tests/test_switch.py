"""KL-SWITCH: the pack's own off switch is not reachable from inside a session.

Three shapes, each driven through the real hook subprocess so the assertion is
about the check as it actually runs, never about a helper called in-process:

    the verb        `keyless disable` / `keyless uninstall`, and the pack's
                     own uninstall scripts, however they are wrapped, piped
                     through an interpreter, or substituted
    a tool write     Write/Edit/MultiEdit/NotebookEdit aimed at the pack's own
                     config
    a shell write    the same files, reached from Bash — a redirect, `tee`,
                     `cp`, `sed -i`, an assignment resolved, an interpreter
                     payload

Every "fires" case above is paired with a look-alike that must stay silent —
a read of the same file, a mention of the verb in a commit message, a `--help`
— because a check that refuses those is a check its owner disables, and then
it protects nothing.

That pairing runs the other way too for the one act on keyless's own
`config.json` that is NOT refused. `_declarations_gate` below is written from
the refusing side: the allowed shape is asserted once per write tool, and every
other case is a look-alike that must still deny — the same shape aimed at the
file that configures the guards, a name removed, a route moved, a binary path
smuggled in beside a legitimate addition, and every shape whose result this
process cannot compute. Each refusal is asserted against the MESSAGE as well as
the verdict wherever another check could produce the same colour, because a deny
credited to the wrong gate is an arm nobody is scoring.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import DECOY, Suite, bash, drive, fixtures, read, write  # noqa: E402


def run():
    s = Suite("switch")
    root = fixtures()
    home = os.path.join(root, "switch-home")
    os.makedirs(home, exist_ok=True)
    env = {"HOME": home}

    # ── the verb: fires ──────────────────────────────────────────────────────
    for cmd in (
        "keyless disable",
        "keyless uninstall",
        "/usr/local/bin/keyless disable",
        "sudo keyless disable",
        "env FOO=1 keyless disable",
        "timeout 5 keyless disable",
        # `script`'s first positional is its log file, never the command.
        "script -q /dev/null keyless disable",
        "script /tmp/typescript keyless disable",
        "script -qc 'keyless disable' /dev/null",
        "script --command 'keyless uninstall' /dev/null",
        'bash -c "keyless disable"',
        "$(keyless disable)",
        "`keyless disable`",
        "keyless --config /tmp/x.json disable",
        "keyless --audit /tmp/a.log --no-audit uninstall",
        # Spellings the shell reads as the plain words.
        "key''less disable",
        "keyless dis\"\"able",
        "K=keyless; $K disable",
    ):
        s.check("KL-SWITCH verb fires: %s" % cmd, drive(bash(cmd)).kind, "deny")

    v = drive(bash("keyless disable"))
    s.check_in("KL-SWITCH verb names no way around it",
               "person's decision", v.message)
    for spelling in ("keyless enable", "KEYLESS_HOOKS_DISABLE", "hooks.json",
                     "--config", "edit"):
        s.check("KL-SWITCH message names no remedy (%r)" % spelling,
                spelling in v.message, False)

    # ── the verb: silent — help, and every other pack-side verb (C5) ────────
    for cmd in (
        "keyless disable --help",
        "keyless disable -h",
        "keyless -h",
        "keyless help",
        "keyless help disable",
        "keyless run -s X -- echo hi",
        "keyless ls",
        "keyless enable",
        "keyless doctor",
        "keyless setup",
        'git commit -m "mention keyless disable in the changelog"',
        # Prose about the verb, written into a file. Replayed over real
        # sessions these were every false positive on the verb: markdown code
        # spans are backticks, and in single quotes or a quoted heredoc they
        # are characters, not commands.
        "cat >> report.md <<'EOF'\nRun `keyless disable` to stop the guards.\nkeyless disable\nEOF",
        "cat > note.md <<EOF\nkeyless disable is the off switch\nEOF",
        "PROMPT='Work the issue: `keyless disable` stops every guard'; echo \"$PROMPT\" > p.txt",
    ):
        s.check("KL-SWITCH verb silent: %s" % cmd, drive(bash(cmd)).kind, "silent")

    # ── the same text, where the shell really does run it ────────────────────
    for cmd in (
        "bash <<EOF\nkeyless disable\nEOF",
        "cat > note.md <<EOF\n`keyless disable`\nEOF",
        'echo "`keyless disable`"',
        'echo "$(keyless disable)"',
    ):
        s.check("KL-SWITCH verb fires where it executes: %s" % cmd,
                drive(bash(cmd)).kind, "deny")

    # ── the pack's own uninstallers: fires ───────────────────────────────────
    for cmd in (
        "hooks/uninstall.sh",
        "./hooks/uninstall.sh --scope project",
        "/abs/path/hooks/uninstall.sh",
        "sh hooks/uninstall.sh",
        "bash hooks/uninstall.sh",
        "python3 hooks/install.py --uninstall",
        "./hooks/install.sh --uninstall",
        "sudo hooks/uninstall.sh",
    ):
        s.check("KL-SWITCH uninstaller fires: %s" % cmd, drive(bash(cmd)).kind, "deny")

    # ── the pack's own uninstallers: silent ──────────────────────────────────
    for cmd in (
        "cat hooks/uninstall.sh",
        "hooks/install.py --dry-run",
        "hooks/install.sh",
        "hooks/install.sh --scope project",
        # THE CONTROL for the path suffix. A script that merely SHARES the
        # basename `uninstall.sh`, outside this pack's own `hooks/` directory,
        # is somebody else's script — widening the match to the basename
        # alone would refuse it too.
        "./other/uninstall.sh",
        "sh vendor/uninstall.sh",
    ):
        s.check("KL-SWITCH uninstaller silent: %s" % cmd, drive(bash(cmd)).kind, "silent")

    # ── a tool write to a guard file ─────────────────────────────────────────
    hooks_json = os.path.join(home, ".config", "keyless", "hooks.json")
    config_json = os.path.join(home, ".config", "keyless", "config.json")
    s.check("KL-SWITCH Write on hooks.json denies",
            drive(write(hooks_json, "{}"), env=env).kind, "deny")
    s.check("KL-SWITCH Write on config.json denies",
            drive(write(config_json, "{}"), env=env).kind, "deny")
    s.check("KL-SWITCH Edit on hooks.json denies",
            drive({"hook_event_name": "PreToolUse", "tool_name": "Edit",
                   "tool_input": {"file_path": hooks_json, "old_string": "true",
                                 "new_string": "false"},
                   "cwd": root, "session_id": "test-session"}, env=env).kind,
            "deny")
    s.check("KL-SWITCH MultiEdit on hooks.json denies",
            drive({"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                   "tool_input": {"file_path": hooks_json,
                                 "edits": [{"old_string": "a", "new_string": "b"}]},
                   "cwd": root, "session_id": "test-session"}, env=env).kind,
            "deny")

    project_guard = os.path.join(root, ".keyless-hooks.json")
    s.check("KL-SWITCH Write on the project-layer file denies",
            drive(write(project_guard, "{}"), env=env).kind, "deny")

    s.check("KL-SWITCH Write on an unrelated file is silent",
            drive(write(os.path.join(root, "notes.md"), "hello"), env=env).kind,
            "silent")

    # ── a shell write to a guard file ────────────────────────────────────────
    for cmd in (
        "echo '{}' > ~/.config/keyless/hooks.json",
        "echo x >~/.config/keyless/hooks.json",
        "printf '{}' >> ~/.config/keyless/hooks.json",
        "tee ~/.config/keyless/hooks.json <<< '{}'",
        "cp /tmp/x.json ~/.config/keyless/hooks.json",
        "mv /tmp/x.json ~/.config/keyless/hooks.json",
        "ln -sf /tmp/x.json ~/.config/keyless/hooks.json",
        "install -m 644 /tmp/x.json ~/.config/keyless/hooks.json",
        "rsync /tmp/x.json ~/.config/keyless/hooks.json",
        "dd if=/tmp/x.json of=~/.config/keyless/hooks.json",
        "truncate -s 0 ~/.config/keyless/hooks.json",
        "rm ~/.config/keyless/hooks.json",
        "sed -i '' 's/true/false/' ~/.config/keyless/hooks.json",
        "F=~/.config/keyless/hooks.json; echo x > $F",
        "python3 -c \"open('~/.config/keyless/hooks.json', 'w').write('{}')\"",
        # Named only relative to a directory the command moved into.
        "cd ~/.config/keyless && echo '{}' > hooks.json",
        "cd ~/.config && cd keyless && tee config.json <<< '{}'",
        "pushd ~/.config/keyless; sed -i '' 's/a/b/' hooks.json",
        # The directory itself, which reaches every file inside it.
        "cp -r /tmp/evil/ ~/.config/keyless/",
        "rm -r ~/.config/keyless",
        "mv ~/.config/keyless ~/.config/keyless.bak",
        "find ~/.config/keyless -name '*.json' -delete",
        "find ~/.config/keyless -name hooks.json -exec rm {} \\;",
    ):
        s.check("KL-SWITCH shell-write fires: %s" % cmd,
                drive(bash(cmd, cwd=root), env=env).kind, "deny")

    # ── reading a guard file passes, whatever door it comes through ─────────
    for cmd in (
        "cat ~/.config/keyless/hooks.json",
        "jq . ~/.config/keyless/hooks.json",
        "grep enabled ~/.config/keyless/hooks.json",
        "git diff ~/.config/keyless/hooks.json",
        "git commit -am 'edit hooks.json'",
        "echo not a real path",
        "ls ~/.config/keyless",
        "ls -la ~/.config/keyless/",
        "cd ~/.config/keyless && cat hooks.json",
        "mkdir -p ~/.config/keyless",
        "find ~/.config/keyless -iname '*.json'",
        # The same basename somewhere the pack never reads.
        "cd /tmp && echo x > hooks.json",
    ):
        s.check("KL-SWITCH shell-write silent (reader): %s" % cmd,
                drive(bash(cmd, cwd=root), env=env).kind, "silent")

    s.check("KL-SWITCH Read tool on hooks.json is untouched by this check",
            drive(read(hooks_json), env=env).kind, "silent")
    s.check("KL-SWITCH Grep tool on hooks.json is untouched by this check",
            drive({"hook_event_name": "PreToolUse", "tool_name": "Grep",
                   "tool_input": {"pattern": "enabled", "path": hooks_json},
                   "cwd": root, "session_id": "test-session"}, env=env).kind,
            "silent")

    # ── an unrelated write, and an unrelated read, are silent ────────────────
    s.check("KL-SWITCH silent on an unrelated redirect",
            drive(bash("echo hi > /tmp/keyless-switch-unrelated.txt")).kind,
            "silent")

    # ── C8: the project layer cannot flip the switch ─────────────────────────
    _project_layer_cannot_disable(s)

    # ── declaring a name: the one act on config.json that is not refused ─────
    _declarations_gate(s)

    return s


def _project_layer_cannot_disable(s):
    from keyless_hooks.config import load

    root = fixtures()
    project = os.path.join(root, "switch-c8")
    os.makedirs(project, exist_ok=True)
    with open(os.path.join(project, ".keyless-hooks.json"), "w") as fh:
        fh.write('{"enabled": false, "observe": true, "allowed_add": [".fixture"]}')

    cfg = load(project)
    s.check("a project file cannot disable the pack", cfg.enabled, True)
    s.check("a project file cannot force record-only mode", cfg.observe, False)
    s.check("a project file can still extend its list keys",
            ".fixture" in cfg.allowed, True)


# ── declaring a name ────────────────────────────────────────────────────────

# The document every case below starts from. `stores` carries a boolean and a
# path because those are the two things an addition must never be able to smuggle
# a change to: `enabled`, and a place a binary could be named.
_BASE = {
    "stores": {
        "infisical": {"enabled": True, "path": "/backend"},
        "daemon": {"enabled": False},
    },
    "secrets": {
        "ALREADY_DECLARED": {"store": "infisical", "env": "prod"},
        # A second route, in the other vocabulary — a store whose coordinates
        # name an ITEM rather than a variable. Both spellings have to be pinned:
        # the coordinate names differ per store, and a route is only unmoved if
        # every one of them is.
        #
        # Every coordinate below is an invented decoy already on
        # `DECOY_COORDINATES` in `tests/publication.rs` — this is the triple that
        # file's own documentation uses. A fixture is where a real vault name
        # reaches a published file, and that gate is what caught one here.
        "ALSO_DECLARED": {"store": "proton", "vault": "Personal",
                          "item": "Router", "field": "password"},
    },
}

# What a session would actually add: coordinates, no value.
_NEW = {"store": "infisical", "env": "staging", "key": "A_STAGING_KEY"}


def _edit(path, old, new, cwd=None, replace_all=False):
    return {"hook_event_name": "PreToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": path, "old_string": old,
                           "new_string": new, "replace_all": replace_all},
            "cwd": cwd or fixtures(), "session_id": "test-session"}


def _multi(path, edits, cwd=None):
    return {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
            "tool_input": {"file_path": path, "edits": edits},
            "cwd": cwd or fixtures(), "session_id": "test-session"}


def _plant(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def _doc(mutate=None):
    """A deep copy of `_BASE`, optionally mutated, as JSON text."""
    doc = json.loads(json.dumps(_BASE))
    if mutate:
        mutate(doc)
    return json.dumps(doc, indent=2)


def _plus(**names):
    """`_BASE` with names ADDED under `secrets` — the shape that is allowed."""
    def add(doc):
        doc["secrets"].update(names)
    return _doc(add)


def _read_bounded_refuses_what_is_not_a_file(s, home):
    """A FIFO with no writer, a directory, and a device that never ends.

    `KEYLESS_CONFIG` is an ordinary environment variable, so a config path is
    whatever somebody points it at. Each of these answers None, and each answers
    it AT ONCE: the failure being guarded against is a read that waits or grows,
    which is why the assertion is about a returned value rather than a verdict.
    """
    from keyless_hooks.declarations import read_bounded

    fifo = os.path.join(home, "a-fifo")
    if not os.path.exists(fifo):
        os.mkfifo(fifo)
    s.check("a FIFO with no writer reads as nothing", read_bounded(fifo), None)
    s.check("a directory reads as nothing", read_bounded(home), None)
    s.check("a device with no end reads as nothing",
            read_bounded("/dev/zero"), None)
    s.check("an absent path reads as nothing",
            read_bounded(os.path.join(home, "not-here.json")), None)
    # THE CONTROL. Without it every line above passes over a reader that returns
    # None for everything, which is the same function with the feature deleted.
    real = _plant(os.path.join(home, "a-real-file.json"), '{"secrets": {}}')
    s.check("and a real file reads as its own text",
            read_bounded(real), '{"secrets": {}}')


def _declarations_gate(s):
    root = fixtures()
    # Its own HOME, so the "the file is absent" assertion earlier in this module
    # keeps its meaning: that one needs no config.json at the default location,
    # and these need one.
    home = os.path.join(root, "switch-declarations-home")
    keyless_dir = os.path.join(home, ".config", "keyless")
    config = os.path.join(keyless_dir, "config.json")
    guards = os.path.join(keyless_dir, "hooks.json")
    project = os.path.join(home, ".keyless-hooks.json")
    env = {"HOME": home}

    # Planted, so every refusal below is refused on its own terms rather than
    # because there was nothing on disk to compare against. The two guard files
    # hold the IDENTICAL document, which is what makes the path the only
    # difference between the allowed case and its two look-alikes.
    _plant(config, _doc())
    _plant(guards, _doc())
    _plant(project, _doc())

    # ── allowed: a name gained, and nothing else moved ───────────────────────
    s.check("Write declaring a name is not refused",
            drive(write(config, _plus(NEW_NAME=_NEW)), env=env).kind, "silent")
    s.check("Write declaring several names at once is not refused",
            drive(write(config, _plus(ONE=_NEW, TWO={})), env=env).kind, "silent")
    s.check("Write declaring a name with no route at all is not refused",
            drive(write(config, _plus(BARE={})), env=env).kind, "silent")
    s.check("Edit declaring a name is not refused",
            drive(_edit(config, '"secrets": {',
                        '"secrets": {\n    "NEW_NAME": {"store": "infisical"},'),
                  env=env).kind, "silent")
    s.check("MultiEdit declaring a name is not refused",
            drive(_multi(config, [{"old_string": '"secrets": {',
                                   "new_string": '"secrets": {\n    "NEW_NAME": {},'}]),
                  env=env).kind, "silent")
    s.check("MultiEdit declaring two names in two edits is not refused",
            drive(_multi(config, [
                {"old_string": '"secrets": {',
                 "new_string": '"secrets": {\n    "ONE": {},'},
                {"old_string": '"ONE": {},',
                 "new_string": '"ONE": {},\n    "TWO": {},'}]), env=env).kind,
            "silent")
    # Rewriting the same bytes adds nothing and takes nothing away. It is a
    # no-op and is treated as one.
    s.check("Write of byte-identical content is not refused",
            drive(write(config, _doc()), env=env).kind, "silent")

    # The first declaration in a config that had none. `secrets` absent and
    # `secrets` empty are the same starting point and both have to work, or the
    # allowance never covers the first name anybody declares.
    for label, doc in (("absent", {"stores": _BASE["stores"]}),
                       ("empty", {"stores": _BASE["stores"], "secrets": {}})):
        _plant(config, json.dumps(doc))
        s.check("the first declaration in a config whose secrets map is %s" % label,
                drive(write(config, json.dumps(
                    {"stores": _BASE["stores"], "secrets": {"FIRST": _NEW}})),
                    env=env).kind, "silent")
    _plant(config, _doc())

    # ── the same shape, aimed at the files that configure the guards ─────────
    for label, path in (("hooks.json", guards),
                        (".keyless-hooks.json", project)):
        verdict = drive(write(path, _plus(NEW_NAME=_NEW)), env=env)
        s.check("the additive shape aimed at %s still denies" % label,
                verdict.kind, "deny")
        s.check_in("and it is KL-SWITCH that refuses %s" % label,
                   "[KL-SWITCH]", verdict.message)
        s.check_in("and the refusal is the guard-config one for %s" % label,
                   "files that configure the guards", verdict.message)
    s.check("the additive shape aimed at hooks.json by Edit still denies",
            drive(_edit(guards, '"secrets": {', '"secrets": {\n    "X": {},'),
                  env=env).kind, "deny")

    # THE BASENAME TRAP, and its control. `KEYLESS_HOOKS_CONFIG` may name a file
    # spelled `config.json`, and then that file IS the guard config — so the
    # classification cannot be a basename test. One file, one document, one
    # additive write: only which variable points at it differs.
    trap = _plant(os.path.join(home, "elsewhere", "config.json"), _doc())
    s.check("a config.json that KEYLESS_HOOKS_CONFIG names is the GUARD config",
            drive(write(trap, _plus(NEW_NAME=_NEW)),
                  env={"HOME": home, "KEYLESS_HOOKS_CONFIG": trap}).kind, "deny")
    s.check("the same file named by KEYLESS_CONFIG is the declarations file",
            drive(write(trap, _plus(NEW_NAME=_NEW)),
                  env={"HOME": home, "KEYLESS_CONFIG": trap}).kind, "silent")
    s.check("and named by BOTH it is still the GUARD config",
            drive(write(trap, _plus(NEW_NAME=_NEW)),
                  env={"HOME": home, "KEYLESS_HOOKS_CONFIG": trap,
                       "KEYLESS_CONFIG": trap}).kind, "deny")

    # ── a name taken away, or pointed somewhere else ─────────────────────────
    def _drop(doc):
        doc["secrets"].pop("ALREADY_DECLARED")

    def _drop_and_add(doc):
        doc["secrets"].pop("ALREADY_DECLARED")
        doc["secrets"]["NEW_NAME"] = _NEW

    def _repoint_store(doc):
        doc["secrets"]["ALREADY_DECLARED"]["store"] = "keychain"

    def _repoint_and_add(doc):
        doc["secrets"]["ALREADY_DECLARED"]["env"] = "dev"
        doc["secrets"]["NEW_NAME"] = _NEW

    def _extend_route(doc):
        doc["secrets"]["ALREADY_DECLARED"]["field"] = "password"

    # Each replacement is another allowlisted decoy, for the reason `_BASE` gives.
    def _repoint_vault(doc):
        doc["secrets"]["ALSO_DECLARED"]["vault"] = "company"

    def _repoint_item(doc):
        doc["secrets"]["ALSO_DECLARED"]["item"] = "decoy"

    def _repoint_field(doc):
        doc["secrets"]["ALSO_DECLARED"]["field"] = "username"

    def _shorten_route(doc):
        doc["secrets"]["ALSO_DECLARED"].pop("field")

    for label, mutate in (("a name removed", _drop),
                          ("a name removed while another is added", _drop_and_add),
                          ("an existing route's store moved", _repoint_store),
                          ("an existing route moved while a name is added",
                           _repoint_and_add),
                          ("an existing route given one more coordinate",
                           _extend_route),
                          ("an existing route's vault moved", _repoint_vault),
                          ("an existing route's item moved", _repoint_item),
                          ("an existing route's field moved", _repoint_field),
                          ("an existing route with a coordinate taken away",
                           _shorten_route)):
        verdict = drive(write(config, _doc(mutate)), env=env)
        s.check("declarations write denies: %s" % label, verdict.kind, "deny")
        s.check_in("and KL-SWITCH is the gate that refused it (%s)" % label,
                   "[KL-SWITCH]", verdict.message)
        s.check_in("and the refusal is the declarations one (%s)" % label,
                   "`secrets` map", verdict.message)
    s.check("an empty document denies — it takes every name away",
            drive(write(config, "{}"), env=env).kind, "deny")

    # ── anything outside the secrets map ─────────────────────────────────────
    def _plant_binary(doc):
        doc["stores"]["infisical"]["binary"] = "/tmp/a-binary-this-session-wrote"
        doc["secrets"]["NEW_NAME"] = _NEW

    def _flip_enabled(doc):
        doc["stores"]["daemon"]["enabled"] = True
        doc["secrets"]["NEW_NAME"] = _NEW

    def _retype_enabled(doc):
        # A boolean retyped as the integer Python reads as its equal. The
        # crate's loader answers that with a type error and then reads NO
        # config, so a plain `==` here would pass a document that takes every
        # declared name away.
        doc["stores"]["infisical"]["enabled"] = 1
        doc["secrets"]["NEW_NAME"] = _NEW

    def _add_top_level(doc):
        doc["enabled"] = False
        doc["secrets"]["NEW_NAME"] = _NEW

    def _drop_a_store(doc):
        doc["stores"].pop("daemon")
        doc["secrets"]["NEW_NAME"] = _NEW

    for label, mutate in (("a store's binary path", _plant_binary),
                          ("a store's enabled flag", _flip_enabled),
                          ("a store's enabled flag RETYPED", _retype_enabled),
                          ("a new top-level key", _add_top_level),
                          ("a store removed", _drop_a_store)):
        verdict = drive(write(config, _doc(mutate)), env=env)
        s.check("a name added beside %s still denies" % label,
                verdict.kind, "deny")
        s.check_in("and it is KL-SWITCH that refuses it (%s)" % label,
                   "[KL-SWITCH]", verdict.message)

    # ── a route that is not a route ──────────────────────────────────────────
    for label, route in (("a string", "infisical"), ("a list", ["infisical"]),
                         ("a number", 1), ("null", None)):
        s.check("a gained name whose route is %s denies" % label,
                drive(write(config, _plus(NEW_NAME=route)), env=env).kind, "deny")
    s.check("a secrets map that is not a map denies",
            drive(write(config, json.dumps(
                {"stores": _BASE["stores"], "secrets": []})), env=env).kind, "deny")
    # A constant Python's reader takes and the crate's refuses. Allowed, it
    # would leave a document the CLI cannot load — every declared name gone.
    s.check("a gained name holding a value only one reader accepts denies",
            drive(write(config, _plus(NEW_NAME={"note": float("nan")})),
                  env=env).kind, "deny")

    # A DUPLICATE KEY, which is the case that looks harmless and is not. Both
    # readers keep the last one inside the `secrets` map; at the TOP LEVEL the
    # crate refuses the document and falls back to declaring NOTHING, while
    # Python keeps the last and sees every name — measured against the CLI. So
    # the additive-looking one is the dangerous one, and it is refused at both
    # levels. Written as text, because no serializer emits a duplicate key.
    #
    # 🔴 EVERY DOCUMENT HERE RESOLVES, LAST-WINS, TO EXACTLY `_BASE` PLUS ONE
    # NAME, and that is the whole design of these arms rather than a detail. An
    # earlier version spelled them with names `_BASE` does not declare, so they
    # were refused because a declared name had gone missing — true, and nothing
    # to do with the duplicate. They stayed green with the duplicate guard
    # removed. A mutant said so; reading them did not.
    stores = json.dumps(_BASE["stores"])
    declared_now = json.dumps(_BASE["secrets"])
    declared_plus = json.dumps(dict(_BASE["secrets"], NEW_NAME=_NEW))
    one_route = json.dumps(_BASE["secrets"]["ALREADY_DECLARED"])
    other_route = json.dumps(_BASE["secrets"]["ALSO_DECLARED"])
    for label, content in (
        ("at the top level",
         '{"stores": %s, "secrets": %s, "secrets": %s}'
         % (stores, declared_now, declared_plus)),
        ("inside the secrets map",
         '{"stores": %s, "secrets": {"ALREADY_DECLARED": %s, '
         '"ALREADY_DECLARED": %s, "ALSO_DECLARED": %s, "NEW_NAME": %s}}'
         % (stores, one_route, one_route, other_route, json.dumps(_NEW))),
        ("on a key outside the secrets map",
         '{"stores": %s, "stores": %s, "secrets": %s}'
         % (stores, stores, declared_plus)),
    ):
        s.check("a duplicate key %s denies" % label,
                drive(write(config, content), env=env).kind, "deny")
    # And over a file that ALREADY carries one, nothing is additive: that config
    # declares no names to the CLI, so a person has to repair it first. The
    # planted document resolves last-wins to exactly `_BASE`, so an ordinary
    # additive write over it is refused by the duplicate and by nothing else.
    _plant(config, '{"stores": %s, "secrets": %s, "secrets": %s}'
           % (stores, declared_now, declared_now))
    s.check("an additive write over a file that already holds a duplicate denies",
            drive(write(config, _plus(NEW_NAME=_NEW)), env=env).kind, "deny")
    _plant(config, _doc())

    # ── nothing this process can compute is allowed ──────────────────────────
    s.check("unparseable new content denies",
            drive(write(config, '{"secrets": {"NEW_NAME": {}'), env=env).kind, "deny")
    s.check("content with trailing text after the document denies",
            drive(write(config, _plus(NEW_NAME=_NEW) + "\nand then some"),
                  env=env).kind, "deny")
    s.check("new content that is a JSON list denies",
            drive(write(config, '["NEW_NAME"]'), env=env).kind, "deny")
    s.check("a Write payload carrying no content at all denies",
            drive({"hook_event_name": "PreToolUse", "tool_name": "Write",
                   "tool_input": {"file_path": config}, "cwd": root,
                   "session_id": "test-session"}, env=env).kind, "deny")

    s.check("an Edit whose old_string is absent denies",
            drive(_edit(config, '"nowhere_in_the_file": {', '"x": {}'),
                  env=env).kind, "deny")
    s.check("an Edit whose old_string matches twice denies",
            drive(_edit(config, '"infisical"', '"keychain"'), env=env).kind, "deny")
    s.check("an Edit whose old_string equals its replacement denies",
            drive(_edit(config, '"secrets": {', '"secrets": {'), env=env).kind, "deny")
    s.check("an Edit with an empty old_string denies",
            drive(_edit(config, "", _plus(NEW_NAME=_NEW)), env=env).kind, "deny")
    s.check("a replace_all Edit that repoints every site denies",
            drive(_edit(config, '"infisical"', '"keychain"', replace_all=True),
                  env=env).kind, "deny")
    s.check("a MultiEdit whose LAST edit is not additive denies",
            drive(_multi(config, [
                {"old_string": '"secrets": {',
                 "new_string": '"secrets": {\n    "ONE": {},'},
                {"old_string": '"prod"', "new_string": '"dev"'}]), env=env).kind,
            "deny")
    s.check("a MultiEdit with no edits denies",
            drive(_multi(config, []), env=env).kind, "deny")
    s.check("a MultiEdit with an entry that is not a mapping denies",
            drive(_multi(config, ["not a mapping"]), env=env).kind, "deny")
    s.check("NotebookEdit on the declarations file denies",
            drive({"hook_event_name": "PreToolUse", "tool_name": "NotebookEdit",
                   "tool_input": {"notebook_path": config,
                                  "new_source": _plus(NEW_NAME=_NEW)},
                   "cwd": root, "session_id": "test-session"}, env=env).kind,
            "deny")

    # ── the file on disk is not one this can read ────────────────────────────
    _plant(config, "{ this document will not parse")
    s.check("an additive-looking write over an unparseable file denies",
            drive(write(config, _plus(NEW_NAME=_NEW)), env=env).kind, "deny")

    # OVER AN EMPTY DOCUMENT, and this is the shape that scores the refusal
    # rather than something standing beside it. Against `_BASE` an unparseable
    # write is refused by the comparison of everything OUTSIDE `secrets` —
    # nothing matches a document with no `stores` in it — so those arms pass
    # whatever the parse failure is treated as. An empty document has nothing
    # outside `secrets` to disagree about, so the parse failure is the only
    # thing left that can refuse. Read as "no names declared" instead of as a
    # refusal, every one of these is allowed. A mutant found that; the arms
    # above did not.
    _plant(config, "{}")
    for label, content in (("unparseable content", "{ not json"),
                           ("a JSON list", '["NEW_NAME"]'),
                           ("a bare string", '"NEW_NAME"'),
                           ("nothing at all", "")):
        s.check("over an empty document, %s still denies" % label,
                drive(write(config, content), env=env).kind, "deny")
    # THE CONTROL for that group: over the same empty document, a real
    # declaration IS allowed — so the four refusals above are about what could
    # not be read, and not about the file being empty.
    s.check("and over the same empty document a real declaration is allowed",
            drive(write(config, json.dumps({"secrets": {"FIRST": _NEW}})),
                  env=env).kind, "silent")
    _plant(config, json.dumps({"stores": _BASE["stores"], "secrets": []}))
    s.check("an additive-looking write over a non-map secrets key denies",
            drive(write(config, _plus(NEW_NAME=_NEW)), env=env).kind, "deny")
    os.unlink(config)
    s.check("a write that would CREATE the declarations file denies",
            drive(write(config, _plus(NEW_NAME=_NEW)), env=env).kind, "deny")
    # The same absent file, written with a document that WOULD be additive
    # against an empty one. This is the arm that separates "there was nothing to
    # compare against" from "an absent file reads as `{}`" — and only the second
    # of those would let a created file declare `stores`, where a backend's
    # binary path lives.
    s.check("and one that would be additive against an empty document denies too",
            drive(write(config, json.dumps({"secrets": {"FIRST": _NEW}})),
                  env=env).kind, "deny")
    _plant(config, _doc())

    # ── the path need not lead to a regular file ─────────────────────────────
    # Asserted in process, against the reader itself, because the property is
    # that this returns rather than WAITS — and a hook driven as a subprocess
    # reports a wait as a timeout, which is a crash rather than a verdict.
    _read_bounded_refuses_what_is_not_a_file(s, home)

    # ── past the size the CLI's own loader will read ─────────────────────────
    # Past that bound keyless reads no config at all, so the write does not add
    # a declaration — it takes every existing one away.
    s.check("a result past the loader's own bound denies",
            drive(write(config, _plus(BIG={"note": "x" * (1024 * 1024)})),
                  env=env).kind, "deny")
    oversized = _plant(os.path.join(keyless_dir, "config.json"),
                       _plus(BIG={"note": "x" * (1024 * 1024)}))
    s.check("an Edit against a file already past that bound denies",
            drive(_edit(oversized, '"secrets": {', '"secrets": {\n    "X": {},'),
                  env=env).kind, "deny")
    _plant(config, _doc())

    # ── a shell write is refused whatever it would have written ──────────────
    additive = '{"secrets":{"NEW_NAME":{}}}'
    for cmd in (
        "echo '%s' > ~/.config/keyless/config.json" % additive,
        "printf '%s' >> ~/.config/keyless/config.json" % additive,
        "tee ~/.config/keyless/config.json <<< '%s'" % additive,
        "cp /tmp/declared.json ~/.config/keyless/config.json",
        "sed -i '' 's/prod/staging/' ~/.config/keyless/config.json",
        "cd ~/.config/keyless && echo '%s' > config.json" % additive,
        "python3 -c \"open('~/.config/keyless/config.json','w').write('%s')\"" % additive,
    ):
        s.check("a shell write of an additive document still denies: %s" % cmd,
                drive(bash(cmd, cwd=root), env=env).kind, "deny")
    shell = drive(bash("echo '%s' > ~/.config/keyless/config.json" % additive,
                       cwd=root), env=env)
    s.check_in("and KL-SWITCH is the gate that refused the shell write",
               "[KL-SWITCH]", shell.message)

    # ── reading it is still not refused ──────────────────────────────────────
    for cmd in ("cat ~/.config/keyless/config.json",
                "jq .secrets ~/.config/keyless/config.json",
                "keyless ls", "keyless items", "keyless fields", "keyless doctor"):
        s.check("reading the declarations is silent: %s" % cmd,
                drive(bash(cmd, cwd=root), env=env).kind, "silent")

    # ── silence here does not disarm the check that refuses a VALUE ──────────
    # The whole argument for the allowance is that the file holds coordinates.
    # A write that puts a credential into it is a different act, and the gate
    # that judges that act must still be reached.
    leaked = drive(write(config, _plus(NEW_NAME={"store": "infisical",
                                                 "field": DECOY["github_pat"]})),
                   env=env)
    s.check("an added entry carrying a credential VALUE is not let through",
            leaked.kind in ("deny", "rewrite"), True)

    # ── the refusal names no way to switch a guard off ───────────────────────
    refusal = drive(write(config, "{}"), env=env).message
    for spelling in ("keyless enable", "KEYLESS_HOOKS_DISABLE", "hooks.json",
                     "--config", "observe"):
        s.check("the declarations refusal names no remedy (%r)" % spelling,
                spelling in refusal, False)
    s.check_in("and it still says where the decision is made",
               "person's decision", refusal)

    # ── the control: a config.json the pack never reads ──────────────────────
    s.check("a config.json somewhere the pack never reads is silent",
            drive(write(os.path.join(root, "unrelated", "config.json"),
                        _plus(NEW_NAME=_NEW)), env=env).kind, "silent")
    s.check("and a non-additive write to it is silent too",
            drive(write(os.path.join(root, "unrelated", "config.json"), "{}"),
                  env=env).kind, "silent")


if __name__ == "__main__":
    raise SystemExit(0 if run().report() else 1)
