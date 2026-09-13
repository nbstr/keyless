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
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import Suite, bash, drive, fixtures, read, write  # noqa: E402


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


if __name__ == "__main__":
    raise SystemExit(0 if run().report() else 1)
