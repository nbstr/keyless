#!/usr/bin/env python3
"""Merge the keyless hook pack into a Claude Code settings file, or remove it.

    python3 install.py                      into ~/.claude/settings.json
    python3 install.py --scope project      into ./.claude/settings.json
    python3 install.py --claude-dir DIR     into DIR/settings.json
    python3 install.py --dry-run            print the merged file, write nothing
    python3 install.py --uninstall          take it back out
    python3 install.py --list-backups       every backup this script has written

Usually reached as `keyless setup`, which resolves the directory, keeps the
receipt and reports the result alongside everything else it did. This runs
standalone too and behaves identically.

Three properties, each because the alternative loses a user's configuration:

**Never a blind overwrite.** The existing file is parsed, the pack's entries are
merged into it, and everything else is carried through untouched. A settings file
holds work nobody wants to re-do.

**A backup before every write**, named with a timestamp, next to the original.

**A re-parse before the file is replaced.** The merged text is written to a
temporary file, read back, and parsed as JSON; only then does it replace the
original, atomically. A settings file that does not parse disables every hook the
user has, which is the one failure mode worse than not installing.

Idempotent in both directions: installing twice changes nothing the second time,
and uninstalling something that is not installed is a no-op that says so.

**A RECEIPT, so removal is exact and re-installing does not overwrite a
decision.** Two faults live in an installer that matches against the list it
ships rather than a record of what it wrote, and both are silent:

    before install   permissions.allow = ["Bash(keyless ls:*)"]   <- the user's own
    install          already present, so nothing is added
    uninstall        the rule is in the shipped list, so it is REMOVED

The install was a no-op and the uninstall took away a rule this pack never put
there. Pointed the other way, the same missing record makes "never installed"
and "installed and then deliberately deleted" the same observation — an absent
rule — so every re-run silently puts back what somebody threw out.

So `merge` records exactly what it ADDED, `unmerge` removes exactly that, and a
re-run adds nothing it has already installed once. `--restore` is how somebody
asks for the deleted entries back; nothing does it on their behalf.

**Idempotent against a FOLDED install too.** Some estates keep one registered
handler per event and have that script invoke this pack rather than registering
it beside their own. The pack is fully live that way, but the registered command
names the forwarder, not `keyless_hook.py` — so a re-run used to add a second
registration and undo the arrangement. `merge` now also recognises a pack reached
through a forwarder; `unmerge` deliberately does NOT, so uninstalling never
deletes a script this pack does not own. See `_is_folded_in`.
"""

import argparse
import json
import os
import shlex
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FRAGMENT = os.path.join(HERE, "settings-fragment.json")
MARKER = "keyless_hook.py"


def settings_path(scope, claude_dir=None):
    if scope == "project":
        return os.path.join(os.getcwd(), ".claude", "settings.json")
    if scope == "project-local":
        return os.path.join(os.getcwd(), ".claude", "settings.local.json")
    base = claude_dir or os.environ.get("KEYLESS_CLAUDE_DIR") or os.path.join(
        os.path.expanduser("~"), ".claude")
    return os.path.join(base, "settings.json")


def receipt_path(explicit=None):
    """Where the record of this install lives.

    The same file `keyless` writes, resolved the same way, so a standalone run
    and a `keyless setup` run share one record rather than each keeping a
    private half of the truth.
    """
    if explicit:
        return explicit
    if os.environ.get("KEYLESS_RECEIPT"):
        return os.environ["KEYLESS_RECEIPT"]
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state")
    return os.path.join(state, "keyless", "setup-receipt.json")


def load_receipt(path):
    """The whole receipt, and this installer's slice of it.

    Every other key belongs to `keyless` itself and is carried through
    untouched. One writer per key is what stops two programs racing each other
    over the same file.
    """
    try:
        with open(path) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}, {}
    if not isinstance(data, dict):
        return {}, {}
    mine = data.get("claude")
    return data, mine if isinstance(mine, dict) else {}


def save_receipt(path, whole, mine):
    """Write the receipt back with `claude` replaced. Never raises."""
    whole = dict(whole)
    whole.setdefault("version", 1)
    if mine is None:
        whole.pop("claude", None)
    else:
        whole["claude"] = mine
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = "%s.keyless-tmp.%d" % (path, os.getpid())
        with open(tmp, "w") as fh:
            fh.write(json.dumps(whole, indent=2) + "\n")
        os.replace(tmp, path)
    except OSError as exc:
        # A receipt that cannot be written is worth saying out loud and is not
        # worth failing an install over: the merge already happened, and the
        # cost is a less exact uninstall rather than a broken settings file.
        sys.stderr.write("warning: could not write %s (%s). `--uninstall` will "
                         "fall back to the shipped list.\n" % (path, exc))


def load_fragment(hard_deny=False):
    with open(FRAGMENT) as fh:
        text = fh.read()
    # The hooks directory is resolved from this script's own location, so the
    # fragment carries no absolute path and the pack works from wherever it was
    # cloned. A hardcoded home directory is the reason most shipped hook configs
    # only work on their author's machine.
    data = json.loads(text.replace("__KEYLESS_HOOKS_DIR__", HERE))
    extra = data.pop("_keylessHardDeny", [])
    data.pop("_keylessComment", None)
    if hard_deny:
        data.setdefault("permissions", {}).setdefault("deny", []).extend(extra)
    return data


def load_settings(path):
    if not os.path.exists(path):
        return {}, False
    with open(path) as fh:
        text = fh.read()
    if not text.strip():
        return {}, True
    try:
        data = json.loads(text)
    except ValueError as exc:
        sys.stderr.write(
            "REFUSING TO TOUCH %s: it is not valid JSON (%s).\n"
            "Fix or move that file first — merging into a file this script "
            "cannot parse would mean rewriting it from scratch, and everything "
            "already in it would be lost.\n" % (path, exc))
        raise SystemExit(2)
    if not isinstance(data, dict):
        sys.stderr.write("REFUSING TO TOUCH %s: its top level is not an object.\n" % path)
        raise SystemExit(2)
    return data, True


def _has_our_handler(group):
    """Is the pack REGISTERED in this group — named directly by a command?

    This is the removal test, and it stays narrow on purpose. See `_is_folded_in`
    for why the install test is deliberately wider than this one.
    """
    for handler in group.get("hooks", []):
        if isinstance(handler, dict) and MARKER in str(handler.get("command", "")):
            return True
    return False


def _handler_script(command):
    """The file a registered command actually runs, or "" if none resolves."""
    try:
        parts = shlex.split(str(command))
    except ValueError:
        parts = str(command).split()
    for part in parts:
        candidate = os.path.expanduser(part)
        if os.path.isfile(candidate):
            return candidate
    return ""


def _is_folded_in(group, limit=200000):
    """Is the pack already REACHED from this group — run by somebody's script?

    An estate that keeps one handler per event does not register this pack
    beside its own. It registers ONE forwarder and has that script invoke this
    pack, which is a perfectly good installation: the hook still runs, on every
    event it asked for. But the registered command is the forwarder's path and
    contains no `keyless_hook.py`, so `_has_our_handler` says "not installed" and
    `merge` adds a SECOND registration — undoing the arrangement every time
    anyone re-runs the installer, and leaving a rival behind on an event whose
    owner had deliberately consolidated it.

    ⚠️ THE ASYMMETRY IS THE SAFETY PROPERTY, NOT AN OVERSIGHT. `merge` tests
    `_has_our_handler OR _is_folded_in`; `unmerge` tests `_has_our_handler`
    ALONE. Widening the removal test the same way would make `--uninstall`
    delete somebody else's forwarder — a script this pack does not own, whose
    other passengers would go down with it and whose absence takes that estate's
    whole chain for the event with it. Uninstalling must never remove a file's
    registration because that file mentions us.

    The alternative — writing `keyless_hook.py` into the forwarder's registered
    command so the existing narrow test matches — was rejected for exactly that
    reason: it makes the re-add stop and makes `--uninstall` destructive.

    Reading is bounded and never raises: an unreadable or enormous handler is
    simply not recognised as a fold, which fails toward re-adding a registration
    (noisy, and reported) rather than toward silently skipping an install.
    """
    for handler in group.get("hooks", []):
        if not isinstance(handler, dict):
            continue
        script = _handler_script(handler.get("command", ""))
        if not script:
            continue
        try:
            with open(script, errors="replace") as fh:
                if MARKER in fh.read(limit):
                    return True
        except OSError:
            continue
    return False


def merge(settings, fragment, record=None, restore=False):
    """Return (merged, [what changed], record). `settings` is not mutated.

    `record` is what this pack has installed here before. Its two jobs are
    opposite and both are load-bearing:

    - an entry it names is **never re-added**, however absent it is. Somebody
      deleted it on purpose, and an installer that silently puts a deletion back
      is overwriting a decision. `restore` is how that is asked for out loud.
    - an entry it names is the **only** thing `unmerge` may remove. See the
      module docstring for the measured shape of getting that wrong.

    It grows monotonically until an uninstall clears it, so "installed once and
    since deleted" stays distinguishable from "never installed".
    """
    out = json.loads(json.dumps(settings))
    record = dict(record or {})
    changes = []
    skipped = []
    known_events = list(record.get("events", []))

    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        sys.stderr.write("REFUSING: `hooks` in the settings file is not an object.\n")
        raise SystemExit(2)

    for event, groups in fragment.get("hooks", {}).items():
        existing = hooks.setdefault(event, [])
        if not isinstance(existing, list):
            sys.stderr.write("REFUSING: `hooks.%s` is not a list.\n" % event)
            raise SystemExit(2)
        # Registered directly, OR already reached from somebody's forwarder.
        # The second test is what stops a re-run undoing a consolidated estate;
        # `unmerge` deliberately does not share it. See `_is_folded_in`.
        if any(isinstance(g, dict) and (_has_our_handler(g) or _is_folded_in(g))
               for g in existing):
            if event not in known_events:
                known_events.append(event)
            continue
        if event in known_events and not restore:
            skipped.append("a %s handler you removed" % event)
            continue
        existing.extend(groups)
        changes.append("added a %s handler" % event)
        if event not in known_events:
            known_events.append(event)

    # `setdefault` above creates an empty list for every event it looked at, so
    # a run that adds nothing would otherwise leave `"hooks": {"PreToolUse": []}`
    # behind — a key the file never had, added by a no-op.
    for event in [event for event, groups in hooks.items() if not groups]:
        del hooks[event]
    if not hooks:
        del out["hooks"]
    record["events"] = known_events

    for verdict in PERMISSION_LISTS:
        record[verdict] = _add_rules(out, fragment, verdict, changes, skipped,
                                     list(record.get(verdict, [])), restore)

    if skipped:
        changes.append("left alone: %s" % "; ".join(skipped))
    return out, changes, record


# The permission lists this pack owns, in both directions. One tuple rather than
# two hand-written blocks per direction: a list added by `merge` and forgotten by
# `unmerge` is a rule an uninstall leaves behind, which is the failure an
# uninstaller exists to prevent.
PERMISSION_LISTS = ("allow", "deny")


def _add_rules(out, fragment, verdict, changes, skipped, known, restore):
    """Merge `permissions.<verdict>` into `out` in place; return the new record.

    A rule already in the file is recorded as ours ONLY if it was already in
    `known` — a rule the user wrote first stays theirs, which is the whole
    reason an uninstall can no longer take it away.
    """
    rules = fragment.get("permissions", {}).get(verdict, [])
    if not rules:
        return known
    perms = out.setdefault("permissions", {})
    if not isinstance(perms, dict):
        sys.stderr.write("REFUSING: `permissions` is not an object.\n")
        raise SystemExit(2)
    existing = perms.setdefault(verdict, [])
    if not isinstance(existing, list):
        sys.stderr.write("REFUSING: `permissions.%s` is not a list.\n" % verdict)
        raise SystemExit(2)

    added = []
    for rule in rules:
        if rule in existing:
            continue
        if rule in known and not restore:
            skipped.append("a %s rule you removed" % verdict)
            continue
        existing.append(rule)
        added.append(rule)
    if added:
        changes.append("added %d permission %s rule(s)" % (len(added), verdict))
    if not existing:
        del perms[verdict]
    if not perms:
        del out["permissions"]
    return known + [rule for rule in added if rule not in known]


def _remove_rules(out, verdict, ours, changes):
    """Take back exactly the `permissions.<verdict>` rules we installed."""
    ours = set(ours)
    if not ours:
        return
    perms = out.get("permissions")
    if not (isinstance(perms, dict) and isinstance(perms.get(verdict), list)):
        return
    kept = [rule for rule in perms[verdict] if rule not in ours]
    removed = len(perms[verdict]) - len(kept)
    if removed:
        changes.append("removed %d permission %s rule(s)" % (removed, verdict))
    if kept:
        perms[verdict] = kept
    else:
        del perms[verdict]


def unmerge(settings, record):
    """Remove exactly what `record` says this pack installed.

    ⚠️ **`record` is the whole authority, and the shipped fragment is not
    consulted at all.** Matching against the fragment removes a rule the user
    wrote before the install — the pack never added it, the install correctly
    left it alone, and the uninstall deleted it anyway.

    With no record — a settings file merged by an older version of this script,
    or one whose receipt was lost — the caller falls back to the fragment and
    SAYS so, because removing nothing is its own kind of wrong.
    """
    out = json.loads(json.dumps(settings))
    changes = []
    events = set(record.get("events", []))

    hooks = out.get("hooks")
    if isinstance(hooks, dict):
        for event in list(hooks):
            if event not in events:
                continue
            groups = hooks.get(event)
            if not isinstance(groups, list):
                continue
            # The narrow test on purpose: a handler that merely REACHES this
            # pack through somebody's forwarder is their script, and removing
            # its registration takes every other passenger down with it.
            kept = [g for g in groups if not (isinstance(g, dict) and _has_our_handler(g))]
            if len(kept) != len(groups):
                changes.append("removed a %s handler" % event)
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
        if not hooks:
            del out["hooks"]

    for verdict in PERMISSION_LISTS:
        _remove_rules(out, verdict, record.get(verdict, []), changes)
    if out.get("permissions") == {}:
        del out["permissions"]

    return out, changes


def write_atomically(path, data):
    """Write, re-parse the written bytes, and only then replace the original."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    tmp = "%s.keyless-tmp.%d" % (path, os.getpid())
    with open(tmp, "w") as fh:
        fh.write(text)
    try:
        with open(tmp) as fh:
            json.loads(fh.read())
    except ValueError as exc:
        os.unlink(tmp)
        sys.stderr.write("ABORTED: the merged settings did not re-parse (%s). "
                         "Your file is untouched.\n" % exc)
        raise SystemExit(3)
    os.replace(tmp, path)


def backup(path):
    if not os.path.exists(path):
        return None
    stamp = time.strftime("%Y%m%dT%H%M%S")
    dest = "%s.keyless-backup-%s" % (path, stamp)
    # Two writes in the same second must not collide: an install immediately
    # followed by an uninstall would otherwise overwrite the only copy of the
    # user's original file with the copy taken after it was modified.
    n = 1
    while os.path.exists(dest):
        dest = "%s.keyless-backup-%s.%d" % (path, stamp, n)
        n += 1
    shutil.copy2(path, dest)
    return dest


def list_backups(path):
    directory = os.path.dirname(path) or "."
    base = os.path.basename(path) + ".keyless-backup-"
    try:
        names = sorted(n for n in os.listdir(directory) if n.startswith(base))
    except OSError:
        names = []
    if not names:
        print("no backups next to %s" % path)
        return 0
    for name in names:
        print(os.path.join(directory, name))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", default="user",
                    choices=["user", "project", "project-local"],
                    help="user: ~/.claude/settings.json (default). "
                         "project: ./.claude/settings.json, committable. "
                         "project-local: ./.claude/settings.local.json, gitignored.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the merged file and write nothing")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--list-backups", action="store_true")
    ap.add_argument("--hard-deny", action="store_true",
                    help="also deny .env, .npmrc, .netrc, .pgpass and *.pem at the "
                         "permission layer. Stronger, and it COSTS the names view: a "
                         "permission deny pre-empts the hook's rewrite, so the agent "
                         "is told the read was refused instead of which names the "
                         "file declares. Use --uninstall --hard-deny to remove both.")
    ap.add_argument("--claude-dir", default=None, metavar="DIR",
                    help="the agent's configuration directory, holding settings.json. "
                         "Defaults to ~/.claude. Named rather than assumed: an install "
                         "into a file the harness never opens reports success and "
                         "guards nothing.")
    ap.add_argument("--receipt", default=None, metavar="PATH",
                    help="the record of what was installed, so removal is exact and a "
                         "re-run does not put back what you deleted.")
    ap.add_argument("--restore", action="store_true",
                    help="re-add entries a previous install added and you have since "
                         "removed. Without this they stay removed.")
    ap.add_argument("--create-dir", action="store_true",
                    help="create the agent directory if it does not exist. Without "
                         "this, a machine with no agent harness is reported and "
                         "skipped rather than having one invented for it.")
    ap.add_argument("--report", action="store_true",
                    help="one line per change and nothing else. What `keyless setup` "
                         "passes, because it prints its own closing notes.")
    args = ap.parse_args()

    path = settings_path(args.scope, args.claude_dir)
    if args.list_backups:
        return list_backups(path)

    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory) and not args.create_dir:
        # `keyless` is a general tool and most machines running it have no agent
        # harness at all. Creating another program's configuration directory on
        # the chance it might want one is the same overreach as editing a config
        # nobody asked us to. Reported, skipped, exit 0 — not a failure.
        print("%s does not exist, so there is no agent harness here to register "
              "the pack in. Nothing was written." % directory)
        print("Pass --create-dir, or --claude-dir DIR, if that is wrong.")
        return 0

    receipt_file = receipt_path(args.receipt)
    whole, record = load_receipt(receipt_file)
    fragment = load_fragment(hard_deny=args.hard_deny)
    settings, existed = load_settings(path)

    if args.uninstall:
        if not record:
            # No record: an older install, or a lost receipt. Fall back to the
            # shipped list and say so, because this is the one path that can
            # remove a rule the user wrote themselves.
            record = {"events": list(fragment.get("hooks", {})),
                      "allow": list(fragment.get("permissions", {}).get("allow", [])),
                      "deny": list(fragment.get("permissions", {}).get("deny", []))}
            sys.stderr.write(
                "note: no install record at %s, so removal falls back to the "
                "shipped list. A rule you wrote yourself that happens to match "
                "it will be removed too.\n" % receipt_file)
        merged, changes = unmerge(settings, record)
        new_record = None
    else:
        merged, changes, new_record = merge(settings, fragment, record,
                                            restore=args.restore)
        new_record["settings"] = path
        new_record["created"] = not existed

    if not changes:
        print("%s: nothing to do (%s)."
              % (path, "already uninstalled" if args.uninstall else "already installed"))
        if not args.uninstall and new_record is not None:
            save_receipt(receipt_file, whole, new_record)
        return 0

    if args.dry_run:
        print(json.dumps(merged, indent=2))
        sys.stderr.write("\n(dry run — %s would change: %s)\n" % (path, "; ".join(changes)))
        return 0

    saved = backup(path) if existed else None
    write_atomically(path, merged)
    save_receipt(receipt_file, whole, new_record)
    print("%s: %s" % (path, "; ".join(changes)))
    if saved:
        print("backup: %s" % saved)
    if not args.uninstall and not args.report:
        print("\nThe harness re-reads this file while a session is running, so the pack")
        print("is live now. Run `/hooks` to confirm it loaded. Two levers, both out of")
        print("an agent's reach because a session cannot set its own environment —")
        print("put them in this file's `env`:")
        print('  "env": { "KEYLESS_HOOKS_OBSERVE": "1" }   record, never block')
        print('  "env": { "KEYLESS_HOOKS_DISABLE": "1" }   off entirely')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
