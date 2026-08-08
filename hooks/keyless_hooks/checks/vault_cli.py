"""KL-VAULT — a vault CLI verb that prints a plaintext value is refused.

This is the check that makes the pack store-agnostic. An injector alone is
theatre: the agent that cannot type the literal simply runs `op read`,
`infisical secrets get`, or `security find-generic-password -w` and gets the
same plaintext by another door. Every entry in the table is one of those doors.

Two disciplines carry the whole check:

**Read the subcommand, never the binary.** Every binary in the table has a
harmless sibling one word away — `op run` beside `op read`, `doppler secrets set`
beside `doppler secrets`, `vault kv put` beside `vault kv get`. A gate on the
binary blocks the working path, and a gate that blocks the working path is
uninstalled within a day.

**Anchor on the statement head.** `git commit -m "use op read for this"` names
the verb and performs nothing; the head there is `git`, so nothing fires. The
one case where a quoted string IS the act — `bash -c "op read …"` — is handled
by re-scanning what an interpreter was handed, not by widening the match.

**Match the VERB PATH, never the argument text.** A row's pattern is tested
against the leading flag-free run of words — `secrets folders get`, not
`secrets folders get --env=prod --path=/`. Matching the raw argument string is
what made a prefix rule refuse `infisical secrets folders get`, which lists
folder NAMES and prints no value at all. A subcommand path is structured, so it
is read as structure; the flag condition (a row's fourth element) is still
tested against the raw arguments, because that is what it is for.

**A help invocation prints documentation, never a value.** `infisical secrets
--help` and `railway variables --help` were both refused by the prefix rule, and
a gate that will not let an agent read a manual page is a gate that gets
switched off. `--help`, a bare `-h`, and a leading `help` word clear every row.
"""

import re

from ..shellview import head_of, interpreter_payloads, rest_after_head, statements, words

CHECK = "KL-VAULT"

# Compiled once per process. The table is small and the patterns are anchored, so
# the whole scan is a handful of failed matches on the first character.
_CACHE = {}


def _compiled(cfg):
    key = id(cfg)
    hit = _CACHE.get(key)
    if hit is not None:
        return hit
    table = {}
    for row in cfg.vault_verbs:
        if not isinstance(row, (list, tuple)) or len(row) < 3:
            continue
        binary, pattern, alternative = row[0], row[1], row[2]
        flag = row[3] if len(row) > 3 else None
        try:
            rx = re.compile(pattern)
            frx = re.compile(flag) if flag else None
        except re.error:
            # A user's bad pattern disables that row and nothing else. A config
            # error must never take out the checks that parsed fine.
            continue
        table.setdefault(binary, []).append((rx, frx, alternative, pattern))
    _CACHE.clear()
    _CACHE[key] = table
    return table


_HELP_FLAGS = frozenset(["--help", "-h", "-?", "help"])


def _unquote(tok):
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
        return tok[1:-1]
    return tok


def _tokens(rest):
    return [_unquote(rest[a:b]) for a, b in words(rest)]


def is_help(rest):
    """True when these arguments ask for documentation.

    `-h` is treated as help for every binary in this table. That is a tuned
    choice, not an oversight: across the fourteen stores here `-h` is either help
    or an unrecognised flag, and the cost of being wrong is one manual page
    printed instead of refused — against a measured cost of refusing `infisical
    secrets --help` twice in one session, which is how a pack gets uninstalled.
    A store where `-h` means something else must be spelled with its own row.
    """
    toks = _tokens(rest)
    for tok in toks:
        if tok in _HELP_FLAGS:
            return True
    for tok in toks:
        if not tok.startswith("-"):
            return tok == "help"
    return False


def verb_path(rest):
    """The leading flag-free subcommand path, space-joined.

    A `--flag=value` is self-contained, so collection continues past it and
    `infisical secrets --env=prod folders get` still reads as `secrets folders
    get`. A bare `-f` may or may not consume the next word, and nothing here can
    know which, so it ENDS the path — the words after it are unknowable as verbs.

    Ending the path is the safe direction. `infisical secrets --recursive get X`
    collapses to `secrets`, which the bare-`secrets` row refuses, because bare
    `infisical secrets` does print every value. Truncation therefore fails toward
    blocking on exactly the stores where the bare command is itself the leak.
    """
    out = []
    for tok in _tokens(rest):
        if tok.startswith("-"):
            if "=" in tok:
                continue
            break
        out.append(tok)
    return " ".join(out)


def run(payload, cfg):
    if payload.event != "PreToolUse" or payload.tool != "Bash":
        return None
    cmd = payload.command
    if not cmd or not cmd.strip():
        return None

    table = _compiled(cfg)
    texts = [cmd] + interpreter_payloads(cmd, cfg.interpreters)
    for text in texts:
        for stmt in statements(text):
            head = head_of(stmt)
            rows = table.get(head)
            if not rows:
                continue
            rest = rest_after_head(stmt)
            if is_help(rest):
                # Documentation, for any binary in the table. Costs one scan of a
                # handful of words and closes the whole `--help` false positive.
                continue
            path = verb_path(rest)
            for rx, frx, alternative, pattern in rows:
                if not rx.search(path):
                    continue
                if frx is not None and not frx.search(rest):
                    # The metadata-only spelling of the same subcommand.
                    continue
                return ("deny", _message(head, path, alternative),
                        {"binary": head, "pattern": pattern})
    return None


def _message(binary, path, alternative):
    # The first two words of the verb path, and never the raw arguments. One row
    # in the table takes a secret as a POSITIONAL argument — `pass-cli totp
    # generate <base32-secret>` — so echoing what the user typed would put the
    # credential in the very transcript this check exists to keep it out of.
    # Two words name every verb in the table and stop short of that operand.
    shown = " ".join(path.split()[:2])
    return (
        "[%s] `%s %s` prints a plaintext credential to stdout, which puts it in "
        "this transcript, in the scrollback, and in any log that captures tool "
        "output. Refused.\n\n"
        "Run the command that NEEDS the secret under keyless instead — the value "
        "reaches the child process and nothing else:\n"
        "    keyless run -s <NAME> -- <the command you were going to run>\n\n"
        "`keyless ls` lists the names it can resolve. This store's own safe verb "
        "is `%s`; that one is not blocked.\n\n"
        "There is no flag on this gate and no spelling of the print verb that "
        "passes. An operator can drop the rule by editing `vault_verbs` in "
        "~/.config/keyless/hooks.json, or disable the pack for a session with "
        "KEYLESS_HOOKS_DISABLE=1 in the settings file's `env` block — a session "
        "cannot set its own environment, which is the point."
        % (CHECK, binary, shown, alternative))
