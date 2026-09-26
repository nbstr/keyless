"""KL-VAULT — a vault CLI verb that prints a plaintext value is refused.

This is the check that makes the pack store-agnostic. An injector alone is
theatre: the agent that cannot type the literal simply runs `op read`,
`infisical secrets get`, or `security find-generic-password -w` and gets the
same plaintext by another door. Every entry in the table is one of those doors.

Two disciplines carry the whole check:

**Read the subcommand, never the binary.** Every binary in the table has a
harmless sibling one word away — `op item list` beside `op item get`, `doppler
secrets set` beside `doppler secrets`, `vault kv put` beside `vault kv get`. A
store's RUNNER is not one of them: it hands the value to a child whose output
nothing filters, and `checks/vendor_runner` refuses it. A gate on the
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

from ..shellview import head_of, rest_after_head, statements
from ..vaultscan import acts, is_help, per_config, verb_path  # noqa: F401  (is_help: public API)
from .vendor_runner import RECIPES, runner_hit


CHECK = "KL-VAULT"


# Compiled once per config. The table is small and the patterns are anchored, so
# the whole scan is a handful of failed matches on the first character.
_CACHE = {}


def _compiled(cfg):
    return per_config(_CACHE, cfg, _build_vault_table)


def _build_vault_table(cfg):
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
    return table


def run(payload, cfg):
    table = _compiled(cfg)
    for head, rest, path in acts(payload, cfg):
        rows = table.get(head)
        if not rows:
            continue
        for rx, frx, alternative, pattern in rows:
            if not rx.search(path):
                continue
            if frx is not None and not frx.search(rest):
                # The metadata-only spelling of the same subcommand.
                continue
            return ("deny", _message(head, path, _safe_alternative(alternative, cfg)),
                    {"binary": head, "pattern": pattern})
    return None


def _safe_alternative(alternative, cfg):
    """The row's alternative, or "" when it is empty, not a string, or a verb
    KL-RUNNER refuses. A refusal that recommends a spawn with no output
    protection is how an agent was walked from a blocked print verb to a leak;
    a user-configured row must not be able to reintroduce that sentence."""
    if not isinstance(alternative, str) or not alternative.strip():
        return ""
    for stmt in statements(alternative):
        head = head_of(stmt)
        if head and runner_hit(head, verb_path(rest_after_head(stmt)), cfg):
            return ""
    return alternative.strip()


def _message(binary, path, alternative):
    # The first two words of the verb path, and never the raw arguments. One row
    # in the table takes a secret as a POSITIONAL argument — `pass-cli totp
    # generate <base32-secret>` — so echoing what the user typed would put the
    # credential in the very transcript this check exists to keep it out of.
    # Two words name every verb in the table and stop short of that operand.
    shown = " ".join(path.split()[:2])
    extra = ""
    if alternative:
        extra = ("The verb beside this one that answers the adjacent question and "
                 "prints no value:\n    %s\n\n" % alternative)
    return (
        "[%s] `%s %s` prints a plaintext credential to stdout, which puts it in "
        "this transcript, in the scrollback, and in any log that captures tool "
        "output. Refused.\n\n"
        "%s%s\n\n"
        "There is no flag on this gate and no spelling of the print verb that "
        "passes, and the store's own runner is refused too. The person running "
        "this session can change the rule in ~/.config/keyless/hooks.json, which "
        "is not writable from inside a session."
        % (CHECK, binary, shown, extra, RECIPES))
