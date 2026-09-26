"""KL-RUNNER — a vendor runner spawned from an agent shell is refused.

`infisical run`, `op run`, `pass-cli run`, `doppler run`, `railway run`: each
fetches a store's values and spawns a command with them in its environment, and
each hands the command's output straight back to whoever ran it. The runner
prints nothing itself, which is why it was once recommended as the safe sibling
of every print verb — and on 2026-09-26 that recommendation walked an agent to
`${VAR:-ABSENT}`, which printed four live keys into its transcript.

`keyless run` is the one spawn a session is pointed at instead. It masks both
streams, the value's encodings, and a value split across writes. The recipes
below, which both vault gates end their refusals on, answer what the agent was
actually asking — is it set, how long, is it the same in two places — with a
verdict and never a value.
"""

import re

from ..vaultscan import acts, per_config


CHECK = "KL-RUNNER"


_RUNNER_CACHE = {}


def _runners(cfg):
    return per_config(_RUNNER_CACHE, cfg, _build_runner_table)


def _build_runner_table(cfg):
    table = {}
    for row in cfg.vendor_runners:
        if not isinstance(row, (list, tuple)) or len(row) < 2:
            continue
        try:
            rx = re.compile(row[1])
        except re.error:
            continue
        table.setdefault(row[0], []).append((rx, row[1]))
    return table


def runner_hit(head, path, cfg):
    for rx, pattern in _runners(cfg).get(head, ()):
        if rx.search(path):
            return pattern
    return None


def run(payload, cfg):
    """KL-RUNNER — a vendor runner spawned from an agent shell is refused.

    A runner prints nothing itself. It hands the store's values to a child whose
    output reaches the transcript unfiltered, so the leak is whatever the child
    prints — and a presence check spelled `${VAR:-ABSENT}` prints the value.
    """
    for head, _rest, path in acts(payload, cfg):
        pattern = runner_hit(head, path, cfg)
        if pattern:
            return ("deny", _runner_message(head),
                    {"binary": head, "pattern": pattern})
    return None


# The recipes both refusals end on. They answer the questions an agent refused a
# print verb is actually asking — is it set, how long, is it the same value in two
# places — with nothing but a verdict reaching the output, and under `keyless
# run`, whose masking is the backstop if the child prints the value anyway.
RECIPES = (
    "To use a secret, run the command that needs it under keyless. The value "
    "reaches that process and nothing else, and keyless redacts it — and its "
    "base64, hex, URL and JSON forms — from both stdout and stderr:\n"
    "    keyless run -s <NAME> -- <the command you were going to run>\n\n"
    "To check whether it is set, and how long it is, without printing it:\n"
    "    keyless run -s A=<NAME> -- sh -c '[ -n \"$A\" ] && echo \"set, ${#A} chars\" "
    "|| echo unset'\n"
    "To check whether two environments hold the same value, without printing "
    "either — an unresolved name is reported as unset, never as a match:\n"
    "    keyless run --env <one> -s A=<NAME> -- keyless run --env <two> -s B=<NAME> "
    "-- sh -c 'if [ -z \"$A\" ] || [ -z \"$B\" ]; then echo \"unset: A=${A:+set} "
    "B=${B:+set}\"; elif [ \"$A\" = \"$B\" ]; then echo identical; else echo "
    "different; fi'\n\n"
    "`keyless ls` lists the names keyless can resolve. A name it cannot resolve "
    "is not reachable from this session by another route: declaring it is for "
    "the person running the session.")


def _runner_message(binary):
    return (
        "[%s] `%s run` spawns a command with this store's values in its "
        "environment and passes the command's output straight into this "
        "transcript. Whatever the command prints lands here in plaintext — a "
        "debug line, an error that quotes its config, or a presence check spelled "
        "`${VAR:-unset}`, which prints the value whenever it is set. Refused.\n\n"
        "%s\n\n"
        "The person running this session can change the rule in "
        "~/.config/keyless/hooks.json, which is not writable from inside a session."
        % (CHECK, binary, RECIPES))
