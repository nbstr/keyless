"""Which statements a Bash call runs, as (head, arguments, verb path).

KL-VAULT and KL-RUNNER ask the same question of a command — which vault binary
does it invoke, with which subcommand — and differ only in the table they look
the answer up in. So the answer is computed here, once, from every text
`executed.command_texts` says the shell will run, plus the child command each
`keyless run … --` hands its process. The help exemption and the verb-path rule
live here for the same reason: a gate that disagreed with its sibling about what
`--help` means would refuse a manual page one of them had already cleared.
"""

from .executed import command_texts
from .shellview import head_of, rest_after_head, statements, words

__all__ = ["is_help", "verb_path", "per_config", "acts"]


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


def per_config(cache, cfg, build):
    """`build(cfg)`, computed once for as long as `cfg` is the config in use.

    Keyed on the Config OBJECT, which the cache holds, and never on `id(cfg)`.
    An id is recycled the moment its object is freed, so an id-keyed cache
    handed a second, different config the first one's table whenever the first
    had been collected — measured: a test building two configs in turn read the
    first config's row alternative out of the second's refusal, which made an
    arm about user rows unable to fail. Holding the object keeps its id unique.
    """
    if cache.get("cfg") is cfg:
        return cache["table"]
    table = build(cfg)
    cache.clear()
    cache["cfg"] = cfg
    cache["table"] = table
    return table


# The texts one tool call can run, as a bound on how far `_texts` follows
# `keyless run … -- <cmd>` delegations. Each delegation is a fresh command line.
_DELEGATION_LIMIT = 64


# `keyless` options that take a separate operand, globally or on `run`. A word
# after one of these is its value, never the child command.
_KEYLESS_VALUED = frozenset(["-s", "--secret", "--config", "--audit", "--env"])


def _keyless_run_tail(stmt):
    """The command `keyless run … [--] <cmd>` hands its child, or "".

    `keyless run -s X -- infisical run -- sh -c '…'` masks X and nothing the
    inner runner injects, and `keyless run -s X -- <print verb>` prints a value
    keyless never saw. Both are the act this module refuses, reached through the
    one spawn the refusal recommends — so the child command is read as a command
    line of its own rather than as arguments to `keyless`.
    """
    if head_of(stmt) != "keyless":
        return ""
    rest = rest_after_head(stmt)
    seen_run = False
    takes_value = False
    for start, end in words(rest):
        tok = rest[start:end]
        if takes_value:
            takes_value = False
            continue
        if tok == "--":
            return rest[end:].strip() if seen_run else ""
        if tok.startswith("-"):
            takes_value = tok in _KEYLESS_VALUED
            continue
        if not seen_run:
            if tok != "run":
                # A different keyless verb; nothing it runs is a child command.
                return ""
            seen_run = True
            continue
        return rest[start:].strip()
    return ""


def _texts(cmd, cfg):
    """Every command line this tool call runs, keyless-run children included."""
    out = []
    seen = set()
    pending = [cmd]
    while pending and len(out) < _DELEGATION_LIMIT:
        for text in command_texts(pending.pop(0), cfg.interpreters):
            if text in seen:
                continue
            seen.add(text)
            out.append(text)
            for stmt in statements(text):
                tail = _keyless_run_tail(stmt)
                if tail:
                    pending.append(tail)
    return out


def acts(payload, cfg):
    """(head, rest, verb path) for every statement this Bash call runs whose
    head could be a vault binary. Help invocations are dropped here, for every
    binary in both tables — a manual page is documentation, never a value."""
    if payload.event != "PreToolUse" or payload.tool != "Bash":
        return
    cmd = payload.command
    if not cmd or not cmd.strip():
        return
    for text in _texts(cmd, cfg):
        for stmt in statements(text):
            head = head_of(stmt)
            if not head:
                continue
            rest = rest_after_head(stmt)
            if is_help(rest):
                continue
            yield head, rest, verb_path(rest)
