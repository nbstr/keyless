"""What keyless will actually SERVE a name, read the way `keyless ls` reads it.

`secretpaths.names_in` returns every key a protected file *declares* — strings
the file itself chose, with no relation to what keyless is configured to do
with them. A file's own `DIRECT_URL` or `FRONTEND_PORT` is not evidence that
keyless can resolve a name spelled that way; some of those keys are runtime
values an application reads, not developer-tooling credentials at all. This
module answers the question a remedy actually needs: for one such name, is it
SERVABLE, NOT_SERVABLE, or — because the daemon could not be asked — UNKNOWN.

Two sources feed the answer, the same two `keyless ls` reads:

    declared    this session's own config, the `secrets` map — free, no
                socket touched.
    daemon      only where `stores.daemon.enabled` is true: what
                `keylessd` will serve, over `Op::Names`.

# Why this is a small client of its own, not a call to `keyless ls`

`keyless ls` asks the daemon on the CLI's own configured `timeout_ms`
(3000ms by default), which is sized for a `resolve` that may cost a live
vendor call. `Op::Names` costs none — it answers from the daemon's in-memory
catalogue — so a guard sitting in front of every protected file access must
not inherit a ceiling built for the slow case. [`_GUARD_DEADLINE_S`] is this
module's own, far shorter, and it is what keeps a wedged daemon from turning
into noticeable latency on every read this pack refuses.

# The three-way answer, and why UNKNOWN is not NOT_SERVABLE

A daemon that does not answer within the deadline has told this module
nothing about what it would have served — [`crate::store::daemon`]'s own
invariant is that killing or starving the daemon can only ever narrow what a
caller learns, never widen it. Reporting such a name as "keyless cannot
serve this" would assert something this call never actually found out, which
is the exact failure this module exists to stop repeating.
"""

import json
import os
import socket
import time

__all__ = ["SERVABLE", "NOT_SERVABLE", "UNKNOWN", "Served", "served", "classify",
           "advice_lines"]

SERVABLE = "servable"
NOT_SERVABLE = "not_servable"
UNKNOWN = "unknown"

# How long this module waits for keylessd to answer `Op::Names`, in seconds.
#
# Deliberately far below the daemon client's own configured `timeout_ms`
# (3000ms by default) for the reason in the module docstring: a listing needs
# no vendor call, so a live daemon answers in well under a millisecond, and
# 200ms already generously covers a daemon that is momentarily busy. Past
# this the daemon is behaving abnormally, and a guard that runs on every
# protected file access must degrade rather than hold the tool call up for it.
_GUARD_DEADLINE_S = 0.2

_DEFAULT_SOCKET = "/usr/local/var/run/keyless/keylessd.sock"


def _config_path():
    override = os.environ.get("KEYLESS_CONFIG")
    if override:
        return override
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "keyless", "config.json")


def _load_config():
    """`(declared_names, daemon_settings)`.

    `daemon_settings` is `None` when the daemon is not in play here — not
    configured, or explicitly disabled — which means `declared_names` is the
    whole answer, exactly as it is for `keyless ls` on a machine with no
    daemon. Any failure to read or parse the config (absent, malformed, not
    an object) is the same as an empty one: fail open toward "nothing
    declared", never toward a guess.
    """
    try:
        with open(_config_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return frozenset(), None
    if not isinstance(data, dict):
        return frozenset(), None
    secrets = data.get("secrets")
    declared = frozenset(secrets.keys()) if isinstance(secrets, dict) else frozenset()
    stores = data.get("stores")
    daemon = stores.get("daemon") if isinstance(stores, dict) else None
    if not isinstance(daemon, dict) or not daemon.get("enabled"):
        return declared, None
    return declared, daemon


def _socket_path(daemon_settings):
    override = os.environ.get("KEYLESS_SOCKET")
    if override:
        return override
    configured = daemon_settings.get("socket")
    if isinstance(configured, str) and configured:
        # `src/paths.rs`'s `ConfigPath::expand` resolves a leading `~/` against
        # `$HOME` at parse time, so the in-memory value the daemon itself uses
        # is never the literal string in the file. A socket declared that way
        # is an ordinary operator config, not an edge case, so this mirrors
        # only that one expansion — a `$`-prefixed value is refused there
        # rather than expanded, and passing it through unexpanded here just
        # fails to connect, which degrades the same way any other bad path
        # does.
        return os.path.expanduser(configured) if configured.startswith("~") else configured
    return _DEFAULT_SOCKET


def _ask_daemon(socket_path):
    """The names `Op::Names` answers with, or `None` on any failure.

    Never raises. An absent socket, a refused connection, a daemon that never
    answers within the deadline, or a malformed reply all come back the same
    way: `None`. There is no path here that returns a name the daemon did not
    actually send, and no path that reads a value — the request carries none
    and `Reply::Info` has no field that could hold one.
    """
    request = (json.dumps({
        "v": 1, "op": "names", "name": "", "cwd": "", "argv": [], "progress": False,
    }) + "\n").encode("utf-8")
    deadline = time.monotonic() + _GUARD_DEADLINE_S
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(_GUARD_DEADLINE_S)
            sock.connect(socket_path)
            sock.sendall(request)
            chunks = []
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                sock.settimeout(remaining)
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        line = b"".join(chunks).split(b"\n", 1)[0]
        if not line:
            return None
        reply = json.loads(line)
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(reply, dict) or reply.get("status") != "info":
        return None
    names = reply.get("names")
    if not isinstance(names, list):
        return None
    return frozenset(n for n in names if isinstance(n, str))


class Served(object):
    """What this call learned about what keyless will serve.

    `names` is names only, never a value or a coordinate — the same boundary
    [`crate::store::catalogue`] holds on the daemon's own side. `complete` is
    false only when a daemon that IS in play did not answer in time, which is
    the one case where an absent name means "not yet known" rather than
    "not servable".
    """

    __slots__ = ("names", "complete")

    def __init__(self, names, complete):
        self.names = names
        self.complete = complete


def served():
    """Ask what keyless will serve, on this module's own bounded terms."""
    declared, daemon_settings = _load_config()
    if daemon_settings is None:
        return Served(declared, complete=True)
    daemon_names = _ask_daemon(_socket_path(daemon_settings))
    if daemon_names is None:
        return Served(declared, complete=False)
    return Served(declared | daemon_names, complete=True)


def classify(name, served_result):
    """SERVABLE, NOT_SERVABLE, or UNKNOWN for one name against one `Served`."""
    if name in served_result.names:
        return SERVABLE
    if served_result.complete:
        return NOT_SERVABLE
    return UNKNOWN


def advice_lines(names, served_result):
    """One line of remedy per name, each true on its own terms and carrying no
    leading indentation — a caller places each line inside its own layout.

    The one place this wording is written, so a check that lists names never
    invents its own claim about what keyless will do with one — see the
    module docstring for why a CANNOT-serve verdict and a DID-NOT-ASK verdict
    are different sentences.
    """
    lines = []
    for name in names:
        verdict = classify(name, served_result)
        if verdict == SERVABLE:
            lines.append("keyless run -s %s -- <the command that needs it>" % name)
        elif verdict == NOT_SERVABLE:
            lines.append(
                "%s — keyless does not serve this name: it is declared "
                "nowhere and minted by no enumerated vault item. If it is a "
                "credential, declare it under `secrets` or add it to the "
                "vault so keyless can serve it. If it is not a "
                "developer-tooling credential at all — a port, a URL, a "
                "value your deployed application reads at runtime — keyless "
                "is the wrong tool for it." % name)
        else:
            lines.append(
                "%s — the daemon did not answer in time, so keyless "
                "cannot say whether this name is servable. `keyless run -s "
                "%s` will say so directly; this refusal does not." % (name, name))
    return lines
