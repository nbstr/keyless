"""KL-FILE / KL-DEST: the remedy names what keyless will actually serve.

Before this suite, `_deny_text` and the names-only view offered
`keyless run -s <NAME>` for every key a `.env`-shaped file happened to
declare, whether or not keyless had ever heard of it. This drives the real
hook — bytes on stdin, JSON on stdout — against a fixture file whose names
are deliberately a mix: one declared locally, one minted by a stand-in
daemon, one neither, so the three-way answer (`served.SERVABLE`,
`NOT_SERVABLE`, `UNKNOWN`) is asserted the same way every other check in this
pack is: by driving the subprocess and reading what it actually says, never
by calling `served.py` in-process.

The stand-in daemon is a real `AF_UNIX` listener speaking the exact wire
shape `src/ipc/protocol.rs` decodes — one JSON line in, one out — so this
suite also pins the byte contract between the two languages: if the Rust
side's `Op`/`Reply` spelling ever drifts, the request this file asserts on
stops matching and the suite catches it before a real daemon does.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import Suite, bash, drive, keyless_config, read, write  # noqa: E402

# The guard's own deadline (`served._GUARD_DEADLINE_S`), doubled, plus room
# for process start-up. A wedged daemon that cost the guard anywhere near
# this long would be the latency risk the design was written to rule out.
_LATENCY_CEILING_S = 1.0


def _write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def _short_socket_path(tag):
    # Deliberately under `/tmp`, never under the scratch directory that owns
    # the rest of a test's fixtures: `sockaddr_un.sun_path` is 104 bytes on
    # macOS and a path built from a `tempfile.mkdtemp()` root routinely runs
    # past that, which fails as a platform quirk rather than as a test result.
    # See `tests/support/short_socket.rs` on the Rust side of this same fact.
    return "/tmp/klhooktest-%d-%s.sock" % (os.getpid(), tag)


class FakeDaemon(object):
    """A one-shot stand-in for `keylessd`, answering one `Op::Names` request.

    Speaks the exact wire shape `Request`/`Reply` decode in
    `src/ipc/protocol.rs`: one JSON object, one newline, in each direction.
    Never asked to resolve a value, never capable of sending one.
    """

    def __init__(self, tag, names=(), delay=0.0, respond=True):
        self.path = _short_socket_path(tag)
        try:
            os.unlink(self.path)
        except OSError:
            pass
        self._names = list(names)
        self._delay = delay
        self._respond = respond
        self.received = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        self._server.listen(1)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            self._server.settimeout(5)
            conn, _ = self._server.accept()
        except OSError:
            return
        try:
            conn.settimeout(5)
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            self.received.append(buf.split(b"\n", 1)[0])
            if self._delay:
                time.sleep(self._delay)
            if self._respond:
                reply = (json.dumps(
                    {"v": 1, "status": "info", "names": self._names}) + "\n")
                conn.sendall(reply.encode("utf-8"))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        try:
            self._server.close()
        except OSError:
            pass
        self._thread.join(timeout=5)
        try:
            os.unlink(self.path)
        except OSError:
            pass


def run():
    s = Suite("test_daemon_advice")
    tmp = tempfile.mkdtemp(prefix="keyless-daemon-advice-")

    # ── no daemon in play: declared config alone decides ────────────────────
    root = os.path.join(tmp, "declared-only")
    _write_file(os.path.join(root, ".env"),
               "GITHUB_TOKEN=whatever\nFRONTEND_PORT=whatever\n")
    cfg = keyless_config(os.path.join(tmp, "declared-only-cfg", "config.json"),
                         secrets=["GITHUB_TOKEN"])
    env = {"KEYLESS_CONFIG": cfg}

    v = drive(bash("cat %s/.env" % root, cwd=root), env=env)
    s.check("declared name: deny fires", v.kind, "deny")
    s.check_in("declared name: offers the run command",
              "keyless run -s GITHUB_TOKEN --", v.message)
    s.check("undeclared name: no run command offered for it",
           "keyless run -s FRONTEND_PORT" in v.message, False)
    s.check_in("undeclared name: says plainly keyless does not serve it",
              "FRONTEND_PORT — keyless does not serve this name", v.message)
    s.check("no value ever appears in the remedy",
           "whatever" in v.message, False)

    # ── a real daemon, reachable and enumerating ─────────────────────────────
    daemon_root = os.path.join(tmp, "daemon-yes")
    _write_file(os.path.join(daemon_root, ".env"),
               "MINTED_ONLY=whatever\nNOBODY_KNOWS_THIS=whatever\n")
    daemon = FakeDaemon("reachable", names=["MINTED_ONLY"])
    try:
        cfg = keyless_config(
            os.path.join(tmp, "daemon-yes-cfg", "config.json"),
            daemon={"enabled": True, "socket": daemon.path, "timeout_ms": 3000})
        env = {"KEYLESS_CONFIG": cfg}

        v = drive(read(os.path.join(daemon_root, ".env"), cwd=daemon_root), env=env)
        s.check("daemon-served name: Read is rewritten", v.kind, "rewrite")
        view = ""
        if v.updated and v.updated.get("file_path"):
            with open(v.updated["file_path"]) as fh:
                view = fh.read()
        s.check_in("daemon-served name: view offers the run command",
                  "keyless run -s MINTED_ONLY --", view)
        s.check_in("daemon-absent name: view says keyless does not serve it",
                  "NOBODY_KNOWS_THIS — keyless does not serve this name", view)

        s.check("the guard asked the daemon exactly once",
               len(daemon.received), 1)
        sent = json.loads(daemon.received[0]) if daemon.received else {}
        s.check("the request names the Names op", sent.get("op"), "names")
        s.check("the request carries the protocol version", sent.get("v"), 1)
        s.check("the request asks for no heartbeat", sent.get("progress"), False)
    finally:
        daemon.stop()

    # ── a daemon that is enabled but not answering (no listener at all) ──────
    root = os.path.join(tmp, "daemon-absent")
    _write_file(os.path.join(root, ".env"), "UNCONFIRMED=whatever\n")
    cfg = keyless_config(
        os.path.join(tmp, "daemon-absent-cfg", "config.json"),
        daemon={"enabled": True, "socket": _short_socket_path("nolisten"),
               "timeout_ms": 3000})
    env = {"KEYLESS_CONFIG": cfg}
    started = time.monotonic()
    v = drive(bash("cat %s/.env" % root, cwd=root), env=env)
    elapsed = time.monotonic() - started
    s.check("daemon absent: deny still fires", v.kind, "deny")
    s.check_in("daemon absent: says it could not be asked",
              "UNCONFIRMED — the daemon did not answer in time", v.message)
    s.check("daemon absent: never claims the name is unservable",
           "UNCONFIRMED — keyless does not serve this name" in v.message, False)
    s.check("daemon absent: stays well under the latency ceiling",
           elapsed < _LATENCY_CEILING_S, True)

    # ── a daemon that accepts the connection and then says nothing ──────────
    # The case that actually proves the GUARD owns the deadline: the config
    # below claims a 10-second `timeout_ms`, and if the guard read that value
    # instead of its own short one, this case would hang for seconds.
    wedged = FakeDaemon("wedged", delay=5.0)
    try:
        root = os.path.join(tmp, "daemon-wedged")
        _write_file(os.path.join(root, ".env"), "STILL_UNCONFIRMED=whatever\n")
        cfg = keyless_config(
            os.path.join(tmp, "daemon-wedged-cfg", "config.json"),
            daemon={"enabled": True, "socket": wedged.path, "timeout_ms": 10000})
        env = {"KEYLESS_CONFIG": cfg}
        started = time.monotonic()
        v = drive(bash("cat %s/.env" % root, cwd=root), env=env)
        elapsed = time.monotonic() - started
        s.check("wedged daemon: deny still fires", v.kind, "deny")
        s.check_in("wedged daemon: says it could not be asked",
                  "STILL_UNCONFIRMED — the daemon did not answer in time", v.message)
        s.check("wedged daemon: the guard's OWN deadline is what bounds it, "
               "not the configured timeout_ms",
               elapsed < _LATENCY_CEILING_S, True)
    finally:
        wedged.stop()

    # ── a malformed keyless config degrades to "nothing declared" ───────────
    root = os.path.join(tmp, "malformed-config")
    _write_file(os.path.join(root, ".env"), "SOME_NAME=whatever\n")
    cfg_path = os.path.join(tmp, "malformed-config-cfg", "config.json")
    _write_file(cfg_path, "{not json")
    env = {"KEYLESS_CONFIG": cfg_path}
    v = drive(bash("cat %s/.env" % root, cwd=root), env=env)
    s.check("malformed config: deny still fires rather than crashing", v.kind, "deny")
    s.check_in("malformed config: treated as nothing declared",
              "SOME_NAME — keyless does not serve this name", v.message)

    # ── KL-DEST carries the same per-name breakdown ─────────────────────────
    root = os.path.join(tmp, "dest-write")
    _write_file(os.path.join(root, ".env"), "DEST_KNOWN=whatever\nDEST_UNKNOWN=whatever\n")
    cfg = keyless_config(os.path.join(tmp, "dest-write-cfg", "config.json"), secrets=["DEST_KNOWN"])
    env = {"KEYLESS_CONFIG": cfg}
    v = drive(write(os.path.join(root, ".env"), "DEST_KNOWN=new\n", cwd=root), env=env)
    s.check("KL-DEST: deny fires", v.kind, "deny")
    s.check_in("KL-DEST: offers the run command for the declared name",
              "keyless run -s DEST_KNOWN --", v.message)
    s.check_in("KL-DEST: names the undeclared one plainly",
              "DEST_UNKNOWN — keyless does not serve this name", v.message)

    return s


if __name__ == "__main__":
    suite = run()
    raise SystemExit(0 if suite.report() else 1)
