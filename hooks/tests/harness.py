"""Drive the real hook as a subprocess and classify its verdict.

In-process calls would be faster and would test the wrong thing. The contract
this pack has with the harness is *bytes on stdin, JSON on stdout, an exit code*
— and three of the failure modes worth catching (a crash before the emit, a
partial write, an exit code that blocks) exist only at that boundary.

Every fixture value in this suite is invented here. No test reads a real `.env`,
a real keychain item or a real token: the object under test is the lock.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HOOK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "keyless_hook.py")

# Decoys. Each is shaped like the real credential its name claims, at the real
# LENGTH, invented for this file, and matching nothing that exists.
#
# A decoy body is written so a READER can see it is fake — a repeated word, or
# base64 that decodes to DECOY. No pattern in this pack tests entropy, so a
# realistic-looking random body buys nothing and costs a reader the ability to
# tell a fixture from a leak. Prefix, separators and length are what matter.
#
# The length is not cosmetic. `ghp_` + 34 characters was two short of the real
# format, so the vendor pattern never matched it — and the contract test still
# passed, because the generic `NAME=<opaque>` rule caught the same literal. A
# pattern validated only against a decoy of the wrong shape is a pattern nobody
# proof-read. VENDOR_DECOYS below asserts each one by KIND so that cannot recur.
DECOY = {
    "github_pat": "ghp_" + "DECOYNOTAREALTOKENDECOYNOTAREALTOKEN",
    "aws_key": "AKIA" + "DECOYNOTAREALKEY",
    "stripe": "sk_live_" + "DECOYNOTAREALKEY0000",
    "openai": "sk-proj-" + "DECOYNOTAREALTOKENDECOY",
    "slack": "xoxb-" + "0000000000-0000000000-DECOYNOTAREALTOKEN",
    "google": "AIza" + "DECOYNOTAREALKEYDECOYNOTAREALKEY",
    "npm": "npm_" + "DECOYNOTAREALTOKENDECOYNOTAREALTOKEN",
    "jwt": ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoiREVDT1kifQ."
            "eyJzdWIiOiJrZXlsZXNzLWRlY295IiwibmFtZSI6Ik5PVCBBIFJFQUwgVE9LRU4ifQ."
            "DECOYSIGNATURENOTAREALSIGNATURE"),
    "generic": "Zx7Kq2mW9pLv4Tn8Rb1Ys6Hd3Fj0Gc5A",
}

# kind -> a literal that pattern MUST recognise as that kind. Asserted through
# `fingerprint.scan`, not through a rewrite, because a rewrite can be produced
# by the generic rule while the vendor pattern matches nothing.
VENDOR_DECOYS = {
    "aws_access_key": "AKIADECOYNOTAREALKEY",
    "github_pat": DECOY["github_pat"],
    "github_fine_pat": "github_pat_11DECOYNOTAREALTOKEN0000DECOYNOTAREALTOKEN0000",
    "slack_token": "xoxb-0000000000-0000000000-DECOYNOTAREALTOKEN",
    "openai_key": "sk-proj-DECOYNOTAREALTOKENDECOY",
    "stripe_key": "sk_live_DECOYNOTAREALKEY0000",
    "google_api_key": "AIzaDECOYNOTAREALKEYDECOYNOTAREALKEY",
    "sendgrid_key": "SG.DECOYNOTAREALKEY0.DECOYNOTAREALKEY00",
    "npm_token": "npm_DECOYNOTAREALTOKENDECOYNOTAREALTOKEN",
    "doppler_token": "dp.pt.DECOYNOTAREALTOKENDECOYNOTAREALTOKEN0000",
    "gitlab_pat": "glpat-DECOYNOTAREALTOKEN00",
    "huggingface_token": "hf_DECOYNOTAREALTOKEN000000000000",
    "shopify_token": "shpat_deadbeefdeadbeefdeadbeefdeadbeef",
    "linear_key": "lin_api_DECOYNOTAREALTOKENDECOYNOTAREALT",
    "infisical_token": ("st.DECOYINFISICALTOKEN000.NOTAREALCREDENTIAL0000."
                        "EXAMPLEONLY000000000"),
    "meta_token": "EAADECOYNOTAREALTOKENDECOYNOTAREALTOKENDECOYNOTAREALTOKEN000000",
    "pypi_token": "pypi-DECOYNOTAREALTOKENDECOYNOTAREALTOKENDECOYNOTAREALTOKEN",
    "jwt": ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoiREVDT1kifQ."
            "eyJzdWIiOiJrZXlsZXNzLWRlY295In0.DECOYSIGNATURENOTAREALSIGNATURE"),
    "private_key_block": "-----BEGIN OPENSSH PRIVATE KEY-----",
}


class Verdict(object):
    __slots__ = ("kind", "message", "updated", "exit_code", "stdout", "stderr")

    def __init__(self, kind, message, updated, exit_code, stdout, stderr):
        self.kind = kind
        self.message = message
        self.updated = updated
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    def __repr__(self):
        return "Verdict(%s, updated=%r)" % (self.kind, self.updated)


def drive(payload, env=None, raw_stdin=None, state=None):
    """Run the hook once. `payload` is a dict, or None when `raw_stdin` is given."""
    e = dict(os.environ)
    e["KEYLESS_HOOKS_STATE"] = state or _state_dir()
    e.pop("KEYLESS_HOOKS_DISABLE", None)
    e.pop("KEYLESS_HOOKS_OBSERVE", None)
    e["KEYLESS_HOOKS_CONFIG"] = os.path.join(e["KEYLESS_HOOKS_STATE"], "no-such-config.json")
    if env:
        e.update(env)
    data = raw_stdin if raw_stdin is not None else json.dumps(payload)
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    proc = subprocess.run([sys.executable, HOOK], input=data, env=e,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    out = proc.stdout.decode("utf-8", "replace")
    err = proc.stderr.decode("utf-8", "replace")
    return _classify(out, err, proc.returncode)


def _classify(out, err, code):
    if not out.strip():
        return Verdict("silent", "", None, code, out, err)
    try:
        obj = json.loads(out)
    except ValueError:
        return Verdict("malformed", out, None, code, out, err)
    hso = obj.get("hookSpecificOutput") or {}
    if hso.get("permissionDecision") == "deny":
        return Verdict("deny", hso.get("permissionDecisionReason", ""), None, code, out, err)
    if hso.get("permissionDecision") == "allow":
        return Verdict("allow", hso.get("permissionDecisionReason", ""), None, code, out, err)
    if "updatedInput" in hso:
        return Verdict("rewrite", hso.get("additionalContext", ""),
                       hso["updatedInput"], code, out, err)
    if "additionalContext" in hso:
        return Verdict("warn", hso["additionalContext"], None, code, out, err)
    if obj.get("decision") == "block":
        return Verdict("deny", obj.get("reason", ""), None, code, out, err)
    return Verdict("other", out, None, code, out, err)


_STATE = None


def _state_dir():
    global _STATE
    if _STATE is None:
        _STATE = tempfile.mkdtemp(prefix="keyless-hooks-test-")
    return _STATE


# ── fixture estate ──────────────────────────────────────────────────────────

_FIXTURE = None


def fixtures():
    """A throwaway tree with decoy secret files, built once per run.

    Includes a symlink and a nested project, because both are ordinary in a real
    estate and both are places a path matcher silently stops working.
    """
    global _FIXTURE
    if _FIXTURE is not None:
        return _FIXTURE
    root = tempfile.mkdtemp(prefix="keyless-fixtures-")
    _write(os.path.join(root, ".env"),
           "DATABASE_URL=postgres://u:%s@db.local/app\n"
           "STRIPE_KEY=%s\nDEBUG=true\n" % (DECOY["generic"], DECOY["stripe"]))
    _write(os.path.join(root, ".env.example"),
           "DATABASE_URL=postgres://user:password@localhost/db\nSTRIPE_KEY=sk_test_xxx\n")
    _write(os.path.join(root, "README.md"), "Copy .env.example to .env and fill it in.\n")
    _write(os.path.join(root, "id_ed25519"),
           "-----BEGIN OPENSSH PRIVATE KEY-----\n"
           "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n"
           "ZWQyNTUxOQAAACBQdW5jaGVkQ2FyZE5vdEFSZWFsS2V5AAAAIExpdGVyYWxseUZha2U=\n"
           "-----END OPENSSH PRIVATE KEY-----\n")
    os.makedirs(os.path.join(root, "nested", "app"), exist_ok=True)
    _write(os.path.join(root, "nested", "app", ".env"), "INNER_TOKEN=%s\n" % DECOY["generic"])

    # Decoys named after the operands the pack was MEASURED refusing in
    # production, so the regression suite can assert those exact strings without
    # any test reading a real credential file. Tests that use them drive the hook
    # with HOME pointed here, which is what makes `~/.cckeys.json` resolvable and
    # harmless at the same time.
    _write(os.path.join(root, ".cckeys.json"),
           '{"github": {"scope": "repo", "key": "%s"}}\n' % DECOY["github_pat"])
    _write(os.path.join(root, ".npmrc"),
           "//registry.npmjs.org/:_authToken=%s\n" % DECOY["npm"])
    _write(os.path.join(root, ".claude.json"),
           '{"apiKey": "%s"}\n' % DECOY["generic"])
    # The SAME store, pretty-printed. Both shapes are needed and neither covers
    # the other: a compact document is one line holding many pairs, and a nested
    # one is mostly brace lines. Each broke the names-only view in its own way,
    # and a suite carrying only the compact form stayed green while every
    # pretty-printed `.json` in the protected list reported no names at all.
    _write(os.path.join(root, ".credentials.json"),
           '{\n'
           '  "aws": {\n'
           '    "access_key": "%s"\n'
           '  },\n'
           '  "gcp": {\n'
           '    "refresh_token": "%s"\n'
           '  }\n'
           '}\n' % (DECOY["aws_key"], DECOY["generic"]))
    for name in ("prod.env", "dev.env", "peg-prod.env"):
        _write(os.path.join(root, name), "STRIPE_KEY=%s\n" % DECOY["stripe"])
    _write(os.path.join(root, "packages", "prisma-db", ".env"),
           "DATABASE_URL=postgres://u:%s@db/app\n" % DECOY["generic"])
    # A directory that shares a protected basename. `.env/` cannot be opened as a
    # file, and a directory holds no credential of its own.
    os.makedirs(os.path.join(root, "logs", ".env"), exist_ok=True)

    # A directory holding a protected dotfile and NO allowed look-alike beside it.
    #
    # The regex cases have to run here, not in the root. In the root, `.*` also
    # globs onto `.env.example`, one allowed form clears the whole candidate, and
    # the assertion passes without the rule under test ever mattering — measured,
    # that made the `.*` case survive its own mutation. A test that cannot fail is
    # worse than no test.
    _write(os.path.join(root, "regex-cwd", ".npmrc"),
           "//registry.npmjs.org/:_authToken=%s\n" % DECOY["npm"])
    _write(os.path.join(root, "regex-cwd", "notes.txt"), "nothing secret here\n")
    try:
        os.symlink(os.path.join(root, ".env"), os.path.join(root, "config-link"))
    except OSError:
        pass
    _FIXTURE = root
    return root


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def cleanup():
    for d in (_FIXTURE, _STATE):
        if d and os.path.isdir(d):
            shutil.rmtree(d, ignore_errors=True)


# ── assertions ──────────────────────────────────────────────────────────────

class Suite(object):
    def __init__(self, name):
        self.name = name
        self.passed = 0
        self.failures = []

    def check(self, label, got, want):
        if got == want:
            self.passed += 1
        else:
            self.failures.append((label, got, want))
        return got == want

    def check_in(self, label, needle, haystack):
        ok = needle in haystack
        if ok:
            self.passed += 1
        else:
            self.failures.append((label, "<%r not found>" % needle, haystack[:200]))
        return ok

    def report(self):
        total = self.passed + len(self.failures)
        for label, got, want in self.failures:
            sys.stderr.write("FAIL  %s\n      got:  %r\n      want: %r\n"
                             % (label, got, want))
        sys.stdout.write("%-22s %3d/%3d\n" % (self.name, self.passed, total))
        return not self.failures


def bash(command, cwd=None):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "cwd": cwd or fixtures(),
            "session_id": "test-session"}


def read(path, cwd=None):
    return {"hook_event_name": "PreToolUse", "tool_name": "Read",
            "tool_input": {"file_path": path}, "cwd": cwd or fixtures(),
            "session_id": "test-session"}


def write(path, content, cwd=None):
    return {"hook_event_name": "PreToolUse", "tool_name": "Write",
            "tool_input": {"file_path": path, "content": content},
            "cwd": cwd or fixtures(), "session_id": "test-session"}
