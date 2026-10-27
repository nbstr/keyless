"""Three checks that fired on a WORD where the act was absent, and the acts they
must still catch.

Each section is a pair: the shapes a real session was refused or warned on, which
must pass, and the shapes that ARE the act, which must still fire. Silence alone
proves nothing — a check that stopped matching would satisfy every allow-row — so
every section's true positives run in the same fixture and the same cwd.

    KL-FILE    a glob the shell never expands is not a read of what it would match
    KL-VAULT   a `--raw` URL reads what its PATH names; its query string is data
    KL-SEEN    a value spelled as a variable NAME, or a documentation placeholder,
               is not a credential in output — and a postgres URL with a real
               password still is

The connection strings are assembled from pieces, never written whole. This file
is itself written through the pack, and a whole one is what KL-WRITE reads.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
from harness import DECOY, Suite, bash, drive  # noqa: E402


# ── KL-FILE ──────────────────────────────────────────────────────────────────
# Driven from `regex-cwd/`, which holds a `.npmrc`, so `.*` expanded against it
# reaches a protected file. That is the condition the false positive needs.

FILE_QUOTED_GLOB_PASSES = [
    # The refused command, in shape: a PromQL matcher handed to a script.
    ("$S/pq.sh 'sum by (path,status) (increase(http_requests_total{"
     "k8s_deployment_name=\"web\",path=~\"(?i).*(telegram|webhook).*\"}[24h]))'"
     " > $S/wh.json 2>&1"),
    "./pq.sh '.*'",
    './pq.sh ".*"',
    "./pq.sh \\.\\*",
    "./pq.sh $'.*'",
    "cat '.*'",
    "bash pq.sh '.*'",
    "bash -c \"./pq.sh '.*'\"",
    "python3 -c \"import re; re.findall('.*', s)\"",
]

FILE_GLOB_STILL_DENIES = [
    "cat .*",
    "cat .n*",
    "cat '.n'*",
    "cat \".n\"*c",
    "find . -name '.n*' -exec cat {} +",
    "find . -name \".n*\" -exec cat {} \\;",
    "git log -p -- '.n*'",
    "rsync -a --include='.n*' ./ /tmp/x",
    # A local shell's code is globbed by THAT shell. These were silent before
    # the payload was scanned as a command of its own.
    "bash -c 'cat .n*'",
    "sh -c \"cat .n*c\"",
    "zsh -lc 'cat ./.n*'",
    "eval 'cat .n*'",
    "eval cat .n*",
    "bash -c 'bash -c \"cat .n*\"'",
    # and the literal match never depended on expansion
    "cat '.npmrc'",
]


# ── KL-VAULT ─────────────────────────────────────────────────────────────────

_PROXY = "/api/v1/namespaces/monitoring/services/prometheus-server:80/proxy/api/v1/query"

VAULT_RAW_PASSES = [
    'kubectl get --raw "%s?query=${q}"' % _PROXY,
    'kubectl get --raw "%s?query=$(cat q.txt)"' % _PROXY,
    "kubectl get --raw '%s?query=up'" % _PROXY,
    'kubectl get --raw "%s?query=kube_secret_info{path=\\"/secrets\\"}"' % _PROXY,
    'porter kubectl --cluster 1 -- get --raw "%s?query=${q2}"' % _PROXY,
]

VAULT_RAW_STILL_DENIES = [
    'kubectl get --raw "/api/v1/namespaces/default/secrets/db"',
    'kubectl get --raw "/api/v1/namespaces/default/secrets?labelSelector=${L}"',
    'kubectl get --raw "/api/v1/namespaces/${NS}/services/p:80/proxy/q?query=up"',
    'kubectl get --raw "/api/v1/namespaces/default/${R:?}/x"',
    'kubectl get --raw "$URL"',
    'kubectl get --raw "$(echo /api/v1/secrets)?x=1"',
    "kubectl get secret db -o yaml",
]


# ── KL-SEEN ──────────────────────────────────────────────────────────────────

def _url(scheme, user, password, rest):
    return scheme + "://" + user + ":" + password + "@" + rest


_PLACEHOLDER = "[" + "YOUR-PASSWORD" + "]"
_REAL_PW = DECOY["generic"]

SEEN_PASSES = [
    # `keyless ls`: a name, and the store name it injects as.
    "aws  AWS key. Inject as -s AWS_SECRET_ACCESS_KEY=AWS_NAB_ADMIN_SECRET_KEY.\n",
    # a keyless name mapping
    "keyless run -s NEXUS_API_KEY=NEXUS_STAGING_API_KEY -- nexus agents list\n",
    # a workflow's secret wiring
    "  with:\n    client_secret_secret: GOOGLE_CLIENT_SECRET\n",
    # Supabase's documented connection strings
    _url("postgresql", "postgres", _PLACEHOLDER,
         "db.abcdefghijkl.supabase.co:5432/postgres") + "\n",
    _url("postgres", "postgres.abcdefghijkl", _PLACEHOLDER,
         "aws-0-us-east-1.pooler.supabase.com:6543/postgres") + "\n",
]

SEEN_STILL_WARNS = [
    # The true positive the brief pins: a connection string with a password,
    # printed by `ps`.
    "nab  4242  0.0  psql " + _url("postgres", "app", _REAL_PW, "10.0.0.4:5432/app") + "\n",
    "DATABASE_URL=" + _url("postgres", "user", _REAL_PW, "host/db") + "\n",
    # a bracket that is not the documentation placeholder
    _url("postgres", "app", "[" + _REAL_PW + "]", "host/db") + "\n",
    # a literal behind a credential name
    "API_KEY=" + _REAL_PW + "\n",
    # all capitals with no underscore is base32 — a TOTP seed — not a name
    "TOTP_SECRET=" + "JBSWY3DPEHPK3PXPJBSW" + "\n",
    # lower-case snake is not the variable-name convention
    "SECRET = " + "hx_q7_mz_k2_rv_p9_ty" + "\n",
    # and a vendor shape is a vendor shape whatever is beside it
    "AWS_SECRET_ACCESS_KEY=" + DECOY["github_pat"] + "\n",
]


def _post(output, root):
    return {"hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_input": {"command": "./print.sh"},
            "tool_response": {"stdout": output}, "cwd": root,
            "session_id": "test-session"}


EXPECTED_CHECKS = (len(FILE_QUOTED_GLOB_PASSES) + len(FILE_GLOB_STILL_DENIES)
                   + len(VAULT_RAW_PASSES) + len(VAULT_RAW_STILL_DENIES)
                   + len(SEEN_PASSES) + len(SEEN_STILL_WARNS)
                   # the fixture control
                   + 1
                   # the count itself
                   + 1)


def run():
    s = Suite("act-not-word")
    root = harness.fixtures()
    cwd = os.path.join(root, "regex-cwd")

    # Control: the fixture really holds what the KL-FILE arms need. Without a
    # `.npmrc` beside them, every quoted-glob pass is silent for the wrong reason.
    s.check("fixture control: regex-cwd holds a .npmrc",
            os.path.isfile(os.path.join(cwd, ".npmrc")), True)

    for cmd in FILE_QUOTED_GLOB_PASSES:
        s.check("KL-FILE passes a glob the shell never expands: %s" % cmd[:60],
                drive(bash(cmd, cwd=cwd)).kind, "silent")
    for cmd in FILE_GLOB_STILL_DENIES:
        s.check("KL-FILE still denies: %s" % cmd[:60],
                drive(bash(cmd, cwd=cwd)).kind, "deny")

    for cmd in VAULT_RAW_PASSES:
        s.check("KL-VAULT passes a raw URL whose PATH names no Secret: %s" % cmd[-50:],
                drive(bash(cmd)).kind, "silent")
    for cmd in VAULT_RAW_STILL_DENIES:
        s.check("KL-VAULT still denies: %s" % cmd[:60],
                drive(bash(cmd)).kind, "deny")

    # Labelled by position, never by content: a failure line prints its label,
    # and half of these rows carry a decoy credential.
    for i, out in enumerate(SEEN_PASSES):
        s.check("KL-SEEN passes a name or placeholder: row %d" % i,
                drive(_post(out, root)).kind, "silent")
    for i, out in enumerate(SEEN_STILL_WARNS):
        s.check("KL-SEEN still warns on a real value: row %d" % i,
                drive(_post(out, root)).kind, "warn")

    ran = s.passed + len(s.failures)
    s.check("exactly %d checks ran" % EXPECTED_CHECKS, ran + 1, EXPECTED_CHECKS)
    return s


if __name__ == "__main__":
    ok = run().report()
    harness.cleanup()
    raise SystemExit(0 if ok else 1)
