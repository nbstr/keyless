"""Shell grammar: words that are not statement heads, and regexes that are not paths.

Every allow-case here was refused live, on a session doing ordinary work, and the
first rows of each group are verbatim or reduced from that refusal. Four readings
of a command were wrong, each in the parser rather than in a credential table:

    `in` cut a statement     `for w in pass fail` became the vault read `pass fail`
    argv read as code        `python3 find.py 'pass received'` — a script's ARGUMENT
    Python read as shell     `python3 - <<'PY'` bodies, where `pass` is a keyword
    a regex read as a path   `grep 'vibe-agent\\.env'` refused on the fragment `.env`

plus one classification: zsh's `print` is its `echo`, and was missing from the
non-readers beside it.

Each group sits beside the shapes it must NOT open, asserted to REFUSE in the same
run, and the run ends with unit controls on the four mechanisms — so a silent
allow-case is shown to be silent because the reading changed, not because a check
stopped looking at the command.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import harness  # noqa: E402
from harness import DECOY, Suite, bash, drive  # noqa: E402

ALLOW = [
    # ── KL-FILE: a pattern token that reaches its program carrying a backslash
    # names no file the call opens. See `pattern_token.is_unmistakable_regex`.
    "/usr/bin/grep -i -E 'forgejo|mirror|vibe-agent\\.env|vibe-environment' notes.txt",
    "grep -n 'dotenv\\|\\.env' notes.txt",
    "git grep -nE 'process\\.env\\.[A-Z_]+' -- src",
    "grep -rn \"process\\.env\" src/",
    # ── KL-VAULT: `in` introduces WORDS in `for`, `select` and `case`, never a
    # command, so a list word is not a statement head.
    "for w in pass fail; do echo $w; done",
    "for t in pass dotstar cred; do python3 show.py $t; done",
    "select pass in a b; do :; done",
    # ── KL-VAULT: a quoted ARGUMENT to a script is that script's argv. Only a
    # shell runs its arguments.
    "python3 /private/tmp/find.py 'pass received' 'credentials'",
    "python3 -m cc_hooks.registry --probe 'pass show y'",
    "node scripts/probe.mjs 'op read op://a/b'",
    # ── KL-VAULT: a body fed to Python or Node is code in THAT language. Python's
    # `pass` statement, prose inside a string, and stdin DATA handed to a script
    # are none of them shell.
    "python3 - <<'PY'\ntry:\n    x = 1\nexcept Exception:\n    pass  # fail-open: keep going\nPY",
    "python3 - <<'PY'\ns = '''\n    // the\n    // pass after a tenant is deleted\n'''\nprint(s)\nPY",
    "python3 - <<'PY'\nbody = 'for (let pass = 0; grew && pass < 1; pass += 1) {}'\nPY",
    "python3 /tmp/probe.py <<'EOF'\nkubectl get secret db -o yaml\nEOF",
    "node <<'EOF'\nconst s = `op read op://a/b`;\nEOF",
]

# Run in `regex-cwd`, which holds `.npmrc` and no allowed look-alike, so a `.*`
# that expanded against the directory WOULD refuse. `REGEX_CWD_CONTROL` proves it.
ALLOW_REGEX_CWD = [
    # Verbatim shape of the refusal: the substitution's own double quotes nest
    # inside the outer ones, the quote-blind view hands `'.*'` to `print`'s
    # statement, and `print` was not a non-reader.
    "F=/tmp/x.log; print -r -- \"gone: $(/usr/bin/grep -c -E \"worktree '.*' already gone\" $F)\"",
]
REGEX_CWD_CONTROL = "cat .*"

REFUSE = [
    # An UNQUOTED regex loses its backslash to the shell, so the program opens
    # `e2e.env`; a quoted regex never shields a real file operand beside it, nor
    # one supplied through a flag.
    "grep EMAIL= e2e\\.env",
    "grep 'x\\.env' .env",
    "grep -e 'x\\.env' .env",
    "grep -n 'a\\|b' prod.env",
    # A file handed to `print` is read by the substitution, which is scanned as a
    # statement of its own.
    "print -r -- \"$(cat .env)\"",
    # A list word is not a head; the loop BODY and a case ARM still are, and a
    # protected path in the list is still an operand.
    "for w in a b; do pass show $w; done",
    "for f in .env; do cat $f; done",
    "case $x in y) pass show z;; esac",
    # A shell handed a script argument, inline code, and a here-string all stay
    # payloads.
    "bash ./run.sh 'op read op://a/b'",
    "sh -c 'pass show y'",
    "bash <<< 'op read op://a/b'",
    # A body fed to a SHELL is every line a command; a Python body under an
    # UNQUOTED delimiter is expanded by the outer shell first; a Perl backtick
    # runs a shell.
    "bash <<'EOF'\npass show y\nEOF",
    "python3 - <<EOF\nprint(\"$(op read op://a/b)\")\nEOF",
    "perl <<'EOF'\nprint `op read op://a/b`;\nEOF",
    # Real secret shapes typed into a shell, which nothing here reads differently:
    # a vendor AWS key, a password, a literal token.
    "export AWS_ACCESS_KEY_ID=%s" % DECOY["aws_key"],
    "export PASSWORD=hunter2hunter2X9q",
    "GITHUB_TOKEN=%s gh api user" % DECOY["github_pat"],
]

# Each mechanism, read directly. (what, actual-thunk, expected)
def _units():
    from keyless_hooks.executed import fed_bodies
    from keyless_hooks.languages import runs_inline_code
    from keyless_hooks.pattern_token import is_unmistakable_regex
    from keyless_hooks.shellview import head_of, heredocs, statements, words

    interp = frozenset(["bash", "python3", "perl", "node"])

    def heads(cmd):
        return [head_of(st) for st in statements(cmd)]

    def regex(stmt):
        start = [a for a, b in words(stmt)][1]
        return is_unmistakable_regex(stmt, start)

    def toks(stmt):
        return [stmt[a:b] for a, b in words(stmt)]

    return [
        ("`for` list stays in the `for` statement",
         lambda: heads("for w in pass fail; do echo $w; done"),
         ["for", "do", "echo", "done"]),
        ("`case` pattern stays in the `case` statement",
         lambda: heads("case $r in pass) echo ok;; esac")[0], "case"),
        ("single-quoted backslash regex", lambda: regex("grep 'a\\.env' f"), True),
        ("double-quoted backslash regex", lambda: regex('grep "a\\.env" f'), True),
        ("unquoted backslash is not", lambda: regex("grep a\\.env f"), False),
        ("partly quoted is not", lambda: regex("grep 'a'\\.env f"), False),
        ("quoted, no backslash is not", lambda: regex("grep 'a.env' f"), False),
        ("double-quote escape the shell removes is not",
         lambda: regex('grep "a\\$.env" f'), False),
        ("python3 script argv is not code",
         lambda: runs_inline_code("python3", toks("python3 x.py 'a b'")), False),
        ("python3 -c is code",
         lambda: runs_inline_code("python3", toks("python3 -c 'a b'")), True),
        ("perl -ne bundles the code flag",
         lambda: runs_inline_code("perl", toks("perl -ne 'print'")), True),
        ("a here-string is code",
         lambda: runs_inline_code("python3", toks("python3 <<< 'x'")), True),
        ("a shell's quoted argument stays a payload",
         lambda: runs_inline_code("bash", toks("bash x.sh 'a b'")), True),
        ("python body yields no shell",
         lambda: fed_bodies(heredocs("python3 - <<'P'\npass x\nP"), interp), []),
        ("bash body is the body",
         lambda: fed_bodies(heredocs("bash <<'P'\npass x\nP"), interp), ["pass x"]),
        ("perl body yields its backtick",
         lambda: fed_bodies(heredocs("perl <<'P'\nprint `op read x`;\nP"), interp),
         ["op read x"]),
    ]


def run():
    s = Suite("shell-grammar")
    root = harness.fixtures()
    home = {"HOME": root}
    regex_cwd = os.path.join(root, "regex-cwd")

    for cmd in ALLOW:
        s.check("allows: %s" % cmd[:56].replace("\n", "\\n"),
                drive(bash(cmd, cwd=root), env=home).kind, "silent")
    for cmd in ALLOW_REGEX_CWD:
        s.check("allows in regex-cwd: %s" % cmd[:44],
                drive(bash(cmd, cwd=regex_cwd), env=home).kind, "silent")
    s.check("regex-cwd control: a live `.*` there refuses",
            drive(bash(REGEX_CWD_CONTROL, cwd=regex_cwd), env=home).kind, "deny")
    for cmd in REFUSE:
        s.check("still refuses: %s" % cmd[:50].replace("\n", "\\n"),
                drive(bash(cmd, cwd=root), env=home).kind, "deny")

    units = _units()
    for what, actual, expected in units:
        s.check("unit: %s" % what, actual(), expected)

    expected = len(ALLOW) + len(ALLOW_REGEX_CWD) + 1 + len(REFUSE) + len(units) + 1
    ran = s.passed + len(s.failures)
    s.check("exactly %d checks ran" % expected, ran + 1, expected)
    return s


if __name__ == "__main__":
    raise SystemExit(0 if run().report() else 1)
