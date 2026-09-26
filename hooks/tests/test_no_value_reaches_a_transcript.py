"""No value reaches a transcript: the runner gate, the matcher, and the refusals.

On 2026-09-26 a session refused a vault print verb was told, by that refusal,
that the store's own runner was "not blocked". It used the runner for a presence
check spelled `${VAR:-ABSENT}` and printed four live keys into its transcript.
Three defects made that possible, and each gets arms in BOTH directions here:

* **KL-RUNNER.** A vendor runner is refused, wherever the shell would run it —
  and a `keyless run`, the one spawn every refusal names, stays open.
* **The matcher.** A print verb or a runner is found in command position — after
  `&&`, `;`, `|`, inside `$( )`, inside `sh -c '…'`, and in combinations of
  those — and NOT in text the shell never runs: a quoted heredoc, a single-quoted
  argument, a backslash-escaped backtick in a commit message.
* **The refusals.** Every command line a refusal recommends is one the pack
  itself lets through and one that cannot print a value unfiltered, and a
  user-configured row cannot put a runner back into the sentence.

Every command below spells the vault verbs by concatenation. This file is run
from sessions that the live pack guards, and a literal print verb in a command
that merely OPENS this file is the false positive this file exists to pin.
"""

import os
import re
import sys

# In-process arms import the pack itself, from THIS tree — never from whatever a
# sibling module happened to put on the path first.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import Suite, bash, drive  # noqa: E402

IN = "infisical"
PRINT = IN + " secrets get GROQ_API_KEY"
RUNNER = IN + " run --env=prod -- sh -c 'echo \"[${GROQ_API_KEY:-ABSENT}]\"'"


def _kind(cmd):
    return drive(bash(cmd)).kind


def _message(cmd):
    return drive(bash(cmd)).message or ""


def run():
    s = Suite("no-value-in-transcript")
    _runner_fires(s)
    _runner_stays_open(s)
    _matcher_command_position(s)
    _matcher_mentions(s)
    _refusal_census(s)
    _user_row_cannot_recommend_a_runner(s)
    return s


# ── KL-RUNNER ───────────────────────────────────────────────────────────────

def _runner_fires(s):
    for label, cmd in (
            ("the leaking shape", RUNNER),
            ("infisical run", IN + " run -- npm start"),
            ("op run", "op run -- ./deploy.sh"),
            ("op run, masking off", "op run --no-masking -- printenv KEYLESS_PROBE"),
            ("pass-cli run", "pass-cli run -- npm start"),
            ("doppler run", "doppler run -- npm start"),
            ("railway run", "railway run -- npm start"),
            ("after &&", "cd app && " + IN + " run -- npm start"),
            ("inside sh -c", "sh -c '" + IN + " run -- npm start'"),
            ("inside a quoted substitution", 'echo "$(op run -- printenv X)"'),
            # The one spawn the refusal names must not become the way around it:
            # keyless masks X, and nothing the inner runner injects.
            ("delegated through keyless run",
             "keyless run -s X -- " + IN + " run -- npm start"),
            ("a heredoc fed to bash", "bash <<'EOF'\n" + IN + " run -- npm start\nEOF")):
        s.check("KL-RUNNER fires: %s" % label, _kind(cmd), "deny")
    msg = _message(RUNNER)
    s.check_in("KL-RUNNER names itself", "[KL-RUNNER]", msg)
    s.check_in("KL-RUNNER names keyless run", "keyless run -s <NAME> --", msg)
    s.check_in("KL-RUNNER answers presence", "set, ${#A} chars", msg)
    s.check_in("KL-RUNNER answers same-value", "then echo identical; else echo different", msg)
    s.check_in("KL-RUNNER never calls two unset values a match", 'echo "unset: A=${A:+set}', msg)


def _runner_stays_open(s):
    for label, cmd in (
            ("infisical run --help", IN + " run --help"),
            ("op run -h", "op run -h"),
            ("keyless run", "keyless run -s GROQ_API_KEY -- npm start"),
            # The recipe the refusals hand out, verbatim in shape.
            ("the presence recipe",
             "keyless run -s A=GROQ_API_KEY -- sh -c '[ -n \"$A\" ] && "
             "echo \"set, ${#A} chars\" || echo unset'"),
            ("the comparison recipe",
             "keyless run --env dev -s A=GROQ_API_KEY -- keyless run --env prod "
             "-s B=GROQ_API_KEY -- sh -c 'if [ -z \"$A\" ] || [ -z \"$B\" ]; then "
             "echo \"unset: A=${A:+set} B=${B:+set}\"; elif [ \"$A\" = \"$B\" ]; then "
             "echo identical; else echo different; fi'"),
            ("infisical login", IN + " login"),
            ("op item list", "op item list")):
        s.check("KL-RUNNER silent: %s" % label, _kind(cmd), "silent")


# ── the matcher, in command position ────────────────────────────────────────

def _matcher_command_position(s):
    for label, cmd in (
            ("bare", PRINT),
            ("after &&", "true && " + PRINT),
            ("after ;", "true; " + PRINT),
            ("after |", "echo x | " + PRINT),
            ("in $( )", "echo $(" + PRINT + ")"),
            ("in a quoted $( )", 'echo "$(' + PRINT + ')"'),
            ("in backticks", "echo `" + PRINT + "`"),
            ("in sh -c", "sh -c '" + PRINT + "'"),
            # Both of the next two need the extractors applied to EACH OTHER's
            # output: a substitution inside an interpreter payload, and an
            # interpreter inside a substitution. The second walked past the gate
            # before this layer existed.
            ("a quoted $( ) inside sh -c", "sh -c 'echo \"$(" + PRINT + ")\"'"),
            ("sh -c inside a quoted $( )", "echo \"$(sh -c '" + PRINT + "')\""),
            ("a heredoc fed to bash", "bash <<EOF\n" + PRINT + "\nEOF"),
            ("a substitution in an unquoted heredoc",
             "cat > /tmp/x <<EOF\n$(" + PRINT + ")\nEOF"),
            ("delegated through keyless run", "keyless run -s X -- " + PRINT)):
        s.check("matcher fires: %s" % label, _kind(cmd), "deny")


def _matcher_mentions(s):
    for label, cmd in (
            # The exact shape that was refused: a JSON mission description written
            # through a quoted heredoc, quoting the verb in markdown backticks.
            ("a quoted heredoc of JSON",
             "cat > /tmp/m.json <<'EOF'\n{\"description\": \"the agent ran `"
             + PRINT + "` and it was refused\"}\nEOF"),
            ("single-quoted backticks", "echo 'the `" + PRINT + "` verb prints'"),
            ("escaped backticks in a commit message",
             "git commit -m \"docs: \\`" + PRINT + "\\` prints a value\""),
            ("a $( ) in a quoted heredoc", "cat > /tmp/x <<'EOF'\n$(" + PRINT + ")\nEOF"),
            ("a grep pattern", "/usr/bin/grep -rn '" + PRINT + "' src"),
            ("a runner named in a commit message",
             ("git commit -m \"stop using `" + IN + " run` in agent shells\"")
             .replace("`", "\\`")),
            ("a runner in a quoted heredoc",
             "cat > notes.md <<'EOF'\nnever `op run -- x` from a session\nEOF")):
        s.check("matcher silent: %s" % label, _kind(cmd), "silent")


# ── the refusals ────────────────────────────────────────────────────────────

# One refusal from every BLOCK check that can fire on Bash, plus every vault row
# that has an alternative. The census reads what each one RECOMMENDS.
_REFUSED = (
    ("KL-FILE", "cat .env"),
    ("KL-ENV", "env > /tmp/e"),
    ("KL-ENV whole", 'python3 -c "import os; print(os.environ)"'),
    ("KL-VAULT infisical", PRINT),
    ("KL-VAULT op", "op read op://vault/item/field"),
    ("KL-VAULT claude", "claude mcp get 1up"),
    ("KL-VAULT pass", "pass work/github"),
    ("KL-VAULT op --reveal", "op item create --vault company --reveal -"),
    ("KL-RUNNER", RUNNER),
)

# A recommended command is an indented line: every refusal in the pack sets the
# command it hands the reader on a line of its own, four spaces in.
_RECOMMENDED = re.compile(r"^    (\S.*)$", re.M)


def _refusal_census(s):
    for label, cmd in _REFUSED:
        msg = _message(cmd)
        s.check("census fixture refuses: %s" % label, bool(msg), True)
        lines = _RECOMMENDED.findall(msg)
        for line in lines:
            # Whatever the pack recommends, the pack must let through — and a
            # runner it recommends would be refused here by KL-RUNNER.
            # A REWRITE is allowed: KL-ENV's own names-only line is rewritten
            # by KL-ENV into the same shape, and that is the call going through.
            s.check("census: %s recommends an allowed line: %s" % (label, line[:40]),
                    _kind(line) != "deny", True)
    # The discriminating arm: the two vault refusals that used to name a runner
    # recommend only keyless. A single `infisical run` line in either reds this.
    for label, cmd in (("KL-VAULT", PRINT), ("KL-RUNNER", RUNNER)):
        heads = sorted(set(l.split()[0] for l in _RECOMMENDED.findall(_message(cmd))))
        s.check("census: %s recommends keyless only" % label, heads, ["keyless"])


def _user_row_cannot_recommend_a_runner(s):
    """A user row's alternative is printed in the refusal — unless KL-RUNNER
    would refuse it. In-process, because the config is the variable."""
    from keyless_hooks import config as klconfig
    from keyless_hooks import payload as klpayload
    from keyless_hooks.checks import vault_cli
    import json

    def verdict(alternative):
        cfg = klconfig.Config(vault_verbs=[["acmevault", r"^get\b", alternative, None]])
        raw = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                          "tool_input": {"command": "acmevault get TOKEN"},
                          "cwd": os.getcwd()})
        return vault_cli.run(klpayload.parse(raw), cfg) or ("", "", {})

    # Control first: an alternative that prints nothing IS shown, so the arm below
    # is not green merely because alternatives never reach the message at all.
    kind, msg, _ = verdict("acmevault list")
    s.check("user row: a harmless alternative is refused-with", kind, "deny")
    s.check_in("user row: a harmless alternative is shown", "acmevault list", msg)
    kind, msg, _ = verdict(IN + " run -- <cmd>")
    s.check("user row: a runner alternative still refuses", kind, "deny")
    s.check("user row: a runner alternative is dropped", IN + " run" in msg, False)
