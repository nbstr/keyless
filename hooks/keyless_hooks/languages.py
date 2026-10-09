"""Which interpreters run SHELL, and which run a language of their own.

`config.DEFAULT_INTERPRETERS` answers one question — does this program execute
an argument it is handed — and the checks that read through it used to assume a
second answer from the first: that what it executes is a shell command line. For
`bash`, `ssh` and `eval` that is true. For `python3` and `node` it is not, and
reading their code as shell turned the language's own words into statement
heads. Measured on real sessions, every one refused as a vault read:

    python3 - <<'PY' … except Exception:\\n    pass  # fail-open … PY
    python3 - <<'PY' … s = '''… the\\n    // pass after a tenant … ''' … PY
    python3 /tmp/find.py 'pass received'

The first is Python's `pass` statement, the second a line of prose inside a
string, the third an ARGUMENT to a script — `sys.argv[1]`, which no shell runs.

So this module names the languages that are not shell, and nothing else. A
program missing from `FOREIGN` is treated as shell, which is the direction that
keeps scanning: a user-added interpreter, `make`, `just`, `docker` and `kubectl`
all keep the behaviour they had.
"""

__all__ = ["FOREIGN", "BACKTICK_RUNS_SHELL", "is_foreign", "runs_inline_code"]

# debt: a foreign body or `-c` payload contributes no shell text except Perl, Ruby
#       and PHP backticks, so a print verb handed to the language's own process
#       API — `os.system("…")`, `subprocess.run("…", shell=True)`, `execSync("…")`
#       — is not seen by KL-VAULT or KL-RUNNER. Reading those bodies as shell did
#       not see it either: the verb sits in a string argument the shell view blanks.
#       Upgrade trigger: a replayed session or an adversarial row reaches a print
#       verb through one of those calls. nbstr/keyless#89.


# Interpreters whose code is a language of its own, mapped to the short-option
# LETTERS that hand them that code inline. A bundled flag counts — `perl -ne`,
# `node -pe`, `python3 -Ic` — because each of those ends in the code flag.
FOREIGN = {
    "python": "c", "python2": "c", "python3": "c",
    "node": "ep", "bun": "ep",
    "deno": "",
    "perl": "eE", "ruby": "e",
    "php": "rRBE",
    "osascript": "e",
}

# Long options that carry inline code, for the interpreters that have them.
_LONG_CODE = frozenset(["--eval", "--print"])

# The one SUBCOMMAND that takes code: `deno eval '<code>'`.
_CODE_SUBCOMMANDS = {"deno": frozenset(["eval"])}

# Languages in which a back-quoted string RUNS a shell command, as it does in a
# shell. Python and JavaScript have no such operator — a JS template literal is a
# string — so in their code a backtick is text.
BACKTICK_RUNS_SHELL = frozenset(["perl", "ruby", "php"])


def is_foreign(head):
    return head in FOREIGN


def runs_inline_code(head, toks):
    """True when this statement hands `head` CODE inline rather than a script.

    `toks` are the statement's words, raw. Without an inline-code flag the first
    positional is a SCRIPT PATH and every later word is that script's `argv`, so
    a quoted word there is data the interpreter itself never executes.

    The scan is deliberately loose, because a wrong YES costs only what this
    module exists to remove — one quoted argument read as code — while a wrong NO
    would hide `python3 -c "…"`. So any word that looks like a code flag counts,
    wherever it sits, and so does a here-string: `python3 <<< '<code>'`.
    """
    letters = FOREIGN.get(head)
    if letters is None:
        # Not a foreign language: every quoted word stays a payload, as before.
        return True
    subs = _CODE_SUBCOMMANDS.get(head, frozenset())
    for tok in toks:
        if tok.startswith("<<<"):
            return True
        if tok in subs:
            return True
        word = tok.split("=", 1)[0]
        if word in _LONG_CODE:
            return True
        if letters and word.startswith("-") and not word.startswith("--") \
                and any(c in letters for c in word[1:]):
            return True
    return False
