"""Defaults, and the user's overrides on top of them.

Everything the pack blocks is a list in here, so a user who keeps secrets
somewhere this file has never heard of extends one JSON object instead of
patching Python. Store-agnostic is not a slogan: no default below names a
particular vault as the one that must be used.

Two files are read, later winning:

    ~/.config/keyless/hooks.json          your machine
    <cwd>/.keyless-hooks.json             this project, committable

Both are optional and both fail open. A config that will not parse leaves the
defaults standing and records the reason; it never disables the pack and never
takes down the tool call that happened to be running when it was saved.
"""

import json
import os

__all__ = ["load", "Config"]

# Files whose *content* is a credential. Basename globs match at any depth;
# an entry containing "/" is anchored, with a leading ~ expanded.
DEFAULT_PROTECTED = [
    ".env",
    ".env.*",
    "*.env",
    ".npmrc",
    ".netrc",
    ".pgpass",
    ".cckeys.json",
    ".claude.json",
    ".credentials.json",
    "~/.aws/credentials",
    "~/.infisical/.token",
    "~/.config/gh/hosts.yml",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.ssh/id_*",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "id_dsa*",
    "*.pem",
    "~/.gnupg/*.key",
    "~/.config/op/*.sqlite",
]

# Names that LOOK protected and are not. This list is the whole reason a
# `.env.example` can still be read, and it is checked before the protected list
# so an exclusion can never be shadowed by a broader glob.
DEFAULT_ALLOWED = [
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.schema",
    ".env.test.example",
    "*.pub",
    "*.md",
    "*.lock",
    # Language idioms that end in `.env` and name no file. `*.env` is the loosest
    # entry in the protected list, and `grep -rn 'process.env' src/` is an ordinary
    # command that it refuses as a credential read.
    #
    # An exact exclusion, deliberately, rather than a rule that asks whether the
    # file exists: the hook resolves against the payload's cwd, so an existence
    # test answers about the wrong directory after a `cd` and hands back a read it
    # should have refused. See the note in `secretpaths.py`.
    "process.env",
    "import.meta.env",
    # The object-spread spelling of the same idiom. `{ ...process.env }` is how
    # every Node program builds an environment for a child, and the tokenizer
    # hands the spread over as the operand `...process.env`, which `process.env`
    # above does not cover and `*.env` does. The spelling without spaces —
    # `{...process.env}` — never matched, because the trailing brace defeats
    # `*.env`; only the spaced form was refused, every time it was written.
    "...process.env",
    "...import.meta.env",
]

# Commands that cannot put a file's CONTENT on stdout: metadata readers,
# destroyers, and printers of their own arguments. The allowlist sits on this
# closed side deliberately — the set of programs that can print a file is
# unbounded and grows, so allowlisting readers fails toward allowing, while
# excluding the small closed set of non-readers fails toward blocking.
#
# `cp` and `mv` are absent on purpose: relocating a protected file out from
# under its own glob is a bypass, not a metadata read.
DEFAULT_NON_READERS = [
    "ls", "stat", "test", "[", "[[", "touch", "mkdir", "rm", "rmdir",
    "chmod", "chown", "chgrp", "file", "find", "du", "df", "basename",
    "dirname", "shred", "unlink", "ln", "echo", "printf", "true", "false",
    ":", "cd", "pwd", "which", "type", "man", "keyless",
]

# Programs whose first positional argument is a PATTERN, a script or a filter —
# never a path. A metacharacter blob handed to one of these is a regex, and
# expanding it against the real filesystem is what made `grep '.*'` read as a
# request for every dotfile in the directory, `.npmrc` and `.env` included.
#
# ONLY THE GLOB EXPANSION IS WITHHELD, and only for the pattern token. A literal
# path is still matched everywhere, so `grep TOKEN .env` and
# `jq -r .k ~/.cckeys.json` are refused exactly as before — those two shapes are
# the bulk of what this pack genuinely catches.
#
# That asymmetry is a safety property, not a detail. Dropping the pattern token's
# candidates outright was tried and it allowed `grep EMAIL= /tmp/e2e.env`: the
# pattern `EMAIL=` is shaped like an assignment, the positional walk skips it as
# one, and the FILE becomes "the pattern". While only expansion is withheld, that
# mis-identification costs a false positive or a missed glob; while the candidate
# is dropped, it costs the credential.
#
# The exemption covers the whole token, keyed on POSITION — see
# `shellview.positional_span`. Keying it on the candidate's STRING exempted only
# the candidate equal to the whole pattern, and `candidate_operands` carves
# fragments out of every token: `"(if|\?).*\b(x|y)\b"` yields `.*` on its own,
# which then expanded against the cwd onto every dotfile in it. A string
# comparison also cannot tell the two roles in `grep .env .env` apart.
#
# The interpreters below are on this list for their `-c`/`-e` FLAG payloads. Their
# first positional is a SCRIPT PATH the interpreter opens and executes, so it is a
# genuine read and `checks/file_read` deliberately withholds the exemption from
# them — `python3 .env` is still refused.
DEFAULT_PATTERN_TOOLS = [
    "grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "jq", "yq",
    "python", "python2", "python3", "perl", "ruby", "node",
]

# Heads whose own first positional is a SUBCOMMAND, and whose pattern therefore
# sits one place further along. `git grep -nE "<re>" -- <pathspec>` is the whole
# of the observed evidence; `hg` and `jj` spell the same verb the same way and are
# listed for the sibling sweep rather than because either was measured.
#
# Spelled as a pair rather than by adding `git` to the list above, which would be
# wrong in both directions: it would exempt the first positional of
# `git show HEAD:.npmrc` — a real read — while still reading the pattern of
# `git grep` as the word `grep`.
DEFAULT_PATTERN_SUBCOMMANDS = [
    "git grep", "hg grep", "jj grep",
]

# Programs whose ARGUMENT is a program. A quoted string is data everywhere else
# and code here, which is the whole reason `bash -c "cat .env"` walks past a
# gate built on tokenization: to the tokenizer it is one opaque word.
DEFAULT_INTERPRETERS = [
    "bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "eval",
    "python", "python2", "python3", "node", "deno", "bun", "perl", "ruby",
    "php", "osascript", "ssh", "docker", "kubectl", "make", "just",
]

# Vault CLI verbs that put a plaintext credential on stdout.
#
#   [binary, verb-path-regex, the verb that does the same job safely, flag-regex]
#
# The second element is matched against the VERB PATH — the leading flag-free run
# of words, so `secrets folders get --env=prod --path=/` is tested as
# `secrets folders get`. See `checks/vault_cli.verb_path`. Patterns are POSITIVE
# and name the act: the one question each row answers is *does this verb put a
# secret VALUE on stdout*, and a row exists only where the answer is yes.
#
# That is a correction of shape, not of detail. These rows used to be prefix
# negations — `^secrets\b(?!\s+set)`, "everything under `secrets` except one
# sibling" — and a negation cannot help being wrong about a subcommand nobody
# thought of. `infisical secrets folders get` lists folder NAMES and prints no
# value; it was refused twice in one session, and `infisical secrets --help` and
# `railway variables --help` were refused too. A gate that cries wolf gets
# switched off, and then it protects nothing.
#
# The fourth element, when present, is a SECOND condition on the RAW arguments —
# used where the same subcommand prints metadata or a value depending on one
# flag. Measured: `security find-generic-password` with no flags prints the item
# attributes and no password blob; `-w` prints the password.
#
# Sibling verbs that USE a secret without printing it — `op run`, `infisical
# run`, `doppler run`, `pass-cli run`, `vault kv put`, `doppler secrets set` —
# are absent by design. A gate that also blocks the working path gets
# uninstalled, and what comes back is the plaintext literal on the command line.
#
# `measured` below means the tool's own `--help` was read, at the version named.
# `documented` means the vendor's documentation, with no local binary to check.
DEFAULT_VAULT_VERBS = [
    # ── Infisical 0.43.114 — measured ───────────────────────────────────────
    # Bare `infisical secrets` prints every value in the environment: its own
    # help lists `infisical secrets` as the example and offers `--plain`, "print
    # values without formatting, one per line". `secrets folders {get,create,
    # delete}` is navigation over folder NAMES and prints no value.
    ["infisical", r"^secrets$", "infisical run -- <cmd>", None],
    ["infisical", r"^secrets\s+get\b", "infisical run -- <cmd>", None],
    # `secrets delete` and `generate-example-env` both carry flags that render
    # secrets (`-o`, and a fetch token), and neither is a verb an agent reaches
    # for. Kept blocked: the false-positive argument is weighted by how often a
    # verb is actually run, and refusing a verb nobody types costs no
    # credibility while allowing one wrongly dumps an environment.
    ["infisical", r"^secrets\s+delete\b", "infisical run -- <cmd>", None],
    ["infisical", r"^secrets\s+generate-example-env\b", "infisical run -- <cmd>", None],
    ["infisical", r"^export\b", "infisical run -- <cmd>", None],
    ["infisical", r"^dynamic-secrets$", "infisical run -- <cmd>", None],
    ["infisical", r"^dynamic-secrets\s+lease\s+create\b", "infisical run -- <cmd>", None],
    ["infisical", r"^ssh\s+issue-credentials\b", "keyless run -s <NAME> -- <cmd>", None],
    ["infisical", r"^token\s+renew\b", "keyless run -s <NAME> -- <cmd>", None],
    ["infisical", r"^service-token\s+create\b", "keyless run -s <NAME> -- <cmd>", None],
    # ── 1Password — documented ──────────────────────────────────────────────
    ["op", r"^(read|inject)\b", "op run -- <cmd>", None],
    ["op", r"^item\s+get\b", "op run -- <cmd>", None],
    ["op", r"^document\s+get\b", "op run -- <cmd>", None],
    # ── Proton Pass CLI 2.2.5 — measured ────────────────────────────────────
    # `item view` prints the item. `item totp` and `totp generate` print a
    # one-time code, which is a credential. `inject` writes the rendered
    # template to STDOUT unless `--out-file` is given. Everything else in this
    # CLI is metadata or the sanctioned `run`: `item list`, `vault list`,
    # `share list`, `info`, `password generate|score`, `session *`, `agent *`.
    ["pass-cli", r"^item\s+view\b", "pass-cli run -- <cmd>", None],
    ["pass-cli", r"^item\s+totp\b", "pass-cli run -- <cmd>", None],
    ["pass-cli", r"^totp\s+generate\b", "pass-cli run -- <cmd>", None],
    ["pass-cli", r"^inject$", "pass-cli run -- <cmd>", None],
    ["pass-cli", r"^personal-access-token\s+(create|renew)\b",
     "pass-cli run -- <cmd>", None],
    # ── Claude Code CLI — measured 2026-08-13 ───────────────────────────────
    # `claude mcp get <name>` prints the server's stored env block verbatim, and
    # an MCP server is registered with `--env NAME=<token>` by nearly every
    # vendor's own copy-paste line — so the value is in ~/.claude.json in the
    # clear and this verb reads it back out. That file is already `protected`
    # and KL-FILE refuses to READ it; this row closes the door beside that one,
    # where a subcommand reads the same bytes on the agent's behalf.
    # `claude mcp list` names the servers, their command and their status, and
    # prints no env at all — measured against a server that had one.
    ["claude", r"^mcp\s+get\b", "claude mcp list", None],
    # ── pass / gopass — documented ──────────────────────────────────────────
    # These have no print SUBCOMMAND: `pass <name>` is itself the print form, so
    # the safe verbs are the enumerable side and this row is the one negation
    # left in the table. The trailing `\S` is load-bearing — bare `pass` prints
    # the store's tree of NAMES, and without it an empty verb path matched the
    # negation and refused a listing.
    ["pass", r"^(?!(?:insert|generate|git|init|ls|list|find|search|rm|edit|cp|mv|"
             r"grep|help|version|--)\b)\S", "pass ls lists names", None],
    ["gopass", r"^(?!(?:insert|generate|git|init|ls|list|find|search|rm|edit|cp|mv|"
               r"grep|help|version|sync|--)\b)\S", "gopass ls lists names", None],
    # ── HashiCorp Vault — documented ────────────────────────────────────────
    # `kv list` and `kv metadata get` are metadata and never match.
    ["vault", r"^(read|kv\s+get)\b", "vault agent templating, or keyless run", None],
    ["vault", r"^print\s+token\b", "keyless run -s <NAME> -- <cmd>", None],
    # ── Doppler — documented ────────────────────────────────────────────────
    ["doppler", r"^secrets$", "doppler run -- <cmd>", None],
    ["doppler", r"^secrets\s+(get|download|substitute)\b", "doppler run -- <cmd>", None],
    # ── AWS — verb list measured, output shapes documented ──────────────────
    ["aws", r"^secretsmanager\s+(batch-)?get-secret-value\b",
     "keyless run -s <NAME> -- <cmd>", None],
    ["aws", r"^ssm\s+get-parameters?\b", "keyless run -s <NAME> -- <cmd>",
     r"--with-decryption"],
    # ── GCP / Azure — documented ────────────────────────────────────────────
    ["gcloud", r"^secrets\s+versions\s+access\b", "keyless run -s <NAME> -- <cmd>", None],
    ["az", r"^keyvault\s+secret\s+show\b", "keyless run -s <NAME> -- <cmd>", None],
    # ── macOS keychain — measured ───────────────────────────────────────────
    # The flag pattern allows letters on BOTH sides of `w`/`g`, because `security`
    # clusters short flags: `-ws NAME` parses as `-w -s NAME` and was measured
    # searching the keychain, while the old pattern required `w` to end the
    # cluster and so missed it. The leading `(?:^|\s)` is what keeps a value like
    # `-s my-widget` from matching on its own `-widget`.
    ["security", r"^find-(generic|internet)-password\b", "keyless run -s <NAME> -- <cmd>",
     r"(?:^|\s)-[A-Za-z]*[wg][A-Za-z]*(?=\s|$)"],
    ["security", r"^dump-keychain\b", "keyless run -s <NAME> -- <cmd>",
     r"(?:^|\s)-[A-Za-z]*d[A-Za-z]*(?=\s|$)"],
    # ── Bitwarden / python-keyring / Heroku — documented ────────────────────
    ["bw", r"^(get|list\s+items)\b", "bw run, or keyless run -s <NAME> -- <cmd>", None],
    ["keyring", r"^get\b", "keyless run -s <NAME> -- <cmd>", None],
    ["heroku", r"^config$", "heroku run, or keyless run -s <NAME> -- <cmd>", None],
    ["heroku", r"^config:get\b", "heroku run, or keyless run -s <NAME> -- <cmd>", None],
    # ── Kubernetes — verb list measured, format behaviour documented ────────
    # Any output format other than `name` can render the `.data` map, and a
    # `.data` map is plaintext with extra steps — base64 is an encoding, not a
    # mask. Enumerating the safe formats rather than the dangerous ones is the
    # closed side of the allowlist: `-o custom-columns='KEYS:.data'` is a format
    # nobody would think to enumerate, and one such command puts every value in
    # the secret into the transcript at once — which is what makes a missing row
    # here expensive rather than merely untidy.
    # `kubectl describe secret` prints sizes only and never
    # matches this row, and bare `kubectl get secret` prints a name/type/age
    # table with no values.
    #
    # The separator is optional in the `-ojson` direction only. `--output` leads
    # the alternation and `(?=[a-z])` is a lookahead rather than an optional
    # group, so `--output=name` cannot match by backtracking around the `name`
    # exclusion — an optional `[= ]?` did exactly that and turned the safe
    # format into a block.
    ["kubectl", r"^get\s+secret", "keyless run -s <NAME> -- <cmd>",
     r"(?:^|\s)(?:--output|-o)(?:[= ]\s*|(?=[a-z]))(?!name\b)"],
    # ── Railway — documented ────────────────────────────────────────────────
    # Every spelling of `railway variables` renders the value table, `--set`
    # included, so there is no metadata sibling to carve out here.
    ["railway", r"^variables$", "railway run -- <cmd>", None],
]

# Env-var name segments that mark a value as credential-shaped. Split on _ and -
# and compared whole, so SSH_KEY_PATH matches on KEY while PWD never matches on
# itself. Whole-segment comparison is the difference between a usable signal and
# one that fires on every path variable in the environment.
DEFAULT_SECRET_SEGMENTS = [
    "token", "secret", "password", "passwd", "apikey", "credential",
    "credentials", "pat", "auth", "privatekey", "accesskey", "seckey",
]

DEFAULT_SECRET_SEGMENT_PAIRS = [
    ("api", "key"), ("access", "key"), ("secret", "key"), ("private", "key"),
    ("auth", "token"), ("session", "key"), ("signing", "key"), ("client", "secret"),
]


class Config(object):
    __slots__ = ("protected", "allowed", "non_readers", "interpreters", "vault_verbs",
                 "pattern_tools", "pattern_subcommands", "secret_segments",
                 "secret_pairs", "enabled", "observe", "errors")

    def __init__(self, **kw):
        self.protected = kw.get("protected", list(DEFAULT_PROTECTED))
        self.allowed = kw.get("allowed", list(DEFAULT_ALLOWED))
        self.non_readers = frozenset(kw.get("non_readers", DEFAULT_NON_READERS))
        self.interpreters = frozenset(kw.get("interpreters", DEFAULT_INTERPRETERS))
        self.pattern_tools = frozenset(kw.get("pattern_tools", DEFAULT_PATTERN_TOOLS))
        self.pattern_subcommands = frozenset(
            kw.get("pattern_subcommands", DEFAULT_PATTERN_SUBCOMMANDS))
        self.vault_verbs = kw.get("vault_verbs", list(DEFAULT_VAULT_VERBS))
        self.secret_segments = frozenset(kw.get("secret_segments", DEFAULT_SECRET_SEGMENTS))
        self.secret_pairs = kw.get("secret_pairs", list(DEFAULT_SECRET_SEGMENT_PAIRS))
        self.enabled = kw.get("enabled", True)
        self.observe = kw.get("observe", False)
        self.errors = kw.get("errors", [])


def _merge_list(base, patch, key):
    """`key` replaces; `key + "_add"` extends. Both, so a user can drop a default
    they disagree with without restating the other twenty."""
    out = list(base)
    if isinstance(patch.get(key), list):
        out = [x for x in patch[key] if isinstance(x, (str, list))]
    add = patch.get(key + "_add")
    if isinstance(add, list):
        out = out + [x for x in add if isinstance(x, (str, list))]
    return out


def _read(path, errors):
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        # Fail open with a record. A malformed config must never be the reason a
        # tool call fails, and must never silently disable the pack either.
        errors.append("%s: %s" % (path, type(exc).__name__))
        return {}
    return data if isinstance(data, dict) else {}


def load(cwd=""):
    """Defaults, then the user file, then the project file. Never raises."""
    errors = []
    home = os.path.expanduser("~")
    user_path = os.environ.get("KEYLESS_HOOKS_CONFIG") or os.path.join(
        home, ".config", "keyless", "hooks.json")
    patch = _read(user_path, errors)
    if cwd and os.path.isdir(cwd):
        patch2 = _read(os.path.join(cwd, ".keyless-hooks.json"), errors)
        for k, v in patch2.items():
            patch[k] = v

    return Config(
        protected=_merge_list(DEFAULT_PROTECTED, patch, "protected"),
        allowed=_merge_list(DEFAULT_ALLOWED, patch, "allowed"),
        non_readers=_merge_list(DEFAULT_NON_READERS, patch, "non_readers"),
        interpreters=_merge_list(DEFAULT_INTERPRETERS, patch, "interpreters"),
        pattern_tools=_merge_list(DEFAULT_PATTERN_TOOLS, patch, "pattern_tools"),
        pattern_subcommands=_merge_list(DEFAULT_PATTERN_SUBCOMMANDS, patch,
                                        "pattern_subcommands"),
        vault_verbs=_merge_list(DEFAULT_VAULT_VERBS, patch, "vault_verbs"),
        secret_segments=_merge_list(DEFAULT_SECRET_SEGMENTS, patch, "secret_segments"),
        secret_pairs=DEFAULT_SECRET_SEGMENT_PAIRS,
        enabled=patch.get("enabled", True) is not False,
        observe=patch.get("observe", False) is True,
        errors=errors,
    )
