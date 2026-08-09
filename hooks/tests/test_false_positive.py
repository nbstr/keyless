"""Every metadata, listing, navigation and help verb must PASS.

This is the layer that did not exist. KL-VAULT was built and tested from the
attacker's side only — "does the print verb get refused" — and a table of prefix
negations passed that suite completely while refusing `infisical secrets folders
get`, which lists folder NAMES and prints no value at all. It was refused twice
in one session, by a session that wanted the gate to work.

**A gate that cries wolf gets switched off, and then it protects nothing.** So a
false positive is not a lesser bug than a false negative here — it is the bug
that eventually removes every other guarantee in the pack. A false negative
leaks one secret; a false positive spends the pack's credibility, and the pack
is uninstalled as a whole.

Two properties are asserted, and the second is what stops this file rotting into
theatre:

**Exactly the expected number of checks must run.** A filtered or mis-imported
run that exercises nothing exits 0 and reads as a pass — a previous effort's
negative controls silently ran zero tests because the name filters were wrong.
`EXPECTED_CHECKS` is asserted against the count the suite actually performed, so
a case list that quietly empties out fails instead of passing.

**The suite is proven able to fail, against the shape that actually failed.**
`PREFIX_RULES` below is the prefix-negation shape this table must never return
to. It is not kept as history; it is an executable control. Every safe command
is replayed against it through the real config file, and the run asserts that it
refuses a named set of them. If that control ever comes back clean, the case list
has drifted somewhere harmless and none of the assertions above mean anything.

Four controls now, and each pins a different way this file could go vacuous:

    PREFIX_RULES             the vault TABLE shape that refused safe verbs
    HELP_CONTROL             the row still matches; `is_help` is why it is silent
    ASSIGN_VALUE_CONTROL     the walk reaches the assignment; the VALUE clears it
    ASSIGN_POSITION_CONTROL  the value WOULD fire; the POSITION is why it does not

The last two are a pair on purpose. A KL-ASSIGN whose walk silently stopped
finding assignments would keep every allow-case in this file green while
protecting nothing at all, and no assertion of the form "it is silent" can tell
those two apart.
"""

import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import harness
from harness import DECOY, Suite, bash, drive, write

# Verbs that print no credential value. Grouped by store, with how each was
# established. `measured` means the tool's own help output was read on this
# machine; `documented` means the vendor's documentation, with no local binary.
#
# Deliberately absent, because asserting them PASSES would assert they are safe
# and they are not: `vault login`, `infisical login`, `pass-cli login`,
# `pass-cli agent create`, `pass-cli agent renew`, `bw unlock`. Each prints a
# token. They stay unblocked because they are a store's own bootstrap path — the
# same reason `op run` is unblocked — and that is a named gap, not a safe verb.
SAFE = [
    # ── Infisical 0.43.114 — measured ───────────────────────────────────────
    # The first entry is the exact command that was refused twice.
    "infisical secrets folders get --env=prod --path=/",
    "infisical secrets folders get",
    "infisical secrets folders create /new",
    "infisical secrets folders delete /old",
    "infisical secrets --env=prod folders get",
    "infisical secrets --help",
    "infisical secrets folders --help",
    "infisical secrets -h",
    "infisical help secrets",
    "infisical secrets set FOO=bar",
    "infisical secrets agent-proxy",
    "infisical run -- npm start",
    "infisical init",
    "infisical scan",
    "infisical ssh connect myhost",
    "infisical vault set file",
    # ── 1Password — documented ──────────────────────────────────────────────
    "op item list",
    "op vault list",
    "op user list",
    "op run -- ./deploy.sh",
    "op signin",
    "op item get --help",
    # ── Proton Pass CLI 2.2.5 — measured ────────────────────────────────────
    # `pass-cli run` is the store's own sanctioned verb and keyless itself calls
    # it; refusing it would break the tool this pack recommends.
    "pass-cli run -- npm start",
    "pass-cli item list",
    "pass-cli vault list",
    "pass-cli share list",
    "pass-cli info",
    "pass-cli info -o json",
    "pass-cli agent list",
    "pass-cli agent monitor",
    "pass-cli agent access list",
    "pass-cli agent instructions",
    "pass-cli password generate",
    "pass-cli session lock",
    "pass-cli item create",
    "pass-cli item move github work",
    "pass-cli item list --help",
    "pass-cli --help",
    # ── pass / gopass — documented ──────────────────────────────────────────
    # Bare `pass` prints the store's tree of names, not a value.
    "pass",
    "pass ls",
    "pass find github",
    "pass insert newsecret",
    "pass git push",
    "gopass ls",
    "gopass sync",
    "gopass --help",
    # ── HashiCorp Vault — documented ────────────────────────────────────────
    "vault kv list secret/",
    "vault kv metadata get secret/app",
    "vault kv put secret/app foo=bar",
    "vault status",
    "vault kv get --help",
    # ── Doppler — documented ────────────────────────────────────────────────
    "doppler secrets set FOO=bar",
    "doppler secrets delete FOO",
    "doppler run -- npm start",
    "doppler setup",
    "doppler secrets --help",
    # ── AWS — verb list measured, output shapes documented ──────────────────
    "aws secretsmanager describe-secret --secret-id prod/db",
    "aws secretsmanager list-secrets",
    "aws secretsmanager list-secret-version-ids --secret-id prod/db",
    "aws ssm get-parameter --name /a/b",
    "aws ssm describe-parameters",
    "aws s3 ls",
    # ── GCP / Azure — documented ────────────────────────────────────────────
    "gcloud secrets list",
    "gcloud secrets versions list --secret=api-key",
    "gcloud secrets describe api-key",
    "az keyvault secret list --vault-name kv",
    "az keyvault list",
    # ── macOS keychain — measured ───────────────────────────────────────────
    # Measured: with no flags this prints the item attributes and no password
    # blob. The second case is the one the flag pattern must not match on its
    # own `-widget`.
    "security find-generic-password -s keyless -a TOKEN",
    "security find-generic-password -s my-widget",
    "security find-internet-password -s example.com",
    "security dump-keychain",
    "security list-keychains",
    "security find-certificate -a",
    # ── Bitwarden / python-keyring / Heroku — documented ────────────────────
    "bw list folders",
    "bw list collections",
    "bw status",
    "bw sync",
    "keyring set svc user",
    "keyring --help",
    "heroku config:set K=V",
    "heroku config:unset K",
    "heroku config:edit",
    "heroku logs --tail",
    # ── Kubernetes — verb list measured, format behaviour documented ────────
    # All four `name` spellings, because the exclusion is the whole rule.
    "kubectl get secret db",
    "kubectl get secret db -o name",
    "kubectl get secret db --output=name",
    "kubectl get secret db -oname",
    "kubectl get secret db -o=name",
    "kubectl describe secret db",
    "kubectl get pods -o yaml",
    # ── Railway — documented ────────────────────────────────────────────────
    "railway variables --help",
    "railway run -- npm start",
    "railway status",
    "railway logs",
    # ── mentions, not acts ──────────────────────────────────────────────────
    'git commit -m "use infisical secrets get for prod"',
    'echo "run pass-cli item view to see it"',
    "grep -rn 'vault kv get' docs/",
]

# The prefix-negation shape this table must never return to. An executable
# control, not a record: it must refuse the commands below, or the case list has
# drifted somewhere harmless and every assertion in this file is vacuous.
PREFIX_RULES = [
    ["infisical", r"^secrets\b(?!\s+set)", "infisical run -- <cmd>", None],
    ["railway", r"^variables\b(?!\s+set)", "railway run -- <cmd>", None],
    ["pass", r"^(?!(?:insert|generate|git|init|ls|list|find|search|rm|edit|cp|mv|"
             r"grep|help|version|--)\b)", "pass is a print verb", None],
]

# Commands the prefix TABLE refuses and the verb-path table allows. Named one by
# one: a bare count would still pass if the control started refusing a different
# set for a different reason.
#
# The `--help` false positives are absent on purpose. They are fixed in the CHECK
# rather than in the table, so they survive a table swap and this control cannot
# see them — HELP_CONTROL below is their control instead. Two bugs, two shapes,
# two independent proofs.
PREFIX_REFUSES = [
    "infisical secrets folders get --env=prod --path=/",
    "infisical secrets folders get",
    "infisical secrets folders create /new",
    "infisical secrets folders delete /old",
    "infisical secrets --env=prod folders get",
    "infisical secrets agent-proxy",
    "pass",
]

# Arguments that ask for documentation, and the row that WOULD refuse each one if
# the help exemption were removed. Asserted in-process against the check's own
# primitives, because a subprocess cannot be run with one code path deleted.
#
# The pairing is the point: each case proves the verb path still matches a
# blocking row, AND that `is_help` is the single reason nothing fires. Asserting
# only "it is silent" would stay green if the row had merely stopped matching.
# `infisical secrets folders --help` is absent because it needs no exemption: its
# verb path is `secrets folders`, which matches no blocking row. Only a help flag
# that TRUNCATES the path back onto a blocking row needs saving, and those are the
# three below.
HELP_CONTROL = [
    ("secrets --help", "secrets", r"^secrets$"),
    ("secrets -h", "secrets", r"^secrets$"),
    ("variables --help", "variables", r"^variables$"),
]

# A secret that arrives as a POSITIONAL argument. `pass-cli totp generate` takes
# the base32 seed on the command line, so the block message must name the verb
# and never echo what was typed — a hook that prints a secret in its own refusal
# is the leak it exists to prevent.
ARGV_SECRET = ["pass-cli totp generate " + DECOY["generic"]]

# ── KL-FILE and KL-ENVVAR, from the pack's own decision log ─────────────────
#
# Every command below is built from an operand the deployed pack was MEASURED
# acting on. 66 organic decisions, after excluding 315 rows from the synthetic
# `test-session` id and the 122 `KL-BOOM: RuntimeError: deliberate` rows the
# fail-open suite produces. Of 38 organic KL-FILE denies, 11 had an operand that
# was not a file path — a 29% false-positive rate on the pack's largest block
# category, which is how sessions learn to route around a gate.
#
# These are the real strings, not synthetic stand-ins. `.*` handed to `grep` was
# 8 of the 11 on its own.
# These run in `regex-cwd`, which holds a protected dotfile and no allowed
# look-alike. In the fixture ROOT, `.*` also globs onto `.env.example` and one
# allowed form clears the candidate — so the assertion would pass without the
# rule under test ever running, and it survived its own mutation that way.
FILE_FALSE_POSITIVES_REGEX_CWD = [
    # A regex, expanded against a real directory and matching every dotfile.
    "grep -rn '.*' src/",
    "grep -E '.*' notes.txt",
    "python3 -c \"import re; re.findall('.*', s)\"",
    "sed -n 's/.*/x/p' notes.txt",
    "awk '/.*/ {print}' notes.txt",
    # A non-greedy regex. Same class, one character longer.
    "grep -oP '.*?' notes.txt",
]

FILE_FALSE_POSITIVES = [
    # A jq filter that happens to end in a protected suffix. Both halves matter:
    # the whole token contains `==` and is not a path, AND the flag-attached
    # operand split must not carve `staging.env` out of the comparison.
    "jq -r '.name==\"staging.env\"' config.json",
    "jq -r '.name==staging.env' config.json",
    # A trailing separator names a directory. `.env/` cannot open the file `.env`.
    # The spelling WITHOUT the slash is deliberately absent: distinguishing it
    # needs an `isdir` test against the payload's cwd, which answers about the
    # wrong directory after a `cd` and would hand back a real read.
    "wc -l logs/.env/",
    # A JS property access, not a file. `process.env` matched `*.env` — the
    # loosest entry in the protected list — and this operand refused one of this
    # suite's own test commands while it was being written.
    #
    # Honest scope: the two logged rows for this operand came from the test
    # battery and from the session writing this fix, not from an organic session.
    # It is a real defect in the same class, and it is not one of the 11 counted
    # against production below.
    "grep -rn 'process.env' src/",
    # A heredoc body is text ABOUT commands. This shape refused a real `git
    # commit` while this branch was being written: markdown back-quotes in the
    # message are read as command substitution, so the prose inside them became a
    # command with an operand. The body was blanked for ACT detection and scanned
    # raw for OPERANDS, and only making those agree fixes it.
    "git commit -F - <<'MSG'\nfix: stop reading it at boot\n\n- `grep TOKEN .env` is what broke\n- `jq -r .k ~/.cckeys.json` stays refused\nMSG",
    "node -e \"console.log(process.env.PORT)\"",
    # `console.log(process.env)` is deliberately NOT here: that one serialises
    # every value and KL-ENV refuses it correctly.
]

# The genuine saves, by measured operand. 27 of the 38 organic denies, and every
# one must stay refused: a fix for the `.*` class that quietly opens these has
# traded a credibility problem for a leak. Driven with HOME pointed at the fixture
# tree, so `~/...` resolves to a decoy and no test reads a real credential.
FILE_TRUE_POSITIVES = [
    "jq -r '.github.key' ~/.cckeys.json",
    "jq -r .github ~/.cckeys.json",
    "python3 -c \"import json; json.load(open('~/.cckeys.json'))\"",
    "cat ~/.npmrc",
    "grep -n DATABASE_URL .env",
    "grep -n STRIPE prod.env",
    "grep -rn KEY dev.env",
    "cat peg-prod.env",
    "grep -n DATABASE_URL packages/prisma-db/.env",
    "cat .claude.json",
    "cat *.env",
    # `cat` is not a pattern tool, so its glob IS a path and still expands. A
    # stem-length threshold on the string would have allowed this whole shape.
    #
    # `cat .*` is deliberately not the case used: in this fixture tree that glob
    # also matches `.env.example`, and one allowed form clears the candidate.
    # That is the pack's standing "exclusions win" rule, identical before and
    # after this branch, and it is not what this assertion is about.
    "cat .npmrc*",
    # A pattern tool reading a real file through a glob. Only the FIRST
    # positional is the pattern; a later glob is a path and still expands.
    "grep -n STRIPE prod.*",
    # A pattern supplied by a flag means no positional is the pattern, so the
    # first one is a path again. The GLOB spelling is the discriminating case:
    # `-f prod.env` is caught by the literal match either way, and only
    # `-f prod.*` needs the expansion the flag test preserves.
    "grep -f patterns.txt prod.env",
    "grep -f prod.* notes.txt",
    # Unexpanded substitutions: the literal still carries a protected basename.
    "grep -n KEY $W/packages/prisma-db/.env",
    "python3 -c \"open('$d/.claude.json')\"",
]

# The `pat` class. All 6 organic KL-ENVVAR warns fired on a lower-case `pat` in a
# session doing 167 `re.*` calls — a PATTERN variable. The uppercase spellings
# below are the 3 that were genuine and must still warn.
ENVVAR_FALSE_POSITIVES = [
    "pat = re.compile(r'x')",
    "echo $pat",
    "echo $path",
    "echo ${pat}",
    "printenv pat",
]

ENVVAR_TRUE_POSITIVES = [
    "echo $GITHUB_TOKEN",
    "echo $STRIPE_SECRET",
    "echo $GITHUB_PAT",
    "echo $GH_PAT",
    "printenv GITHUB_TOKEN",
]

# ── KL-ASSIGN ───────────────────────────────────────────────────────────────
#
# This check denies on `Bash`, which is the most-used tool there is, so its
# false-positive floor decides whether the pack survives at all. Measured before
# it was registered, over commands that were really run rather than invented:
# 86,117 agent `Bash` calls from the local transcript corpus and 1,791
# interactive shell commands. 50,638 of them contain an `=`. 326 denied, and
# every one was a real credential assignment — 201 connection-string passwords,
# 114 credential-named opaque values, 9 JWTs, 2 AWS access keys. Zero denials on
# anything else.
#
# The cases below are the shapes that corpus is MADE of. Re-derive the numbers
# rather than trusting this paragraph; the corpus grows every day.

# Two fixtures spelled in halves, because this pack's own KL-WRITE rewrites the
# file it is being written into. `TOKEN="<12+ opaque characters>"` is exactly the
# shape it substitutes, and both of these arrived on disk as `${AUTH_TOKEN}` and
# `${PASSWORD}` the first time — fixtures asserting the OPPOSITE of what they
# were written to assert, with the suite still green. harness.py splits its
# decoys for the same reason. Read the file back after writing it.
ASSIGN_RUNTIME_FETCH = "export AUTH_TOKEN=" + '"$(cat ~/.token)"'
ASSIGN_PROSE = 'export BANNER="db password: ' + 'correct-horse-battery-staple"'

# The case that PROVES expansion-blanking is load-bearing. It took a mutation to
# find, and two earlier candidates were vacuous — worth recording, because the
# obvious spellings are all covered by something else and a test built on one
# passes whether the blanking is there or not:
#
#   $VAR / ${VAR}   `_is_placeholder` returns True for any value containing `${`,
#                   and separately for a value that IS a `$VAR`. Covered.
#   value opens $   `_ASSIGN`'s value class excludes `$`, so `NAME=$(…)` never
#                   reaches a finding at all. Covered.
#   $( … )          never reaches the scan in one piece: `statement_spans` cuts
#                   at `(` and `)`, so the assignment word is already truncated
#                   to `postgres://app:$` before this check reads it.
#
# A BACKTICK substitution is caught by none of those, and `_URL_AUTH` reads it as
# an eleven-character password. That is the one class where blanking decides the
# verdict — which is also why the other alternatives in `_EXPANSION` stay: they
# keep this check's reasoning its own, rather than resting on another module's
# placeholder list continuing to cover them.
ASSIGN_SUBST_IN_URL = ("export DATABASE_URL=postgres://app:`get-"
                       + "db-pw`@db.internal/app")

ASSIGN_FALSE_POSITIVES = [
    # ordinary configuration — the bulk of every `=` in the corpus
    "export NODE_ENV=production",
    "export PORT=3000",
    "export RUST_LOG=debug",
    "export CI=true",
    "export EDITOR=vim",
    "export TZ=Europe/Brussels",
    "export LANG=en_US.UTF-8",
    "export HOMEBREW_NO_AUTO_UPDATE=1",
    "export PYTHONPATH=./src:./tests",
    "export CONFIG_PATH=/etc/app/config.yaml",
    "export npm_config_registry=https://registry.npmjs.org/",
    "declare -x NODE_ENV=production",
    "VERSION=3.11.4 make install",
    "export GIT_AUTHOR_NAME='Some Person'",
    # a value that is a REFERENCE. This is the correct usage the pack asks for,
    # and a check keyed on the variable NAME refuses every one of them.
    'export PATH="$HOME/.local/bin:$PATH"',
    'export DATABASE_URL="$DATABASE_URL"',
    'export TOKEN="$TOKEN"',
    "export SECRET_KEY=${SECRET_KEY}",
    "export FOO=$(some-command)",
    # A value fetched at run time. Credential-NAMED, and the substitution is
    # opaque enough to satisfy every filter in `fingerprint` — so blanking the
    # expansion is the only thing that keeps this silent.
    ASSIGN_RUNTIME_FETCH,
    ASSIGN_SUBST_IN_URL,
    # Prose. `password:` followed by twelve-plus word characters satisfies the
    # generic NAME=<opaque> rule exactly, and only the whitespace test withholds
    # it. A gate that denies a sentence is a gate that gets uninstalled.
    ASSIGN_PROSE,
    # high-entropy values that are not credentials
    "export COMMIT_SHA=e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
    "export BUILD_ID=550e8400-e29b-41d4-a716-446655440000",
    # `set -x` is tracing, not an assignment. It AMPLIFIES this leak by echoing
    # later assignments, which is a fact about the shell and not an act to judge.
    "set -x",
    "set -euo pipefail",
    # The counter-half of the qualified-`*_KEY` keywords. `secret_key`,
    # `signing_key` and `encryption_key` are keywords; a credential word followed
    # by any OTHER identifier is not, because such a name refers to a credential
    # instead of holding one. Measured over 86,125 real commands: admitting a
    # bounded suffix generally adds `AWS_ACCESS_KEY_ID` (30 — the public half of
    # the pair), `apiKeyConnectionId` (22), `secretRef` (11) and `secretsManager`.
    # These are the shapes that decide it, so they must stay silent.
    "export CACHE_KEY=%s" % DECOY["generic"],
    "export IDEMPOTENCY_KEY=%s" % DECOY["generic"],
    "export SECRET_NAME=%s" % DECOY["generic"],
    "export SECRET_ARN=%s" % DECOY["generic"],
    "export AWS_ACCESS_KEY_ID=%s" % DECOY["generic"],
    "export KEY=%s" % DECOY["generic"],
    # Bare `key=` is 121 assignments in the same corpus and none of them is a
    # credential, which is why `key` is not a keyword on its own.
    "export SORT_KEY=%s" % DECOY["generic"],
]

# The same literal in ARGUMENT position. Each of these carries a value that
# `fingerprint` recognises; they are silent only because the word is past the
# statement's head, where an `=` belongs to the program and not to the shell.
ASSIGN_FALSE_POSITIVES_ARGV = [
    "make BUILD=%s" % DECOY["github_pat"],
    "./configure --with-token=%s" % DECOY["github_pat"],
    'git commit -m "set GITHUB_TOKEN=%s in CI"' % DECOY["github_pat"],
    "dd if=/dev/zero of=/tmp/x bs=1M count=1",
]

ASSIGN_TRUE_POSITIVES = [
    "export GITHUB_TOKEN=%s" % DECOY["github_pat"],
    "STRIPE_SECRET_KEY=%s ./deploy.sh" % DECOY["stripe"],
    "AWS_ACCESS_KEY_ID=%s" % DECOY["aws_key"],
    "env NPM_TOKEN=%s npm publish" % DECOY["npm"],
    "declare -x SLACK_TOKEN=%s" % DECOY["slack"],
    "export FOO=%s" % DECOY["github_pat"],
    "export DATABASE_URL=postgres://admin:%s@db.example.com/prod" % DECOY["generic"],
    # Name-keyed only. DECOY["generic"] is deliberately not a vendor shape, so
    # each of these is denied by the keyword or by nothing — which is what the
    # first version of this suite could not tell apart: it spelled the case as
    # `STRIPE_SECRET_KEY=<a Stripe key>`, where the vendor pattern fires and the
    # keyword never has to.
    "export SECRET_KEY=%s" % DECOY["generic"],
    "export DJANGO_SECRET_KEY=%s" % DECOY["generic"],
    "export SESSION_SIGNING_KEY=%s" % DECOY["generic"],
    "export CREDENTIAL_ENCRYPTION_KEY=%s" % DECOY["generic"],
    # libpq's own variable, and the one name where the left-hand lookbehind costs
    # real coverage: `password` is glued to `pg`, so no separator precedes it.
    "PGPASSWORD=%s psql -h db.example.com -U app" % DECOY["generic"],
]

# ── KL-WRITE: a credential REFERENCE is the correct usage, not a leak ───────
#
# This check REWRITES, and a rewrite that is wrong changes a file on disk with
# nothing refused and nothing to notice. Measured over 51,384 real Write and Edit
# payloads, 378 of the 540 name-keyed findings were a reference of one of the
# shapes below — a member expression, a call, a constant, a runtime fetch — so
# the check was damaging correct source in the majority of the files it touched.
#
# Every row here is spelled in fragments, and that is not decoration. Spelled
# whole, this pack's own live KL-WRITE rewrites the fixture on its way to disk
# and the row then asserts the opposite of what it was written to assert, with
# the suite still green. `ASSIGN_RUNTIME_FETCH` above carries the same scar.
#
# Every row was checked to FIRE before the discriminator existed. A row that is
# silent for some unrelated reason — a floor, a placeholder, a character class —
# is a control that passes whether the rule under test is there or not, and this
# file has already lost one that way.
_REF_EQ, _REF_CO, _REF_SP = "=", ": ", " = "

WRITE_REFERENCE_FALSE_POSITIVES = [
    ("member path", "this.secret" + _REF_SP + "config.secret;\n"),
    ("env read", "const token" + _REF_SP + "process.env.GITHUB_TOKEN\n"),
    ("env read, python", "password" + _REF_SP + "os.environ.get('PGPASSWORD')\n"),
    ("snake member path", "secret_key" + _REF_SP + "settings.secret_key\n"),
    ("call", "const token" + _REF_SP + "getAuthToken();\n"),
    ("call on a member", "const apiKey" + _REF_SP + "config.getSecret();\n"),
    ("type annotation, comma",
     "export function send(\n  credentials" + _REF_CO + "PushCredentialConfig,\n) {}\n"),
    ("type annotation, paren",
     "export function read(credentials" + _REF_CO + "PushCredentialConfig) {}\n"),
    ("constant reference",
     "await login({ password" + _REF_CO + "E2E_LOGIN_PASSWORD, mfa" + _REF_CO
     + "false });\n"),
    ("runtime fetch written into a file",
     "AUTH_TOKEN" + _REF_EQ + '"' + "$(cat ~/.token)" + '"' + "\n"),
]

# ── the assignment NAME, and why the collapse is positional ─────────────────
#
# A quote or a backslash inside a variable NAME is removed by the shell before
# the variable is set — but only where the word is an ARGUMENT. Measured by
# running all three shells, not inferred:
#
#     FOO""_BAR=hello              bash/zsh/sh: command not found, FOO_BAR UNSET
#     export FOO""_BAR=hello       bash/zsh:    FOO_BAR is hello
#     env FOO""_BAR=hello sh -c …  bash/zsh:    FOO_BAR is hello
#
# So collapsing unconditionally would invent an assignment the shell never
# makes, and collapsing nowhere leaves the bypass the adversarial table now
# drives. Each half is asserted, because a rule that is right for one reason and
# wrong for the other reads identically from its call sites.
ASSIGN_NAME_COLLAPSE = [
    ("SECRET''_KEY=x", "SECRET_KEY"),
    ('PG""PASSWORD=x', "PGPASSWORD"),
    ("GITHUB\\_TOKEN=x", "GITHUB_TOKEN"),
    ('"NPM_TOKEN=x"', "NPM_TOKEN"),
]

# The residual class, asserted so it cannot drift silently in either direction.
# A bare identifier that ends on whitespace is STILL rewritten, because nothing
# but the value's own randomness separates a constant's name from a credential,
# and every discriminator that reaches this shape was measured dropping a real
# one. This row is a LIMIT, not a target: it says what the check does today, so
# a later change to it is a decision somebody makes rather than a side effect.
WRITE_REFERENCE_RESIDUAL = (
    "unqualified identifier at end of line",
    "await login({\n  password" + _REF_CO + "E2E_LOGIN_PASSWORD\n});\n")


# ── the two controls, and they prove OPPOSITE things ────────────────────────
#
# Asserting only "it is silent" is worth nothing: a walk that stopped finding
# assignments at all would keep every case above green while the check protected
# nothing. Each pair below names WHICH half is responsible.
#
# VALUE: the walk reaches the assignment, and `fingerprint` clears the value.
# Every one is credential-NAMED, so a name-keyed gate refuses all four.
#
# The first row only started proving that once `secret_key` became a keyword.
# Before it did, `SECRET_KEY` matched no keyword at all, so the row was silent
# whether or not expansion-blanking worked — a control that could not fail,
# sitting inside the suite whose job is to make silence explain itself.
ASSIGN_VALUE_CONTROL = [
    ('export SECRET_KEY="$SECRET_KEY"', "SECRET_KEY"),
    ('export GITHUB_TOKEN="$GITHUB_TOKEN"', "GITHUB_TOKEN"),
    (ASSIGN_RUNTIME_FETCH, "AUTH_TOKEN"),
    ("export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}", "AWS_SECRET_ACCESS_KEY"),
]

# POSITION: the value WOULD fire, and the walk deliberately never offers it.
ASSIGN_POSITION_CONTROL = [
    ("make BUILD=%s" % DECOY["github_pat"], "BUILD", DECOY["github_pat"]),
    ("npm run build -- --token=%s" % DECOY["npm"], "token", DECOY["npm"]),
]

# len(SAFE) allow-assertions + len(PREFIX_REFUSES) table-control assertions
# + 1 table-control-total + 3 per HELP_CONTROL case + 2 per ARGV_SECRET case
# + the count check itself.
EXPECTED_CHECKS = (len(SAFE) + len(PREFIX_REFUSES) + 1 + 3 * len(HELP_CONTROL)
                   + 2 * len(ARGV_SECRET)
                   + len(FILE_FALSE_POSITIVES_REGEX_CWD)
                   + len(FILE_FALSE_POSITIVES) + len(FILE_TRUE_POSITIVES)
                   + len(ENVVAR_FALSE_POSITIVES) + len(ENVVAR_TRUE_POSITIVES)
                   + len(ASSIGN_FALSE_POSITIVES) + len(ASSIGN_FALSE_POSITIVES_ARGV)
                   + len(ASSIGN_TRUE_POSITIVES)
                   + 2 * len(ASSIGN_VALUE_CONTROL) + 2 * len(ASSIGN_POSITION_CONTROL)
                   + 2 * len(WRITE_REFERENCE_FALSE_POSITIVES) + 2
                   + 2 * len(ASSIGN_NAME_COLLAPSE)
                   + 1)


def _assignments_in(cmd):
    """The (name, raw_value) pairs KL-ASSIGN's walk would offer to the scanner."""
    from keyless_hooks.checks.shell_assign import assignments
    from keyless_hooks.shellview import statements, strip_heredocs
    out = []
    for stmt in statements(strip_heredocs(cmd)):
        out.extend(assignments(stmt))
    return out


def _config(rows):
    """A real config file, so this also exercises `vault_verbs` REPLACE semantics."""
    fd, path = tempfile.mkstemp(prefix="keyless-fp-cfg-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump({"vault_verbs": rows}, fh)
    return path


def run():
    s = Suite("false-positive")

    # ── every safe verb passes ───────────────────────────────────────────────
    for cmd in SAFE:
        s.check("allows: %s" % cmd[:52], drive(bash(cmd)).kind, "silent")

    # ── control 1: the table shape that failed must still fail ───────────────
    cfg = _config(PREFIX_RULES)
    try:
        refused = [c for c in SAFE
                   if drive(bash(c), env={"KEYLESS_HOOKS_CONFIG": cfg}).kind == "deny"]
        for cmd in PREFIX_REFUSES:
            s.check("prefix table refuses (control): %s" % cmd[:40],
                    cmd in refused, True)
        # Nothing beyond the named set: a control that refuses MORE than expected
        # is measuring something other than the prefix bug.
        s.check("table control refuses exactly the named set",
                sorted(refused), sorted(PREFIX_REFUSES))
    finally:
        os.unlink(cfg)

    # ── control 2: the help exemption is the only thing saving these ─────────
    from keyless_hooks.checks.vault_cli import is_help, verb_path
    for rest, path, row in HELP_CONTROL:
        s.check("help control path: %s" % rest, verb_path(rest), path)
        s.check("help control row matches: %s" % rest,
                re.search(row, path) is not None, True)
        s.check("help control is_help: %s" % rest, is_help(rest), True)

    # ── a refusal never echoes a secret it was handed ────────────────────────
    for cmd in ARGV_SECRET:
        v = drive(bash(cmd))
        s.check("argv secret is refused: %s" % cmd[:30], v.kind, "deny")
        s.check("refusal does not echo the secret: %s" % cmd[:30],
                DECOY["generic"] in v.message, False)

    # ── KL-FILE: operands that are not paths ─────────────────────────────────
    root = harness.fixtures()
    home = {"HOME": root}
    regex_cwd = os.path.join(root, "regex-cwd")
    for cmd in FILE_FALSE_POSITIVES_REGEX_CWD:
        s.check("KL-FILE allows: %s" % cmd[:48],
                drive(bash(cmd, cwd=regex_cwd), env=home).kind, "silent")
    for cmd in FILE_FALSE_POSITIVES:
        s.check("KL-FILE allows: %s" % cmd[:48],
                drive(bash(cmd, cwd=root), env=home).kind, "silent")

    # ── KL-FILE: the genuine saves, by measured operand ──────────────────────
    for cmd in FILE_TRUE_POSITIVES:
        s.check("KL-FILE still denies: %s" % cmd[:48],
                drive(bash(cmd, cwd=root), env=home).kind, "deny")

    # ── KL-ENVVAR: a lower-case name is not a credential name ────────────────
    for cmd in ENVVAR_FALSE_POSITIVES:
        s.check("KL-ENVVAR allows: %s" % cmd[:40], drive(bash(cmd)).kind, "silent")
    for cmd in ENVVAR_TRUE_POSITIVES:
        s.check("KL-ENVVAR still warns: %s" % cmd[:40], drive(bash(cmd)).kind, "warn")

    # ── KL-ASSIGN: configuration and references are not credentials ──────────
    from keyless_hooks.checks.shell_assign import credential_findings
    for cmd in ASSIGN_FALSE_POSITIVES:
        s.check("KL-ASSIGN allows: %s" % cmd[:48], drive(bash(cmd)).kind, "silent")
    for cmd in ASSIGN_FALSE_POSITIVES_ARGV:
        s.check("KL-ASSIGN allows (argv): %s" % cmd[:44],
                drive(bash(cmd)).kind, "silent")
    for cmd in ASSIGN_TRUE_POSITIVES:
        s.check("KL-ASSIGN still denies: %s" % cmd[:44], drive(bash(cmd)).kind, "deny")

    # control 3: silence is the VALUE's doing, not a walk that stopped walking.
    for cmd, name in ASSIGN_VALUE_CONTROL:
        values = [v for n, v in _assignments_in(cmd) if n == name]
        s.check("assign control: the walk reaches %s" % name, bool(values), True)
        s.check("assign control: the value clears %s" % name,
                credential_findings(name, values[0]) if values else ["<not reached>"],
                [])

    # control 4: and the position rule is load-bearing — these values DO fire,
    # and are silent only because the word is an argument.
    for cmd, name, value in ASSIGN_POSITION_CONTROL:
        s.check("assign control: the walk skips %s" % name,
                [n for n, _v in _assignments_in(cmd) if n == name], [])
        s.check("assign control: but that value would fire: %s" % name,
                bool(credential_findings(name, value)), True)

    # ── KL-WRITE: a reference is not a literal ───────────────────────────────
    #
    # Driven through the real hook, so this asserts the FILE is left alone rather
    # than asserting something about a function. Each row is asserted twice: the
    # verdict is silent, AND the content the hook would have passed on is byte-
    # identical to what was handed in. A rewrite that produced identical bytes
    # would satisfy the first assertion and fail the second.
    for label, content in WRITE_REFERENCE_FALSE_POSITIVES:
        v = drive(write(os.path.join(root, "src.ts"), content))
        s.check("KL-WRITE leaves a reference alone: %s" % label, v.kind, "silent")
        s.check("KL-WRITE changed nothing: %s" % label,
                (v.updated or {}).get("content", content), content)

    # And the limit, stated as an assertion rather than as a comment.
    label, content = WRITE_REFERENCE_RESIDUAL
    v = drive(write(os.path.join(root, "src.ts"), content))
    s.check("KL-WRITE still rewrites the residual shape: %s" % label, v.kind, "rewrite")
    s.check("KL-WRITE residual substitutes the field name",
            "${" + "PASSWORD}" in (v.updated or {}).get("content", ""), True)

    # ── the name collapse is positional, and both halves are load-bearing ────
    from keyless_hooks.shellview import assignment_split
    for token, name in ASSIGN_NAME_COLLAPSE:
        s.check("a spliced NAME in argument position is an assignment: %s" % name,
                (assignment_split(token, declared=True) or ("", ""))[0], name)
        s.check("a spliced NAME in PREFIX position is a command, not an assignment: "
                "%s" % name, assignment_split(token), None)

    # ── the count itself ─────────────────────────────────────────────────────
    # A suite that runs nothing exits 0. Asserted last so it counts itself.
    ran = s.passed + len(s.failures)
    s.check("exactly %d checks ran" % EXPECTED_CHECKS, ran + 1, EXPECTED_CHECKS)
    return s


if __name__ == "__main__":
    ok = run().report()
    harness.cleanup()
    raise SystemExit(0 if ok else 1)
