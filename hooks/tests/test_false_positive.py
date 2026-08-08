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
"""

import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import harness
from harness import DECOY, Suite, bash, drive

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

# len(SAFE) allow-assertions + len(PREFIX_REFUSES) table-control assertions
# + 1 table-control-total + 3 per HELP_CONTROL case + 2 per ARGV_SECRET case
# + the count check itself.
EXPECTED_CHECKS = (len(SAFE) + len(PREFIX_REFUSES) + 1 + 3 * len(HELP_CONTROL)
                   + 2 * len(ARGV_SECRET)
                   + len(FILE_FALSE_POSITIVES_REGEX_CWD)
                   + len(FILE_FALSE_POSITIVES) + len(FILE_TRUE_POSITIVES)
                   + len(ENVVAR_FALSE_POSITIVES) + len(ENVVAR_TRUE_POSITIVES) + 1)


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

    # ── the count itself ─────────────────────────────────────────────────────
    # A suite that runs nothing exits 0. Asserted last so it counts itself.
    ran = s.passed + len(s.failures)
    s.check("exactly %d checks ran" % EXPECTED_CHECKS, ran + 1, EXPECTED_CHECKS)
    return s


if __name__ == "__main__":
    ok = run().report()
    harness.cleanup()
    raise SystemExit(0 if ok else 1)
