"""Contract: payload in, decision out, for every check.

Four case classes per check, which is the minimum that proves anything:
it fires · it is silent when the act is not there · it is silent on a
LOOK-ALIKE (the act named rather than performed) · the message says something
the reader can act on.

The look-alike rows are the expensive ones to omit. A guard that fires on a
commit message about `.env`, or on a runbook explaining `op read`, is a guard
its owner disables — and then it protects nothing at all.
"""

import os
import sys

import harness
from harness import (DECOY, VENDOR_DECOYS, Suite, bash, drive, fixtures,
                     read, write)


def run():
    s = Suite("contract")
    root = fixtures()

    # ── KL-FILE: fires ──────────────────────────────────────────────────────
    for cmd in ("cat .env",
                "head -20 .env",
                "grep DATABASE_URL .env",
                "awk '{print}' .env",
                "xxd .env",
                "cat < .env",
                "cat ./nested/app/.env",
                "cat %s/.env" % root,
                "cat ~/.aws/credentials",
                "cat id_ed25519"):
        s.check("KL-FILE fires: %s" % cmd, drive(bash(cmd)).kind, "deny")

    # ── KL-FILE: a path spelled with a leading tilde ────────────────────────
    #
    # A config file is not a shell, and neither is a tool payload: nothing expands
    # `~` unless something is written to. Joining the raw string onto the working
    # directory produced `<cwd>/~/.cckeys.json`, which no filesystem test will ever
    # find — so `isfile` said no, and BOTH the Read rewrite and the Grep deny read
    # that as "no file here, nothing to protect" and allowed the read outright.
    # The block was lost, not merely its list of names.
    #
    # HOME points at the fixture tree, so `~/...` resolves to a decoy and no test
    # reads a real credential.
    home = {"HOME": root}
    s.check("KL-FILE Read on ~ does not silently allow",
            drive(read("~/.cckeys.json", cwd=root), env=home).kind, "rewrite")
    s.check("KL-FILE Grep on ~ does not silently allow",
            drive({"hook_event_name": "PreToolUse", "tool_name": "Grep",
                   "tool_input": {"pattern": "key", "path": "~/.cckeys.json"},
                   "cwd": root, "session_id": "test-session"}, env=home).kind, "deny")

    # An unresolvable path is not an absent one. A hook holds no model of shell
    # state, so `$SOMEWHERE/.env` cannot be resolved — and "I could not look" must
    # not be reported as "there is nothing here".
    s.check("KL-FILE Read on an unresolvable path denies",
            drive(read("$SECRETS_DIR/.env", cwd=root), env=home).kind, "deny")

    # The courtesy half: the refusal says WHICH credentials the session was
    # reaching for. Both halves had to be fixed for this to work — the tilde, and
    # a key/value ratio that counted a JSON file's brace lines against it and so
    # produced `names: 0` for every `.json` in the protected list.
    v = drive(bash("jq -r '.github.key' ~/.cckeys.json", cwd=root), env=home)
    s.check("KL-FILE ~ deny still fires", v.kind, "deny")
    s.check_in("KL-FILE ~ deny names the credential", "github", v.message)
    s.check("KL-FILE ~ deny leaks no value", DECOY["github_pat"] in v.message, False)
    # EVERY name on the line, not just the first. A credential store written on
    # one line declares several, and reading one key per line named the first
    # service and stayed silent about the rest.
    s.check_in("KL-FILE compact JSON names every key", "github, scope, key", v.message)

    # The pretty-printed shape of the same store. Its brace lines used to count
    # against the key/value ratio and take the whole file under the threshold, so
    # a nested `.json` — most of the protected list — reported no names at all.
    v = drive(bash("cat .credentials.json", cwd=root), env=home)
    s.check("KL-FILE nested JSON deny fires", v.kind, "deny")
    s.check_in("KL-FILE nested JSON names its keys", "aws, access_key, gcp", v.message)
    s.check("KL-FILE nested JSON leaks no value", DECOY["aws_key"] in v.message, False)

    # And the property the ratio exists to protect, asserted rather than assumed:
    # a private key yields NO names, because a plausible-looking fragment of key
    # material is worse than an honest refusal to describe the file.
    v = drive(bash("cat id_ed25519", cwd=root), env=home)
    s.check("KL-FILE private key deny fires", v.kind, "deny")
    s.check_in("KL-FILE private key yields no names", "(none readable", v.message)

    # ── KL-FILE: silent when the act is elsewhere ───────────────────────────
    for cmd in ("cat .env.example",
                "cat README.md",
                "ls -la .env",
                "stat .env",
                "rm .env",
                "touch .env",
                "test -f .env && echo yes",
                "keyless run -s DATABASE_URL -- psql"):
        s.check("KL-FILE silent: %s" % cmd, drive(bash(cmd)).kind, "silent")

    # ── KL-FILE: look-alikes — the act NAMED, not performed ─────────────────
    for cmd in ('git commit -m "fix .env loading in the app"',
                'echo "remember to add .env to .gitignore"',
                "echo .env >> .gitignore",
                'printf "%s\\n" "the .env file is generated"'):
        s.check("KL-FILE look-alike: %s" % cmd, drive(bash(cmd)).kind, "silent")

    # a heredoc writing a runbook that MENTIONS the command
    doc = "cat <<'EOF' > runbook.md\nDo not run: cat .env\nEOF"
    s.check("KL-FILE heredoc mention", drive(bash(doc)).kind, "silent")

    # ── KL-FILE: Read is rewritten, not refused ─────────────────────────────
    v = drive(read(os.path.join(root, ".env")))
    s.check("KL-FILE Read rewrites", v.kind, "rewrite")
    if v.updated:
        view = v.updated.get("file_path", "")
        s.check("KL-FILE view path differs", view != os.path.join(root, ".env"), True)
        body = open(view).read() if os.path.isfile(view) else ""
        s.check("KL-FILE view carries names", "STRIPE_KEY" in body, True)
        s.check("KL-FILE view carries NO value", DECOY["stripe"] in body, False)
        s.check("KL-FILE view carries NO url password", DECOY["generic"] in body, False)

    # a private key has no key/value shape, so it yields no names at all
    v = drive(read(os.path.join(root, "id_ed25519")))
    s.check("KL-FILE pem rewrites", v.kind, "rewrite")
    if v.updated:
        body = open(v.updated["file_path"]).read()
        s.check("KL-FILE pem yields no names", "no names could be read" in body, True)
        s.check("KL-FILE pem leaks no material", "b3BlbnNzaC1r" in body, False)

    s.check("KL-FILE Read of example is silent",
            drive(read(os.path.join(root, ".env.example"))).kind, "silent")

    # ── KL-VAULT: fires, across stores ──────────────────────────────────────
    for cmd in ("op read op://vault/item/field",
                "op item get github --fields label=token",
                "infisical secrets",
                "infisical secrets get DATABASE_URL",
                "infisical export --format=dotenv",
                "vault kv get secret/app",
                "doppler secrets",
                "aws secretsmanager get-secret-value --secret-id prod/db",
                "gcloud secrets versions access latest --secret=api-key",
                "az keyvault secret show --name apikey --vault-name kv",
                "security find-generic-password -s keyless -a TOKEN -w",
                "bw get password github",
                "aws ssm get-parameter --name /a/b --with-decryption",
                "kubectl get secret db -o yaml",
                # A flag that may or may not consume the next word truncates the
                # verb path back to bare `secrets`, which prints everything. The
                # truncation must fail toward blocking, not toward silence.
                "infisical secrets --env prod get DB_URL",
                # Rows added after reading each CLI's own help output. Every one
                # of these prints a credential and none was blocked before.
                "infisical dynamic-secrets",
                "infisical dynamic-secrets lease create --lease-id abc",
                "infisical ssh issue-credentials --templateName t",
                "infisical token renew",
                "infisical service-token create",
                "pass-cli item totp github",
                "pass-cli inject -i template.env",
                "pass-cli personal-access-token create",
                "op document get deploy-key",
                "vault print token",
                "doppler secrets get STRIPE_KEY",
                "doppler secrets download --no-file",
                "aws secretsmanager batch-get-secret-value --secret-id-list a b",
                "security dump-keychain -d",
                "heroku config",
                "heroku config:get DATABASE_URL",
                "railway variables",
                "pass work/github",
                "gopass work/github",
                "bw get item github",
                "keyring get svc user",
                # `-ojson` with no separator, and `-ws` with the password flag
                # clustered ahead of another flag. Both parse, and both used to
                # walk past the flag condition.
                "kubectl get secret db -ojson",
                "security find-generic-password -ws keyless"):
        s.check("KL-VAULT fires: %s" % cmd[:38], drive(bash(cmd)).kind, "deny")

    # ── KL-VAULT: the safe sibling verb stays open ──────────────────────────
    for cmd in ("op run -- ./deploy.sh",
                "op signin",
                "op item list",
                "infisical run -- npm start",
                "infisical secrets set FOO=bar",
                "doppler run -- npm start",
                "doppler secrets set FOO=bar",
                "vault kv put secret/app foo=bar",
                "security find-generic-password -s keyless -a TOKEN",
                "kubectl get secret db",
                "aws ssm get-parameter --name /a/b"):
        s.check("KL-VAULT silent: %s" % cmd[:38], drive(bash(cmd)).kind, "silent")

    # ── KL-VAULT: look-alikes ───────────────────────────────────────────────
    for cmd in ('git commit -m "document op read usage"',
                'echo "use op read to fetch it"',
                "grep -rn 'op read' docs/"):
        s.check("KL-VAULT look-alike: %s" % cmd[:38], drive(bash(cmd)).kind, "silent")

    # ── KL-ENV ──────────────────────────────────────────────────────────────
    v = drive(bash("env"))
    s.check("KL-ENV bare env rewrites", v.kind, "rewrite")
    s.check_in("KL-ENV rewrite masks", "keyless:redacted", (v.updated or {}).get("command", ""))
    v = drive(bash("env | grep -i token"))
    s.check("KL-ENV pipeline preserved",
            (v.updated or {}).get("command", "").endswith("| grep -i token"), True)
    s.check("KL-ENV redirect denies", drive(bash("env > /tmp/e")).kind, "deny")
    s.check("KL-ENV printenv rewrites", drive(bash("printenv")).kind, "rewrite")
    s.check("KL-ENV export -p rewrites", drive(bash("export -p")).kind, "rewrite")
    s.check("KL-ENV node whole-env denies",
            drive(bash('node -e "console.log(process.env)"')).kind, "deny")
    s.check("KL-ENV python whole-env denies",
            drive(bash('python3 -c "import os; print(dict(os.environ))"')).kind, "deny")

    # The whole environment reaching a SINK. This gate used to fire on the
    # expression alone, which denied the copy idiom every language uses to build
    # a child's environment; it now fires on where the expression GOES. These are
    # the shapes that must still be refused, and the last three are the exact
    # bypasses the assignment exemption would otherwise have opened.
    for label, cmd in (
            ("print", 'python3 -c "import os; print(os.environ)"'),
            ("json.dumps", 'python3 -c "import os,json; print(json.dumps(os.environ))"'),
            ("JSON.stringify", 'node -e "console.log(JSON.stringify(process.env))"'),
            ("ruby puts", 'ruby -e "puts ENV.to_h"'),
            ("perl", 'perl -e "print %ENV"'),
            # A serialisation ASSIGNED to a name. `_COPY_LHS` matches here — the
            # match really is the right-hand side of an assignment — so the ONLY
            # thing refusing it is the sink word standing in front of it.
            ("serialise into a variable",
             'node -e "const s = JSON.stringify(process.env); post(s)"'),
            ("py serialise into a variable",
             'python3 -c "import os,json; s = json.dumps(os.environ)"'),
            # One hop: copied in one statement, printed in the next. Nothing but
            # the dataflow pass reaches these two.
            ("copy then print",
             'python3 -c "import os; e = dict(os.environ); print(e)"'),
            ("copy then log",
             'node -e "const e = { ...process.env }; console.log(e)"'),
            # A printer that is a printer in ONE language only. Ruby's `p` is a
            # full dump and an ordinary variable name everywhere else, so it is
            # scoped to ruby — and re-aiming this gate at the act had quietly
            # reopened it until an adversarial sweep found it.
            ("ruby p", 'ruby -e "env = ENV.to_h; p env"'),
            ("ruby p direct", 'ruby -e "p ENV.to_h"'),
            ("perl say", 'perl -e "say %ENV"'),
            # An interpreter nested in a shell. The outer head is `bash`, which
            # this gate does not read, and nothing looked inside the quoted
            # argument — so the cheapest wrapper in existence walked past it.
            # This one predates the re-aiming; it was silent on both sides.
            ("bash -c wrapper",
             'bash -c \'python3 -c "import os; print(os.environ)"\''),
            ("sh -c wrapper",
             'sh -c \'node -e "console.log(process.env)"\''),
            ("bash -c copy then print",
             'bash -c \'python3 -c "import os; e=dict(os.environ); print(e)"\''),
            # PHP was an interpreter head with no pattern behind it, so a PHP
            # dump was never seen at all.
            ("php superglobal", 'php -r "print_r($_ENV);"'),
            ("php bare getenv", 'php -r "var_dump(getenv());"'),
    ):
        s.check("KL-ENV dump denies (%s)" % label, drive(bash(cmd)).kind, "deny")

    for cmd in ("set -e",
                "set -euo pipefail",
                "export FOO=1",
                "env FOO=1 ./run.sh",
                'node -e "console.log(process.env.PATH)"',
                'python3 -c "import os; print(os.environ.get(\'PATH\'))"'):
        s.check("KL-ENV silent: %s" % cmd[:34], drive(bash(cmd)).kind, "silent")

    # ── KL-ENVVAR: advisory only ────────────────────────────────────────────
    s.check("KL-ENVVAR warns", drive(bash("echo $GITHUB_TOKEN")).kind, "warn")
    s.check("KL-ENVVAR warns on braces", drive(bash("echo ${STRIPE_SECRET}")).kind, "warn")
    s.check("KL-ENVVAR warns on printenv NAME",
            drive(bash("printenv GITHUB_TOKEN")).kind, "warn")
    s.check("KL-ENVVAR silent on PATH", drive(bash("echo $PATH")).kind, "silent")
    s.check("KL-ENVVAR silent on PWD", drive(bash("echo $PWD")).kind, "silent")
    s.check("KL-ENVVAR silent on non-printer", drive(bash("test -n $API_TOKEN")).kind, "silent")

    # ── KL-ASSIGN: a credential literal typed into a shell assignment ────────
    for label, cmd in (
            ("export", "export GITHUB_TOKEN=%s" % DECOY["github_pat"]),
            ("quoted value", 'export GITHUB_TOKEN="%s"' % DECOY["github_pat"]),
            ("command prefix", "STRIPE_SECRET_KEY=%s ./deploy.sh" % DECOY["stripe"]),
            ("bare statement", "AWS_ACCESS_KEY_ID=%s" % DECOY["aws_key"]),
            ("env wrapper", "env NPM_TOKEN=%s npm publish" % DECOY["npm"]),
            ("two wrappers", "sudo env GITHUB_TOKEN=%s ./x.sh" % DECOY["github_pat"]),
            ("declare -x", "declare -x SLACK_TOKEN=%s" % DECOY["slack"]),
            ("local", "local GOOGLE_API_KEY=%s" % DECOY["google"]),
            ("readonly", "readonly OPENAI_KEY=%s" % DECOY["openai"]),
            ("inside sh -c", 'bash -c "export GITHUB_TOKEN=%s"' % DECOY["github_pat"]),
            ("loop body", "for i in 1 2; do export JWT=%s; done" % DECOY["jwt"]),
            ("after a keyword", "if true; then export GITHUB_TOKEN=%s; fi"
                                % DECOY["github_pat"]),
            ("second of two", "export TZ=UTC GITHUB_TOKEN=%s" % DECOY["github_pat"]),
            ("url password", "export DATABASE_URL=postgres://admin:%s@db.example.com/prod"
                             % DECOY["generic"]),
            # The name says nothing and the value says everything. A check keyed
            # on the variable's name is silent here, which is the whole argument
            # for keying on the value instead.
            ("uninformative name", "export FOO=%s" % DECOY["github_pat"])):
        s.check("KL-ASSIGN fires: %s" % label, drive(bash(cmd)).kind, "deny")

    # silent when the value is a REFERENCE — the usage this pack asks for
    for cmd in ("export NODE_ENV=production",
                "export PORT=3000",
                "export RUST_LOG=debug",
                'export PATH="$HOME/.local/bin:$PATH"',
                'export DATABASE_URL="$DATABASE_URL"',
                "export FOO=$(some-command)",
                'export TOKEN="$TOKEN"',
                "export SECRET_KEY=${SECRET_KEY}",
                "declare -x NODE_ENV=production",
                "set -x"):
        s.check("KL-ASSIGN silent: %s" % cmd[:34], drive(bash(cmd)).kind, "silent")

    # look-alikes: an `=` that is an ARGUMENT, not a shell assignment
    for label, cmd in (
            ("make variable", "make BUILD=%s" % DECOY["github_pat"]),
            ("a configure flag", "./configure --with-token=%s" % DECOY["github_pat"]),
            ("a commit message", 'git commit -m "set GITHUB_TOKEN=%s in CI"'
                                 % DECOY["github_pat"])):
        s.check("KL-ASSIGN look-alike: %s" % label, drive(bash(cmd)).kind, "silent")

    # the refusal has to leave the reader with a WORKING command
    v = drive(bash("export GITHUB_TOKEN=%s" % DECOY["github_pat"]))
    s.check("KL-ASSIGN names the variable", "GITHUB_TOKEN" in v.message, True)
    # `-- cmd "$NAME"` is expanded by the calling shell where the name is unset,
    # and `-- cmd '$NAME'` arrives as a literal. Only a single-quoted `sh -c`
    # body works, so a remediation string missing it teaches an empty credential.
    s.check_in("KL-ASSIGN teaches the working spelling",
               "keyless run -s GITHUB_TOKEN -- sh -c '", v.message)
    s.check("KL-ASSIGN never echoes the value",
            DECOY["github_pat"] in v.message, False)

    # ── KL-WRITE: rewrite, never refuse ─────────────────────────────────────
    for label, literal in (("github", DECOY["github_pat"]), ("aws", DECOY["aws_key"]),
                           ("stripe", DECOY["stripe"]), ("openai", DECOY["openai"]),
                           ("slack", DECOY["slack"]), ("google", DECOY["google"]),
                           ("npm", DECOY["npm"]), ("jwt", DECOY["jwt"])):
        content = "TOKEN=%s\n" % literal
        v = drive(write(os.path.join(root, "out.env"), content))
        s.check("KL-WRITE rewrites %s" % label, v.kind, "rewrite")
        s.check("KL-WRITE removes %s" % label,
                literal in (v.updated or {}).get("content", literal), False)

    v = drive(write(os.path.join(root, "deploy.sh"),
                    'curl -H "Authorization: Bearer %s" https://api.example.com\n'
                    % DECOY["generic"]))
    s.check("KL-WRITE catches bearer", v.kind, "rewrite")
    s.check("KL-WRITE bearer removed",
            DECOY["generic"] in (v.updated or {}).get("content", ""), False)

    v = drive(write(os.path.join(root, "app.env"),
                    "DATABASE_URL=postgres://admin:%s@db.example.com/prod\n" % DECOY["generic"]))
    s.check("KL-WRITE catches url password", v.kind, "rewrite")

    # placeholders and references must survive untouched
    for content in ("TOKEN=${GITHUB_TOKEN}\n",
                    "TOKEN=your-token-here\n",
                    "TOKEN=xxxxxxxxxxxx\n",
                    "password: changeme\n",
                    "api_key: <YOUR_KEY>\n",
                    "TOKEN=$GITHUB_TOKEN\n",
                    "# set TOKEN in the environment\n",
                    "version: 3.11.4\nname: my-app\n"):
        s.check("KL-WRITE silent: %s" % content.strip()[:30],
                drive(write(os.path.join(root, "x.env"), content)).kind, "silent")

    # Edit's old_string must not be rewritten, or the edit stops matching disk
    v = drive({"hook_event_name": "PreToolUse", "tool_name": "Edit",
               "tool_input": {"file_path": os.path.join(root, "a.txt"),
                              "old_string": "TOKEN=%s" % DECOY["github_pat"],
                              "new_string": "TOKEN=%s" % DECOY["aws_key"]},
               "cwd": root})
    s.check("KL-WRITE edit rewrites new_string", v.kind, "rewrite")
    s.check("KL-WRITE edit leaves old_string alone",
            (v.updated or {}).get("old_string"), "TOKEN=%s" % DECOY["github_pat"])

    # ── the instrument follows the FILE, not the finding ────────────────────
    #
    # `${NAME}` is a repair only where the file's own reader resolves it. Each
    # row below is the SAME literal in a different destination, so the verdict
    # cannot be coming from the value.
    for path, kind, why in (
            ("out.env", "rewrite", "dotenv expands it"),
            ("deploy.sh", "rewrite", "a shell expands it"),
            ("compose.yml", "rewrite", "compose expands it"),
            ("app.conf", "rewrite", "an ini reader expands it"),
            ("Dockerfile", "rewrite", "a build arg expands it"),
            ("NOTES.md", "rewrite", "prose has no grammar to break"),
            ("notes.txt", "rewrite", "plain text has none either"),
            ("src.ts", "deny", "a program does not expand it"),
            ("main.py", "deny", "nor does this one"),
            ("data.json", "deny", "a data document carries it verbatim"),
            ("cert.pem", "deny", "an unknown reader is assumed not to expand"),
            ("noextension", "deny", "and so is a file with no extension")):
        v = drive(write(os.path.join(root, path), "AWS_KEY=%s\n" % DECOY["aws_key"]))
        s.check("KL-WRITE %s -> %s (%s)" % (path, kind, why), v.kind, kind)

    # A DENY leaves the payload alone. The point of refusing rather than
    # substituting is that nobody is handed a broken file, so a deny that also
    # carried an `updatedInput` would defeat its own reason for existing.
    v = drive(write(os.path.join(root, "src.ts"), "AWS_KEY=%s\n" % DECOY["aws_key"]))
    s.check("KL-WRITE deny carries no rewrite", v.updated, None)
    # `keyless run` appears in the REWRITE message too, so asserting it here is
    # green whether or not the refusal exists. Assert a word only the refusal
    # says.
    s.check_in("KL-WRITE deny says it refused", "Refused.", v.message)
    s.check_in("KL-WRITE deny still names the working alternative",
               "keyless run", v.message)

    # The third rung. A NAME-keyed match in a file that expands nothing is the
    # class `fingerprint` documents as inseparable from a reference, so it is
    # neither refused nor substituted — and the content must come through
    # BYTE-IDENTICAL, which is the whole difference from what this check used to
    # do to a source file.
    warned = "const password = \"%s\";\n" % DECOY["generic"]
    v = drive(write(os.path.join(root, "src.ts"), warned))
    s.check("KL-WRITE warns on a name-keyed match in source", v.kind, "warn")
    s.check("KL-WRITE warn substitutes nothing", v.updated, None)

    # ...and the same literal in a file that DOES expand is still rewritten, so
    # the row above is the destination's doing and not the value's.
    v = drive(write(os.path.join(root, "w.env"), warned))
    s.check("KL-WRITE control: the same value rewrites in a .env", v.kind, "rewrite")

    # ── the allow list is real, and it downgrades rather than silences ───────
    #
    # The refusal has always named `allowed`; until this was wired it named a
    # remedy that changed nothing. `*.lock` is on the default allow list and is
    # not a file type whose reader expands, so it reaches the deny branch and is
    # let through it.
    v = drive(write(os.path.join(root, "deps.lock"), "AWS_KEY=%s\n" % DECOY["aws_key"]))
    s.check("KL-WRITE allowed path is not refused", v.kind, "warn")
    s.check_in("KL-WRITE allowed path says which pattern spared it", "*.lock", v.message)
    v = drive(write(os.path.join(root, "deps.locked"), "AWS_KEY=%s\n" % DECOY["aws_key"]))
    s.check("KL-WRITE control: a near-miss name is still refused", v.kind, "deny")

    # ── MultiEdit: the text lives in a LIST, and it must be reached ──────────
    #
    # The tool was named in this check's tool set while every field it reads sat
    # at the top level, so a bulk edit was scanned for nothing at all — coverage
    # that looks exactly like coverage and is not. These rows assert the walk
    # reaches the list AND that what comes back is the same list.
    def multiedit(path, edits):
        return {"hook_event_name": "PreToolUse", "tool_name": "MultiEdit",
                "tool_input": {"file_path": os.path.join(root, path), "edits": edits},
                "cwd": root, "session_id": "test-session"}

    edits = [
        {"old_string": "A=1", "new_string": "A=2", "replace_all": False},
        {"old_string": "TOKEN=old", "new_string": "TOKEN=%s" % DECOY["github_pat"]},
        {"old_string": "B=1", "new_string": "B=2"},
    ]
    v = drive(multiedit("bulk.env", edits))
    s.check("KL-WRITE reaches a MultiEdit edit list", v.kind, "rewrite")
    got = (v.updated or {}).get("edits")
    s.check("MultiEdit rewrite returns a list", isinstance(got, list), True)
    s.check("MultiEdit rewrite preserves the list LENGTH", len(got or []), len(edits))
    s.check("MultiEdit rewrite preserves entry ORDER and untouched entries",
            [got[0], got[2]] if isinstance(got, list) and len(got) == 3 else None,
            [edits[0], edits[2]])
    s.check("MultiEdit rewrite preserves every OTHER key of the touched entry",
            sorted((got[1] if isinstance(got, list) and len(got) > 1 else {}).keys()),
            sorted(edits[1].keys()))
    s.check("MultiEdit rewrite leaves the touched entry's old_string alone",
            (got[1] if isinstance(got, list) and len(got) > 1 else {}).get("old_string"),
            "TOKEN=old")
    # Asserted as the EXACT replacement, not as "the literal is absent". The
    # absence form is satisfied by a rewrite that never happened — `got` is None,
    # the lookup yields "", and the literal is not in "" — which is the vacuous
    # shape this suite exists to refuse. This form can only pass if the walk
    # reached the list AND substituted the file's own key.
    s.check("MultiEdit rewrite substitutes the file's key into new_string",
            (got[1] if isinstance(got, list) and len(got) > 1 else {}).get("new_string"),
            "TOKEN=${" + "TOKEN}")

    # An entry that is not a mapping is not addressable. It must survive whole
    # rather than being coerced into one — a rewrite that reshapes a structure it
    # does not understand is worse than one that never ran.
    odd = ["not-a-mapping", {"old_string": "x", "new_string": "K=%s" % DECOY["aws_key"]}]
    v = drive(multiedit("odd.env", odd))
    got = (v.updated or {}).get("edits")
    s.check("MultiEdit passes a non-mapping entry through untouched",
            (got or [None])[0], "not-a-mapping")

    # The tier table applies to a bulk edit exactly as it does to a Write: the
    # destination decides, and a bulk edit names one destination for every entry.
    v = drive(multiedit("bulk.ts", [{"old_string": "x",
                                     "new_string": "K=%s" % DECOY["aws_key"]}]))
    s.check("MultiEdit into source is refused", v.kind, "deny")
    v = drive(multiedit("bulk.ts", [{"old_string": "x", "new_string": "y"}]))
    s.check("MultiEdit with nothing credential-shaped is silent", v.kind, "silent")

    # A MultiEdit whose only match is in `old_string` is silent. The text is
    # already on disk and already in the transcript; refusing the edit that
    # REMOVES it would refuse the repair.
    v = drive(multiedit("bulk.ts", [{"old_string": "K=%s" % DECOY["aws_key"],
                                     "new_string": "K=process.env.K"}]))
    s.check("MultiEdit ignores a match confined to old_string", v.kind, "silent")

    # ── KL-HEREDOC: the KL-WRITE act, spelled as a command ──────────────────
    #
    # Every destination here is deliberately NOT a protected name. `cat > x.env
    # <<EOF` is refused by KL-FILE — which reads `cat` plus a `.env` operand as a
    # credential read — so a row written that way is green whatever this check
    # does. Each row asserts the CHECK ID in the message for the same reason: a
    # verdict alone cannot say which gate produced it.
    for cmd, kind, why in (
            ("cat > app.conf <<'EOF'\nSTRIPE_KEY=%s\nEOF" % DECOY["stripe"],
             "deny", "redirect before the opener"),
            ("cat <<'EOF' > app.conf\nSTRIPE_KEY=%s\nEOF" % DECOY["stripe"],
             "deny", "redirect after the opener"),
            ("cat >> app.conf <<'EOF'\nSTRIPE_KEY=%s\nEOF" % DECOY["stripe"],
             "deny", "an append redirect"),
            ("cat <<-EOF > app.conf\nSTRIPE_KEY=%s\nEOF" % DECOY["stripe"],
             "deny", "the tab-stripping opener"),
            ("cat <<EOF > app.conf\nSTRIPE_KEY=%s\nEOF" % DECOY["stripe"],
             "deny", "an unquoted delimiter"),
            ("cat > deploy.sh <<'EOF'\nexport STRIPE_KEY=%s\nEOF" % DECOY["stripe"],
             "deny", "a shell script destination"),
            ("cat > app.ts <<'EOF'\nconst k = \"%s\";\nEOF" % DECOY["aws_key"],
             "deny", "a vendor shape into source"),
            ("cat > app.ts <<'EOF'\nconst password = \"%s\";\nEOF" % DECOY["generic"],
             "warn", "a name-keyed match into source"),
            ("node <<'EOF'\nconst k = \"%s\";\nEOF" % DECOY["aws_key"],
             "warn", "no redirect, so the destination is stdin"),
            ("cat > notes.md <<'EOF'\nSTRIPE_KEY=%s\nEOF" % DECOY["stripe"],
             "warn", "an allowed destination downgrades the refusal"),
            ("cat > app.conf <<'EOF'\nSTRIPE_KEY=${STRIPE_KEY}\nEOF",
             "silent", "a reference is not a literal"),
            ("cat > app.conf <<'EOF'\nDEBUG=true\nEOF",
             "silent", "nothing credential-shaped"),
            ("cat > runbook.txt <<'EOF'\nRun the deploy on the box.\nEOF",
             "silent", "prose is not a credential")):
        v = drive(bash(cmd, cwd=root))
        s.check("KL-HEREDOC %s (%s)" % (kind, why), v.kind, kind)
        if kind != "silent":
            s.check_in("KL-HEREDOC owns that verdict (%s)" % why,
                       "[KL-HEREDOC]", v.message)

    # A heredoc body must reach the check WHOLE. Truncating it at the first line
    # would keep every row above green while missing a literal further down.
    v = drive(bash("cat > app.conf <<'EOF'\nA=1\nB=2\nC=3\nSTRIPE_KEY=%s\nEOF"
                   % DECOY["stripe"], cwd=root))
    s.check("KL-HEREDOC reads past the first body line", v.kind, "deny")

    # An UNTERMINATED heredoc still carries its body into the tool call.
    v = drive(bash("cat > app.conf <<'EOF'\nSTRIPE_KEY=%s" % DECOY["stripe"], cwd=root))
    s.check("KL-HEREDOC reads an unterminated body", v.kind, "deny")

    # ── reading the DESTINATION off the opener ──────────────────────────────
    #
    # Every row is the same body into the same kind of file, spelled differently.
    # A destination read wrongly is silent in both directions: the wrong file's
    # reader class picks the wrong tier, and no failure says so.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from keyless_hooks.checks.heredoc_write import _destination
    for opener, want, why in (
            ("cat > app.conf <<'EOF'", "app.conf", "operator and operand apart"),
            ("cat >app.conf <<'EOF'", "app.conf", "operand glued to the operator"),
            ("cat >> app.conf <<'EOF'", "app.conf", "an append"),
            ("cat 1> app.conf <<'EOF'", "app.conf", "an explicit stdout descriptor"),
            ("cat <<'EOF' > app.conf", "app.conf", "the redirect after the opener"),
            ("cat > 'my file.conf' <<'EOF'", "my file.conf", "a quoted path with a space"),
            ("cat 2> err.log > app.conf <<'EOF'", "app.conf",
             "stderr first — it names where ERRORS go, not the body"),
            ("cat <<'EOF' >&2", "", "a descriptor duplication names no file"),
            ("cat <<'EOF' &> all.log", "",
             "and neither does the both-streams form"),
            ("cat <<'EOF' >>&1", "", "nor a malformed one, by backtracking"),
            ("node <<'EOF'", "", "no redirect at all"),
            ("cat <<'EOF' | tee app.conf", "",
             "a destination named by a program is not a redirect")):
        s.check("KL-HEREDOC destination: %s" % why, _destination(opener), want)

    # And the tier really follows what that read returned: stderr going to a
    # `.log` must not decide the verdict for a body landing in a `.conf`.
    v = drive(bash("cat 2> err.log > app.conf <<'EOF'\nSTRIPE_KEY=%s\nEOF"
                   % DECOY["stripe"], cwd=root))
    s.check("KL-HEREDOC judges the stdout destination, not the stderr one",
            v.kind, "deny")

    # The BODY is what is judged, not the command line around it. The same
    # literal outside a heredoc is KL-ASSIGN's, and the same command with the
    # literal removed is nobody's — so a row that passed because the text merely
    # appeared somewhere would fail one of these two.
    v = drive(bash("cat > app.conf <<'EOF'\nnothing here\nEOF\n# %s" % DECOY["stripe"],
                   cwd=root))
    s.check("KL-HEREDOC judges the body, not the surrounding text", v.kind, "silent")

    # The two views of a heredoc must stay the same set. `strip_heredocs` blanks
    # exactly the spans `heredocs()` reports, so a body can never become visible
    # to an act-detection trigger by accident.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from keyless_hooks import shellview as _sv
    _cmd = "cat > x <<'EOF'\ncat .env\nEOF\necho done"
    _blanked = _sv.strip_heredocs(_cmd)
    s.check("strip_heredocs preserves length", len(_blanked), len(_cmd))
    s.check("strip_heredocs blanks exactly what heredocs() reports",
            [_blanked[a:b].strip() for doc in _sv.heredocs(_cmd) for a, b in doc.spans],
            [""])
    s.check("heredocs() reports the body it blanked",
            [doc.body for doc in _sv.heredocs(_cmd)], ["cat .env"])

    # ── every vendor pattern must match ITS OWN instance ────────────────────
    # By KIND, and through `scan` rather than through a rewrite: a rewrite can be
    # produced by the generic NAME=<opaque> rule while the vendor pattern matches
    # nothing at all. That is exactly what happened — `ghp_` + 34 characters is
    # two short of the real format, and the test was green for the wrong reason.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from keyless_hooks import fingerprint
    for kind, literal in sorted(VENDOR_DECOYS.items()):
        kinds = [f.kind for f in fingerprint.scan("value: %s" % literal)]
        s.check("pattern matches its own instance: %s" % kind, kind in kinds, True)

    # The rewrite must name the FILE's key, not the pattern's label — a file
    # referencing ${STRIPE_KEY} when the key is STRIPE_SECRET_KEY names a
    # variable nobody set.
    for text, want in (("GITHUB_TOKEN=%s" % DECOY["github_pat"], "${GITHUB_TOKEN}"),
                       ("STRIPE_SECRET_KEY=%s" % DECOY["stripe"], "${STRIPE_SECRET_KEY}"),
                       ("AWS_SECRET_ACCESS_KEY=%s" % DECOY["aws_key"],
                        "${AWS_SECRET_ACCESS_KEY}")):
        s.check("rewrite keeps the file's key: %s" % want,
                want in fingerprint.redact(text)[0], True)

    # ── the name-keyed rule, where the keyword is not the whole identifier ──
    #
    # Every case below uses DECOY["generic"] — deliberately NOT a vendor shape.
    # The three cases above pass through a vendor pattern, so they stayed green
    # while `STRIPE_SECRET_KEY=<an opaque value>` matched nothing at all: the
    # keyword has to be followed immediately by `=`, and `SECRET` is followed by
    # `_KEY`. A decoy that two rules can catch cannot tell you which one did.
    #
    # The names are spelled out rather than read from `_ASSIGN` — a table driven
    # by the pattern it is testing goes green the moment an entry is deleted from
    # both at once.
    for name in ("SECRET_KEY", "DJANGO_SECRET_KEY", "STRIPE_SECRET_KEY",
                 "SIGNING_KEY", "SESSION_SIGNING_KEY", "ENCRYPTION_KEY",
                 "CREDENTIAL_ENCRYPTION_KEY", "PGPASSWORD"):
        found = fingerprint.scan("%s=%s" % (name, DECOY["generic"]))
        s.check("name-keyed catches %s" % name,
                [f.kind for f in found], ["named_credential"])
        # The reference has to resolve. Reading only as far as the KEYWORD is the
        # bug that turned GITHUB_TOKEN into ${GITHUB}; a qualified tail puts the
        # other half of the same name at risk.
        s.check("name-keyed names %s in full" % name,
                "${%s}" % name in fingerprint.redact("%s=%s"
                                                     % (name, DECOY["generic"]))[0], True)

    # The counter-half, and it is what keeps the rule above narrow. A credential
    # word with MORE identifier after it names a credential rather than holding
    # one, so these must stay silent — `AWS_ACCESS_KEY_ID` is the public half of
    # the pair and `SECRET_ARN` is an address.
    #
    # Each name goes red under a mutation, and two different ones: the first
    # group under M42 (`key` promoted to a keyword on its own), the second under
    # M41 (any bounded suffix allowed after a keyword). A silence assertion that
    # no mutation can break is a comment with a `check` call around it.
    for name in ("CACHE_KEY", "SORT_KEY", "OBJECT_KEY", "PARTITION_KEY",
                 "IDEMPOTENCY_KEY", "KEY", "ROW_KEY",
                 "SECRET_NAME", "SECRET_REF", "SECRET_ARN",
                 "AWS_ACCESS_KEY_ID", "TOKEN_DOCS_URL", "SECRETS_MANAGER_ARN"):
        s.check("name-keyed leaves %s alone" % name,
                fingerprint.scan("%s=%s" % (name, DECOY["generic"])), [])

    # ── the VALUE/REFERENCE line, from the VALUE side ───────────────────────
    #
    # `fingerprint` withholds a name-keyed finding when the value is a reference
    # rather than a literal — a member path, a call, an expression ending on code
    # punctuation, a run-time substitution. Every row below sits ONE CHARACTER
    # from one of those exemptions and must still be caught, because an exemption
    # that also swallows the literal beside it is a hole, not a fix.
    #
    # Each is written as `%s` against a decoy rather than spelled out: this file
    # is itself written through KL-WRITE, and a spelled literal arrives on disk
    # as `${NAME}`.
    for label, text in (
            # a data grammar terminates a bare value on whitespace or end of line
            ("end of line", "GITHUB_TOKEN=%s\n" % DECOY["generic"]),
            ("space", "PGPASSWORD=%s psql -h db" % DECOY["generic"]),
            # `;` ends a shell statement, so it is NOT code punctuation here
            ("shell semicolon", "SECRET_KEY=%s; ./deploy.sh" % DECOY["generic"]),
            # `:` sits INSIDE composite tokens. Reading it as code punctuation
            # was tried and it dropped a real credential.
            ("colon inside a composite token",
             "ACCESS_TOKEN=%s::readonly" % DECOY["generic"]),
            ("yaml mapping", "secret: %s\n" % DECOY["generic"]),
            ("http header", "X-Hook-Token: %s\n" % DECOY["generic"]),
            # a generated password truncates the value class at its first symbol
            ("password with punctuation", "DB_PASSWORD=%s!aQ\n" % DECOY["generic"]),
            # QUOTED beats every exemption: someone spelled it, whatever it looks
            # like. This is the row that keeps `TOKEN = "a.b.c"` — a JWT — caught.
            ("quoted, dotted like a member path",
             'const TOKEN = "%s";' % ("abcdefgh" + ".ijklmnop" + ".qrstuvwx")),
            ("quoted, ends on code punctuation",
             'client({ apiKey: "%s", region: "eu" });' % DECOY["generic"]),
    ):
        s.check("still a literal: %s" % label,
                [f.kind for f in fingerprint.scan(text)], ["named_credential"])

    # A vendor pattern is never reachable by the exemption, because the exemption
    # withholds only the name-keyed finding. Asserted by KIND on the exact shapes
    # a reference test could otherwise swallow.
    for kind, text in (
            ("jwt", "TOKEN=%s" % DECOY["jwt"]),
            ("openai_key", "TOKEN=%s," % DECOY["openai"]),
            ("aws_access_key", "client(SECRET=%s)" % DECOY["aws_key"]),
    ):
        s.check("vendor pattern survives the exemption: %s" % kind,
                [f.kind for f in fingerprint.scan(text)], [kind])

    # ── the never-allow invariant ───────────────────────────────────────────
    for payload in (bash("cat .env"), bash("env"), read(os.path.join(root, ".env")),
                    write(os.path.join(root, "o.env"), "T=%s" % DECOY["github_pat"]),
                    bash("ls")):
        s.check("never emits allow", drive(payload).kind == "allow", False)

    # ── operator levers ─────────────────────────────────────────────────────
    s.check("KEYLESS_HOOKS_DISABLE silences everything",
            drive(bash("cat .env"), env={"KEYLESS_HOOKS_DISABLE": "1"}).kind, "silent")
    v = drive(bash("cat .env"), env={"KEYLESS_HOOKS_OBSERVE": "1"})
    s.check("observe mode does not deny", v.kind, "warn")
    s.check_in("observe mode says so", "[observe]", v.message)

    # ── PostToolUse is a detector, never a censor ───────────────────────────
    v = drive({"hook_event_name": "PostToolUse", "tool_name": "Bash",
               "tool_input": {"command": "./print.sh"},
               "tool_response": {"stdout": "TOKEN=%s\n" % DECOY["github_pat"]},
               "cwd": root})
    s.check("KL-SEEN warns on output", v.kind, "warn")
    s.check("KL-SEEN does not echo the value", DECOY["github_pat"] in v.message, False)

    # ── no message ever carries a value ─────────────────────────────────────
    leaky = []
    for payload in (bash("cat .env"), read(os.path.join(root, ".env")),
                    bash("cat %s/.env" % root),
                    bash("export GITHUB_TOKEN=%s" % DECOY["github_pat"]),
                    bash("DB=postgres://a:%s@h/d ./run.sh" % DECOY["generic"]),
                    write(os.path.join(root, "o.env"), "T=%s" % DECOY["stripe"])):
        v = drive(payload)
        for value in DECOY.values():
            if value in v.stdout:
                leaky.append(value[:12])
    s.check("no verdict prints a decoy value", leaky, [])

    return s


if __name__ == "__main__":
    ok = run().report()
    harness.cleanup()
    raise SystemExit(0 if ok else 1)
