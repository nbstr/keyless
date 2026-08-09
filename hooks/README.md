# keyless hooks

**The injector is only half the tool. This is the other half.**

`keyless run` makes the safe path *available*. It does not make it the *only*
path — and an agent under completion pressure takes the shortest path, not the
safest one. So it reads the `.env`, or runs `op read`, or dumps `env`, and the
injector was theatre.

This is a store-agnostic hook pack that closes those doors from inside the agent
harness. It works the same whether your secrets live in 1Password, Infisical,
Proton Pass, the macOS Keychain, Vault, Doppler, or a `.env` file.

```console
$ keyless setup
~/.claude/settings.json: added a PreToolUse handler; added a PostToolUse handler; added 4 permission allow rule(s); added 8 permission deny rule(s)
```

`keyless setup` installs this pack along with everything else, which is the point
of it: for a while the binaries had one installer and this pack had another, and
neither mentioned the other. `./install.sh` still works standalone and does the
same merge.

**Turning it off is one word**, and reaching for it is better than working around
the pack by hand:

```console
$ keyless disable    no check fires. Nothing is unregistered and nothing is lost
$ keyless enable     back on
```

It writes `"enabled": false` into `~/.config/keyless/hooks.json` — this pack's own
config, read by `config.py`, and not the agent's settings file. `keyless doctor`
reports `SWITCHED OFF` for as long as it is.

---

## What it does

Eight checks, one process per event. Each names the working alternative in the
same breath as the refusal, so the agent's next action is the right one rather
than a retry or a question.

| id | fires on | verdict |
|---|---|---|
| `KL-FILE` | a file whose content is a credential — `.env`, `~/.aws/credentials`, `~/.ssh/id_*`, `.npmrc`, `.claude.json`, … | **rewrite** on `Read`, **deny** on `Bash`/`Grep` |
| `KL-VAULT` | a vault CLI verb that prints plaintext, across 16 stores | **deny** |
| `KL-ENV` | an environment dump — `env`, `printenv`, `set`, `export -p`, and the whole-environment object reaching a printer or serialiser inside an interpreter | **rewrite** when bare, **deny** when it captures |
| `KL-ENVVAR` | a credential-named variable being echoed | **warn** |
| `KL-ASSIGN` | a credential literal typed into a shell assignment — `export X=…`, `X=… cmd` | **deny** |
| `KL-HEREDOC` | a credential literal written into a file through a here-document — `cat > f <<EOF` | **deny**, **warn** when no file is named |
| `KL-WRITE` | a credential literal in a `Write`, `Edit`, `MultiEdit` or `NotebookEdit` | **rewrite**, **deny** or **warn** — see below |
| `KL-SEEN` | a credential shape in tool output | **warn** |

### It prefers rewriting to refusing — where the rewrite is a repair

A block costs a turn and teaches nothing; the second attempt writes the same
literal into a different file. So the pack substitutes wherever substituting
actually helps.

**What makes `${NAME}` a repair is that the file's own reader resolves it.** A
`.env`, a shell script, a compose file, a CI job: each expands the reference, so
the corrected file is one `keyless run` away from working. A `.ts` file expands
nothing. `const key = ${STRIPE_KEY}` is a syntax error, and the author is handed
a broken file and told it was repaired — including inside a test fixture, where
a decoy silently turned into `${NAME}` is a control that no longer controls
anything and still looks like one.

Source files are the large majority of what a write check sees, so `KL-WRITE`
reads the destination and picks its instrument:

| the destination | the finding | what happens |
|---|---|---|
| its reader expands `${NAME}` — `.env`, `.sh`, `.yml`, `.conf`, `.toml`, a `Dockerfile` | any | **rewrite** — the write proceeds without the secret |
| prose or plain data — `.md`, `.txt`, `.csv` | any | **rewrite** — there is no grammar to break |
| anything else — a program, a manifest, a data document, an unknown type | a **vendor** shape (`AKIA…`, `ghp_…`, a private-key header) | **deny** — the shape is proof on its own |
| anything else | only a **name-keyed** match (`password: <opaque>`) | **warn**, and the write goes through UNTOUCHED |

The last row is the one worth defending. That rule cannot separate a literal from
an identifier that merely looks opaque — `password`: `E2E_LOGIN_PASSWORD` — so
refusing would refuse ordinary source edits and substituting would corrupt them.
Reporting it is the only act that is right whichever of the two it was.

An unknown extension is treated as *not* expanding. That is the direction that
fails safe: the worst outcome of guessing wrong is a message instead of a
substitution.

**The refusal's escape hatch is real.** A path on the `allowed` list — where
examples live — downgrades a deny to a note rather than silencing it. The message
has always named `allowed`; until now it named a remedy that did nothing.

`KL-ASSIGN` and `KL-HEREDOC` never substitute, and the reason is worth stating:
the substitution that is right for a file is dangerous for a command. Rewriting
`STRIPE_SECRET_KEY=<literal> ./deploy.sh` into `${STRIPE_SECRET_KEY}` runs the
deploy against production with an EMPTY credential, immediately, with nobody
looking. A file is read before it is used; a command is not — and inside an
unquoted here-document the shell expands `${NAME}` *before* it reaches the file,
so the same rewrite writes a reference in one spelling and an empty value in the
other.

### The bulk-edit tool keeps its text in a list

`MultiEdit` was named in the write check's tool set while every field the check
read sat at the top level, so a bulk edit was scanned for nothing at all —
coverage that looks exactly like coverage and is not. The walk reaches
`edits[].new_string` now, and the rewrite returns the **same list**: same length,
same order, every other key of every entry carried over, entries that are not
mappings passed through untouched, and `old_string` never rewritten (it has to
keep matching what is on disk). Those are assertions in the contract suite, not
claims here.

**The Claude Code build this was measured against does not offer that tool at
all** — replayed over every tool call in the transcript tree, `MultiEdit` was
named in settings and in prose and never once invoked. So this closes no leak
that has happened here; it makes a coverage claim TRUE that was false, on a tool
name the pack advertises, that other harnesses do offer and that this one has
shipped before. An unexercised name in a tool set is the same shape as an
untested control: it looks like cover and answers nothing.

**A `Read` of a protected file is redirected to a names-only view.** The agent
gets what it was actually after:

```
# keyless: /app/.env holds credentials.
# This is a NAMES-ONLY view. No value from that file appears below,
# and no value from it is available to this session.
#
# Use one without reading it:   keyless run -s <NAME> -- <your command>
# See what keyless can resolve: keyless ls

DATABASE_URL=[keyless:redacted]
STRIPE_KEY=[keyless:redacted]
DEBUG=[keyless:redacted]
```

**A bare environment dump is masked, and the pipeline survives.**

```
env                  ->  env | sed -E 's/=.*/=[keyless:redacted]/'
env | grep -i token  ->  env | sed -E 's/=.*/=[keyless:redacted]/' | grep -i token
```

The filter still filters, the names still print, no value crosses the boundary,
and the call is never refused.

**Copying the environment for a child process is not a dump, and is not
touched.** This gate is aimed at the act, not at the expression:

```
env = dict(os.environ)                     allowed
const env = { ...process.env }             allowed
spawn(cmd, { env: { ...process.env } })    allowed
subprocess.run(cmd, env=os.environ.copy()) allowed

print(os.environ)                          denied
console.log(JSON.stringify(process.env))   denied
e = dict(os.environ); print(e)             denied
```

Building a child's environment is the same act `keyless run` performs, and a
gate that refuses it is a tax on ordinary work rather than a guard. The last row
is the two-statement spelling, caught by one hop of dataflow within the single
command string; two hops is out of reach and stays out of reach, because a hook
holds no model of interpreter state.

**A credential literal being written into a file whose reader expands a
reference becomes one.** Where the reader does not, the tier table above applies
instead and nothing is substituted.

```
GITHUB_TOKEN=ghp_DECOYNOTAREALTOKENDECOYNOTAREALTOKEN
                      ↓
GITHUB_TOKEN=${GITHUB_TOKEN}
```

The write proceeds. The file simply does not carry the secret, and `${NAME}` is
a form the file's own reader already resolves — so the corrected file is one
`keyless run` away from working rather than a dead end. The name comes from the
file's own key, never from the pattern's label: `${STRIPE_KEY}` would be a
variable nobody set.

---

## The two invariants

### 1. It never blocks you by failing

Exit 2 blocks a tool call and every other non-zero exit does not, so a hook that
crashes already fails open. What that buys is only as good as how cleanly it
crashes, so the discipline is layered:

- **Payload fields are coerced at one entry point.** A wrongly-typed field
  becomes the empty value of its declared type — never a crash, and never a
  fabricated default a check might act on.
- **Each check runs inside its own guard.** One that raises is recorded as an
  `error` row and skipped; the others still run.
- **No blanket `try/except` around the checks.** That converts a crash into a
  silent skip — the same absence wearing a disguise — and you cannot write an
  assertion about a swallowed exception.
- **The battery drives it.** Hostile stdin shapes, wrong-typed fields, a
  raising check, five broken environments, an unwritable state directory, three
  corrupt configs, and a physically truncated module. Every one exits 0.
- **A broken environment must still DENY.** Losing state is not a reason to stop
  protecting, and that is asserted separately from exiting 0.

Two operator levers, both out of an agent's reach because a session cannot set
its own environment. They go in the settings file's `env` block:

```json
"env": { "KEYLESS_HOOKS_OBSERVE": "1" }
"env": { "KEYLESS_HOOKS_DISABLE": "1" }
```

`OBSERVE` records every verdict and enforces none, writing `mode: observe` so a
promotion can be justified from the log rather than from a feeling. `DISABLE`
turns the pack off entirely.

### 2. It never introduces a read path of its own

No check prints a secret value into its output, its log, or its error message.

The one place bytes from a secret file reach output is the names-only view, and
it is built so that cannot go wrong: a name is copied only from the left of a
key/value line, only when it matches a bounded identifier pattern *whole*, and
only from a file where a **majority** of content lines have that shape. A PEM
key has one such line in thirty, so it yields no names at all rather than a
plausible-looking slice of key material.

The decision log records a check id, a verdict, a tool, a path, a command's head
word and the NAME of a credential shape. It does not record a value, an encoding
of one, **or a hash of one** — a hash of a low-entropy secret is a value with a
delay.

### The invariant behind both: it never emits `allow`

`permissionDecision: "allow"` suppresses the host's own permission prompt *and*
overrides other guards' opinions on the same call. A secrets hook emitting it
would silently disarm whatever else you have registered on `PreToolUse`.

Measured on Claude Code 2.1.223: **`updatedInput` is honoured with no
`permissionDecision` field at all.** A `Read` was redirected to a redacted copy
and the model quoted the redaction; the paired control with the hook removed
quoted the canary. So a rewrite costs nothing and grants nothing. This pack
rewrites, denies, or stays silent.

---

## Install

```console
$ cd hooks
$ ./install.sh                     # ~/.claude/settings.json
$ ./install.sh --scope project     # ./.claude/settings.json, committable
$ ./install.sh --dry-run           # print the merge, write nothing
$ ./uninstall.sh                   # take it back out
```

Requires Python 3.8+ and nothing else — stdlib only, no toolchain, no install
step for the pack itself.

The installer **never blindly overwrites**. It parses your existing settings,
merges only its own entries, writes to a temporary file beside the original,
flushes it to disk, re-parses those bytes as JSON, and only then replaces the
original through an atomic rename. A settings file that does not parse disables
every hook you have, which is the one outcome worse than not installing. It
refuses outright to touch a settings file it cannot already parse.

Idempotent in both directions. Your own hooks and deny rules come through
byte-identical.

**No backup file is written, and the reason is that every job one would do is
already done in the write itself.** An input it cannot parse is refused before
anything is opened; an output that does not parse is discarded before the
original is touched; the replace is atomic, so the file is the old bytes or the
new bytes and never a half of either; and the receipt below makes removal exact.
A copy beside the original adds none of that, and it leaves files behind in a
directory this pack does not own.

### About the permission deny rules

The fragment adds `permissions.deny` entries for **opaque credential stores
only** — `~/.ssh/id_*`, `~/.aws/credentials`, `~/.claude.json`,
`~/.cckeys.json`, `~/.infisical/.token`, and friends. For those a hard gate is
strictly better than the hook: it survives a broken hook, `bypassPermissions`,
`--dangerously-skip-permissions`, and the subagent boundary.

**`.env` is deliberately absent, and that is a measured decision.** A permission
deny *pre-empts* the hook's rewrite. Driven live: with `Read(**/.env)` in the
list, the session was told only "denied by permission settings" — no names, no
alternative. With it removed, the same session was told which three names the
file declares and offered `keyless run -s DATABASE_URL -- <cmd>`. The hook is
the better layer for a file worth inventorying; the deny rule is the better
layer for a file that is nothing but key material.

`./install.sh --hard-deny` adds `.env`, `.npmrc`, `.netrc`, `.pgpass` and
`*.pem` to the deny list for anyone who wants the hard gate anyway. It costs the
names view.

---

## Configure

Everything the pack blocks is a list, so a store this file has never heard of is
one JSON object away. Two files are read, later winning, both optional and both
fail-open:

```
~/.config/keyless/hooks.json     your machine
<cwd>/.keyless-hooks.json        this project, committable
```

```json
{
  "protected_add": ["secrets.yaml", "~/.config/myvault/token"],
  "allowed_add": ["fixtures/*.env"],
  "vault_verbs_add": [["myvault", "^get\\b", "myvault run -- <cmd>", null]],
  "pattern_tools_add": ["mygrep"],
  "observe": false
}
```

Any key takes `_add` to extend the default or the bare name to replace it —
both, so dropping one default does not mean restating the other twenty. A config
that will not parse leaves the defaults standing; it never disables the pack, and
a single row whose regex will not compile disables that row and nothing else.

`vault_verbs` rows are `[binary, verb-path-regex, the safe alternative,
flag-regex]`. The pattern is matched against the VERB PATH — the leading
flag-free run of words — so `secrets folders get --env=prod --path=/` is tested
as `secrets folders get`. The subcommand is read, never just the binary: every
store in the table has a harmless sibling one word away (`op run` beside
`op read`, `doppler secrets set` beside `doppler secrets`, `infisical secrets
folders get` beside `infisical secrets get`), and a gate that blocks the working
path gets uninstalled. `--help`, a bare `-h` and a leading `help` clear every row.

The fourth element is a second condition on the RAW arguments, for a subcommand
that prints metadata or a value depending on one flag — `security
find-generic-password` prints attributes until `-w` is added.

`pattern_tools` is the list of programs whose FIRST positional argument is a
pattern, a script or a filter rather than a path: `grep`, `sed`, `awk`, `jq` and
the interpreters. That one operand is exempt from filesystem glob expansion, so
`grep -rn '.*' src/` is a regex rather than a request for every dotfile in the
directory. Only the first positional, and only when no `-e`/`-f`/`--regexp`/
`--file` flag supplied the pattern from elsewhere — `grep -n KEY prod.*` and
`grep -f patterns.txt prod.env` are both still reads.

---

## Latency

The number that decides whether this stays installed. Measured interleaved
against two baselines in the same loop, 25 rounds each, so the figure is the
pack's and not the machine's:

| case | median | p90 | over a bare interpreter | over deps |
|---|---:|---:|---:|---:|
| bare `python3 -c pass` | 18.2 ms | 19.4 ms | — | — |
| `python3 -c "import json, re"` | 19.1 ms | 20.2 ms | +0.9 ms | — |
| unmatched `Bash` call | 25.2 ms | 26.2 ms | **+7.0 ms** | **+6.1 ms** |
| unmatched `Write` (4 KB) | 24.9 ms | 26.1 ms | +6.6 ms | +5.7 ms |
| a firing `Bash` deny | 25.3 ms | 26.5 ms | +7.0 ms | +6.1 ms |
| a `Read` rewrite (reads the file, writes the view) | 26.7 ms | 27.6 ms | +8.4 ms | +7.6 ms |
| a 100 KB `Write` scan | 52.8 ms | 54.1 ms | +34.6 ms | +33.7 ms |

**Single figures, on one machine, on one interpreter. Do not quote them — run
the rig.** The absolute column moves with load and the deltas move with the
interpreter, and this section carried a single decimal figure as though it were a
constant until it was run somewhere else.

### Two baselines, because the first one lies across interpreters

`re` and `json` are stdlib this pack cannot exist without: it parses JSON on
stdin and every check is a compiled pattern. Whether the interpreter's own `site`
already imported them decides who is billed for that work — and it moves the
headline number by more than a factor of two with no change to any code here:

| interpreter | over a bare interpreter | over `import json, re` |
|---|---:|---:|
| 3.9 | +21.2 ms | +12.8 ms |
| 3.13 | +10.8 ms | +9.8 ms |
| 3.14 | +9.6 ms | +7.1 ms |

Same machine, same pack, same payload, all three loaded identically. **A test
asserting a RATIO against interpreter start time is measuring the operating
system**, which is why this suite was red on Linux on every Python from 3.6 to
3.13 while nothing here was wrong. The assertions read the delta over the second
baseline; the first stays in the table because it is the honest answer to *what
does a session pay*, which is a different question from *did this pack regress*.

### The table reports medians. The assertions read minima.

Noise only ever *adds* time, so across 25 interleaved rounds the minimum is the
closest estimate of what the work costs and the median is what a user waits.
Those are different questions and this suite needs both.

It used to assert `a firing check costs under 2x the floor` on medians, and the
two "worked" rows are the only ones that touch the filesystem. Measured with the
machine deliberately saturated, five consecutive runs, **that assertion failed
four times** — the worked median moved between 30 ms and 200 ms while the floor
sat at 24 ms, because I/O contention inflates a file read and does not inflate an
import. In the same five runs the CPU-bound assertions never moved: 5.6–6.4 ms
against a 25 ms limit, 27.7–30.6 ms against 60 ms. On minima, under that same
saturation, the worked cases sit **+1.3 ms and +4.6 ms** above the floor.

The thresholds come from the one regression this suite has actually had — a
module-scope `traceback` import worth +8.1 ms — with room for a slow runner. They
do **not** catch an 8 ms creep, because 8 ms of regression on 3.14 lands inside
3.9's healthy band. Catching that needs a recorded per-interpreter baseline,
committed and refreshed deliberately; there is nowhere in this suite to keep one,
and saying so beats a tighter number that goes red on a slow runner and gets
loosened by whoever sees it first.

It was far worse until `-X importtime` showed `traceback` pulling
`_colorize → dataclasses → inspect` at module scope — on every call in every
session, for a path reachable only when a check is already broken. It and
`hashlib` are imported at their use sites now.

The scanner is a small number of compiled alternations in-process — no
subprocess, no `gitleaks`, no `trufflehog`. A separate binary would add a
process spawn to the same critical path, which is the whole budget.

Reproduce: `python3 tests/test_latency.py`.

---

## Proving it

```console
$ python3 tests/run.py        # contract, false-positive, fail-open, adversarial,
                              #   install, publication, latency
$ python3 tests/mutate.py     # every check broken on purpose; each must be caught
```

Both commands print their own counts, and this document deliberately does not
restate one: a number copied into prose goes stale the next time a check is added,
and this section carried three that were wrong by the time anyone read them.

Five kinds of proof, because a green contract suite is a hypothesis:

- **contract** — every gate × {fires, silent, look-alike}, plus every vendor
  pattern asserted by *kind* against a decoy of the real length.
- **fail-open** — every malformed, hostile and broken input allows, *and no check
  crashed while allowing it*. The second half is not decoration: the engine
  isolates a handler that raises, so the process exits 0 and prints nothing —
  byte-for-byte what a correctly silent verdict looks like. A whole check could
  have been dead on every hostile payload in this layer and the layer would have
  stayed green. The decision log carries an `error` verdict, and that is what is
  asserted.
- **adversarial** — the attack corpus driven against the block list, printed as a
  table with an honest survivor row.
- **publication** — no comment or docstring in `hooks/` carries a measurement of
  one person's machine or accounts, and no commit message does either. A grammar
  rather than a list of forbidden values, so it catches the next one and names
  none of the last ones.
- **mutation** — each check broken on purpose, with the patched file diffed to
  prove the mutation *landed*, and a baseline control in the same copied tree so
  a broken invocation can never read as a run of successful mutations.

Every fixture value is invented in the suite. No test reads a real `.env`, a
real keychain item, or a real token.

### What still gets through

Published, because an honest list of survivors is worth more than a claim of
completeness. `tests/test_adversarial.py` fails if an unlisted attack gets
through **and** if a listed one is now blocked — a stale limit is a lie in the
other direction.

| gets through | why it is out of reach |
|---|---|
| `echo .env \| xargs cat` | the operand reaches the reader through a pipe at run time; no static view of the command text contains it as an operand of `cat` |
| `cat $ENVFILE`, where the variable was set by an **earlier** call | the hook sees one command at a time and holds no model of shell state, so that name cannot be resolved to a path |
| `printf 'cat .env' > s.sh; bash s.sh` | writing a script is not reading a file, and running it names no protected path. The read happens inside a process no hook is shown |
| a value the agent already holds in context | nothing here can un-see something. `KL-SEEN` reports it and cannot redact it — `PostToolUse` has no redaction channel |
| `cat <<'EOF' \| tee f` | the body reaches a file, but the file is named as an ARGUMENT to another program rather than as a redirect operand. Resolving it means modelling what every filter in a pipeline does with its arguments — `tee`, `sponge`, `dd of=`, a script of your own |
| `node <<'EOF'` carrying a literal | the body is a program, a query or a manifest on standard input, and no file is named at all. Reported rather than refused: refusing a body fed to an interpreter would refuse ordinary work, and there is no file to remove the value from |
| a name-keyed match written into source | reported rather than refused or rewritten, for the reason in the tier table above — neither act is right when the rule cannot say which of the two it is looking at |

Those are rows in the attack corpus, not prose: the suite drives them on every
run and fails if one becomes blocked, so the list cannot quietly go stale in
either direction.

`cat > .env <<EOF` used to be on this list. It is not any more — `KL-HEREDOC`
reads the body through the same walk that blanks it for every other check, and
the blanking is untouched. Reading a body for CONTENT is not act detection: a
body redirected into a file is not text about a command, it is the bytes of the
file being written.

The attacks that are blocked include `sh -c`, `bash -c`, `eval`,
`$(echo cat) .env`, `cat $(echo .env)`, `echo "$(cat .env)"`, backticks,
`python3 -c`, `node -e`, `perl`, `while read … < .env`, `cat < .env`,
`cat <.env`, `.en''v`, `.e*v`, `.en[vw]`, `dd if=.env`, `\cat`, `/bin/cat`,
`sudo`, `env`, `command`, `timeout 5`, a symlink, a `..` traversal, a variable
assigned in the same command, `for … in .env`, subshells, brace groups, `xxd`,
`base64`, `od`, `strings`, `nl`, `tr`, `cp`, `mv`, and the same set aimed at the
vault CLIs and the environment dumps.

---

## Harness notes

Measured on Claude Code 2.1.223, not inferred:

- **`PreToolUse` can substitute input via `updatedInput`, with no
  `permissionDecision` field.** It binds subagents. This is the mechanism for
  every rewrite here.
- **`PostToolUse` cannot redact a tool result.** `updatedToolOutput`,
  `updatedOutput`, `toolResult` and `displayContent` were all ignored and the
  model received the canary; only `additionalContext` reaches it. `KL-SEEN` is
  therefore a detector and a warner, never a censor. Anyone building on
  after-the-fact redaction is building on nothing.
- **A `permissions.deny` path rule is a real gate**, and it *pre-empts* a hook
  rewrite on the same call. See "About the permission deny rules".
- **`Bash(<binary>:*)` deny rules are near-worthless** — half of ten bypass
  spellings walk past `Bash(cat:*)`. Nothing here matches on a binary name
  alone; the triggers read the FILE a command touches, or the subcommand that
  selects the mode.

### Known limits

- **`KL-WRITE` still rewrites one shape of credential REFERENCE**, and it is the
  only one left: a bare identifier that ends on whitespace or on end of line —
  `password`: `E2E_LOGIN_PASSWORD`. A member path, a call, an expression ending
  on `(`, `,` or `)`, and a run-time `$( … )` are all withheld now, each with a
  false-positive row driving it in `tests/test_false_positive.py`. The residual
  shape has a row of its own asserting that it IS still rewritten, so a change
  to it is a decision rather than a side effect. Nothing separates it from a
  literal but the value's own randomness, and the three discriminators that
  reach it — an entropy floor, a `:` versus `=` separator, "the same word
  appears elsewhere in this file" — were each measured dropping a real
  credential.
- **The file-type table is a table, and a table is never complete.** `targets.py`
  enumerates the readers that expand `${NAME}` and the file types that have no
  grammar to break; everything else is treated as a program. A type missing from
  the first list gets a message where a substitution would have worked, which is
  the cheap direction — but a type wrongly IN it gets a substitution into
  something that had to parse. Read that file before adding a row.
- **A rewrite in a file whose reader expands is still only a repair if the value
  is a secret.** A decoy or a public identifier in a `.env` is substituted away
  exactly like a live key, and the write proceeds, so nothing announces the loss
  beyond the message. Spell such a value so it is not credential-shaped, or put
  its file on the `allowed` list.
- **`settings.json` is writable by a session**, so a gate configured there sits
  inside its own blast radius. Closing that needs a privilege boundary the
  harness does not currently expose. Managed policy settings are the nearest
  thing available, and this pack does not attempt it.
- **Masking is a filter, not a control** — the same limit `keyless` itself
  states. A capable agent that decides to exfiltrate is not the threat model; an
  agent taking a shortcut is.
- **`auto` permission mode contains an undisclosed LLM classifier and is
  non-deterministic.** Never count a classifier block as coverage, and never
  measure a hook from a single run.

### Portability to other harnesses

| | Claude Code | Cursor | Codex / OpenAI |
|---|---|---|---|
| the checks (`keyless_hooks/`) | ✅ | ✅ — pure functions over a command string, a path and a file's content | ✅ |
| the engine's I/O contract | ✅ | ⚠️ needs an adapter for that host's payload and decision shapes | ⚠️ same |
| `updatedInput` rewrites | ✅ measured | ❔ unverified — check before relying on it | ❔ unverified |
| `permissions.deny` path rules | ✅ | ❌ no equivalent | ❌ no equivalent |
| `install.sh` | ✅ | ❌ different settings file and schema | ❌ |

The porting surface is `payload.py` and `engine.py` — roughly 200 lines. The
checks, the shell views, the path matcher and the scanner carry no host
assumptions at all. **The one thing not to assume is the rewrite:** the whole
"prefer rewrite over deny" design rests on a measurement made against one host,
and a host without input substitution turns three rewrites into three denies.

---

## Layout

```
hooks/
├── keyless_hook.py            the entry point the harness runs
├── install.py / install.sh / uninstall.sh
├── settings-fragment.json     what gets merged, with its reasoning inline
├── keyless_hooks/
│   ├── engine.py              one process, every check, one verdict
│   ├── registry.py            every check, its event, its tier
│   ├── payload.py             the coercion boundary
│   ├── config.py              every list the pack blocks on
│   ├── shellview.py           three views of a command; statements, heads, here-docs
│   ├── secretpaths.py         is this a secret file, and what names does it declare
│   ├── targets.py             what a file's own reader does with ${NAME}
│   ├── fingerprint.py         credential shapes, and the rewrite
│   ├── decisions.py           the log, which never holds a value
│   └── checks/
└── tests/
```
