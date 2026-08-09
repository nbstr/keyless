# keyless

**Use your keys without ever holding one.**

You name a credential. The command you run receives it. You never see it, your
shell history never records it, and your AI agent's transcript never contains
it.

```console
$ keyless run -s DATABASE_URL -- psql
$ keyless run -s GITHUB_TOKEN -- gh pr list
$ keyless run -s STRIPE_KEY=stripe-live -- ./deploy.sh
```

The secret is read from a store, placed in the child process's environment, and
scrubbed out of the child's stdout and stderr on the way back. `-s NAME` injects
the secret `NAME` as `$NAME`. `-s ENV=NAME` injects the secret `NAME` under a
different variable, so what a store calls something and what a program expects
never have to agree.

Two rules shape everything else, and both are structural rather than advisory:

- **[`keyless run` never refuses to run your
  command.](#rule-1-it-never-refuses-to-run-your-command)** A missing name, a
  broken config or an unreachable store warns on stderr and runs your command
  anyway, with an unmodified environment.
- **[No verb prints a value.](#rule-2-there-is-no-verb-that-prints-a-value)**
  There is no `get`, no `--reveal`, no debug flag. If a command needs a
  credential, run the command under `keyless run`.

On its own that is a good habit around a store your own uid can read. Add
[`keylessd`](#keylessd--the-uid-boundary) and it becomes a boundary: the store
moves behind a second uid, your sessions ask over a socket, and the socket
carries names and results but never the store credential.

macOS today. MIT licensed.

---

## Why this exists

A credential reaches a command in **four shapes**. Each one puts the value
itself on the command line, where the shell, the history file and an agent's
transcript all record it:

| Shape | What it looks like |
|---|---|
| Embedded in a URL | `https://user:VALUE@host` |
| An environment assignment | `export TOKEN=VALUE`, `VAR=VALUE cmd` |
| A CLI flag | `--token VALUE` |
| An HTTP header | `Authorization: Bearer VALUE` |

All four are **one primitive wide** — *spawn a child with the secret in its
environment*. So `run` is the product and everything else is support.

### Your number, not ours

How often this happens on **your** machine is the only count that should
persuade you of anything, and this README is the wrong place to learn it from.
Standard tools, nothing installed. Each line prints a count and never prints a
matching line — the same rule the tool itself follows:

```console
# swap in ~/.bash_history, or any transcript directory
H=~/.zsh_history

grep -acE 'https?://[^ /]*:[^ /@]*@' "$H"                       # url
grep -acE '[A-Z_]{4,}=[^ ]{12,}' "$H"                           # env
grep -acE '\-\-(token|key|secret|password)[= ][^ -][^ ]*' "$H"   # flag
grep -acE '[Aa]uthorization: *(Bearer|Basic) [^ "]+' "$H"        # header
```

Four counts. They are counts of **lines, not of secrets** — a shape is
checkable without anyone reading a value, which is why the recipe counts shapes
and never values. A correctly wrapped `keyless run` matches none of the four, so
it does not count the fix as the problem.

The CLI-flag shape is the documented reason [`keyless put` has no `--value`
flag](#storing-a-secret).

---

## Install

```console
git clone https://github.com/nbstr/keyless
cd keyless
cargo install --path .
keyless --version
```

Requires Rust 1.89 or later — [rustup.rs](https://rustup.rs) if you have no
toolchain. `cargo install` writes to `~/.cargo/bin`, which has to be on your
`PATH`; the `--version` line is there so you find that out now rather than
three commands later.

The store trait is portable and the rest of the tool has no platform-specific
behaviour beyond POSIX process handling. The daemon's caller attestation is the
exception — it is XNU-specific, and [`install/README.md`](install/README.md)
records what replaces each piece on Linux.

That installs the client only, and the client alone reads your keychain
directly. For the uid boundary, see [`install/README.md`](install/README.md) —
one `sudo`, and the installer is dry-run until you pass `--commit`.

---

## Your first command

Put a secret in your keychain — or let `keyless` generate one and put it there,
which is the flow in which no plaintext exists outside the store:

```console
$ security add-generic-password -s keyless -a DATABASE_URL -w
$ keyless new DATABASE_URL          # generates it; see Storing a secret below
```

Then use it:

```console
$ keyless run -s DATABASE_URL -- psql
```

That already works with no config file at all: an undeclared name is looked up
as its own account under the default keychain service. **Declaring names is what
makes them enumerable**, which is what `ls` lists — and what lets one name point
somewhere other than the default.

`~/.config/keyless/config.json`:

```json
{
  "stores": { "keychain": { "service": "keyless" } },
  "secrets": {
    "DATABASE_URL": { "note": "staging read replica" },
    "GITHUB_TOKEN": { "account": "demo-token", "service": "demo" }
  }
}
```

```console
$ keyless ls
DATABASE_URL	*	-	staging read replica
GITHUB_TOKEN	*	-	-

$ keyless doctor
config   /Users/you/.config/keyless/config.json
         ok, 2 names declared
audit    /Users/you/.local/state/keyless/audit.jsonl
         ok, 41 rows, chain intact
store    keychain ok

0 problem(s). A problem here degrades a run; it never blocks one.
```

`doctor --probe` additionally asks each name whether it resolves, printing `ok`
or `missing` — never a value, and never a length, because a length is still
information about a secret. It may trigger a keychain access prompt, which a
plain `doctor` does not.

`ls` prints four tab-separated fields — name, store, location, note — with `-`
wherever there is nothing to say, so a parser never has to count them. The
**location** column answers "which tenant does this name point at?", and only
Infisical has an answer worth printing there: its environment decides *which
real value* comes back.

```console
$ keyless ls
DATABASE_URL	infisical	staging:/backend	staging read replica
STRIPE_KEY  	infisical	no-env:/backend 	-
GITHUB_TOKEN	keychain 	-               	-
```

`no-env` is the set of names that will degrade until you give them an
environment. A keychain account is not printed: it picks an item, not a tenant,
and a lookup detail in a listing is noise.

**Nothing in the config file is ever a secret value.** It holds names,
references, store kinds, paths and timeouts. There is no field a value fits in,
which is why it needs no special permissions and can be committed.

Unknown fields are ignored rather than rejected, so a config written for a newer
build with more backends degrades to "I cannot serve those names" instead of
refusing to parse and therefore serving none.

---

## Stores

Three, and the first is the only one on by default.

| Store | `enabled` default | Reached by | Live path verified |
|---|---|---|---|
| `keychain` | **on** | `security find-generic-password -w` | yes |
| `infisical` | off | `infisical run … -- printenv KEY` | yes — CLI 0.43.114, 2026-08-06 |
| `proton` | off | `pass-cli run --env-file … -- printenv` | yes — CLI 2.2.5, 2026-08-08 |

The two network-backed ones are off unless asked for: a keychain-only setup must
not start paying a process spawn and a network round trip per lookup because a
newer build knows how to talk to a vault.

```json
{
  "stores": {
    "keychain": { "service": "keyless" },
    "infisical": { "enabled": true, "path": "/backend" },
    "proton": { "enabled": true, "session_dir": "/Users/you/.keyless-pass-session" },
    "default": "keychain"
  },
  "secrets": {
    "DATABASE_URL": { "store": "infisical", "env": "staging", "path": "/api",
                      "key": "DB_URL" },
    "GITHUB_TOKEN": { "store": "keychain", "account": "demo-token" },
    "HOME_WIFI":    { "store": "proton", "vault": "Personal", "item": "Router",
                      "field": "password" }
  }
}
```

### One name, several stores

With a company vault and a personal vault both configured, `DATABASE_URL` could
mean either. "Ask each backend in turn and take the first hit" answers that with
configuration order — silently, and wrongly half the time. A personal database
URL handed to a deploy script is not a convenience feature misfiring; it is one
tenant's credential crossing into another's work, and nothing in the output would
say so.

So the default is **explicit**. Exactly one backend is eligible for a name, and
which one is never inferred from ordering:

| The name declares | Backends configured | Outcome |
|---|---|---|
| `"store": "infisical"` | any | that backend, and only it |
| nothing, `stores.default` set | any | the default backend, and only it |
| nothing | exactly one | that one |
| nothing | two or more | **ambiguous** — the run degrades and names the candidates |

```console
$ keyless run -s DATABASE_URL -- ./migrate.sh
keyless: DEGRADED — 1 names unresolved: DATABASE_URL
keyless:   DATABASE_URL: 2 stores could answer (infisical, proton) and none is
                         pinned; add "store" to this name, or set "stores.default"
...your command runs anyway...
```

Ambiguity is resolved by **refusing to guess**, not by picking — and the
candidates are not queried to see which of them happens to have it. That would
read a value out of a store you never meant to touch, and against Proton Pass it
would write a remote audit entry for a read that was only ever a guess.

A single-store setup needs no pin. `stores.policy` set to `"ordered"` restores
first-hit-wins for anyone whose backends all hold secrets of the same trust
level. It is opt-in because the failure it enables is silent.

### Infisical — a verb that hands back a process, not a value

Three of the CLI's verbs yield a secret — `infisical secrets`, `infisical
secrets get NAME`, `infisical export` — and **all three write plaintext to
stdout**, which in an agent session is the transcript. So `keyless` uses the one
verb that prints nothing: `infisical run --env=… --path=… -- <cmd>`, which
fetches the secrets, puts them in a child's environment, and execs.

That verb gives you a *process*, not a value, and there are two ways to build on
it.

**Nesting** — `keyless run` spawns `infisical run` spawns your command. The
plaintext never enters `keyless` at all, which sounds safer. What it costs:

- **Masking dies.** `keyless` cannot redact a value it has never seen, and
  Infisical masks nothing. Every Infisical-backed secret loses the protection
  this README leads with.
- **Your command gets everything.** `infisical run` injects every secret at the
  path, not the ones you asked for, which in a real project is hundreds of names
  reaching a child that wanted one.
- **`INJECTED` becomes a lie.** Measured: a `run` against an environment and path
  holding nothing exits **0** and reports `Injecting 0 Infisical secrets`. Under
  nesting `keyless` sees a clean exit, reports `INJECTED`, and your command has
  nothing. `DEGRADED` — the whole point of naming what did not resolve — becomes
  unimplementable.
- **A third process** between your terminal and your command, carrying the
  signals, the window size and the exit code.

**Probing** — what `keyless` does. Run that same verb with the smallest possible
child: `printenv KEY`, which writes one variable to stdout and exits. `keyless`
captures it, wraps it in the same zeroizing type the keychain path uses, and
injects exactly the names you asked for.

This is not a way around the policy; it is the policy's own mechanism. The denied
verbs are denied because they print a value **into the session**. Here it goes
into a pipe `keyless` owns and out again only into your command's environment,
masked on the way back. `security -w` has exactly this shape and always has.

What probing costs, stated rather than implied:

- **One `infisical run` per name** — a process spawn and a network round trip
  each. Ten names is ten fetches, and the timeout below is per lookup.
- **The plaintext enters `keyless`.** Nesting would have avoided that. It buys
  masking, exact narrowing and an honest `DEGRADED`.
- **`infisical` still loads every secret at the path into its own memory.**
  Narrowing is about what reaches your command, not about what the vendor's CLI
  fetches.

Every invocation passes `--telemetry=false`. The CLI's telemetry defaults to
**on**, so shelling out with default flags would make `keyless` the reason a
report left your machine — see [No telemetry](#no-telemetry). It also pins
`--log-destination=stderr`, because the CLI reads that from `LOG_DESTINATION`
too and a value of `stdout` there would interleave log lines with the value
being read.

`keyless` never opens `~/.infisical/.token`, `~/.infisical/.client-id`, or the
encrypted cache beside them. The login belongs to the CLI and is inherited by
spawning it; there is no config field a token fits in.

#### An environment is required, and has no default

`--env` is mandatory on Infisical's own CLI, and it has no default — because an
environment there **is the tenancy boundary**. `prod` and `staging` hold the same
key names with different real values.

`keyless` defaults it nowhere, and the reason is measured. With a machine-wide
default of `prod`:

- **Every name a caller invented resolved against production.** A name declared
  in no config at all came back with a real value — exit 0, nothing on stderr.
- Asking for `DATABASE_URL` while meaning staging returned **production**, and
  the command succeeded.

So an environment comes from exactly two places, most specific first:

| Where | Covers |
|---|---|
| the name's own `env` under `secrets` | that name, everywhere |
| `keyless run --env <slug>` | every name in that run declaring none |

**Neither, and the lookup does not happen.** Nothing is spawned and no network
call is made — a missing environment is a lookup that never happened, not one
that failed:

```console
$ keyless run -s DATABASE_URL -- ./migrate.sh
keyless: DEGRADED — 1 names unresolved: DATABASE_URL
keyless:   DATABASE_URL: store `infisical` was not asked: `DATABASE_URL` has no
           Infisical environment. Infisical requires one on every call and
           `keyless` does not default it, because a default resolves a name you
           never declared against whichever environment this machine happens to
           name. Give it one: put "env": "staging" on "DATABASE_URL" under
           `secrets`, or pass `keyless run --env staging` for the whole command.
           A name's own `env` wins over the flag.
...your command runs anyway, with an unmodified environment...
```

That is a degrade, never a refusal — [rule
1](#rule-1-it-never-refuses-to-run-your-command) has no exception for this
either.

**A name's own `env` outranks `--env`.** The flag is a blanket aimed at the names
that say nothing; a name that states where it lives is not repainted by it, so
`--env staging` on a run that also touches a production-pinned name leaves that
name in production.

A config that sets `stores.infisical.env` is told, on every run, that the key is
ignored and which line to delete. Unknown keys are dropped silently by design,
so removing the field outright would have made an existing `"env": "prod"`
vanish without a word.

`path` is deliberately **not** treated this way and still defaults to `/`. That
is the vendor's own default, so `keyless` invents nothing; and the two fail
differently — a wrong path can only miss a folder *inside the environment you
named*, which degrades and says so, while a wrong environment returns a
plausible value from the other side of the boundary. `keyless ls` prints both
coordinates for every Infisical name, so a folder that holds nothing is visible
without a lookup.

#### Pin the project, or resolution depends on where you are standing

The CLI finds its project by walking up from the working directory looking for
`.infisical.json`. `keyless` runs wherever you are, so without a pin the *same
config* resolves in one checkout and degrades in another, with the vendor's own
message about `infisical init` — which sends you to fix the directory rather than
the config.

```json
"infisical": {
  "enabled": true,
  "project_id": "<your-infisical-project-id>"
}
```

`project_id` is passed as `--projectId` on every invocation. `config_dir` is the
other half of the same fix, for a project you would rather locate by its
`.infisical.json`:

```json
"infisical": { "enabled": true, "config_dir": "~/work/api" }
```

Working-directory discovery remains the fallback when neither is set, so nothing
changes for a config that never needed this.

**A leading `~` is expanded against `$HOME` in every path field of this file**,
so the line above needs no editing to say whose machine it is on. Three forms
are refused at parse time rather than taken literally, because taken literally
each one creates a directory of that name beside whatever the caller was
standing in: `~user/…` (this build does not read the passwd database), `$VAR/…`
(a config file is not a shell), and a `~` when `HOME` is unset. A refusal names
the line, and the command still runs.

### Proton Pass — verified against `pass-cli` 2.2.5

Same shape, same reason: `pass-cli item view --field` prints plaintext, and
`pass-cli run --env-file FILE -- CMD` prints nothing. A lookup writes a one-line
env file holding a `pass://SHARE_ID/ITEM_ID/FIELD` reference — a reference,
never a value — at mode 0600, runs the probe under it, and deletes the file.

Observed on macOS against a live account on 2026-08-08, with disposable decoy
items in a throwaway vault: the `run --env-file … --no-masking -- <COMMAND>`
spelling, the reference format, the session scoping below, and that the vendor's
masking is opt-out rather than opt-in. `pass-cli agent create` exists too — it is
not web-app-only.

One requirement no code can check: **an agent token needs Pass Plus or higher.**
Plan for that before you set this up. A free account fails authentication, which
reaches `keyless` as a degraded run rather than as an explanation.

#### `session_dir` is the scoping, and it has no default

`pass-cli` keeps one logged-in identity **per session directory**, chosen by
`PROTON_PASS_SESSION_DIR` and falling back to a shared per-user location. So two
identities coexist on one machine and look identical at the call site:

| session directory | identity | vaults |
|---|---|---|
| the default | the full account | every vault |
| `~/.keyless-pass-session` | a vault-scoped agent token | the ones it was granted |

An adapter that sets nothing inherits the default. That bypasses the scoping
**in the direction that looks correct** — a session holding every vault resolves
every name successfully, and nothing in the output says the wrong identity
answered. So `keyless` passes the directory explicitly, and when
`stores.proton.session_dir` is absent it **degrades the lookup** instead of
guessing:

```console
$ keyless run -s HOME_WIFI -- ./setup.sh
keyless: DEGRADED — 1 names unresolved: HOME_WIFI
keyless:   HOME_WIFI: `stores.proton.session_dir` is not set, so which Proton
                      identity answers would be whatever `pass-cli` was last
                      logged into ...
...your command runs anyway...
```

Degrading the *name* is not refusing the *command*: the child still runs, with
its exit code and its terminal intact. Nothing is spawned and no remote audit
entry is written for a read whose identity nobody chose.

#### Address items by NAME — a share id is minted per session

**A share id is not a coordinate you can store.** Measured 2026-08-08: the same
vault answered with two different share ids to two live sessions of one account.
A reference is therefore relative to the session that resolves it, and one
written into a config file stops working the next time the token is renewed or a
session recovers — as a **degraded run**, which is quiet.

So address an item the way a person does. Vault name, item title, field are
stable; `keyless` resolves the volatile half at every lookup:

```json
"EXAMPLE_API_KEY": {
  "store": "proton",
  "vault": "personal",
  "item":  "example-api-key",
  "field": "password"
}
```

Behind that, one `pass-cli item list --vault-name <VAULT> --output json` per run
supplies this session's `share_id` and `id`, a fresh `pass://…` reference is
built in memory, and the value comes back through `run` exactly as before. The
listing is memoised for the life of the invocation — several names from one
vault cost one listing — **in memory and never on disk**. A cache on disk that
the client can read is a `get` verb with extra steps, and `keyless` does not
offer one.

Four rules, each of which degrades the name and never the command:

| Situation | Outcome |
|---|---|
| exactly one live item carries the title | resolved |
| two or more do | **refused**, and the banner names every candidate id |
| the only match is in the trash | **refused**, and the banner says so |
| no item carries the title, or the vault cannot be listed | refused, naming what was looked for |

Ambiguity is refused rather than picked, for the same reason two backends
answering one name are: guessing is right half the time and silent the other
half. Pin one with the `reference` form when you genuinely have two items of one
name.

#### The `reference` form still works, and it is the fragile one

```json
"HOME_WIFI": { "store": "proton", "reference": "pass://SHARE_ID/ITEM_ID/password" }
```

It resolves, it pins exactly one item, and it is the escape hatch for a title
two items share. Outside that case it costs two things, both silent:

- **It dies when the session is replaced**, because the share id it carries
  belonged to a session that no longer exists.
- **It resolves a trashed item.** Measured 2026-08-08: `pass-cli run` returns a
  trashed item's value, exit 0, nothing on stderr. The vendor applies no trash
  filter, so the check lives in the listing — and this form never lists.

Declaring both forms for one name is refused before anything is spawned, rather
than one of them being preferred silently.

If you do write a reference, read the ids from the session `keyless` is
configured to use, at the time you write it:

```console
$ PROTON_PASS_SESSION_DIR=~/.keyless-pass-session pass-cli vault list --output json
$ PROTON_PASS_SESSION_DIR=~/.keyless-pass-session pass-cli item list --vault-name <vault> --output json
```

#### `pass-cli run` resolves every `pass://` in the environment it inherits

Measured 2026-08-08. `--env-file` is not the only place it looks — one unrelated
`UNRELATED=pass://…` exported in your shell is enough:

```console
$ UNRELATED=pass://bogus/bogus/password pass-cli run -- printenv HOME
Error: Failed to resolve secrets
Caused by:
    0: Failed to resolve secret pass://bogus/bogus/password in variable UNRELATED
```

Left alone that costs two things. Every extra reference is **fetched and
logged**, permanently and off-machine, for an item `keyless` was never asked
about; and one unresolvable reference anywhere in the environment fails the
*whole* probe, so every Proton-backed name degrades for a reason unrelated to
any of them. So `keyless` removes variables whose value holds `pass://` from the
probe's environment. Your own command's environment is untouched.

#### Never run `pass-cli` with a cleared environment — it destroys the login

The obvious hardening — hand the probe an empty environment — is worse than the
problem. Under `env -i`, `pass-cli` 2.2.5 does not merely fail to authenticate:
it **reinitialises the session database at that path**, replacing a logged-in
session with an empty one.

| session created by | after the reset |
|---|---|
| a personal access token | recovers by itself, with a **new share id** for the same vault |
| `pass-cli login` (web) | gone — you log in again |

Treat the session store as something `pass-cli` may rewrite on any invocation.
Remove exactly the variables that cause a problem and leave the rest alone.

The share id moving is the reason references are written against the session
that will resolve them, and never copied from another session or another day.

Two details of the contract shape the adapter:

- **`--no-masking` is passed on the probe.** Proton's own output masking is on by
  default and substitutes `<concealed by Proton Pass>`. The probe reads the
  child's output, so with masking left on it would inject the placeholder as
  though it were the credential. `keyless` masks your real command's output
  itself, over more encodings, so nothing is lost. If the flag is ever ignored,
  a value that comes back concealed is refused rather than injected.
- **Every read carries a reason**, in `PROTON_PASS_AGENT_REASON`, stored
  end-to-end encrypted beside the audit entry. `keyless` sends the verb, the
  program's base name, its argument *count*, and the name being resolved:

  ```
  keyless run psql (2 args): resolving DATABASE_URL
  ```

  **Never the arguments themselves.** An argument is one of the four shapes
  [this tool exists to remove](#why-this-exists), and a reason is assembled
  *before* anything has resolved, so there is nothing to redact it with — and it
  is then sent to a vendor and kept. Putting argv in it would take the exact
  leak this tool exists to prevent and forward it to a third party under a field
  labelled "reason".

### Timeouts

A network store must not hang your terminal. Every lookup is bounded — **10
seconds** by default, per name, set with `timeout_ms`:

- Long enough that a cold CLI start, a TLS handshake and a token refresh all fit
  without degrading a run that would have worked.
- Short enough that a black-holed connection costs one command a pause instead of
  wedging a terminal until you reach for Ctrl-C.

**Expiry is a degraded path, never an error path.** The lookup is killed, the
name is reported unresolved, and your command runs with an unmodified
environment. The never-block rule has no exception for a slow network.

Ten names against an unreachable store is ten timeouts, so the wait is per
lookup, not per run. `doctor` is where you find out why.

---

## Finding what to put in the config

`keyless ls` lists what you have already declared. It reads the config file and
nothing else, which leaves an obvious hole: **to declare a name you have to know
what the store calls the item and the field, and finding that out used to mean
printing the value.** The only `pass-cli` verb that reveals a field name prints
the values with it, so setting the tool up required doing the exact thing the
tool exists to prevent.

Two verbs close that.

```console
$ keyless items --store proton --vault personal
personal	Trashed	login	keyless-decoy-alpha
personal	Active	custom	demo api key

$ keyless fields --store proton --vault personal --item "demo api key"
API Key	    custom	Hidden	    item.content.extra_fields[0]
Secret	    custom	Hidden	    item.content.extra_fields[1]
Expiry Date	custom	Timestamp	item.content.extra_fields[2]
Permissions	custom	Text	    item.content.extra_fields[3]
note	    builtin	-	        item.content
title	    builtin	-	        item.content
```

Tab-separated columns, like `ls`, because this output is read by agents at least
as often as by people. `items` gives vault, state, type, title. `fields` gives
name, kind, type, path — and the `name` column is what goes in a config entry's
`field`:

```json
"DEMO_KEY": { "store": "proton", "vault": "personal",
              "item": "demo api key", "field": "API Key" }
```

**Neither prints a value. Neither prints a value's length either** — a length is
information about a secret, and `doctor --probe` has always refused to print one.

### A trashed item is shown, and `fields` on one is refused

Both halves are deliberate. Hiding a trashed item leaves you hunting for
something that is in the bin; listing it *unmarked* is worse, because you would
then write a config entry against a title that can never resolve — the resolver
refuses a trashed item on purpose. So `items` reports the state verbatim and
`fields` says why it will not go further:

```console
$ keyless fields --store proton --vault personal --item keyless-decoy-alpha
keyless: store `proton` failed: the only item titled `keyless-decoy-alpha` in
vault `personal` is in the trash, so no config entry can resolve against it;
restore it first
```

### How the Proton path keeps the value out of the output

`pass-cli item view` is the only verb that reveals an item's field names, and it
prints the values too. There is no vendor flag that stops it. So the plaintext
enters the process whether anyone wants it or not, and everything between arrival
and the first byte of output is the mechanism:

- the bytes land in a capture buffer that zeroizes on drop;
- they are parsed into a guard type with no `Display`, no `Serialize`, a `Debug`
  that prints `ItemView(<redacted>)`, and a `Drop` that zeroizes **every string
  in the JSON tree** — which covers the early-return and panic paths as well;
- exactly two rules produce output, and there is no third. An array element
  carrying a label key beside a value key contributes its **label**; anything
  else contributes a **key**. Nothing recurses into a value container, so
  `content` and `value` are read as structure and never as data;
- the type column (`Hidden`, `Timestamp`) is the *key* of the object wrapping the
  value, so reporting it never goes near the value;
- every error message on the path is built from stderr only, as everywhere else
  in this tool, because stdout is where the value is.

Requiring a field descriptor to be an **array element** is load-bearing rather
than tidy. The vendor's own top-level `item` object carries a `content` key, so an
`item` that ever gained a `name` would be read as one field descriptor and every
real field would silently vanish from the listing. A shape that puts a descriptor
outside an array falls back to emitting keys — a worse listing, never a leak.

Measured against `pass-cli` 2.2.5, and **the two shapes are not the same**:

| Source | label | value |
|---|---|---|
| `item view --output json` | `item.content.extra_fields[N].name` | `…[N].content` |
| `item create custom --get-template` | `sections[].fields[].field_name` | `…value` |

The template's shape is the only one of the two you can read without printing a
credential, so it is the tempting thing to build against — and it is wrong for a
real item. Both are handled.

### Two backends say why they cannot do this

A verb that works in one backend and leaks in another is worse than one that is
plainly absent in the second, because you learn to trust it from the backend
where it is safe. So:

| Backend | `items` / `fields` | Why |
|---|---|---|
| `proton` | yes | `item list` and `item view`, with the extraction above |
| `keychain` | no | `security` has no verb listing one service's items without dumping the whole keychain file, and one extra flag on that dump prints values |
| `infisical` | no | every verb that lists keys prints their values, and there is no keys-only flag |
| `daemon` | no | a client that could enumerate the store could read what it never named — the hole the uid boundary closes |

For Infisical the tempting workaround is unsafe rather than merely ugly: filter
the vendor's output down to what is left of each `=`, and a value containing a
newline produces a following line with no `=` in it, which the filter passes
straight through.

---

## Storing a secret

```console
$ keyless new DEMO_KEY --length 32
stored	DEMO_KEY	pass://personal/demo api key/API Key (custom item)	proton (manager)

$ printf '%s' "$value_from_the_provider" | keyless put DEMO_KEY
stored	DEMO_KEY	keychain keyless/DEMO_KEY	keychain (this user, no separate manager exists)
```

`new` generates the value from the kernel's CSPRNG and **never shows it to
anybody**. That is the point rather than an omission: it exists in the process and
in the store, and nowhere else. There is no `--show`, no `--print`, and `put`
echoes nothing.

`put` takes the value on **stdin and nowhere else**. There is no `--value`, no
`--secret`, and no positional value:

```console
$ keyless put DEMO_KEY --value hunter2
error: unexpected argument '--value' found
```

An argument is readable from the process table for as long as the process lives
— the CLI-flag shape, one of the four [above](#why-this-exists). A flag that
exists gets used, so the flag does not exist — structurally, the same way `run`
has no `--reveal`.

At a terminal, `put` prompts with echo off. If echo cannot be switched off it
does **not** prompt anyway; a prompt that echoes would print the credential.

### These verbs may refuse. `run` may not

`keyless run` never refuses, because blocking your work gets the tool uninstalled
and then the plaintext comes back. That argument does not transfer to setup
commands: `new` and `put` run once, with you watching, and nothing downstream is
waiting on them. And a write that "degraded" would report success with nothing
stored — which the next `run` would report as a missing name, for a reason nobody
can find. So they exit non-zero and say what is missing:

| Exit | Meaning |
|---:|---|
| 0 | stored |
| 65 | the value is unusable — empty, not UTF-8, too large, a line break the backend cannot hold |
| 71 | `/dev/urandom` could not be read |
| 78 | nothing was attempted; a config file needs editing |
| 1 | the backend refused or could not be reached |

### The reader and the manager are two different identities

`stores.proton.session_dir` is the **reader**: a viewer-role agent token, the
default, and the only identity `run`, `ls`, `items` and `fields` can reach. It
cannot create, move or trash anything, which is what you want every session on
the machine to hold.

`stores.proton.manager.session_dir` is a **second** token with the editor role,
used by `new` and `put` and by nothing else:

```json
"proton": {
  "enabled": true,
  "session_dir": "~/.keyless-pass-session",
  "manager": { "session_dir": "~/.keyless-pass-manager" }
}
```

Minting it, measured against `pass-cli` 2.2.5:

```console
$ pass-cli agent create keyless-manager --expiration 3m --vault personal
$ pass-cli agent access grant keyless-manager --vault-name personal --role editor
```

**`--role` defaults to `viewer`.** That is why an unexplained `NotAllowed` from a
write is nearly always the token's role and not the vault's permissions, and why
`keyless` attaches that fix to the failure instead of quoting the vendor and
stopping:

```console
$ keyless new DEMO_KEY
keyless: store `proton` refused the write: cannot create `demo api key` in
vault `personal`: Error creating login item: Could not perform operation. Reason:
NotAllowed. That is the token's ROLE, not the request ...
```

`pass-cli` puts the cause on a `Caused by:` line, so `keyless` quotes the whole
of its stderr. The first line on its own says `Error creating login item` and
names nothing you can act on.

### What the split is, and what it is not

Read this part rather than assuming the symmetry.

**It buys:** two tokens, two audit trails at the vendor, two expiries, and a
fleet of sessions that cannot write to the vault at all. That is real and worth
having.

**It is not a boundary.** Any process running as your uid can set
`PROTON_PASS_SESSION_DIR` to the manager's directory and act as the manager. A
file mode does not help, because the reader has to work in every session and is
therefore readable by every session. **Locally the reader/manager split is
advisory.**

The only thing on this machine that can hold a credential your uid cannot reach
is [`keylessd`](#keylessd--the-uid-boundary), behind a second uid. So the
enforced version of this split is "the manager token lives on the daemon's
side", and it is not built: `keylessd` carries a file store and a keychain store,
no Proton adapter, and the protocol has no write operation.

Given that, **`keyless` refuses every local write while the daemon is enabled**
rather than reaching around it:

```console
$ keyless new DEMO_KEY
keyless: `stores.daemon.enabled` is set, so the manager identity belongs on the
daemon's side of the uid boundary and a local write would reach around it ...
```

The rule the whole daemon design rests on is that killing it must yield **fewer**
powers, never more. A local write path that opens whenever the daemon is off is
that hole, one verb over.

For the keychain there is no second identity to have: the login keychain has one
owner, and every process running as you can already read and write it with
`security`. So keychain writes need no `manager` block, and the identity they
report says so — claiming a manager there would be a claim about a boundary that
is not present, and one false claim teaches you the other one is false too.

### What each backend can write, and what it cannot

| Backend | Write | Notes |
|---|---|---|
| `keychain` | `add-generic-password -U -w`, value on stdin | `-U` updates in place, so this rotates |
| `proton` | `item create <type> --from-template -`, template on stdin | **creates only** |
| `infisical` | no | `infisical secrets set` takes the value as a command-line argument, and the CLI offers no stdin form |

Two measured details behind those:

- **`security` asks for the password twice.** Fed one line, it reads end of input
  for the retype, the two disagree, it re-prompts, accepts two empty answers and
  **exits 0 having stored an empty value.** Exit status alone is therefore not
  evidence that anything was written, so `keyless` writes the value twice and
  treats a `passwords don't match` on stderr as a failure. A value containing a
  line break is refused rather than stored as its first line.
- **Proton writes create and never overwrite.** `item update` takes
  `--field name=value` and offers no template on stdin, so updating would mean
  putting the value in argv. A title that already exists is refused with the
  reason, and that pre-flight listing is load-bearing: creating a second item with
  one title makes the name form ambiguous, which is how a write verb silently
  breaks a working `run`.

### The audit row says which identity did it

Every `run` row carries `"identities":["<store> (reader)"]`, and a write row says
`proton (manager)`. A `Registry` cannot hold a writer and `ProtonStore` does not
read the `manager` block, so a `run` row saying `(manager)` is unreachable — which
makes "did a session ever act as the editor?" a question you answer from the log
rather than from trust.

---

## What this protects you from, and what it does not

Read this section before you rely on any of the rest.

### Masking is a filter, not a control

The child's stdout and stderr are scanned and any appearance of an injected
value is replaced with `[keyless:NAME]`.

It defends against **accident** — a tool that echoes its config, a stack trace
carrying a connection string, `curl -v` printing a header. It does not defend
against **intent**:

```console
$ keyless run -s TOKEN -- sh -c 'echo $TOKEN > /tmp/x'
```

Three tokens defeat it, and no amount of pattern matching would change that. The
threat model is a capable agent taking a shortcut, not an adversary.

### What is caught

Twenty encodings, each modelling a named real producer, all of them checked in
the test suite against literals generated by an independent implementation:

| Encoding | Where it comes from |
|---|---|
| raw, lowercase, uppercase | the value itself, and CLIs that normalise |
| base64 standard, padded and unpadded | Kubernetes `data:` values, SDK encoders, JWT segments |
| base64 URL-safe, padded and unpadded | JOSE `base64url`, query parameters |
| base32, padded and unpadded | TOTP seeds, some Kubernetes tooling |
| hex lower and upper | Python `bytes.hex()`, Rust `{:x}`, Node `toString("hex")` |
| `0x`-prefixed hex, lower and upper | Ethereum tooling, C-style dumps |
| URL query escape (space → `+`) | Go `url.QueryEscape` |
| URL path escape (space → `%20`) | Go `url.PathEscape` |
| URL strict (RFC 3986) | conservative encoders |
| JSON minimal | `serde_json`, `JSON.stringify` |
| JSON HTML-escaped (`& < >`) | Go `encoding/json` default |
| JSON slash-escaped (`\/`) | PHP `json_encode` default |
| JSON ASCII-only (`\uXXXX`) | Python `json.dumps` default |

A value split across two, three or a hundred writes is still caught: the writer
holds a byte back for as long as it could still turn out to begin a needle, and
releases it once the following bytes rule that out. Splitting
mid-multibyte-character is covered too, and so is one byte per write through a
live terminal.

Needles shorter than 4 bytes are dropped, and a secret shorter than 4 bytes
produces no needles at all — including through its encodings, since base64 of
3 bytes is 4 characters and exactly as collision-prone as the 3 raw bytes were.

### What is not caught, and never will be

Substring matching sees bytes, so anything that does not preserve a contiguous
byte image of the value is invisible. Each of these has a test asserting it is
*not* caught, so the claim stays honest and a future change that closes one is
visible:

- **Compression** — gzip, zstd, brotli. A compressed body carrying a token has
  no substring in common with the token.
- **Encryption and hashing** — TLS payloads, an HMAC computed from the secret.
- **A secret encoded together with other data.** HTTP Basic auth base64-encodes
  `user:password` as one string; base64 is 3-byte aligned, so the encoding of
  the password alone is a substring of it only when `user:` happens to be a
  multiple of three bytes — one username length in three. `curl -u user:pass -v`
  prints exactly this and it usually survives masking. Catching it reliably needs
  the username, which this tool does not have. **This is the sharpest limit in
  the design**, and it is why HTTP Basic is absent from the table above: base64
  catches a secret encoded **alone**, which is what a Kubernetes `data:` value or
  an SDK encoder produces.
- **A hex dump.** `xxd` groups its output into two-byte columns separated by
  spaces, and `xxd -p` wraps every 60 characters, so neither preserves a
  contiguous hex image of a value longer than 30 bytes. The hex encodings catch
  what a *program* produces — `bytes.hex()`, `{:x}`, `toString("hex")` — not what
  a dump tool renders for a human.
- **A child that writes the value somewhere else** — a file, a socket, an
  argument to another process. Masking filters a stream; it does not confine a
  process.

Masking costs a little output latency, and only where it must. The writer holds
back a byte only while that byte could still turn out to be the start of a
secret; anything that cannot begin one is released the moment it arrives. So a
prompt, a progress bar or a line of log output reaches you whole and on time,
and the withholding is confined to the handful of bytes that genuinely look like
the beginning of a value.

### The properties, stated precisely

What this gives you:

- The value is not in your shell history, your terminal scrollback, or an agent
  transcript.
- The value is not in the audit log.
- A tool that echoes the value has that output redacted.
- The value is held in a type with no `Display`, no `Serialize`, a `Debug` that
  prints `Secret(<redacted>)`, and a `Drop` that zeroizes.

What it does not give you, stated so nobody assumes otherwise:

- **The child gets the real value.** It can do anything with it. Environment
  injection is the mechanism, and a same-user process can read another's
  environment on most systems.
- **Copies exist that cannot be scrubbed.** The pipe buffer the backend wrote
  through, the backend process's own memory, and the environment block
  `std::process::Command` builds — none of those are ours to zeroize. This
  reduces the plaintext's residency; it does not eliminate it.
- **A vault CLI loads more than you asked for.** `infisical run` fetches every
  secret at the path into its own memory before the probe reads one of them.
  `keyless` narrows what reaches *your command*; it cannot narrow what the
  vendor's CLI fetches.
- **A Proton name form enumerates its whole vault.** `item list` returns every
  item's title, id and state, not just the one asked for. That is metadata and
  never a value — `--show-secrets` is what would print content, and it is never
  passed — but it is one more read against the vault per run, and it is the
  price of not storing an id that expires. Scope the agent token to a vault you
  are willing to have enumerated.
- **`doctor` cannot prove a Proton Pass login works.** It checks that `pass-cli`
  is present and executable and that `session_dir` is configured, and says so.
  It does not check the login: every deeper check is a network round trip and a
  permanent remote audit entry for a read nobody requested. Reachability and
  authentication are found out at the first real lookup, which degrades.
- **`fields` reads an item's values into this process.** `pass-cli item view` is
  the only verb that reveals field names and it prints the values with them, with
  no flag to stop it. The buffer zeroizes on drop, the parsed tree zeroizes on
  drop, and only names built from key positions leave the guard type — but the
  plaintext of every field on that item is briefly resident, which is more than
  `run` does for one name. Use it on the item you are configuring, not as a
  browser.
- **The reader/manager split is advisory unless the daemon holds the manager.**
  Two session directories are two tokens and two audit trails, not a boundary:
  anything running as your uid can point `PROTON_PASS_SESSION_DIR` at the
  manager's. See [the split](#what-the-split-is-and-what-it-is-not).
- **`new` trusts `/dev/urandom`.** It is the kernel's CSPRNG, seeded before
  userspace exists, and a short read is an error rather than a shorter password.
  If you do not trust it, generate the value in the provider's UI and `put` it.
- **Nothing here survives `sudo`.** If you are an admin on your own machine,
  this is a boundary against your sessions, not against you.

---

## `keylessd` — the uid boundary

Everything above is a wrapper around a store **your own uid can read**. That is
a good habit and it is not a boundary.

`security find-generic-password -s <service> -w` returns a plaintext value with
**no prompt and exit 0**. Anything readable by your uid is readable by every
session you start and every subagent any of them spawns — every API token, every
database URL, and the agent's own credentials alongside them. No file mode, no
deny rule and no wrapper changes that.

**A second uid does**, because the kernel enforces it and there is nothing to
bypass.

```
your sessions (uid 501)          keylessd (uid _keyless)
  keyless run -s TOKEN  ──socket──▶  reads the store
        ▲                             writes the audit log
        └──── the value ──────────────┘
             names and results cross. the store credential never does.
```

See [`install/README.md`](install/README.md). It needs `sudo` exactly once, to
create a user, and the installer prints its whole plan and changes nothing until
you pass `--commit`.

### Who is allowed to ask

The daemon identifies the **running image** of whoever connects — not a path, and
not anything the caller says about itself. Six kernel facts, cross-checked
against each other:

| fact | source |
|---|---|
| effective uid | `getpeereid`, cross-checked against `LOCAL_PEERCRED` and the audit token |
| pid | `LOCAL_PEERPID`, cross-checked against the audit token |
| pid **generation** | the audit token, stamped by the kernel at connect |
| code hash of the live image | `csops(pid, CS_OPS_CDHASH)` |
| live generation, twice | `proc_pidinfo`, read either side of the code hash |

Two races close by construction rather than by timing:

- **The binary is swapped after connecting.** The code hash comes from the
  kernel's record of the *loaded image*. No path is resolved and no file is
  opened, so there is no file to swap. Resolving the pid to a path and hashing
  that path is the obvious implementation and it is broken: an unprivileged
  process can rename a different binary over the path and attest as the
  allowlisted hash. There is a test that performs exactly that attack, and a
  twin that pins the other binary so "refused" cannot be confused with "nothing
  worked".
- **The pid is recycled.** The audit token carries the generation the kernel
  assigned at connect; the live generation is read immediately before and after
  the code hash. Three agreeing values mean the pid never left the process that
  connected. `(pid, start_time)` — the usual advice — is *unavailable* here:
  `proc_pidinfo(PROC_PIDTBSDINFO)`, where a start time lives, returns `EPERM` to
  an unprivileged caller reading another user's process, which is precisely the
  daemon's situation. Measured before the code was written.

Attestation runs **per request, not per connection**, because a process can
`exec` a different image without closing its sockets. There is a test that does
that: connect as a pinned program, get served, `exec` an unpinned one, and ask
again on the same connection. The second request is refused.

### What happens when the caller is `node`

Interpreters need their own answer, because the obvious one is silently wrong.

**The code identity of a `node` process is node's.** It is identical for every
program node will ever run. Allowlisting an AI agent would allowlist every Node
program on the machine, including whatever `npx` last fetched. There is no way
around it: the script's path comes from argv, which the process can rewrite, and
hashing it means hashing a file at a path — the exact race above.

So `keyless` **refuses interpreted callers outright**, and it costs nothing:

- An agent harness is typically a Node program, and it is **never the peer on
  this socket**.
- The peer is always `keyless run`, one compiled binary with one identity.
- The agent gets a secret by *running* `keyless run`, which is the only
  supported path and the one the whole tool is built around.

A Node process connecting directly is not a user being inconvenienced; it is
something that should not be there. It is refused by name, told to go through
`keyless run`, and never silently attested as "the node binary".

The check runs **before** the allowlist, so an operator cannot authorise an
interpreter by pinning it — there is a test that pins `perl`'s real hash, drives
a real `perl` client, and is still refused, plus a negative control proving the
interpreter rule is what refused it. `keylessd pin` refuses to emit the pin in
the first place, and there is no config key that turns any of this off.

### What the boundary does *not* buy

- **It does not stop an agent using a secret it is allowed to use.** An attested
  `keyless run -s TOKEN -- sh -c 'echo $TOKEN'` is an attested client running an
  arbitrary command. Attestation says *which program is asking*, never *what it
  intends*. Caller attestation is the weakest of the three legs here; the uid
  boundary on the store and the unforgeable audit log are the load-bearing ones.
- **It does not survive `sudo`.**
- **It does not migrate anything, and this is the one that actually matters.**
  Standing the daemon up next to a login keychain that still holds your secrets
  closes *nothing* — the items are still there and still readable by every
  session. The step that shuts the hole is moving each secret somewhere only
  `_keyless` can read and then **deleting it from the login keychain**. No script
  should guess which of your items that applies to, so none of them does.

### Many sessions at once

**Single-flight per name.** Twenty sessions starting together and all wanting
`GITHUB_TOKEN` produce **one** upstream call. Without it a store rate limit
degrades the whole fleet at the same instant, which is indistinguishable from the
daemon being down.

**The in-memory TTL cache is not an offline cache.** The forbidden thing is a
cache a *client* can decrypt without the daemon, because its key would have to
live on the client's side of the boundary — a `get` verb with extra steps. This
one never touches disk and dies with the daemon, so killing `keylessd` strictly
reduces what is obtainable.

**And there is no local fallback.** Enabling the daemon *disables* every local
backend — keychain, Infisical and Proton Pass alike — whatever each one's own
flag says. It is enforced in `store::build`, not documented as a convention,
because a fallback would re-open the hole the moment the daemon stopped, and
anyone able to stop a process could choose that. Killing the daemon must get you
fewer secrets, never more.

### The rule still has no exception

A daemon that is absent, stale, wedged, refusing, killed mid-request, speaking
another protocol version, or answering nonsense is a `DEGRADED` like any other
store failure: one line on stderr, and **your command runs** with an unmodified
environment. There is one property test per failure mode — seventeen of them —
and each asserts the child actually ran by reading a file the child wrote, which
a process that never started cannot imitate.

---

## The hook pack — closing the other paths

`run` makes the safe path available. It does not make it the only path, and an
agent under completion pressure takes the shortest one. So it reads the `.env`,
runs `op read`, or dumps `env`, and the injector was theatre.

[`hooks/`](hooks/README.md) is a store-agnostic pack that closes those doors
from inside the agent harness — Python 3, stdlib only, one command to install
and one to remove:

```console
$ cd hooks && ./install.sh
```

It refuses a vault CLI's print verb across 16 stores, refuses a shell command
that reads a credential file, and **rewrites rather than refuses wherever a
rewrite exists**: a `Read` of a `.env` is redirected to a names-only view, a
bare `env` is masked with its pipeline intact, and a credential literal in a
file being written becomes `${NAME}` while the write proceeds.

Same two rules as the binary. Every hook fails open — a crash, a timeout, an
unparseable payload or a missing interpreter allows the call — and no hook
prints a secret value into its own output, log or message.

**A deny rule on a binary name is not a substitute.** Measured against the
harness: five of ten bypass spellings walk straight past a `Bash(cat:*)` rule.
Nothing in this pack matches on a binary name alone; the triggers read the FILE
a command touches, or the subcommand that selects the mode.

Measured overhead: **about +6 ms per tool call** — +5.2 ms on a quiet machine,
+6.3 ms on a busy one, against a bare interpreter interleaved in the same loop.
Every mutation in its spec is caught, and the attacks that still get through are
published rather than omitted — see [`hooks/README.md`](hooks/README.md).

### Why `fields` exists, and where the gate still misfires

`items` and `fields` exist because the gate did its job. An item's field name
could not be found, because the only verb that reveals it prints the value and
the pack refused it. The right answer was a verb that returns the names without
the values, not a hole in the pack.

One rough edge, measured 2026-08-08: the vault rule matches `pass-cli item view`
**including `pass-cli item view --help`**, which prints a usage message and no
credential. Two other false positives are already recorded against
`infisical secrets folders …`; this is a third of the same shape — the rule reads
the verb and not what the invocation would actually output. It is a nuisance
rather than a risk, and the fix belongs in `vault_verbs`, not in a session
routing around the gate.

---

## Reference

### Rule 1: it never refuses to run your command

**Once `keyless run` has parsed its arguments, there is no code path in which it
exits without spawning the child.** Not on a missing store, not on an unknown
name, not on a corrupt config, not on a store that errors, hangs or floods, not
on a value the kernel refuses to put in an environment, and not on a machine
temporarily out of process slots. It warns on stderr and runs the command anyway
with an unmodified environment.

<details>
<summary>The clause at the front of that sentence is doing real work. Here is what it buys and what it costs.</summary>

This used to read *"there is no code path in which `keyless run` exits without
spawning the child"*, with no clause, and that absolute was false. An adversarial
review found **nine** ways to end a `keyless run` with no child — a config that
was a FIFO, a `security` binary with no deadline, a stored value containing a NUL
byte, a `-s` argument that was not UTF-8, and five more. Every one is fixed, and
each has a test that fails without the fix.

The clause survives the fixes because one class cannot be fixed from inside this
tool: an argument the parser rejects. `keyless run --bogus -- ./deploy.sh` exits
**2** and runs nothing, because a flag `keyless` does not recognise might be a
flag that changes what running means. Guessing would be worse than refusing, and
the refusal happens before any code this project controls.

So the honest claim is the qualified one. **An absolute with a counterexample is
worth less than a bounded claim that holds** — it invites exactly the search that
found the nine, and the first person to run `keyless run --typo` gets to say the
headline is false. What the qualified sentence still says, and what the audit of
20+ competing tools found no other tool saying: **no failure of a secret ever
costs you the command.**

</details>

```console
$ keyless run -s DATABASE_URL -s GITHUB_TOKEN -- ./migrate.sh
keyless: DEGRADED — 2 names unresolved: DATABASE_URL, GITHUB_TOKEN
keyless:   DATABASE_URL: not found in any store
...your command runs, and its exit code is yours...
```

There are two states and no third:

- **INJECTED** — every requested name resolved, was injected, and is masked.
- **DEGRADED** — anything else. The environment is untouched.

A partial injection would be a third state, so it does not exist: if one name of
three is missing, none of the three is injected. Fewer secrets, never more.

This is not politeness. A tool that occasionally blocks the work gets
uninstalled, and what comes back is the plaintext literal on the command line.
Degrading loses the protection for one command; failing loses it for good.

*Degraded runs still mask.* Whatever did resolve is still compiled into the
output filter even though nothing is injected — so a value you typed by hand
stays out of the audit log and out of the echoed output. Injection is withheld
when degraded; redaction is not.

There are exactly three ways out without a child, and none of them is `keyless`
declining to run something it could have run:

| Exit | Meaning | Who decided |
|---:|---|---|
| 2 | an argument could not be parsed — an unknown flag, a missing `--` | clap, before `keyless` runs |
| 64 | no command followed the flags (`EX_USAGE`) | `keyless`, with nothing to spawn |
| 127 | the command exists as text but not as an executable | the kernel, at `execve` |

Everything else — every store, every name, every config, every deadline, every
value the kernel will not accept — is a **degrade**: a line on stderr, the
command runs, and its exit code is yours.

A non-UTF-8 `-s` argument is deliberately **not** in that table. It used to be:
clap rejected it and exited 2 while a perfectly runnable command sat after the
`--`. It is taken as bytes now, so it becomes one unresolvable name and the run
degrades.

### Rule 2: there is no verb that prints a value

No `get`. No `read`, `export`, `show`, `cat`, `--reveal`, `--print`,
`--no-masking`. Not behind a flag, not behind an environment variable, not "just
for debugging".

A single verb that writes a plaintext value to stdout voids the entire design,
because a caller takes the shortest path and that verb is always the shortest
path. This is behavioural, not theoretical: a CLI that already reads its key
from the environment still gets that key typed at it as a literal flag, because
the flag is one line and setting up the environment is more than one.
Availability of the safe path does not win. Only being the shortest path wins.

The rule holds across the whole verb set, and each verb has to earn it
separately:

| Verb | What it prints |
|---|---|
| `run` | your command's output, with injected values replaced by `[keyless:NAME]` |
| `ls` | the names you declared, and which environment each one points at |
| `items` | vault, state, type, title |
| `fields` | field names, kinds, types, paths — never a value, never a length |
| `new` | that it stored something, and where |
| `put` | the same, and it echoes nothing it read |
| `doctor` | `ok` / `missing` / a store's own error |

`new` is the interesting one: it generates a credential and then does not show it
to you. There is no flag that does.

### Terminals

Masking needs the child's output to pass through `keyless`, and that normally
costs you the terminal: a program handed a pipe answers *no* to "am I on a
terminal?", so `npm install` loses its progress bar, `git log` loses its pager
and its colour, and prompts change shape. A tax on every invocation is how a
tool gets uninstalled — which brings the plaintext literal straight back.

So when you really are at a terminal, `keyless` allocates a pseudo-terminal and
gives it to the child. The child sees a terminal because it **has** one. The
bytes still cross the masker on the way out.

|  | what the child gets |
|---|---|
| stdin, stdout and stderr are all terminals | a real pty — `isatty` true, colour, size, prompts |
| anything redirected, a pipe, a CI job | pipes, exactly as before |
| nothing to mask | your own stdio, inherited untouched |

All three streams must be terminals before a pty is used, and each one is a
separate reason:

- **stdout** — with no terminal there is nothing to preserve, and writing escape
  sequences into a pipe or a file corrupts it.
- **stderr** — a pty carries ONE stream. Merging the child's stderr into it
  would silently defeat a deliberate `2>errors.log`. That is data loss, not a
  cosmetic difference.
- **stdin** — a pty has no end-of-file to deliver. Relaying a pipe that ends into
  a pty means synthesising an EOT, whose meaning depends on the child's line
  discipline; getting it subtly wrong truncates input.

What comes with the pty:

- **The window size**, at start and on every resize. `SIGWINCH` reaches the
  child, so a full-screen program reflows.
- **Raw mode**, so Ctrl-C, arrow keys and paste reach the child untouched.
- **Ctrl-C goes to the child, not to `keyless`.** Your terminal is raw, so it
  raises no `SIGINT`; the `0x03` byte travels into the pty, and the child's own
  line discipline raises `SIGINT` for the child. `SIGTERM`, `SIGHUP` and
  `SIGQUIT` sent to `keyless` are forwarded rather than acted on, so the run
  always leaves through the same exit path — with the terminal restored and the
  child's exit code intact. On the pipe path the child shares this terminal's
  process group and receives Ctrl-C directly.
- **Restoration on every exit path** — normal exit, a child killed by a signal,
  and a panic (a hook covers the aborting kind, where destructors do not run).
  `SIGKILL` and a hard `abort()` cannot be covered by anything; `stty sane`
  repairs a terminal left raw by either.

**A pty is a comfort, not a precondition.** If one cannot be allocated — no
`/dev/ptmx`, no free descriptors, an unsupported platform — `keyless` prints one
line, falls back to pipes, and runs your command with its secrets injected
exactly as it would have. The never-block rule has no exception for terminals.

There is no flag to force a pty on or off. The condition is observable and the
fallback is automatic, so a switch would only be a way to get it wrong.

### The audit log

Append-only JSONL at `~/.local/state/keyless/audit.jsonl`, mode 0600.

```json
{"hash":"9f2c…","v":1,"ts":"2026-08-06T14:22:01.417Z","ts_ms":1786033321417,
 "verb":"run","state":"INJECTED","cwd":"/Users/you/src/app",
 "names":["DATABASE_URL"],"unresolved":[],
 "argv":["psql","--dbname=[keyless:DATABASE_URL]"],
 "argv_truncated":false,"exit_code":0,"prev":"4ab1…"}
```

**A value is never in here.** Not raw, not encoded, not hashed. The argv is
redacted with the same masker that filters the child's output, so a value typed
as a literal flag — the habit this tool replaces — is recorded as
`[keyless:NAME]` rather than as itself.

Rows are capped below `PIPE_BUF` (4096 on macOS) and appended under an exclusive
advisory lock, because many agent sessions can append concurrently. An oversized
argv is truncated rather than allowed to interleave with another session's row.

#### The chain, and what it is worth

Each row carries `sha256(previous_row_hash || this_row_bytes)`. The hash covers
the payload and links to the previous *hash*, so editing or removing any row
breaks every row after it. `keyless doctor` verifies it.

**Its integrity is bounded by who can write the file.** A process that can append
can also rewrite the file and recompute every hash — about four lines of work.
So the chain detects accidental truncation, partial writes and tampering by
anything that cannot rewrite the file, and detects nothing at all about a writer
who can.

**The chain is the detector. The file mode is the boundary.** They are different
things and only one of them is cryptography:

| | log written by | mode | can a session forge it? |
|---|---|---|---:|
| without the daemon | your own session | `0600` yours | **yes** |
| with the daemon | `_keyless` | `0640` `_keyless:keyless` | no |

Under the daemon your sessions can read the log and cannot write it, so a
rewrite is refused by the kernel before the chain is ever consulted. Without the
daemon the chain is worth exactly what it says above and no more.

A test asserts *both* halves, including the uncomfortable one:
`a_wholesale_rewrite_is_not_detected_by_the_chain_alone` rebuilds a log from
scratch and confirms it verifies perfectly — so the limit stays a checked
property rather than a caveat someone quietly drops.

Neither half survives `sudo`.

### No telemetry

`keyless` sends nothing anywhere, ever. No analytics, no version check, no crash
reporting, no error upload. There is no opt-out because there is nothing to opt
out of. It opens no network socket of its own — the only socket it ever opens is
the local Unix one to `keylessd` — and a test reads the built binary and fails if
an endpoint or a known analytics vendor's name appears in it.

**The promise extends through the subprocesses it spawns.** A network-backed
store reaches the network — that is what you asked it for — but nothing else
leaves with it. The Infisical CLI's own telemetry defaults to **on**, so
`keyless` passes `--telemetry=false` on every invocation it makes. Without that,
`keyless` would be the reason a report left your machine while this section
claimed otherwise.

The binary test allows exactly one `telemetry` string — `--telemetry=false` — and
fails both if any other appears and if that one ever goes missing.

This says nothing about the `infisical` runs you make yourself.

---

## Not built yet

Deliberately out of scope, with the seams left clean:

- **More backends.** `Store` is one trait with one method. Adding 1Password,
  Bitwarden or Vault means implementing it and registering it in `store::build`;
  `run` never learns which backend answered, and neither does the daemon.
- **Infisical and Proton Pass *behind* the daemon.** This is a gap with teeth,
  so it is stated rather than buried. Enabling the daemon suppresses every local
  backend — that is the [rule](#many-sessions-at-once) that keeps a fallback from
  re-opening the hole — but `keylessd`'s own store set is the file store and the
  keychain. So a user who resolves names through Infisical today and switches the
  daemon on will find those names **degrading**, loudly, with a warning naming
  the suppressed backend.
  Closing it means giving `keylessd` the same two adapters plus a decision about
  what reason it records, which is a change worth making on its own rather than
  inside a merge. It also needs an answer for `run --env`: the protocol carries a
  name and nothing else, so an Infisical name served by the daemon would have to
  declare its own `env` in the daemon's config, or the request would have to
  carry one — and a client naming its own environment is a client choosing its
  own tenant, which is the decision the daemon exists to take away from it.
- **A write operation on the daemon, and the manager identity behind its uid.**
  This is the same gap read from the write side, and it is the one that makes the
  [reader/manager split](#what-the-split-is-and-what-it-is-not) advisory rather
  than enforced. The protocol has `resolve`, `ping` and `names`; adding `write`
  means a new `Op`, a write capability on the daemon's registry, and a policy
  decision about which clients may ask — an attested client that may *read* a
  name should not automatically be allowed to *replace* it. Until then `new` and
  `put` refuse while the daemon is enabled rather than reaching around it.
- **Rotating a Proton value.** `item update` takes `--field name=value`, so using
  it would put the credential in argv. A vendor that accepts an update template on
  stdin — the way `item create` already does — closes this in about ten lines.
  Until then `put` against Proton creates and refuses an existing title.
- **`--materialize`** — for tools that can only read a file.
- **Linux.** The daemon's attestation is XNU-specific. What replaces each
  primitive is written down in [`install/README.md`](install/README.md), and the
  Linux answer is *better* — `pidfd_open` makes pid reuse impossible rather than
  merely detectable. Not shipped because it is not tested.
- **Per-name authorisation.** Today an attested client may ask for any name the
  daemon can resolve. Binding names to specific client images is a policy change,
  not an architecture change: the decision already has the verified identity in
  hand at the point where it currently only checks the allowlist.

There are no `TODO` comments in the source. Work is either done or listed here.

---

## Development

```console
cargo test                              # 518 pass, 15 ignored (the live Proton suite)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The 15 ignored are the entire live Proton Pass suite, which needs a real
account. CI asserts `ignored == 15`, so that stays visible rather than quietly
drifting.

The hook pack has its own suite: `python3 hooks/tests/run.py` runs every check
against fixed inputs, and `python3 hooks/tests/mutate.py` breaks each check on
purpose and requires every breakage to be caught. Both print their own counts —
this document deliberately does not restate one, because a count copied into
prose goes stale the next time a check is added.

Two guards police what this repository publishes about the person who wrote it.
`tests/publication.rs` refuses a vault, item, account or service name that is
not an allowlisted decoy, any prose that makes a claim about the machine it was
written on, and any wall-clock instant that is not an obvious fixture — across
every published file, not only the Rust sources. The publication layer of the
hook suite refuses a number standing next to a word that makes it a measurement
of one machine, in `hooks/` prose **and in commit messages**. Install the
matching `commit-msg` hook so the second one fires before the message is written,
which is the only point at which it can still be edited:

```console
ln -sf ../../install/commit-msg.sh .git/hooks/commit-msg
```

Who built it stays. What is inside their machine does not: the copyright, the
author and the reasoning are identity, and a count only they can reproduce is an
inventory.

No test reads a real credential, and no test reaches a real vault. All three
backends are exercised against shell stubs — `security find-generic-password` is
never invoked against a real service name, no keychain prompt is triggered,
`security add-generic-password` never touches your keychain, and neither
`infisical` nor `pass-cli` is ever run against an account. Every value in the
suite is a decoy invented in `tests/support`.

The Infisical stub reproduces behaviour **measured** against CLI 0.43.114: the
flags it accepts, that its stdout is byte-for-byte the child's, and the exact
stderr wording that separates an unset variable from a failure of the CLI's own.
The Proton stub encodes behaviour **measured** against `pass-cli` 2.2.5 on
2026-08-08: the `run --env-file … --no-masking --` spelling, the reference
format, that `PROTON_PASS_SESSION_DIR` selects the identity, and the record
shape `item list --output json` returns — `id`, `share_id`, `state`, `title`,
with no `item_id` key. The discovery stub adds the `item view --output json`
shape, whose every value position holds a marker string — which is what makes
"no value reached the field list" an assertion rather than a restatement of the
parser.

Both stubs take their fixtures from **files** rather than inlining JSON into the
shell script. That is not style: the vendor's own wording includes
`passwords don't match`, and an apostrophe inside a single-quoted shell string is
a syntax error. Inline one and the stub fails to parse, and the adapter reports
the shell's error as though it were the vendor's refusal — a fixture bug that
reads as a real finding.

The stubs record the argv they were called with, so the tests assert on the
invocation the adapter actually built rather than on a copy of the adapter's own
list of flags. A test that iterates the same list the implementation uses is
worthless: deleting an entry deletes it from both, and the suite stays green.

**`cargo test --test <name>` does not rebuild `examples/`.** The attestation
suite drives two real signed binaries from there, so filtering to one test file
after editing a peer runs the *previous* binary, and a correct fix reads as a
no-op. The support helper aborts the run when a peer is older than its source;
`cargo test` with no filter is always safe.

The security core is tested from three directions, and each catches a different
class:

| suite | what it is for |
|---|---|
| `daemon.rs` | it works: injection, masking, single-flight, the chain under 20 concurrent sessions |
| `daemon_degraded.rs` | the never-block invariant, once per way a daemon can fail |
| `attestation.rs` | the attacks, each with a control proving the machinery still works |

Every claim in the attestation suite has a negative control, because "the attack
was refused" and "nothing worked at all" are the same colour of green. Eight
mutations — attestation always allows, single-flight removed, daemon-absent made
fatal, the code hash taken from the path instead of the live image, the
interpreter refusal removed, the local fallback restored, attestation moved to
once-per-connection, and a malformed reply accepted — are each killed by a named
test.

The discovery and write verbs carry five more, each verified by making the
mutation, confirming the byte change with `diff`, and running exactly one test:

| Mutation | Killed by |
|---|---|
| the type column reports the container's *value* instead of its *key* | `store::proton::…::no_extracted_field_name_is_ever_a_value` |
| `put` gains a `--value` flag | `cli::there_is_no_way_to_pass_a_value_to_put_as_an_argument` |
| every listed item is reported `Active` | `stores::a_listing_reports_a_trashed_items_state_verbatim` |
| `--projectId` is not passed through | `store::infisical::…::project_coordinates_are_passed_only_when_configured` |
| the reader falls back to the manager's session directory | `store::proton::…::a_read_never_uses_the_manager_identity_even_when_one_is_configured` |

The second of those is the reason that test asserts on **exit code 2** — clap
refusing the word — rather than on "the command failed". Under `Command::output()`
stdin is empty, so a `put` that accepted `--value` and ignored it would fail
anyway, and a test that only checked for failure would have stayed green with the
flag present.

A filtered `cargo test` that matches **zero** tests exits 0 and reads exactly like
a pass, which is how a negative control goes green without exercising anything. So
each of those runs went through a harness that parses the `test result:` lines and
aborts unless exactly one test executed.

`.cargo/config.toml` pins the linker to `/usr/bin/cc`. On a machine where some
other tool installs its own `cc` earlier in `PATH`, every link otherwise fails
with `unknown option '-lSystem'`, which reads as a broken Rust toolchain rather
than a shadowed binary.

### Dependencies

Five crates, in four rows, and each earns its place:

| Crate | Why |
|---|---|
| `clap` | argument parsing; the derive form keeps the verb set readable at a glance, which matters when the absence of a verb is a security property |
| `serde` + `serde_json` | config parsing and audit rows — one format doing both jobs |
| `zeroize` | the optimiser is permitted to delete a write to memory that is never read again, which is exactly what hand-rolled scrubbing is |
| `nix` | the pty syscalls — `openpty`, `termios`, the three window/controlling-terminal `ioctl`s, `sigwait`, `pthread_kill`. Six of its 35 features are enabled |

`nix` is where hand-rolling stops being minimalism. A codec has a specification
and published vectors, so owning one is cheap and checkable. An `ioctl` request
constant does not: get it wrong and the code compiles, links, and then writes the
wrong number of bytes through a pointer at runtime, differently on every
platform. A terminal framework would have been far more than the job needs; the
six enabled features are the job.

base64, base32, hex, SHA-256, percent-encoding, JSON escaping and the civil-date
conversion are all written here rather than taken as dependencies. Each is short,
well specified, and checked against published vectors — RFC 4648 for the codecs,
FIPS 180-4 for the hash. Owning a codec is only cheaper than depending on one if
it is actually checked, so it is.

---

## Licence

MIT.
