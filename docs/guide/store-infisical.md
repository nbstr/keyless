# Infisical — a verb that hands back a process, not a value

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
report left your machine — see [No telemetry](reference.md#no-telemetry). It also pins
`--log-destination=stderr`, because the CLI reads that from `LOG_DESTINATION`
too and a value of `stdout` there would interleave log lines with the value
being read.

`keyless` never opens the vendor's login, wherever the vendor keeps it — a
system-keyring item, for the version this adapter was measured against — nor the
project settings and encrypted cache in its state directory. A session's login
belongs to the CLI and is inherited by spawning it; there is no config field a
token fits in.

A daemon has no such login to inherit, because a keyring item belongs to the uid
that unlocked it. It hands the vendor a machine identity instead — see
[Infisical behind the daemon](#infisical-behind-the-daemon).

## Infisical behind the daemon

`keylessd` carries this adapter. Enable it under `stores.infisical` in
`keylessd.json`, give every name its own `env` under `secrets` there, and name
where the machine identity lives:

```json
{
  "stores": {
    "infisical": {
      "enabled": true,
      "binary": "/opt/homebrew/bin/infisical",
      "project_id": "<your project id>",
      "credentials_file": "/usr/local/var/lib/keyless/infisical.json",
      "credentials": { "INFISICAL_TOKEN": "MACHINE_IDENTITY" }
    }
  },
  "secrets": { "DATABASE_URL": { "store": "infisical", "env": "staging" } }
}
```

`credentials` maps a variable the vendor CLI reads to an **entry name** in a
mode-`0600` file the daemon owns. The value is never in this config, never in
the launchd plist — which is installed world-readable — and never in argv. It is
read at spawn time and dropped with the lookup, so rotating it needs no restart.

Three things this arrangement is deliberately strict about:

- **Its own file, not the one the `file` store serves.** Anything in that file
  is a name an attested client can ask for, so a machine identity kept there
  would be handed to any session that guessed its label. Sharing one file works
  and is warned about by name.
- **`INFISICAL_*` only.** Unbounded, the field sets any variable on a child
  process as the daemon's uid: `PATH` would choose which binary the vendor is,
  `HOME` which login it finds.
- **No environment the daemon can supply.** There is no `env` key in the daemon's
  Infisical settings and no field for one on the wire, so a name that declares
  none is refused before anything is spawned. That is the whole reason this
  adapter is safer here than in a session — see below.

## An environment is required, and has no default

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

**Behind the daemon there is only the first**, and that is a security property
rather than a missing feature. The protocol carries a name and no environment,
so a client cannot say which tenant it means — and a name that appears nowhere
in `keylessd.json` therefore has no environment at all, which is what stops an
invented name becoming a real query against a real vault. A daemon-side degrade
says so, and points at the daemon's config rather than offering a flag the
client cannot send.

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

That is a degrade, never a refusal: no store was asked, so none answered that
it holds no such name, and [rule
1](reference.md#rule-1-it-never-blocks-your-command-on-a-failure) has no exception for this
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
named*, which refuses the run and says so, while a wrong environment returns a
plausible value from the other side of the boundary. `keyless ls` prints both
coordinates for every Infisical name, so a folder that holds nothing is visible
without a lookup.

## Pin the project, or resolution depends on where you are standing

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
