# The hook pack — closing the other paths

`run` makes the safe path available. It does not make it the only path, and an
agent under completion pressure takes the shortest one. So it reads the `.env`,
runs `op read`, or dumps `env`, and the injector was theatre.

[`hooks/`](../../hooks/README.md) is a store-agnostic pack that closes those doors
from inside the agent harness — Python 3, stdlib only, one command to install
and one to remove:

```console
$ cd hooks && ./install.sh
```

It refuses a vault CLI's print verb across 16 stores, refuses a shell command
that reads a credential file, and **rewrites rather than refuses wherever a
rewrite exists**: a `Read` of a `.env` is redirected to a names-only view, a
bare `env` is masked with its pipeline intact, and a credential literal in a
file being written becomes `${NAME}` while the write proceeds — where the value
is proved a credential by its own SHAPE, or by the grammar around it, and the
destination's reader resolves the reference. A value flagged only because the
identifier beside it reads like a credential is REPORTED and never edited, in
any destination: that rule cannot tell `PGPASSWORD=<a literal>` from
`password`: `e2eLoginPassword`, and a file edited on evidence that weak is
handed back broken and called repaired.

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
published rather than omitted — see [`hooks/README.md`](../../hooks/README.md).

## Why `fields` exists, and where the gate still misfires

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
