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

- **[`keyless run` never blocks your command on a
  failure.](docs/guide/reference.md#rule-1-it-never-blocks-your-command-on-a-failure)** A broken
  config, an unreachable store or a dead daemon warns on stderr and runs your
  command anyway, with an unmodified environment. It refuses only a name its
  store does not hold, an empty name, or a caller that fails attestation: exit
  64, the command never starts, and stderr names what to ask for instead.
- **[No verb prints a value.](docs/guide/reference.md#rule-2-there-is-no-verb-that-prints-a-value)**
  There is no `get`, no `--reveal`, no debug flag. If a command needs a
  credential, run the command under `keyless run`.

On its own that is a good habit around a store your own uid can read. Add
[`keylessd`](docs/guide/keylessd.md#keylessd--the-uid-boundary) and it becomes a boundary: the store
moves behind a second uid, your sessions ask over a socket, and the socket
carries names and results but never the store credential.

macOS today. MIT licensed.

---

## Contents

- [Why this exists](docs/guide/why-this-exists.md)
- [Install](docs/guide/install.md)
- [The first five minutes](docs/guide/first-five-minutes.md)
- [Names, the config, and what `ls` is telling you](docs/guide/names-and-config.md)
- [Stores](docs/guide/stores.md)
  - [Infisical — a verb that hands back a process, not a value](docs/guide/store-infisical.md)
  - [Proton Pass — verified against `pass-cli` 2.7.0](docs/guide/store-proton.md)
  - [1Password — one vault, named once](docs/guide/store-1password.md)
- [Finding what to put in the config](docs/guide/finding-names.md)
- [Storing a secret](docs/guide/storing-a-secret.md)
- [What this protects you from, and what it does not](docs/guide/threat-model.md)
- [`keylessd` — the uid boundary](docs/guide/keylessd.md)
- [The hook pack — closing the other paths](docs/guide/hook-pack.md)
- [Reference](docs/guide/reference.md)
- [Not built yet](docs/guide/not-built-yet.md)
- [Development](docs/guide/development.md)

## The audit log

Append-only JSONL at `~/.local/state/keyless/audit.jsonl`, mode 0600.

```json
{"hash":"9f2c…","v":1,"ts":"2000-01-01T00:00:00.123Z","ts_ms":946684800123,
 "verb":"run","state":"INJECTED","cwd":"/Users/you/src/app",
 "names":["DATABASE_URL"],"unresolved":[],
 "argv":["psql","--dbname=[keyless:DATABASE_URL]"],
 "argv_truncated":false,"exit_code":0,"prev":"4ab1…"}
```

`ts` is `ts_ms` rendered and nothing else, so the two can never disagree.

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

## Licence

MIT.
