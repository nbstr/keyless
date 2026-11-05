# Storing a secret

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
— the CLI-flag shape, one of the four [above](why-this-exists.md#why-this-exists). A flag that
exists gets used, so the flag does not exist — structurally, the same way `run`
has no `--reveal`.

At a terminal, `put` prompts with echo off. If echo cannot be switched off it
does **not** prompt anyway; a prompt that echoes would print the credential.

## These verbs refuse on failure. `run` does not

`keyless run` never blocks on a store's failure, because blocking your work gets
the tool uninstalled and then the plaintext comes back; it refuses only a name
its store does not hold, an empty name, or a caller that fails attestation. That
argument does not transfer to setup
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

## The reader and the manager are two different identities

`stores.proton.session_dir` is the **reader**: a viewer-role agent token, the
default, and the only identity `run`, `ls`, `items` and `fields` can reach. It
cannot create, move or trash anything, which is what you want every session on
the machine to hold. On a session this is a plain directory; on the daemon the
same key names the ROOT of a set of generation directories it renews into.

`stores.proton.manager.session_dir` is a **second** token with the editor role,
used by `new` and `put` and by nothing else:

```json
"proton": {
  "enabled": true,
  "session_dir": "~/.keyless-pass-session",
  "manager": { "session_dir": "~/.keyless-pass-manager" }
}
```

Minting it takes three commands and **two different identities**, measured
against `pass-cli` 2.3.2. The first two act as your ACCOUNT — they mint a token
for an agent, they are not run by one — so they belong wherever your own login
lives, which is the default session unless you keep it somewhere named:

```console
# No PROTON_PASS_SESSION_DIR here — these run as the ACCOUNT, in whichever
# session your own login lives in, and the default one is where it usually is.
$ pass-cli agent create keyless-manager --expiration 3m
$ pass-cli agent access grant keyless-manager --vault-name personal --role editor
```

**The create names no vault, and that is the whole trick.** `agent create
--vault <V>` grants access at mint time and FIXES the access set: every later
`agent access grant` on that agent answers `NotAllowed` — for every role,
including the one it already holds — and `agent access revoke` answers
`NotExists` for the very vault the agent can read. So an editor agent cannot be
created with `--vault` and upgraded afterwards; it is created bare and granted.

The reader agent is the opposite case and keeps its `--vault`, because viewer is
what `create` grants and no second command is wanted:

```console
# Still no PROTON_PASS_SESSION_DIR — minting is the ACCOUNT's act either way.
$ pass-cli agent create keyless-reader --expiration 3m --vault personal
```

`NotAllowed` from `access grant` therefore has two unrelated causes that read
identically — a vault the account cannot share, and an agent that was minted
with `--vault`. The second is the common one and nothing in the message says so.

The third is the one that creates the manager's session, and leaving it out is
why a config can point at a directory that has nothing in it. `agent create`
prints a token and writes to no session directory:

```console
$ PROTON_PASS_SESSION_DIR=~/.keyless-pass-manager \
  PROTON_PASS_PERSONAL_ACCESS_TOKEN=<the token above> pass-cli login
```

That spelling is the vendor's own, from `pass-cli agent instructions`. The
alternative, `pass-cli login --pat <TOKEN>`, exists and is not recommended here:
an argument is readable from the process table for as long as the process lives,
which is the leak this tool exists to remove. The environment is not free either
— that line lands in your shell history — but it is the better of the two the
vendor offers.

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

## What the split is, and what it is not

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
is [`keylessd`](keylessd.md#keylessd--the-uid-boundary), behind a second uid. So the
enforced version of this split is "the manager token lives on the daemon's
side", and it is not built: the daemon's Proton adapter reads, and the protocol
has no write operation to carry a manager identity over.

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

## What each backend can write, and what it cannot

| Backend | Write | Notes |
|---|---|---|
| `keychain` | `add-generic-password -U -w`, value on stdin | `-U` updates in place, so this rotates |
| `proton` | `item create <type> --from-template -`, template on stdin | **creates only** |
| `infisical` | no | `infisical secrets set` takes the value as a command-line argument, and the CLI offers no stdin form |
| `onepassword` | not yet | `op item create -` reads a JSON template on stdin, so a writer is possible and is listed under *Not built yet*; the assignment form `password=<value>` puts the value in argv and is what the refusal steers away from |

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

## The audit row says which identity did it

Every `run` row carries `"identities":["<store> (reader)"]`, and a write row says
`proton (manager)`. A `Registry` cannot hold a writer and `ProtonStore` does not
read the `manager` block, so a `run` row saying `(manager)` is unreachable — which
makes "did a session ever act as the editor?" a question you answer from the log
rather than from trust.

---
