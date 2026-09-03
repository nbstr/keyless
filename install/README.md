# Installing the daemon

**This is one step of the install, not the install.** `keyless setup` is the
whole of it — config, guards, agent instructions — and it REPORTS this daemon
rather than standing it up. `keyless setup --daemon` runs the script below under
`sudo` for you; everything here is what that runs, and it is worth reading first.

Two files to read before you run anything: [`install.sh`](install.sh) and
[`sh.keyless.keylessd.plist`](sh.keyless.keylessd.plist).

**The installer is dry-run by default.** It prints every command it would run,
in order, and changes nothing. `--commit` is the only thing that makes it act.

```console
$ cargo build --release             # the installer copies from target/release
$ ./install/install.sh              # prints the plan
$ sudo ./install/install.sh --commit
```

It needs `sudo` exactly once, to create a user. Nothing afterwards does.

[`uninstall.sh`](uninstall.sh) reverses all of it — the launchd job, the
files, and the user account the install created. It is dry-run by default
too, and takes the same `--commit`. It deliberately keeps the audit log and the
store; both are printed at the end so you deal with them on purpose.

`keyless uninstall` is the other half, and the two do not overlap: this script
owns everything under `/usr/local` and the system account, and that verb owns
the config, the guards' registration and the agent instructions.

---

## What the one `sudo` buys

A uid you are not.

That is the entire mechanism. Everything else in `keyless` is a good habit
around a store your own uid can read — and **anything readable by your uid is
readable by every session and every subagent one spawns.** No file mode, no
deny rule and no wrapper changes that. A second uid does, because the kernel
enforces it and there is nothing to bypass.

| path | mode | owner | what it means for you |
|---|---|---|---|
| `/usr/local/var/lib/keyless/secrets.json` | `0600` | `_keyless:keyless` | you cannot read it |
| `/usr/local/var/log/keyless/audit.jsonl` | `0640` | `_keyless:keyless` | you read it, you cannot write it |
| `/usr/local/var/run/keyless/keylessd.sock` | `0660` | `_keyless:keyless` | you connect to it |
| `/usr/local/var/run/keyless/` | `0755` | `_keyless:keyless` | you cannot replace the socket |
| `/usr/local/etc/keyless/keylessd.json` | `0644` | `root:wheel` | you read the policy |

The socket is `0660` and not `0640` because **connecting to a unix socket needs
write permission**, not read. A socket a group can only read is a socket that
group cannot use.

The audit log's mode is the whole unforgeability claim. Each row carries
`sha256(previous_hash || row)`, which detects an edit only if the editor cannot
also recompute every hash after it. A writer with write access can, in about
four lines. `0640` is what makes your sessions not that writer.

---

## The step the installer will not do for you

**Installing this daemon next to a login keychain that still holds your secrets
closes nothing.**

`security find-generic-password -s <service> -w` returns plaintext, with no
prompt and exit 0, to every process running as you. Standing up a daemon does
not change that. The items are still there and still readable.

The step that shuts the hole is a migration, and it has two halves:

1. Put the secret where only `_keyless` can read it.
2. **Delete it from your login keychain.**

Half two is the one that matters, and it is the one that feels optional. Until
it happens you have two doors and have locked one.

```console
$ sudo -u _keyless tee /usr/local/var/lib/keyless/secrets.json >/dev/null <<'EOF'
{ "GITHUB_TOKEN": "...", "DATABASE_URL": "..." }
EOF
$ sudo chmod 0600 /usr/local/var/lib/keyless/secrets.json

$ security delete-generic-password -s keyless -a GITHUB_TOKEN
```

The installer does not do this, and should not: it cannot know which of your
keychain items are meant to stay reachable by hand, and a script that deletes
credentials it guessed at is worse than the problem it is solving.

Verify the delete rather than assuming it. The check is that the *old* path
stops working:

```console
$ security find-generic-password -s keyless -a GITHUB_TOKEN -w
security: SecKeychainSearchCopyNext: The specified item could not be found.
```

---

## Then point your sessions at it

`~/.config/keyless/config.json`:

```json
{ "stores": { "daemon": { "enabled": true } } }
```

Enabling the daemon **disables every local backend** — keychain, Infisical,
1Password and Proton Pass alike — whatever each one's own `enabled` flag says. That is
enforced in `store::build`, not documented as a convention, because a local
fallback would re-open the hole the moment the daemon stopped — and anyone who
can stop a process could choose that. Killing `keylessd` must get you fewer
secrets, never more.

**Log out and back in.** Group membership is established at login; until then
your shell is not in the `keyless` group and the kernel refuses the connection
before the daemon ever sees it. The symptom is every name degrading, which
looks exactly like a broken daemon.

---

## Checking it

```console
$ keyless doctor
$ sudo keylessd check  --config /usr/local/etc/keyless/keylessd.json
$ keylessd verify --config /usr/local/etc/keyless/keylessd.json
```

`check` runs under `sudo` and the other two do not. The store and the daemon's
credential file sit in a `0700` directory owned by the daemon, which is the
whole point of them; read as you, `check` cannot open either one and reports
that it could not rather than reporting nothing wrong.

`keyless doctor` also reports the case worth catching: a socket that is
listening while your config does not mention it. That means the daemon is
installed and every session is still reading the keychain directly — and
nothing else in the tool would ever say so, because from `run`'s point of view
everything is working.

`check`'s `client` row is the other one. It walks your `PATH` for `keyless` and
compares each one it finds against `peer.allow_images`, which is the only place
that holds both halves of the question — see below.

---

## Two copies of the same program

Putting `keyless` in `/usr/local/bin` does not make it the one your shell runs.
A second copy earlier on `PATH` wins, and it is a different binary with a
different code hash, so the daemon refuses it. Both symptoms name something
else:

- the old copy simply lacks whatever landed since it was built, so a verb that
  exists answers `unrecognized subcommand` and reads as a bad build;
- the refusal reads `` `keyless` is not a pinned client ``, which reads as a
  broken pin and sends you to re-pin a file that was already pinned correctly.

The installer walks `PATH` and reports anything named `keyless` or `keylessd`
reached before `/usr/local/bin`, in the dry run and in the commit run alike. It
removes exactly one class of them, and only through `cargo uninstall keyless`:
a copy `<CARGO_HOME>/.crates.toml` records as this package's. That file is
cargo's own ledger, so it is provenance rather than resemblance, it survives the
copy being old — which is the whole difficulty, since being old is the defect —
and `rm` would leave the ledger claiming the binary is still installed, which
brings the shadow back on the next `cargo install`.

**Anything else of that name is reported and never touched.** No property of the
bytes distinguishes a stale build of ours from somebody else's program, so the
installer does not guess, and neither does `check`.

Neither of them sees the whole of it. A `PATH` is one process's, and a shell
that has already looked a name up keeps its answer until you run `hash -r`. So
both can MISS a shadow and neither can invent one — and `check` is the half that
runs in your own shell, whenever something is already wrong.

---

## Serving names out of Infisical

Optional. Skip it if you do not use Infisical; nothing above depends on it and
the installer does not enable it.

A session reaches Infisical by spawning the vendor CLI, which finds the login
already in the calling user's keychain. **The daemon cannot do that.** A login
keychain belongs to the uid that unlocked it, so the daemon's uid has an empty
one, and giving that uid a home directory does not change it. The daemon uses a
**machine identity** instead: a client id and a client secret you create in
Infisical, scoped to the environments you are willing to let it read, and
revocable there.

### Why a client secret and not a token

`infisical run` authenticates with `INFISICAL_TOKEN` and with nothing else.
Given a client id and client secret in its environment it ignores both and
tries to open a browser login, which under launchd fails with a message about a
login flow. So a token is the only thing a lookup can use — and a token
expires.

A daemon has nobody to prompt when that happens. What you would see is every
Infisical name degrading, at an hour nobody chose, with your commands still
running and their environments simply missing the values. So the daemon stores
the **identity** and mints its own token per lookup, which is one extra round
trip and never expires.

The price is a long-lived credential on a disk, and the whole of what bounds it
is one file's mode and one file's owner. Which is why `keylessd check` verifies
both rather than checking that the file exists — and reads what is in it, since
an empty file has exactly that mode and that owner and holds no login at all.

### Setting it up

Add the store to `/usr/local/etc/keyless/keylessd.json`. Coordinates only —
there is no field in this file that a credential fits in:

```json
"infisical": {
  "enabled": true,
  "binary": "/absolute/path/to/infisical",
  "domain": "https://<your-region>.infisical.com",
  "project_id": "<your-project-id>",
  "credentials_file": "/usr/local/var/lib/keyless/infisical.json",
  "credentials": {
    "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "MACHINE_IDENTITY_CLIENT_ID",
    "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "MACHINE_IDENTITY_CLIENT_SECRET"
  }
}
```

Three of those are easy to get wrong and quiet about it:

- **`binary` should be absolute.** launchd hands a daemon its own `PATH`, not a
  login shell's, so the bare name that resolves for you may resolve to nothing
  for the daemon.
- **`domain` is the region.** The CLI defaults to the US cloud. An identity
  created in another region has no account there, and what you read is a
  refusal about your credentials rather than about your region.
- **Every name needs its own `env`.** The daemon has no default environment and
  will not invent one — that is deliberate, and it is what stops a name nobody
  declared resolving against production. A name without one is refused before
  anything is spawned.

```json
"secrets": {
  "DATABASE_URL": { "store": "infisical", "env": "<slug>", "path": "/backend" }
}
```

Then put the identity in the daemon's own file. This prompts, echoes nothing,
and takes no value on the command line — so the credential is in no shell
history and in no process table:

```console
$ sudo keylessd credential --name MACHINE_IDENTITY_CLIENT_ID
$ sudo keylessd credential --name MACHINE_IDENTITY_CLIENT_SECRET
$ sudo keylessd check --config /usr/local/etc/keyless/keylessd.json
```

`check` prints two separate rows about this, and they answer different
questions. `identity` is about the file: does it exist, is it `0600`, is it
owned by the uid the daemon runs as, and is there a login in it — an empty file
and a file holding an identity are the same file by mode and owner, and the
empty one is what a fresh install leaves. `store infisical` is about the tenant:
does Infisical accept the login. A credential that is refused says so and never
reports a name as missing — those two are the outcomes that must never be
confused, because one means "fix your login" and the other means "look in
another vault".

## Serving names out of one 1Password vault

Optional. Skip it if you do not use 1Password; nothing above depends on it and
the installer does not enable it.

This is the arrangement that turns the store's vault pin from an allowlist into
a boundary. On a session, `op` inherits a login that sees every vault the
person can see, and `stores.onepassword.vault` only stops `keyless` from
reading the others. Behind the daemon, `op` is handed a **service account** —
an identity the vendor mints with access to named vaults and refuses
everything else — and the token lives in a file only the daemon's uid can
read. Sessions ask over the socket by name and never see it.

### Mint the service account

At the vendor, as yourself, with read access to exactly the one vault the
daemon may serve:

```console
$ op service-account create keyless-agents --vault company:read_items
```

That prints the token once. It goes into the daemon's file in the next step and
nowhere else; a service account cannot be granted your Personal or Private
vault, which is the vendor's own rule and the right one.

### Configure the store

Add it to `/usr/local/etc/keyless/keylessd.json`. Coordinates only; there is no
field in this file a credential fits in:

```json
"onepassword": {
  "enabled": true,
  "binary": "/absolute/path/to/op",
  "vault": "company",
  "config_dir": "/usr/local/var/lib/keyless/op",
  "credentials_file": "/usr/local/var/lib/keyless/onepassword.json",
  "credentials": { "OP_SERVICE_ACCOUNT_TOKEN": "SERVICE_ACCOUNT" }
}
```

- **`vault` is required and never defaulted.** It is the same rule a session
  has, for the same reason: which vault a name resolves against must be
  written down, never inferred from what the login happens to see — and it
  should be the vault the service account was minted for, or every lookup is
  refused by the vendor.
- **`field` decides whether this store serves the names you declared or the
  whole vault.** Read the box below before you set it. It is the field a name
  reads when its own entry names none — convenient when every item in the vault
  has the same shape, and it has a consequence behind the socket.
- **`config_dir`** names a directory the daemon's uid can write. `op` keeps an
  account list and a cache socket under the calling user's config directory,
  and a daemon's home may not be one it can write to. Create it owned by the
  daemon.
- **An absolute `binary`**, for the reason the Infisical section gives.
- **`OP_*` only** under `credentials`. Anything else is refused by every
  lookup and named by `keylessd check`.

> ### ⚠️ With `field` set, the vault itself is the allowlist
>
> A 1Password item needs three coordinates: the vault, the item's title, and
> the field. The vault is the store's, and the title defaults to the name being
> asked for — so `field` is the **last one missing**. Set it store-wide, and a
> name that appears in **no** `secrets` entry still resolves: it is looked up as
> the item of that title, in the pinned vault, at that field.
>
> On a session that changes nothing — the person at the keyboard already has a
> login that reads the whole vault. Behind the daemon it is the access model.
> The daemon holds an identity no client has, `secrets` is routing rather than a
> gate, and `keylessd` has no list of declared names to check a request against.
> So **any client the policy attests can ask for anything the vault holds, by
> guessing an item's title.**
>
> That is deliberate, and it is why the store is pinned to one vault and why the
> service account is minted for that vault and no other: **put in it only what
> every attested client on this machine may read.**
>
> **To serve declared names and nothing else**, leave `stores.onepassword.field`
> out and put `"field"` on each name under `secrets`. An undeclared name then
> has no field to read, and it is refused before anything is spawned — a field
> is the one coordinate this tool will not guess.
>
> `keylessd` warns at startup, and `keylessd check` prints the same line, naming
> the vault, whenever this store is enabled with a store-wide `field`. Nobody
> has to remember to come back and read this.

Each name is an item in that vault, by title, and the item's id when two share
one. Giving every name its own `field` is what keeps the store to the names you
declared:

```json
"secrets": {
  "STRIPE_KEY": { "store": "onepassword", "item": "demo api key", "field": "credential" }
}
```

### Put the token in the daemon's own file

Prompts, echoes nothing, takes no value on the command line:

```console
$ sudo keylessd credential --store onepassword --name SERVICE_ACCOUNT
$ keylessd check --config /usr/local/etc/keyless/keylessd.json
```

`--store` picks which credential file the entry goes in. It can be left off
when only one store's `credentials` names the entry, and is refused when more
than one does.

`check` prints the same two rows it prints for Infisical: `identity` is about
the file — does it exist, is it `0600`, is it owned by the daemon — and `store
onepassword` is the vendor accepting the token **and listing that vault's
items**, which is the permission `--vault company:read_items` grants and the
round trip every lookup starts with. A refused token says so and never reports
a name as missing. What no green row here claims is that `op run` has resolved
a reference on this machine; nothing short of reading a value can claim that.

### What has not been measured

The adapter's authenticated path is built from the vendor's documentation and
has not been run against a signed-in account; the README's *Not built yet*
carries the detail. Whether a service account under launchd needs the
`config_dir` above, or works without it, is one of the things that first live
run will settle.

### Removing it

`install/uninstall.sh` deletes every credential file, unlike the secrets store
beside them. The store may be your only copy of something; these files never
are, because the identity lives at the vendor. **Revoke it there as well** — deleting
the copy is not revoking the credential.

---

## Serving names out of Proton Pass

Optional, and independent of everything above.

### The problem this arrangement solves

Proton keeps **one logged-in identity per session directory**, chosen by
`PROTON_PASS_SESSION_DIR`. A session inherits whichever identity the person at
the keyboard logged in — usually the whole account. The daemon gets one of its
own instead, at `/usr/local/var/lib/keyless/proton-session`, created by the
installer at `0700` and readable by nobody else.

Two facts about that directory decide whether any of this works, and the second
one is the reason this adapter took a day to move behind the daemon.

**It must be writable by the daemon.** `pass-cli` rewrites its session store on
invocations that only read. A read-only directory is not a safer version of
this arrangement; it is a broken one.

**The daemon must be able to find the local key that directory is encrypted
with.** By default that key lives in a login keyring, and a keyring belongs to
the uid that unlocked it — a daemon uid has none. Asked for a key it cannot
find, beside a session store that exists, `pass-cli` **forces a logout and
reinitialises the store**:

```text
Error: Local encryption key not found but local data exists. Forcing logout for security.
```

That is the mechanism behind the warning elsewhere in this repository that a
`pass-cli` run with a stripped environment destroys a web-login session. The
stripping was one way of reaching it, not the cause: it took away what the
keyring provider needed to answer. A daemon reaches the same place by simply
not having a keychain.

So the daemon always names a key provider, and `keyring` is not a value
`keylessd.json` will accept — it refuses to start rather than run that way.
`fs` keeps the key in the session directory beside the store, at the same
`0600` under the same uid.

### Mint the agent token

At the vendor, as yourself, scoped to exactly the one vault the daemon may
serve:

```console
# No PROTON_PASS_SESSION_DIR here — this runs as the ACCOUNT, in whichever
# session your own login lives in, and the default one is where it usually is.
# It is NOT run by the agent it mints, and not by the daemon.
$ pass-cli agent create keyless-agents --expiration 1y --vault company
```

One command, with `--vault`, because viewer is what `create` grants. The main
README's manager recipe creates bare and grants afterwards for the opposite
reason: `create --vault` FIXES the access set, so an editor cannot be minted
that way and upgraded. A viewer wants exactly what `create` gives it.

**Viewer, not editor.** With the daemon enabled, `keyless` refuses every write
for every store, so an editor token here would be a strictly larger prize with
no ability whatsoever to be used. The vendor enforces the rest in its crypto
layer rather than by policy: *"Personal access tokens and agent sessions cannot
perform user key operations."*

**Write down the day it expires.** The next section needs it, and it cannot be
recovered later — see *What `check` can and cannot tell you* below.

### Configure the store

Coordinates only; there is no field in `keylessd.json` a credential fits in:

```json
"proton": {
  "enabled": true,
  "binary": "/absolute/path/to/pass-cli",
  "session_dir": "/usr/local/var/lib/keyless/proton-session",
  "key_provider": "fs",
  "token_expires": "<YYYY-MM-DD>",
  "credentials_file": "/usr/local/var/lib/keyless/proton.json",
  "credentials": { "PROTON_PASS_PERSONAL_ACCESS_TOKEN": "AGENT_TOKEN" }
}
```

- **`session_dir` is required and never defaulted.** With none, the vendor
  falls back to a location derived from the caller's home, which for a daemon
  uid is either nothing or something nobody meant to be a credential store.
  Every Proton name degrades instead, and startup says so.
- **`key_provider`** is `fs` or `env`, and defaults to `fs`. `env` takes the
  key from `PROTON_PASS_ENCRYPTION_KEY`, which then has to be named under
  `credentials` beside the token. `keyring` is refused at parse time.
- **`token_expires`** is a date you write down, not one anything can discover.
- **An absolute `binary`**, for the reason the Infisical section gives.
- **Two variables only** under `credentials`:
  `PROTON_PASS_PERSONAL_ACCESS_TOKEN` and `PROTON_PASS_ENCRYPTION_KEY`. This is
  narrower than the `INFISICAL_*` rule next door, deliberately: a prefix rule
  would accept `PROTON_PASS_SESSION_DIR` and `PROTON_PASS_KEY_PROVIDER` too,
  and a credential entry able to set either would silently overrule which
  identity answers and whether its session survives being read.

Each name is an item in that vault, by vault name, title and field:

```json
"secrets": {
  "OPENAI_API_KEY": { "store": "proton", "vault": "company",
                      "item": "demo api key", "field": "password" }
}
```

**None of the three is defaulted, and that is a security property rather than
an inconvenience.** A name that appears nowhere in this file has no address, so
there is no query to make: no `pass-cli` process runs, no vault is listed, and
no audit entry is written at Proton for a name nobody declared. Guessing any
one of the three would cost a real read against a real vault.

### Log the daemon in

One command. It prompts for the token, echoes nothing, and takes no value on
the command line:

```console
$ sudo keylessd login --store proton
$ sudo keylessd check --config /usr/local/etc/keyless/keylessd.json
```

It reads every coordinate out of the config you just wrote — which is why the
store is configured first, and why there is no `--session-dir` or
`--key-provider` flag here. A flag that disagreed with the config would log a
session into a directory the daemon never opens, and that fails in a way that
reads exactly like a wrong token.

What it does, and why each part of it is not optional:

- **Creates the session directory `0700` under the daemon**, or repairs one that
  is not — including giving back any file inside it that a hand-run login left
  owned by root. Whoever runs a `pass-cli` owns what it writes, and `pass-cli`
  rewrites its session store on invocations that only read.
- **Runs the login as the daemon's uid**, read off the audit log, which the
  installer creates owned by the daemon. No audit log, no login: guessing the
  uid is the one mistake here that produces a working-looking install.
- **Sets `PROTON_PASS_KEY_PROVIDER`** from `key_provider`, for the reason at the
  top of this section — without it the vendor looks in a keyring the daemon's
  uid does not have, and reinitialises the session store instead.
- **Puts the token in the child's environment**, never in `--pat`. `ps` is
  world-readable, and an argument is in it for as long as the process lives.
- **Records the token in `proton.json` only after the account has accepted it.**
  That file is what re-establishes the session when the vendor drops one, which
  it does without warning. A token written before the login would be a
  credential `check` reports as sound — its `token` row judges shape — sitting
  in a `0600` file and unlocking nothing.

**Run it twice and nothing breaks.** `pass-cli` refuses to replace a session it
already holds (`Client is already authenticated`), so the second run touches
neither the session nor `proton.json` and says so. To ROTATE the token, add
`--replace`, which logs the old session out first — deliberately a flag, because
a logout followed by a token the account refuses leaves the directory with no
identity at all.

`keylessd credential --store proton --name <entry>` still writes that file on
its own, without touching the session. That is the verb for a `key_provider` of
`env`, whose local key is a second credential the login reads back rather than
prompting for twice.

### What `check` can and cannot tell you

Five states, and telling them apart is the whole point:

| Row | State |
|---|---|
| `identity PROBLEM … does not exist` | no token has been written |
| `identity PROBLEM … is mode …` / `… owned by uid …` | the file is there and shut to the wrong people |
| `token PROBLEM … is not an agent token` | what is in it is not shaped like `pst_<token>::<key>` |
| `token PROBLEM … EXPIRED on …` / `… expires on …, in N day(s)` | the date you wrote down |
| `store proton PROBLEM … refused this daemon's agent token` | the vendor will not accept it |

The last two are why `token_expires` is a config field. **The vendor's refusal
is one sentence for three different causes** — *"This personal access token is
invalid, expired or has been deleted"* — so nothing can ask it whether a token
is about to expire, and by the time it answers at all, every Proton name has
already stopped resolving. A date written down is the only thing that can turn
that into a scheduled task.

With no date declared, that row reads `unproven` and says so. A check nobody
could make must not read as one that passed.

### Removing it

`install/uninstall.sh` deletes `proton.json` **and** the session directory,
together. A key left beside a deleted store is useless, and a store left beside
a deleted key is a directory `pass-cli` will force a logout over the next time
anything points at it.

**Revoke the token at the vendor as well.** It is the one most likely to be
forgotten, because it is the only one that would have died on its own: an
unrevoked agent token is a working credential with a date on it rather than a
permanent one. That is a smaller window, not a closed one.

---

## Re-pinning after an upgrade

The allowlist holds the **code hash** of the `keyless` binary. Rebuilding it
changes that hash, so an upgrade that replaces the binary without updating the
config produces a daemon that refuses its own client.

Re-running the installer is the ordinary way to upgrade, and it is safe to run
as many times as you like. It never writes over `secrets.json`, `audit.jsonl` or any
of the vendor credential files — an existing file keeps its contents and has
only its mode and owner re-asserted, and the Proton session directory is left
with its contents intact and only its mode and owner re-asserted too — and it
never rewrites `keylessd.json`, because the template it renders has no vendor
blocks and no `secrets` block and would delete yours. What it does instead is print the new hash and stop, leaving one thing
for you:

```console
$ sudo ./install/install.sh --commit
# it prints: ACTION REQUIRED ... <hash>
# put that hash in peer.allow_images, then:
$ sudo launchctl kickstart -k system/sh.keyless.keylessd
```

By hand, if you would rather not run the script at all:

```console
$ sudo cp target/release/keyless /usr/local/bin/keyless
$ keylessd pin --path /usr/local/bin/keyless
# put the new hash in peer.allow_images, then:
$ sudo launchctl kickstart -k system/sh.keyless.keylessd
```

`keylessd pin` refuses to pin an interpreter, and so does the daemon at request
time. Pinning `node` or `python3` would authorise every program that
interpreter will ever run — see the README's section on why that costs you
nothing.

---

## Linux

Not shipped, because it is not tested. What changes, so nobody has to work it
out twice:

**The attestation does not port.** `csops(CS_OPS_CDHASH)`, the audit token and
`proc_pidinfo` are XNU. The Linux equivalents are:

| macOS | Linux |
|---|---|
| `getpeereid` / `LOCAL_PEERCRED` | `SO_PEERCRED` (`struct ucred`) |
| `LOCAL_PEERTOKEN` pid generation | no equivalent — use `pidfd_open(2)`, which *is* the race-free handle |
| `csops(CS_OPS_CDHASH)` on the live image | no code signature at all; hash `/proc/<pid>/exe` **opened via the pidfd**, never re-opened by path |
| `proc_pidinfo` uniq identifier | the pidfd, or `/proc/<pid>/stat` field 22 (start time) |

`pidfd_open` is strictly better than what macOS offers: it is a handle to a
*process*, so pid reuse is not merely detectable, it is impossible. Open the
pidfd first, then read everything through it.

**The trap to avoid is the one this design was measured against.**
`readlink("/proc/<pid>/exe")` and then opening the resulting path is the
vulnerable pattern — that is a path, and paths can be replaced. Open
`/proc/<pid>/exe` **directly** as a file descriptor and hash the descriptor. On
Linux it is the race-free primitive and it is easier than the racy one.

**systemd** replaces launchd, and `DynamicUser=yes` replaces creating a user by
hand:

```ini
[Service]
DynamicUser=yes
ExecStart=/usr/local/bin/keylessd run --config /etc/keyless/keylessd.json
LoadCredential=store:/etc/keyless/secrets.json
RuntimeDirectory=keyless
RuntimeDirectoryMode=0750
StateDirectory=keyless
LimitCORE=0
ProtectSystem=strict
PrivateTmp=yes
NoNewPrivileges=yes
```

`LoadCredential=` is the better half of the deal: systemd reads the file as
root and hands the daemon a descriptor under `$CREDENTIALS_DIRECTORY`, so the
store never has to be readable by the daemon's own (dynamic, unstable) uid at
all. `RuntimeDirectoryMode=0750` plus a `SupplementaryGroups=` entry replaces
the group dance in `install.sh`.

`LimitCORE=0` matters as much there as the `HardResourceLimits` block does in
the plist: a core dump of this process contains every cached plaintext, on
disk, outside every guarantee the rest of the design makes.
