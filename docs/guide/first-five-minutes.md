# The first five minutes

Nothing assumed, ending in one working `keyless run`. Keychain only, because it
is the one store that needs no account you do not already have.

**1. Install, and prove it is on your `PATH`.**

```console
$ cargo install --path .
$ keyless setup
```

`setup` prints the resolved path of the binary that is running, which is how you
find out now — rather than three commands later — whether `~/.cargo/bin` is on
your `PATH`. It also writes the config that step 5 is about, so if you have run
it already, that step is a re-read rather than a write.

**2. Store something. Not a real credential yet — a throwaway.**

`put` reads the value from stdin and nothing else. It echoes nothing back.

```console
$ printf '%s' 'throwaway-value' | keyless put FIRST_SECRET
keyless: `FIRST_SECRET` is not declared in your config, so `keyless ls` will not
list it and `keyless doctor --probe` will not check it. The value is stored either way.
stored	FIRST_SECRET	keychain keyless/FIRST_SECRET	keychain (this user, no separate manager exists)
```

The warning is the first line and `stored` is the result. Both are true: the
write landed, and until step 5 gives the name a config entry, the two verbs you
would reach for to confirm it will say nothing about it.

**3. Use it.**

```console
$ keyless run -s FIRST_SECRET -- sh -c 'echo "${#FIRST_SECRET} characters arrived"'
15 characters arrived
```

That is the whole product. The value reached the child, your shell history
holds the name and not the value, and nothing printed it.

**4. Now try to check your work the way you check everything else.**

```console
$ keyless get FIRST_SECRET
keyless: there is no `get`, and there will not be one.
```

**This is the part worth pausing on.** Every other tool you have used answers
that question, and the absence of an answer here is the product rather than a
gap in it. There is no flag, no debug mode and no newer build in which `get`
appears.

There *is* a way to ask whether a name resolves. It just never answers with a
value — and it only knows about names you have **declared**, which is what the
config file is for.

**5. Write the config file. `setup` did the store half for you.**

Everything above worked without one, because an undeclared name is looked up as
its own account in the default store. What a config buys is that `keyless` now
knows the name exists — so it can list it, and check it.

```console
$ keyless setup
```

It detects which backends are installed, proves the ones it can prove, writes
`~/.config/keyless/config.json` with the provable one as the default, and says
what each of the others is waiting for. It never asks for a credential and there
is no field in what it writes that one would fit in. (`keyless init` is the same
store detection on its own, for anybody who wants the config and none of the
rest.)

It writes **stores**, not **secrets** — deliberately. Which vault, which item,
which field, which environment are facts about your account, and a setup command
that guessed one would point a name at the wrong tenant. `items` and `fields`
discover those without ever reading a value; see [Discovery](finding-names.md).

Running it twice is safe: an existing config is reported, never replaced, unless
you pass `--force`.

The same run registered the **guards** — the hook pack in `hooks/`, which is what
refuses a command that would print a credential into a transcript. The write
belongs to `hooks/install.py`: it backs the settings file up first, merges rather
than overwrites, re-parses the result before replacing the original, and records
what it added so an uninstall can remove exactly that and nothing you wrote
yourself.

**A machine with no agent harness gets everything else and is told what was
skipped.** `keyless` is a general tool; `~/.claude` is another program's
directory, and setup does not create one for a machine that has no agent. Pass
`--claude-dir DIR` if yours lives somewhere else.

If the binary was copied to a machine without the checkout, the row says so and
names `KEYLESS_PACK_DIR`, which points at the directory holding `hooks/` and
`install/`.

**If the guards are ever in your way, there is a switch and you should use it
rather than working around them.** `disable` turns off protection for every
command that runs afterwards, so it asks you to confirm at a terminal —
type the word `disable` back — before anything changes. There is no flag to
skip that question: a flag is exactly what an unattended caller would add.

```console
$ keyless disable
keyless disable turns every guard off, for every command that runs
afterwards, until keyless enable turns them back on. Type disable to
continue: disable
no check fires. Your config, your secrets and the registration are all
untouched
$ keyless enable       back on, no confirmation needed
```

`keyless doctor` says `SWITCHED OFF` for as long as they are off, and names
when it was switched off. A disabled install that reported healthy would be
the worst false green in the tool.

Add the name by hand, so `~/.config/keyless/config.json` reads:

```json
{
  "stores": { "keychain": { "enabled": true }, "default": "keychain" },
  "secrets": { "FIRST_SECRET": { "note": "throwaway, delete me" } }
}
```

```console
$ keyless ls
FIRST_SECRET	*	-	throwaway, delete me

$ keyless doctor --probe
keyless 0.1.0   /Users/you/.config/keyless/config.json   1 name(s) declared

STORES
  ✔ keychain   proven     service "keyless"
  – infisical    off        "enabled": false under `stores.infisical`
  – onepassword  off        "enabled": false under `stores.onepassword`
  – proton       off        "enabled": false under `stores.proton`
  – daemon       off        not enabled in this config

NAMES
  ✔ FIRST_SECRET  proven     read back from keychain

AUDIT
  ~ audit   unproven   /Users/you/.local/state/keyless/audit.jsonl
      no rows yet, so there is no chain to check

SCOPE
  ~ scope   unproven   not checked, and never will be
      a name that resolves proves a store answered. It proves nothing about
      what the credential may DO or WHOSE it is. An `ls` note claiming a scope
      is prose; ask the provider to enumerate its own grant, and read that.

0 problem(s). A problem here degrades a run; it never blocks one.
```

`proven` means a value came back through the whole path. It never means the
value was shown, and never its length — a length is still information about a
secret.

**There is exactly one green here and it means one thing.** A `proven` store had
a read path answer; a `proven` name was actually read back. Everything short of
that gets its own mark and its own word — `absent` for a step nobody has taken,
`config` for a coordinate only you can supply, `broken` for a store that was
reached and said no, `off` for one you switched off, `blocked` for a name whose
store failed above it. Colour is a third signal on top of the glyph and the word,
so `NO_COLOR`, a pipe and a monochrome terminal lose nothing.

**6. Read what a wrong name does, and what a broken store does.**

Ask for a name that does not exist, with a command that would otherwise
succeed:

```console
$ keyless run -s NO_SUCH_NAME -- sh -c 'echo "got [${NO_SUCH_NAME}]"'
keyless: REFUSED — 1 of 1 names refused; the command was not run
keyless:   `NO_SUCH_NAME`: not declared in your config, so nothing says where its value lives; no store had one under the name itself. Declare it under "secrets", or write it there with `keyless put`
$ echo $?
64
```

**Exit 64, and your command never ran.** The store answered that it holds no
such name, so running the command without it would only move the mistake into
your program's own error — a `401`, an empty query, a login page — where it is
harder to read. A refusal names the mistake at the name.

A store that *cannot answer* is the opposite case, and that is
[Rule 1](reference.md#rule-1-it-never-blocks-your-command-on-a-failure): a locked
keychain, an unreachable vault or a dead daemon prints `DEGRADED`, and your
command runs anyway with the variable unset, because blocking your work over an
outage gets the tool uninstalled and then the plaintext comes back.

**So read stderr on your first run of anything.** `REFUSED` and `DEGRADED` are
the only places either case is ever named. Every line after them belongs to
your command.

**That message is two facts, and the second one is the fix.** A name your config
declares says the shorter thing — `not found in any store` — because its
coordinate was asked and came back empty, and the store is where to look. A name
nothing declares has no coordinate to ask, so the only thing that could be looked
for is the name itself. Being in a vault and being resolvable are different
states, and the line above is careful to claim only the one it can prove: it never
says a store holds your credential, because nothing asked any store where it
lives.

**7. Clean up the throwaway**, so it is not mistaken later for something real:

```console
$ security delete-generic-password -s keyless -a FIRST_SECRET
```

You are now in a position to store a real credential the same way, and to read
the rest of this file when a question comes up rather than before.

---
