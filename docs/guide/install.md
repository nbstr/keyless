# Install

```console
git clone https://github.com/nbstr/keyless
cd keyless
cargo install --path .
keyless setup
```

**Two commands, and the second one is not optional.** `cargo install` places two
binaries and nothing else — that is all a package manager can do, and for a while
it was all this project did, so a fresh clone got the broker with none of its
guards and nothing said so. `keyless setup` is the rest: it detects your stores
and writes a config, registers the hook pack that refuses commands which would
print a credential, installs the agent instructions, and reports the daemon. It
names every file before it touches it, merges rather than replaces, and running
it twice is safe and says so.

Nothing here is one-way:

```console
keyless disable      asks you to confirm at a terminal, then no check fires. Nothing is deleted
keyless enable       back on
keyless uninstall    asks the same way, then removes what setup created and keeps what you wrote
```

**The repository is private, and the clone is the step that tells you so
badly.** Without access, git answers `remote: Repository not found` — which
reads as a typo in the URL, not as a permission you have to be given. There is
no way to tell those apart from the message, so: if you see it, you need to be
added to the repository. Nothing later in this file is reachable until you are.

With access, the SSH remote avoids a browser round trip:

```console
git clone git@github.com:nbstr/keyless
```

Requires Rust 1.89 or later — [rustup.rs](https://rustup.rs) if you have no
toolchain. `cargo install` writes to `~/.cargo/bin`, which has to be on your
`PATH`; the `--version` line is there so you find that out now rather than
three commands later.

The store trait is portable and the rest of the tool has no platform-specific
behaviour beyond POSIX process handling. The daemon's caller attestation is the
exception — it is XNU-specific, and [`install/README.md`](../../install/README.md)
records what replaces each piece on Linux.

That builds two binaries — `keyless`, the client, and `keylessd`, the daemon —
and puts both on your `PATH`. Installing them is not standing the daemon up:
until you do, nothing is listening, and `keyless` reads your keychain directly
as you. `keyless setup --daemon` stands it up under `sudo`, and
[`install/README.md`](../../install/README.md) is the script it runs — dry-run until
you pass `--commit`, and worth reading first.

**Setup cannot finish the daemon for you, and it is honest about that.** The
boundary only exists once your secrets MOVE behind it and are deleted from your
login keychain, and no installer can know which of your keychain items are meant
to stay reachable by hand.

## Who this is for

Somebody who runs commands in a terminal. That is not a style note — `run` is
the whole product, and it wraps a command you were going to type anyway. Wrap
nothing and there is nothing to gain: this tool never stores a password for a
website, and there is no window to open.

There is also no release binary. Installing means a Rust toolchain and a
compile from source, and every store beyond the keychain means a CLI you log
into yourself. Both are fine for somebody whose day already contains a
terminal, and both are a wall for somebody whose day does not.

## What is yours alone, and cannot be handed to you

The keychain path below needs nothing but a Mac. **Every other store needs an
account that is yours**, and no amount of configuration shortcuts it:

| | What you have to do yourself |
|---|---|
| **macOS keychain** | Nothing. It is on by default and needs no config file. |
| **Infisical** | Log in as you. The CLI resolves its project from the **working directory**, so the same command answers in one directory and fails in another with nothing in the output saying that location was the difference. |
| **1Password** | Sign in as you, and name the **one vault** this machine may read. With more than one account configured and none signed in, every call fails with `multiple accounts found` until the config names one. |
| **Proton Pass** | Log in as you. The agent token is minted per account and its session directory does **not** copy between machines or between people. |

So a config file can be shared and a *setup* cannot. Somebody else's working
`config.json` is a map, never a key: the names and routes in it are portable,
and the identity that opens them is not.

Nothing in that table is a limitation of this tool — a broker that let one
person's vault session travel to another person would be the bug.

---
