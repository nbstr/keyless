# Proton Pass — verified against `pass-cli` 2.7.0

Same shape, same reason: `pass-cli item view --field` prints plaintext, and
`pass-cli run --env-file FILE -- CMD` prints nothing. A lookup writes a one-line
env file holding a `pass://SHARE_ID/ITEM_ID/FIELD` reference — a reference,
never a value — at mode 0600, runs the probe under it, and deletes the file.

Observed on macOS against a live account on 2026-08-08, with disposable decoy
items in a throwaway vault: the `run --env-file … --no-masking -- <COMMAND>`
spelling, the reference format, the session scoping below, and that the vendor's
masking is opt-out rather than opt-in. `pass-cli agent create` exists too — it is
not web-app-only.

Re-verified behind the daemon against `pass-cli` 2.7.0 on 2026-11-05:
`keyless doctor --probe` proves the daemon, a fresh `keyless run` injects
through it, and a title the vault does not hold comes back as a store verdict
naming what the vault does serve.

One requirement no code can check: **an agent token needs Pass Plus or higher.**
Plan for that before you set this up. A free account fails authentication, which
reaches `keyless` as a degraded run rather than as an explanation.

## `session_dir` is the scoping, and it has no default

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

## An agent session ends — `auto_login` logs it back in

Proton ends an agent session: "a lifetime of 2 hours", say the vendor's docs,
though one measured on 2026-11-11 still answered 2 h 09 after its login. The
read that finds it ended deletes `<session_dir>/.session`, and a write still in
flight can put an empty `session.json` back. From then on every Proton name
degrades with `This operation requires an authenticated client` until somebody
logs in again. The daemon renews its own session; a session does nothing
unless asked:

```json
"proton": {
  "enabled": true,
  "session_dir": "~/.keyless-pass-session",
  "session": {
    "auto_login": true,
    "token": { "service": "keyless-proton", "account": "my-agent" }
  }
}
```

With that, the lookup that finds the session ended reads the agent token out
of that login-keychain item, logs the session in again, and retries once. The
config names the item, never the token; the token goes into the environment of
that one login and nowhere else. Store it once — `security` prompts for it, so
it stays out of your shell history:

```console
$ security add-generic-password -U -s keyless-proton -a my-agent -w
```

The item needs a service of its own. Under the keychain store's `service`, or
at the coordinates of a name under `secrets`, `keyless run -s` could hand the
token to any command — so `keyless` warns on every run and leaves auto-login
off until it moves. Off by default, nothing changes for a config that does not
ask.

After a Homebrew upgrade of `pass-cli`, macOS asks once more before the new
binary reads the session's key. A lookup gives up after `timeout_ms`, before
anyone has typed a password, so the prompt comes back for every name. Answer it
once by hand, with *Always Allow*:

```console
$ PROTON_PASS_SESSION_DIR=~/.keyless-pass-session pass-cli info
```

## Address items by NAME — a share id is minted per session

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
listing is memoised — several names from one vault cost one listing — **in
memory and never on disk**. A cache on disk that the client can read is a `get`
verb with extra steps, and `keyless` does not offer one.

A memoised listing also expires, after **60 seconds** by default, set with
`listing_ttl_ms`. That is not a performance knob: the listing is where the trash
rule below lives, so a listing reused forever goes on resolving an item somebody
trashed — silently, and for as long as the process holding it stays alive. One
`keyless run` finishes long before the expiry, so it pays nothing for the bound.

Four rules for what a title resolves to. *Refused* in this table is the adapter
declining to read an item; what the run does next follows
[Rule 1](reference.md#rule-1-it-never-blocks-your-command-on-a-failure). Through
`keylessd`, a title the vault does not hold refuses the run — exit 64, the
nearest served names on stderr — and a vault that cannot be listed degrades it:

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

## The `reference` form still works, and it is the fragile one

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

## `pass-cli run` resolves every `pass://` in the environment it inherits

Measured 2026-08-08. `--env-file` is not the only place it looks — one unrelated
`UNRELATED=pass://…` exported in your shell is enough:

```console
$ PROTON_PASS_SESSION_DIR=~/.keyless-pass-session \
  UNRELATED=pass://bogus/bogus/password pass-cli run -- printenv HOME
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

## Never run `pass-cli` with a cleared environment — it destroys the login

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

Three details of the contract shape the adapter:

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
  [this tool exists to remove](why-this-exists.md#why-this-exists), and a reason is assembled
  *before* anything has resolved, so there is nothing to redact it with — and it
  is then sent to a vendor and kept. Putting argv in it would take the exact
  leak this tool exists to prevent and forward it to a third party under a field
  labelled "reason".
- **Every child is told to keep quiet.** `pass-cli` writes a row into its own
  local telemetry database on every command and, by Proton's FAQ, sends them
  unless `PROTON_PASS_DISABLE_TELEMETRY` is set; `PROTON_PASS_NO_UPDATE_CHECK`
  keeps the same child from asking a manifest endpoint whether a newer version
  exists. `keyless` sets both on every `pass-cli` it spawns — the daemon's own
  `login`, `info` and `logout` included — and on none of the command lines it
  prints for you to paste, which carry the session directory alone.
