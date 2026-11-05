# Stores

Four, and the first is the only one on by default.

| Store | `enabled` default | Reached by | Live path verified |
|---|---|---|---|
| `keychain` | **on** | `security find-generic-password -w` | yes |
| `infisical` | off | `infisical run … -- printenv KEY` | yes — CLI 0.43.114, 2026-08-06 |
| `onepassword` | off | `op run --no-masking -- printenv KEYLESS_PROBE`, in one vault | **no** — the unauthenticated half is measured against CLI 2.39.0, 2026-08-31; the rest is the vendor's documentation. See [the section](store-1password.md#1password--one-vault-named-once) |
| `proton` | off | `pass-cli run --env-file … -- printenv` | yes — CLI 2.7.0, 2026-11-05 |

The three network-backed ones are off unless asked for: a keychain-only setup
must not start paying a process spawn and a network round trip per lookup
because a newer build knows how to talk to a vault.

```json
{
  "stores": {
    "keychain": { "service": "keyless" },
    "infisical": { "enabled": true, "path": "/backend" },
    "onepassword": { "enabled": true, "vault": "company", "field": "password" },
    "proton": { "enabled": true, "session_dir": "/Users/you/.keyless-pass-session" },
    "default": "keychain"
  },
  "secrets": {
    "DATABASE_URL": { "store": "infisical", "env": "staging", "path": "/api",
                      "key": "DB_URL" },
    "GITHUB_TOKEN": { "store": "keychain", "account": "demo-token" },
    "HOME_WIFI":    { "store": "proton", "vault": "Personal", "item": "Router",
                      "field": "password" },
    "STRIPE_KEY":   { "store": "onepassword", "item": "demo api key",
                      "field": "credential" }
  }
}
```

## One name, several stores

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

## Timeouts

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

**The daemon allows itself 30 seconds instead**, and the difference is who is
waiting. A session's lookup has a person in front of it, and ten seconds is
already longer than anyone wants to watch a terminal. A daemon's lookup has a
heartbeat in front of it, so a late value still arrives — while one abandoned
at ten seconds is a degraded run that no amount of waiting recovers. Under
memory pressure a vendor process spends hundredths of a second of CPU against
ten seconds of wall time, and every call killed at that ceiling had reached the
vendor and was waiting on the machine.

---
