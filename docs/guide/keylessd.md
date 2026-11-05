# `keylessd` — the uid boundary

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

See [`install/README.md`](../../install/README.md). It needs `sudo` exactly once, to
create a user, and the installer prints its whole plan and changes nothing until
you pass `--commit`.

## Who is allowed to ask

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

## What happens when the caller is `node`

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

## What the boundary does *not* buy

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

## Many sessions at once

**Single-flight per name.** Twenty sessions starting together and all wanting
`GITHUB_TOKEN` produce **one** upstream call. Without it a store rate limit
degrades the whole fleet at the same instant, which is indistinguishable from the
daemon being down.

**The in-memory TTL cache is not an offline cache.** The forbidden thing is a
cache a *client* can decrypt without the daemon, because its key would have to
live on the client's side of the boundary — a `get` verb with extra steps. This
one never touches disk and dies with the daemon, so killing `keylessd` strictly
reduces what is obtainable.

**A recently read name is refreshed off the request path, and outlives its
freshness window only while a store cannot answer.** `cache_ttl_seconds` — 60 by
default — is how long a value is served without asking anyone. Past it the next
reader hands the name to a refresh worker, waits **one second** for it, and takes
the older value if the store is slower than that, for up to `cache_stale_seconds`
— 240 by default — beyond freshness. That second window belongs to a store's
*silence* alone: a store that answers replaces the value, and an answer that
disowns it — no such item, a refused token — evicts it on the spot. Neither
window may be configured past **15 minutes**, and `cache_ttl_seconds: 0` turns
both off. So a vendor CLI that has gone slow costs a lookup a second rather than
its whole latency, while a vendor that has revoked a credential still stops that
credential dead on the first refresh that reaches it.

**A store in silence still hands a run the last value it gave, for up to four
hours.** When a store gives no verdict within its timeout, the daemon serves the
value it last read for that name if that value is younger than
`cache_silent_seconds` — 14400 by default, never more than **24 hours**, and `0`
turns it off. The audit row says `source: "stale"` and carries the value's age.
A store that answers always wins, and a name the store disowned has already been
evicted, so it is never served from here. Past the window the run degrades as
before.

**Which of those two a failure is, the vendor's own words decide.** A failure
naming a transport fault — the connection refused, the host unresolved, the
socket reset — reached nobody, so it decides nothing about the item and the
value stands. Every other sentence is the account answering about this name, so
it evicts. The recognised set is a list of measured phrases and nothing else,
because the two mistakes are not the same size: a verdict read as transport
serves a disowned credential for the rest of the window, while transport read
as a verdict costs one eviction and a fresh lookup.

**A read is never made to wait for a session renewal.** The daemon replaces
its own Proton session by building a fresh generation directory beside the
one already serving, verifying it, and swapping a one-line pointer once it
proves itself — never by logging the old one out first. A lookup that starts
before the swap reads the generation that was current at that instant; one
that starts after reads the new one. The generation being retired keeps
answering every reader already pointed at it until they are done, then it is
logged out and removed — there is no gap for a lookup to land in.

**And there is no local fallback.** Enabling the daemon *disables* every local
backend — keychain, Infisical, 1Password and Proton Pass alike — whatever each
one's own flag says. It is enforced in `store::build`, not documented as a convention,
because a fallback would re-open the hole the moment the daemon stopped, and
anyone able to stop a process could choose that. Killing the daemon must get you
fewer secrets, never more.

## The rule still has no exception

A daemon that is absent, stale, wedged, killed mid-request, speaking another
protocol version, or answering nonsense is a `DEGRADED` like any other store
failure: one line on stderr, and **your command runs** with an unmodified
environment. There is one property test per failure mode — fifteen of them —
and each asserts the child actually ran by reading a file the child wrote, which
a process that never started cannot imitate.

A daemon that *answers* has not failed. When its store holds no such name, or
the caller fails attestation, the run is `REFUSED`: exit 64, your command never
starts, and stderr names the nearest names the daemon serves. Both audit logs
record the refusal under its own state, so an alert watching for `DEGRADED`
sees only runs whose command ran without a value.

---
