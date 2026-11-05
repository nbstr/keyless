# keyless

keyless hands a command the credentials it names, read from a vault through one daemon, so no value passes through the caller's transcript.

## Names and stores

**Store**:
A vault backend the daemon reads values from: Proton Pass, the keychain, a file.
_Avoid_: backend, provider, vault (when the backend is meant)

**Name**:
What a caller asks for, and the environment variable's source: `NEXUS_LINEAR`, `NEXUS_LINEAR__API_TOKEN`, or an item title.
_Avoid_: key, secret id

**Minted name**:
A name the catalogue derives from an item title and a field, rather than one declared in the daemon's config.
_Avoid_: generated name, auto name

**Catalogue**:
The daemon's index from minted names to the item and field each one reads.
_Avoid_: cache, registry

## How a store answers

**Verdict**:
A store's answer to a lookup: the value, or that it holds no such name.
_Avoid_: response, result

**Unknown name**:
A name whose store answered that it holds no such item or field, after the catalogue was rebuilt.
_Avoid_: missing secret, guessed name

**Silence**:
A store giving no verdict within its timeout. Silence says nothing about whether the name exists.
_Avoid_: outage, timeout (as a noun for the state), unreachable

## Serving a value

**Freshness window**:
How long a value read from a store is served from memory without asking the store again.

**Stale window**:
The span after the freshness window in which the older value is still served while a refresh runs, whether or not the store is healthy.
_Avoid_: grace period

**Silent window**:
The span in which the last value read is served because the store fell into silence. It never covers a name the store disowned.
_Avoid_: stale window (for this case), offline cache

## Outcomes of a run

**Injected run**:
A `keyless run` whose child started with every value it named.

**Refused run**:
A `keyless run` that exits without starting its child, because a name is unknown or empty, or the caller failed attestation.
_Avoid_: failed run, blocked run

**Degraded run**:
A `keyless run` whose child started without a value, because its store was in silence and the silent window held nothing for that name.
_Avoid_: partial run, soft failure

**Canary**:
A scheduled `keyless run` of a junk item, whose only purpose is to show the path from caller to store works end to end.
_Avoid_: probe (that is a deliberate miss someone types), health check
