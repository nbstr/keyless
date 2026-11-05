# `keyless run` refuses a name its store does not hold; it degrades only on silence

`keyless run` used to start its child whatever happened, without the value when a lookup missed. From 2026-10-01 to 2026-11-04, 109 misses were names that never resolved at all (guesses, probes, names built from an empty substitution or a pasted config value), and each one ran a child that then failed somewhere harder to read. A run now exits non-zero without starting its child when the store answers that it holds no such name, when the name is empty, or when the caller fails attestation, and degrades only when the store is silent and the silent window holds nothing for that name.

## Considered Options

- **A name syntax rule in the client.** Rejected: every malformed name seen (`nexus-linear,⏎project,`, `---`, a name followed by a pasted token) reaches the store, which answers that it holds no such name, and that verdict already refuses the run. Names cannot be held to environment-variable syntax anyway, because callers address items by title (`nexus-linear`).

## Consequences

- The refusal is decided by the resolving store's verdict, never by the catalogue: the keychain and file stores serve names no index lists, and a catalogue gate would refuse them.
- A miss on a name that does exist triggers a synchronous catalogue rebuild and one more resolve before the verdict, so a new item, a field name and the first request after a daemon restart resolve on first use rather than being refused. A rebuild the store does not answer is silence, not a refusal.
- A refused run is recorded under a state of its own, not `DEGRADED`, so alerting that watches for degraded runs no longer sees typos, deliberate probes or attestation denials, and pages only when a child actually ran without its value.
