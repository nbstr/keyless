# Serve the last value for four hours while a store is silent

The freshness and stale windows stay capped at 900 seconds, because the stale window opens on any refresh slower than a second, so widening it would extend how long a rotated value reaches a child even while the store is healthy. A separate silent window of four hours opens only after a store gives no verdict within its timeout, and never for a name the store disowned. Measured over 126 silence misses from 2026-10-01 to 2026-11-04, the name's last good value was at most 15 minutes old for 40, at most 1 hour for 68, at most 4 hours for 124, and at most 12 hours for 125, so four hours is the shortest window that removes practically all of them.

## Considered Options

- **Widen the stale window.** Rejected: it serves old values on a healthy but slow store too.
- **Retry the vendor once on silence.** Rejected: the same name resolved within 60 seconds of a silence miss twice in 126 cases, and a retry adds up to one more timeout of waiting.
- **Refresh recently used names ahead of expiry.** Rejected: a background scheduler for gains the silent window already delivers.

## Consequences

A credential revoked or rotated while its store is silent keeps reaching children for up to four hours. A store that stays silent past the window degrades runs exactly as before.
