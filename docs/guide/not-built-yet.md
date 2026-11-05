# Not built yet

Deliberately out of scope, with the seams left clean:

- **More backends.** `Store` is one trait with one method. Adding Bitwarden or
  Vault means implementing it and registering it in `store::build`; `run` never
  learns which backend answered, and neither does the daemon.
- **The 1Password live path.** The adapter's authenticated half — a value
  coming back, the listing's JSON shape, an archived item's `state` — is built
  from the vendor's documentation and has not been run against a signed-in
  account. The stub encodes the documented shapes; what needs doing is one
  session against a disposable vault, recorded the way `proton_live.rs` records
  Proton, and any disagreement fixed in the stub.
- **A 1Password writer.** `op item create --vault <V> -` takes a JSON template
  on stdin, which is the shape `put` and `new` need. Until it exists, `keyless
  put` against this store refuses and names that form, so nobody reaches for
  the assignment form that puts the value in argv.
- **A write operation on the daemon, and the manager identity behind its uid.**
  This is the same gap read from the write side, and it is the one that makes the
  [reader/manager split](storing-a-secret.md#what-the-split-is-and-what-it-is-not) advisory rather
  than enforced. The protocol has `resolve`, `ping` and `names`; adding `write`
  means a new `Op`, a write capability on the daemon's registry, and a policy
  decision about which clients may ask — an attested client that may *read* a
  name should not automatically be allowed to *replace* it. Until then `new` and
  `put` refuse while the daemon is enabled rather than reaching around it.
- **Rotating a Proton value.** `item update` takes `--field name=value`, so using
  it would put the credential in argv. A vendor that accepts an update template on
  stdin — the way `item create` already does — closes this in about ten lines.
  Until then `put` against Proton creates and refuses an existing title.
- **`--materialize`** — for tools that can only read a file.
- **Linux.** The daemon's attestation is XNU-specific. What replaces each
  primitive is written down in [`install/README.md`](../../install/README.md), and the
  Linux answer is *better* — `pidfd_open` makes pid reuse impossible rather than
  merely detectable. Not shipped because it is not tested.
- **Per-name authorisation.** Today an attested client may ask for any name the
  daemon can resolve. Binding names to specific client images is a policy change,
  not an architecture change: the decision already has the verified identity in
  hand at the point where it currently only checks the allowlist.

There are no `TODO` comments in the source. Work is either done or listed here.

---
