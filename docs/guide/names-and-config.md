# Names, the config, and what `ls` is telling you

[The first five minutes](first-five-minutes.md#the-first-five-minutes) walks the shortest path
through these. This section is the rest of the answer.

Three ways a value gets into a store, and the third leaves no plaintext
anywhere outside it:

```console
$ security add-generic-password -s keyless -a DATABASE_URL -w   # type it
$ printf '%s' "$from_the_provider" | keyless put DATABASE_URL   # pipe it
$ keyless new DATABASE_URL          # generate it; see Storing a secret below
```

All three work **with no config file at all**: an undeclared name is looked up
as its own account under the default keychain service. What a config buys is
enumerability — a name `keyless` has been told about is one `ls` can list and
`doctor --probe` can check, and an undeclared name is invisible to both even
though `run` resolves it perfectly well. Declaring is also what lets one name
point somewhere other than the default:

```json
{
  "stores": { "keychain": { "service": "keyless" } },
  "secrets": {
    "DATABASE_URL": { "note": "staging read replica" },
    "GITHUB_TOKEN": { "account": "demo-token", "service": "demo" }
  }
}
```

`doctor --probe` asks each declared name whether it resolves, marking it `proven`
or `absent` — never a value, and never a length, because a length is still
information about a secret. It READS each credential to do so, which is why it is
not the default: against Proton that is one vendor call and one permanent
off-machine audit entry per name. It may also trigger a keychain access prompt,
which a plain `doctor` does not.

A plain `doctor` still checks every **store**, and that costs no credential at
all. A store is `proven` when a read path answered — for the keychain, a search
that reached the item database; for Infisical, a fetch of a non-credential key;
for Proton, a vault listing as this session.

`proven` is deliberately not `ok`. It is a verdict on a measurement, not on the
credential: an expired token, an account-wide one and somebody else's all resolve
identically. Every report therefore carries the boundary, probed or not:

```console
SCOPE
  ~ scope   unproven   not checked, and never will be
      a name that resolves proves a store answered. It proves nothing about
      what the credential may DO or WHOSE it is. An `ls` note claiming a scope
      is prose; ask the provider to enumerate its own grant, and read that.
```

See [Why there is no capability check](threat-model.md#why-there-is-no-capability-check).

`ls` prints four tab-separated fields — name, store, location, note — with `-`
wherever there is nothing to say, so a parser never has to count them. The
**location** column answers "which tenant does this name point at?", and only
Infisical has an answer worth printing there: its environment decides *which
real value* comes back.

```console
$ keyless ls
#NAME       	STORE   	LOCATION        	NOTE (yours, unchecked)
DATABASE_URL	infisical	staging:/backend	staging read replica
STRIPE_KEY  	infisical	no-env:/backend 	-
GITHUB_TOKEN	keychain 	-               	-
```

The header is written **only when stdout is a terminal**. A pipe gets exactly
the four fields it always got, so no parser gains a fifth record. It exists
because three of those columns are `keyless`'s own work and the fourth is a
sentence somebody typed once — and they render identically.

`no-env` is the set of names that will degrade until you give them an
environment. A keychain account is not printed: it picks an item, not a tenant,
and a lookup detail in a listing is noise.

**Nothing in the config file is ever a secret value.** It holds names,
references, store kinds, paths and timeouts. There is no field a value fits in,
which is why it needs no special permissions and can be committed.

Unknown fields are ignored rather than rejected, so a config written for a newer
build with more backends degrades to "I cannot serve those names" instead of
refusing to parse and therefore serving none.

---
