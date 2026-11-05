# 1Password — one vault, named once

`op` reads whatever the login behind it can see. This store reads **one
vault**, written down in the config, and nothing under `secrets` can widen it:

```json
"onepassword": { "enabled": true, "vault": "company", "field": "password",
                 "account": "demo" }
```

- **`vault` is required and never defaulted.** Every lookup this store makes is
  `op://company/…`; a name whose own entry says `"vault": "personal"` is
  refused before anything is spawned, and `keyless items onepassword --vault
  personal` is refused rather than listed. Defaulting it — to the account's
  first vault, or to whichever one holds the title — would make the vault a
  name resolves against invisible at the point of use, which is the
  [Infisical environment hazard](store-infisical.md#an-environment-is-required-and-has-no-default)
  in different clothes.
- **`field` is the field a name reads when its entry names none.** `keyless`
  never guesses one: a Login item's credential is `password`, an API
  Credential's is `credential`, and a wrong field resolves to a value that
  looks real and is not. Set it when every item in the vault has the same
  shape, leave it out otherwise and put `field` on each name.
- **`account` is `--account`**, and it is not optional where more than one
  account is configured. Measured against `op` 2.39.0: with several configured
  and none signed in, every authenticated verb fails with `multiple accounts
  found`.

A name is an item in that vault, by title — or by id, which is the escape hatch
when two items share a title:

```json
"STRIPE_KEY":  { "store": "onepassword", "item": "demo api key", "field": "credential" },
"DB_PASSWORD": { "store": "onepassword" },
"WIFI_PSK":    { "store": "onepassword", "item": "Router", "section": "other",
                 "field": "api key" }
```

The second declares nothing, so it is the item titled `DB_PASSWORD` at the
store-wide field. A custom field somebody added to an item lives in a section,
and the third names it: `"section"` is its own key rather than a `/` inside
`field`, so a label that happens to contain one cannot silently become a
different address.

The keychain is on by default, so with this store enabled a name that pins
nothing has two candidates and is reported [ambiguous](stores.md#one-name-several-stores)
rather than guessed. Set `"default": "onepassword"` under `stores`, or switch
the keychain off, or put `"store": "onepassword"` on each name.

## The verb, and the listing in front of it

The lookup is the same shape as the other two vault backends — `op run
--no-masking -- printenv KEYLESS_PROBE`, with the `op://` reference in that one
variable of a **cleared** environment and never in argv. `op read` and `op item
get` print plaintext, and the hook pack refuses them; this adapter never spells
them.

Before the `run`, a listing: `op item list --vault <vault> --format json
--include-archive`, memoised for one run and for
`stores.onepassword.listing_ttl_ms` afterwards. It is what turns a title into
the id the reference is built from, and it is where three rules live:

- **An absent title is an absence.** `doctor` says the item is not in the
  vault; a name nobody declared costs a listing, never a read.
- **An archived item never resolves.** The vendor still resolves a reference
  to one (documented), so the listing is the only thing between a put-away
  credential and a child's environment. The rule is an allowlist on "no
  `state` at all", so a state this build has never heard of fails closed.
  `items` still shows the item, with `ARCHIVED` beside it.
- **Two live items with one title are refused**, and the message names both
  ids.

## An allowlist locally, a boundary behind the daemon

Say this plainly: on the machine you type at, the vault pin is an allowlist.
A session that can run `keyless` can run `op read` against every vault its
login sees, and the pin stops `keyless` from doing that, not the session.

The boundary is the identity. A 1Password **service account** is minted with
access to named vaults and no others, and the vendor refuses it everything
else:

```console
$ op service-account create keyless-agents --vault company:read_items
```

That prints a token once. In a shell it is a credential in an environment
variable, which is the shape this tool exists to remove — so the place for it
is behind [`keylessd`](keylessd.md#keylessd--the-uid-boundary), in a mode-`0600` file only
the daemon's uid can read, read per lookup and written to nothing. The daemon
carries this adapter with the same `vault` rule; the recipe is in
[`install/README.md`](../../install/README.md#serving-names-out-of-one-1password-vault).

And say the other half just as plainly: **behind the daemon, with a store-wide
`field` set, the pinned vault is the allowlist.** An item needs three
coordinates — vault, title, field — the vault is the store's and the title
defaults to the name being asked for, so a store-wide `field` supplies the last
one, and a name in no `secrets` entry resolves anyway. Any client the policy
attests can then ask for anything the vault holds by guessing an item's title,
because `secrets` is routing rather than a gate. Keep in that vault only what
every attested client may read. To serve declared names and nothing else, leave
`stores.onepassword.field` out and give each name its own `"field"`: an
undeclared name then has no field, and a field is the one coordinate this tool
will not guess. `keylessd` says so at startup rather than leaving it here.

## What was measured, and what was not

No account was signed in when this adapter was measured, so the
**authenticated** path — a value coming back, the listing's JSON, an archived
item's `state` — is the vendor's documentation and the stub in `tests/support`
encodes it. What the real `op` 2.39.0 did without a sign-in:

| Measured | Consequence |
|---|---|
| `op run` with **no** reference in its environment runs the child without authenticating | the health check lists the vault's items, never `run` |
| more than one account configured, no sign-in: `multiple accounts found. Use the --account flag …`, exit 1 | `account` is a config field |
| a bogus `OP_SERVICE_ACCOUNT_TOKEN`: `DecodeSACredentials`, exit 9 (`vault get`) / exit 1 (`run`) | read as a refused login, never as a missing name |
| `op` finds its accounts under `env -i` with only `HOME` and `PATH` | the probe runs in a cleared environment |
| the masking placeholder is `<concealed by 1Password>` | `--no-masking` on every probe; a concealed value is refused |
| errors are `[ERROR] <date> <time> <message>` | the prefix is stripped before a message is quoted |

A green `doctor` row for this store says the login can **list** the pinned
vault — the round trip every lookup starts with, and the one the vendor's
`--vault <name>:read_items` grant actually covers. It does not say `op run` has
ever resolved a reference on this machine, so no value has been read and no
name is known to work; `doctor --probe` is what establishes that, and the row
says so itself rather than leaving `proven` to carry both claims.
