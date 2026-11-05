# Finding what to put in the config

`keyless ls` lists what you have already declared. It reads the config file and
nothing else, which leaves an obvious hole: **to declare a name you have to know
what the store calls the item and the field, and finding that out used to mean
printing the value.** The only `pass-cli` verb that reveals a field name prints
the values with it, so setting the tool up required doing the exact thing the
tool exists to prevent.

Two verbs close that.

```console
$ keyless items --store proton --vault personal
personal	Trashed	login	keyless-decoy-alpha
personal	Active	custom	demo api key

$ keyless fields --store proton --vault personal --item "demo api key"
API Key	    custom	Hidden	    item.content.extra_fields[0]
Secret	    custom	Hidden	    item.content.extra_fields[1]
Expiry Date	custom	Timestamp	item.content.extra_fields[2]
Permissions	custom	Text	    item.content.extra_fields[3]
note	    builtin	-	        item.content
title	    builtin	-	        item.content
```

Tab-separated columns, like `ls`, because this output is read by agents at least
as often as by people. `items` gives vault, state, type, title. `fields` gives
name, kind, type, path — and the `name` column is what goes in a config entry's
`field`:

```json
"DEMO_KEY": { "store": "proton", "vault": "personal",
              "item": "demo api key", "field": "API Key" }
```

**Neither prints a value. Neither prints a value's length either** — a length is
information about a secret, and `doctor --probe` has always refused to print one.

## A trashed item is shown, and `fields` on one is refused

Both halves are deliberate. Hiding a trashed item leaves you hunting for
something that is in the bin; listing it *unmarked* is worse, because you would
then write a config entry against a title that can never resolve — the resolver
refuses a trashed item on purpose. So `items` reports the state verbatim and
`fields` says why it will not go further:

```console
$ keyless fields --store proton --vault personal --item keyless-decoy-alpha
keyless: store `proton` failed: the only item titled `keyless-decoy-alpha` in
vault `personal` is in the trash, so no config entry can resolve against it;
restore it first
```

## How the Proton path keeps the value out of the output

`pass-cli item view` is the only verb that reveals an item's field names, and it
prints the values too. There is no vendor flag that stops it. So the plaintext
enters the process whether anyone wants it or not, and everything between arrival
and the first byte of output is the mechanism:

- the bytes land in a capture buffer that zeroizes on drop;
- they are parsed into a guard type with no `Display`, no `Serialize`, a `Debug`
  that prints `ItemView(<redacted>)`, and a `Drop` that zeroizes **every string
  in the JSON tree** — which covers the early-return and panic paths as well;
- exactly two rules produce output, and there is no third. An array element
  carrying a label key beside a value key contributes its **label**; anything
  else contributes a **key**. Nothing recurses into a value container, so
  `content` and `value` are read as structure and never as data;
- the type column (`Hidden`, `Timestamp`) is the *key* of the object wrapping the
  value, so reporting it never goes near the value;
- every error message on the path is built from stderr only, as everywhere else
  in this tool, because stdout is where the value is.

Requiring a field descriptor to be an **array element** is load-bearing rather
than tidy. The vendor's own top-level `item` object carries a `content` key, so an
`item` that ever gained a `name` would be read as one field descriptor and every
real field would silently vanish from the listing. A shape that puts a descriptor
outside an array falls back to emitting keys — a worse listing, never a leak.

Measured against `pass-cli` 2.2.5, and **the two shapes are not the same**:

| Source | label | value |
|---|---|---|
| `item view --output json` | `item.content.extra_fields[N].name` | `…[N].content` |
| `item create custom --get-template` | `sections[].fields[].field_name` | `…value` |

The template's shape is the only one of the two you can read without printing a
credential, so it is the tempting thing to build against — and it is wrong for a
real item. Both are handled.

## Infisical lists keys through the same verb it reads them through

Infisical's CLI has no listing verb: `infisical secrets`, `infisical secrets get`
and `infisical export` all print the values, and `--silent` does not suppress
them. So the listing is not taken from its output at all. `infisical run` puts
the secrets at a coordinate into a child process's environment — and `keyless`
is that child:

```console
$ keyless items infisical --env staging:/demo
staging:/demo	Active	secret	DEMO_API_KEY
staging:/demo	Active	secret	DEMO_DATABASE_URL
…

$ keyless items infisical          # every coordinate your config declares
prod:/demo	Active	secret	DEMO_API_KEY
staging:/demo	Active	secret	DEMO_DATABASE_URL
…
```

The child reads its own environment and writes back the NAMES. **A value cannot
be smuggled out as a name**, and that is a property of the environment rather
than of a filter: the environment is an array of NUL-terminated C strings split
at the FIRST `=`, so a value containing a newline, a tab, a further `=`, a JSON
brace or an ANSI escape is still one entry with one split point. This is exactly
what a text filter cannot promise — strip the values off a vendor's output and a
value containing a newline produces a following line with no `=` in it, which the
filter passes straight through as though it were a key.

Three things that follow, none of them hidden:

- **There is no default environment, here either.** With `--env` / `--vault` you
  list the coordinate you named. Without one you get the coordinates your config
  already declares, and no others — the catalogue is an allowlist, so
  enumerating a coordinate nobody wrote down is something you do on purpose.
- **A secret whose NAME is `HOME`, `PATH`, `TMPDIR`, `INFISICAL_*`, an
  `SSL_CERT_*` or a proxy variable is not listed.** Those are forwarded into the
  cleared environment the vendor runs in, because it needs them to authenticate
  and to reach the network, and nothing afterwards says whether the store
  overwrote one. `keyless doctor --probe` is the exact check for a single name.
- **`keyless fields` has no answer for Infisical, and says so.** A secret there
  is one value, so a config entry needs a `key` and never a `field`.

The REST API would return JSON, where a typed `secretKey` could not carry a
fragment of a value — but reaching it needs a credential to be held and spoken,
and `keyless` never holds one. It spawns the vendor's CLI, which either has its
own login or is handed a machine identity it reads out of its environment;
neither is a value this tool parses or stores, it opens nothing in the vendor's
state directory, it has no config field a token fits in, and it carries no HTTP
client.

## 1Password lists the one vault it is pinned to

`op item list` prints ids, titles and categories and no field content, so the
listing is read directly — confined to the pinned vault, with archived items
shown and marked:

```console
$ keyless items onepassword
company	Active	password	DB_PASSWORD
company	Active	api_credential	demo api key
company	ARCHIVED	login	Router

$ keyless fields onepassword --item "demo api key"
username	builtin	STRING	fields[0]
credential	custom	CONCEALED	fields[1]
notesPlain	builtin	STRING	fields[2]
api key	custom	CONCEALED	fields[3] in section "other"
```

`fields` runs `op item get <id> --vault <vault> --format json`, whose output
carries every field's **value** beside its label — the same situation as the
Proton path, handled the same way: the JSON is parsed into a guard type that
prints `ItemView(<redacted>)`, zeroizes every string in the tree on drop, and
has one accessor that reads labels, types and section labels and never a value.
The `path` column names the section, because a field in one is declared with
`"section"`.

## Two backends say why they cannot do this

A verb that works in one backend and leaks in another is worse than one that is
plainly absent in the second, because you learn to trust it from the backend
where it is safe. So:

| Backend | `items` | `fields` | Why |
|---|---|---|---|
| `proton` | yes | yes | `item list` and `item view`, with the extraction above |
| `onepassword` | the pinned vault only | yes | `item list` prints no content; `item get` does, and is scrubbed as above. Another vault is refused, not listed |
| `infisical` | yes | no | the environment `infisical run` builds is the listing; a secret is one value, so there is no field to name |
| `keychain` | no | no | `security` has no verb listing one service's items without dumping the whole keychain file, and one extra flag on that dump prints values |
| `daemon` | no | no | a client that could enumerate the store could read what it never named — the hole the uid boundary closes |

---
