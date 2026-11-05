# Development

```console
scripts/install-hooks.sh    # once per clone — hooks are not tracked by git
scripts/verify.sh           # ~90s. gates the tree you are standing in
scripts/verify.sh --staged  # the same gate, over the tree the commit would
                            # create. what the pre-commit hook runs
scripts/verify-all.sh       # verify.sh, plus a hostile environment and cargo audit
scripts/mutants.sh          # ~40 min, queued. the mutation campaign
scripts/linux-gates.sh      # the three checks that need Linux
```

The two forms of `verify.sh` are pointed at different trees, and the difference
is the difference between a green gate and a green commit. Bare, it reads the
checkout — which is what somebody checking their own work in progress means by
it. With `--staged` it builds a linked worktree from the staged tree and runs
the gate in there, so what gets checked is exactly what the commit will carry: a
`git add -p` leaves the other half of the file in the checkout, where the
compiler can still see it, and a checkout that compiles is not a commit that
compiles. That copy keeps its own build cache under
`$(git rev-parse --git-common-dir)/keyless-gate`; deleting it costs one slower
run. `scripts/staged-tree.sh` holds that machinery and `scripts/lib.sh` the
reporting every gate shares — both are sourced by the scripts above, never run
on their own.

There is no CI. There was, and it was red for twelve days on two faults that had
nothing to do with the code, which is worse than none: a check nobody reads is a
check nobody reads. Every assertion it made lives in the scripts above, with
three exceptions that a Mac physically cannot perform — `keylessd` refusing on
Linux, the four-XNU-symbol surface, and the hook pack under a second interpreter.
Those are in `scripts/linux-gates.sh`, which refuses to run anywhere else rather
than skipping, because a skip and a pass look identical once the run is over.
**Nothing runs them automatically.** Run them on a Linux box when
`src/ipc/ffi.rs` changes and before a release.

The underlying commands, if you want one on its own:

```console
cargo test                              # 15 ignored (the live Proton suite)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The 15 ignored are the entire live Proton Pass suite, which needs a real
account. `scripts/verify.sh` asserts `ignored == 15`, so that stays visible
rather than quietly drifting.

Every step in those scripts asserts the SIZE of what it did, not just its exit
code, and that is the part worth keeping if you rewrite them. Exit 0 is not
evidence that anything ran: a filtered run matching zero tests exits 0, and a
suite whose harness never linked can too. Both read exactly like a pass.

The hook pack has its own suite: `python3 hooks/tests/run.py` runs every check
against fixed inputs, and `python3 hooks/tests/mutate.py` breaks each check on
purpose and requires every breakage to be caught. Both print their own counts —
this document deliberately does not restate one, because a count copied into
prose goes stale the next time a check is added.

Two guards police what this repository publishes about the person who wrote it.
`tests/publication.rs` refuses a vault, item, account or service name that is
not an allowlisted decoy, any prose that makes a claim about the machine it was
written on, and any wall-clock instant that is not an obvious fixture — across
every published file, not only the Rust sources, and a second time across every
blob any ref can reach. That second corpus is not thoroughness: a class removed
from the working tree by a later commit is still in the history a clone
receives, and reading the tree alone reports it clean.

The publication layer of the hook suite refuses a number standing next to a
word that makes it a measurement of one machine, in `hooks/` prose **and in
commit messages**. The second one fires before the message is written, which is
the only point at which it can still be edited — it is the `commit-msg` hook
`scripts/install-hooks.sh` puts in place, above; `scripts/verify.sh` refuses to
run at all when it finds that hook missing, so a clone that skipped the one
manual step hears about it on the very first gate rather than the first time
someone tries to rewrite a published message.

Who built it stays. What is inside their machine does not: the copyright, the
author and the reasoning are identity, and a count only they can reproduce is an
inventory.

No test reads a real credential, and no test reaches a real vault. All four
backends are exercised against shell stubs — `security find-generic-password` is
never invoked against a real service name, no keychain prompt is triggered,
`security add-generic-password` never touches your keychain, and none of
`infisical`, `op` or `pass-cli` is ever run against an account. Every value in
the suite is a decoy invented in `tests/support`.

The 1Password stub is the one whose shapes are **documented rather than
measured** — the listing's JSON, the `item get` JSON, an archived item's
`state` — and it says so; the two refusals it reproduces (`account is not
signed in`, and the `[ERROR] <date> <time>` prefix) are what `op` 2.39.0
actually printed. It records the argv, the environment NAMES, the reference it
was asked to resolve and the service-account token it was handed, each to its
own file, so a test reads what the vendor received rather than what the adapter
says it sent.

The Infisical stub reproduces behaviour **measured** against CLI 0.43.114: the
flags it accepts, that its stdout is byte-for-byte the child's, and the exact
stderr wording that separates an unset variable from a failure of the CLI's own.
The Proton stub encodes behaviour **measured** against `pass-cli` 2.2.5 on
2026-08-08: the `run --env-file … --no-masking --` spelling, the reference
format, that `PROTON_PASS_SESSION_DIR` selects the identity, and the record
shape `item list --output json` returns — `id`, `share_id`, `state`, `title`,
with no `item_id` key. The discovery stub adds the `item view --output json`
shape, whose every value position holds a marker string — which is what makes
"no value reached the field list" an assertion rather than a restatement of the
parser.

The stubs take their fixtures from **files** rather than inlining JSON into the
shell script. That is not style: the vendor's own wording includes
`passwords don't match`, and an apostrophe inside a single-quoted shell string is
a syntax error. Inline one and the stub fails to parse, and the adapter reports
the shell's error as though it were the vendor's refusal — a fixture bug that
reads as a real finding.

The stubs record the argv they were called with, so the tests assert on the
invocation the adapter actually built rather than on a copy of the adapter's own
list of flags. A test that iterates the same list the implementation uses is
worthless: deleting an entry deletes it from both, and the suite stays green.

**`cargo test --test <name>` does not rebuild `examples/`.** The attestation
suite drives two real signed binaries from there, so filtering to one test file
after editing a peer runs the *previous* binary, and a correct fix reads as a
no-op. The support helper aborts the run when a peer is older than its source;
`cargo test` with no filter is always safe.

The security core is tested from three directions, and each catches a different
class:

| suite | what it is for |
|---|---|
| `daemon.rs`, `daemon_connection.rs` | it works: injection, masking, single-flight, the chain under 20 concurrent sessions |
| `daemon_degraded.rs` | the never-block invariant, once per way a daemon can fail |
| `attestation.rs` | the attacks, each with a control proving the machinery still works |

Every claim in the attestation suite has a negative control, because "the attack
was refused" and "nothing worked at all" are the same colour of green. Eight
mutations — attestation always allows, single-flight removed, daemon-absent made
fatal, the code hash taken from the path instead of the live image, the
interpreter refusal removed, the local fallback restored, attestation moved to
once-per-connection, and a malformed reply accepted — are each killed by a named
test.

Five more come from the discovery and write verbs, and two from the Proton
listing cache, each verified by making the mutation, confirming the byte change
with `diff`, and running the test named beside it:

| Mutation | Killed by |
|---|---|
| the type column reports the container's *value* instead of its *key* | `store::proton::…::no_extracted_field_name_is_ever_a_value` |
| `put` gains a `--value` flag | `cli::there_is_no_way_to_pass_a_value_to_put_as_an_argument` |
| every listed item is reported `Active` | `stores::a_listing_reports_a_trashed_items_state_verbatim` |
| `--projectId` is not passed through | `store::infisical::…::project_coordinates_are_passed_only_when_configured` |
| the reader falls back to the manager's session directory | `store::proton::…::a_read_never_uses_the_manager_identity_even_when_one_is_configured` |
| a vault listing never expires, so an item trashed after it was cached still resolves | `stores::a_listing_older_than_its_ttl_is_fetched_again_before_it_is_trusted` |
| a vault listing expires instantly, which un-caches the listing rather than bounding it | `stores::a_lookup_inside_the_ttl_serves_the_cache_and_lists_nothing` |

The second of those is the reason that test asserts on **exit code 2** — clap
refusing the word — rather than on "the command failed". Under `Command::output()`
stdin is empty, so a `put` that accepted `--value` and ignored it would fail
anyway, and a test that only checked for failure would have stayed green with the
flag present.

A filtered `cargo test` that matches **zero** tests exits 0 and reads exactly like
a pass, which is how a negative control goes green without exercising anything. So
each of those runs went through a harness that parses the `test result:` lines and
aborts unless exactly one test executed.

`.cargo/config.toml` pins the linker to `/usr/bin/cc`. On a machine where some
other tool installs its own `cc` earlier in `PATH`, every link otherwise fails
with `unknown option '-lSystem'`, which reads as a broken Rust toolchain rather
than a shadowed binary.

## Dependencies

Five crates, in four rows, and each earns its place:

| Crate | Why |
|---|---|
| `clap` | argument parsing; the derive form keeps the verb set readable at a glance, which matters when the absence of a verb is a security property |
| `serde` + `serde_json` | config parsing and audit rows — one format doing both jobs |
| `zeroize` | the optimiser is permitted to delete a write to memory that is never read again, which is exactly what hand-rolled scrubbing is |
| `nix` | the pty syscalls — `termios`, the three window/controlling-terminal `ioctl`s, `sigwait`, `pthread_kill`. Six of its 35 features are enabled |

`nix` is where hand-rolling stops being minimalism. A codec has a specification
and published vectors, so owning one is cheap and checkable. An `ioctl` request
constant does not: get it wrong and the code compiles, links, and then writes the
wrong number of bytes through a pointer at runtime, differently on every
platform. A terminal framework would have been far more than the job needs; the
six enabled features are the job.

base64, base32, hex, SHA-256, percent-encoding, JSON escaping and the civil-date
conversion are all written here rather than taken as dependencies. Each is short,
well specified, and checked against published vectors — RFC 4648 for the codecs,
FIPS 180-4 for the hash. Owning a codec is only cheaper than depending on one if
it is actually checked, so it is.

---
