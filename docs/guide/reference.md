# Reference

## Rule 1: it never blocks your command on a failure

**Once `keyless run` has parsed its arguments, no failure of a store, a daemon or
a config stops the child.** Not a missing store, not a corrupt config, not a
store or daemon that errors, hangs or floods, not a value the kernel refuses to
put in an environment, and not a machine temporarily out of process slots. It
warns on stderr and runs the command anyway with an unmodified environment.

It refuses a run only when a store has *answered*, and the answer is that the
request is wrong:

- **a name its store does not hold** — a typo, a guess, a probe, a name built
  from an empty substitution or a pasted config value;
- **an empty name** — `-s VAR=`, or a shell that substituted nothing;
- **a caller that fails attestation** — `keylessd` will not serve that program.

A refused run exits **64** without starting the command, and prints why for
each refused name, with the nearest names the daemon serves or the fields the
item behind the name does have. One refused name refuses the whole run, so the
command never runs with a partial environment you did not expect.

<details>
<summary>The clause at the front of that sentence is doing real work. Here is what it buys and what it costs.</summary>

This used to read *"there is no code path in which `keyless run` exits without
spawning the child"*, with no clause, and that absolute was false. An adversarial
review found **nine** ways to end a `keyless run` with no child — a config that
was a FIFO, a `security` binary with no deadline, a stored value containing a NUL
byte, a `-s` argument that was not UTF-8, and five more. Every one is fixed, and
each has a test that fails without the fix.

The clause survives the fixes because one class cannot be fixed from inside this
tool: an argument the parser rejects. `keyless run --bogus -- ./deploy.sh` exits
**2** and runs nothing, because a flag `keyless` does not recognise might be a
flag that changes what running means. Guessing would be worse than refusing, and
the refusal happens before any code this project controls.

So the honest claim is the qualified one. **An absolute with a counterexample is
worth less than a bounded claim that holds.** What the qualified sentence still
says: **no failure of a store or of `keyless` itself ever costs you the
command.** A wrong name is not a failure of either — running the command without
the credential it named only moves the mistake somewhere harder to read.

</details>

```console
$ keyless run -s DATABASE_URL -s GITHUB_TOKEN -- ./migrate.sh
keyless: DEGRADED — 2 names unresolved: DATABASE_URL, GITHUB_TOKEN
keyless:   DATABASE_URL: store `daemon` is unavailable: ...
...your command runs, and its exit code is yours...

$ keyless run -s DATABSE_URL -- ./migrate.sh
keyless: REFUSED — 1 of 1 names refused; the command was not run
keyless:   `DATABSE_URL`: store `daemon` refused: ...; nearest served names: DATABASE_URL (indexed 2m ago)
```

There are three states:

- **INJECTED** — every requested name resolved, was injected, and is masked.
- **DEGRADED** — a store could not answer for a name. The command runs with an
  untouched environment.
- **REFUSED** — a store answered that it holds no such name, the name was empty,
  or the caller failed attestation. The command never starts.

A partial injection would be a fourth state, so it does not exist: if one name of
three is missing, none of the three is injected. Fewer secrets, never more.

This is not politeness. A tool that occasionally blocks the work gets
uninstalled, and what comes back is the plaintext literal on the command line.
Degrading loses the protection for one command; failing loses it for good. A
refusal is different: it costs one corrected name, never an outage.

*Degraded runs still mask.* Whatever did resolve is still compiled into the
output filter even though nothing is injected — so a value you typed by hand
stays out of the audit log and out of the echoed output. Injection is withheld
when degraded; redaction is not.

These are the ways out without a child:

| Exit | Meaning | Who decided |
|---:|---|---|
| 2 | an argument could not be parsed — an unknown flag, a missing `--` | clap, before `keyless` runs |
| 64 | a refused run, or no command followed the flags (`EX_USAGE`) | a store's answer, or `keyless` with nothing to spawn |
| 127 | the command exists as text but not as an executable | the kernel, at `execve` |

Everything else — every unreachable store, every config, every deadline, every
value the kernel will not accept — is a **degrade**: a line on stderr, the
command runs, and its exit code is yours.

A non-UTF-8 `-s` argument is deliberately **not** in that table. It used to be:
clap rejected it and exited 2 while a perfectly runnable command sat after the
`--`. It is taken as bytes now, so it becomes one unresolvable name and the run
degrades.

## Rule 2: there is no verb that prints a value

No `get`. No `read`, `export`, `show`, `cat`, `--reveal`, `--print`,
`--no-masking`. Not behind a flag, not behind an environment variable, not "just
for debugging".

A single verb that writes a plaintext value to stdout voids the entire design,
because a caller takes the shortest path and that verb is always the shortest
path. This is behavioural, not theoretical: a CLI that already reads its key
from the environment still gets that key typed at it as a literal flag, because
the flag is one line and setting up the environment is more than one.
Availability of the safe path does not win. Only being the shortest path wins.

The rule holds across the whole verb set, and each verb has to earn it
separately:

| Verb | What it prints |
|---|---|
| `run` | your command's output, with injected values replaced by `[keyless:NAME]` |
| `ls` | the names you declared, and which environment each one points at |
| `items` | vault, state, type, title |
| `fields` | field names, kinds, types, paths — never a value, never a length |
| `new` | that it stored something, and where |
| `put` | the same, and it echoes nothing it read |
| `doctor` | `ok` / `missing` / a store's own error |

`new` is the interesting one: it generates a credential and then does not show it
to you. There is no flag that does.

## Terminals

Masking needs the child's output to pass through `keyless`, and that normally
costs you the terminal: a program handed a pipe answers *no* to "am I on a
terminal?", so `npm install` loses its progress bar, `git log` loses its pager
and its colour, and prompts change shape. A tax on every invocation is how a
tool gets uninstalled — which brings the plaintext literal straight back.

So when you really are at a terminal, `keyless` allocates a pseudo-terminal and
gives it to the child. The child sees a terminal because it **has** one. The
bytes still cross the masker on the way out.

|  | what the child gets |
|---|---|
| stdin, stdout and stderr are all terminals | a real pty — `isatty` true, colour, size, prompts |
| anything redirected, a pipe, a CI job | pipes, exactly as before |
| nothing to mask | your own stdio, inherited untouched |

All three streams must be terminals before a pty is used, and each one is a
separate reason:

- **stdout** — with no terminal there is nothing to preserve, and writing escape
  sequences into a pipe or a file corrupts it.
- **stderr** — a pty carries ONE stream. Merging the child's stderr into it
  would silently defeat a deliberate `2>errors.log`. That is data loss, not a
  cosmetic difference.
- **stdin** — a pty has no end-of-file to deliver. Relaying a pipe that ends into
  a pty means synthesising an EOT, whose meaning depends on the child's line
  discipline; getting it subtly wrong truncates input.

What comes with the pty:

- **The window size**, at start and on every resize. `SIGWINCH` reaches the
  child, so a full-screen program reflows.
- **Raw mode**, so Ctrl-C, arrow keys and paste reach the child untouched.
- **Ctrl-C goes to the child, not to `keyless`.** Your terminal is raw, so it
  raises no `SIGINT`; the `0x03` byte travels into the pty, and the child's own
  line discipline raises `SIGINT` for the child. `SIGTERM`, `SIGHUP` and
  `SIGQUIT` sent to `keyless` are forwarded rather than acted on, so the run
  always leaves through the same exit path — with the terminal restored and the
  child's exit code intact. On the pipe path the child shares this terminal's
  process group and receives Ctrl-C directly.
- **Restoration on every exit path** — normal exit, a child killed by a signal,
  and a panic (a hook covers the aborting kind, where destructors do not run).
  `SIGKILL` and a hard `abort()` cannot be covered by anything; `stty sane`
  repairs a terminal left raw by either.

**A pty is a comfort, not a precondition.** If one cannot be allocated — no
`/dev/ptmx`, no free descriptors, an unsupported platform — `keyless` prints one
line, falls back to pipes, and runs your command with its secrets injected
exactly as it would have. Rule 1 has no exception for terminals.

There is no flag to force a pty on or off. The condition is observable and the
fallback is automatic, so a switch would only be a way to get it wrong.

## The audit log

Kept in [the README](../../README.md#the-audit-log), beside the row it shows.

## No telemetry

`keyless` sends nothing anywhere, ever. No analytics, no version check, no crash
reporting, no error upload. There is no opt-out because there is nothing to opt
out of. It opens no network socket of its own — the only socket it ever opens is
the local Unix one to `keylessd` — and a test reads the built binary and fails if
an endpoint or a known analytics vendor's name appears in it.

**The promise extends through the subprocesses it spawns.** A network-backed
store reaches the network — that is what you asked it for — but nothing else
leaves with it. Two vendors carry something to switch off, and both are
switched off on every invocation `keyless` makes, the daemon's own included:

| Vendor | What is switched off |
|---|---|
| Infisical | telemetry defaults to **on**, so `--telemetry=false` goes on every invocation |
| Proton Pass | `PROTON_PASS_DISABLE_TELEMETRY` stops the row `pass-cli` writes per command and the sending of the ones already saved; `PROTON_PASS_NO_UPDATE_CHECK` stops its update check |

Without those, `keyless` would be the reason a report left your machine while
this section claimed otherwise.

The binary test allows exactly two `telemetry` strings — `--telemetry=false`
and `PROTON_PASS_DISABLE_TELEMETRY` — and fails if any other appears, if either
goes missing, or if `PROTON_PASS_NO_UPDATE_CHECK` goes missing.

This says nothing about the `infisical` or `pass-cli` runs you make yourself. A
line you paste carries what you type, and the lines `keyless` prints for you to
paste carry the session directory alone.

---
