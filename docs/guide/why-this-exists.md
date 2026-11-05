# Why this exists

A credential reaches a command in **four shapes**. Each one puts the value
itself on the command line, where the shell, the history file and an agent's
transcript all record it:

| Shape | What it looks like |
|---|---|
| Embedded in a URL | `https://user:VALUE@host` |
| An environment assignment | `export TOKEN=VALUE`, `VAR=VALUE cmd` |
| A CLI flag | `--token VALUE` |
| An HTTP header | `Authorization: Bearer VALUE` |

All four are **one primitive wide** — *spawn a child with the secret in its
environment*. So `run` is the product and everything else is support.

## Your number, not ours

How often this happens on **your** machine is the only count that should
persuade you of anything, and this README is the wrong place to learn it from.
Standard tools, nothing installed. Each line prints a count and never prints a
matching line — the same rule the tool itself follows:

```console
# swap in ~/.bash_history, or any transcript directory
H=~/.zsh_history

grep -acE 'https?://[^ /]*:[^ /@]*@' "$H"                       # url
grep -acE '[A-Z_]{4,}=[^ ]{12,}' "$H"                           # env
grep -acE '\-\-(token|key|secret|password)[= ][^ -][^ ]*' "$H"   # flag
grep -acE '[Aa]uthorization: *(Bearer|Basic) [^ "]+' "$H"        # header
```

Four counts. They are counts of **lines, not of secrets** — a shape is
checkable without anyone reading a value, which is why the recipe counts shapes
and never values. A correctly wrapped `keyless run` matches none of the four, so
it does not count the fix as the problem.

The CLI-flag shape is the documented reason [`keyless put` has no `--value`
flag](storing-a-secret.md#storing-a-secret).

---
