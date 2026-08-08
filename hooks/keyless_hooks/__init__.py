"""keyless hook pack — the bypass paths, closed inside the agent harness.

`keyless run` makes the safe path available. That is not the same as making it
the only path: an injector alone leaves the agent free to read the `.env`, run
`op read`, or dump `env`, and the injector was theatre. This package is the other
half — a store-agnostic set of checks that close those doors from inside the
harness, whatever vault the user actually keeps secrets in.

Entry point: `keyless_hook.py` at the repository's `hooks/` root.
"""

__version__ = "0.1.0"
