"""What a file's own reader does with `${NAME}` — the whole basis of the rewrite.

`KL-WRITE` replaces a credential literal with `${NAME}`, and the ONLY thing that
makes that substitution a repair rather than damage is that the file's reader
resolves it. A `.env` read by dotenv, a shell script, a compose file, a CI job:
each expands the reference, so the corrected file is one `keyless run` away from
working.

A `.ts` file expands nothing. `const key = ${STRIPE_KEY}` is a syntax error, and
the remediation the message prints does not apply — the writer is handed a broken
file instead of a secret, which is a different problem rather than a smaller one.
Replayed over real payloads, source files are the large majority of what this
check acts on, so the substitution was wrong far more often than it was right.

Three classes, because two would force a wrong answer on one of them:

    EXPANDS   the reader substitutes `${NAME}` -> rewriting REPAIRS the file
    INERT     the file has no grammar to break -> rewriting COSTS nothing
    OPAQUE    a program, a manifest, a data document -> rewriting BREAKS it

`INERT` is prose and plain data. `${NAME}` there resolves to nothing, but nothing
was going to run it: a reader sees a placeholder where a secret was, which is
exactly what a redacted document should say. So it joins `EXPANDS` on the side
that may be rewritten, for a different reason, and the two reasons are kept apart
here so that neither can be widened by mistaking it for the other.

An UNKNOWN extension is `OPAQUE`. That is the direction that fails safe: the
worst outcome of guessing OPAQUE is a message instead of a substitution, and the
worst outcome of guessing EXPANDS is a corrupted file whose author is told it was
repaired.
"""

import os

__all__ = ["EXPANDS", "INERT", "OPAQUE", "reader_class", "expands", "rewritable"]

EXPANDS = "expands"
INERT = "inert"
OPAQUE = "opaque"

# Readers that perform `${NAME}` substitution themselves. Each entry is a file
# type whose documented behaviour is expansion, not a type where expansion merely
# tends to happen.
_EXPANDS_EXT = frozenset([
    ".env", ".envrc", ".sh", ".bash", ".zsh", ".ksh", ".profile", ".bashrc",
    ".zshrc", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".config",
    ".properties", ".toml", ".service", ".tf", ".tfvars", ".env-cmdrc",
])

# Files named without an extension whose reader expands. A basename list rather
# than an extension list, because these types are spelled as whole names.
_EXPANDS_NAME = frozenset([
    "Dockerfile", "Containerfile", "Makefile", "GNUmakefile", "makefile",
    "Procfile", "Justfile", "justfile", "Jenkinsfile", ".env", ".envrc",
    ".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile",
])

# Prose and plain data: no execution grammar, so a substituted reference cannot
# break anything. `.json` is deliberately NOT here — it is a data document a
# program parses, and a bare `${NAME}` inside a JSON string is a value that
# program will use verbatim, which is the OPAQUE failure and not this one.
_INERT_EXT = frozenset([
    ".md", ".mdx", ".markdown", ".rst", ".txt", ".text", ".log", ".csv",
    ".tsv", ".adoc", ".org",
])


def _split(path):
    base = os.path.basename(path or "")
    if not base:
        return "", ""
    # `.env.local`, `.env.production` — the reader is dotenv whatever the suffix,
    # so the FIRST segment decides rather than the last. `os.path.splitext` reads
    # `.env.local` as extension `.local`, which no table can usefully carry.
    if base.startswith(".env"):
        return base, ".env"
    root, ext = os.path.splitext(base)
    # `prod.env`, `app.env` — the extension is the whole answer here.
    return base, ext.lower()


def reader_class(path):
    """EXPANDS, INERT or OPAQUE for one path. An empty path is OPAQUE."""
    base, ext = _split(path)
    if not base:
        return OPAQUE
    if base in _EXPANDS_NAME or ext in _EXPANDS_EXT:
        return EXPANDS
    if ext in _INERT_EXT:
        return INERT
    return OPAQUE


def expands(path):
    """True when the file's own reader resolves `${NAME}`."""
    return reader_class(path) == EXPANDS


def rewritable(path):
    """True when substituting `${NAME}` leaves a file that still works."""
    return reader_class(path) in (EXPANDS, INERT)
