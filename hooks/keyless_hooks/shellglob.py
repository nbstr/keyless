"""Whether the SHELL pathname-expands a word, and which programs glob on their own.

A shell expands only the glob metacharacters `*`, `?` and `[` that stand outside
every quote and are not backslash-escaped. `'.*'`, `".*"` and `\\.\\*` reach the
program as the two characters `.*`, whatever the directory holds. That is how a
PromQL matcher `'{path=~"(?i).*webhook.*"}'` reaches a query script intact — and
expanding that word against the cwd, as KL-FILE did, matched `.npmrc` and refused
a read the shell never performs.

The quoted glob is still a glob to a program that expands its OWN arguments.
`find . -name '.e*' -exec cat {} +` prints `.env`, and the quotes are there
precisely so the shell leaves the pattern for `find`. Those programs are the
closed side of this rule and are listed below; for them a quoted glob keeps its
expansion.

debt: `SELF_GLOBBING` is a fixed list. A program missing from it that globs its
      own argument AND prints the matches is read as receiving a literal string,
      so a quoted glob that does not ALSO match a protected pattern as text
      (`'.e*'` against `.env`) is not expanded for it. The literal match is
      unaffected, so `'.env'` and `'*.env'` are refused for every program.
      Ceiling: a self-globbing reader outside this list, handed a quoted glob
      that only filesystem expansion connects to a credential file.
      Upgrade trigger: a transcript scan finds credential content printed by such
      a call, or a program on this list is found to be missing.
"""

__all__ = ["SELF_GLOBBING", "LOCAL_SHELLS", "shell_globs", "keeps_glob",
           "runs_local_shell_code", "local_shell_payloads"]

from .shellview import head_of, rest_after_head, statements, tokens, unquote, words

# Programs that interpret glob metacharacters in their own arguments — a path
# filter, a pathspec, an include rule — and can emit the content of what matched.
SELF_GLOBBING = frozenset([
    "find", "fd", "fdfind", "git", "rsync", "tar", "bsdtar", "zip", "unzip",
    "7z", "scp", "rg", "ag", "ack", "grep", "egrep", "fgrep",
    "rclone", "aws", "gsutil", "gcloud", "jj", "hg",
])


# Shells that run their code argument HERE, in this working directory. Their
# `-c` payload is shell source that a SECOND shell parses, so a glob the outer
# shell protected with quotes may be expanded by the inner one: `bash -c 'cat
# .e*'` prints `.env`. `eval` re-reads its arguments the same way. The payload is
# therefore scanned as a command of its own, with its own quoting — see
# `local_shell_payloads`. `ssh`, `docker` and `kubectl` also run shell code, on a
# filesystem this cwd says nothing about, so they are not here.
LOCAL_SHELLS = frozenset(["bash", "sh", "zsh", "dash", "ksh", "mksh", "fish",
                          "csh", "tcsh", "eval"])


def runs_local_shell_code(head, toks):
    """True when `head` is a local shell handed inline CODE, so its quoted words
    are globbed by that shell. `eval` always is; the others only with a `-c`
    (alone or bundled — `-lc`, `-ec`). Without one, a shell's quoted argument is
    a script's `argv`: `bash pq.sh '.*'` hands the script two characters."""
    if head not in LOCAL_SHELLS:
        return False
    if head == "eval":
        return True
    for tok in toks:
        if tok.startswith("-") and not tok.startswith("--") and "c" in tok[1:]:
            return True
    return False


def shell_globs(tok):
    """True when the shell would pathname-expand this word.

    `$'…'` is ANSI-C quoting and expands nothing. Inside double quotes a
    backslash escapes; inside single quotes nothing does. Unterminated quoting is
    read as quoted to the end, which is what the shell would wait for.
    """
    i, n = 0, len(tok or "")
    quote = None
    while i < n:
        c = tok[i]
        if quote == "'":
            if c == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                quote = None
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if c == "$" and i + 1 < n and tok[i + 1] == "'":
            quote = "'"
            i += 2
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c in "*?[":
            return True
        i += 1
    return False


def keeps_glob(word, heads):
    """True when a candidate carved out of `word` may be filesystem-expanded.

    `heads` are every program name the statement runs the word through — the
    statement's own head and any program it delegates to — because `find …
    -exec cat` is judged by `cat` while `find` is what expands the pattern.

    An EMPTY word means the caller could not recover the token, and that answers
    True: an unknown is not evidence the shell would leave it alone.
    """
    if not word:
        return True
    if shell_globs(word):
        return True
    return any(h in SELF_GLOBBING for h in heads if h)


def local_shell_payloads(cmd, depth=2):
    """The code a LOCAL shell is handed, as command text to be scanned on its own.

    `bash -c '<code>'` contributes `<code>` — every wholly quoted word, which is
    how the payload is spelled. `eval <words>` contributes its words with one
    level of quoting removed, which is what `eval` itself does before it runs
    them: `eval 'cat .e*'` runs `cat .e*`. Nested shells are followed to `depth`.
    """
    out = []
    if not cmd or depth <= 0:
        return out
    for stmt in statements(cmd):
        head = head_of(stmt)
        if not runs_local_shell_code(head, tokens(stmt)):
            continue
        if head == "eval":
            inner = " ".join(tokens(rest_after_head(stmt)))
            found = [inner] if inner.strip() else []
        else:
            found = []
            for a, b in words(stmt):
                tok = stmt[a:b]
                if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in ("'", '"'):
                    inner = unquote(tok)
                    if inner.strip():
                        found.append(inner)
        for inner in found:
            out.append(inner)
            out.extend(local_shell_payloads(inner, depth - 1))
    return out
