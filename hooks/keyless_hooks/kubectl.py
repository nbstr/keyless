"""The verb path of a `kubectl` call, with its RESOURCE TYPE read as kubectl reads it.

KL-VAULT's kubectl rows ask one question: *does this call render a Secret's
`.data` map?* The generic verb path cannot answer it, for two reasons that both
failed open on a real session:

**A resource type that is not a literal cannot be proven safe.** `kubectl get $2
db -o json` read production Secrets from inside a loop, because the path was
`get $2 db` and no row names `$2`. Whatever the variable holds is decided at run
time, after this hook has already said yes. So a type spelled through `$`, `${…}`,
`$(…)` or a backtick is read as `secret` — the one value it could hold that this
row exists for. A NAME spelled through a variable is a different matter:
`kubectl get pod $P -o yaml` names a pod whatever `$P` holds, and stays open.

**kubectl takes flags before its verb and before its type.** `kubectl -n prod get
secret db -o yaml` ends the generic path at `-n`, which leaves nothing to match.
That truncation fails toward blocking for a store whose bare verb is the leak; for
kubectl the bare verb is `kubectl`, which prints help. So the flags kubectl
itself defines as taking an operand are skipped WITH that operand, and the path is
rebuilt as `<verb> <positionals>`.

What makes a word the TYPE is kubectl's own rule: the first positional is a
comma-separated type list (`cm,secret`), unless some positional is `TYPE/NAME`, in
which case every one is. A type is compared case-folded and up to its first dot,
so `Secret`, `SECRETS` and `secrets.v1.` all resolve to the core Secret.

`kubectl get --raw <path>` speaks to the API server by URL and returns the object
as JSON, `.data` included. A raw path naming `/secrets` — or one that is not a
literal — is read as a Secret read for the same reason.

`describe` is deliberately absent: it prints each key's SIZE and never its value.
`get all` is literal and never includes Secrets — the `all` category does not
contain them — so it stays open.

debt: a call that names its objects only through `-f <file>` or `-k <dir>` has no
      type on the command line at all, and passes, because the file is read by
      kubectl after this hook has decided. Ceiling: a manifest file listing a
      Secret, rendered with `-o yaml`. Upgrade trigger: a transcript scan finds
      a rendered Secret from a `kubectl get -f`/`-k` call.
"""

from .shellview import substitution_spans

__all__ = ["HEADS", "kubectl_args", "kubectl_path", "opaque_substitutions"]


# The heads this module reads. `kubectl` itself, and `porter kubectl`, which
# hands everything after its own `--` to a kubectl bound to a Porter cluster.
HEADS = frozenset(["kubectl", "porter"])


# kubectl flags that take a SEPARATE operand — global flags and the ones `get`,
# `edit` and `apply view-last-applied` define. Read from `kubectl options` and
# each verb's `--help` (kubectl v1.3x). A `--flag=value` or a clustered short
# flag (`-nprod`, `-oyaml`) is one word and needs no entry.
_VALUED = frozenset([
    "-n", "--namespace", "--context", "--cluster", "--user", "-s", "--server",
    "--kubeconfig", "--token", "--as", "--as-group", "--as-uid",
    "--request-timeout", "--cache-dir", "--certificate-authority",
    "--client-certificate", "--client-key", "--tls-server-name", "--password",
    "--username", "-v", "--v", "--vmodule", "--log-file", "--log-dir",
    "--log-file-max-size", "--profile", "--profile-output",
    "-o", "--output", "-l", "--selector", "--field-selector", "-L",
    "--label-columns", "--sort-by", "--template", "-f", "--filename", "-k",
    "--kustomize", "--chunk-size", "--raw", "--subresource", "--field-manager",
])

# Boolean flags common enough before a type that guessing about them would cost
# a real command. Any OTHER bare flag ahead of the type is UNKNOWN, and see
# `_types` for how that is read.
_BOOLEAN = frozenset([
    "-A", "--all-namespaces", "-w", "--watch", "--watch-only", "--show-kind",
    "--show-labels", "--no-headers", "--ignore-not-found", "--server-print",
    "--show-managed-fields", "-R", "--recursive", "--all", "--insecure-skip-tls-verify",
    "--match-server-version", "--warnings-as-errors", "--output-watch-events",
    "--save-config", "--validate", "--allow-missing-template-keys",
    "--disable-compression", "--output-patch", "--windows-line-endings",
])

# Porter's own flags on `porter kubectl`, from `porter kubectl --help`.
_PORTER_VALUED = frozenset(["--cluster", "--project", "--host", "--token"])

_SECRET_TYPES = frozenset(["secret", "secrets"])

# The placeholder a non-literal type is rewritten to. It is the word the rows
# already match, so the table needs no row for "a variable".
SECRET = "secret"


def _literal(tok):
    """`tok` with the quoting and escaping a shell would remove, or None when
    something will SUBSTITUTE into it at run time — the value is then unknown."""
    if "$" in tok or "`" in tok or "{}" in tok:
        # `{}` is the operand `xargs -I{}` and `find -exec` substitute.
        return None
    return tok.replace('"', "").replace("'", "").replace("\\", "")


def _type_is_secret(part):
    """True when one entry of a type list names the core Secret."""
    kind = part.split("/", 1)[0].split(".", 1)[0].lower()
    return kind in _SECRET_TYPES


def _list_names_secret(tok):
    """True when a type word is unprovable, or names Secret anywhere in its
    comma list."""
    lit = _literal(tok)
    if lit is None:
        return True
    return any(_type_is_secret(p) for p in lit.split(",") if p)


def kubectl_args(head, toks):
    """The words kubectl itself receives, or None when this is not a kubectl call.

    For `kubectl` that is every word after the head. For `porter kubectl` it is
    the words after porter's own `--`, or — with no `--` — every word after
    `kubectl` that is not one of porter's own flags.
    """
    if head == "kubectl":
        return list(toks)
    if head != "porter":
        return None
    i, n = 0, len(toks)
    while i < n and toks[i].startswith("-"):
        i += 2 if toks[i] in _PORTER_VALUED else 1
    if i >= n or toks[i] != "kubectl":
        return None
    rest = toks[i + 1:]
    if "--" in rest:
        return rest[rest.index("--") + 1:]
    out, j = [], 0
    while j < len(rest):
        if rest[j] in _PORTER_VALUED:
            j += 2
            continue
        out.append(rest[j])
        j += 1
    return out


def _flag_kind(tok):
    """"valued", "self", "boolean" or "unknown" for a word starting with `-`."""
    if tok in _VALUED:
        return "valued"
    if "=" in tok or (len(tok) > 2 and tok[1] != "-"):
        # `--flag=value`, or a clustered short flag (`-nprod`, `-oyaml`).
        return "self"
    if tok in _BOOLEAN:
        return "boolean"
    return "unknown"


def _split(args, eats=frozenset()):
    """(positionals, raw path or None, indices of UNKNOWN bare flags seen while
    the type slot was still empty). `eats` names unknown flags to read as
    taking an operand in this interpretation."""
    positionals = []
    raw = None
    unknown = []
    i, n = 0, len(args)
    after_dashdash = False
    while i < n:
        tok = args[i]
        if after_dashdash or not tok.startswith("-") or tok == "-":
            positionals.append(tok)
            i += 1
            continue
        if tok == "--":
            after_dashdash = True
            i += 1
            continue
        kind = _flag_kind(tok)
        if tok.startswith("--raw="):
            raw = tok[len("--raw="):]
        if kind == "valued":
            if tok == "--raw" and i + 1 < n:
                raw = args[i + 1]
            i += 2
            continue
        if kind == "unknown" and len(positionals) <= 1:
            unknown.append(i)
            if i in eats:
                i += 2
                continue
        i += 1
    return positionals, raw, unknown


def _types(objects):
    """The indices of `objects` kubectl reads as TYPE words: the first, or every
    one when any is `TYPE/NAME`."""
    if any("/" in (_literal(o) or "") for o in objects):
        return range(len(objects))
    return range(min(len(objects), 1))


def _path(args, eats=frozenset()):
    positionals, raw, unknown = _split(args, eats)
    if not positionals:
        return "", unknown, False
    verb = positionals[0]
    if _literal(verb) is None:
        # `kubectl $VERB …` — the verb is decided at run time. Read as the verb
        # that renders, so the row's own output-format condition still decides.
        verb = "get"
    objects = positionals[1:]
    if verb == "apply" and objects[:1] == ["view-last-applied"]:
        verb, objects = "apply view-last-applied", objects[1:]

    if raw is not None:
        lit = _literal(raw)
        if lit is None or "/secrets" in lit.lower():
            return "get " + SECRET, unknown, True

    secret = [i for i in _types(objects) if _list_names_secret(objects[i])]
    if not secret:
        return " ".join([verb] + objects), unknown, False
    # `secret` goes directly after the verb, whichever slot held it, so one row
    # pattern (`^get\\s+secret`) reads `get pod/a secret/b` as well as `get $2`.
    rest = [o for i, o in enumerate(objects) if i not in secret]
    return " ".join([verb, SECRET] + rest), unknown, True


# More unknown flags than this ahead of the type is not a command anyone types;
# each is tried on its own, so the bound is on work, not on correctness.
_MAX_UNKNOWN = 8


def kubectl_path(head, toks):
    """The canonical verb path for a kubectl call, or None if this is not one.

    `<verb> <positionals>`, with the type words that are unprovable or name a
    Secret collapsed to one `secret` directly after the verb. A `--raw` path
    naming Secrets — or unprovable — becomes `get secret`. Everything else is
    passed through as typed, so a row a user adds for another type
    (`^get\\s+configmap`) reads the same path shape.

    A bare flag this module does not know, met before the type, may or may not
    take the next word as its operand, and nothing here can tell which. Each
    such flag is also read the other way, and a reading that finds a Secret
    wins: that fails toward blocking, and the ordinary command never carries an
    unknown flag there, so it costs nothing in practice.
    """
    args = kubectl_args(head, toks)
    if args is None:
        return None
    path, unknown, secret = _path(args)
    if secret:
        return path
    for idx in unknown[:_MAX_UNKNOWN]:
        alt, _, alt_secret = _path(args, frozenset([idx]))
        if alt_secret:
            return alt
    return path


def opaque_substitutions(text):
    """`text` with every top-level `$( … )` and back-quoted span replaced by the
    single word `$SUBST`, so a substitution in an argument slot stays in that
    slot — and reads as what it is, a value decided at run time."""
    spans = substitution_spans(text)
    if not spans:
        return text
    out = text
    for start, end, backquoted in sorted(spans, reverse=True):
        lo = start - (1 if backquoted else 2)
        out = out[:lo] + "$SUBST" + out[end + 1:]
    return out
