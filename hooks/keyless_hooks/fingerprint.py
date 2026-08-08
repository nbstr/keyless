"""Credential-shaped literals in text, and the rewrite that removes them.

Two constraints shape every line here.

**It must be fast.** This runs on the content of every Write and every Edit. A
scanner that adds noticeable delay to editing gets uninstalled, and an
uninstalled scanner protects nothing — so the pass is a small number of compiled
alternations over the text, in-process, with no subprocess and no file I/O. No
pattern contains two adjacent quantifiers over overlapping character classes,
which is the shape that makes a regex quadratic on a near-miss.

**It must never emit a value.** `scan` returns offsets and a shape name. The
matched bytes exist inside this module only so `redact` can replace them; no
caller logs them, and the decision log has no field they would fit in.
"""

import re

__all__ = ["scan", "redact", "Finding"]


class Finding(object):
    __slots__ = ("kind", "start", "end", "name")

    def __init__(self, kind, start, end, name):
        self.kind = kind
        self.start = start
        self.end = end
        self.name = name

    def __repr__(self):
        return "Finding(%s@%d:%d as %s)" % (self.kind, self.start, self.end, self.name)


# Vendor-prefixed credentials. Each alternative is anchored on a literal prefix,
# so the engine rejects a non-match at the first character and there is nothing
# to backtrack over.
_VENDOR = re.compile(
    r"(?P<aws_access_key>\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b)"
    r"|(?P<github_pat>\bgh[pousr]_[A-Za-z0-9]{36,251}\b)"
    r"|(?P<github_fine_pat>\bgithub_pat_[A-Za-z0-9_]{22,251}\b)"
    r"|(?P<slack_token>\bxox[baprse]-[A-Za-z0-9-]{10,}\b)"
    r"|(?P<openai_key>\bsk-(?:proj-|ant-api\d\d-)?[A-Za-z0-9_-]{20,}\b)"
    r"|(?P<stripe_key>\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}\b)"
    r"|(?P<google_api_key>\bAIza[0-9A-Za-z_-]{30,45}\b)"
    r"|(?P<sendgrid_key>\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b)"
    r"|(?P<npm_token>\bnpm_[A-Za-z0-9]{36}\b)"
    r"|(?P<doppler_token>\bdp\.(?:pt|st|sa|ct|scim)\.[A-Za-z0-9]{40,}\b)"
    r"|(?P<gitlab_pat>\bglpat-[A-Za-z0-9_-]{20,}\b)"
    r"|(?P<huggingface_token>\bhf_[A-Za-z0-9]{30,}\b)"
    r"|(?P<shopify_token>\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b)"
    r"|(?P<linear_key>\blin_api_[A-Za-z0-9]{32,}\b)"
    r"|(?P<onepassword_sa>\bops_ey[A-Za-z0-9_.-]{40,}\b)"
    r"|(?P<infisical_token>\bst\.[A-Za-z0-9]{20,}\.[A-Za-z0-9]{20,}\.[A-Za-z0-9]{20,}\b)"
    r"|(?P<meta_token>\bEAA[A-Za-z0-9]{60,}\b)"
    r"|(?P<pypi_token>\bpypi-[A-Za-z0-9_-]{50,}\b)"
    r"|(?P<jwt>\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b)"
    r"|(?P<private_key_block>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"
)

# A credential inside a URL's userinfo. The password class excludes `/` and `@`
# so it cannot run past the host, and both quantifiers sit over disjoint classes.
#
# 8 is the floor, and this is the only pattern in the module that can reach it:
# every other generic rule already requires 12 or 16. Writing a smaller number
# here changes nothing, because `_too_plain` needs 8 DISTINCT characters and no
# value shorter than 8 characters has them — so the two floors have to be read
# together, and a relaxation that moves one alone is a no-op.
#
# Below 8 the shapes are `postgres` against a dev database (23 in the corpus)
# and `([^:]+):([^@]+)@` — a regex fragment, not a URL (7 more).
_URL_AUTH = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\s/:@]{1,64}:([^\s/@\"']{8,128})@")

# `Authorization: Bearer …` and its siblings, in a header, a curl flag, or a
# config file.
_BEARER = re.compile(
    r"(?i)authorization\s*:\s*(?:bearer|token|basic)\s+([A-Za-z0-9._~+/=-]{16,})")

# A credential passed as a command-line flag.
_FLAG = re.compile(
    r"(?i)--?(?:token|api[_-]?key|apikey|password|secret|auth[_-]?token)"
    r"(?:[= ]|\s+)([A-Za-z0-9._~+/=-]{16,})")

# A credential-named key assigned an opaque value. The keyword is matched
# directly with a lookbehind rather than by scanning a wildcard prefix, because
# `[A-Za-z0-9_-]*(?:token|secret)` is exactly the two-adjacent-quantifiers shape
# that goes quadratic on a long non-matching identifier.
#
# The keyword must END the identifier — `["']?\s*[:=]` follows it immediately —
# and that is a precision rule, not an oversight. A credential word with more
# identifier after it usually NAMES a credential rather than holding one:
# measured over 86,125 real agent commands, letting any bounded suffix through
# admits `AWS_ACCESS_KEY_ID` (30, the public half of the pair), `apiKeyConnectionId`
# (22), `secretRef` (11), `secretsManager`, `secretName`, `credentialsFullUri` and
# `TOKEN_DOCS` (a URL) — 142 new findings, almost none of them a secret.
#
# So the tail is ENUMERATED instead. `key` alone is far too generic to be a
# keyword — `cacheKey`, `sortKey`, `objectKey`, `partitionKey`, and 121 bare
# `key=` assignments in the same corpus — but a `key` qualified as secret,
# signing or encryption is a credential every time it appears. `pgpassword` is
# listed whole because the lookbehind blocks a keyword glued to a preceding word,
# and libpq's variable is the one name where that costs real coverage: 33
# occurrences in the corpus, against 51 for every other glued spelling combined
# (`nextPageToken`, `isPersonalToken`, `attributeKey`) — all of them code.
_ASSIGN = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?P<kw>token|secret_key|secret-key|secret|pgpassword|password|passwd|apikey|"
    r"api_key|api-key|access_key|access-key|private_key|private-key|signing_key|"
    r"signing-key|encryption_key|encryption-key|credentials?|auth_token|auth-token)"
    r"[\"']?\s*[:=]\s*"
    r"(?:\"([^\"\n]{12,256})\"|'([^'\n]{12,256})'|([A-Za-z0-9+/_.=~-]{12,256}))")

# Values that are shaped like a credential and are not one. Checked before any
# finding is reported, because a scanner that rewrites `${DB_PASSWORD}` into
# `${DB_PASSWORD}` is noise and a scanner that rewrites `changeme` is worse.
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{3,}|\.{3,}|-+|<[^>]*>|\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|"
    r"%[A-Za-z0-9_]+%|\{\{[^}]*\}\}|your[\w-]*|my[\w-]*|some[\w-]*|the[\w-]*|changeme|placeholder|"
    r"redacted|example\w*|dummy|sample|insert\w*|todo|fixme|none|null|nil|true|"
    r"false|undefined|unset|abc123\w*|foobar\w*|test\w*|fake\w*|secret|password|"
    r"password123|keyless:\w*|\[keyless:[^\]]*\])$")

_LOOKS_LIKE_PATH = re.compile(r"^(?:\.{0,2}/|~/|[A-Za-z]:\\)")
_KEY_CHARS = re.compile(r"[A-Za-z0-9_.-]")

# Below this many distinct characters a "credential" is a word, a version string
# or a hostname. Set from the shortest real credential shapes observed, not from
# a round number: `sk_test_4eC39Hq` has 12 distinct characters.
_MIN_DISTINCT = 8


def _is_placeholder(value):
    v = value.strip()
    if not v or len(v) < 8:
        return True
    if _PLACEHOLDER.match(v):
        return True
    if _LOOKS_LIKE_PATH.match(v):
        return True
    if "[keyless:" in v or "${" in v:
        return True
    if v.isdigit():
        return True
    return False


def _too_plain(value):
    """A generic match needs real variety, or every hostname is a credential."""
    return len(set(value)) < _MIN_DISTINCT


def _name_left_of(text, offset, end=None):
    """The identifier around a match, as a rewrite name.

    `offset` is where the matched KEYWORD starts and `end` where it stops, and
    both halves are needed: the keyword is part of the name. Reading only the
    left half turned `GITHUB_TOKEN=<literal>` into `${GITHUB}` — driven live,
    with a real session then told to use a variable that does not exist.

    Walked in Python rather than captured by a wildcard-prefixed regex: that
    prefix is the two-adjacent-quantifiers shape, and this loop is bounded by
    construction.
    """
    i = offset
    start = offset
    while i > 0 and offset - i < 64:
        if _KEY_CHARS.match(text[i - 1]):
            i -= 1
            start = i
        else:
            break
    raw = text[start:(end if end is not None else offset)].strip("_.-")
    if not raw:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_").upper()
    return cleaned if cleaned and not cleaned[0].isdigit() else ""


_ASSIGN_LEFT = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?\s*[:=]\s*[\"']?$")


def _assigned_name(text, value_start):
    """The key on the left of `KEY = <value>`, or "" when there is no assignment.

    Bounded to 96 characters of lookback, so this is linear in the number of
    findings rather than in the length of the text.
    """
    window = text[max(0, value_start - 96):value_start]
    m = _ASSIGN_LEFT.search(window)
    if not m:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", m.group(1)).strip("_").upper()
    return cleaned if cleaned and not cleaned[0].isdigit() else ""


def scan(text, limit=64):
    """Every credential-shaped literal in `text`, as (kind, span, suggested name).

    Overlaps are resolved by keeping the earliest, longest match, so one literal
    is never reported twice under two shapes and the rewrite cannot corrupt text
    by substituting nested spans.
    """
    if not text or not isinstance(text, str):
        return []

    raw = []
    for m in _VENDOR.finditer(text):
        kind = m.lastgroup or "credential"
        raw.append((m.start(), m.end(), kind, _assigned_name(text, m.start())))
        if len(raw) >= limit:
            break

    for rx, kind in ((_URL_AUTH, "url_password"), (_BEARER, "bearer_token"),
                     (_FLAG, "credential_flag")):
        for m in rx.finditer(text):
            value = m.group(1)
            if _is_placeholder(value) or _too_plain(value):
                continue
            raw.append((m.start(1), m.end(1), kind, ""))
            if len(raw) >= limit:
                break

    for m in _ASSIGN.finditer(text):
        value = m.group(2) or m.group(3) or m.group(4) or ""
        if _is_placeholder(value) or _too_plain(value):
            continue
        gi = 2 if m.group(2) is not None else (3 if m.group(3) is not None else 4)
        raw.append((m.start(gi), m.end(gi), "named_credential",
                    _name_left_of(text, m.start("kw"), m.end("kw"))))
        if len(raw) >= limit:
            break

    # Earliest wins, then longest, then the finding that carries a NAME. The
    # last term matters when a vendor pattern and an assignment match the same
    # span: the assignment knows the file's own key (`STRIPE_SECRET_KEY`) while
    # the vendor pattern only knows its own label (`STRIPE_KEY`), and the
    # substituted reference has to be the name the file's reader will resolve.
    raw.sort(key=lambda t: (t[0], -(t[1] - t[0]), 0 if t[3] else 1))
    out = []
    last_end = -1
    for start, end, kind, name in raw:
        if start < last_end:
            continue
        out.append(Finding(kind, start, end, name or kind.upper()))
        last_end = end
    return out


def redact(text):
    """(rewritten_text, findings). The literal becomes `${NAME}`.

    A rewrite rather than a refusal: the write proceeds, the file simply does not
    carry the secret. `${NAME}` is chosen over a fixed marker because it is the
    form the file's own reader — a shell, a compose file, a CI config — already
    knows how to resolve, so the corrected file is one `keyless run` away from
    working rather than being a dead end.
    """
    findings = scan(text)
    if not findings:
        return text, []

    used = {}
    pieces = []
    cursor = 0
    for f in findings:
        name = f.name or "SECRET"
        seen = used.get(name, 0)
        used[name] = seen + 1
        label = name if seen == 0 else "%s_%d" % (name, seen + 1)
        pieces.append(text[cursor:f.start])
        pieces.append("${%s}" % label)
        cursor = f.end
    pieces.append(text[cursor:])
    return "".join(pieces), findings
