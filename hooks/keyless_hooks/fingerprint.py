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

__all__ = ["scan", "redact", "Finding", "VENDOR_KINDS", "is_vendor"]


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

# The kinds a VENDOR pattern produces, read off the compiled alternation rather
# than restated as a list. A caller asking "is this shape self-evidently a
# credential" gets its answer from the same object that decides the shape, so a
# pattern added above joins this set with no second edit — and a set maintained
# by hand would answer "no" for the newest pattern, which is the one least likely
# to be reviewed.
#
# The distinction it draws is the one that licenses a REFUSAL. A vendor prefix is
# proof on its own: nothing but an AWS key is spelled `AKIA` plus sixteen upper
# alphanumerics. Every other rule here is keyed on a NAME or on POSITION —
# `password: <opaque>` — and cannot separate a literal from an identifier that
# merely looks opaque, which is the residual class this module documents and does
# not claim to have closed.
VENDOR_KINDS = frozenset(_VENDOR.groupindex)


def is_vendor(kind):
    """True when the shape alone proves the value is a credential."""
    return kind in VENDOR_KINDS


# A credential inside a URL's userinfo. The password class excludes `/` and `@`
# so it cannot run past the host, and both quantifiers sit over disjoint classes.
#
# 8 is the floor, and this is the only pattern in the module that can reach it:
# every other generic rule already requires 12 or 16. Writing a smaller number
# here changes nothing, because `_too_plain` needs 8 DISTINCT characters and no
# value shorter than 8 characters has them — so the two floors have to be read
# together, and a relaxation that moves one alone is a no-op.
#
# Below 8 the shapes stop being credentials at all: `postgres` against a dev
# database, and `([^:]+):([^@]+)@` — a regex fragment, not a URL.
_URL_AUTH = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\s/:@]{1,64}:([^\s/@\"']{8,128})@")

# `Authorization: Bearer …` and its siblings, in a header, a curl flag, or a
# config file.
#
# Horizontal whitespace and not `\s` in every gap below. See "a key and its value
# share a line", under `_ASSIGN`.
_BEARER = re.compile(
    r"(?i)authorization[^\S\n]*:[^\S\n]*(?:bearer|token|basic)[^\S\n]+"
    r"([A-Za-z0-9._~+/=-]{16,})")

# A credential passed as a command-line flag.
_FLAG = re.compile(
    r"(?i)--?(?:token|api[_-]?key|apikey|password|secret|auth[_-]?token)"
    r"(?:[= ]|[^\S\n]+)([A-Za-z0-9._~+/=-]{16,})")

# A credential-named key assigned an opaque value. The keyword is matched
# directly with a lookbehind rather than by scanning a wildcard prefix, because
# `[A-Za-z0-9_-]*(?:token|secret)` is exactly the two-adjacent-quantifiers shape
# that goes quadratic on a long non-matching identifier.
#
# The keyword must END the identifier — `["']?\s*[:=]` follows it immediately —
# and that is a precision rule, not an oversight. A credential word with more
# identifier after it usually NAMES a credential rather than holding one:
# replayed over real agent commands, letting any bounded suffix through admits
# `AWS_ACCESS_KEY_ID` (the public half of the pair), `apiKeyConnectionId`,
# `secretRef`, `secretsManager`, `secretName`, `credentialsFullUri` and
# `TOKEN_DOCS` (a URL) — a large new class, almost none of it a secret.
#
# So the tail is ENUMERATED instead. `key` alone is far too generic to be a
# keyword — `cacheKey`, `sortKey`, `objectKey`, `partitionKey`, and every bare
# `key=` in ordinary configuration — but a `key` qualified as secret, signing or
# encryption is a credential every time it appears. `pgpassword` is listed whole
# because the lookbehind blocks a keyword glued to a preceding word, and libpq's
# variable is the one name where that costs real coverage: every other glued
# spelling that turned up (`nextPageToken`, `isPersonalToken`, `attributeKey`) is
# code, and admitting them to save `PGPASSWORD` would be a bad trade.
_ASSIGN = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?P<kw>token|secret_key|secret-key|secret|pgpassword|password|passwd|apikey|"
    r"api_key|api-key|access_key|access-key|private_key|private-key|signing_key|"
    r"signing-key|encryption_key|encryption-key|credentials?|auth_token|auth-token)"
    r"[\"']?[^\S\n]*[:=][^\S\n]*"
    r"(?:\"([^\"\n]{12,256})\"|'([^'\n]{12,256})'|([A-Za-z0-9+/_.=~-]{12,256}))")

# ── a key and its value share a line, and the gap must say so ──────────────
#
# Every gap above is `[^\S\n]` — horizontal whitespace — where it used to be
# `\s`. `\s` matches a NEWLINE, so a key with an EMPTY value ran past the end of
# its own line and took the NEXT line's key as its value. In a file this pack
# rewrites, that substitution then replaced a key NAME with a reference to a
# different variable, silently, under a message announcing a repair:
#
#     env:                            env:
#       GITHUB_TOKEN:          ->       GITHUB_TOKEN:
#       NODE_VERSION: 20                ${GITHUB_TOKEN}: 20
#
# Measured 2026-08-29 through the live hook on a `.github/workflows/*.yml`, and
# reproducible in `.env.example` (`API_TOKEN=` on one line, the next key on the
# next), in a reusable workflow's `secrets:` block, and in any INI or TOML with a
# declared-but-unset key. All four are file types whose reader expands `${NAME}`,
# which is exactly the set this check rewrites rather than reports.
#
# The horizontal-only gap costs nothing real: no format on the rewrite list puts
# a scalar on the line after its key without a block indicator, and a block
# scalar carries no `12,256`-character run of value characters on the separator
# line to match in the first place.
#
# `_one_line` below is the same rule again, enforced on the FINDING rather than
# in the pattern, so a future pattern edit cannot reopen the class quietly.

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


# ── a credential VALUE, or a reference to one ───────────────────────────────
#
# `SECRET_KEY = "AKIA…"` holds a credential. `this.secret` = `config.secret` and
# `token` = `getAuthToken()` NAME one, and naming one is the usage this whole pack
# asks people to write. The name-keyed rule above cannot tell them apart on its
# own: it sees a credential word, an assignment, and something on the right.
#
# Three syntactic tests separate them, and each reads the characters AROUND the
# value rather than the value's own bytes — no entropy test, because a credential
# and an identifier are indistinguishable by entropy at these lengths and a
# threshold there would move with every fixture anyone writes:
#
#   a run-time substitution   `AUTH_TOKEN="$(cat ~/.token)"`
#   a code TERMINATOR         `credentials: PushConfig,`  `token = getToken(`
#   a member PATH             `this.secret` = `config.secret`
#
# **A quoted value is a literal, with ONE exemption, and the exemption is a
# closed list.** `"…",` says the comma belongs to the enclosing code rather than
# to the value, so the TERMINATOR test needs the value unquoted and gets it. The
# MEMBER-PATH test used to need it unquoted too, and that inverted the check:
#
#     token: secrets.GITHUB_TOKEN        left alone
#     token: "secrets.GITHUB_TOKEN"      ->  token: "${TOKEN}"
#
# The unquoted spelling is exempt because the grammar itself says it is an
# expression. The quoted one is a string someone typed, so exempting it needs
# POSITIVE evidence that the string names something — and `a.b.c` in quotes is
# not that evidence on its own. `TOKEN = "abcdefgh.ijklmnop.qrstuvwx"` is a
# dotted opaque triple and it is a literal; the adversarial suite drives that row
# and it went red the first time this exemption was written without a head list.
#
# So the head is enumerated. These are the namespaces a REFERENCE is written
# against in the file types this check rewrites, where quoting the reference is
# ordinary and the string is resolved by the file's own reader or by the code
# around it. A head outside the list keeps the old behaviour — the quoted value
# is a literal — which is the direction that fails toward catching.
_QUOTED_REF_HEADS = frozenset([
    # GitHub Actions contexts
    "secrets", "vars", "env", "github", "inputs", "needs", "steps", "job",
    "jobs", "matrix", "runner", "strategy",
    # Terraform / OpenTofu
    "var", "local", "locals", "data", "module", "each", "path",
    # Helm / Kubernetes templating
    "values", "release", "chart",
    # ordinary code, where a config file quotes an accessor
    "process", "os", "environ", "config", "settings", "self", "this", "props",
    "state", "ctx", "context",
])
_SEGMENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")

# Characters that end an EXPRESSION and cannot end a bare value in any data
# grammar. `.env`, a shell assignment, YAML, an INI and an HTTP header all run a
# bare value to whitespace or to end of line; none of them puts a `(`, a `,` or a
# `)` immediately after one. Every programming language does.
#
# The list is short because it is a CLOSED list of characters that cannot sit
# inside a credential, and every character left out was left out for a reason a
# measurement produced:
#
#   `:`  a composite token carries one — `<token>::<scope>`, and a Telegram bot
#        token is `<digits>:<body>`. Reading it as code punctuation was tried and
#        it dropped a real credential. Measured, not predicted.
#   `;`  `SECRET=<literal>; ./deploy.sh` is an ordinary shell line.
#   `!` `#` `$` `%` `&` `?` `*`
#        a generated password is made of these. The value class stops at the
#        first one, so the character AFTER a real password is routinely one of
#        them.
#
# Leaving them out costs exemptions this closed list would otherwise grant. Most
# of those are dotted member paths, which `_is_member_path` withholds anyway; the
# rest are a bare identifier standing before a `;`, and those stay rewritten,
# which is a false positive this module accepts on purpose. That is the price
# of not reading a shell statement separator as code punctuation, paid in full
# rather than rounded away.
_CODE_END = frozenset(["(", ",", ")"])


def _is_member_path(value):
    """`process.env.SECRET`, `config.secret`, `credentials.value.password`.

    A member expression reads a credential from somewhere; it never is one. The
    bounds are what keeps a dotted TOKEN out: a JWT's first segment is base64 of
    a JSON header — longer than 24 characters and carrying digits — so it fails
    twice here, and it is caught by the `jwt` vendor pattern regardless, which
    this exemption cannot reach because it withholds only the name-keyed finding.
    """
    if "." not in value:
        return False
    parts = value.split(".")
    if not 2 <= len(parts) <= 4:
        return False
    for part in parts:
        if len(part) > 40 or not _SEGMENT.match(part):
            return False
    head = parts[0]
    return len(head) <= 24 and not any(c.isdigit() for c in head)


def _is_reference(text, start, end):
    """True when the matched value NAMES a credential rather than holding one.

    What this does NOT separate is the residual class, and naming it is worth
    more than a claim of completeness: a bare identifier that ends on whitespace
    or on end of line. `password`: `E2E_LOGIN_PASSWORD` and `PGPASSWORD`=<a real
    literal> are the same three tokens in the same order, and only the value's
    own randomness tells them apart, and that class is a large minority of the
    name-keyed findings that still survive this test.

    Three discriminators reach it and none is here, each for a measured reason:
    an ENTROPY floor, which no pattern in this module tests and which moves with
    every fixture anyone writes; the SEPARATOR, exempting `key: value` and
    keeping `key=value`, which drops a credential written into an HTTP header
    and one in a YAML mapping; and "the same word APPEARS ELSEWHERE in this
    file", which drops a real API key that a test spelled twice.
    """
    value = text[start:end]
    if "$(" in value or "`" in value:
        # Assembled when the file is READ, so nothing was typed and nothing is in
        # the transcript. `${VAR}` and a bare `$VAR` are already placeholders;
        # this is the third spelling and the pack's own remediation uses it.
        #
        # Scoped to the name-keyed rule on purpose. `_is_placeholder` is shared
        # with `_URL_AUTH`, and putting it there would clear a connection string
        # whose userinfo password is a back-quoted substitution. That row is the
        # ONE proof that KL-ASSIGN's expansion-blanking is load-bearing rather
        # than decorative, and clearing it here would make the proof vacuous.
        return True
    quoted = start > 0 and text[start - 1] in "\"'`"
    if not quoted and (text[end] if end < len(text) else "") in _CODE_END:
        # `token` = `getAuthToken(`, `credentials: PushConfig,`, `secret: KEY)`.
        # The match is an expression in a programming language, so the credential
        # word in front of it is a field name and not a key holding a value.
        #
        # Gated on the value being UNQUOTED: after `"…"` the comma belongs to the
        # enclosing code, so it says nothing about what is inside the quotes.
        return True
    if not _is_member_path(value):
        return False
    if not quoted:
        return True
    # Quoted: a dotted string needs a head that NAMES a namespace before it is
    # read as a reference. See `_QUOTED_REF_HEADS`.
    return value.split(".", 1)[0].lower() in _QUOTED_REF_HEADS


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


_ASSIGN_LEFT = re.compile(
    r"([A-Za-z_][A-Za-z0-9_.-]{0,63})[\"']?[^\S\n]*[:=][^\S\n]*[\"']?$")


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


def _one_line(text, keyword_start, value_start, value_end):
    """A finding must live on ONE line, keyword and value together.

    The same rule the gaps in `_ASSIGN`, `_BEARER` and `_FLAG` already enforce,
    stated a second time on the finding itself. It is not redundant: the patterns
    are edited far more often than this function, and a `\\s` reintroduced in one
    of those gaps reopens exactly the class that silently rewrote a YAML key into
    a reference to a different variable. Here the same mistake produces a dropped
    finding — a miss, which is the direction this module is allowed to fail in —
    instead of a corrupted file announced as a repair.

    `keyword_start` is `None` for a shape that carries no keyword.
    """
    if "\n" in text[value_start:value_end]:
        return False
    if keyword_start is None:
        return True
    return "\n" not in text[keyword_start:value_start]


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
            if not _one_line(text, m.start(), m.start(1), m.end(1)):
                continue
            raw.append((m.start(1), m.end(1), kind, ""))
            if len(raw) >= limit:
                break

    for m in _ASSIGN.finditer(text):
        value = m.group(2) or m.group(3) or m.group(4) or ""
        if _is_placeholder(value) or _too_plain(value):
            continue
        gi = 2 if m.group(2) is not None else (3 if m.group(3) is not None else 4)
        if not _one_line(text, m.start("kw"), m.start(gi), m.end(gi)):
            continue
        if _is_reference(text, m.start(gi), m.end(gi)):
            continue
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
