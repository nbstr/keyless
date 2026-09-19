"""KL-WRITE — a credential literal in a file being written.

This covers the widest hole there is: a plaintext credential typed straight into
a file, where every later gate can only report it after the fact.

── the instrument depends on the FILE, and that is the whole design ────────────
Substituting `${NAME}` for the literal is a repair only where the file's own
reader resolves it:

    STRIPE_KEY=sk_live_<a real key>   ->   STRIPE_KEY=${STRIPE_KEY}

In a `.env`, a shell script, a compose file or a CI job that is exactly right:
the write proceeds, the file does not carry the secret, and it is one
`keyless run` away from working.

In a source file it is not right at all. `const key = ${STRIPE_KEY}` is a syntax
error, and the remediation the message prints does not apply — the author is
handed a broken file instead of a secret, which is a different problem rather
than a smaller one. Replayed over real payloads, source files are the large
majority of what this check acts on, so the substitution was wrong far more often
than it was right. A check that is wrong most of the time gets uninstalled, and
then the writes it was right about flow too.

── TWO questions, asked in this order, and never conflated ────────────────────
**The EVIDENCE decides whether anything may be edited. The FILE decides only
what to do when it may not be.** Asking them the other way round is the defect
this check shipped with, and it corrupted two files before it was caught.

    evidence is VENDOR or POSITIONAL   the reader expands, or it is prose -> REWRITE
                                       it does not                       -> DENY
    evidence is NAME-KEYED             any destination at all             -> WARN

**Why the evidence decides the edit.** A vendor prefix is proof on its own;
nothing but an AWS key is spelled `AKIA` plus sixteen upper alphanumerics. A
positional match is proof from the grammar AROUND the value — URL userinfo, an
`Authorization: Bearer` argument — which no identifier can fake. The name-keyed
rule is the one `fingerprint` documents as unable to separate a literal from an
identifier that merely looks opaque — `password`: `E2E_LOGIN_PASSWORD` — so
refusing on it would refuse ordinary source edits, and rewriting on it corrupts
them. Telling the author is the only act that is right whichever it was.

**Why a file's reader may not decide this.** `targets.py` answers exactly one
question — would `${NAME}` PARSE here — and that is worth knowing and is not
evidence about the value. This check used to let it stand in for both: a
name-keyed guess got a silent substitution in a `.sh`, a `.env`, a `.yml` or a
`.md`, and the same guess on the same bytes got a warning in a `.ts`. Two
measured corruptions followed, and the substituted name makes both worse than a
plain bad edit, because `_name_left_of` inserts the assignment's OWN key:

    readonly CB_TOKEN="https://…/access-token"   ->   readonly CB_TOKEN="${CB_TOKEN}"

Top-level code under `set -u`, so every invocation of that script died on an
unbound variable, `--help` included — and `bash -n` passed throughout, because
the file was syntactically perfect and semantically destroyed. The same
substitution in a markdown handoff rewrote a sentence's BEFORE half into its
AFTER half, so a paragraph explaining the bug arrived on disk claiming a string
had been replaced by itself.

**Why WARN and not DENY for the name-keyed class.** `X_TOKEN="<12+ chars>"` is an
ordinary line in an ordinary file, and refusing it would refuse ordinary work in
every shell script and every document that quotes one. A gate that refuses
correct work gets switched off, and then the vendor coverage goes with it.

debt: a name-keyed match in a file whose reader expands is no longer substituted,
      so a real secret sitting behind such a name now reaches disk with a warning
      instead of being removed. That is the coverage this trade gives up, and it
      is given up knowingly: the same rule could not be trusted to edit, and an
      edit made on untrustworthy evidence is the larger failure.
      Ceiling: only the NAME-keyed rule loses the edit. Vendor and positional
      findings are substituted exactly as before, in every destination.
      Upgrade trigger: a `verdict=warn` KL-WRITE row now carries `reader` in its
      detail, so the name-keyed-in-a-rewritable-file population is countable for
      the first time. Should those rows turn out to be predominantly real
      secrets, the answer is a stronger EVIDENCE rule for that class — not a
      return to editing on the name.

── the allow list is the escape hatch, and it is now real ──────────────────────
The refusal names `allowed`, and consults it. It did not before: the message
offered a remedy that changed nothing, which is worse than offering none. An
allowed path downgrades a DENY to a WARN — never to silence, because a path being
an ordinary place for an example is not evidence that this particular value is
one.

`updatedInput` carries the substitution. Measured on Claude Code 2.1.223 it is
honoured with no `permissionDecision` field at all, so a rewrite grants nothing
and cannot suppress any other guard's opinion on the same call.
"""

from .. import fingerprint, secretpaths, targets

CHECK = "KL-WRITE"
CHECK_POST = "KL-SEEN"

_TOOLS = frozenset(["Write", "Edit", "NotebookEdit", "MultiEdit"])

_RUN_LINE = "    keyless run -s <NAME> -- <the command that reads this file>"


def _slot_key(addr):
    """The field NAME an address points at, whatever it is nested inside."""
    return addr if isinstance(addr, str) else addr[-1]


def _line_preserved(before, after):
    """A substitution replaces a VALUE. It never changes the shape of the file.

    The one structural claim a rewrite makes that nothing else here checks: the
    text that comes back has the same lines as the text that went in. A finding
    whose span ran past the end of its own line broke it — the substitution
    landed on the NEXT line's key and replaced a key NAME with a reference to a
    different variable, and the message called that a repair.

    `fingerprint` closes that class twice over. This is the third place, and it
    is the one that does not have to be right about WHY: whatever a future
    pattern does, if the rewrite would not preserve the line structure it is not
    a rewrite this check is allowed to make, and the call is refused instead.

    Refused, never dropped. A silent skip here would let the write through with
    the literal intact, which is the one direction this check must never fail in.
    """
    return before.count("\n") == after.count("\n")


def run(payload, cfg):
    if payload.event != "PreToolUse" or payload.tool not in _TOOLS:
        return None

    target = payload.file_path
    # The file's reader decides whether a substitution would PARSE. It is asked
    # nothing else — in particular it is never asked whether a value is a secret,
    # which is the conflation that let a name-keyed guess edit a shell script.
    may_edit = targets.rewritable(target)

    changes = {}
    proof_kinds = []    # evidence that does not come from a name: may be edited
    guess_kinds = []    # name-keyed: reported, never edited
    sites = []
    guess_sites = []
    unsafe = []
    seen_fields = []    # slots that carried a finding — never every slot walked
    for addr, value in payload.text_slots():
        if _slot_key(addr) == "old_string":
            # `old_string` must keep matching what is on disk. Rewriting it makes
            # the edit fail to apply — a rewrite that breaks the caller is a deny
            # wearing a helpful face, and this check is not allowed to be one. It
            # is not scanned for a verdict either: the text is already in the file
            # and in the transcript, so refusing the edit that REMOVES it would
            # refuse the repair.
            continue
        findings = fingerprint.scan(value)
        if not findings:
            continue
        seen_fields.append(_slot_key(addr))
        proof = [f for f in findings if fingerprint.may_substitute(f.kind)]
        guess = [f for f in findings if not fingerprint.may_substitute(f.kind)]
        proof_kinds.extend(f.kind for f in proof)
        guess_kinds.extend(f.kind for f in guess)
        for f in guess:
            guess_sites.append(_site(addr, value, f))
        if not proof:
            continue
        # The candidate is computed for EVERY destination, and only USED where
        # this check edits. `_line_preserved` is a canary for a defect in the
        # scanner rather than a property of the file, so a canary consulted only
        # where a substitution gets applied would quietly stop asking the
        # question for every source file — which is most of what a write check
        # sees. Refused there too: a cross-line finding means the scanner is
        # producing spans it cannot be trusted to have matched, and that is
        # worth a refusal wherever it shows up.
        new_value = fingerprint.apply(value, proof)
        if not _line_preserved(value, new_value):
            unsafe.append(_slot_key(addr))
            continue
        if not may_edit:
            continue
        changes[addr] = new_value
        for f in proof:
            sites.append(_site(addr, value, f))

    if unsafe:
        return ("deny", _unsound_message(target, sorted(set(unsafe))),
                {"reason": "rewrite_would_not_preserve_lines",
                 "fields": sorted(set(unsafe))})

    if not proof_kinds and not guess_kinds:
        return None

    detail = {"fields": sorted(set(seen_fields)),
              "reader": targets.reader_class(target)}

    if changes:
        detail["shapes"] = sorted(set(proof_kinds))[:8]
        if guess_kinds:
            detail["reported_unedited"] = sorted(set(guess_kinds))
        # The fields that were CHANGED, which is narrower than the fields that
        # carried a finding whenever a name-keyed match was left in place.
        edited = sorted(set(_slot_key(a) for a in changes))
        return ("rewrite",
                _rewrite_message(target, proof_kinds, detail["shapes"],
                                 edited, sites, guess_sites),
                payload.rebuild(changes))

    if proof_kinds:
        # Proof, and the destination cannot carry a reference — so neither
        # letting it through nor substituting is right, and it is refused.
        detail["shapes"] = sorted(set(proof_kinds))[:8]
        allowed = secretpaths.is_allowed(target, payload.cwd, cfg)
        if allowed is None:
            return ("deny", _deny_message(target, proof_kinds, detail["shapes"]),
                    detail)
        detail["allowed_by"] = allowed
        return ("warn", _allowed_message(target, detail["shapes"], allowed), detail)

    detail["shapes"] = sorted(set(guess_kinds))[:8]
    return ("warn", _warn_message(target, guess_kinds, guess_sites), detail)


def _site(addr, value, finding):
    return "%s line %d" % (_slot_key(addr),
                           value.count("\n", 0, finding.start) + 1)


def _named(target):
    return target or "the file being written"


def _rewrite_message(target, kinds, shapes, fields, sites, guess_sites=()):
    tail = ""
    if guess_sites:
        tail = (
            "\n\nAlso reported and NOT changed: %d value(s) matched only because "
            "the field NAME reads like a credential. That rule cannot tell a "
            "literal from an identifier, so those bytes were left exactly as you "
            "wrote them — at %s. If one of them IS a credential, it is on disk "
            "now.\n"
            % (len(guess_sites), "; ".join(guess_sites)))
    return (
        "[%s] This write was CHANGED before it reached disk: %d credential-shaped "
        "literal(s) were replaced with `${NAME}` references. You did not ask for "
        "that substitution — read it before you build on it.\n\n"
        "  file      %s\n"
        "  shapes    %s\n"
        "  fields    %s\n"
        "  at        %s\n\n"
        "%s now holds `${NAME}` where those values were. To make it work, supply "
        "the value at run time instead of storing it:\n"
        "%s\n\n"
        "If a match was NOT a credential — a variable NAME, a fixture, a test "
        "vector, a public identifier — then the substitution is wrong and the file "
        "on disk is now wrong. Re-write it with that value spelled so it is not "
        "credential-shaped, or add its path to `allowed` in "
        "~/.config/keyless/hooks.json, which stops the substitution for that file."
        "%s"
        % (CHECK, len(kinds), _named(target), ", ".join(shapes), ", ".join(fields),
           "; ".join(sites) if sites else "unknown", _named(target), _RUN_LINE,
           tail))


def _unsound_message(target, fields):
    return (
        "[%s] Refused. A credential-shaped literal is in this write, and the "
        "substitution that would remove it does not preserve the file's line "
        "structure — so applying it would edit text this check did not match.\n\n"
        "  file      %s\n"
        "  fields    %s\n\n"
        "Nothing was written and nothing was changed. This check may rewrite a "
        "VALUE; it may never reshape a file, and it refuses rather than guessing "
        "which of the two it is about to do.\n\n"
        "This is a defect in the scanner, not in your write. What to do now:\n\n"
        "  * if the value IS a credential, supply it at run time instead:\n"
        "%s\n"
        "  * if it is not, spell it so it is not credential-shaped, or add this "
        "path to `allowed` in ~/.config/keyless/hooks.json.\n\n"
        "Either way the scanner should be reported: this message means a pattern "
        "matched across a line boundary, which `fingerprint._one_line` exists to "
        "prevent."
        % (CHECK, _named(target), ", ".join(fields), _RUN_LINE))


def _deny_message(target, kinds, shapes):
    return (
        "[%s] %d credential-shaped literal(s) are being written into %s, and that "
        "file's reader does not expand `${NAME}`. Shape(s) matched: %s. Refused.\n\n"
        "This is refused rather than rewritten because both alternatives are "
        "wrong here. Letting it through puts the credential on disk. Substituting "
        "`${NAME}` puts a reference nothing resolves into a file that has to "
        "parse — you would get a broken file and be told it was repaired.\n\n"
        "Refusing does not un-print it: the value is already in this transcript. "
        "What it still prevents is the value reaching disk, the repository, and "
        "everything that reads the file. If the credential is real, treat it as "
        "exposed and rotate it.\n\n"
        "What to do instead:\n\n"
        "  * read it at run time from the environment, and supply it with\n"
        "%s\n"
        "  * or put the value in a file whose reader DOES expand a reference — a "
        "`.env`, a shell script, a compose or CI file — where this pack "
        "substitutes it for you and the write proceeds.\n\n"
        "`keyless ls` names what it can resolve. If this value is not a "
        "credential — a fixture, a decoy, a public identifier — spell it so it is "
        "not credential-shaped, or add this path to `allowed` in "
        "~/.config/keyless/hooks.json (or `.keyless-hooks.json` in the project), "
        "which downgrades this refusal to a note. An operator can disable the "
        "pack for a session with KEYLESS_HOOKS_DISABLE=1 in the settings file's "
        "`env` block."
        % (CHECK, len(kinds), _named(target), ", ".join(shapes), _RUN_LINE))


def _warn_message(target, kinds, sites):
    return (
        "[%s] %d value(s) in this write sit behind a field NAME that reads like a "
        "credential. The write proceeded UNCHANGED — nothing was substituted and "
        "nothing was refused.\n\n"
        "  file      %s\n"
        "  at        %s\n\n"
        "This is a question rather than a verdict, and the reason is the EVIDENCE "
        "rather than the file type. The match came from the name on the left of "
        "the assignment, which you chose, so it says nothing about the value on "
        "the right: `X_TOKEN=\"<a public URL>\"` and `X_TOKEN=\"<a real token>\"` "
        "are the same three tokens in the same order.\n\n"
        "Substituting on that evidence is how this check once wrote "
        "`X_TOKEN=\"${X_TOKEN}\"` over a public URL in a shell script — the name "
        "it inserts is the assignment's OWN key, so the line came to read its own "
        "unset variable and the script died on every invocation while still "
        "parsing cleanly. It will not do that again, in any file type.\n\n"
        "If the value IS a credential, it is now on disk and in this transcript: "
        "remove it from the file, read it at run time instead, and rotate it. "
        "Supply it with\n"
        "%s\n\n"
        "If it is a URL, a variable name, a fixture or a public identifier, "
        "nothing needs doing."
        % (CHECK, len(kinds), _named(target),
           "; ".join(sites) if sites else "unknown", _RUN_LINE))


def _allowed_message(target, shapes, allowed):
    return (
        "[%s] A credential-shaped literal is being written into %s. Shape(s) "
        "matched: %s. This would be refused, and is not: the path matches "
        "`%s` in the `allowed` list, which marks it as a place examples live.\n\n"
        "The write proceeded unchanged. If this value is real rather than an "
        "example, the allow list is wrong for this file — remove the value, and "
        "rotate it."
        % (CHECK, _named(target), ", ".join(shapes), allowed))


def run_post(payload, cfg):
    """PostToolUse — a detector, never a censor.

    Measured on this harness: a PostToolUse hook cannot redact a tool result.
    `updatedOutput`, `toolResult`, `modifiedResult` and `displayContent` were all
    ignored and the model quoted the canary verbatim; only `additionalContext`
    reaches it. So there is no architecture in which this call removes a secret
    that has already been printed, and pretending otherwise would be the most
    dangerous kind of comfort.

    What it is good for: telling the reader, in the same turn, that the value it
    just received is now in the transcript and what to do about that.
    """
    if payload.event != "PostToolUse":
        return None
    response = payload.raw.get("tool_response") if isinstance(payload.raw, dict) else None
    text = _flatten(response)
    if not text:
        return None
    findings = fingerprint.scan(text, limit=8)
    if not findings:
        return None
    shapes = sorted(set(f.kind for f in findings))
    return ("warn",
            "[%s] The output just returned contains %d credential-shaped value(s) "
            "(%s). That text is now in this transcript and cannot be removed from "
            "it — a hook at this point can report the fact and nothing else. Do "
            "not copy the value into a file, a command, or a message. If the "
            "credential is real, treat it as exposed and rotate it. To use a "
            "secret without it passing through here: "
            "`keyless run -s <NAME> -- <your command>`."
            % (CHECK_POST, len(findings), ", ".join(shapes)),
            {"shapes": shapes})


def _flatten(response):
    """Tool output as text, whatever shape it arrived in.

    The Bash tool has shipped several shapes for this field — a bare string, and
    a dict under `stdout` / `output` / `content` — so a reader that bets on one
    key sees an empty result whenever the host changes, which reads exactly like
    a command that printed nothing.
    """
    if isinstance(response, str):
        return response[:200000]
    if isinstance(response, list):
        return "\n".join(_flatten(x) for x in response)[:200000]
    if isinstance(response, dict):
        parts = []
        for key in ("stdout", "stderr", "output", "content", "result", "text"):
            v = response.get(key)
            if isinstance(v, (str, list, dict)):
                parts.append(_flatten(v))
        return "\n".join(p for p in parts if p)[:200000]
    return ""
