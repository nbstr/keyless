"""KL-SWITCH — turning the pack off, or rewriting the files that configure it,
is not something a tool call inside this session reaches.

Every other check in this pack answers "does this call touch a credential".
This one answers a question one level up: could the call in front of us
change whether any check answers that question at all — this call, or every
call after it. The adversary here is not a leaked value; it is a session that
routes around every other check by turning them off first.

Three shapes, one refusal — and one narrow exception, in the section below:

    the disable/uninstall verb    `keyless disable`, `keyless uninstall`,
                                   and the pack's own uninstall scripts —
                                   whatever they are asked to do, they end
                                   with `enabled` no longer true
    a tool write                  Write/Edit/MultiEdit/NotebookEdit aimed at
                                   this pack's own config
    a shell write                 the same files, reached from Bash — a
                                   redirect, `tee`, `cp`, `sed -i`, a payload
                                   handed to an interpreter

── two files, and only one of them configures a guard ──────────────────────

`hooks.json` and the project-layer `.keyless-hooks.json` are the guard config.
Rewriting either disarms the pack, so every shape above stays refused for them,
in every spelling, with no exception at all.

`config.json` is a different animal wearing the same coat. It is the CLI's
credential DECLARATIONS — a `secrets` map of name to `{store, vault, item,
field}` — and it holds no credential value, only coordinates. Nothing in this
pack reads it to reach a verdict: `served` reads that map's KEYS and spends them
on the WORDING of a remedy inside a refusal it has already decided. So a name
added there cannot turn any deny into an allow.

What CAN be weakened through that file is real, and none of it is a new name:

    `stores`          every backend's BINARY PATH lives there, and
                      `keyless run` executes it
    an existing name  repointed, it reads a credential from somewhere else
    a removed name    what was declared, and enumerable, narrows

So the rule is stated as the combination it EXCLUDES, never as the first token
that matches: `config.json`, and nothing else, may GAIN keys under `secrets`,
with every pre-existing name's route and every other part of the document
deeply unchanged, judged on content this process can actually compute.
Everything else about that file stays refused.

`SecretRoute` in `src/config.rs` is what makes a gained name inert rather than
merely narrow: it carries coordinates only — no binary, no socket, no timeout,
no command — and the loader ignores a field it does not know, so an unrecognised
key inside a new entry executes nothing.

A SHELL write to `config.json` is refused whatever it would have written. A
redirect's content does not exist when this check runs, so there is nothing to
judge, and a gate that guesses is wrong in the direction that ships.
`NotebookEdit` is refused for the reason it always was: it addresses a cell, not
this file's text.

Anything undeterminable is refused — an absent file, either side unparseable, an
`old_string` that is missing or matches more than once, a document past the size
the CLI's own loader will read. That is the call `secretpaths` already makes for
the credential list, one level up.

Why the allowance exists rather than being tidier without it: declaring a name
is the one act this file is FOR, the CLI has no verb that performs it, and the
refusal sat in front of a change that cannot weaken anything. A gate that
refuses correct work is a gate its owner switches off, and then it protects
nothing.

A *read* of the config is not this check's business; the reader heads below
are the ones a person or an agent legitimately reaches for to see what is
configured, and refusing them would make the pack harder to operate without
making it any harder to switch off. Anything not on that closed list is
refused — including every write-shaped command — because the set of programs
that can rewrite a file is unbounded and a name missing from an allowlist
must fail toward blocking, the same call `secretpaths` makes for the
credential list this pack already protects.

The refusal below names none of `keyless enable`, `KEYLESS_HOOKS_DISABLE`, an
edit to `hooks.json`, or any other way around it. Those exist and they work —
they are how a person, not this session, puts the pack back where they want
it — and printing the sentence that does it hands an agent a recipe for
undoing every other guard in one line. What the message says instead is where
that decision is made: outside the session, by someone at a terminal.
"""

import os
import re

from .. import declarations, secretpaths
from ..executed import command_texts
from ..shellview import (delegated_head, expand_local_assignments,
                         file_operands_spanned, flatten_substitutions, head_of,
                         head_or_wrapper,
                         positional_span, rest_after_head, statements,
                         strip_heredocs, substitution_payloads, tokens, unquote,
                         words)

CHECK = "KL-SWITCH"

_WRITE_TOOLS = frozenset(["Write", "Edit", "MultiEdit", "NotebookEdit"])

# The two files this pack itself reads. They sit in the same directory, one
# basename apart, and that adjacency is ALL they have in common — which is why
# they are two constants and not one pair. One configures the guards; the other
# declares credential coordinates and configures nothing here. The module
# docstring carries which act is refused for which, and why.
_HOOKS_BASENAME = "hooks.json"
_CONFIG_BASENAME = "config.json"

# The project-layer file `config.py` merges on top of the user's own — matched
# by basename alone, at any depth, because a project checkout can put it
# anywhere.
_PROJECT_GUARD_BASENAME = ".keyless-hooks.json"

# Programs that cannot rewrite a file's content, only report on it — the
# closed side of the allowlist, same discipline as `config.DEFAULT_NON_READERS`
# and for the same reason: the set of programs that CAN write is unbounded, so
# naming the readers is what fails toward blocking rather than toward allowing.
_READ_HEADS = frozenset([
    "cat", "less", "more", "head", "tail", "jq", "grep", "egrep", "fgrep", "rg",
    "wc", "diff", "cmp", "ls", "stat", "file", "bat", "test", "[", "[[",
    "md5", "shasum", "sha256sum", "echo", "printf",
])

# `git`'s own read-only subcommands. `git show`, `git log -p` and friends
# print a file's content the same way `cat` does and belong on the list above
# in spirit; they are kept as a pair with the binary name because `git reset`
# and `git checkout` sit one word away and DO write.
_GIT_READ_SUBCOMMANDS = frozenset([
    "add", "diff", "log", "show", "status", "blame", "ls-files", "commit", "grep",
])

_DIR_SAFE_HEADS = frozenset(["cd", "pushd", "mkdir"])

_HELP_TOKENS = frozenset(["--help", "-h", "-?"])

# Flags `keyless` accepts before the verb. `--config`/`--audit` consume the
# word after them; `--no-audit` and every other dashed token are skipped in
# place, so a flag this table has never heard of still does not stop the walk
# from reaching the verb.
_TAKES_VALUE = frozenset(["--config", "--audit"])

# Output redirects only. `<`, `<<<` and `<&` read a file rather than write one,
# and are deliberately absent — a guard file named after one of those is a
# read, judged by the reader-head rule below like any other.
_REDIRECT_OUT = re.compile(r"^\d*(?:>>|>\||&>>|&>|>)")


def run(payload, cfg):
    if payload.event != "PreToolUse":
        return None
    if payload.tool in _WRITE_TOOLS:
        return _tool_write_hit(payload)
    if payload.tool != "Bash":
        return None
    cmd = payload.command
    if not cmd or not cmd.strip():
        return None

    # Every Bash call reaches this check, and nearly none of them can name the
    # switch or a guard file. A substring test on the command with quotes and
    # backslashes collapsed — the spellings `key''less` and `hooks.j\son` the
    # shell reads as the plain words — settles those before any tokenizing.
    # It only ever skips; whenever a needle is present both scans run in full.
    flat = _collapse(cmd)
    targets = _guard_targets()
    dirs = {os.path.dirname(target) for target in targets}
    base = strip_heredocs(cmd)

    if "keyless" in flat or "uninstall" in flat:
        hit = _scan_disable_and_uninstall(cmd, base, cfg)
        if hit:
            return hit
    needles = {os.path.basename(path) for path in targets | dirs}
    needles.add(_PROJECT_GUARD_BASENAME)
    if any(needle in flat for needle in needles):
        return _scan_guard_writes(base, payload, cfg, targets, dirs)
    return None


def _collapse(text):
    return text.replace("'", "").replace('"', "").replace("\\", "")


# ── the off-switch verb, and the pack's own uninstallers ───────────────────

def _keyless_verb(rest):
    """The word `keyless` acts on, past every global flag — or "" for none.

    "" also covers a bare `keyless` with no verb at all, which prints its own
    help and is not this check's business.
    """
    toks = tokens(rest)
    i, n = 0, len(toks)
    while i < n:
        tok = toks[i]
        if tok in _TAKES_VALUE:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return tok
    return ""


def _is_keyless_help(rest):
    toks = tokens(rest)
    if any(tok in _HELP_TOKENS for tok in toks):
        return True
    return _keyless_verb(rest) == "help"


def _keyless_disable_hit(stmt):
    if _collapse(head_of(stmt)) != "keyless":
        return False
    rest = rest_after_head(stmt)
    if _is_keyless_help(rest):
        return False
    return _collapse(_keyless_verb(rest)) in ("disable", "uninstall")


def _raw_head(stmt):
    """The head token exactly as written — leading path and all.

    `head_of` deliberately strips a leading path so `/usr/bin/keyless` and
    `keyless` compare equal; recovering the path here is for the one question
    that needs it — telling `hooks/uninstall.sh` apart from any other script
    that happens to share its basename. Rebuilt from the offset `head_of`'s own
    walk already computed, so this never re-derives the wrapper/assignment
    skipping it depends on.
    """
    name, end = head_or_wrapper(stmt)
    if not name or end < 0:
        return ""
    for start, stop in words(stmt):
        if stop == end:
            return stmt[start:stop]
    return ""


def _first_operand(rest):
    """The first non-flag word, unquoted — for the argument after an
    interpreter's own name, which is the script it is about to run."""
    for start, end in words(rest):
        tok = rest[start:end]
        if tok.startswith("-"):
            continue
        return unquote(tok)
    return ""


def _uninstaller_hit(stmt, head, cfg):
    """True for a statement that runs `hooks/uninstall.sh`, or `install.py` /
    `install.sh` with `--uninstall` — the pack's own removal path, run
    directly or handed to a shell/language interpreter."""
    rest = rest_after_head(stmt)
    if head in cfg.interpreters:
        target = _first_operand(rest)
    else:
        target = unquote(_raw_head(stmt))
    target = target.replace("\\", "")
    if not target:
        return False
    if target.endswith("hooks/uninstall.sh"):
        return True
    base = target.rsplit("/", 1)[-1]
    if base in ("install.py", "install.sh"):
        return "--uninstall" in tokens(rest)
    return False


def _scan_disable_and_uninstall(cmd, base, cfg):
    # `bash -c "…"`, `$(…)` and backticks are re-parsed as their own commands,
    # the way KL-VAULT reads a subcommand handed to an interpreter — a
    # statement-level act, not an operand, so it needs its own head rather than
    # a candidate string pulled out of the payload. `executed.command_texts` is
    # the one answer both gates share for which texts the shell will run.
    texts = [base, expand_local_assignments(base)] + command_texts(cmd, cfg.interpreters)
    for text in texts:
        for stmt in statements(text):
            if _keyless_disable_hit(stmt):
                return ("deny", _message("switch"), {"shape": "keyless-verb"})
            head = head_of(stmt)
            if _uninstaller_hit(stmt, head, cfg):
                return ("deny", _message("uninstall"), {"shape": "uninstaller"})
    return None


# ── the pack's own config files, read or written ───────────────────────────

# Which of the pack's own files a path names. Two roles rather than one flag,
# because the two are refused on different terms — see the module docstring.
_ROLE_GUARD = "guard-config"
_ROLE_DECLARATIONS = "declarations"


def _guard_target_sets():
    """`(guard-config paths, declarations paths)` — every literal path each of
    the pack's two files could resolve to.

    Two sets rather than one, because a BASENAME cannot tell them apart and the
    consequence of getting it wrong is not symmetric. `KEYLESS_HOOKS_CONFIG` is
    an ordinary environment variable and may perfectly well name a file spelled
    `config.json` — and then that file IS the guard config. So a path answering
    to both sets is the guard config, and the declarations set is what is LEFT
    after subtracting it: the ambiguous case lands on the refusing side by
    construction rather than by a test somebody remembered to write.

    Not tested against the filesystem — a target absent right now is still a
    target the call in front of us would create, and `secretpaths` states the
    same rule for the credential list this pack already protects.
    """
    home = os.path.expanduser("~")
    guard, declared = set(), set()
    if home:
        base = os.path.join(home, ".config", "keyless")
        guard.add(os.path.normpath(os.path.join(base, _HOOKS_BASENAME)))
        declared.add(os.path.normpath(os.path.join(base, _CONFIG_BASENAME)))
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        base = os.path.join(xdg, "keyless")
        guard.add(os.path.normpath(os.path.join(base, _HOOKS_BASENAME)))
        declared.add(os.path.normpath(os.path.join(base, _CONFIG_BASENAME)))
    hooks_override = os.environ.get("KEYLESS_HOOKS_CONFIG")
    if hooks_override:
        guard.add(os.path.normpath(hooks_override))
    config_override = os.environ.get("KEYLESS_CONFIG")
    if config_override:
        declared.add(os.path.normpath(config_override))
    return frozenset(guard), frozenset(declared - guard)


def _guard_targets():
    """Every literal path any of the pack's own files could resolve to.

    The union, for the scans that ask one question of both files: which needles
    are worth tokenizing for, which directories reach them, and whether a shell
    statement names one — a shell write is refused whichever of the two it hits.
    """
    guard, declared = _guard_target_sets()
    return guard | declared


def _guard_role(candidate, cwd, guard_targets, declaration_targets):
    """`_ROLE_GUARD`, `_ROLE_DECLARATIONS`, or None for a path that is neither.

    The project-layer file is matched by basename at any depth and is always the
    guard role: it is read by `config.load` to configure the checks themselves.
    """
    if not candidate:
        return None
    stripped = candidate.strip().strip("'\"")
    if not stripped:
        return None
    if os.path.basename(stripped) == _PROJECT_GUARD_BASENAME:
        return _ROLE_GUARD
    forms = set(secretpaths.expansions(candidate, cwd))
    resolved = secretpaths.resolve(candidate, cwd)
    if resolved:
        forms.add(resolved)
    forms = {os.path.normpath(form) for form in forms}
    if forms & guard_targets:
        return _ROLE_GUARD
    if forms & declaration_targets:
        return _ROLE_DECLARATIONS
    return None


def _is_guard_path(candidate, cwd, targets):
    """Does this candidate name one of the pack's own files, given a set of them.

    Every target is handed over as the guard set, so this answers the one
    question its callers ask and cannot accidentally inherit the declarations
    allowance: the allowance is decided in `_tool_write_hit`, on content, and a
    caller with no content to judge must never reach it.
    """
    return _guard_role(candidate, cwd, targets, frozenset()) is not None


def _tool_write_hit(payload):
    guard_targets, declaration_targets = _guard_target_sets()
    role = _guard_role(payload.file_path, payload.cwd,
                       guard_targets, declaration_targets)
    if role is None:
        return None
    if role == _ROLE_DECLARATIONS and _declares_a_name(payload):
        # A name gained, nothing else moved. Silence rather than an `allow`:
        # this pack never emits one (see `engine`), and silence is what leaves
        # every other check free to judge the same call — including the one that
        # refuses a credential VALUE written into this very content.
        return None
    kind = "declarations-write" if role == _ROLE_DECLARATIONS else "tool-write"
    return ("deny", _message(kind), {"tool": payload.tool, "role": role})


def _declares_a_name(payload):
    """True only for a write that leaves keyless's `config.json` holding the
    same document plus one or more new `secrets` keys.

    The on-disk content is read HERE, immediately before the answer, and read
    again on the next call rather than remembered: a decision cached across
    calls would be a decision about a file that has since moved. `declarations`
    owns everything the answer rests on, its refusals included.
    """
    target = secretpaths.resolve(payload.file_path, payload.cwd)
    if not target:
        return False
    before = declarations.read_bounded(target)
    if before is None:
        return False
    after = declarations.written_content(payload, before)
    if after is None:
        return False
    return declarations.adds_only_names(before, after)


def _redirect_targets(stmt):
    """Every raw token this statement's output is redirected onto."""
    toks = [stmt[a:b] for a, b in words(stmt)]
    out = []
    for i, tok in enumerate(toks):
        m = _REDIRECT_OUT.match(tok)
        if not m:
            continue
        remainder = tok[m.end():]
        if remainder:
            out.append(unquote(remainder))
        elif i + 1 < len(toks):
            out.append(unquote(toks[i + 1]))
    return out


def _is_reader(head, stmt):
    if head in _READ_HEADS:
        return True
    if head == "find":
        # A path lister, until it is told to delete or to run something on
        # what it matched.
        return "-delete" not in tokens(stmt) and not delegated_head(stmt)
    if head == "git":
        sub, _offset = positional_span(stmt, 0)
        return sub in _GIT_READ_SUBCOMMANDS
    return False


def _scan_guard_writes(base, payload, cfg, targets, dirs):
    # The same four views KL-FILE reads a Bash command through: as written, an
    # assignment resolved (`F=~/.config/keyless/hooks.json; echo x > $F`), a
    # substitution flattened into its enclosing statement, and a substitution
    # body scanned on its own. `base` arrives with heredoc bodies blanked, for
    # the same reason KL-FILE blanks them: a runbook that quotes one of these
    # paths in prose is not an act on it.
    #
    # `dirs` are the directories the guard files live in. Naming one of these
    # to a program that is not a reader reaches every file inside it: a
    # recursive copy into the directory, a recursive delete of it, or a rename
    # of it never spells a basename at all.
    texts = [base, expand_local_assignments(base), flatten_substitutions(base)]
    texts.extend(substitution_payloads(base))
    seen = set()
    for text in texts:
        if text in seen:
            continue
        seen.add(text)
        hit = _scan_statements_for_guard(text, payload, cfg, targets, dirs)
        if hit:
            return hit
    return None


def _cd_target(stmt, head, cwd):
    """Where a `cd`/`pushd` statement leaves the shell, or None when it is not
    one or its operand cannot be resolved with confidence."""
    if head not in ("cd", "pushd"):
        return None
    operand, _offset = positional_span(stmt, 0)
    if not operand:
        return None
    return secretpaths.resolve(operand, cwd)


def _scan_statements_for_guard(text, payload, cfg, targets, dirs):
    # The working directory is followed through the command, because
    # `cd ~/.config/keyless && echo '{}' > hooks.json` names the file only
    # relative to a directory the payload's own `cwd` never mentions.
    cwd = payload.cwd
    for stmt in statements(text):
        head = head_of(stmt)
        moved = _cd_target(stmt, head, cwd)
        if moved is not None:
            cwd = moved
            continue
        redirected = _redirect_targets(stmt)
        reader = _is_reader(head, stmt)
        for cand, _tok_start in file_operands_spanned(stmt, head, cfg.interpreters):
            if _is_guard_path(cand, cwd, targets):
                if cand in redirected or not reader:
                    return ("deny", _message("shell-write"), {"head": head})
                continue
            # Entering or creating the directory writes nothing in it; whatever
            # writes a guard file there afterwards is judged on its own statement.
            if (not reader and head not in _DIR_SAFE_HEADS
                    and secretpaths.resolve(cand, cwd) in dirs):
                return ("deny", _message("shell-write"), {"head": head, "dir": True})
    return None


# ── the message ─────────────────────────────────────────────────────────────

_WHAT = {
    "switch": "This command turns the pack's guards off.",
    "uninstall": "This command runs the pack's own uninstaller.",
    "tool-write": "This edit targets one of the files that configure the guards.",
    "shell-write": "This command writes to one of the files that configure the guards.",
}


# Said only where the refused call named a file: a script handed the path is
# refused because it could write, whether or not it meant to, and the reader
# that wanted to see the configuration has a door that is not refused.
_READS = ("\n\nReading those files is not refused — `cat` or `jq` show what is "
          "configured, and `keyless ls` and `keyless doctor` report it.")


# The declarations file gets its own refusal, because the generic one above is
# wrong about it twice over: that file configures no guard, and there IS one act
# on it this session reaches. Saying which is not a recipe for undoing anything
# — it is the act that was just refused, described precisely enough to be
# retried correctly — and a refusal that withholds it teaches a reader to retry
# blind, which is how a gate earns the reputation that gets it removed.
#
# It still names no way to switch a guard OFF, which is the property the generic
# message has and this one must keep.
_DECLARATIONS = (
    "[%s] This write changes more of keyless's own `config.json` than the "
    "`secrets` map. Refused.\n\n"
    "That file holds no credential value — it holds coordinates — so DECLARING "
    "a name in it is not refused. A write that adds names under `secrets`, "
    "leaves every name already declared pointing exactly where it pointed, and "
    "leaves every other part of the document alone, goes through. This one does "
    "not.\n\n"
    "What is refused, and why each one is not a detail:\n"
    "  * anything outside `secrets`. Every backend's binary path lives there, "
    "and `keyless run` executes it.\n"
    "  * a name removed, or one already declared whose route moves. Either "
    "changes where a credential is read from.\n"
    "  * a write whose result cannot be computed from here — a shell redirect, "
    "an absent or unparseable file, an `old_string` that is missing or matches "
    "more than once. Undecidable is refused, never guessed.\n\n"
    "Reading the file is not refused: `cat` or `jq` show what is declared, and "
    "`keyless ls` reports it with `keyless items` and `keyless fields` naming "
    "what a store calls an item and a field — none of the three prints a "
    "value.\n\n"
    "Everything else about this file is a person's decision, made at a terminal "
    "outside this session. This refusal does not name another way to do it, "
    "because there is not meant to be one this session can reach."
    % CHECK)


def _message(kind):
    if kind == "declarations-write":
        return _DECLARATIONS
    return (
        "[%s] %s Refused.\n\n"
        "Switching the guards off, or changing the files that configure them, "
        "is a person's decision, made at a terminal outside this session — it "
        "is not something an agent session reaches from in here, whatever the "
        "call is spelled as.\n\n"
        "This refusal does not name another way to do it, because there is not "
        "meant to be one this session can reach.%s"
        % (CHECK, _WHAT.get(kind, "This call reaches the pack's own switch."),
           _READS if kind in ("tool-write", "shell-write") else ""))
