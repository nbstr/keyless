#!/bin/sh
# A `commit-msg` hook that refuses a commit message stating a measurement of one
# machine or account.
#
# Install it into this repository:
#
#     ln -sf ../../install/commit-msg.sh .git/hooks/commit-msg
#
# Why this exists next to the test that already checks the same thing: the test
# runs after the message is written, and a commit message cannot be edited once
# it is pushed without rewriting history. Messages in this repository's own
# history carry a transcript total or a corpus size, and every one of them is
# stuck there until someone rewrites history to scrub it -- a gate that fires
# before the write is the only kind that would have helped.
#
# The grammar is `hooks/tests/test_publication.py`, which owns it, proves it
# against planted claims and measures its false positives.
#
# HOW THE CHECKER IS FOUND, and why not from `dirname "$0"`: this file is
# invoked through `.git/hooks/commit-msg`, and git -- like `sh` -- sets `$0` to
# the path it invoked, not to the file that path leads to. Resolving relative to
# `$0` therefore looks under `.git/hooks/` and finds nothing, whether the hook is
# a symlink or a copy. Resolving the symlink fixes only the symlink shape: a
# copy genuinely lives in `.git/hooks/`, so its own location says nothing about
# where the repository is. The repository root is what the checker's path is
# actually relative to, so ask git for the repository root. `$0` remains a
# fallback for the case where git cannot answer -- running this script by hand
# from outside a work tree.
#
# FAIL OPEN ON A MISSING INTERPRETER, LOUD ON A MISSING CHECKER, REFUSE ON A
# CLAIM. No python3 means the commit proceeds: this is a publication hygiene
# gate, not a security boundary, and it must not be the thing standing between a
# developer and a commit on a machine that simply has no python. A missing
# checker is a different animal -- the checker is TRACKED in this repository, so
# its absence means the install or the tree is broken, and a guard that cannot
# find itself passing silently is exactly the failure this hook exists to
# prevent. That one says so and exits non-zero. A claim it can actually read is
# refused with the shape printed and no value.

set -eu

message_file=${1:-}
[ -n "$message_file" ] || exit 0

relative_checker=hooks/tests/test_publication.py

checker=
root=$(git rev-parse --show-toplevel 2>/dev/null) || root=
if [ -n "$root" ] && [ -f "$root/$relative_checker" ]; then
	checker="$root/$relative_checker"
else
	here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
	if [ -f "$here/../$relative_checker" ]; then
		checker="$here/../$relative_checker"
	fi
fi

if [ -z "$checker" ]; then
	echo "commit-msg: cannot find $relative_checker, so nothing was checked." >&2
	echo "This hook refuses rather than passing: a publication gate that cannot" >&2
	echo "find its own grammar accepts everything, and a commit message cannot be" >&2
	echo "edited once it is pushed. Restore the file, re-run scripts/install-hooks.sh," >&2
	echo "or remove the hook deliberately." >&2
	exit 1
fi

command -v python3 >/dev/null 2>&1 || exit 0

if ! python3 "$checker" --message-file "$message_file"; then
	echo "commit-msg: refused. Edit the message and commit again." >&2
	exit 1
fi

exit 0
