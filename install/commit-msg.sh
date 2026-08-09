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
# it is pushed without rewriting history. Five messages in this repository's own
# history carry a transcript total or a corpus size, and every one of them is
# now stuck there -- a gate that fires before the write is the only kind that
# would have helped.
#
# The grammar is `hooks/tests/test_publication.py`, which owns it, proves it
# against planted claims and measures its false positives. This file resolves
# that path from its own location, so a clone anywhere works and no home
# directory is hardcoded.
#
# FAIL-OPEN ON ABSENCE, REFUSE ON A CLAIM. No python3, or no checker, means the
# commit proceeds: this is a publication hygiene gate, not a security boundary,
# and a developer who cannot commit will delete it within the hour. A claim it
# can actually read is refused with the shape printed and no value.

set -eu

message_file=${1:-}
[ -n "$message_file" ] || exit 0

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
checker="$here/../hooks/tests/test_publication.py"

[ -f "$checker" ] || exit 0
command -v python3 >/dev/null 2>&1 || exit 0

if ! python3 "$checker" --message-file "$message_file"; then
	echo "commit-msg: refused. Edit the message and commit again." >&2
	exit 1
fi

exit 0
