#!/usr/bin/env sh
# Install the keyless hook pack into a Claude Code settings file.
#
#   ./install.sh                    into ~/.claude/settings.json
#   ./install.sh --scope project    into ./.claude/settings.json
#   ./install.sh --dry-run          print the merge, write nothing
#
# Every flag is passed through to install.py, which does the work: it parses the
# existing file, merges rather than overwrites, takes a timestamped backup, and
# re-parses the merged text before replacing anything.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/install.py" "$@"
