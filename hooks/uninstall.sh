#!/usr/bin/env sh
# Remove the keyless hook pack from a Claude Code settings file.
#
#   ./uninstall.sh                  from ~/.claude/settings.json
#   ./uninstall.sh --scope project  from ./.claude/settings.json
#
# Removes exactly what install.sh added — the handlers whose command names
# keyless_hook.py, and the permission deny rules the fragment ships — and leaves
# everything else in the file untouched. `./install.sh --list-backups` prints the
# backups if you would rather restore one.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/install.py" --uninstall "$@"
