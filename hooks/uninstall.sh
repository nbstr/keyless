#!/usr/bin/env sh
# Remove the keyless hook pack from a Claude Code settings file.
#
#   ./uninstall.sh                  from ~/.claude/settings.json
#   ./uninstall.sh --scope project  from ./.claude/settings.json
#
# Removes exactly what install.sh added — the handlers whose command names
# keyless_hook.py, and the permission rules the install RECORDED, never the
# shipped list — and leaves everything else in the file untouched. The record is
# the receipt, which is why a rule you wrote yourself survives this even when the
# pack ships the same rule.
set -eu
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/install.py" --uninstall "$@"
