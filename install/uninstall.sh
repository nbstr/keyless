#!/bin/bash
#
# keyless — remove the daemon.
#
# Dry run by default, like the installer. Pass --commit to apply.
#
# It removes the daemon, its account and its group. It does NOT remove the
# audit log or the store, and that is deliberate:
#
#   - The audit log is a record. Deleting the record as part of removing the
#     thing that wrote it is exactly the shape of an incident nobody can
#     reconstruct afterwards.
#   - The store holds your only copy of secrets you migrated OUT of your
#     keychain. An uninstaller that deletes them is a credential-loss event
#     wearing a helpful hat.
#
# Both paths are printed at the end so you can deal with them deliberately.
#
set -euo pipefail

COMMIT=0
[[ "${1:-}" == "--commit" ]] && COMMIT=1

DAEMON_USER="_keyless"
ACCESS_GROUP="keyless"
PLIST="/Library/LaunchDaemons/sh.keyless.keylessd.plist"
RUN_DIR="/usr/local/var/run/keyless"
LOG_DIR="/usr/local/var/log/keyless"
LIB_DIR="/usr/local/var/lib/keyless"
CONF_DIR="/usr/local/etc/keyless"

step() {
  if [[ $COMMIT -eq 1 ]]; then
    printf '+ %s\n' "$*" >&2
    "$@" || true
  else
    printf '  %s\n' "$*"
  fi
}

if [[ $COMMIT -eq 1 && "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo when you pass --commit." >&2
  exit 1
fi

[[ $COMMIT -eq 0 ]] && echo "keyless uninstaller — DRY RUN. Re-run with: sudo ./install/uninstall.sh --commit"$'\n'

step launchctl bootout system "$PLIST"
step rm -f "$PLIST"
step rm -f "$RUN_DIR/keylessd.sock"
step rm -f /usr/local/bin/keylessd
step rm -f /usr/local/bin/keyless
step rm -rf "$CONF_DIR"
step dscl . -delete "/Users/$DAEMON_USER"
step dseditgroup -o delete "$ACCESS_GROUP"

cat <<KEPT

# Left in place on purpose:
#
#   $LOG_DIR/audit.jsonl   the record of what was asked for, and by what
#   $LIB_DIR/secrets.json  possibly your only copy of migrated credentials
#
# Deal with each deliberately. Before deleting the store, put its contents
# somewhere you can still reach:
#
#   sudo cat $LIB_DIR/secrets.json
#
# Note that once the group is gone the audit log is owned by a uid that no
# longer exists, so read it before removing the account if you care about it.
KEPT

[[ $COMMIT -eq 0 ]] && echo "# DRY RUN — nothing above was executed."
