#!/bin/bash
#
# keyless — remove the daemon.
#
# Dry run by default, like the installer. Pass --commit to apply.
#
# THIS IS HALF THE UNINSTALL. It removes the daemon, its account and its group.
# The config, the guards' registration in your agent's settings and the agent
# instructions are the other half, and they belong to:
#
#   keyless uninstall
#
# The two do not overlap: that verb walks a receipt of what `keyless setup`
# created and touches nothing under /usr/local; this script owns everything that
# needed root to place.
#
# It does NOT remove the audit log or the store, and that is deliberate:
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
# The daemon's own vendor login IS removed, and the asymmetry is the point. It
# is not anybody's only copy of anything — the identity exists at the vendor,
# where you created it and where you can revoke it — so nothing is lost by
# deleting it, while leaving a long-lived credential behind on a machine that
# no longer has a daemon to use it is a landmine with no upside.
#
# Deleting the file is not revoking the credential. Revoke the machine identity
# at the vendor too; that is the half no script here can do.
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
step rm -f "$LIB_DIR/infisical.json"
step rm -f "$LIB_DIR/onepassword.json"
step rm -f "$LIB_DIR/proton.json"
# The session store and the local key that decrypts it. Removed together and
# not one without the other: a key left beside a deleted store is useless, and
# a store left beside a deleted key is a directory `pass-cli` will FORCE A
# LOGOUT over the next time anything points at it.
step rm -rf "$LIB_DIR/proton-session"
step dscl . -delete "/Users/$DAEMON_USER"
step dseditgroup -o delete "$ACCESS_GROUP"

cat <<KEPT

# Left in place on purpose:
#
#   $LOG_DIR/audit.jsonl          the record of what was asked for, and by what
#   $LOG_DIR/audit.jsonl.anchor   which row that record ends on
#   $LIB_DIR/secrets.json         possibly your only copy of migrated credentials
#
# Removed above: $LIB_DIR/infisical.json, $LIB_DIR/onepassword.json,
# $LIB_DIR/proton.json and $LIB_DIR/proton-session -- the daemon's own vendor
# logins and the Proton session store beside one of them. If you gave it an
# Infisical machine identity, a 1Password service account or a Proton agent
# token, REVOKE that identity at the vendor now. The files are gone from this
# machine and the credentials are not dead until you do.
#
# The Proton one is the one most likely to be forgotten, because it is the only
# one that would have died on its own: an agent token expires, so an unrevoked
# one is a working credential with a date on it rather than a permanent one.
# That is a smaller window, not a closed one.
#
# Keep the anchor with the log or drop both. It is the only thing that says how
# long the log is supposed to be, so a log kept without it can lose rows from
# the end and still verify clean.
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
