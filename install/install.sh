#!/bin/bash
#
# keyless — create the daemon's user and install keylessd.
#
# ---------------------------------------------------------------------------
# THIS SCRIPT PRINTS WHAT IT WOULD DO AND CHANGES NOTHING UNLESS YOU PASS
# --commit. Read the plan first. Every line it prints is a command it will run
# verbatim, in that order.
# ---------------------------------------------------------------------------
#
# What it builds, and why each piece is shaped the way it is:
#
#   group  keyless    contains the daemon AND you. It is what lets your
#                     sessions reach the socket while leaving the store
#                     unreadable.
#   user   _keyless   owns the store and the audit log. No shell, no home, no
#                     login. Its whole purpose is to be a uid you are not.
#
#   /usr/local/etc/keyless/keylessd.json   0644 root:wheel     the policy — not secret, and you want to read it
#   /usr/local/var/run/keyless/            0755 _keyless:keyless   the socket lives here
#   /usr/local/var/log/keyless/audit.jsonl 0640 _keyless:keyless   you READ it, you cannot WRITE it
#   /usr/local/var/lib/keyless/secrets.json 0600 _keyless:keyless  you cannot read it at all
#
# The audit mode is the whole unforgeability claim. `keyless` hashes each row
# as sha256(previous_hash || row), which detects an edit only if the editor
# cannot also recompute every hash after it. A writer with write access can.
# 0640 is what makes your sessions not that writer.
#
# ---------------------------------------------------------------------------
# WHAT THIS SCRIPT CANNOT DO FOR YOU, AND WHY IT MATTERS MORE THAN THE REST
# ---------------------------------------------------------------------------
#
# Installing this daemon next to a login keychain that still holds your
# secrets closes NOTHING. `security find-generic-password -s <service> -w`
# will still return plaintext, with no prompt, to every session and every
# subagent. The daemon is necessary and it is not sufficient.
#
# The step that actually shuts the hole is a MIGRATION: move each secret into
# something only _keyless can read, then DELETE it from your login keychain.
# Until the delete happens you have two doors and have locked one.
#
# This script will not do that. It cannot know which of your keychain items
# are meant to be reachable by hand, and a script that deletes credentials it
# guessed at is worse than the problem. See install/README.md.
#
set -euo pipefail

COMMIT=0
[[ "${1:-}" == "--commit" ]] && COMMIT=1

DAEMON_USER="_keyless"
ACCESS_GROUP="keyless"
CONF_DIR="/usr/local/etc/keyless"
RUN_DIR="/usr/local/var/run/keyless"
LOG_DIR="/usr/local/var/log/keyless"
LIB_DIR="/usr/local/var/lib/keyless"
BIN_DIR="/usr/local/bin"
PLIST="/Library/LaunchDaemons/sh.keyless.keylessd.plist"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

# The account this daemon serves. Under sudo, SUDO_USER is the human.
TARGET_USER="${SUDO_USER:-$USER}"

step() {
  if [[ $COMMIT -eq 1 ]]; then
    printf '+ %s\n' "$*" >&2
    "$@"
  else
    printf '  %s\n' "$*"
  fi
}

note() { printf '\n# %s\n' "$*"; }

# --- preflight -------------------------------------------------------------

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer is macOS only. See install/README.md for systemd." >&2
  exit 1
fi

if [[ $COMMIT -eq 1 && "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo when you pass --commit." >&2
  exit 1
fi

if [[ "$TARGET_USER" == "root" ]]; then
  echo "Refusing to install for root. Run this as your own user under sudo." >&2
  exit 1
fi

for binary in keyless keylessd; do
  if [[ ! -x "$REPO/target/release/$binary" ]]; then
    echo "Build first: cargo build --release  (missing target/release/$binary)" >&2
    exit 1
  fi
done

# Pick ids below 500 so macOS hides the account from the login window. Chosen
# by scanning rather than hardcoded: a fixed uid collides on exactly the
# machines where a collision is most confusing to diagnose.
pick_id() {
  local kind="$1" candidate=300
  while :; do
    if ! dscl . -list "$kind" UniqueID 2>/dev/null | awk '{print $2}' | grep -qx "$candidate" &&
       ! dscl . -list "$kind" PrimaryGroupID 2>/dev/null | awk '{print $2}' | grep -qx "$candidate"; then
      echo "$candidate"
      return
    fi
    candidate=$((candidate + 1))
  done
}

EXISTING_UID="$(dscl . -read "/Users/$DAEMON_USER" UniqueID 2>/dev/null | awk '{print $2}' || true)"
EXISTING_GID="$(dscl . -read "/Groups/$ACCESS_GROUP" PrimaryGroupID 2>/dev/null | awk '{print $2}' || true)"
NEW_GID="${EXISTING_GID:-$(pick_id /Groups)}"
NEW_UID="${EXISTING_UID:-$(pick_id /Users)}"

if [[ $COMMIT -eq 0 ]]; then
  cat <<PLAN

keyless installer — DRY RUN. Nothing below has been executed.
Re-run with:  sudo ./install/install.sh --commit

  daemon user   $DAEMON_USER  (uid $NEW_UID)$([[ -n "$EXISTING_UID" ]] && echo "  [already exists]")
  access group  $ACCESS_GROUP  (gid $NEW_GID)$([[ -n "$EXISTING_GID" ]] && echo "  [already exists]")
  served user   $TARGET_USER

Commands, in order:
PLAN
fi

# --- the group, which is the only thing that connects you to the daemon -----

note "The access group. You and the daemon are both in it; nobody else is."
step dseditgroup -o create -i "$NEW_GID" -r "keyless socket access" "$ACCESS_GROUP"
step dseditgroup -o edit -a "$TARGET_USER" -t user "$ACCESS_GROUP"

# --- the daemon's user -----------------------------------------------------

note "The daemon's account. No shell, no home, hidden from the login window."
step dscl . -create "/Users/$DAEMON_USER"
step dscl . -create "/Users/$DAEMON_USER" RealName "keyless secrets daemon"
step dscl . -create "/Users/$DAEMON_USER" UserShell /usr/bin/false
step dscl . -create "/Users/$DAEMON_USER" NFSHomeDirectory /var/empty
step dscl . -create "/Users/$DAEMON_USER" UniqueID "$NEW_UID"
step dscl . -create "/Users/$DAEMON_USER" PrimaryGroupID "$NEW_GID"
step dscl . -create "/Users/$DAEMON_USER" IsHidden 1
step dscl . -create "/Users/$DAEMON_USER" Password '*'
step dseditgroup -o edit -a "$DAEMON_USER" -t user "$ACCESS_GROUP"

# --- binaries --------------------------------------------------------------

note "Binaries."
step install -d -m 0755 "$BIN_DIR"
step install -m 0755 "$REPO/target/release/keyless" "$BIN_DIR/keyless"
step install -m 0755 "$REPO/target/release/keylessd" "$BIN_DIR/keylessd"

# --- directories -----------------------------------------------------------

note "Directories. The socket's parent is NOT writable by you: if it were, you
# could delete the socket and bind your own in its place."
step install -d -m 0755 -o root -g wheel "$CONF_DIR"
step install -d -m 0755 -o "$DAEMON_USER" -g "$ACCESS_GROUP" "$RUN_DIR"
step install -d -m 0755 -o "$DAEMON_USER" -g "$ACCESS_GROUP" "$LOG_DIR"
step install -d -m 0700 -o "$DAEMON_USER" -g "$ACCESS_GROUP" "$LIB_DIR"

note "The store. 0600 under the daemon's uid: unreadable by you, by every
# session you start, and by every subagent any of them spawns."
step install -m 0600 -o "$DAEMON_USER" -g "$ACCESS_GROUP" /dev/null "$LIB_DIR/secrets.json"

note "The audit log. 0640: you read it, you cannot write it. That asymmetry
# is what the hash chain needs in order to mean anything."
step install -m 0640 -o "$DAEMON_USER" -g "$ACCESS_GROUP" /dev/null "$LOG_DIR/audit.jsonl"

# --- the policy ------------------------------------------------------------

note "Pin the client. The hash is of the binary's code signature, and it is
# what the daemon compares against the LIVE image of whoever connects."
if [[ $COMMIT -eq 1 ]]; then
  CLIENT_HASH="$("$BIN_DIR/keylessd" pin --path "$BIN_DIR/keyless" 2>/dev/null)"
  TARGET_UID="$(id -u "$TARGET_USER")"
else
  CLIENT_HASH="<keylessd pin --path $BIN_DIR/keyless>"
  TARGET_UID="$(id -u "$TARGET_USER" 2>/dev/null || echo '<uid>')"
fi

CONFIG_JSON=$(cat <<JSON
{
  "socket": "$RUN_DIR/keylessd.sock",
  "audit": "$LOG_DIR/audit.jsonl",
  "cache_ttl_seconds": 60,
  "idle_timeout_seconds": 15,
  "peer": {
    "allow_uids": [$TARGET_UID],
    "allow_images": ["$CLIENT_HASH"]
  },
  "stores": {
    "file": { "enabled": true, "path": "$LIB_DIR/secrets.json" }
  }
}
JSON
)

note "The daemon's config. World-readable on purpose: it holds a policy, never
# a credential, and you should be able to read what is authorising what."
if [[ $COMMIT -eq 1 ]]; then
  printf '%s\n' "$CONFIG_JSON" > "$CONF_DIR/keylessd.json"
  chmod 0644 "$CONF_DIR/keylessd.json"
  chown root:wheel "$CONF_DIR/keylessd.json"
else
  printf '  write %s:\n' "$CONF_DIR/keylessd.json"
  printf '%s\n' "$CONFIG_JSON" | sed 's/^/    /'
fi

# --- launchd ---------------------------------------------------------------

note "launchd. KeepAlive, because a daemon that stays down degrades every
# session until somebody notices."
step install -m 0644 -o root -g wheel "$HERE/sh.keyless.keylessd.plist" "$PLIST"
step launchctl bootout system "$PLIST" || true
step launchctl bootstrap system "$PLIST"

# --- what you still have to do yourself ------------------------------------

cat <<'NEXT'

# ---------------------------------------------------------------------------
# NOT DONE, AND THE INSTALL IS NOT FINISHED WITHOUT IT
# ---------------------------------------------------------------------------
#
# 1. Put your secrets where only the daemon can read them:
#
#      sudo -u _keyless tee /usr/local/var/lib/keyless/secrets.json >/dev/null <<'EOF'
#      { "GITHUB_TOKEN": "...", "DATABASE_URL": "..." }
#      EOF
#      sudo chmod 0600 /usr/local/var/lib/keyless/secrets.json
#
# 2. DELETE them from your login keychain. Until you do, every session can
#    still read them directly and this daemon has changed nothing:
#
#      security delete-generic-password -s <service> -a <account>
#
# 3. Point your sessions at the daemon, in ~/.config/keyless/config.json:
#
#      { "stores": { "daemon": { "enabled": true } } }
#
#    Enabling the daemon DISABLES the local keychain backend. That is
#    deliberate: a fallback would re-open the hole the moment the daemon
#    stopped, and anyone able to stop a process could choose that.
#
# 4. Log out and back in, or your shell will not yet be in the keyless group
#    and every request will be refused at the socket.
#
# 5. Check it:
#
#      keyless doctor
#      keylessd check --config /usr/local/etc/keyless/keylessd.json
#      keylessd verify --config /usr/local/etc/keyless/keylessd.json
#
NEXT

if [[ $COMMIT -eq 0 ]]; then
  echo "# DRY RUN — nothing above was executed. Re-run with --commit to apply."
fi
