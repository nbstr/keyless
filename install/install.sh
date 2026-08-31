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

# --- install only from a checkout that is not behind what it tracks --------
#
# FIRST, before the build check below, because the two prescribe opposite
# actions and only one of them can be right. The build check says "cargo build
# --release"; on a tree that is six commits behind, that compiles the wrong
# code and produces an artefact both checks then call fresh.
#
# The build check compares the binary against the source beside it, and it is
# blind to a source tree that is ITSELF old. A checkout six commits behind
# builds a binary that is fresh by that rule — nothing under src/ is newer than
# the artefact — and installs a program missing every fix in those six commits.
# That is not a hypothetical: `keyless doctor` prints `build proven` over a
# binary carrying a lookup that answers from the caller's own environment,
# because the tree it was built from is behind the branch it tracks.
#
# `keyless doctor` asks the same question of the tree the running binary was
# built from. This asks it at the one moment somebody is standing here, which is
# the moment a refusal can still be acted on.
#
# It NEVER fetches. This runs under sudo, and a fetch as root writes root-owned
# objects into a human's .git. So it reads the ref the last fetch left behind,
# which means it can only ever MISS a finding and can never invent one — a
# refusal here is therefore always true, and a pass is only as new as that
# fetch.
#
# Everything else is skipped rather than guessed: no git, no repository, a
# detached HEAD or a branch tracking nothing all leave `behind` empty and let
# the install through. Installing a deliberately older revision already looks
# like that — `git switch --detach <sha>` has no upstream — so the legitimate
# case passes without needing an override flag nobody would resist using.

# git must run as the human who owns the checkout. As root it refuses a
# repository owned by somebody else ("dubious ownership"), so without this the
# check would silently skip itself in exactly the mode that installs.
as_owner() {
  if [[ "$(id -u)" -eq 0 && "$TARGET_USER" != "root" ]]; then
    sudo -u "$TARGET_USER" "$@"
  else
    "$@"
  fi
}

if UPSTREAM="$(GIT_OPTIONAL_LOCKS=0 as_owner git -C "$REPO" rev-parse --abbrev-ref '@{u}' 2>/dev/null)"; then
  BEHIND="$(GIT_OPTIONAL_LOCKS=0 as_owner git -C "$REPO" rev-list --count "HEAD..$UPSTREAM" 2>/dev/null || true)"
  if [[ "${BEHIND:-0}" =~ ^[0-9]+$ && "${BEHIND:-0}" -gt 0 ]]; then
    echo "Stale checkout: $REPO is at least $BEHIND commit(s) behind $UPSTREAM." >&2
    echo "The binary matches this source; this source is that old. Nothing here" >&2
    echo "contacted the remote, so the real distance may be greater." >&2
    echo "Run: git -C $REPO pull --ff-only && cargo build --release" >&2
    exit 1
  fi
fi

for binary in keyless keylessd; do
  if [[ ! -x "$REPO/target/release/$binary" ]]; then
    echo "Build first: cargo build --release  (missing target/release/$binary)" >&2
    exit 1
  fi
  # And built from THIS source, not from whatever the tree said last week. The
  # rule is cargo's own — a source newer than the artefact means a rebuild — so
  # this refuses exactly what `cargo build --release` would redo, and `keyless
  # doctor` asks the same question of the binary already installed.
  #
  # `-newer` on a path list rather than a `find -newer` over `src/` alone:
  # `Cargo.lock` changes on a dependency bump and nothing under `src/` does.
  newer="$(find "$REPO/src" "$REPO/Cargo.toml" "$REPO/Cargo.lock" \
             -newer "$REPO/target/release/$binary" -print -quit 2>/dev/null || true)"
  if [[ -n "$newer" ]]; then
    echo "Stale build: $newer changed after target/release/$binary was built." >&2
    echo "Run: cargo build --release" >&2
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
# `-p` preserves the BUILD time on the copy. Without it the copy is stamped at
# install time, so a binary built before a source edit looks newer than that
# edit and `keyless doctor` reports a stale install as current — the one way
# this check can be made to lie.
step install -p -m 0755 "$REPO/target/release/keyless" "$BIN_DIR/keyless"
step install -p -m 0755 "$REPO/target/release/keylessd" "$BIN_DIR/keylessd"

# --- the same program, reached before the one just installed ---------------
#
# Placing a binary in $BIN_DIR does not make it the one a shell runs. A second
# copy earlier on PATH wins, and the two failures that produces both name
# something else:
#
#   - The old copy simply lacks whatever landed since it was built. Measured:
#     `keylessd credential --name ...` answered `unrecognized subcommand` from a
#     copy ten days old while the binary carrying that verb sat here, unreached.
#     The error names a missing feature, so the first hypothesis is a bad build.
#   - Worse, and quieter: the config below pins the CODE HASH of the client
#     installed above. A different binary has a different hash, so the daemon
#     refuses it — and the refusal reads as a broken pin, which sends somebody
#     to re-pin a file that was already pinned correctly.
#
# WHAT ESTABLISHES THAT A FILE HERE IS OURS, AND WHY IT IS NOT THE FILE
#
# Nothing about the bytes can say it. A hash comparison identifies the binary
# just built and identifies nothing else, so a stale build of ours and a
# stranger's program of the same name are the same answer to it. Running the
# candidate and reading its subcommands is worse than useless: an old build
# fails that test precisely BECAUSE it is old, which is the defect.
#
# `cargo install` writes down what it did. `<CARGO_HOME>/.crates.toml` maps a
# package to the binary names it put in `<CARGO_HOME>/bin`, and it is the record
# `cargo uninstall` itself reads. That is provenance rather than resemblance, it
# survives the build being old, and it is the only thing here allowed to select
# a file for removal. Anything else found is REPORTED and never touched: it is
# somebody's file, and this script does not delete files it cannot identify.
#
# WHY THE REMOVAL IS `cargo uninstall` AND NOT `rm`
#
# `rm` leaves cargo's ledger claiming the binary is still installed, so the next
# `cargo install` short-circuits and the shadow comes back. The package's own
# verb removes both binaries and the record together. It runs as the operator,
# never as root: those files are theirs, and CARGO_HOME is derived from the
# candidate's own path rather than from $HOME, which under sudo is root's.
#
# WHAT THIS CANNOT SEE, SAID RATHER THAN IMPLIED
#
# The PATH walked here is this process's. The operator's NEXT shell may resolve
# differently, and a shell that has already looked a name up keeps using its
# answer until `hash -r`. So this can only ever MISS a shadow and can never
# invent one — and it is not the whole of the fix: `keylessd check` asks the
# same question against the pin, in the operator's own shell, every time
# somebody runs it because something is already wrong.

# Find what is reached before $2 on the PATH in $1, one finding per line:
#
#   cargo <CARGO_HOME> <file>   cargo's ledger says this package installed it
#   foreign <file>              something else of that name; not ours to touch
#   unreachable <dir>           $2 is not on that PATH at all
#
# `cargo_recorded` is nested so this whole function is one liftable block —
# `tests/install_scripts.rs` executes it verbatim against a fabricated PATH,
# which is the only way to test a resolution rule without installing anything.
find_shadows() {
  local search="$1" install_dir="$2" name dir candidate bin_dir cargo_home
  local -a dirs=()

  cargo_recorded() {
    local file="$1" want home
    want="$(basename "$file")"
    home="$(dirname "$(dirname "$file")")"
    if [[ "$(basename "$(dirname "$file")")" != "bin" ]]; then return 1; fi
    if [[ ! -r "$home/.crates.toml" ]]; then return 1; fi
    # A line reads: "<package> <version> (<source>)" = ["bin", "bin"]. The
    # 9-character prefix test is what keeps `keyless-ui` from matching
    # `keyless`, and it is the difference between removing our install and
    # removing somebody else's crate.
    awk -v want="$want" -F'" = ' '
      substr($1, 1, 9) == "\"keyless " && index($2, "\"" want "\"") { found = 1 }
      END { exit(found ? 0 : 1) }
    ' "$home/.crates.toml"
  }

  # Split on `:` through `read`, never by word-splitting `$PATH`: an entry
  # holding a glob character expands under word splitting and stops naming the
  # directory it came from.
  #
  # The trailing newline is load-bearing. `read` returns non-zero on a final
  # line that has none, so the loop drops it — and the entry it drops is the
  # LAST one on PATH, which is exactly where a system-wide install directory
  # sits. Measured without it: the install directory went unseen, so every walk
  # reported it as not on PATH and no shadow was ever found.
  while IFS= read -r dir; do dirs+=("$dir"); done < <(printf '%s\n' "$search" | tr ':' '\n')

  local reachable=0
  if [[ ${#dirs[@]} -gt 0 ]]; then
    for dir in "${dirs[@]}"; do
      if [[ "$dir" == "$install_dir" ]]; then reachable=1; fi
    done
  fi
  if [[ $reachable -eq 0 ]]; then
    # Nothing is shadowing anything, because nothing installed here is reached
    # at all. Removing another copy in this state would leave the operator with
    # no `keyless` on PATH whatsoever, which is worse than the shadow.
    printf 'unreachable\t%s\n' "$install_dir"
    return 0
  fi

  for name in keyless keylessd; do
    if [[ ${#dirs[@]} -eq 0 ]]; then continue; fi
    for dir in "${dirs[@]}"; do
      if [[ "$dir" == "$install_dir" ]]; then break; fi
      if [[ -z "$dir" ]]; then continue; fi
      candidate="$dir/$name"
      if [[ ! -f "$candidate" || ! -x "$candidate" ]]; then continue; fi
      if cargo_recorded "$candidate"; then
        bin_dir="$(dirname "$candidate")"
        cargo_home="$(dirname "$bin_dir")"
        printf 'cargo\t%s\t%s\n' "$cargo_home" "$candidate"
      else
        printf 'foreign\t%s\n' "$candidate"
      fi
    done
  done
  return 0
} # end find_shadows

note "Anything named keyless reached before $BIN_DIR. A shell runs the first
# one it finds, which is not made the one placed above by placing it there."

SHADOW_HOMES=""
while IFS=$'\t' read -r kind first rest; do
  case "$kind" in
    unreachable)
      printf '# %s is not on the PATH this script can see, so nothing installed there\n' "$first"
      printf '# is reached. Add it to PATH; nothing else here is touched while that holds.\n'
      ;;
    cargo)
      printf '# %s is reached before %s, and cargo records it as this package.\n' "$rest" "$BIN_DIR"
      case "$SHADOW_HOMES" in
        *"|$first|"*) ;;
        *) SHADOW_HOMES="$SHADOW_HOMES|$first|" ;;
      esac
      ;;
    foreign)
      printf '# %s is reached before %s and nothing here can say what it is, so it\n' "$first" "$BIN_DIR"
      printf '# is left alone. Put %s ahead of it on PATH, then run `hash -r`.\n' "$BIN_DIR"
      ;;
  esac
done < <(find_shadows "${PATH:-}" "$BIN_DIR")

# One removal per cargo home, because `cargo uninstall` takes the package and
# removes every binary of it at once. Through `step`, so the dry run prints the
# command the commit run executes — this must not be a step that only appears
# when it is too late to read it.
if [[ -n "$SHADOW_HOMES" ]]; then
  printf '# Removed below, by cargo itself, so its ledger stops claiming they are\n'
  printf '# installed. Run `hash -r` afterwards: a shell keeps resolving a path it has\n'
  printf '# already looked up, including one that no longer exists.\n'
  while IFS= read -r home; do
    if [[ -z "$home" ]]; then continue; fi
    step sudo -u "$TARGET_USER" env "CARGO_HOME=$home" "$home/bin/cargo" uninstall keyless
  done < <(printf '%s' "$SHADOW_HOMES" | tr '|' '\n' | sort -u)
fi # end shadow removal

# --- directories -----------------------------------------------------------

note "Directories. The socket's parent is NOT writable by you: if it were, you
# could delete the socket and bind your own in its place."
step install -d -m 0755 -o root -g wheel "$CONF_DIR"
step install -d -m 0755 -o "$DAEMON_USER" -g "$ACCESS_GROUP" "$RUN_DIR"
step install -d -m 0755 -o "$DAEMON_USER" -g "$ACCESS_GROUP" "$LOG_DIR"
step install -d -m 0700 -o "$DAEMON_USER" -g "$ACCESS_GROUP" "$LIB_DIR"

# --- state files, placed without ever destroying what is already there -----
#
# `install -m 0600 /dev/null <dest>` is NOT "create if missing". It is a COPY,
# and a copy over an existing file TRUNCATES it: a store full of migrated
# credentials becomes a zero-byte file, exit 0, nothing printed. This script
# offers a dry run precisely so it gets read and then re-run, and the paths
# below hold the only copy of things nobody can get back — so the destructive
# form is not a hazard this script may carry.
#
# What re-running still does is re-assert the two facts that ARE the boundary:
# the mode and the owner. `chmod` and `chown` change neither the contents nor
# the inode, so an editor that widened the store or a `cp` that left it owned
# by whoever typed sudo is repaired by the same command that is safe to run on
# a file with everything in it.
place_state_file() {
  local mode="$1" dest="$2"
  if [[ -e "$dest" ]]; then
    printf '# %s already exists. Its contents are left alone; only its mode and owner are re-asserted.\n' "$dest"
    step chmod "$mode" "$dest"
    step chown "$DAEMON_USER:$ACCESS_GROUP" "$dest"
  else
    step install -m "$mode" -o "$DAEMON_USER" -g "$ACCESS_GROUP" /dev/null "$dest"
  fi
}

note "The store. 0600 under the daemon's uid: unreadable by you, by every
# session you start, and by every subagent any of them spawns."
place_state_file 0600 "$LIB_DIR/secrets.json"

note "The audit log. 0640: you read it, you cannot write it. That asymmetry
# is what the hash chain needs in order to mean anything."
place_state_file 0640 "$LOG_DIR/audit.jsonl"

note "The daemon's own vendor logins. 0600, one file per vendor, and EMPTY on a
# first install: this script never asks you for a credential and never holds
# one. See the Infisical and 1Password steps at the end for how a value gets in
# without passing through a command line."
place_state_file 0600 "$LIB_DIR/infisical.json"
place_state_file 0600 "$LIB_DIR/onepassword.json"

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

# ---------------------------------------------------------------------------
# AN EXISTING CONFIG IS NEVER REWRITTEN, AND THE REFUSAL IS NOT LAZINESS
# ---------------------------------------------------------------------------
#
# The template above has no "infisical" block and no "secrets" block. Those are
# hand-added — this script's own closing instructions are what tell an operator
# to add them — so writing the template over a config that has them deletes
# exactly the work the script asked for, and the daemon that comes back up
# serves a strictly smaller set of names while reporting no fault.
#
# Three ways out were available. Merging is the one that looks best and is the
# worst: a merge has to decide, per key, whether a difference is the operator's
# edit or this script's newer default, and it would have to make that decision
# in shell, over JSON, on a machine where `jq` may not exist. A merge that gets
# it wrong is a config that nobody wrote and everybody believes. Writing only
# when absent is safe and silently strands the ONE field that legitimately
# changes on a re-run — the pinned image hash, which a rebuilt `keyless`
# invalidates and which, left stale, makes the daemon refuse its own client.
#
# So: refuse, and report the one thing the operator now has to do by hand. The
# hash is printed here, where somebody is standing, rather than discovered
# later as every request being denied.
CONF_FILE="$CONF_DIR/keylessd.json"
if [[ $COMMIT -eq 1 ]]; then
  if [[ -e "$CONF_FILE" ]]; then
    printf '# %s already exists and was NOT rewritten. It may carry `infisical`\n' "$CONF_FILE"
    printf '# and `secrets` blocks this installer has no template for.\n'
    if grep -qF -- "$CLIENT_HASH" "$CONF_FILE"; then
      printf '# It already pins the client just installed. Nothing to do.\n'
    else
      printf '#\n'
      printf '# ACTION REQUIRED: it does NOT pin the client just installed, so the daemon\n'
      printf '# will refuse every request from it. Put this hash in peer.allow_images:\n'
      printf '#\n'
      printf '#   %s\n' "$CLIENT_HASH"
      printf '#\n'
      printf '# then: sudo launchctl kickstart -k system/sh.keyless.keylessd\n'
    fi
  else
    printf '%s\n' "$CONFIG_JSON" > "$CONF_FILE"
    chmod 0644 "$CONF_FILE"
    chown root:wheel "$CONF_FILE"
  fi
elif [[ -e "$CONF_FILE" ]]; then
  printf '  %s already exists; it would NOT be rewritten. The new pin would be\n' "$CONF_FILE"
  printf '  printed for you to place in peer.allow_images by hand.\n'
else
  printf '  write %s:\n' "$CONF_FILE"
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
# 5. Check it. `check` under sudo, because the store and the daemon's own
#    credential file live in a 0700 directory owned by the daemon: read as
#    you, it cannot open either of them and can only report that:
#
#      keyless doctor
#      sudo keylessd check --config /usr/local/etc/keyless/keylessd.json
#      keylessd verify --config /usr/local/etc/keyless/keylessd.json
#
# ---------------------------------------------------------------------------
# OPTIONAL: serve names out of Infisical as well
# ---------------------------------------------------------------------------
#
# Skip all of this if you do not use Infisical. Nothing above depends on it and
# the daemon does not enable it by default.
#
# A session reaches Infisical by spawning the vendor CLI and inheriting the
# login already in its own keychain. The daemon cannot: a login keychain belongs
# to the uid that unlocked it, so the daemon's uid has an empty one, and giving
# it a home directory does not change that. It uses a MACHINE IDENTITY instead —
# a client id and a client secret you create in Infisical, scoped to the
# environments you want the daemon to be able to read and revocable there.
#
# a. Add the store to /usr/local/etc/keyless/keylessd.json. Coordinates only;
#    there is no field in this file a credential fits in:
#
#      "infisical": {
#        "enabled": true,
#        "binary": "/absolute/path/to/infisical",
#        "domain": "https://<your-region>.infisical.com",
#        "project_id": "<your-project-id>",
#        "credentials_file": "/usr/local/var/lib/keyless/infisical.json",
#        "credentials": {
#          "INFISICAL_UNIVERSAL_AUTH_CLIENT_ID": "MACHINE_IDENTITY_CLIENT_ID",
#          "INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET": "MACHINE_IDENTITY_CLIENT_SECRET"
#        }
#      }
#
#    An ABSOLUTE path for "binary": launchd hands a daemon its own PATH, not a
#    login shell's, so the bare name a session resolves may resolve to nothing.
#
#    "domain" matters and is quiet when it is wrong: the CLI defaults to the US
#    cloud, and an identity created in another region simply has no account
#    there. Name the region you created the identity in.
#
#    Every name you want served needs its own "env" under "secrets" — the daemon
#    has no default environment and will not invent one:
#
#      "secrets": { "DATABASE_URL": { "store": "infisical", "env": "<slug>",
#                                     "path": "/backend" } }
#
# b. Put the identity in the daemon's own file. This prompts, echoes nothing,
#    and takes no value on the command line — so the credential is in no shell
#    history and in no process table:
#
#      sudo keylessd credential --name MACHINE_IDENTITY_CLIENT_ID
#      sudo keylessd credential --name MACHINE_IDENTITY_CLIENT_SECRET
#
# c. Check it. `identity` reports the file's mode, its owner and how many
#    entries are in it, and the `store infisical` row is the login actually
#    being accepted by your tenant. Under sudo: read as you, the file cannot be
#    opened at all, and the row says so rather than counting nothing:
#
#      sudo keylessd check --config /usr/local/etc/keyless/keylessd.json
#
# WHY A CLIENT SECRET AND NOT A TOKEN. An access token is smaller and expires;
# a daemon has nobody to prompt when it does, and what you would see is every
# Infisical name quietly degrading at an hour nobody chose. With the identity
# on disk the daemon mints its own token per lookup and never asks you again.
# The credential file's 0600 mode and its owner ARE the boundary that makes
# that safe, which is why `keylessd check` verifies both rather than merely
# checking the file is there — and reads what is in it, because an empty file
# has exactly that mode and that owner and holds no login at all.
#
# ---------------------------------------------------------------------------
# OPTIONAL: serve names out of ONE 1Password vault as well
# ---------------------------------------------------------------------------
#
# Skip all of this if you do not use 1Password. Nothing above depends on it.
#
# This is the arrangement that makes "one vault and no other" a boundary rather
# than a config line. Create a SERVICE ACCOUNT at the vendor with read access to
# exactly the vault the daemon may read — `op service-account create <name>
# --vault <VAULT>:read_items` prints the token once, and the vendor refuses that
# token every other vault. The token then lives in the daemon's own 0600 file,
# and the socket carries names and values but never the token.
#
# a. Add the store to /usr/local/etc/keyless/keylessd.json. Coordinates only;
#    there is no field in this file a credential fits in:
#
#      "onepassword": {
#        "enabled": true,
#        "binary": "/absolute/path/to/op",
#        "vault": "<the one vault>",
#        "field": "password",
#        "config_dir": "/usr/local/var/lib/keyless/op",
#        "credentials_file": "/usr/local/var/lib/keyless/onepassword.json",
#        "credentials": { "OP_SERVICE_ACCOUNT_TOKEN": "SERVICE_ACCOUNT" }
#      }
#
#    "vault" is required and is never defaulted: it is the whole point.
#    "field" is the field a name reads when its own entry names none — set it
#    when every item in the vault has the same shape, leave it out otherwise.
#    "config_dir" names a directory the daemon's uid can write, because the
#    vendor keeps an account list and a cache socket there and a daemon's home
#    may not be writable; create it owned by the daemon.
#
#    Each name is an item in that vault, by title:
#
#      "secrets": { "STRIPE_KEY": { "store": "onepassword", "item": "<title>",
#                                   "field": "credential" } }
#
# b. Put the token in the daemon's own file. Prompts, echoes nothing, takes no
#    value on the command line:
#
#      sudo keylessd credential --store onepassword --name SERVICE_ACCOUNT
#
# c. Check it. `identity` reports the file's mode and owner, and the
#    `store onepassword` row is the vendor accepting the token for THAT vault:
#
#      keylessd check --config /usr/local/etc/keyless/keylessd.json
#
NEXT

if [[ $COMMIT -eq 0 ]]; then
  echo "# DRY RUN — nothing above was executed. Re-run with --commit to apply."
fi
