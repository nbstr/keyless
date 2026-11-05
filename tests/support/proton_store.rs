use std::path::Path;
use std::path::PathBuf;

use super::install_executable;
use super::proton_session::{VendorStore, vendor_store_trace_path};

/// Write a `pass-cli` stand-in that models the vendor's store semantics and
/// hands everything else to `inner`.
///
/// It answers `login`, `logout`, `info` and `completions` itself and `exec`s
/// `inner` for the value-reading verbs, which is the same division
/// `tests/daemon_proton_support/session_verbs.rs`'s stand-in already draws.
/// What it adds is everything the vendor does BEFORE it dispatches — and two of the
/// three ways it destroys a session live in exactly that stretch.
///
/// # The three paths to `remove_dir_all`, and why two of them are reads
///
/// | Path | Source | When |
/// | --- | --- | --- |
/// | the SDK's `on_session_invalidated` callback | `features/mod.rs:266-268` | the account revoked this session, from inside ANY command |
/// | dispatch: the session is not authenticated | `main.rs:337-341` | before the command runs, on every verb |
/// | dispatch: the session needs an extra password | `main.rs:354-358` | same |
///
/// All three land in `remove_local_data` (`commands/logout.rs:26-44`), which is
/// one `remove_dir_all` over `<PROTON_PASS_SESSION_DIR>/.session`. So a plain
/// `pass-cli run` — a read — deletes the whole store on its way to reporting an
/// ordinary error, and it does so on the two dispatch paths before it has run
/// the command at all.
///
/// # What survives, and what a verb creates
///
/// `get_base_dir` (`utils.rs:53-85`) joins `.session` onto the variable and
/// CREATES it, mode `0700`, on every verb before dispatch. So the directory the
/// variable names survives every deletion above, and a verb pointed at a
/// directory holding no session leaves an empty `.session` behind it.
///
/// # The key
///
/// `get_key_provider` (`features/mod.rs:63-84`) reads
/// `PROTON_PASS_KEY_PROVIDER` off the environment, so the arm is the caller's
/// choice and never this fixture's. Unset **or empty** is `keyring`, a third
/// provider — not `fs`, which is the reading a missing scope call invites.
///
/// # What it deliberately does not model
///
/// That exactly one process writes the local key. That is this crate's own
/// claim, proven by `daemon::credential`'s own tests, and a stand-in asserting
/// it would be a stand-in for us.
pub fn stub_pass_cli_store(dir: &Path, inner: &Path, behaviour: &VendorStore) -> PathBuf {
    let trace = vendor_store_trace_path(dir);
    // The account, which is the one piece of state that is NOT inside the
    // session directory — `client.logout()` revokes at the server, and every
    // deletion below then runs against a directory that no longer holds a
    // session the account will honour. Keeping it here rather than in
    // `.session` is what makes a revocation survive the `remove_dir_all` that
    // follows it, exactly as the account's own record does.
    let revoked = dir.join("pass-cli.store.revoked");
    let body = format!(
        r#"#!/bin/sh
verb="$1"
root="${{PROTON_PASS_SESSION_DIR-}}"
trace='{trace}'
revoked='{revoked}'

# One line per call, written once, at the point the branch is decided.
note() {{ printf '%s %s %s\n' "${{verb:-<none>}}" "${{root:-<unset>}}" "$1" >> "$trace"; }}

# `completions` is the one verb that returns before the base directory is
# touched at all.  main.rs:250-254
if [ "$verb" = 'completions' ]; then note completions; exit 0; fi

if [ -z "$root" ]; then
  note no-session-dir
  printf '%s\n' 'Error: Error getting base dir' >&2
  exit 1
fi

# get_base_dir(): `.session` is joined onto the variable and CREATED, mode
# 0700, on every verb before dispatch.  utils.rs:53-85
#
# `mkdir -p` then `chmod` rather than one call: the vendor uses DirBuilder's
# own mode on every level it creates, and the shell has no spelling for that.
# The leaf is the one this fixture's cases read.
base="$root/.session"
mkdir -p "$base" 2>/dev/null
chmod 700 "$base" 2>/dev/null
session="$base/session.json"
key_file="$base/local.key"
database="$base/pass-cli.db"

# remove_dir_all, with its listing and its final rmdir as the two separate acts
# they are.  commands/logout.rs:26-44
remove_local_data() {{
  if [ ! -d "$base" ]; then
    printf '%s\n' 'There was no data to be removed'
    return 0
  fi
  # The glob IS the listing, expanded once. An entry created after this line
  # is not in it, survives the unlinks, and fails the rmdir below.
  for entry in "$base"/* "$base"/.[!.]*; do
    [ -e "$entry" ] || continue
    rm -rf "$entry"
  done
  sleep {rmdir_window}
  if rmdir "$base" 2>/dev/null; then return 0; fi
  # The wording of the anyhow chain a failing `remove_dir_all` renders was NOT
  # read from a run of the real binary; `Error deleting base dir` is the
  # context string at logout.rs:36 and `Directory not empty` is what this
  # crate's own incident log recorded beside it. The two-line shape between
  # them is modelled.
  printf '%s\n' 'Error: Error deleting base dir' >&2
  printf '%s\n' 'Caused by:' >&2
  printf '%s\n' '    Directory not empty (os error 66)' >&2
  return 1
}}

# get_key(), per provider.  Prints the key's IDENTITY, never a key: under `fs`
# that is the id this fixture minted, and under `env` a checksum of the
# variable — the same shape the vendor logs, which prints a fingerprint and
# never the key.
resolve_key() {{
  case "$provider" in
    fs)
      # FsLocalKeyProvider::get_local_key: read it when it is there, MINT one
      # when it is not — on any verb.  features/mod.rs:177-211
      if [ -f "$key_file" ]; then cat "$key_file"; return 0; fi
      minted="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
      # `create_new(true).mode(0o600)` at features/mod.rs:196-199 is O_EXCL, so
      # two children that both find the key missing race and the loser gets
      # nothing. `set -C` is the shell's own O_EXCL and refuses identically.
      if (set -C; printf '%s' "$minted" > "$key_file") 2>/dev/null; then
        chmod 600 "$key_file"
        printf '%s' "$minted"
        return 0
      fi
      return 1
      ;;
    env)
      # EnvLocalKeyProvider derives the key from the variable's bytes and
      # stores nothing.  env_key_provider.rs:43-45
      printf 'env:%s' "$(printf '%s' "${{PROTON_PASS_ENCRYPTION_KEY-}}" | cksum | tr -d ' ')"
      return 0
      ;;
  esac
  return 1
}}

# get_key_provider(): the arm is the variable's, and unset OR EMPTY is
# `keyring`.  features/mod.rs:63-84
provider="${{PROTON_PASS_KEY_PROVIDER-}}"
case "$provider" in
  fs) ;;
  env)
    # EnvLocalKeyProvider::new refuses an unset or empty variable with this
    # exact sentence, and features/mod.rs:78 propagates it with `?` — so no
    # client is built, no dispatch is reached, and NOTHING is deleted. That is
    # what separates a misconfigured probe from a destructive one.
    # env_key_provider.rs:33-41
    if [ -z "${{PROTON_PASS_ENCRYPTION_KEY-}}" ]; then
      note env-key-missing
      printf '%s\n' 'Error: PROTON_PASS_ENCRYPTION_KEY environment variable must be set and non-empty when using env key provider' >&2
      exit 1
    fi
    ;;
  keyring|'')
    # The daemon's own uid has an empty login keyring, so KeyringKeyProvider
    # takes its NoEntry arm. With local data beside it that arm FORCE-LOGS-OUT
    # — the guard the `fs` provider has no equivalent of.
    # features/keyring.rs:258-268, local_data_exists at :141-143
    if [ -f "$session" ] || [ -f "$database" ]; then
      printf '%s\n' 'Error: Local encryption key not found but local data exists. Forcing logout for security.' >&2
      rm -f "$key_file"
      remove_local_data > /dev/null 2>&1
      printf '%s\n' "Run 'pass-cli login' to authenticate again." >&2
      note keyring-forced-logout
      exit 1
    fi
    # The other half of that arm mints a key INTO the keyring and carries on.
    # A shell stand-in has no keyring to mint into, so it refuses in words that
    # are plainly its own rather than putting the vendor's name on a guess.
    note keyring-no-local-data
    printf '%s\n' 'stub: the keyring provider has no keyring to reach' >&2
    exit 1
    ;;
  *)
    note invalid-provider
    printf '%s\n' "Error: Invalid PROTON_PASS_KEY_PROVIDER value: '$provider'. Valid values are 'fs', 'keyring', or 'env'" >&2
    exit 1
    ;;
esac

# `logout --force` and `completions` are the only commands that never build the
# client, which is why they are the only two that work against a store nothing
# can decrypt.  main.rs:267-274, commands/logout.rs:69-79
if [ "$verb" = 'logout' ] && [ "$2" = '--force' ]; then
  printf '%s\n' 'Executing force logout'
  # try_cleanup_all_key_providers, then cleanup().  features/mod.rs:45-61
  rm -f "$key_file"
  remove_local_data
  status=$?
  if [ $status -eq 0 ]; then
    note force-logged-out
    printf '%s\n' 'Successfully performed force logout'
  else
    note force-logout-enotempty
  fi
  exit $status
fi

key="$(resolve_key)" || {{
  note key-race-lost
  printf '%s\n' 'Error: Error creating local key file' >&2
  exit 1
}}

# Building the client opens the store, so a session.json the resolved key
# cannot decrypt fails EVERY remaining verb — a plain `logout` included, which
# is why a store in this state cannot be repaired by the obvious command.
# main.rs:267-274
if [ -f "$session" ]; then
  stored="$(sed -n 's/^key=//p' "$session" | head -1)"
  if [ "$stored" != "$key" ]; then
    note undecryptable
    printf '%s\n' 'Error: Error decrypting local session(Error decrypting session: aead::Error)' >&2
    exit 1
  fi
fi

# login is dispatched at main.rs:275-309, ahead of every session check below.
if [ "$verb" = 'login' ]; then
  sleep {login_delay}
  : > "$database"
  # persist_now writes session.json under whatever get_key() answered AT THAT
  # MOMENT, by rename.
  printf 'session=%s\nkey=%s\nauth=yes\nextra=no\n' \
    "$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" "$key" > "$session.tmp"
  mv "$session.tmp" "$session"
  note logged-in
  printf '%s\n' 'Personal access token session created successfully'
  exit 0
fi

# get_session() answers None.  main.rs:325-335
if [ ! -f "$session" ]; then
  if [ "$verb" = 'logout' ]; then
    note already-logged-out
    printf '%s\n' 'There was not an active session, you are already logged out' >&2
    exit 0
  fi
  note no-session
  printf '%s\n' 'ERROR pass-cli/src/main.rs:332: Command is not logout there is no session' >&2
  printf '%s\n' 'Error: This operation requires an authenticated client' >&2
  exit 1
fi

sid="$(sed -n 's/^session=//p' "$session" | head -1)"
auth="$(sed -n 's/^auth=//p' "$session" | head -1)"
extra="$(sed -n 's/^extra=//p' "$session" | head -1)"

# DELETION PATH 2 — dispatch, session present and not authenticated. The
# cleanup runs BEFORE the command, on every verb.  main.rs:336-341
if [ "$auth" != 'yes' ]; then
  remove_local_data > /dev/null 2>&1
  note not-authenticated
  printf '%s\n' 'ERROR pass-cli/src/main.rs:338: Session is some but is not logged in' >&2
  printf '%s\n' 'Error: This operation requires an authenticated client' >&2
  exit 1
fi

# DELETION PATH 3 — dispatch, the session needs an extra password. Same
# cleanup, same place.  main.rs:342-358
if [ "$extra" = 'yes' ]; then
  remove_local_data > /dev/null 2>&1
  note needs-extra-password
  printf '%s\n' 'ERROR pass-cli/src/main.rs:355: Session is some but needs extra password' >&2
  printf '%s\n' 'Error: This operation requires an authenticated client' >&2
  exit 1
fi

is_revoked() {{ grep -qx "$1" "$revoked" 2>/dev/null; }}

if [ "$verb" = 'logout' ]; then
  if is_revoked "$sid"; then
    # A logout whose server call fails exits BEFORE remove_key and
    # remove_local_data, so it touches nothing on disk.  logout.rs:48-54
    note logout-refused
    printf '%s\n' 'Error logging out: This operation requires an authenticated client' >&2
    printf '%s\n' "There has been an error during the logout process. If it persists, you may run 'pass-cli logout --force'" >&2
    exit 1
  fi
  # client.logout() revokes AT THE ACCOUNT. From here every other child holding
  # this session is answered "logged out", whatever it was asked for, and the
  # local deletion has not started.  logout.rs:48
  printf '%s\n' "$sid" >> "$revoked"
  sleep {logout_delay}
  # remove_key() is unconditional and runs before remove_local_data. Under
  # `fs` it unlinks local.key while a concurrent reader's session file still
  # needs it; under `env` it is a documented no-op, so there is nothing to
  # unlink and nothing to race.
  # logout.rs:56-64, features/mod.rs:229-237, env_key_provider.rs:65-68
  case "$provider" in fs) rm -f "$key_file" ;; esac
  remove_local_data
  status=$?
  if [ $status -eq 0 ]; then
    note logged-out
    printf '%s\n' 'Successfully logged out'
  else
    note logout-enotempty
  fi
  exit $status
fi

# DELETION PATH 1 — the SDK's own callback. The account revoked this session,
# so the command's first request is refused and the SDK calls
# on_session_invalidated() from inside whatever command that was — a read
# included.  features/mod.rs:266-268 -> logout.rs:81-84
#
# The store ALSO schedules its own session.json write on a background task
# which re-reads, and mints when absent, the key at write time. The two are not
# ordered against each other, and the terminal state is the one where that
# write survives and the key it was written under does not: the next child
# mints a fresh key and cannot decrypt what is on disk.
#
# That the SDK behaves this way is inferred from the CLI's handling of it — the
# SDK crate is not in the vendor's public repository, so `schedule_persist`'s
# own source was not read.
if is_revoked "$sid"; then
  (
    sleep {persist_key_delay}
    # local_key_path() canonicalizes the base directory, so a write arriving
    # after the directory is gone ERRORS rather than minting a key into a
    # store nothing is serving from.  features/mod.rs:214-220
    [ -d "$base" ] || exit 0
    persisted="$(resolve_key)" || exit 0
    sleep {persist_write_delay}
    [ -d "$base" ] || exit 0
    printf 'session=%s\nkey=%s\nauth=yes\nextra=no\n' "$sid" "$persisted" \
      > "$session.tmp" 2>/dev/null && mv "$session.tmp" "$session" 2>/dev/null
  ) &
  remove_local_data > /dev/null 2>&1
  # The background write is bounded by the process that scheduled it: the
  # vendor's runtime goes down with the command, so a write that has not landed
  # by the time the command returns never lands at all.
  wait
  note revoked-cleanup
  # main.rs:229-235, which is where an invalidated session is turned into words.
  printf '%s\n' 'Your session has been invalidated and you have been logged out automatically.' >&2
  printf '%s\n' 'Please log in again with: pass login' >&2
  exit 1
fi

# `info` is answered HERE rather than handed to `inner`, and that is the whole
# point of it: this crate classifies a failing read by asking `info` about the
# same session, so a fixture whose `info` shared the read's fate could not tell
# a verdict about a NAME from a fault in the SESSION. Every session check above
# has already run, so this answers exactly when the session is sound.
if [ "$verb" = 'info' ]; then
  note info-answered
  printf '%s\n' 'ok'
  exit 0
fi

note dispatched
exec '{inner}' "$@"
"#,
        trace = trace.display(),
        revoked = revoked.display(),
        inner = inner.display(),
        login_delay = behaviour.login_delay.as_secs_f64(),
        logout_delay = behaviour.logout_delay.as_secs_f64(),
        rmdir_window = behaviour.rmdir_window.as_secs_f64(),
        persist_key_delay = behaviour.persist_key_delay.as_secs_f64(),
        persist_write_delay = behaviour.persist_write_delay.as_secs_f64(),
    );

    install_executable(&dir.join("pass-cli-store-stub"), &body)
}
