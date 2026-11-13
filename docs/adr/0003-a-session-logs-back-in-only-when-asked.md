# A session logs back in with an agent token from the keychain, only when asked

Proton ends an agent session, and a session — the default way to run keyless — had no way back: every Proton name degraded until somebody ran `pass-cli login` by hand. A dev session serving 33 names died twice on 2026-11-10, at 12:55 and 20:25, and the macOS unified log of that day shows all 392 `pass-cli` calls reading their key from the keychain, so the keychain was not at fault; the session's end was. `stores.proton.session.auto_login` now lets the lookup that finds the session ended read an agent token from a login-keychain item the config names, run `pass-cli login` with it, and retry once. Proven on a real session with `pass-cli` 2.5.1 and 2.7.0 on 2026-11-11: one login, then the 33 names. Off unless asked for.

## Considered Options

- **Point sessions at the daemon.** Rejected: `keylessd` already renews its own login, but it is a service of its own to install and run, and the session had no path back at all.
- **A `--auto-login` flag on `keyless run`.** Rejected: every command line would have to repeat it, and the one that forgets it dies the same way.
- **The token's value in the config.** Rejected: a config file is read, pasted and committed. The config names the keychain item and never holds the token.
- **Log in ahead of expiry, on a timer.** Rejected: the lifetime is no fixed clock — documented as two hours, one session still answered 2 h 09 after its login — and a timer needs a process in the background, which is the daemon's job.

## Consequences

- The token reaches the environment of the one `pass-cli login` child, never an argument vector, a log line or a message.
- An item `keyless run -s` could serve — under the keychain store's own service, or at a declared name's coordinates — leaves auto-login off, with a warning on every run.
- One login at a time, across processes, and a failed login answers every later name of that run instead of being tried again per name.
- The retry follows only a login the session needed, so it does not reopen ADR-0001's rejected retry on silence: a silent store gives `pass-cli info` no verdict, and no login runs.
