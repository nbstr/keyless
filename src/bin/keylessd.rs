//! `keylessd` — the daemon binary.
//!
//! Five verbs, and none of them prints a value. That is the same structural
//! property the session binary has, and it holds for the same reason: a verb
//! that writes plaintext to stdout would be the shortest path, and the shortest
//! path is the one that gets used.
//!
//! - `run` — serve.
//! - `pin` — print the code hash of a client, for the allowlist.
//! - `check` — parse the config and say what it would do.
//! - `verify` — recompute the audit chain.
//! - `credential` — put the daemon's own vendor login into its `0600` file.
//!
//! `credential` is the one that READS a value, and it reads it from stdin with
//! the terminal's echo off. There is no `--value` flag and no positional value,
//! for the reason `keyless put` has none: an argument is readable from the
//! process table for as long as the process lives, and a value typed into a
//! command is a value in a shell history. Offering the flag guarantees it gets
//! used, so it does not exist.
//!
//! `pin`, `check` and `credential` are the install-time verbs. They exist so
//! an operator never has to hand-compute a hash, guess whether a config is doing
//! what they meant, or reach for a shell to get a credential into a file — the
//! first two are how an allowlist ends up authorising nothing and being widened
//! in frustration, and the third is how a credential ends up in a history file.
//!
//! # macOS only, and it SAYS so rather than being missing
//!
//! Attestation reads the code-signing hash of the live image through
//! `csops(CS_OPS_CDHASH)` and anchors identity on the pid generation from
//! `proc_pidinfo`. Both are XNU, so everything below is compiled on macOS only.
//!
//! Off macOS this binary still BUILDS and still runs — and refuses, naming the
//! reason. That is deliberate. A binary that is silently absent from the build
//! cannot be told apart from one that broke, and "command not found" teaches an
//! operator nothing. A refusal that names `csops` and points at the porting
//! table does.
//!
//! There is no weaker daemon here, on any platform. The alternative to macOS
//! attestation is not lenient attestation, it is no daemon at all.

/// The daemon proper. Every line of it is XNU-bound; see the module header.
#[cfg(any(target_os = "macos", keyless_force_xnu))]
mod daemon {
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::process::ExitCode;

    use clap::{Args, Parser, Subcommand};

    use keyless::attest::is_interpreter;
    use keyless::audit::AuditLog;
    use keyless::daemon::check::report as check_report;
    use keyless::daemon::config::{DaemonConfig, refuse_interpreter_pin};
    use keyless::daemon::credential;
    use keyless::daemon::{Daemon, Running};
    use keyless::ipc::ffi::live_code_hash;
    use keyless::ipc::peer::code_hash_of_file;
    use keyless::mask::encodings::hex_lower;

    use nix::sys::signal::{SigSet, Signal};

    /// Where the daemon's own config lives when nothing says otherwise.
    const DEFAULT_CONFIG: &str = "/usr/local/etc/keyless/keylessd.json";

    #[derive(Parser)]
    #[command(
        name = "keylessd",
        version,
        about = "The keyless daemon: holds the store credential on the other side of a uid boundary.",
        long_about = "keylessd resolves named credentials for sessions that ask over a Unix socket.\n\n\
                      It runs as its own user. The store it reads — a keychain, a file — belongs to \
                      that user, so the sessions cannot read it directly however many of them there \
                      are and whatever they run.\n\n\
                      A session that cannot reach this daemon degrades: its command still runs, with \
                      an unmodified environment. There is no path in which keylessd being down stops \
                      anybody working.",
        disable_help_subcommand = true
    )]
    struct Cli {
        #[command(subcommand)]
        command: Verb,
    }

    #[derive(Subcommand)]
    enum Verb {
        /// Serve until told to stop.
        Run(ConfigArg),
        /// Print the code hash of a client binary, for the allowlist.
        Pin(PinArgs),
        /// Parse the config and report what it would do. Reads no secret.
        Check(ConfigArg),
        /// Recompute the audit chain.
        Verify(VerifyArgs),
        /// Put one value into the daemon's own credential file. Prints nothing.
        Credential(CredentialArgs),
        /// Log the daemon into a vendor and record the credential that
        /// re-establishes that session. Prints no value.
        Login(LoginArgs),
    }

    #[derive(Args)]
    struct ConfigArg {
        /// Config file.
        #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    }

    #[derive(Args)]
    struct PinArgs {
        /// An executable file to pin.
        #[arg(long, value_name = "PATH", conflicts_with = "pid")]
        path: Option<PathBuf>,
        /// A running process to pin, by pid. Reads the loaded image, so this is
        /// what the daemon will actually compare against.
        #[arg(long, value_name = "PID")]
        pid: Option<i32>,
    }

    #[derive(Args)]
    struct CredentialArgs {
        /// The entry name, as `stores.<store>.credentials` in the config
        /// spells it. The VALUE is read from stdin and never from here.
        #[arg(long, value_name = "ENTRY")]
        name: String,
        /// Which store's credential file to write: `infisical`,
        /// `onepassword` or `proton`. Defaults to whichever store's
        /// `credentials` names the entry, and to `infisical` when none does.
        #[arg(long, value_name = "STORE")]
        store: Option<String>,
        /// Config file, used to find the credential file and the daemon's uid.
        #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    }

    #[derive(Args)]
    struct LoginArgs {
        /// Which vendor to log in. `proton` is the only store with a session;
        /// the other two are credentials and `credential` writes those.
        #[arg(long, value_name = "STORE")]
        store: String,
        /// Log an EXISTING session out first, then log in.
        ///
        /// The token-rotation path, and deliberately not the default: without
        /// it the vendor refuses to replace a session it already has, which is
        /// what makes a second run safe.
        #[arg(long)]
        replace: bool,
        /// Config file. Every coordinate the login needs is read from it, and
        /// none of them can be given here — a flag that disagreed with this
        /// file would log a session into a directory the daemon never opens.
        #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    }

    #[derive(Args)]
    struct VerifyArgs {
        /// Audit log. Defaults to the path in the config.
        #[arg(long, value_name = "PATH")]
        audit: Option<PathBuf>,
        /// Config file, used to find the audit log when `--audit` is absent.
        #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    }

    pub fn main() -> ExitCode {
        let code = dispatch();
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
        code
    }

    fn dispatch() -> ExitCode {
        match Cli::parse().command {
            Verb::Run(args) => serve(&args.config),
            Verb::Pin(args) => pin(&args),
            Verb::Check(args) => check(&args.config),
            Verb::Verify(args) => verify(&args),
            Verb::Credential(args) => credential(&args),
            Verb::Login(args) => login(&args),
        }
    }

    fn fail(message: &str) -> ExitCode {
        let _ = writeln!(io::stderr(), "keylessd: {message}");
        ExitCode::FAILURE
    }

    fn serve(config_path: &std::path::Path) -> ExitCode {
        let config = match DaemonConfig::load(config_path) {
            Ok(config) => config,
            Err(error) => return fail(&error.to_string()),
        };
        let policy = match config.policy() {
            Ok(policy) => policy,
            Err(error) => return fail(&error.to_string()),
        };

        for warning in config.warnings() {
            let _ = writeln!(io::stderr(), "keylessd: warning: {warning}");
        }

        // Block the shutdown signals on this thread BEFORE anything else is
        // spawned. A thread inherits the mask in force when it is created, so
        // blocking first is what stops a stray SIGTERM being delivered to the
        // accept thread and killing the process by default action.
        let mut shutdown = SigSet::empty();
        shutdown.add(Signal::SIGTERM);
        shutdown.add(Signal::SIGINT);
        shutdown.add(Signal::SIGHUP);
        if let Err(error) = shutdown.thread_block() {
            return fail(&format!("cannot block the shutdown signals: {error}"));
        }

        let daemon = match Daemon::bind(&config, policy) {
            Ok(daemon) => daemon,
            Err(error) => {
                return fail(&format!(
                    "cannot listen on {}: {error}",
                    config.socket.display()
                ));
            }
        };
        let socket = daemon.socket().to_path_buf();

        let running = match Running::spawn(daemon) {
            Ok(running) => running,
            Err(error) => return fail(&format!("cannot start the accept loop: {error}")),
        };

        let _ = writeln!(
            io::stderr(),
            "keylessd: listening on {}, audit at {}",
            socket.display(),
            config.audit.display()
        );

        match shutdown.wait() {
            Ok(signal) => {
                let _ = writeln!(io::stderr(), "keylessd: {signal} — stopping");
            }
            Err(error) => {
                let _ = writeln!(io::stderr(), "keylessd: sigwait failed: {error}");
            }
        }

        // Dropping stops the accept loop, joins it, and removes the socket.
        drop(running);
        ExitCode::SUCCESS
    }

    fn pin(args: &PinArgs) -> ExitCode {
        match (&args.path, args.pid) {
            (Some(path), None) => {
                if let Err(error) = refuse_interpreter_pin(path) {
                    return fail(&error.to_string());
                }
                match code_hash_of_file(path) {
                    Ok(hash) => {
                        // stdout carries the hash and nothing else, so this is
                        // usable in a pipeline. Everything explanatory is stderr.
                        let _ = writeln!(io::stdout(), "{}", hex_lower(&hash));
                        let _ = writeln!(
                            io::stderr(),
                            "keylessd: add that to peer.allow_images in the daemon's config"
                        );
                        ExitCode::SUCCESS
                    }
                    Err(error) => fail(&format!("cannot pin {}: {error}", path.display())),
                }
            }
            (None, Some(pid)) => {
                let image = keyless::ipc::ffi::image_path(pid)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<unknown>".to_owned());
                let name = std::path::Path::new(&image)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if is_interpreter(name) {
                    return fail(&format!(
                        "pid {pid} is running `{name}`, an interpreter; pinning it would authorise \
                         every program it runs"
                    ));
                }
                match live_code_hash(pid) {
                    Ok(hash) => {
                        let _ = writeln!(io::stdout(), "{}", hex_lower(&hash));
                        let _ =
                            writeln!(io::stderr(), "keylessd: that is the live image of {image}");
                        ExitCode::SUCCESS
                    }
                    Err(error) => fail(&format!("cannot read the image of pid {pid}: {error}")),
                }
            }
            _ => fail("give exactly one of --path or --pid"),
        }
    }

    fn check(config_path: &std::path::Path) -> ExitCode {
        let config = match DaemonConfig::load(config_path) {
            Ok(config) => config,
            Err(error) => return fail(&error.to_string()),
        };

        // Asking the world is the caller's job, so the walk of PATH happens
        // here and the report is handed its answer. `daemon::shadow` says why:
        // a report that read the environment itself would make every test that
        // went through it a test of the machine it ran on, and the PATH under
        // test is the whole subject.
        //
        // The policy is passed only when it parsed. A config whose pins are
        // malformed has no pin set to compare a file against, and the policy
        // row above has already said so.
        let client = keyless::daemon::shadow::look(
            std::env::var_os("PATH").as_deref(),
            config.policy().ok().as_ref(),
        );

        // The whole report, and its verdict, are `daemon::check`'s. What is
        // left here is the exit code, which is the one thing a library cannot
        // decide for a binary.
        match check_report(&config, config_path, &client, &mut io::stdout()) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::FAILURE,
            Err(error) => fail(&format!("the report could not be written: {error}")),
        }
    }

    /// Put one value into the daemon's own credential file.
    ///
    /// The value arrives on stdin. When stdin is a terminal it is prompted for
    /// with echo off; when it is a pipe it is read whole. Nothing is printed but
    /// the entry name and the file it landed in, and there is no flag that could
    /// carry the value — so it is in no shell history, no process table and no
    /// transcript.
    fn credential(args: &CredentialArgs) -> ExitCode {
        let config = match DaemonConfig::load(&args.config) {
            Ok(config) => config,
            Err(error) => return fail(&error.to_string()),
        };

        // One file per vendor. Which one is decided by `--store`, else by
        // which store's `credentials` map names the entry — and when none
        // does, by the historical default, so a recipe written before the
        // other files existed keeps working and the note below still fires.
        let names_it = |credentials: &std::collections::BTreeMap<String, String>| {
            credentials.values().any(|entry| entry == &args.name)
        };
        let store = match args.store.as_deref() {
            Some(store @ ("infisical" | "onepassword" | "proton")) => store,
            Some(other) => {
                return fail(&format!(
                    "`--store {other}` names no store with a credential file of its own; this \
                     build has: infisical, onepassword, proton"
                ));
            }
            None => {
                // Which file, when nothing said. Decided by which store's own
                // `credentials` map names the entry, so a recipe that predates
                // a second file keeps working — and refused outright when more
                // than one claims it, because writing a vault-unlocking token
                // into the wrong vendor's file is not a mistake that announces
                // itself.
                let claimed: Vec<&str> = [
                    ("infisical", &config.stores.infisical.credentials),
                    ("onepassword", &config.stores.onepassword.credentials),
                    ("proton", &config.stores.proton.credentials),
                ]
                .into_iter()
                .filter_map(|(id, credentials)| names_it(credentials).then_some(id))
                .collect();
                match claimed.as_slice() {
                    [one] => one,
                    [] => "infisical",
                    several => {
                        return fail(&format!(
                            "`{}` is named by more than one store's `credentials` ({}); pass \
                             --store to say which file it goes in",
                            args.name,
                            several.join(", ")
                        ));
                    }
                }
            }
        };
        let (path, declared) = match store {
            "onepassword" => (
                config.stores.onepassword.credentials_file.to_path_buf(),
                &config.stores.onepassword.credentials,
            ),
            "proton" => (
                config.stores.proton.credentials_file.to_path_buf(),
                &config.stores.proton.credentials,
            ),
            _ => (
                config.stores.infisical.credentials_file.to_path_buf(),
                &config.stores.infisical.credentials,
            ),
        };

        // The one arrangement that makes writing this credential worse than not
        // writing it: everything in the file the `file` store serves is a name
        // an attested client can ask for, so a machine identity kept there is
        // handed to any session that guesses its label.
        if config.stores.file.enabled && path == config.stores.file.path.to_path_buf() {
            return fail(&format!(
                "{} is the file the `file` store serves, so anything written there is a name \
                 any attested client can ask for over the socket. Point \
                 `stores.{store}.credentials_file` at a file of its own first",
                path.display()
            ));
        }

        // Echo off, on the descriptor the terminal test asked about, and no
        // prompt at all when it cannot be switched off. See
        // `credential::prompt_for`, which both this verb and `login` read
        // through so neither can lose one of those rules.
        let value = match credential::prompt_for(
            &format!("value for {}", args.name),
            &format!(
                "printf '%s' \"$value\" | keylessd credential --name {}",
                args.name
            ),
        ) {
            Ok(value) => value,
            Err(detail) => return fail(&detail),
        };

        if let Err(error) = credential::store_entry(&path, &args.name, &value) {
            return fail(&error.to_string());
        }

        // The whole output, and there is nothing in it that could carry a value.
        let _ = writeln!(io::stdout(), "stored\t{}\t{}", args.name, path.display());

        // Said afterwards rather than refused beforehand: the file has to be
        // writable before a config can point at it, so writing an entry nothing
        // reads yet is a legitimate order to do this in.
        if !names_it(declared) {
            let _ = writeln!(
                io::stderr(),
                "keylessd: nothing in `stores.{store}.credentials` names `{}`, so no lookup \
                 will read it yet",
                args.name
            );
        }

        ExitCode::SUCCESS
    }

    /// Log the daemon into a vendor, and record the token that re-establishes
    /// that session.
    ///
    /// Every coordinate comes from the config and none of them is a flag; the
    /// token arrives on stdin with echo off, exactly as `credential`'s does.
    /// The sequencing is `daemon::login`'s, so what is left here is the exit
    /// code and the order the checks are made in — and that order is the point:
    /// everything that can refuse this config refuses BEFORE a credential is
    /// asked for, so nobody types a token into a setup that was never going to
    /// use it.
    fn login(args: &LoginArgs) -> ExitCode {
        use keyless::daemon::login;

        if args.store != login::STORE {
            return fail(&login::refuse_store(&args.store));
        }

        let config = match DaemonConfig::load(&args.config) {
            Ok(config) => config,
            Err(error) => return fail(&error.to_string()),
        };
        let coordinates = match login::coordinates(&config) {
            Ok(coordinates) => coordinates,
            Err(detail) => return fail(&detail),
        };
        let Some(owner) = credential::daemon_owner(config.audit.as_path()) else {
            return fail(&login::no_daemon_uid(config.audit.as_path()));
        };

        match login::ensure_session_dir(&coordinates.session_dir, owner) {
            Ok(login::Ensured::Created) => {
                let _ = writeln!(
                    io::stdout(),
                    "session\tcreated\t{}",
                    coordinates.session_dir.display()
                );
            }
            Ok(login::Ensured::Sound) => {
                let _ = writeln!(
                    io::stdout(),
                    "session\tready\t{}",
                    coordinates.session_dir.display()
                );
            }
            Ok(login::Ensured::Repaired(repairs)) => {
                let _ = writeln!(
                    io::stdout(),
                    "session\trepaired\t{}",
                    coordinates.session_dir.display()
                );
                for repair in repairs {
                    let _ = writeln!(io::stderr(), "keylessd: {repair}");
                }
            }
            Err(detail) => return fail(&detail),
        }

        let extra = match login::extra_credentials(&coordinates) {
            Ok(extra) => extra,
            Err(detail) => return fail(&detail),
        };

        let token = match credential::prompt_for(
            &format!("agent token for {}", login::STORE),
            &format!(
                "printf '%s' \"$token\" | keylessd login --store {}",
                login::STORE
            ),
        ) {
            Ok(token) => token,
            Err(detail) => return fail(&detail),
        };

        // Checked before the vendor is spawned. Every structural fault here
        // arrives from the account as one sentence covering an invalid token,
        // an expired one and a deleted one — which sends the reader to a
        // dashboard to look for a token that was never wrong.
        if let Err(detail) = keyless::store::proton::classify_token(token.expose()) {
            return fail(&format!(
                "that is not a personal access token: {detail}. Nothing was sent to Proton Pass \
                 and nothing was written. No part of what you typed is printed here"
            ));
        }

        if let Err(detail) = login::perform(
            &coordinates,
            owner,
            args.replace,
            &token,
            extra,
            &mut io::stdout(),
        ) {
            return fail(&detail);
        }

        // Said afterwards rather than refused beforehand: a date is a thing an
        // operator writes down from the vendor's own output, and refusing the
        // login over it would mean refusing the step that produced it.
        if config.stores.proton.token_expires.is_none() {
            let _ = writeln!(
                io::stderr(),
                "keylessd: `stores.{}.token_expires` names no date, so nothing will warn you \
                 before this token stops. The vendor cannot be asked — its refusal reads the \
                 same for expired, revoked and wrong — so write the expiry down there now",
                login::STORE
            );
        }
        let _ = writeln!(
            io::stderr(),
            "keylessd: run `keylessd check --config {}` to see whether the account accepts it",
            args.config.display()
        );
        ExitCode::SUCCESS
    }

    fn verify(args: &VerifyArgs) -> ExitCode {
        let path = match &args.audit {
            Some(path) => path.clone(),
            None => match DaemonConfig::load(&args.config) {
                Ok(config) => config.audit.to_path_buf(),
                Err(error) => return fail(&error.to_string()),
            },
        };

        match AuditLog::new(path.clone()).verify() {
            Ok(0) => {
                let _ = writeln!(io::stdout(), "{} is empty", path.display());
                ExitCode::SUCCESS
            }
            Ok(rows) => {
                let _ = writeln!(io::stdout(), "{rows} rows, chain intact");
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.to_string()),
        }
    }
}

#[cfg(any(target_os = "macos", keyless_force_xnu))]
fn main() -> std::process::ExitCode {
    daemon::main()
}

/// Refuse, and say exactly why.
///
/// Not `unimplemented!()` and not a silent success: an operator who reaches
/// this has a real question ("why is there no daemon?") and the answer is a
/// platform interface, not a missing feature.
#[cfg(not(any(target_os = "macos", keyless_force_xnu)))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "keylessd: this daemon runs on macOS only, and this build is not macOS.\n\
         \n\
         Attestation identifies a caller by the code-signing hash of its LIVE\n\
         process image (csops with CS_OPS_CDHASH) and anchors that identity on\n\
         the pid generation (proc_pidinfo). Both are XNU interfaces. There is no\n\
         port here, so there is no daemon here to start -- rather than a daemon\n\
         that attests on weaker evidence.\n\
         \n\
         The `keyless` client itself is portable and works on this platform. With\n\
         no daemon answering it degrades, which is the same path it already takes\n\
         when a daemon is absent: it warns, and your command still runs.\n\
         \n\
         Porting notes, including the Linux equivalents: install/README.md"
    );
    std::process::ExitCode::FAILURE
}
