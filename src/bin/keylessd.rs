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
    use keyless::cmd::write::read_value;
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
        /// The entry name, as `stores.infisical.credentials` in the config
        /// spells it. The VALUE is read from stdin and never from here.
        #[arg(long, value_name = "ENTRY")]
        name: String,
        /// Config file, used to find the credential file and the daemon's uid.
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

        let mut out = io::stdout();
        let _ = writeln!(out, "config   {}", config_path.display());
        let _ = writeln!(out, "socket   {}", config.socket.display());
        let _ = writeln!(out, "audit    {}", config.audit.display());
        let _ = writeln!(
            out,
            "cache    {}s in memory, never on disk",
            config.cache_ttl_seconds
        );

        match config.policy() {
            Ok(policy) => {
                let _ = writeln!(
                    out,
                    "policy   {} uid(s), {} pinned image(s), interpreted callers refused",
                    config.peer.allow_uids.len(),
                    policy.image_count()
                );
            }
            Err(error) => {
                let _ = writeln!(out, "policy   PROBLEM {error}");
                return ExitCode::FAILURE;
            }
        }

        // Before the stores, because a store row that says PROBLEM because the
        // daemon cannot read its own login is a symptom, and this is the cause.
        // The two questions are different: this one asks whether the credential
        // is where it must be and shut to everyone else; the `infisical` row
        // below asks whether Infisical accepts it.
        let _ = credential::report(&config, &mut out);

        for store in config.registry().stores() {
            match store.health() {
                Ok(()) => {
                    let _ = writeln!(out, "store    {} ok", store.id());
                }
                Err(error) => {
                    let _ = writeln!(out, "store    {} PROBLEM {error}", store.id());
                }
            }
        }

        // A healthy store is not a store that will be asked. With two enabled,
        // which one answers a name is decided here and nowhere else, so the
        // decision is printed beside them rather than left to be inferred from
        // a run that degrades later.
        let _ = writeln!(
            out,
            "routing  {} policy, default {}, {} name(s) pinned",
            match config.stores.policy {
                keyless::config::Policy::Explicit => "explicit",
                keyless::config::Policy::Ordered => "ordered",
            },
            config.stores.default_store.as_deref().unwrap_or("unset"),
            config
                .secrets
                .values()
                .filter(|route| route.store.is_some())
                .count()
        );

        let warnings = config.warnings();
        for warning in &warnings {
            let _ = writeln!(out, "warning  {warning}");
        }

        if warnings.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
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
        use std::io::IsTerminal;

        let config = match DaemonConfig::load(&args.config) {
            Ok(config) => config,
            Err(error) => return fail(&error.to_string()),
        };
        let path = config.stores.infisical.credentials_file.to_path_buf();

        // The one arrangement that makes writing this credential worse than not
        // writing it: everything in the file the `file` store serves is a name
        // an attested client can ask for, so a machine identity kept there is
        // handed to any session that guesses its label.
        if config.stores.file.enabled && path == config.stores.file.path.to_path_buf() {
            return fail(&format!(
                "{} is the file the `file` store serves, so anything written there is a name \
                 any attested client can ask for over the socket. Point \
                 `stores.infisical.credentials_file` at a file of its own first",
                path.display()
            ));
        }

        let interactive = io::stdin().is_terminal();
        // Echo is switched off around the read and restored afterwards. If it
        // cannot be switched off, the prompt is NOT offered: a prompt that
        // echoes would print the credential, which is worse than refusing.
        let quiet = if interactive {
            match keyless::tty::without_echo() {
                Ok(guard) => Some(guard),
                Err(error) => {
                    return fail(&format!(
                        "cannot switch terminal echo off ({error}), so the value would be \
                         printed as you typed it. Pipe it in instead: `printf '%s' \"$value\" \
                         | keylessd credential --name {}`",
                        args.name
                    ));
                }
            }
        } else {
            None
        };

        if interactive {
            let _ = write!(
                io::stderr(),
                "keylessd: value for {} (not echoed): ",
                args.name
            );
            let _ = io::stderr().flush();
        }
        let value = read_value(&mut io::stdin(), interactive);
        drop(quiet);
        if interactive {
            // Echo was off, so the user's Enter produced no newline on screen.
            let _ = writeln!(io::stderr());
        }

        let value = match value {
            Ok(value) => value,
            Err(error) => return fail(&error.to_string()),
        };

        if let Err(error) = credential::store_entry(&path, &args.name, &value) {
            return fail(&error.to_string());
        }

        // The whole output, and there is nothing in it that could carry a value.
        let _ = writeln!(io::stdout(), "stored\t{}\t{}", args.name, path.display());

        // Said afterwards rather than refused beforehand: the file has to be
        // writable before a config can point at it, so writing an entry nothing
        // reads yet is a legitimate order to do this in.
        if !config
            .stores
            .infisical
            .credentials
            .values()
            .any(|entry| entry == &args.name)
        {
            let _ = writeln!(
                io::stderr(),
                "keylessd: nothing in `stores.infisical.credentials` names `{}`, so no lookup \
                 will read it yet",
                args.name
            );
        }

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
