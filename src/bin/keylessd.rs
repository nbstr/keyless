//! `keylessd` — the daemon binary.
//!
//! Four verbs, and none of them prints a value. That is the same structural
//! property the session binary has, and it holds for the same reason: a verb
//! that writes plaintext to stdout would be the shortest path, and the shortest
//! path is the one that gets used.
//!
//! - `run` — serve.
//! - `pin` — print the code hash of a client, for the allowlist.
//! - `check` — parse the config and say what it would do.
//! - `verify` — recompute the audit chain.
//!
//! `pin` and `check` are the install-time verbs. They exist so an operator
//! never has to hand-compute a hash or guess whether a config is doing what
//! they meant, both of which are how an allowlist ends up authorising nothing
//! and being widened in frustration.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use keyless::attest::is_interpreter;
use keyless::audit::AuditLog;
use keyless::daemon::config::{DaemonConfig, refuse_interpreter_pin};
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
struct VerifyArgs {
    /// Audit log. Defaults to the path in the config.
    #[arg(long, value_name = "PATH")]
    audit: Option<PathBuf>,
    /// Config file, used to find the audit log when `--audit` is absent.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_CONFIG)]
    config: PathBuf,
}

fn main() -> ExitCode {
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
                    let _ = writeln!(io::stderr(), "keylessd: that is the live image of {image}");
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
