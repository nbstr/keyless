//! The `keyless` binary: argument parsing and nothing else.
//!
//! Every decision lives in the library so it can be tested without a process,
//! and so the never-block invariant is provable by calling a function rather
//! than by scraping a terminal.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use keyless::State;
use keyless::audit::AuditLog;
use keyless::cmd::discover::{fields, items};
use keyless::cmd::doctor::doctor;
use keyless::cmd::ls::ls;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::cmd::write::{new, put};
use keyless::config::Config;
use keyless::paths::Paths;
use keyless::random::DEFAULT_LENGTH;
use keyless::store::Invocation;
use keyless::store::discover::discoverer;
use keyless::store::manage::manager;
use keyless::store::proton::Reason;
use keyless::{NAME, store};

/// Use a secret without ever holding one.
#[derive(Parser)]
#[command(
    name = NAME,
    version,
    about = "Use a secret without ever holding one: name it, and it reaches the child process and nothing else.",
    long_about = "keyless resolves named credentials and hands them to a child process's \
                  environment. The value never appears in your shell history, your transcript, \
                  or this tool's output.\n\n\
                  There is deliberately no verb that prints a value. If a command needs a \
                  credential, run the command under `keyless run`.\n\n\
                  `keyless run` never refuses to run your command. If a secret cannot be \
                  resolved it warns, runs the command with an unmodified environment, and \
                  forwards the exit code.\n\n\
                  `items` and `fields` say what a store holds — titles, states and field \
                  names — so a config entry can be written without ever reading a value. \
                  `new` and `put` store one: `new` generates it with the kernel's random \
                  source and `put` reads it from stdin. Neither shows it to you, and there \
                  is no flag that passes a value as an argument.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Config file. Defaults to $XDG_CONFIG_HOME/keyless/config.json.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Audit log. Defaults to $XDG_STATE_HOME/keyless/audit.jsonl.
    #[arg(long, global = true, value_name = "PATH")]
    audit: Option<PathBuf>,

    /// Do not record this invocation.
    #[arg(long, global = true)]
    no_audit: bool,

    #[command(subcommand)]
    command: Verb,
}

#[derive(Subcommand)]
enum Verb {
    /// Run a command with named secrets in its environment.
    Run(RunArgs),
    /// List declared secret names. Never prints a value.
    Ls,
    /// List the items a store holds. Titles and states, never a value.
    Items(ItemsArgs),
    /// List the field names on one item. Never a value, never a length.
    Fields(FieldsArgs),
    /// Generate a value and store it. Never prints it.
    New(NewArgs),
    /// Read a value from stdin and store it. Never echoes it.
    Put(PutArgs),
    /// Check the config, the stores and the audit log.
    Doctor(DoctorArgs),
}

#[derive(Args)]
struct ItemsArgs {
    /// Which store to ask. Defaults to the only configured one.
    #[arg(long, value_name = "STORE")]
    store: Option<String>,

    /// Narrow to one vault. Without it, every vault the identity can see.
    #[arg(long, value_name = "VAULT")]
    vault: Option<String>,
}

#[derive(Args)]
struct FieldsArgs {
    /// Which store to ask. Defaults to the only configured one.
    #[arg(long, value_name = "STORE")]
    store: Option<String>,

    /// The vault the item is in. Required for stores that have vaults.
    #[arg(long, value_name = "VAULT")]
    vault: Option<String>,

    /// The item's exact title.
    #[arg(long, value_name = "TITLE")]
    item: String,
}

#[derive(Args)]
struct NewArgs {
    /// The declared name to store it under.
    #[arg(value_name = "NAME")]
    name: String,

    /// Which store to write to. Defaults to the name's own `store`.
    #[arg(long, value_name = "STORE")]
    store: Option<String>,

    /// How many characters to generate.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_LENGTH)]
    length: usize,
}

/// `put` takes the value on **stdin and nowhere else**.
///
/// There is deliberately no `--value`, no `--secret` and no positional value: an
/// argument is readable from the process table for as long as the process lives,
/// which is the CLI-flag shape this tool exists to remove. A flag that exists
/// gets used, so the flag does not exist.
#[derive(Args)]
struct PutArgs {
    /// The declared name to store it under.
    #[arg(value_name = "NAME")]
    name: String,

    /// Which store to write to. Defaults to the name's own `store`.
    #[arg(long, value_name = "STORE")]
    store: Option<String>,
}

#[derive(Args)]
struct RunArgs {
    /// A secret to inject, as NAME or ENV=NAME. Repeatable.
    ///
    /// `OsString` rather than `String`, and that is a never-block fix rather
    /// than a nicety. clap rejects a non-UTF-8 value for a `String` argument
    /// **before `dispatch` is ever called**, and exits 2 — a third way out with
    /// no child, reached while a perfectly runnable command sat after the `--`.
    /// Taken as bytes, the same input becomes one unresolvable name: the run
    /// warns, degrades, and still runs the command.
    #[arg(short = 's', long = "secret", value_name = "[ENV=]NAME")]
    secret: Vec<OsString>,

    /// Infisical environment for names in this run that declare none.
    ///
    /// Infisical requires one on every call and `keyless` defaults none, so a
    /// name that declares no `env` and is not covered by this does not resolve —
    /// the run degrades and says so. A name's own `env` wins over this.
    #[arg(long, value_name = "SLUG")]
    env: Option<String>,

    /// The command to run, after `--`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        value_name = "COMMAND"
    )]
    command: Vec<OsString>,
}

#[derive(Args)]
struct DoctorArgs {
    /// Also ask each declared name whether it resolves. Prints ok or missing,
    /// never a value. May trigger a keychain access prompt.
    #[arg(long)]
    probe: bool,
}

fn main() {
    let code = dispatch();
    // `process::exit` skips the runtime's stdout flush, so do it here.
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    std::process::exit(code);
}

fn dispatch() -> i32 {
    let cli = Cli::parse();

    let mut paths = Paths::discover();
    if let Some(path) = cli.config {
        paths.config = path;
    }
    if let Some(path) = cli.audit {
        paths.audit = path;
    }

    let load = Config::load(&paths.config);

    match cli.command {
        Verb::Run(args) => {
            // Built here rather than above, because two of its inputs describe
            // this command rather than this machine: the reason one backend
            // records against every read — which carries the program's name and
            // never its arguments, see `store::proton::Reason` — and the
            // Infisical environment `--env` named, which no config supplies.
            let built = store::build(
                &load.config,
                &Invocation::for_run(&args.command).with_infisical_env(args.env.clone()),
            );
            let registry = built.registry;

            // Seeded with whatever building the registry had to say — chiefly
            // which local backends the daemon suppressed. Printed before
            // anything else, because it explains a degrade that would
            // otherwise look like a broken store.
            let mut warnings = built.warnings;
            if let Some(problem) = &load.problem {
                warnings.push(problem.to_string());
            }

            let mut bindings = Vec::new();
            let mut unusable = Vec::new();
            for spec in &args.secret {
                let printable = spec.to_string_lossy().into_owned();
                match spec.to_str().map(Binding::parse) {
                    Some(Ok(binding)) => bindings.push(binding),
                    Some(Err(reason)) => {
                        warnings.push(reason);
                        unusable.push(printable);
                    }
                    None => {
                        warnings.push(format!(
                            "`{printable}` is not valid UTF-8, so it names no secret"
                        ));
                        unusable.push(printable);
                    }
                }
            }

            let log = (!cli.no_audit).then(|| AuditLog::new(paths.audit.clone()));
            let request = RunRequest {
                bindings: &bindings,
                unusable: &unusable,
                argv: &args.command,
                registry: &registry,
                audit: log.as_ref(),
                warnings: &warnings,
                // The binary always asks; `Auto` is what decides.
                tty: TtyPolicy::Auto,
            };

            let mut notes = io::stderr();
            match run(request, &mut notes) {
                Ok(outcome) => outcome.exit_code,
                Err(error) => {
                    let _ = writeln!(notes, "{NAME}: {error}");
                    error.exit_code()
                }
            }
        }

        Verb::Ls => match ls(&load.config, &mut io::stdout()) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("{NAME}: {error}");
                1
            }
        },

        Verb::Items(args) => {
            let store = match store::choose_store(&load.config, None, args.store.as_deref()) {
                Ok(store) => store,
                Err(problem) => {
                    eprintln!("{NAME}: {problem}");
                    return 78;
                }
            };
            match discoverer(&load.config, &store, &Reason::for_verb("items")) {
                Ok(discover) => {
                    match items(
                        discover.as_ref(),
                        args.vault.as_deref(),
                        &mut io::stdout(),
                        &mut io::stderr(),
                    ) {
                        Ok(code) => code,
                        Err(error) => {
                            eprintln!("{NAME}: {error}");
                            1
                        }
                    }
                }
                Err(error) => {
                    eprintln!("{NAME}: {error}");
                    1
                }
            }
        }

        Verb::Fields(args) => {
            let store = match store::choose_store(&load.config, None, args.store.as_deref()) {
                Ok(store) => store,
                Err(problem) => {
                    eprintln!("{NAME}: {problem}");
                    return 78;
                }
            };
            match discoverer(&load.config, &store, &Reason::for_verb("fields")) {
                Ok(discover) => {
                    match fields(
                        discover.as_ref(),
                        args.vault.as_deref(),
                        &args.item,
                        &mut io::stdout(),
                        &mut io::stderr(),
                    ) {
                        Ok(code) => code,
                        Err(error) => {
                            eprintln!("{NAME}: {error}");
                            1
                        }
                    }
                }
                Err(error) => {
                    eprintln!("{NAME}: {error}");
                    1
                }
            }
        }

        Verb::New(args) => {
            let Some(writer) = writer_for(&load.config, &args.name, args.store.as_deref(), "new")
            else {
                return 78;
            };
            let route = load.config.route(&args.name);
            let written = new(
                writer.as_ref(),
                &args.name,
                &route,
                args.length,
                &mut io::stdout(),
                &mut io::stderr(),
            );
            finish_write(
                "new",
                &args.name,
                writer.as_ref(),
                written,
                &paths,
                cli.no_audit,
            )
        }

        Verb::Put(args) => {
            let Some(writer) = writer_for(&load.config, &args.name, args.store.as_deref(), "put")
            else {
                return 78;
            };
            let route = load.config.route(&args.name);
            let interactive = io::stdin().is_terminal();

            // Echo is switched off around the read and restored afterwards. If it
            // cannot be switched off, the prompt is NOT offered: a prompt that
            // echoes would print the credential, which is worse than refusing.
            let quiet = if interactive {
                match keyless::tty::without_echo() {
                    Ok(guard) => Some(guard),
                    Err(error) => {
                        eprintln!(
                            "{NAME}: cannot switch terminal echo off ({error}), so the value \
                             would be printed as you typed it. Pipe it in instead: \
                             `printf '%s' \"$value\" | {NAME} put {}`",
                            args.name
                        );
                        return 74;
                    }
                }
            } else {
                None
            };

            let written = put(
                writer.as_ref(),
                &args.name,
                &route,
                &mut io::stdin(),
                interactive,
                &mut io::stdout(),
                &mut io::stderr(),
            );
            drop(quiet);
            finish_write(
                "put",
                &args.name,
                writer.as_ref(),
                written,
                &paths,
                cli.no_audit,
            )
        }

        Verb::Doctor(args) => {
            let verb = if args.probe {
                "doctor --probe"
            } else {
                "doctor"
            };
            let built = store::build(&load.config, &Invocation::for_verb(verb));
            let log = AuditLog::new(paths.audit.clone());
            match doctor(
                &paths,
                &load,
                &built.registry,
                &log,
                // Both channels: `doctor` is exactly the place the routine
                // consequences of a configuration are worth spelling out.
                &built
                    .warnings
                    .iter()
                    .chain(built.notes.iter())
                    .cloned()
                    .collect::<Vec<_>>(),
                args.probe,
                &mut io::stdout(),
            ) {
                Ok(code) => code,
                Err(error) => {
                    eprintln!("{NAME}: {error}");
                    1
                }
            }
        }
    }
}

/// The writer for one name, or `None` after saying why there is not one.
///
/// Separate from the verb bodies because `new` and `put` must resolve the identity
/// by exactly the same rule: an explicit `--store`, then the name's own `store`
/// pin, then `stores.default`, then the single configured backend. Two copies of
/// that would eventually disagree about which identity writes.
fn writer_for(
    config: &Config,
    name: &str,
    requested: Option<&str>,
    verb: &str,
) -> Option<Box<dyn keyless::store::manage::Manage>> {
    let store = match store::choose_store(config, Some(name), requested) {
        Ok(store) => store,
        Err(problem) => {
            eprintln!("{NAME}: {problem}");
            return None;
        }
    };
    match manager(config, &store, &Reason::for_verb(verb)) {
        Ok(writer) => Some(writer),
        Err(error) => {
            eprintln!("{NAME}: {error}");
            None
        }
    }
}

/// Record the write and return its exit code.
///
/// The row carries the verb, the name, and the IDENTITY that wrote it — which is
/// the point of recording it at all. A row saying `proton (manager)` can only have
/// come from a write verb, and a `run` row can only ever say `(reader)`, so "did a
/// session ever act as the editor?" is answerable from the log rather than from
/// trust.
///
/// No value can be in the row: the masker is empty because this process no longer
/// holds the value by the time it is written, and there is no flag by which one
/// could have reached argv in the first place.
fn finish_write(
    verb: &str,
    name: &str,
    writer: &dyn keyless::store::manage::Manage,
    written: io::Result<keyless::cmd::write::Written>,
    paths: &Paths,
    no_audit: bool,
) -> i32 {
    let code = match written {
        Ok(written) => written.exit_code,
        Err(error) => {
            eprintln!("{NAME}: {error}");
            return 1;
        }
    };

    if !no_audit {
        let state = if code == 0 {
            State::Injected
        } else {
            State::Degraded
        };
        let names = vec![name.to_owned()];
        let unresolved = if code == 0 { Vec::new() } else { names.clone() };
        let event = keyless::audit::Event::new(
            verb,
            state,
            names,
            &std::env::args().collect::<Vec<_>>(),
            &keyless::mask::Masker::new(),
        )
        .with_unresolved(unresolved)
        .with_identities(vec![writer.identity()])
        .with_exit_code(code);
        if let Err(error) = AuditLog::new(paths.audit.clone()).append(&event) {
            eprintln!("{NAME}: warning: {error}");
        }
    }
    code
}
