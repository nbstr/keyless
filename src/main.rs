//! The `keyless` binary: argument parsing and nothing else.
//!
//! Every decision lives in the library so it can be tested without a process,
//! and so the never-block invariant is provable by calling a function rather
//! than by scraping a terminal.

use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use keyless::State;
use keyless::audit::AuditLog;
use keyless::cmd::discover::{fields, items};
use keyless::cmd::doctor::{DoctorRequest, doctor};
use keyless::cmd::init::{InitRequest, init};
use keyless::cmd::ls::ls;
use keyless::cmd::refuse;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::cmd::status::Style;
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
    long_about = "keyless puts a named credential into one child process's environment, and \
                  nowhere else. The value never reaches your shell history, your scrollback, \
                  an agent's transcript, or this tool's own output.\n\n\
                  THE ONE RULE\n\
                  \x20 There is deliberately no verb that prints a value, and there never will \
                  be. That absence is the product. To use a secret, run the command that needs \
                  it under `keyless run`.\n\n\
                  IT NEVER BLOCKS YOUR COMMAND\n\
                  \x20 If a name cannot be resolved, `keyless run` says so on stderr, runs your \
                  command with that variable unset, and forwards the command's own exit code. \
                  So a missing credential is your program's error, at your program's exit code \
                  — never a refusal from this tool.\n\n\
                  WHAT EACH VERB IS FOR\n\
                  \x20 init     detect your stores, write a config, and prove one works\n\
                  \x20 doctor   what is proven right now, what is not, and what to do next\n\
                  \x20 ls       the names you have declared, and where each one points\n\
                  \x20 items    what a store holds — titles and states, never a value\n\
                  \x20 fields   the field names on one item — never a value, never a length\n\
                  \x20 new      generate a credential and store it, showing it to nobody\n\
                  \x20 put      read a credential on stdin and store it, echoing nothing\n\
                  \x20 run      run a command with named secrets in its environment",
    after_help = "START HERE\n\
                  \x20 keyless init                    detect, configure, prove\n\
                  \x20 keyless doctor                  is anything wrong, and where\n\
                  \x20 keyless run -s NAME -- cmd      the only way a value leaves a store\n\n\
                  Run `keyless <verb> --help` for one verb in full.",
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
    /// Say what is proven right now, what is not, and what to do next.
    Doctor(DoctorArgs),
    /// Detect your stores, write a config, and prove one works.
    Init(InitArgs),

    /// The words people reach for when they want to see a value.
    ///
    /// Hidden, so the verb list above stays exactly as long as it was and a
    /// reader can still check at a glance that nothing prints a value. Nothing
    /// new is reachable: these already exited 2, and they still exit 2. What
    /// changes is that the exit now says why. See [`keyless::cmd::refuse`].
    #[command(
        name = "get",
        hide = true,
        aliases = ["show", "cat", "read", "reveal", "print", "view", "dump", "export"]
    )]
    Refused(RefusedArgs),
}

#[derive(Args)]
struct RefusedArgs {
    /// Swallowed and never read. `keyless get DATABASE_URL` has to reach the
    /// refusal rather than dying on an unexpected argument, because the name is
    /// exactly what somebody typing this would have supplied.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "IGNORED"
    )]
    rest: Vec<OsString>,
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
    /// `-s DATABASE_URL` puts the secret `DATABASE_URL` in the child's
    /// environment as `$DATABASE_URL`. `-s PGURL=DATABASE_URL` puts the same
    /// secret there as `$PGURL`, so what a store calls something and what a
    /// program expects never have to agree.
    ///
    /// A name also lands in the variables its own declaration says it answers
    /// to, so `-s STAGING_DATABASE_URL` can arrive as `$DATABASE_URL` as well
    /// without anybody spelling it here. Both, never instead. A spelled
    /// `ENV=NAME` is an instruction and is never widened. `keyless doctor` lists
    /// which names do this.
    ///
    /// Repeat the flag for each name. A name that cannot be resolved does not
    /// stop the run: it is reported on stderr and the command runs with that
    /// variable unset.
    //
    // `OsString` rather than `String`, and that is a never-block fix rather
    // than a nicety. clap rejects a non-UTF-8 value for a `String` argument
    // **before `dispatch` is ever called**, and exits 2 — a third way out with
    // no child, reached while a perfectly runnable command sat after the `--`.
    // Taken as bytes, the same input becomes one unresolvable name: the run
    // warns, degrades, and still runs the command.
    //
    // Kept as an ordinary comment, not a doc comment: clap renders paragraph
    // two onward of a doc comment as `--help` text, so this paragraph was
    // being shown to every user who asked what `-s` does. A maintainer's
    // reason for a type is not the answer to that question.
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
    /// Also ask each declared name whether it resolves.
    ///
    /// Prints only that it resolved, that it is absent, or the store's error —
    /// never a value and never a length. This READS each credential out of its
    /// store, which is why it is not the default: against Proton that is one
    /// vendor call and one permanent audit entry per name. It may also trigger
    /// a keychain access prompt.
    #[arg(long)]
    probe: bool,
}

/// `init` writes a config file and nothing else. It never accepts a value.
///
/// There is no `--secret`, no `--value` and no prompt for one: the file it
/// writes holds names, store kinds and paths, and there is no field a credential
/// fits in. Adding one would be a change to [`keyless::config`], not to this
/// verb.
#[derive(Args)]
struct InitArgs {
    /// Write this backend as the default, instead of deciding.
    ///
    /// Accepted even for a backend that has not proved yet — writing the config
    /// before the login is a normal order to do things in.
    #[arg(long, value_name = "BACKEND")]
    store: Option<String>,

    /// Take the detected answer without asking anything.
    #[arg(long)]
    yes: bool,

    /// Replace an existing config file. Without it, an existing file is left
    /// exactly as it is and the run reports what it found.
    #[arg(long)]
    force: bool,

    /// Also install the hook pack into your Claude Code settings file.
    ///
    /// Without this, `init` only REPORTS whether the pack is registered. The
    /// settings file belongs to another program, so the write is a step you ask
    /// for. `hooks/install.py` performs it: it merges rather than overwrites,
    /// backs the file up first, and takes itself back out with `--uninstall`.
    #[arg(long)]
    hooks: bool,
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
                // `declared`, not `parse`: a bare `-s NAME` also lands in the
                // variables that name's own declaration says it answers to, so
                // the label and the variable never have to be reconciled by
                // hand. See `config::SecretRoute::aliases`.
                match spec
                    .to_str()
                    .map(|spec| Binding::declared(spec, &load.config))
                {
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

        // The header is for a person; a pipe gets the four fields it always
        // got. `stdout` is the stream being asked about, so it is the one asked.
        Verb::Ls => match ls(&load.config, io::stdout().is_terminal(), &mut io::stdout()) {
            Ok(()) => {
                // An empty `ls` printed nothing at all and exited 0, which is
                // the same output a broken install produces — and the state
                // every new user is in on their first run. The counts stay on
                // stdout at zero bytes, so a parser sees exactly what it always
                // saw; the sentence goes to stderr, where every other note from
                // this tool already goes.
                if load.config.secrets.is_empty() {
                    eprintln!(
                        "{NAME}: no names declared. `{NAME} run -s NAME -- cmd` still works for a \
                         name your default store already holds; declaring names is what makes \
                         them listable here."
                    );
                }
                0
            }
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
            warn_if_undeclared(&load.config, &args.name);
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
            warn_if_undeclared(&load.config, &args.name);
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
            let notes = built
                .warnings
                .iter()
                .chain(built.notes.iter())
                .cloned()
                .collect::<Vec<_>>();
            let request = DoctorRequest {
                paths: &paths,
                load: &load,
                registry: &built.registry,
                audit: &log,
                // Both channels: `doctor` is exactly the place the routine
                // consequences of a configuration are worth spelling out.
                notes: &notes,
                probe: args.probe,
                // The stream being decorated is the one asked about, exactly as
                // `ls` asks about its own. A redirected report gets clean text.
                style: Style::detect(io::stdout().is_terminal()),
            };
            match doctor(&request, &mut io::stdout()) {
                Ok(code) => code,
                Err(error) => {
                    eprintln!("{NAME}: {error}");
                    1
                }
            }
        }

        Verb::Init(args) => {
            // Both streams, because the question is written to one and read from
            // the other. A terminal on only one side is a pipeline, and a
            // pipeline is never prompted.
            let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
            let request = InitRequest {
                paths: &paths,
                force: args.force,
                assume_yes: args.yes,
                only: args.store.as_deref(),
                interactive,
                install_hooks: args.hooks,
                style: Style::detect(io::stdout().is_terminal()),
            };
            let stdin = io::stdin();
            match init(
                &request,
                &mut stdin.lock(),
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

        // Stderr, not stdout. This verb produces no result, and a message on
        // stdout would land in whatever the user piped it into — the one place
        // an explanation is no help at all.
        Verb::Refused(_) => {
            let word = refuse::typed_word(env::args());
            match refuse::no_such_verb(&word, &mut io::stderr()) {
                Ok(code) => code,
                Err(_) => refuse::EXIT_NO_SUCH_VERB,
            }
        }
    }
}

/// Say so when a stored name is one nothing else in the tool will ever mention.
///
/// `put` and `new` accept an undeclared name on purpose — it routes to its own
/// account in the default store, and requiring a config edit before a first
/// write would put a text editor in front of the shortest safe path. But `ls`
/// and `doctor --probe` read the CONFIG, so an undeclared name is invisible to
/// both: `put` reports `stored`, and the two verbs a person then reaches for to
/// confirm it print nothing about it at all.
///
/// Three outputs that each look like a working tool, describing a name that is
/// really there. The write is fine; the silence afterwards is what needs a
/// sentence. On stderr, so `stored` stays the only thing on stdout.
fn warn_if_undeclared(config: &Config, name: &str) {
    if !config.secrets.contains_key(name) {
        eprintln!(
            "{NAME}: `{name}` is not declared in your config, so `{NAME} ls` will not list it \
             and `{NAME} doctor --probe` will not check it. The value is stored either way."
        );
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
