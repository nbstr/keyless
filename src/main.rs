//! The `keyless` binary: argument parsing and nothing else.
//!
//! Every decision lives in the library so it can be tested without a process,
//! and so the never-block invariant is provable by calling a function rather
//! than by scraping a terminal.

use std::env;
use std::io::{self, IsTerminal, Write};

use clap::Parser;

use keyless::audit::AuditLog;
use keyless::cmd::discover::{fields, items};
use keyless::cmd::doctor::{DoctorRequest, doctor};
use keyless::cmd::init::{InitRequest, init};
use keyless::cmd::ls::ls;
use keyless::cmd::refuse;
use keyless::cmd::run::{Binding, RunRequest, TtyPolicy, run};
use keyless::cmd::setup::uninstall::uninstall;
use keyless::cmd::setup::{SetupRequest, setup};
use keyless::cmd::status::Style;
use keyless::cmd::write::{new, put};
use keyless::config::Config;
use keyless::paths::Paths;
use keyless::store::Invocation;
use keyless::store::discover::discoverer;
use keyless::store::envnames;
use keyless::store::proton::Reason;
use keyless::{NAME, store};

#[path = "main/args.rs"]
mod args;
#[path = "main/switch.rs"]
mod switch;
#[path = "main/writes.rs"]
mod writes;

use args::{Cli, Verb};
use switch::{confirm_or_refuse, record_switch, setup_paths, switch};
use writes::{finish_write, warn_if_undeclared, writer_for};

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
        Verb::Ls => match ls(
            &load.config,
            io::stdout().is_terminal(),
            &mut io::stdout(),
            &mut io::stderr(),
        ) {
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
            let store = match store::choose_store(&load.config, None, args.store()) {
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
            let store = match store::choose_store(&load.config, None, args.store()) {
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
                // The guards row is a top-level fact about this machine, so the
                // one caller a person actually types always supplies it.
                setup: Some(&setup_paths(&args.scope)),
                // Both channels: `doctor` is exactly the place the routine
                // consequences of a configuration are worth spelling out.
                notes: &notes,
                probe: args.probe,
                // The one caller that is a real machine asks the real machine.
                // Every other caller hands `doctor` a fixed answer, which is
                // what keeps the report testable.
                freshness: &keyless::freshness::check(),
                checkout: &keyless::checkout::check(),
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
                report_guards: true,
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

        Verb::Setup(args) => {
            let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
            let resolved = setup_paths(&args.scope);
            let request = SetupRequest {
                paths: &paths,
                setup: &resolved,
                dry_run: args.dry_run,
                restore: args.restore,
                with_daemon: args.daemon,
                with_skill: !args.no_skill,
                interactive,
                assume_yes: args.yes,
                only: args.store.as_deref(),
                style: Style::detect(io::stdout().is_terminal()),
            };
            let stdin = io::stdin();
            match setup(
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

        Verb::Disable(scope) => switch(&scope, false, &paths),
        Verb::Enable(scope) => switch(&scope, true, &paths),

        Verb::Uninstall(scope) => match confirm_or_refuse("uninstall", &paths) {
            Some(code) => code,
            None => {
                let resolved = setup_paths(&scope);
                let request = SetupRequest {
                    paths: &paths,
                    setup: &resolved,
                    dry_run: false,
                    restore: false,
                    with_daemon: false,
                    with_skill: true,
                    interactive: false,
                    assume_yes: true,
                    only: None,
                    style: Style::detect(io::stdout().is_terminal()),
                };
                let code = match uninstall(&request, &mut io::stdout(), &mut io::stderr()) {
                    Ok(code) => code,
                    Err(error) => {
                        eprintln!("{NAME}: {error}");
                        1
                    }
                };
                record_switch(&paths, "uninstall", "uninstalled", code);
                code
            }
        },

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

        // The listing probe. It reads no config, reaches no store and writes no
        // audit row, because it is not an invocation of `keyless` in its own
        // right — it is the far end of one `items` call that already recorded
        // itself. Its whole body is "name the environment I was handed".
        Verb::Names => match envnames::emit(envnames::names(), &mut io::stdout()) {
            Ok(()) => 0,
            // A broken pipe here is the parent giving up on the listing, which
            // it will report itself. Saying it twice on a stream the parent is
            // also reading would corrupt the diagnosis it is building.
            Err(_) => 1,
        },
    }
}
