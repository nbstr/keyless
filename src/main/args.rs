//! The command line as clap reads it: the banner `--help` prints, the verbs,
//! and each verb's arguments.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use keyless::NAME;
use keyless::random::DEFAULT_LENGTH;

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
                  IT NEVER BLOCKS YOUR COMMAND ON A FAILURE\n\
                  \x20 If a store or the daemon cannot answer, `keyless run` says DEGRADED on \
                  stderr, runs your command with that variable unset, and forwards the \
                  command's own exit code. It refuses only a name its store does not hold, an \
                  empty name, or a caller that fails attestation: REFUSED on stderr with the \
                  nearest names served, exit 64, and your command never starts.\n\n\
                  WHAT EACH VERB IS FOR\n\
                  \x20 setup    install everything: config, guards, agent instructions\n\
                  \x20 disable  confirm at a terminal, then stop every guard firing. Nothing \
                  is deleted\n\
                  \x20 enable   arm them again, no confirmation needed\n\
                  \x20 uninstall  confirm at a terminal, then remove exactly what setup \
                  created, and nothing you wrote\n\
                  \x20 init     detect your stores, write a config, and prove one works\n\
                  \x20 doctor   what is proven right now, what is not, and what to do next\n\
                  \x20 ls       the names you have declared, and where each one points\n\
                  \x20 items    what a store holds — titles and states, never a value\n\
                  \x20 fields   the field names on one item — never a value, never a length\n\
                  \x20 new      generate a credential and store it, showing it to nobody\n\
                  \x20 put      read a credential on stdin and store it, echoing nothing\n\
                  \x20 run      run a command with named secrets in its environment",
    after_help = "START HERE\n\
                  \x20 keyless setup                   one command; it names every file it touches\n\
                  \x20 keyless doctor                  is anything wrong, and where\n\
                  \x20 keyless run -s NAME -- cmd      the only way a value leaves a store\n\n\
                  IN YOUR WAY?\n\
                  \x20 keyless disable                 asks you to confirm at a terminal, \
                  then the guards stop firing. Your config and your secrets are untouched, \
                  and `keyless enable` is the whole of the way back.\n\
                  \x20 keyless uninstall               asks the same way, then removes what \
                  setup created, keeps what you wrote\n\n\
                  Run `keyless <verb> --help` for one verb in full.",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    /// Config file. Defaults to $XDG_CONFIG_HOME/keyless/config.json.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) config: Option<PathBuf>,

    /// Audit log. Defaults to $XDG_STATE_HOME/keyless/audit.jsonl.
    #[arg(long, global = true, value_name = "PATH")]
    pub(crate) audit: Option<PathBuf>,

    /// Do not record this invocation.
    ///
    /// `disable`, `enable` and `uninstall` ignore this: every switch of the
    /// guards is recorded whether it ran or was refused, because the record
    /// is what makes "when did the guards stop firing" answerable later —
    /// the one question a flag that suppressed it would make unanswerable
    /// for the person who never asked to skip it.
    #[arg(long, global = true)]
    pub(crate) no_audit: bool,

    #[command(subcommand)]
    pub(crate) command: Verb,
}

#[derive(Subcommand)]
pub(crate) enum Verb {
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

    /// Install everything: the config, the guards, and the agent instructions.
    #[command(alias = "install")]
    Setup(SetupArgs),

    /// Confirm at a terminal, then stop every guard firing. Nothing is
    /// deleted.
    Disable(ScopeArgs),

    /// Arm the guards again. Never asks — there is nothing here to confirm.
    Enable(ScopeArgs),

    /// Confirm at a terminal, then remove exactly what `setup` created, and
    /// nothing you wrote.
    Uninstall(ScopeArgs),

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

    /// One half of a wire protocol, not a verb anybody types.
    ///
    /// `keyless items --store infisical` spawns `infisical run` with THIS
    /// binary as the child, because the environment that child is handed is the
    /// only place the vendor's CLI ever says which keys a coordinate holds. The
    /// child writes back the NAMES of its own environment and never a value; see
    /// [`keyless::store::envnames`] for why a value cannot leave through it.
    ///
    /// Hidden for the same reason `get` is: the verb list is a security property
    /// a reader checks at a glance, and this one is machinery rather than a
    /// verb. Unlike `get` it is hidden without being a refusal — running it by
    /// hand prints the names of your own shell environment, which is what `env`
    /// already does.
    #[command(name = keyless::store::infisical::NAMES_VERB, hide = true)]
    Names,
}

#[derive(Args)]
pub(crate) struct RefusedArgs {
    /// Swallowed and never read. `keyless get DATABASE_URL` has to reach the
    /// refusal rather than dying on an unexpected argument, because the name is
    /// exactly what somebody typing this would have supplied.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "IGNORED"
    )]
    pub(crate) rest: Vec<OsString>,
}

#[derive(Args)]
pub(crate) struct ItemsArgs {
    /// Which store to ask. Defaults to the only configured one.
    ///
    /// `keyless items proton` is what a person types, so the positional form is
    /// the documented one. `--store` still works and is what a script that
    /// already had one keeps using; supplying both is refused rather than
    /// ranked.
    #[arg(value_name = "STORE")]
    pub(crate) store: Option<String>,

    /// Same thing as the positional STORE, for a caller that already spelled it
    /// this way.
    #[arg(long = "store", value_name = "STORE", conflicts_with = "store")]
    pub(crate) store_flag: Option<String>,

    /// Narrow to one vault.
    ///
    /// Proton: a vault name; without it, every vault the identity can see.
    /// Infisical: `<env>` or `<env>:<path>` — the coordinate `keyless ls`
    /// prints. Without it, every coordinate the config declares, and no others.
    /// 1Password: only the vault the store is pinned to; naming another is
    /// refused rather than listed.
    #[arg(long, visible_alias = "env", value_name = "VAULT")]
    pub(crate) vault: Option<String>,
}

impl ItemsArgs {
    /// The store, from whichever spelling arrived. `clap` guarantees at most one.
    pub(crate) fn store(&self) -> Option<&str> {
        self.store.as_deref().or(self.store_flag.as_deref())
    }
}

#[derive(Args)]
pub(crate) struct FieldsArgs {
    /// Which store to ask. Defaults to the only configured one.
    #[arg(value_name = "STORE")]
    pub(crate) store: Option<String>,

    /// Same thing as the positional STORE.
    #[arg(long = "store", value_name = "STORE", conflicts_with = "store")]
    pub(crate) store_flag: Option<String>,

    /// The vault the item is in. Required for stores that have vaults.
    #[arg(long, visible_alias = "env", value_name = "VAULT")]
    pub(crate) vault: Option<String>,

    /// The item's exact title.
    #[arg(long, value_name = "TITLE")]
    pub(crate) item: String,
}

impl FieldsArgs {
    /// The store, from whichever spelling arrived. `clap` guarantees at most one.
    pub(crate) fn store(&self) -> Option<&str> {
        self.store.as_deref().or(self.store_flag.as_deref())
    }
}

#[derive(Args)]
pub(crate) struct NewArgs {
    /// The declared name to store it under.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,

    /// Which store to write to. Defaults to the name's own `store`.
    #[arg(long, value_name = "STORE")]
    pub(crate) store: Option<String>,

    /// How many characters to generate.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_LENGTH)]
    pub(crate) length: usize,
}

/// `put` takes the value on **stdin and nowhere else**.
///
/// There is deliberately no `--value`, no `--secret` and no positional value: an
/// argument is readable from the process table for as long as the process lives,
/// which is the CLI-flag shape this tool exists to remove. A flag that exists
/// gets used, so the flag does not exist.
#[derive(Args)]
pub(crate) struct PutArgs {
    /// The declared name to store it under.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,

    /// Which store to write to. Defaults to the name's own `store`.
    #[arg(long, value_name = "STORE")]
    pub(crate) store: Option<String>,
}

#[derive(Args)]
pub(crate) struct RunArgs {
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
    pub(crate) secret: Vec<OsString>,

    /// Infisical environment for names in this run that declare none.
    ///
    /// Infisical requires one on every call and `keyless` defaults none, so a
    /// name that declares no `env` and is not covered by this does not resolve —
    /// the run degrades and says so. A name's own `env` wins over this.
    #[arg(long, value_name = "SLUG")]
    pub(crate) env: Option<String>,

    /// The command to run, after `--`.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        value_name = "COMMAND"
    )]
    pub(crate) command: Vec<OsString>,
}

#[derive(Args)]
pub(crate) struct DoctorArgs {
    /// Also ask each declared name whether it resolves.
    ///
    /// Prints only that it resolved, that it is absent, or the store's error —
    /// never a value and never a length. This READS each credential out of its
    /// store, which is why it is not the default: against Proton that is one
    /// vendor call and one permanent audit entry per name. It may also trigger
    /// a keychain access prompt.
    #[arg(long)]
    pub(crate) probe: bool,

    /// The same scope flags `setup` takes.
    ///
    /// A report is about ONE machine. Without these, a `doctor` aimed at a
    /// scratch config still read the default agent directory and printed a
    /// guards row about a different install — two machines in one report, with
    /// nothing saying so.
    #[command(flatten)]
    pub(crate) scope: ScopeArgs,
}

/// `init` writes a config file and nothing else. It never accepts a value.
///
/// There is no `--secret`, no `--value` and no prompt for one: the file it
/// writes holds names, store kinds and paths, and there is no field a credential
/// fits in. Adding one would be a change to [`keyless::config`], not to this
/// verb.
#[derive(Args)]
pub(crate) struct InitArgs {
    /// Write this backend as the default, instead of deciding.
    ///
    /// Accepted even for a backend that has not proved yet — writing the config
    /// before the login is a normal order to do things in.
    #[arg(long, value_name = "BACKEND")]
    pub(crate) store: Option<String>,

    /// Take the detected answer without asking anything.
    #[arg(long)]
    pub(crate) yes: bool,

    /// Replace an existing config file's store choice. Without it, an
    /// existing file is left exactly as it is and the run reports what it
    /// found. Every name already declared under `secrets` is carried over —
    /// this switches which backend is default, it does not forget what you
    /// told it to fetch.
    #[arg(long)]
    pub(crate) force: bool,

    /// Also install the hook pack into your Claude Code settings file.
    ///
    /// Without this, `init` only REPORTS whether the pack is registered. The
    /// settings file belongs to another program, so the write is a step you ask
    /// for. `hooks/install.py` performs it: it merges rather than overwrites,
    /// replaces the file atomically, and takes itself back out with
    /// `--uninstall`.
    #[arg(long)]
    pub(crate) hooks: bool,
}

/// The flags every setup-family verb shares.
///
/// One struct rather than four copies: `uninstall` has to resolve the agent
/// directory exactly as `setup` did, or it looks for its own work in the wrong
/// file and reports that there was none.
#[derive(Args)]
pub(crate) struct ScopeArgs {
    /// The agent's configuration directory, holding `settings.json`.
    ///
    /// Defaults to `~/.claude`, or `$KEYLESS_CLAUDE_DIR`. Every report prints
    /// the file it resolved: an install into a settings file the harness never
    /// opens would report success and guard nothing.
    #[arg(long, value_name = "DIR")]
    pub(crate) claude_dir: Option<PathBuf>,

    /// The record of what setup created. Defaults to
    /// `$XDG_STATE_HOME/keyless/setup-receipt.json`.
    #[arg(long, value_name = "PATH")]
    pub(crate) receipt: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct SetupArgs {
    #[command(flatten)]
    pub(crate) scope: ScopeArgs,

    /// Print every file this would touch, and change nothing.
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Also stand up the daemon. Needs root, and asks for it with sudo.
    ///
    /// Separate because it is a different kind of act: it creates a system
    /// user, writes under `/usr/local`, and only makes sense once you move your
    /// secrets behind it — which is a decision this command cannot take for you.
    #[arg(long)]
    pub(crate) daemon: bool,

    /// Do not install the agent instructions.
    #[arg(long)]
    pub(crate) no_skill: bool,

    /// Put back entries a previous setup installed and you have since removed.
    ///
    /// Without this they stay removed. An installer that silently restores a
    /// deletion overwrites a decision every time it runs.
    #[arg(long)]
    pub(crate) restore: bool,

    /// Write this backend as the default, instead of deciding.
    #[arg(long, value_name = "BACKEND")]
    pub(crate) store: Option<String>,

    /// Take the detected answer without asking anything.
    #[arg(long)]
    pub(crate) yes: bool,
}
