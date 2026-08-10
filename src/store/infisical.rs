//! Infisical, via the one verb of its CLI that does not print a value.
//!
//! # The problem this adapter exists to solve
//!
//! Infisical's CLI has three verbs that yield a secret — `infisical secrets`,
//! `infisical secrets get NAME` and `infisical export` — and **all three write
//! plaintext to stdout**. In an agent session stdout is the transcript, so all
//! three are exactly the disclosure `keyless` exists to prevent, and all three
//! are the right thing for an agent harness to deny outright.
//!
//! The fourth verb, `infisical run --env=<env> --path=<path> -- <cmd>`, prints
//! nothing. It fetches the secrets, adds them to a child process's environment,
//! and execs. That is the only mechanism this adapter is allowed to use, and it
//! has a consequence worth stating plainly: **it hands back a process, not a
//! value.**
//!
//! # Two ways to build on a verb that yields no value
//!
//! **Nesting** — `keyless run` spawns `infisical run`, which spawns the user's
//! command. The plaintext never enters this process at all, which sounds like
//! the safer answer. Measured against what it actually costs, it is not:
//!
//! - **Masking dies.** `keyless` cannot redact a value it has never seen, and
//!   Infisical has no masking of its own. Every Infisical-backed secret would
//!   lose the one protection this tool's own README leads with.
//! - **The child gets everything.** `infisical run` injects every secret at the
//!   path, not the ones that were asked for, which in a real project is
//!   hundreds of names reaching a child that asked for one.
//! - **`INJECTED` becomes a lie.** Measured 2026-08-06 with CLI 0.43.114: a
//!   `run` against an environment and path that hold nothing at all exits **0**
//!   and reports `Injecting 0 Infisical secrets`. Under nesting `keyless` sees
//!   a clean exit, reports `INJECTED`, and the child has nothing. The state
//!   would be a guess dressed as a fact, and `DEGRADED` — the whole point of
//!   naming what did not resolve — would be unimplementable.
//! - **Three processes and a pty problem.** The child `keyless` supervises
//!   would be `infisical`, not the user's command, so signals, window resizes
//!   and the exit code all travel one layer further than the terminal code
//!   here was written for.
//!
//! **Probing** — what this adapter does. Run `infisical run` with the smallest
//! possible child: `printenv NAME`, which writes one variable to stdout and
//! exits. `keyless` captures that, wraps it in [`Secret`], and from there the
//! path is identical to the keychain adapter's. One name in, one value out.
//!
//! This is not a way around the policy; it is the policy's own mechanism. The
//! denied verbs are denied because they print a value **into the session**. Here
//! the value goes into a pipe this process owns, into a type that zeroizes on
//! drop, and out again only into the child's environment — masked on the way
//! back. `security -w` has exactly the same shape and is what the keychain
//! adapter has always done.
//!
//! What probing costs, stated rather than implied:
//!
//! - **One `infisical run` per name.** Each is a process spawn and a network
//!   round trip. Ten names is ten fetches, and the timeout is per lookup.
//! - **The plaintext enters this process.** Nesting would have avoided that.
//!   It buys masking, exact narrowing and an honest `DEGRADED`, and the
//!   residency is the same one the keychain path already accepts.
//! - **`infisical` still holds every secret at the path in its own memory.**
//!   Narrowing is about what reaches the user's command, not about what the
//!   vendor's CLI loads.
//!
//! # Measured, not assumed
//!
//! Against `infisical` 0.43.114 on 2026-08-06:
//!
//! | Observation | Consequence here |
//! |---|---|
//! | stdout of a `run` is byte-for-byte the child's stdout | the probe can be read directly |
//! | `--silent` suppresses tip/info lines | passed on every call |
//! | logs default to stderr, and `LOG_DESTINATION=stdout` moves them to stdout | `--log-destination=stderr` is passed explicitly, so a stray environment variable cannot poison the probe |
//! | `--telemetry` defaults to **true** | `--telemetry=false` is passed on every call; see below |
//! | a child exiting non-zero yields `failed to wait for command termination: exit status N` on stderr | tells "the variable is unset" apart from "Infisical itself failed" |
//! | Infisical's own failure yields its own message and empty stdout | reported as a backend error, with that message |
//!
//! # Telemetry
//!
//! `keyless` promises it makes no network call the user did not ask for. The
//! Infisical CLI's telemetry defaults to on, so an adapter that shelled out
//! with default flags would break that promise transitively — `keyless` would
//! be the reason a report left the machine. `--telemetry=false` is therefore
//! not configurable here: it is passed on every invocation this adapter makes.
//! It says nothing about what the user's own `infisical` runs do.
//!
//! # What this adapter never touches
//!
//! `~/.infisical/.token`, `~/.infisical/.client-id`, and the encrypted cache in
//! `~/.infisical/secrets-backup/`. The login belongs to the CLI and is inherited
//! by spawning it. There is no code path here that opens a file under
//! `~/.infisical`, and no config field in which a token would fit.
//!
//! # There is no default environment, and that is the point
//!
//! `--env` is mandatory on the vendor's CLI. It has no default, because an
//! environment in Infisical is the tenancy boundary: `prod` and `staging` hold
//! the same key names with different real values.
//!
//! An earlier build of this adapter defaulted the environment in its own config,
//! and the cost was measured rather than imagined. With `stores.default` set to
//! `infisical` and that default set to `prod`, **every name a caller invented
//! resolved against production** — including one declared in no config at all,
//! which came back with a real value, exit 0, and nothing on stderr. A caller
//! asking for `DATABASE_URL` while meaning staging got production and the
//! command succeeded.
//!
//! So the environment now comes from exactly two places, most specific first:
//!
//! 1. the name's own `env` in `secrets`;
//! 2. `keyless run --env <slug>`, which covers every name in that invocation
//!    that declares none.
//!
//! Neither, and **the lookup does not happen**. Nothing is spawned, no network
//! call is made, and the name is reported unresolved with the sentence in
//! [`missing_env_detail`]. That is a degrade, not a refusal: `run` still spawns
//! the child with an unmodified environment and still forwards its exit code.
//!
//! `path` is deliberately not treated the same way — see
//! [`crate::config::InfisicalConfig::path`] for the asymmetry.
//!
//! # Listing what a coordinate holds, on a CLI with no listing verb
//!
//! [`Discover`] is implemented on the same one verb. `infisical run` puts every
//! secret at a coordinate into a child's environment, so the child knows their
//! NAMES — and `keyless` is the child. It runs itself as
//! `keyless __names`, which writes the names of its own environment and never a
//! value; see [`crate::store::envnames`] for why a value cannot be smuggled out
//! as a name through that path.
//!
//! Two consequences of taking a listing from an environment rather than from a
//! vendor's listing verb, both stated rather than implied:
//!
//! - **The child's environment is cleared before the vendor runs**, down to
//!   [`FORWARDED_EXACT`] plus `INFISICAL_*`. Without that, every variable this
//!   process happens to carry would appear in the listing as though the store
//!   held it.
//! - **A secret whose name is one of those forwarded ones is not listed.** An
//!   inherited `PATH` and a secret called `PATH` arrive as one entry, and
//!   nothing in the environment says which wrote it. The forwarded set is
//!   deliberately tiny and fixed so the blind spot is nameable.
//!
//! # The lookup is cleared too, and that is not decoration
//!
//! [`InfisicalStore::resolve`] runs the vendor with the SAME cleared
//! environment, for a reason measured rather than argued. The probe's child is
//! `printenv KEY`, and `printenv` cannot tell a variable the vendor injected
//! from one this process already carried. So a probe that inherited the
//! environment answered from that environment: with a config declaring `X`
//! against Infisical, `X` exported in the calling shell, and a store holding
//! **nothing at all**, `keyless doctor --probe` printed
//! `✔ X proven — read back from infisical`. That is the exact false green this
//! tool exists to refuse, and it was not confined to the nine forwarded names —
//! it applied to every name. A `run` on the same evidence said nothing at all,
//! which is how this tool spells success, and wrote an `INJECTED` row naming
//! that store into the audit log — so the wrong answer was durable rather than
//! merely printed.
//!
//! Clearing makes the lookup exact for every name that is NOT forwarded: the
//! store holds it, or `printenv` exits 1 and the name is unresolved. For a name
//! that IS forwarded the variable must still be handed in — the vendor needs
//! `HOME` and `PATH` to run at all — so [`InfisicalStore::resolve`] compares the
//! value it reads back against the exact bytes it forwarded and refuses to
//! return its own environment as a credential. Three outcomes, all stated:
//!
//! | Read back | Meaning | What happens |
//! |---|---|---|
//! | differs from what was forwarded | only the vendor could have written it | resolved |
//! | identical to what was forwarded | the store holds nothing, or holds that same value | reported, never returned |
//! | `printenv` exits 1 | the variable is unset in the child | unresolved, as for any name |
//!
//! **Whether the vendor's injection outranks a forwarded variable of the same
//! name is the vendor's own behaviour, and this crate asserts nothing about
//! it.** It does not need to: the comparison is correct under either
//! precedence. That is the whole reason it is a comparison rather than a rule.
//!
//! # Why not the vendor's own listing verbs, and why not its REST API
//!
//! `infisical secrets` and `infisical export` print values, and `--silent`
//! does not suppress them — measured. Building on them would mean stripping
//! values off text, and a value containing a newline produces a following line
//! with no `=` in it, which a stripper passes through as though it were a key.
//! Being *nearly* safe is how this class of bug ships.
//!
//! The REST API returns JSON, where a typed `secretKey` field could not carry a
//! fragment of a value — but reaching it needs a credential, and `keyless` has
//! none. This adapter authenticates by spawning the vendor's CLI and inheriting
//! its login; there is no code path here that opens a file under `~/.infisical`,
//! and no config field a token fits in. An HTTP client would also be the first
//! network stack in a crate whose whole dependency list is five crates and
//! whose auditability is the product. So the API is the wrong trade here, not
//! an unexamined one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::config::Config;
use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;
use crate::store::discover::{Discover, FieldSummary, ItemSummary};
use crate::store::envnames;
use crate::store::exec::{self, CaptureError, capture, first_line, strip_one_newline};

/// Disables the vendor CLI's telemetry, which defaults to on.
///
/// A single constant so the string is greppable and so the CLI test that
/// forbids telemetry strings in the built binary can allow this one exactly.
const TELEMETRY_OFF: &str = "--telemetry=false";

/// The substring the CLI uses when it is reporting the *child's* exit status
/// rather than a failure of its own.
///
/// Measured against 0.43.114: an unset variable makes `printenv` exit 1, and
/// the CLI reports `failed to wait for command termination: exit status 1`.
/// Infisical's own failures — no project, bad token, no network — carry their
/// own wording and never this one.
///
/// If a future release rewords it, this stops matching and the lookup is
/// reported as a backend error carrying that new wording. The run degrades
/// either way; only the sentence the user reads changes, and it changes to
/// something more informative rather than less.
const CHILD_EXIT_MARKER: &str = "exit status";

/// This backend's id, as it appears in a `store` pin and in every message.
///
/// A constant because `ls` has to ask "is this name an Infisical name?" to know
/// whether it has an environment to show, and a second spelling of the string
/// would drift into a listing that quietly stopped answering that question.
pub const STORE_ID: &str = "infisical";

/// What `ls` prints where an environment would go, when a name has none.
///
/// A word rather than a blank, because a blank column reads as "nothing to say
/// here" and this is the opposite: it is the one fact that stops the name
/// resolving.
pub const NO_ENV: &str = "no-env";

/// Where one name points, before an environment is known to exist.
///
/// `env` is an `Option` because [there is no default](self#there-is-no-default-environment-and-that-is-the-point).
/// `None` is not a value to substitute for; it is a name that cannot be looked
/// up, and the type says so rather than leaving it to a caller to remember.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The environment slug, from the name's own `env` or from `--env`.
    pub env: Option<String>,
    /// The folder path. Defaults to `/`, which is the vendor's own default.
    pub path: String,
    /// The key read at that coordinate. Defaults to the name itself.
    pub key: String,
}

impl Route {
    /// One field for `ls`: `staging:/backend`, or `no-env:/backend`.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}:{}", self.env.as_deref().unwrap_or(NO_ENV), self.path)
    }
}

/// Every declared name's Infisical coordinates, plus what an undeclared one gets.
///
/// Public, and shared by the adapter and by `ls`, so the two cannot disagree
/// about where a name points. A listing that showed a different environment from
/// the one the lookup uses would be worse than showing none at all — it would be
/// the same invisible-environment hazard, wearing the clothes of the fix.
#[derive(Debug, Clone, Default)]
pub struct Routing {
    default_path: String,
    invocation_env: Option<String>,
    routes: BTreeMap<String, Route>,
}

impl Routing {
    /// Read the config, with the environment this invocation supplied, if any.
    #[must_use]
    pub fn from_config(config: &Config, invocation_env: Option<&str>) -> Self {
        let settings = &config.stores.infisical;
        let invocation_env = invocation_env.map(str::to_owned);
        let routes = config
            .secrets
            .iter()
            .map(|(name, route)| {
                let resolved = Route {
                    // The name's own `env` outranks `--env`. The flag is a
                    // blanket for names that say nothing; a name that states
                    // where it lives must not be repainted by it.
                    env: route.env.clone().or_else(|| invocation_env.clone()),
                    path: route.path.clone().unwrap_or_else(|| settings.path.clone()),
                    key: route.key.clone().unwrap_or_else(|| name.clone()),
                };
                (name.clone(), resolved)
            })
            .collect();

        Routing {
            default_path: settings.path.clone(),
            invocation_env,
            routes,
        }
    }

    /// Where `name` points. An undeclared name looks itself up as the key, at
    /// the default path — and with an environment only if the invocation gave
    /// one, which is what stops an invented name reaching a real vault.
    #[must_use]
    pub fn route(&self, name: &str) -> Route {
        self.routes.get(name).cloned().unwrap_or_else(|| Route {
            env: self.invocation_env.clone(),
            path: self.default_path.clone(),
            key: name.to_owned(),
        })
    }

    /// Every distinct coordinate the config's own names point at.
    ///
    /// This is what `items` lists when nobody named a location, and the choice
    /// is the answer to "should a listing verb enumerate a whole store?".
    /// **It does not.** The config is an allowlist, so with no `--vault` the
    /// verb reports the coordinates already written down in it and no others —
    /// which is exactly the set somebody setting up a name needs to see. A
    /// coordinate nobody declared is reachable only by naming it, which makes
    /// enumerating the store a thing a person does on purpose rather than a
    /// default.
    ///
    /// Ordered and deduplicated, so two names in one folder cost one listing.
    fn declared_locations(&self) -> Vec<Location> {
        let mut seen: BTreeSet<Location> = self
            .routes
            .values()
            .filter_map(|route| {
                route.env.as_ref().map(|env| Location {
                    env: env.clone(),
                    path: route.path.clone(),
                })
            })
            .collect();
        if let Some(env) = &self.invocation_env {
            seen.insert(Location {
                env: env.clone(),
                path: self.default_path.clone(),
            });
        }
        seen.into_iter().collect()
    }

    /// Coordinates a health check may use, without inventing an environment.
    ///
    /// The invocation's own environment first, then the first declared name that
    /// has one — taken with that name's path so the pair is coherent. Borrowing
    /// an environment somebody wrote down is not the same as defaulting one:
    /// nothing here supplies an environment that appears nowhere in the config
    /// or on the command line.
    ///
    /// `BTreeMap` iteration is ordered by name, so "first" is deterministic
    /// rather than whatever a hash happened to produce.
    fn health_coordinates(&self) -> Option<Coordinates> {
        if let Some(env) = self.invocation_env.clone() {
            return Some(Coordinates {
                env,
                path: self.default_path.clone(),
                key: HEALTH_KEY.to_owned(),
            });
        }
        self.routes.values().find_map(|route| {
            route.env.clone().map(|env| Coordinates {
                env,
                path: route.path.clone(),
                key: HEALTH_KEY.to_owned(),
            })
        })
    }
}

/// Why a name with no environment cannot be looked up, and both ways to fix it.
///
/// Written once, because this sentence is the whole migration: a config that
/// used to lean on a machine-wide default gets these words instead of a value
/// from the wrong environment, and it has to be good enough to act on without
/// anybody explaining it.
fn missing_env_detail(name: &str) -> String {
    format!(
        "`{name}` has no Infisical environment. Infisical requires one on every \
         call and `keyless` does not default it, because a default resolves a \
         name you never declared against whichever environment this machine \
         happens to name. Give it one: put \"env\": \"staging\" on \"{name}\" \
         under `secrets`, or pass `keyless run --env staging` for the whole \
         command. A name's own `env` wins over the flag."
    )
}

/// The subcommand the listing probe runs `keyless` as.
///
/// Two leading underscores because it is not a verb anybody types: it is one
/// half of a wire protocol whose other half is [`InfisicalStore::items`]. It is
/// hidden from `--help` for the same reason `get` is — the verb list is a
/// security property a reader must be able to check at a glance — and unlike
/// `get` it is hidden without being a refusal, because it does something.
pub const NAMES_VERB: &str = "__names";

/// The variables forwarded into the cleared environment the vendor CLI runs in.
///
/// Everything else is dropped, so a variable this process happens to carry
/// cannot appear in a listing as though the store held it.
///
/// Each entry is here because the vendor needs it, and the list is short on
/// purpose: **a secret whose name is on this list cannot be told apart from the
/// forwarded variable and is not listed.** Keeping the list to the names nobody
/// stores as a credential is what keeps that blind spot nameable.
///
/// A LOOKUP of such a name is a different matter and is not blind: see
/// [`InfisicalStore::resolve`], which compares what it reads back against what
/// it forwarded, and reports the collision rather than returning either guess.
///
/// - `HOME` — where the CLI keeps its login, its instance domain and its cache.
///   Without it the lookup is unauthenticated.
/// - `PATH` — the binary defaults to the bare name `infisical`, so the spawn
///   itself needs it.
/// - `TMPDIR`, `SSL_CERT_FILE`, `SSL_CERT_DIR` and the proxy variables — the
///   ordinary way a machine says how to reach the network at all.
///
/// `LOG_LEVEL`, `LOG_FORMAT` and `LOG_DESTINATION` are deliberately ABSENT.
/// The CLI reads all three from the environment, this adapter pins them on the
/// command line, and forwarding them would only let an ambient variable make
/// the vendor noisier on a stream this code reads.
pub const FORWARDED_EXACT: [&str; 9] = [
    "HOME",
    "PATH",
    "TMPDIR",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "no_proxy",
];

/// Every variable starting with this is forwarded too.
///
/// Machine-identity auth, a self-hosted domain and a service token all arrive
/// this way, and a listing that worked only for a browser login would be a
/// listing that worked only on a laptop.
pub const FORWARDED_PREFIX: &str = "INFISICAL_";

/// Whether a variable of this process is handed to the vendor CLI.
#[must_use]
fn is_forwarded(name: &str) -> bool {
    FORWARDED_EXACT.contains(&name) || name.starts_with(FORWARDED_PREFIX)
}

/// This process's forwarded variables, name and value.
///
/// The listing's baseline, and the only thing a listing subtracts. It is what
/// this process ACTUALLY carries rather than what [`is_forwarded`] would allow:
/// on a machine with no proxy configured, `HTTPS_PROXY` is forwarded by nothing
/// and a secret of that name is a real secret.
fn forwarded_vars() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| is_forwarded(&name.to_string_lossy()))
        .collect()
}

/// The value this process hands the vendor under `key`, if it hands one.
///
/// `None` covers both halves of "there is no collision": a key that is not
/// forwarded at all, and a forwarded NAME that this machine does not actually
/// set. The second is the same asymmetry [`forwarded_vars`] rests on — with no
/// proxy configured, a secret called `HTTPS_PROXY` is an ordinary secret.
fn forwarded_value(key: &str) -> Option<std::ffi::OsString> {
    if is_forwarded(key) {
        std::env::var_os(key)
    } else {
        None
    }
}

/// Why a forwarded name's value cannot be attributed, and how to make it one.
///
/// Written by this crate rather than taken from a backend's stderr, like the
/// empty-value sentence beside it. It carries no value: the whole subject is
/// that the two candidate values are byte-identical, so naming either would
/// name both.
fn shadowed_detail(key: &str) -> String {
    format!(
        "`{key}` is one of the variables this process must hand the Infisical CLI for it to \
         run at all, and the value read back is byte-for-byte the one that was handed in. \
         Either the store holds no `{key}`, or it holds that same value — nothing in a child's \
         environment says which wrote it, so this is reported rather than guessed. Store the \
         secret under a key of its own and point at it with \"key\" under `secrets`."
    )
}

/// One environment-and-folder pair a listing can be taken at.
///
/// The same two coordinates [`Route`] carries, without the key — because a
/// listing is the question "which keys are here?", so a key would be an answer
/// smuggled into the question.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location {
    /// The environment slug. Never defaulted; see the module docs.
    pub env: String,
    /// The folder path, defaulted to the vendor's own `/`.
    pub path: String,
}

impl Location {
    /// The one field a listing shows, in the spelling `ls` already prints:
    /// `staging:/backend`.
    #[must_use]
    pub fn describe(&self) -> String {
        format!("{}:{}", self.env, self.path)
    }

    /// Read the `--vault` form: `staging`, or `staging:/backend`.
    ///
    /// The path half is optional and falls back to `default_path`, which is the
    /// same field `resolve` defaults a route's path from — so a location typed
    /// with no path points where an undeclared name of the config would.
    ///
    /// # Errors
    ///
    /// A sentence naming the accepted form, when the environment half is empty.
    /// An environment is never guessed here for the same reason it is never
    /// guessed in a lookup: `prod` and `staging` hold the same key names.
    pub fn parse(spec: &str, default_path: &str) -> Result<Location, String> {
        let (env, path) = match spec.split_once(':') {
            Some((env, path)) => (env.trim(), path.trim()),
            None => (spec.trim(), ""),
        };
        if env.is_empty() {
            return Err(format!(
                "`{spec}` names no Infisical environment. Write it as `<env>` or \
                 `<env>:<path>`, for example `staging` or `staging:/backend` — \
                 the same coordinate `{} ls` prints beside every Infisical name",
                crate::NAME
            ));
        }
        let path = if path.is_empty() {
            default_path.to_owned()
        } else if path.starts_with('/') {
            path.to_owned()
        } else {
            // The vendor's paths are absolute. Accepting `staging:backend` and
            // fixing it is kinder than a 404 from the API that says the folder
            // was not found.
            format!("/{path}")
        };
        Ok(Location {
            env: env.to_owned(),
            path,
        })
    }
}

/// The variable a health check asks for.
///
/// Already in this process's environment and not a credential, so proving the
/// whole chain works reads none of the user's secrets.
const HEALTH_KEY: &str = "PATH";

/// Where one name lives in Infisical, once an environment is known.
///
/// The type a probe can be built from — which is why [`Route`] and this are
/// separate types rather than one type with an `Option`. There is no way to
/// construct a probe without an environment, so no code path can forget to
/// check for one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Coordinates {
    env: String,
    path: String,
    key: String,
}

/// Reads one secret at a time through `infisical run`.
pub struct InfisicalStore {
    binary: PathBuf,
    probe_binary: PathBuf,
    routing: Routing,
    project_id: Option<String>,
    config_dir: Option<PathBuf>,
    timeout: Duration,
}

impl InfisicalStore {
    /// Construct from a parsed config and this invocation's `--env`, if any.
    #[must_use]
    pub fn from_config(config: &Config, invocation_env: Option<&str>) -> Self {
        let settings = &config.stores.infisical;
        InfisicalStore {
            binary: settings.binary.to_path_buf(),
            probe_binary: settings.probe_binary.to_path_buf(),
            routing: Routing::from_config(config, invocation_env),
            project_id: settings.project_id.clone(),
            config_dir: settings
                .config_dir
                .as_deref()
                .map(|path| path.to_path_buf()),
            timeout: crate::config::bounded_timeout(settings.timeout_ms),
        }
    }

    /// The coordinates for a name, or the sentence saying why there are none.
    ///
    /// The error path spawns nothing and reaches no network: a name with no
    /// environment is not a failed lookup, it is a lookup that never happened.
    fn coordinates(&self, name: &str) -> Result<Coordinates, StoreError> {
        let route = self.routing.route(name);
        match route.env {
            Some(env) => Ok(Coordinates {
                env,
                path: route.path,
                key: route.key,
            }),
            None => Err(self.misconfigured(missing_env_detail(name))),
        }
    }

    /// Build one `infisical run … -- printenv KEY` invocation.
    ///
    /// Every flag here is either a coordinate or a defence:
    ///
    /// - `--silent` and `--log-level=error` keep tip and info lines out of the way.
    /// - `--log-destination=stderr` is passed **explicitly** because the CLI also
    ///   reads it from `LOG_DESTINATION`, and a value of `stdout` there would
    ///   interleave log lines with the value this adapter is about to read.
    /// - `--telemetry=false` keeps this tool's no-network promise intact.
    ///
    /// The key reaches `printenv` as an argument, never as text interpolated
    /// into a shell command, so a name cannot become a command.
    ///
    /// **The environment is cleared**, down to [`FORWARDED_EXACT`] and
    /// `INFISICAL_*`, exactly as [`names_command`](Self::names_command) does.
    /// `printenv` reads a variable, not a store, so without the clearing it
    /// answers from whatever this process happened to carry and the adapter
    /// reports the caller's own environment as a credential read back from
    /// Infisical. The module docs carry the measurement.
    ///
    /// `--expand=false` is deliberately NOT passed here, unlike in the listing:
    /// expansion rewrites values, a value is precisely what this path is for,
    /// and a secret that references another is the vendor's own feature.
    fn probe_command(&self, at: &Coordinates) -> Command {
        let mut command = Command::new(&self.binary);
        command.env_clear();
        command.envs(forwarded_vars());
        command.arg("run");
        command.arg(format!("--env={}", at.env));
        command.arg(format!("--path={}", at.path));
        command.arg("--silent");
        command.arg("--log-level=error");
        command.arg("--log-destination=stderr");
        command.arg(TELEMETRY_OFF);
        if let Some(project) = &self.project_id {
            command.arg(format!("--projectId={project}"));
        }
        if let Some(dir) = &self.config_dir {
            command.arg("--project-config-dir");
            command.arg(dir);
        }
        command.arg("--");
        command.arg(&self.probe_binary);
        command.arg(&at.key);
        command
    }

    /// Build one `infisical run … -- keyless __names` invocation.
    ///
    /// The same flags as [`probe_command`](Self::probe_command), plus two
    /// differences that are the whole of this path's safety:
    ///
    /// - **The environment is cleared** down to [`FORWARDED_EXACT`] and
    ///   `INFISICAL_*`. What is left is exactly the baseline the caller
    ///   subtracts, so nothing this process carries can appear in a listing.
    /// - **`--expand=false`.** That switches off the CLI's own shell-parameter
    ///   expansion, which rewrites VALUES and can neither add nor remove a key —
    ///   so a names-only read loses nothing, and one thing that interpolates
    ///   value text near a stream this code reads stops running. It is not the
    ///   whole of expansion: the request the CLI sends still carries
    ///   `expandSecretReferences=true`, which is the server's own, observed in
    ///   the URL a 404 quotes back. One interpolation removed, not all.
    ///
    /// `probe` is the `keyless` binary itself. It is passed in rather than
    /// resolved here so a test can point it somewhere it can observe.
    fn names_command(&self, at: &Location, probe: &std::path::Path) -> Command {
        let mut command = Command::new(&self.binary);
        command.env_clear();
        command.envs(forwarded_vars());
        command.arg("run");
        command.arg(format!("--env={}", at.env));
        command.arg(format!("--path={}", at.path));
        command.arg("--silent");
        command.arg("--log-level=error");
        command.arg("--log-destination=stderr");
        command.arg("--expand=false");
        command.arg(TELEMETRY_OFF);
        if let Some(project) = &self.project_id {
            command.arg(format!("--projectId={project}"));
        }
        if let Some(dir) = &self.config_dir {
            command.arg("--project-config-dir");
            command.arg(dir);
        }
        command.arg("--");
        command.arg(probe);
        command.arg(NAMES_VERB);
        command
    }

    /// The names the store holds at one location, and nothing else.
    ///
    /// The subtraction is exact, because the baseline is not a guess about what
    /// a shell might carry: [`names_command`](Self::names_command) cleared the
    /// environment and set exactly [`forwarded_vars`], so that is what comes
    /// back out.
    ///
    /// Filtering by the SET rather than by [`is_forwarded`] is the difference
    /// between hiding what was forwarded and hiding what COULD have been. On a
    /// machine with no proxy configured, nothing forwards `HTTPS_PROXY` — so a
    /// secret of that name is a real secret and gets listed.
    fn names_at(&self, at: &Location, probe: &std::path::Path) -> Result<Vec<String>, StoreError> {
        let baseline: BTreeSet<String> = forwarded_vars()
            .into_iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        let captured = capture(self.names_command(at, probe), self.timeout)
            .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            // stderr only, as everywhere in this crate. Measured against
            // 0.43.114: a bad environment, a bad folder and a bad login all
            // answer with the vendor's own sentence and an EMPTY stdout, so
            // there is nothing on the other stream to be tempted by.
            return Err(self.backend(format!(
                "cannot list {}: {}",
                at.describe(),
                first_line(&captured.stderr)
            )));
        }

        // Sorted, because the order an environment comes back in carries no
        // meaning — unlike a vault listing, where the vendor's order is at
        // least the vendor's. A stable order is what makes two listings of one
        // coordinate diffable.
        let mut names: Vec<String> = envnames::parse(&captured.stdout)
            .map_err(|detail| self.backend(format!("cannot list {}: {detail}", at.describe())))?
            .into_iter()
            .filter(|name| !baseline.contains(name))
            .collect();
        names.sort();
        Ok(names)
    }

    fn unavailable(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Unavailable {
            store: STORE_ID.to_owned(),
            detail: detail.into(),
        }
    }

    fn backend(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Backend {
            store: STORE_ID.to_owned(),
            detail: detail.into(),
        }
    }

    fn misconfigured(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Misconfigured {
            store: STORE_ID.to_owned(),
            detail: detail.into(),
        }
    }

    fn unreachable(&self, error: &CaptureError) -> StoreError {
        exec::unavailable(STORE_ID, &self.binary, error)
    }
}

impl Store for InfisicalStore {
    fn id(&self) -> &str {
        STORE_ID
    }

    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        let at = self.coordinates(name)?;
        // Read BEFORE the spawn, from the same source the spawn forwards from,
        // so the comparison below is against the exact bytes that went in
        // rather than against a second reading of a variable that could have
        // changed in between.
        let forwarded = forwarded_value(&at.key);
        let mut captured = capture(self.probe_command(&at), self.timeout)
            .map_err(|error| self.unreachable(&error))?;

        if !captured.status.success() {
            // stdout is empty on every failure path the CLI has, so reading it
            // here would be reading nothing — but the rule stands regardless:
            // a message is built from stderr only.
            let detail = first_line(&captured.stderr);
            if detail.contains(CHILD_EXIT_MARKER) {
                // The probe ran and reported the variable unset. That is an
                // answer — "this store does not have it" — not a failure.
                return Ok(None);
            }
            return Err(self.backend(detail));
        }

        // Moved out rather than borrowed, so the only remaining copy is the one
        // `Secret::from_bytes` is about to zeroize.
        let mut bytes = std::mem::take(&mut captured.stdout);
        strip_one_newline(&mut bytes);

        if bytes.is_empty() {
            // `printenv` exits 0 for a variable that is set and empty. An empty
            // credential is a misconfiguration worth naming rather than an
            // absence, which is how the keychain adapter treats it too.
            return Err(self.backend(format!(
                "{} is set but empty at {} {}",
                at.key, at.env, at.path
            )));
        }

        // The one name the clearing cannot make exact: a key the vendor itself
        // needs. Returning this would hand the caller's own `PATH` back as a
        // credential, stamped `INJECTED`.
        if let Some(shadow) = &forwarded
            && bytes == std::os::unix::ffi::OsStrExt::as_bytes(shadow.as_os_str())
        {
            return Err(self.backend(shadowed_detail(&at.key)));
        }

        Secret::from_bytes(bytes)
            .map(Some)
            .ok_or_else(|| self.backend(format!("{} is not valid UTF-8", at.key)))
    }

    fn health(&self) -> Result<(), StoreError> {
        // End to end: binary present, login valid, network reachable, project
        // resolvable. The probe asks for `PATH`, which this process already has
        // and which is not a credential, so a health check reads no secret of
        // the user's — while still proving the whole chain works.
        //
        // It does make the CLI fetch the environment's secrets into its own
        // memory, as any `infisical run` does. That is the cost of checking the
        // thing that actually breaks; a `--version` check would prove only that
        // a file exists.
        //
        // With no environment anywhere, the check is reported as a problem
        // rather than skipped: a backend that is enabled and can resolve nothing
        // is exactly what `doctor` exists to say out loud.
        let Some(at) = self.routing.health_coordinates() else {
            return Err(self.misconfigured(
                "no Infisical environment is declared anywhere, so no name can resolve. \
                 Put \"env\" on each name under `secrets`, or pass \
                 `keyless run --env <slug>` per command",
            ));
        };
        let captured = capture(self.probe_command(&at), self.timeout)
            .map_err(|error| self.unreachable(&error))?;

        if captured.status.success() {
            Ok(())
        } else {
            Err(self.unavailable(first_line(&captured.stderr)))
        }
    }
}

impl Discover for InfisicalStore {
    fn id(&self) -> &str {
        STORE_ID
    }

    fn items(&self, vault: Option<&str>) -> Result<Vec<ItemSummary>, StoreError> {
        // The listing is taken from a child of this binary, so the binary has to
        // be able to name itself. A build that cannot is reported rather than
        // guessed at: `argv[0]` would be a guess, and on a machine where it is
        // wrong the guess spawns something else entirely.
        let probe = std::env::current_exe().map_err(|error| {
            self.unavailable(format!(
                "cannot locate the running `{}` binary, which is the listing probe: {error}",
                crate::NAME
            ))
        })?;

        let locations = match vault {
            Some(spec) => vec![
                Location::parse(spec, &self.routing.default_path)
                    .map_err(|detail| self.misconfigured(detail))?,
            ],
            None => {
                let declared = self.routing.declared_locations();
                if declared.is_empty() {
                    // The example is a METAVARIABLE, never a real coordinate.
                    // `tests/publication.rs` reads the token after `--vault ` in
                    // any published file and fails on anything that is not an
                    // allowlisted decoy — a spelled-out `<env>:<path>` is the
                    // form that teaches the shape without naming an account.
                    return Err(self.misconfigured(format!(
                        "no Infisical coordinate is declared anywhere, so there is nothing to \
                         list. Name one — `{} items infisical --vault <env>:<path>` — or put \
                         \"env\" on a name under `secrets`. There is no default environment, \
                         because `prod` and `staging` hold the same key names",
                        crate::NAME
                    )));
                }
                declared
            }
        };

        let mut summaries = Vec::new();
        for at in locations {
            let vault = at.describe();
            summaries.extend(self.names_at(&at, &probe)?.into_iter().map(|key| {
                ItemSummary {
                    vault: vault.clone(),
                    // What a config entry's `key` must match, and what its
                    // `name` defaults to.
                    title: key,
                    // Infisical has no trash and no per-secret state: a key that
                    // reached the child's environment is a key `run` resolves.
                    // The word is the resolver's own allowlist value, so
                    // `is_active` agrees with what a lookup would do.
                    state: "Active".to_owned(),
                    // One word, because this backend has one kind of thing. A
                    // richer answer — shared against personal, imported against
                    // direct — is not in what an environment can say.
                    kind: "secret".to_owned(),
                }
            }));
        }
        Ok(summaries)
    }

    fn fields(&self, _vault: Option<&str>, item: &str) -> Result<Vec<FieldSummary>, StoreError> {
        // An honest absence rather than a fabricated single field named after
        // the item. `fields` exists because a Proton item is a record with
        // several values in it and a config entry has to name one; an Infisical
        // secret is one value, so the coordinate is complete without a field and
        // a config entry that sets one is wrong rather than incomplete.
        Err(self.backend(format!(
            "an Infisical secret is a single value, so `{item}` has no fields to choose between \
             and a config entry needs no \"field\". `{} items infisical --vault <env>:<path>` \
             lists the keys, and a key goes in \"key\"",
            crate::NAME
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CHILD_EXIT_MARKER, FORWARDED_EXACT, InfisicalStore, Location, NO_ENV, Routing,
        TELEMETRY_OFF, is_forwarded,
    };
    use crate::config::Config;
    use crate::store::Store;
    use crate::store::discover::Discover;
    use std::ffi::OsStr;

    fn config_from(json: &str) -> Config {
        serde_json::from_str(json).expect("valid config")
    }

    fn store_from(json: &str) -> InfisicalStore {
        InfisicalStore::from_config(&config_from(json), None)
    }

    fn store_from_with_env(json: &str, env: &str) -> InfisicalStore {
        InfisicalStore::from_config(&config_from(json), Some(env))
    }

    /// The rendered argv of the command the adapter would run.
    ///
    /// Panics when the name has no environment, which is deliberate: every test
    /// that reads an argv is asserting something about an invocation that
    /// happens, and one that silently rendered a command for a lookup the
    /// adapter refuses to make would assert nothing.
    fn argv(store: &InfisicalStore, name: &str) -> Vec<String> {
        let at = store
            .coordinates(name)
            .expect("this fixture must supply an environment");
        let command = store.probe_command(&at);
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .map(std::borrow::Cow::into_owned)
            .collect()
    }

    // -----------------------------------------------------------------------
    // The environment: two sources, no default.
    // -----------------------------------------------------------------------

    #[test]
    fn a_name_with_no_environment_anywhere_is_never_looked_up() {
        // The whole reason this rule exists. Before it, this same config
        // resolved DATABASE_URL against whatever `stores.infisical.env` said —
        // production, on the machine where it was measured.
        let store = store_from(
            r#"{"stores":{"infisical":{"enabled":true,
                                       "binary":"/nonexistent/keyless-test/infisical"}},
                "secrets":{"DATABASE_URL":{}}}"#,
        );
        let error = store
            .resolve("DATABASE_URL")
            .expect_err("a name with no environment must not resolve");
        let said = error.to_string();

        // `was not asked` is the Misconfigured wording. If the guard were gone
        // the adapter would spawn the (absent) binary and say `unavailable`
        // instead, so this assertion fails in exactly the regression case.
        assert!(said.contains("was not asked"), "{said}");
        assert!(said.contains("DATABASE_URL"), "{said}");
        assert!(said.contains("env"), "{said}");
        assert!(said.contains("--env"), "{said}");
    }

    #[test]
    fn a_config_level_env_key_is_read_by_nothing() {
        // The negative control for the field kept in `InfisicalConfig` purely so
        // a stale config can be reported. If anything ever wires it back into a
        // lookup, this name resolves and this test goes red.
        let store = store_from(
            r#"{"stores":{"infisical":{"enabled":true,"env":"prod",
                                       "binary":"/nonexistent/keyless-test/infisical"}},
                "secrets":{"DATABASE_URL":{}}}"#,
        );
        let said = store
            .resolve("DATABASE_URL")
            .expect_err("`stores.infisical.env` must not supply an environment")
            .to_string();
        assert!(said.contains("was not asked"), "{said}");
        assert!(
            !said.contains("prod"),
            "the ignored key must not leak into the lookup: {said}"
        );
    }

    #[test]
    fn an_undeclared_name_is_not_looked_up_either() {
        // The measured hazard was an INVENTED name — one declared in no config
        // at all — coming back with a production value.
        let store = store_from(
            r#"{"stores":{"infisical":{"enabled":true,
                                       "binary":"/nonexistent/keyless-test/infisical"}}}"#,
        );
        let said = store
            .resolve("META_APP_ID")
            .expect_err("an invented name must not resolve")
            .to_string();
        assert!(said.contains("was not asked"), "{said}");
        assert!(said.contains("META_APP_ID"), "{said}");
    }

    #[test]
    fn the_invocation_environment_covers_a_name_that_declares_none() {
        let store = store_from_with_env(
            r#"{"stores":{"infisical":{"enabled":true}},"secrets":{"A":{}}}"#,
            "staging",
        );
        assert!(argv(&store, "A").iter().any(|arg| arg == "--env=staging"));
        // And an undeclared name too: `--env` is stated for this invocation, so
        // there is nothing invisible about which environment it names.
        assert!(
            argv(&store, "INVENTED")
                .iter()
                .any(|a| a == "--env=staging")
        );
    }

    #[test]
    fn a_names_own_environment_outranks_the_invocation_environment() {
        // Precedence, in the direction that matters: a blanket flag aimed at the
        // names that say nothing must not repaint one that does.
        let store = store_from_with_env(
            r#"{"stores":{"infisical":{"enabled":true}},
                "secrets":{"PINNED":{"env":"prod"},"LOOSE":{}}}"#,
            "staging",
        );
        assert!(argv(&store, "PINNED").iter().any(|a| a == "--env=prod"));
        assert!(!argv(&store, "PINNED").iter().any(|a| a == "--env=staging"));
        assert!(argv(&store, "LOOSE").iter().any(|a| a == "--env=staging"));
    }

    #[test]
    fn a_route_sets_environment_path_and_key_independently() {
        let store = store_from(
            r#"{"secrets":{"A":{"env":"staging"},
                           "B":{"env":"dev","path":"/backend"},
                           "C":{"env":"dev","key":"OTHER_NAME"}}}"#,
        );
        assert!(argv(&store, "A").iter().any(|a| a == "--env=staging"));
        // The vendor's own default path, which `keyless` did not invent.
        assert!(argv(&store, "A").iter().any(|a| a == "--path=/"));
        assert!(argv(&store, "B").iter().any(|a| a == "--path=/backend"));
        assert_eq!(
            argv(&store, "C").last().map(String::as_str),
            Some("OTHER_NAME")
        );
    }

    #[test]
    fn the_path_stays_defaulted_and_the_default_is_the_vendors() {
        // The asymmetry with the environment, asserted rather than only argued:
        // a name that supplies an environment and no path is still looked up.
        let store = store_from(r#"{"secrets":{"A":{"env":"dev"}}}"#);
        assert!(argv(&store, "A").iter().any(|arg| arg == "--path=/"));
    }

    #[test]
    fn a_listing_shows_the_environment_a_name_would_resolve_against() {
        let config = config_from(
            r#"{"stores":{"infisical":{"path":"/backend"}},
                "secrets":{"PINNED":{"env":"prod"},"LOOSE":{}}}"#,
        );
        let routing = Routing::from_config(&config, None);
        assert_eq!(routing.route("PINNED").describe(), "prod:/backend");
        assert_eq!(
            routing.route("LOOSE").describe(),
            format!("{NO_ENV}:/backend"),
            "a name with no environment must be visibly missing one"
        );
    }

    #[test]
    fn the_invocation_uses_run_and_no_verb_that_prints_a_value() {
        // The security property of this adapter, asserted on the argv itself.
        // `secrets`, `export` and `secrets get` all write plaintext to stdout
        // and are denied at the harness level; if one ever appears here, this
        // adapter has become the way around that.
        let store = store_from(r#"{"secrets":{"DECOY":{"env":"dev"}}}"#);
        let argv = argv(&store, "DECOY");
        assert_eq!(argv.get(1).map(String::as_str), Some("run"));
        for forbidden in ["secrets", "export", "get", "read", "reveal"] {
            assert!(
                !argv.iter().any(|arg| arg == forbidden),
                "`{forbidden}` appeared in {argv:?}"
            );
        }
    }

    #[test]
    fn telemetry_is_switched_off_on_every_call() {
        // The vendor CLI defaults telemetry ON. Shelling out with default flags
        // would make `keyless` the reason a report leaves the machine, which
        // its own README forbids.
        let store = store_from_with_env("{}", "dev");
        assert!(argv(&store, "ANY").iter().any(|arg| arg == TELEMETRY_OFF));
    }

    #[test]
    fn the_log_destination_is_pinned_so_an_env_var_cannot_poison_the_probe() {
        // The CLI reads its log destination from LOG_DESTINATION as well as
        // from the flag. With that set to `stdout`, log lines would interleave
        // with the value being read. The explicit flag wins — measured.
        let store = store_from_with_env("{}", "dev");
        let argv = argv(&store, "ANY");
        assert!(argv.iter().any(|arg| arg == "--log-destination=stderr"));
        assert!(argv.iter().any(|arg| arg == "--silent"));
    }

    #[test]
    fn the_key_is_an_argument_to_the_probe_and_never_shell_text() {
        // A name with shell metacharacters must arrive as one argv element.
        // There is no shell in this pipeline, and this asserts it stays that
        // way: `-c`, `sh` or a joined command string would all show up here.
        let store = store_from(r#"{"secrets":{"WEIRD":{"env":"dev","key":"A; rm -rf /"}}}"#);
        let argv = argv(&store, "WEIRD");
        assert_eq!(argv.last().map(String::as_str), Some("A; rm -rf /"));
        assert!(!argv.iter().any(|arg| arg == "-c"));
    }

    #[test]
    fn the_separator_precedes_the_probe_binary() {
        // Without `--`, the CLI parses the probe's own arguments as its own.
        let store = store_from_with_env("{}", "dev");
        let argv = argv(&store, "ANY");
        let separator = argv
            .iter()
            .position(|arg| arg == "--")
            .expect("the invocation must separate the child command");
        assert!(
            argv.get(separator + 1)
                .is_some_and(|arg| arg.contains("printenv"))
        );
    }

    #[test]
    fn project_coordinates_are_passed_only_when_configured() {
        let bare = store_from_with_env("{}", "dev");
        assert!(
            !argv(&bare, "ANY")
                .iter()
                .any(|arg| arg.contains("projectId"))
        );

        let pinned = store_from_with_env(
            r#"{"stores":{"infisical":{"project_id":"abc-123","config_dir":"/tmp/proj"}}}"#,
            "dev",
        );
        let argv = argv(&pinned, "ANY");
        assert!(argv.iter().any(|arg| arg == "--projectId=abc-123"));
        assert!(argv.iter().any(|arg| arg == "/tmp/proj"));
    }

    #[test]
    fn a_missing_binary_degrades_rather_than_panicking() {
        // An environment is supplied, so the adapter genuinely reaches for the
        // binary. Without one it would refuse before spawning and this test
        // would pass for the wrong reason.
        let store = store_from_with_env(
            r#"{"stores":{"infisical":{"binary":"/nonexistent/keyless-test/infisical"}}}"#,
            "dev",
        );
        let error = store
            .resolve("ANY")
            .expect_err("a missing binary must error");
        assert!(error.to_string().contains("unavailable"));
        assert!(store.health().is_err());
    }

    #[test]
    fn the_child_exit_marker_is_what_separates_absent_from_broken() {
        // A guard on the one string this adapter reads out of vendor output. It
        // is documented as measured; if someone edits it to something the CLI
        // never prints, every unset name starts reporting as a backend failure.
        assert_eq!(CHILD_EXIT_MARKER, "exit status");
        assert!(
            "failed to wait for command termination: exit status 1".contains(CHILD_EXIT_MARKER)
        );
        assert!(
            !"Please either run infisical init to connect to a project".contains(CHILD_EXIT_MARKER)
        );
    }

    // -----------------------------------------------------------------------
    // Listing: the coordinate, the invocation, and what it refuses to guess.
    // -----------------------------------------------------------------------

    /// The argv of the listing probe, rendered without running it.
    fn listing_argv(store: &InfisicalStore, spec: &str) -> Vec<String> {
        let at = Location::parse(spec, "/").expect("this fixture supplies an environment");
        let command = store.names_command(&at, std::path::Path::new("/opt/keyless"));
        std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(OsStr::to_string_lossy)
            .map(std::borrow::Cow::into_owned)
            .collect()
    }

    #[test]
    fn a_location_reads_an_environment_and_an_optional_path() {
        assert_eq!(
            Location::parse("staging:/backend", "/").expect("valid"),
            Location {
                env: "staging".to_owned(),
                path: "/backend".to_owned()
            }
        );
        // No path half: the config's default, which is the same one an
        // undeclared name would be looked up at.
        assert_eq!(
            Location::parse("prod", "/backend").expect("valid"),
            Location {
                env: "prod".to_owned(),
                path: "/backend".to_owned()
            }
        );
        // The vendor's paths are absolute, and a 404 saying "folder not found"
        // is a worse answer than fixing an obvious spelling.
        assert_eq!(
            Location::parse("prod:backend", "/").expect("valid").path,
            "/backend"
        );
        assert_eq!(
            Location::parse("staging:/backend", "/")
                .expect("valid")
                .describe(),
            "staging:/backend",
            "the listing must name a coordinate in the spelling `ls` prints"
        );
    }

    #[test]
    fn a_location_with_no_environment_is_refused_rather_than_defaulted() {
        // The same rule as a lookup, for the same reason: `prod` and `staging`
        // hold the same key names, so guessing lists the wrong side of a
        // tenancy boundary and looks exactly like listing the right one.
        for spec in [":/backend", "", "   "] {
            let said = Location::parse(spec, "/").expect_err("an environment is mandatory");
            assert!(said.contains("names no Infisical environment"), "{said}");
            assert!(said.contains("<env>:<path>"), "{said}");
        }
    }

    #[test]
    fn the_listing_uses_run_and_no_verb_that_prints_a_value() {
        // The same assertion as the lookup path, on the newer invocation. The
        // denied verbs are denied because they print plaintext; a listing built
        // on one would be the way around that.
        let store = store_from("{}");
        let argv = listing_argv(&store, "dev");
        assert_eq!(argv.get(1).map(String::as_str), Some("run"));
        for forbidden in ["secrets", "export", "get", "read", "reveal"] {
            assert!(
                !argv.iter().any(|arg| arg == forbidden),
                "`{forbidden}` appeared in {argv:?}"
            );
        }
        assert!(argv.iter().any(|arg| arg == TELEMETRY_OFF));
        assert!(argv.iter().any(|arg| arg == "--log-destination=stderr"));
        // Shell-parameter expansion rewrites values and cannot change the key
        // set, so a names-only read switches it off.
        assert!(argv.iter().any(|arg| arg == "--expand=false"));
    }

    #[test]
    fn the_listing_child_is_this_binary_asking_for_names() {
        let store = store_from("{}");
        let argv = listing_argv(&store, "dev");
        let separator = argv
            .iter()
            .position(|arg| arg == "--")
            .expect("the invocation must separate the child command");
        // One LITERAL for the whole child command, so nothing on the right-hand
        // side can be edited by editing the implementation. Spelling this as
        // `argv.len() == separator + 3` took both sides from the code under
        // test — the length and the offset move together — and
        // `tests/oracle_independence.rs` failed the build for it. The literal
        // also states "and no other argument" without arithmetic.
        let child: Vec<&str> = argv[separator + 1..].iter().map(String::as_str).collect();
        assert_eq!(child, ["/opt/keyless", "__names"], "{argv:?}");
    }

    #[test]
    fn the_listing_hands_the_vendor_only_the_forwarded_variables() {
        // The subtraction that turns a child's environment into a listing is
        // exact only because this set is. Anything else this process carries
        // would show up as though the store held it.
        let store = store_from("{}");
        let at = Location::parse("dev", "/").expect("valid");
        let command = store.names_command(&at, std::path::Path::new("/opt/keyless"));
        for (name, _) in command.get_envs() {
            let name = name.to_string_lossy().into_owned();
            assert!(
                is_forwarded(&name),
                "`{name}` was handed to the vendor but is not a forwarded variable"
            );
        }
    }

    #[test]
    fn the_forwarded_set_is_the_documented_one() {
        // A guard on the blind spot's SIZE. Every name added here is a name a
        // listing can no longer report, so growing this set silently is how the
        // verb starts lying by omission.
        assert!(is_forwarded("HOME"));
        assert!(is_forwarded("PATH"));
        assert!(is_forwarded("INFISICAL_TOKEN"));
        assert!(is_forwarded("INFISICAL_API_URL"));
        assert!(!is_forwarded("DATABASE_URL"));
        assert!(!is_forwarded("NODE_ENV"));
        // Deliberately absent: the CLI reads all three from the environment and
        // this adapter pins them on the command line, so forwarding one could
        // only make the vendor noisier on a stream this code reads.
        for quiet in ["LOG_LEVEL", "LOG_FORMAT", "LOG_DESTINATION"] {
            assert!(!is_forwarded(quiet), "`{quiet}` must not be forwarded");
        }
        assert_eq!(
            FORWARDED_EXACT.len(),
            9,
            "a variable added to the forwarded set is a name `items` can no longer report"
        );
    }

    #[test]
    fn with_no_location_the_listing_covers_only_the_declared_coordinates() {
        // The answer to "should a listing verb enumerate a whole store?". The
        // config is an allowlist, so the default is the coordinates in it —
        // deduplicated, because two names in one folder are one listing.
        let config = config_from(
            r#"{"stores":{"infisical":{"path":"/backend"}},
                "secrets":{"A":{"env":"prod"},
                           "B":{"env":"prod"},
                           "C":{"env":"staging"},
                           "D":{"env":"prod","path":"/web"},
                           "E":{}}}"#,
        );
        let declared = Routing::from_config(&config, None).declared_locations();
        let described: Vec<String> = declared.iter().map(Location::describe).collect();
        assert_eq!(
            described,
            ["prod:/backend", "prod:/web", "staging:/backend"],
            "a coordinate nobody declared must not be listed, and one declared twice \
             must not be listed twice"
        );
    }

    #[test]
    fn a_config_that_declares_no_environment_refuses_to_list_rather_than_guessing() {
        let store = store_from(r#"{"stores":{"infisical":{"enabled":true}},"secrets":{"A":{}}}"#);
        let said = Discover::items(&store, None)
            .expect_err("there is no coordinate to list")
            .to_string();
        assert!(
            said.contains("no Infisical coordinate is declared"),
            "{said}"
        );
        assert!(said.contains("--vault"), "{said}");
        // The reason, not just the refusal: somebody who reads only this line
        // has to learn why a default would be wrong rather than which flag to add.
        assert!(said.contains("same key names"), "{said}");
    }

    #[test]
    fn fields_says_an_infisical_secret_has_none_and_points_at_the_key() {
        let store = store_from(r#"{"secrets":{"A":{"env":"dev"}}}"#);
        let said = Discover::fields(&store, None, "DATABASE_URL")
            .expect_err("an Infisical secret is one value")
            .to_string();
        assert!(said.contains("single value"), "{said}");
        assert!(said.contains("DATABASE_URL"), "{said}");
        // An absence that names the verb that DOES answer, rather than one that
        // leaves the reader looking for a flag.
        assert!(said.contains("items infisical"), "{said}");
    }
}
