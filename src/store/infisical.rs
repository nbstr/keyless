//! Infisical, via the one verb of its CLI that does not print a value.
//!
//! # The problem this adapter exists to solve
//!
//! Infisical's CLI has three verbs that yield a secret — `infisical secrets`,
//! `infisical secrets get NAME` and `infisical export` — and **all three write
//! plaintext to stdout**. In an agent session stdout is the transcript, so all
//! three are exactly the disclosure `keyless` exists to prevent, and all three
//! are denied at the harness level on this machine.
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
//!   path, not the ones that were asked for. On this machine that is 405 names
//!   reaching a child that asked for one.
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

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use crate::config::Config;
use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::Store;
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
    fn probe_command(&self, at: &Coordinates) -> Command {
        let mut command = Command::new(&self.binary);
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

    fn unavailable(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Unavailable {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }

    fn backend(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Backend {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }

    fn misconfigured(&self, detail: impl Into<String>) -> StoreError {
        StoreError::Misconfigured {
            store: self.id().to_owned(),
            detail: detail.into(),
        }
    }

    fn unreachable(&self, error: &CaptureError) -> StoreError {
        exec::unavailable(self.id(), &self.binary, error)
    }
}

impl Store for InfisicalStore {
    fn id(&self) -> &str {
        STORE_ID
    }

    fn resolve(&self, name: &str) -> Result<Option<Secret>, StoreError> {
        let at = self.coordinates(name)?;
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

#[cfg(test)]
mod tests {
    use super::{CHILD_EXIT_MARKER, InfisicalStore, NO_ENV, Routing, TELEMETRY_OFF};
    use crate::config::Config;
    use crate::store::Store;
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
}
