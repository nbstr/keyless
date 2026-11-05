//! Parsing a `--secret` request, and the variables a secret may never land in.

use super::Binding;

impl Binding {
    /// Parse `NAME` or `ENV=NAME`.
    ///
    /// The two-part form exists because the store's name for a credential and
    /// the variable a tool reads are often different — `gh` wants
    /// `GITHUB_TOKEN` whatever the item is called.
    ///
    /// Syntax only: this reads the spec and nothing else, so a request parsed
    /// here lands in exactly the one variable the spec spells. Use
    /// [`Binding::declared`] to also give the credential the variables its
    /// declaration says it answers to.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (env, name) = match spec.split_once('=') {
            Some((env, name)) => (env.trim(), name.trim()),
            None => (spec.trim(), spec.trim()),
        };
        if !is_valid_env_name(env) {
            return Err(format!(
                "`{env}` is not a usable environment variable name (letters, digits and underscore, not starting with a digit)"
            ));
        }
        if let Some(reason) = hijacks_the_child(env) {
            return Err(format!(
                "`{env}` cannot be bound to a secret: {reason}. The value would choose what \
                 the child runs, and masking would hide it while it did"
            ));
        }
        Ok(Binding {
            env: env.to_owned(),
            name: name.to_owned(),
            also: Vec::new(),
        })
    }

    /// Parse a spec, and give the credential every variable its declaration says
    /// it answers to.
    ///
    /// This is what the binary calls, and the difference between it and
    /// [`Binding::parse`] is the whole of the fix described in
    /// [`crate::config::SecretRoute::aliases`]: a bare `-s NAME` reaches the
    /// child under the variable the program actually reads, without anybody
    /// having to know that the label and the variable were different.
    ///
    /// # A config is not a trusted input
    ///
    /// It arrives by `--config` or `KEYLESS_CONFIG`, so a declaration can name
    /// any variable at all — including the ones in [`hijacks_the_child`], where
    /// the stored VALUE would choose which program the child runs while masking
    /// hid it doing so. Every derived variable therefore goes through the same
    /// two checks a typed one does, and a rejected one is dropped rather than
    /// failing the run: the caller asked for a name, not for an alias, and the
    /// name still resolves and still lands in its own variable.
    pub fn declared(spec: &str, config: &crate::config::Config) -> Result<Self, String> {
        let mut binding = Binding::parse(spec)?;
        // A spelled `ENV=NAME` is an instruction about where the value goes. It
        // is not widened, because the caller has already answered the question.
        if binding.env != binding.name {
            return Ok(binding);
        }
        binding.also = config
            .route(&binding.name)
            .aliases(&binding.name)
            .into_iter()
            .filter(|variable| {
                variable != &binding.env
                    && is_valid_env_name(variable)
                    && hijacks_the_child(variable).is_none()
            })
            .collect();
        Ok(binding)
    }

    /// The request as the caller spelled it, for a line on stderr.
    ///
    /// `ENV=NAME` when the two differ, so an empty name still shows up as
    /// the `ENV=` the caller typed rather than as nothing at all.
    pub(super) fn spelled(&self) -> String {
        if self.env == self.name {
            self.name.clone()
        } else {
            format!("{}={}", self.env, self.name)
        }
    }

    /// Every variable this request would set, the spelled one first.
    pub(super) fn targets(&self) -> Vec<String> {
        std::iter::once(self.env.clone())
            .chain(self.also.iter().cloned())
            .collect()
    }
}

fn is_valid_env_name(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Variables whose value decides **which code runs**, before the child's own
/// first instruction. Bound to a secret, the store chooses the program.
///
/// # The attack this closes
///
/// ```console
/// $ keyless run -s PATH=DECOY -- sh -c '...'
/// ```
///
/// resolved `DECOY` out of the store, put it in `PATH`, and the `sh` that ran
/// came from the directory the stored VALUE named — not from `/bin`. **And the
/// value is a needle in the masker, so it is redacted out of everything the run
/// prints while it is doing this.** A substitution that is both effective and
/// invisible is the worst combination available, and nothing else in this tool
/// lets a store's contents reach a decision rather than a variable.
///
/// # Why this is a denylist, and why a denylist cannot be complete
///
/// An allowlist is not available: the whole product is binding a value to a
/// variable name that only the caller's tool knows — `GITHUB_TOKEN`,
/// `STRIPE_KEY`, whatever an internal service reads. There is no set of legal
/// names to enumerate.
///
/// So this is a denylist, and a denylist over "variables that cause code to be
/// loaded" is **open-ended by construction**: every interpreter is free to
/// invent one, and `PYTHONPATH`, `NODE_OPTIONS`, `PERL5LIB`, `RUBYOPT`,
/// `JAVA_TOOL_OPTIONS` and `GEM_PATH` are each a code-loading variable belonging
/// to software this crate does not know about and cannot enumerate.
///
/// What this list is therefore scoped to is the boundary `keyless` itself owns:
/// **the variables the operating system's process startup and dynamic linker
/// read, plus the ones the shell reads before it runs the command it was
/// given.** Those decide what happens between this tool's `execve` and the
/// child's first instruction, which is the interval this tool is responsible
/// for. Past that instruction the child is running its own code and its own
/// rules, and a value bound to `NODE_OPTIONS` is the caller's to get right.
///
/// Stated plainly rather than implied, because the alternative is a reader
/// believing the list is exhaustive: **binding a secret to a variable your
/// interpreter treats as code is still possible and is still a bad idea.**
fn hijacks_the_child(env: &str) -> Option<&'static str> {
    // Exact names read by process startup or by a shell before it runs its
    // argument. `IFS` re-splits words; `ENV`, `BASH_ENV` and `ZDOTDIR` name a
    // file the shell SOURCES; `SHELLOPTS` turns options on, `xtrace` among
    // them; `CDPATH` redirects a `cd`.
    const STARTUP: &[&str] = &[
        "PATH",
        "IFS",
        "ENV",
        "BASH_ENV",
        "ZDOTDIR",
        "SHELLOPTS",
        "CDPATH",
    ];
    if STARTUP.contains(&env) {
        return Some("it decides which program the child finds and runs");
    }
    // The dynamic linkers, by prefix: glibc and musl read `LD_PRELOAD`,
    // `LD_LIBRARY_PATH` and `LD_AUDIT`; dyld reads `DYLD_INSERT_LIBRARIES` and
    // `DYLD_LIBRARY_PATH`. A prefix rather than a list, because both families
    // keep adding members and a missed one loads attacker code.
    if env.starts_with("LD_") || env.starts_with("DYLD_") {
        return Some("the dynamic linker loads code named by it, before `main`");
    }
    None
}
