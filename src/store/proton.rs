//! Proton Pass, via `pass-cli run`.
//!
//! Personal credentials, kept in a different vault from the company's — which
//! is the whole reason the resolution policy in [`super`] refuses to guess which
//! store a name belongs to.
//!
//! # Status: observed against `pass-cli` 2.7.0, 2026-11-05
//!
//! The argv this adapter builds, the reference format it passes through, the
//! session scoping below and the vendor's masking were all exercised against
//! the real CLI on macOS (Homebrew, `pass-cli` 2.2.5) against a live account,
//! using disposable decoy items, and proven again on 2.7.0 by `keyless doctor
//! --probe` and a fresh read of an item and of one of its fields. `run
//! --env-file <FILE> --no-masking -- <COMMAND>` exists with exactly that
//! spelling, and `agent create` exists too.
//!
//! One requirement the code cannot check and a user must plan for: **an agent
//! token needs Pass Plus or higher.** The free tier is excluded, so a free
//! account fails authentication — which reaches `keyless` as a degraded run
//! rather than as an explanation.
//!
//! # Scoping: which login answers is a config field, never an inheritance
//!
//! `pass-cli` keeps one logged-in identity per **session directory**, chosen by
//! `PROTON_PASS_SESSION_DIR` and falling back to a shared per-user location.
//! Two identities therefore coexist on one machine with no visible difference
//! at the call site: a vault-scoped agent token in its own directory, and
//! whatever a plain `pass-cli login` left in the default one.
//!
//! Measured 2026-08-08: the default session was the full account and saw two
//! vaults; the agent session saw one. An adapter that sets nothing inherits the
//! default — so the scoping a user deliberately set up is bypassed, and it is
//! bypassed **in the direction that looks correct**, because a session holding
//! every vault resolves every name successfully. Nothing in the output would
//! say the wrong identity answered.
//!
//! So the session directory is [`crate::config::ProtonConfig::session_dir`],
//! it is passed to every child explicitly, and when it is absent this adapter
//! **degrades the lookup** rather than falling back to the ambient session.
//! See [`ProtonStore::session_dir`] for why that is the right one of the three
//! available answers.
//!
//! # Addressing: names in the config, ids resolved fresh
//!
//! **A share id is minted per session, so it is not a coordinate you can store.**
//! Measured 2026-08-08: the same vault `personal` answered with two different share ids
//! to two live sessions of one account. A `pass://SHARE_ID/ITEM_ID/FIELD`
//! reference is therefore relative to the session that resolves it, and a
//! reference written into a config file dies the next time the token is renewed
//! or a session recovers — as a **degraded run**, which is quiet.
//!
//! So the recommended form addresses an item the way a person does: vault name,
//! item title, field. Those are stable. The volatile half is looked up at every
//! lookup, from `pass-cli item list --vault-name <VAULT> --output json`, whose
//! records carry `share_id`, `id`, `state` and `title` — everything needed to
//! build a fresh reference in memory. Note the item id is the key **`id`**;
//! there is no `item_id` key, and reading one yields `None`.
//!
//! Three decisions that path forced, each made rather than guessed:
//!
//! - **Two live items with the same title are refused, never picked.** Same rule
//!   as [`crate::config::Policy::Explicit`] for two backends answering one name:
//!   guessing is a wrong credential delivered silently. The error names every
//!   candidate id, so the `reference` form is the way to pin one.
//! - **A trashed item never resolves.** `item list` still returns it, with
//!   `state: "Trashed"`. Resolving one would hand a child a value its owner
//!   believes they deleted. The filter is an **allowlist** on `Active` rather
//!   than a denylist on `Trashed`: a state this build has never heard of must
//!   fail closed.
//! - **The listing is memoised, in memory only, and it expires.** One `keyless
//!   run` resolves several names, usually from one vault, so the cache turns N
//!   spawns into one. It is reused only while it is younger than
//!   [`crate::config::ProtonConfig::listing_ttl_ms`], because the listing is
//!   also what carries the trash rule below: an entry kept indefinitely goes on
//!   resolving an item somebody trashed an hour ago, and does it silently. A
//!   run cannot outlive the default, so the memoisation costs nothing there;
//!   the bound is what makes the adapter safe to hold open across commands.
//!   There is deliberately no on-disk cache: a cache the client can read is a
//!   `get` verb with extra steps.
//!
//! The `reference` form still resolves, unchanged. It is the escape hatch for an
//! ambiguous title, and the wrong choice for everything else — it is fragile
//! across sessions, and it is **not** covered by the trash rule above.
//!
//! **Measured 2026-08-08: `pass-cli run` resolves a reference to a TRASHED item
//! and returns its value, exit 0, with nothing on stderr.** The vendor applies
//! no trash filter of its own, so the only thing standing between a deleted item
//! and a child's environment is the listing check in this adapter — which the
//! reference form skips by construction, because it never lists anything. That
//! is the strongest reason to prefer the name form, and the reason the ambiguity
//! escape hatch is a narrow recommendation rather than a general one.
//!
//! # The mechanism
//!
//! Same shape as the Infisical adapter, for the same reason: `pass-cli item
//! view --field` prints plaintext to stdout and is therefore unusable, while
//! `pass-cli run [--env-file FILE] -- CMD` puts secrets in a child's
//! environment and prints nothing. So a lookup is a `run` whose child is
//! `printenv`, and the env file is written for that one lookup and deleted
//! after it.
//!
//! Three details of the vendor's contract shape the code:
//!
//! - **`--no-masking` is required for the probe.** Proton's own output masking
//!   is on by default and replaces a value in the child's output with
//!   `<concealed by Proton Pass>`. The probe reads the child's output, so with
//!   masking left on it would read the mask token and inject *that* as the
//!   credential. Disabling it here costs nothing: `keyless` masks the real
//!   child's output itself, over more encodings, and the probe's own output
//!   never leaves this process.
//! - **Every read needs a reason.** `PROTON_PASS_AGENT_REASON` must be present
//!   and non-empty, is capped at 300 characters, and is stored end-to-end
//!   encrypted beside the audit entry. See [`Reason`] for what goes in it and
//!   what deliberately does not.
//! - **Every child is told to keep quiet.** The vendor writes a row to its own
//!   local telemetry database on every command and, by its own FAQ, phones it
//!   home unless [`DISABLE_TELEMETRY_VAR`] is set. [`NO_UPDATE_CHECK_VAR`]
//!   stops the same child asking a manifest endpoint whether a newer version
//!   exists — a check the vendor already skips when stderr is not a terminal,
//!   which is every child spawned here, so the variable is what holds that
//!   shut if a release ever reads the terminal differently. Replacing the
//!   binary at `stores.proton.binary` is the operator's own act either way.
//!   See [`set_vendor_switch_offs`], set on every command this adapter
//!   spawns, read or write — and on none of the command lines this crate
//!   PRINTS for a person to paste, which carry the session directory alone.
//!
//! # What this adapter never touches
//!
//! No token file, no keyring entry, no account credential. The login belongs to
//! `pass-cli` and is inherited by spawning it, and there is no config field in
//! which a token would fit.
//!
//! # Why there is no `keyless login proton`, and no `keyless proton -- …`
//!
//! The obvious close for the lost-session-directory class is a `keyless` verb
//! that runs the vendor for you with the variable already set. Attacked before
//! being built, it is not the answer:
//!
//! - **The general form is a `get` verb wearing a hyphen.** `keyless proton --
//!   <args>` reaches `item view --field password`, `totp generate`, `inject` and
//!   `personal-access-token create`, and every one of those prints a credential
//!   to stdout. The whole claim of this tool is that no verb prints a value, and
//!   the most reachable verb in it must not be the exception. An allowlist of
//!   harmless vendor verbs would narrow that and would still be a list this
//!   crate has to keep correct against somebody else's release schedule.
//! - **A narrow `keyless login proton` closes one verb out of seventeen.** See
//!   [`SESSION_SCOPED_VERBS`]: an operator reaches for `info`, `logout`, `agent
//!   create` and `agent renew` in the same sitting, and each one silently
//!   answers about the DEFAULT session when the variable is missing. Closing the
//!   one that was noticed leaves the class open.
//! - **Neither reaches the person who typed the command.** Both incidents began
//!   with a command line that had been WRITTEN DOWN without the variable — in
//!   this crate's own messages, in its README, and in the vendor's own `agent
//!   instructions`, which tells its reader to recover from an authentication
//!   error by logging out. A new verb adds a second correct spelling; it removes
//!   no wrong one.
//! - **Every wrapper is one more place to destroy a session.** See
//!   [`remove_ambient_references`]: handed an environment somebody sanitised,
//!   `pass-cli` reinitialises the session database at that path, and a web-login
//!   session does not come back.
//!
//! So the coordinate is attached where a command line is WRITTEN instead.
//! [`scoped_command`] is the only place the prefix is assembled, and
//! `tests/session_coordinate.rs` fails the suite when a published file writes a
//! command line the variable is absent from.

mod auto_login;
mod commands;
mod discover;
mod environment;
mod failure;
mod item_view;
mod listing;
mod reason;
mod resolve;
mod routing;
mod session;
mod session_dir;
mod store;
mod token;

#[cfg(test)]
mod tests;

pub use auto_login::AutoLogin;
pub(crate) use commands::flag_value;
pub use environment::ENCRYPTION_KEY_VAR;
pub use environment::KEY_PROVIDER_VAR;
pub use environment::KeyProvider;
pub(crate) use environment::REASON_VAR;
pub(crate) use environment::REFERENCE_SCHEME;
pub(crate) use environment::SESSION_DIR_VAR;
#[cfg(test)]
pub(crate) use environment::assert_vendor_switch_offs;
pub(crate) use environment::remove_ambient_references;
pub(crate) use environment::set_vendor_switch_offs;
pub use failure::reached_no_service;
pub(crate) use item_view::scrub;
pub(crate) use listing::ItemListing;
pub use listing::MAX_LISTING_TTL_MS;
pub(crate) use listing::Matched;
pub use listing::bounded_listing_ttl;
pub(crate) use listing::match_title;
pub use reason::Reason;
pub use routing::Routing;
pub use session_dir::SESSION_DIR_PLACEHOLDER;
pub use session_dir::SESSION_SCOPED_VERBS;
pub(crate) use session_dir::SESSION_SUBDIR;
pub(crate) use session_dir::relative_session_dir;
pub use session_dir::scoped_command;
pub use session_dir::scoped_command_template;
pub use store::ProtonStore;
pub(crate) use store::resolve_executable;
pub use token::AgentToken;
pub use token::TOKEN_VAR;
pub use token::classify_token;
pub use token::login_into;
pub use token::login_with_token;

/// This adapter's id, as a config route and an error message spell it.
pub const STORE_ID: &str = "proton";
