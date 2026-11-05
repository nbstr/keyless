#![allow(dead_code)]

pub mod generations;
pub mod session_fault;
pub mod session_verbs;
pub mod vendor_store;
pub mod warm_cache;

use std::path::Path;

use keyless::daemon::config::DaemonConfig;

use crate::support::backend::Backend;
use crate::support::client::write_secrets;
use crate::support::proton::{Listing, stub_pass_cli_listing};
use crate::support::short_socket_path;

/// The one name the daemon's config declares, with all three coordinates.
pub const DECLARED: &str = "FIXTURE_DECLARED";

/// A name the daemon's config declares and gives only part of an address.
pub const HALF_WRITTEN: &str = "FIXTURE_WITHOUT_AN_ITEM";

/// The vault the one declared name lives in. Not a real vault anywhere.
pub const VAULT: &str = "company";

/// The item title the one declared name lives under.
pub const ITEM: &str = "decoy";

/// The session directory the daemon's config points at.
///
/// Never touched by a stub — the fixtures below record what they were handed
/// rather than reading anything out of it — but it must be an absolute path,
/// because a relative one degrades every lookup for a different reason and
/// every case here would pass without asking anything.
pub fn session_dir(dir: &Path) -> std::path::PathBuf {
    dir.join("session")
}

/// A listing holding exactly the one item the declared name addresses.
///
/// Written out by hand rather than built from the adapter's own idea of the
/// shape: a fixture generated from that would agree with it whatever it became.
pub const LISTING: &str = concat!(
    r#"{"items":[{"id":"It3mOne","share_id":"ShAr3","state":"Active","#,
    r#""title":"decoy","item_type":"login"}]}"#
);

/// The generation directory `daemon_config_with_proton` (or any fixture that
/// calls [`crate::support::generations::publish_generation`] against this root) actually
/// published, read back off `<root>/current` rather than re-derived.
///
/// A vendor child is scoped at THIS directory, never at `session_dir(dir)`
/// itself — that path is the root of generations under this change, and a
/// test asserting a spawn's scope has to compare against the generation a
/// real reader would resolve to, which is exactly what `current` names.
pub fn published_generation(dir: &Path) -> std::path::PathBuf {
    let root = session_dir(dir);
    let name = crate::support::generations::current_generation(&root)
        .expect("the fixture must have published a generation before starting the daemon");
    root.join(name)
}

/// Where the stand-in vendor records the argv it was spawned with.
///
/// Its EXISTENCE is the whole signal for the `run` path: `stub_pass_cli_listing`
/// writes it as its first act after the listing branch, so a missing file means
/// no `run` was ever created.
pub fn vendor_argv(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.argv")
}

/// Where the same stand-in records an `item list` invocation.
///
/// Separate from the one above because they are separate claims. `run` is the
/// verb that reads a value; `item list` is the verb that turns a vault and a
/// title into ids, and it is a real read against a real vault with a real
/// audit entry. An undeclared name must cost neither.
pub fn vendor_list_argv(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.list.argv")
}

/// Where the stand-in records the reference a `run` read out of its env file.
///
/// Written by `run` alone, the one verb that reads a value. The catalogue's own
/// enumeration (`vault list`, `item list`, `info`) never writes it.
pub fn vendor_reference(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.reference")
}

/// The stand-in agent token. Distinct from every other decoy here, and long
/// enough that a grep for it in any output means a real leak.
pub const TOKEN_DECOY: &str = "decoy-Pat8-agent-token-never-real-0606";

/// The stand-in local encryption key, for `key_provider: env` fixtures.
/// Distinct from [`TOKEN_DECOY`] and long enough that a grep for it in any
/// output means a real leak. Its LENGTH, never its text, is what any
/// assertion here may compare against.
pub const ENCRYPTION_KEY_DECOY: &str = "decoy-Lk4l-local-encryption-key-never-real-0911";

/// Where a credential-carrying stand-in records the login it was handed.
pub fn vendor_token(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.token")
}

/// Where it records the key provider it was handed, or `<unset>`.
///
/// `${VAR-<unset>}` rather than `${VAR:-<unset>}`, so a variable that arrived
/// EMPTY is told apart from one that never arrived at all.
pub fn vendor_key_provider(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.key-provider")
}

/// Where it records the uid and gid it actually ran as, as `uid:gid`.
pub fn vendor_identity(dir: &Path) -> std::path::PathBuf {
    dir.join("pass-cli.identity")
}

/// A `pass-cli` stand-in that also records the key provider it was given.
///
/// `stub_pass_cli_listing` records the session directory and the reason, which
/// is everything the session-side cases need. The daemon needs one more: which
/// key provider reached the child. That is not cosmetic — see
/// `keyless::store::proton::KeyProvider` — so it is read from the place it is
/// supposed to arrive rather than from the adapter's own account of what it set.
pub fn stub_recording_key_provider(
    dir: &Path,
    behaviour: &Backend,
    listing: &Listing,
) -> std::path::PathBuf {
    let inner = stub_pass_cli_listing(dir, behaviour, listing);
    let wrapper = dir.join("pass-cli-wrapper");
    let body = format!(
        "#!/bin/sh\n\
         printf '%s' \"${{PROTON_PASS_KEY_PROVIDER-<unset>}}\" > '{provider}'\n\
         printf '%s' \"${{PROTON_PASS_PERSONAL_ACCESS_TOKEN-<unset>}}\" > '{token}'\n\
         printf '%s:%s' \"$(id -u)\" \"$(id -g)\" > '{identity}'\n\
         exec '{inner}' \"$@\"\n",
        provider = vendor_key_provider(dir).display(),
        token = vendor_token(dir).display(),
        identity = vendor_identity(dir).display(),
        inner = inner.display(),
    );
    std::fs::write(&wrapper, body).expect("write the wrapper");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    wrapper
}

/// A daemon config carrying the Proton store and nothing else, with a
/// generation already published into its session root.
///
/// From JSON rather than a struct literal, deliberately: a key the daemon does
/// not read is dropped in silence, and a struct literal cannot show that the
/// coordinates below travelled through a file. `timeout_ms` is spelled out for
/// the reason `tests/suite_hygiene.rs` enforces — a fixture killed by its own
/// deadline fails in a shape that reads as a missing fixture.
///
/// One store, so nothing is ambiguous. With the file store also enabled, an
/// unpinned name would be reported ambiguous with **nothing asked**, and every
/// case below would pass without proving anything.
///
/// # Why every case here needs a published generation
///
/// Under generations, `<session_dir>` is the ROOT — a read resolves against
/// whatever `<root>/current` names, and a fresh root names nothing. None of
/// the cases built on this config are about the renewal loop establishing
/// that first generation (`daemon_proton_renewal.rs` is), so each one
/// publishes its own before the daemon that will read it ever starts, the same
/// way an operator's first `keylessd login` would have to before any of those
/// cases could observe a resolve at all.
pub fn daemon_config_with_proton(dir: &Path, vendor: &Path) -> DaemonConfig {
    crate::support::generations::publish_generation(&session_dir(dir));
    // A credential file with both entries written, because this fixture takes
    // the crate's own `key_provider` default: under `env` a config declaring
    // no key is one a real `pass-cli` refuses at provider construction, so a
    // control running that way would be modelling an arrangement that cannot
    // work anywhere but against a stand-in.
    let credentials = dir.join("proton.json");
    write_secrets(
        &credentials,
        &[
            ("AGENT_TOKEN", TOKEN_DECOY),
            ("LOCAL_KEY", ENCRYPTION_KEY_DECOY),
        ],
    );
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "credentials_file":"{credentials}",
                                   "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN",
                                                   "PROTON_PASS_ENCRYPTION_KEY":"LOCAL_KEY"}},
                                   "timeout_ms":60000}}}},
             "secrets":{{"{DECLARED}":{{"store":"proton","vault":"{VAULT}",
                                        "item":"{ITEM}","field":"password"}},
                         "{HALF_WRITTEN}":{{"store":"proton","vault":"{VAULT}"}}}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = session_dir(dir).display(),
        credentials = credentials.display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}
