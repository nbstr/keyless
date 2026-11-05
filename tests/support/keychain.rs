use std::path::Path;
use std::path::PathBuf;

use super::install_executable;

/// How the `security` stub should behave.
pub enum Stub {
    /// Return a value, like a keychain item that exists.
    Returns(&'static str),
    /// Exit 44, which is how `security` reports `errSecItemNotFound`.
    NotFound,
    /// Fail in some other way, like a locked keychain.
    Errors,
    /// Report unhealthy for `list-keychains` as well as failing lookups.
    Dead,
}

/// Write a config at `<dir>/config.json` whose keychain store is a stub, with
/// `secrets` as its declarations.
///
/// `secrets` is the caller's because it is the only half that differs between
/// the four sites this replaced — one of them declares a second name to prove
/// the narrowing, the rest declare `DECOY` alone. The store half is identical
/// at all four and now has one home.
///
/// # Why the deadline is written here at all
///
/// `timeout_ms` is a CEILING, never a measurement: not one case using this
/// config asserts anything about how long the stub took. Left out, the store
/// inherits `keyless::config::DEFAULT_TIMEOUT_MS` — the PRODUCTION default, ten
/// seconds — and the only thing that number then decides is how loaded the
/// machine has to be before a passing test reports a failure. So the value is
/// `keyless::config::MAX_TIMEOUT_MS`, the top of the range the tool will
/// honour, which is the nearest a config can be spelled to the "no deadline"
/// these cases actually want.
///
/// It was written into four copies of this literal before this function
/// existed, and `tests/suite_hygiene.rs`'s deadline gate is what refuses a
/// fifth that leaves it out.
pub fn keychain_stub_config(dir: &Path, behaviour: &Stub, secrets: &str) -> PathBuf {
    let stub = stub_security(dir, behaviour);
    let path = dir.join("config.json");
    let body = format!(
        r#"{{"stores":{{"keychain":{{"service":"keyless","binary":"{binary}","timeout_ms":60000}}}},
            "secrets":{secrets}}}"#,
        binary = stub.display(),
    );
    std::fs::write(&path, body).expect("write config");
    path
}

/// Write an executable stand-in for `/usr/bin/security`.
///
/// The real binary is never invoked by this suite. A stub means the tests can
/// exercise every branch of the adapter — found, absent, backend error — with
/// no dependency on what is or is not in the developer's keychain.
pub fn stub_security(dir: &Path, behaviour: &Stub) -> PathBuf {
    // `add-generic-password` is answered by every stub that is not `Dead`, and it
    // records what arrived on stdin at `<dir>/security.stdin`. Whether a *read*
    // finds an item is orthogonal to whether a *write* is accepted, so the two are
    // separate branches rather than one shared exit status.
    //
    // The real binary reads the password from stdin twice; `cat` here is what lets
    // a test check that both copies arrived, and draining stdin is also what stops
    // the writer thread blocking on a full pipe.
    let write = format!(
        "\x20 add-generic-password) cat > '{}'; exit 0 ;;\n",
        dir.join("security.stdin").display()
    );
    let body = match behaviour {
        Stub::Returns(value) => format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
             \x20 find-generic-password) printf '%s\\n' '{value}'; exit 0 ;;\n\
             {write}\
             esac\n\
             exit 1\n"
        ),
        Stub::NotFound => format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
             \x20 find-generic-password) exit 44 ;;\n\
             {write}\
             esac\n\
             exit 1\n"
        ),
        Stub::Errors => format!(
            "#!/bin/sh\n\
             case \"$1\" in\n\
             \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
             {write}\
             esac\n\
             echo 'security: SecKeychainSearchCopyNext: User interaction is not allowed.' >&2\n\
             exit 51\n"
        ),
        Stub::Dead => {
            "#!/bin/sh\necho 'security: keychain is unavailable' >&2\nexit 1\n".to_owned()
        }
    };

    install_executable(&dir.join("security-stub"), &body)
}

/// A `security` stand-in that takes `millis` to answer.
///
/// Coalescing is only observable while a request is in flight, so a test that
/// wants to see it needs a backend slow enough to have an in-flight window.
/// This is that backend: a real subprocess on the real adapter path, just a
/// slow one.
pub fn slow_store_stub(dir: &Path, value: &str, millis: u64) -> PathBuf {
    let seconds = millis as f64 / 1000.0;
    let body = format!(
        "#!/bin/sh\n\
         case \"$1\" in\n\
         \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
         \x20 find-generic-password) sleep {seconds}; printf '%s\\n' '{value}'; exit 0 ;;\n\
         esac\n\
         exit 1\n"
    );
    install_executable(&dir.join("security-slow"), &body)
}

/// A `security` stand-in that answers instantly the first time and sleeps
/// past `seconds` on every call after, so a refresh queued behind the first
/// answer cannot land inside the refresh grace.
pub fn slow_after_first_store_stub(dir: &Path, value: &str, seconds: u64) -> PathBuf {
    let counter = dir.join("calls.count");
    let body = format!(
        "#!/bin/sh\n\
         count=$(cat '{counter}' 2>/dev/null || echo 0)\n\
         count=$((count + 1))\n\
         echo \"$count\" > '{counter}'\n\
         case \"$1\" in\n\
         \x20 list-keychains) echo '\"/tmp/stub.keychain-db\"'; exit 0 ;;\n\
         \x20 find-generic-password)\n\
         \x20\x20\x20 if [ \"$count\" -gt 1 ]; then sleep {seconds}; fi\n\
         \x20\x20\x20 printf '%s\\n' '{value}'; exit 0 ;;\n\
         esac\n\
         exit 1\n",
        counter = counter.display(),
    );
    install_executable(&dir.join("security-slow-after-first"), &body)
}
