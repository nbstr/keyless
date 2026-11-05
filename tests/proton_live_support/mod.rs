//! What every live Proton suite shares: its required inputs, a registry built
//! from a config string, and an equality check that never prints a value.

// Each live suite is its own crate and uses a different subset.
#![allow(dead_code)]

use keyless::config::Config;
use keyless::store::{self, Invocation, Registry};

/// A required input, or a panic naming it.
///
/// Never a default and never a skip: a live test that invents its own inputs
/// verifies the invention.
pub fn required(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        panic!(
            "{key} must be set to run the live Proton tests; see the header of tests/proton_live.rs"
        )
    })
}

pub fn registry_from(json: &str) -> Registry {
    let config: Config = serde_json::from_str(json).expect("the test config must be valid");
    store::build(&config, &Invocation::default()).registry
}

/// Assert equality without ever putting either side in the failure message.
pub fn assert_is_expected(got: &str, expected: &str, what: &str) {
    assert_eq!(
        got.len(),
        expected.len(),
        "{what}: got {} bytes, expected {}",
        got.len(),
        expected.len()
    );
    assert!(got == expected, "{what}: same length, different bytes");
}
