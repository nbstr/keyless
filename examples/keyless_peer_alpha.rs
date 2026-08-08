//! A test peer. Pinned by the attestation tests as the authorised client.
//!
//! Its twin `keyless_peer_beta` is the unauthorised one. The two differ only in
//! the tag they print, which is enough to give them different code hashes —
//! and a different code hash is the entire thing under test.

#[path = "shared/peer_impl.rs"]
mod peer_impl;

fn main() {
    peer_impl::run("alpha");
}
