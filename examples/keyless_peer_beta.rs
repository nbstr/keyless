//! A test peer that is deliberately **not** pinned.
//!
//! The twin of `keyless_peer_alpha`. It exists so the adversarial tests have a
//! second real, signed, Mach-O executable to be refused as — and to be renamed
//! over alpha's path in the swap attack, where the question is whether the
//! daemon reports the identity of the file at the path or of the image actually
//! running.

#[path = "shared/peer_impl.rs"]
mod peer_impl;

fn main() {
    peer_impl::run("beta");
}
