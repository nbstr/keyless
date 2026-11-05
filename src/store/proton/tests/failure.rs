use super::{SCOPED, parts_store};
use crate::error::StoreError;
use crate::store::proton::failure::reached_no_service;

#[test]
fn a_vendor_that_never_reached_the_service_is_not_a_verdict_on_the_item() {
    // Each sentence is the vendor's own or this platform's `strerror`, and
    // each arrives inside a longer line, which is how it arrives in the log.
    for phrase in [
        "Error in personal access token login flow: failed to connect to host",
        "error resolving destination: unknown error errno=None",
        "Connection refused (os error 61)",
        "Network is unreachable (os error 51)",
        "No route to host (os error 65)",
        "Connection reset by peer (os error 54)",
        "Operation timed out (os error 60)",
        "Software caused connection abort (os error 53)",
    ] {
        assert!(
            reached_no_service(phrase),
            "a transport failure was read as a verdict: {phrase}"
        );
    }

    // The controls, and they are what the allowlist is for: each of these
    // is the account answering ABOUT the item, so each has to evict a
    // cached value rather than extend its life.
    for verdict in [
        "vault `company` holds no item titled `decoy`",
        "the personal access token was refused",
        "some sentence no release has ever printed",
        "",
    ] {
        assert!(
            !reached_no_service(verdict),
            "a verdict was read as a transport failure: {verdict}"
        );
    }
}

#[test]
fn the_error_variant_is_what_carries_that_distinction_to_the_cache() {
    // The daemon's cache reads the VARIANT, never the sentence: an
    // `Unavailable` keeps a value alive past its freshness window and a
    // `Backend` evicts it. So the classification has to survive the trip
    // through the store, not merely hold inside the predicate above.
    // The session side (no `Generations` behind it, an explicit
    // directory so `enter()` has somewhere to read) is what `parts_store`
    // builds without a session dir added — see the test beside this one
    // — so `session_is_at_fault` short-circuits on `pass.generation()`
    // being `None` and the vendor's own words are the only thing
    // deciding either verdict below.
    let store = parts_store().in_session_dir(Some(std::path::PathBuf::from(SCOPED)));
    let pass = store.enter().expect("no generations is not a refusal");

    let silent = store.vendor_failed(
        &pass,
        "cannot list vault `company`: failed to connect to host".to_owned(),
        "failed to connect to host",
    );
    assert!(
        matches!(silent, StoreError::Unavailable { .. }),
        "a store that could not answer was reported as a verdict: {silent}"
    );

    let verdict = store.vendor_failed(
        &pass,
        "cannot list vault `company`: no such vault".to_owned(),
        "no such vault",
    );
    assert!(
        matches!(verdict, StoreError::Backend { .. }),
        "a vendor verdict was reported as a store that could not answer: {verdict}"
    );
}
