use crate::store::proton::token::{classify_token, refused_the_token};

#[test]
fn a_refused_token_is_told_apart_from_a_broken_session() {
    // The fifth state a `check` must distinguish, and the only one that
    // takes a round trip to establish. Its remedy is at the vendor;
    // everything else on this path is fixed on the filesystem, and a
    // reader told to re-mint a session will re-mint it with the same
    // rejected token and watch it fail again.
    //
    // The vendor's own wording, read out of the 2.3.2 binary. It is ONE
    // sentence for three causes — expired, revoked, mistyped — which is
    // exactly why the branch cannot claim more than which side the fault
    // is on.
    for said in [
        "Invalid or expired personal access token",
        "This personal access token is invalid, expired or has been deleted.",
        "Error creating personal access token session",
    ] {
        assert!(refused_the_token(said), "not matched: {said}");
    }

    // The control, and it is the whole point of the branch: these are
    // faults on THIS filesystem, and reading them as a token problem would
    // send somebody to the vendor's dashboard for a token that is fine.
    for said in [
        "No active session",
        "This operation requires an authenticated client",
        "Error decrypting local session",
        "Could not find vault",
    ] {
        assert!(!refused_the_token(said), "wrongly matched: {said}");
    }
}

#[test]
fn a_token_that_is_not_one_is_named_by_its_shape_and_never_by_its_content() {
    // Every string below is a plausible paste into the credential file,
    // and every one of them passes the mode check, the owner check and the
    // parse check. What tells them apart is the shape, and the message may
    // describe the shape without ever rendering the value.
    let cases: [(&str, &str); 6] = [
        ("", "empty"),
        ("keyless-daemon", "pst_"),
        ("pst_decoy0Aa1", "::"),
        ("pst_decoy0Aa1::", "no encryption key"),
        ("pst_::ZGVjb3k=", "with nothing between"),
        ("pst_decoy0Aa1::not base64!", "base64-urlsafe"),
    ];
    for (value, expected) in cases {
        let said = classify_token(value).expect_err(&format!("`{value}` must not pass as a token"));
        assert!(said.contains(expected), "for `{value}`: {said}");
        assert!(
            !said.contains(value) || value.is_empty(),
            "the value reached the message: {said}"
        );
    }

    // The control. Without it, every case above is satisfied by a function
    // that refuses everything.
    classify_token("pst_decoy0Pat0never0real0Aa1::ZGVjb3kta2V5LTA5MDk=")
        .expect("a well-formed token must pass");

    // And whitespace, which is the paste that looks right in an editor and
    // authenticates as a different string.
    assert!(classify_token("pst_decoy0Aa1::ZGVjb3k=\n").is_err());
}
