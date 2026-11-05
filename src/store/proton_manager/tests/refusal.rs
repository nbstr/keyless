use super::manager;

#[test]
fn a_vendor_refusal_about_the_role_carries_the_fix() {
    // The exact bytes the live account produced on 2026-08-08. `NotAllowed` is
    // on the `Caused by:` line, three lines down — quoting only the first line
    // reported this as `Error creating login item`, which names no cause, and
    // the guidance below never fired.
    let stderr = b"Error: Error creating login item\n\nCaused by:\n    Could not perform \
                   operation. Reason: NotAllowed\n";
    let detail = manager()
        .refused(stderr, "cannot create `d`", true)
        .to_string();
    assert!(detail.contains("NotAllowed"), "{detail}");
    assert!(detail.contains("ROLE"), "{detail}");
    assert!(detail.contains("--role editor"), "{detail}");

    // The negative control for reading past the first line: with only the
    // first line quoted this fails, which is what makes the assertion above a
    // statement about `summarise` being wired in here.
    assert!(
        !crate::store::exec::first_line(stderr).contains("NotAllowed"),
        "the first line already carried the cause, so this test proves nothing"
    );
}

#[test]
fn an_unexplained_create_failure_names_the_role_as_a_likelihood_not_a_fact() {
    // `--role` defaults to `viewer`, so an unexplained create failure is far
    // more often a read-only token than anything else. Saying so is useful;
    // asserting it would be wrong the day the network drops.
    let detail = manager()
        .refused(
            b"Error: Error creating login item\n",
            "cannot create `d`",
            true,
        )
        .to_string();
    assert!(detail.contains("most common cause"), "{detail}");
    assert!(detail.contains("--role editor"), "{detail}");
    assert!(
        !detail.contains("That is the token's ROLE"),
        "an unexplained failure was reported as a certainty: {detail}"
    );
}

#[test]
fn a_listing_failure_is_not_blamed_on_the_role() {
    // A viewer CAN list. Attaching the role guidance here would send the
    // reader to fix something that is not broken.
    let detail = manager()
        .refused(
            b"Error: Error finding vault\n",
            "cannot list vault `personal`",
            false,
        )
        .to_string();
    assert!(detail.contains("finding vault"), "{detail}");
    assert!(!detail.contains("--role"), "{detail}");
}
