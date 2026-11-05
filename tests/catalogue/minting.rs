//! The naming rule, held against the fixture of awkward live names.

use keyless::store::catalogue::naming::{mint, mint_bare};

#[test]
fn the_minter_reproduces_every_awkward_name_the_daemon_already_serves() {
    // (item title, field name, the name the live daemon serves it under).
    let declared = [
        // A non-ASCII letter is ONE underscore, not one per UTF-8 byte. This is
        // the case a byte-wise walk gets wrong while looking right everywhere
        // else: `D_COY` with two underscores would be a name nobody has ever
        // asked for. Two live names carry this shape.
        ("decoy-db-alpha", "Réf décoy", "DECOY_DB_ALPHA__R_F_D_COY"),
        (
            "decoy-db-alpha",
            "Type de bàse de décoys",
            "DECOY_DB_ALPHA__TYPE_DE_B_SE_DE_D_COYS",
        ),
        // A title that starts with a digit is not a legal variable name, so it
        // is prefixed rather than trimmed — trimming would collide `9decoy`
        // with an item titled `decoy`.
        ("9decoy", "password", "_9DECOY"),
        // Spaces beside hyphens, which mint the same character either way.
        (
            "decoy PAT alpha-beta-gamma",
            "password",
            "DECOY_PAT_ALPHA_BETA_GAMMA",
        ),
        // A multi-word custom field label, which is where a caller's guess is
        // least likely to be right.
        ("decoy-agent", "Token decoy", "DECOY_AGENT__TOKEN_DECOY"),
        // The bare case: one item, one password, one name with no suffix.
        ("demo api key", "password", "DEMO_API_KEY"),
    ];

    for (title, field_name, expected) in declared {
        assert_eq!(
            mint(title, field_name).as_deref(),
            Some(expected),
            "`{title}` / `{field_name}`"
        );
    }
}

#[test]
fn a_title_that_mints_nothing_addressable_mints_no_name_at_all() {
    // An empty result is not a name, it is a collision waiting: every untitled
    // item would answer to it.
    assert_eq!(mint_bare(""), None);
    assert_eq!(mint("", "password"), None);
    // And a field whose name normalises to nothing cannot suffix anything.
    assert_eq!(mint("real", ""), None);
}
