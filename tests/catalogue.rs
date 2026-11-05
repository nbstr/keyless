//! The naming rule, and what a derived index refuses to carry.
//!
//! # Why a fixture stands in for the 50 live names, and why it is invented
//!
//! The rule in `src/store/catalogue/naming.rs` was derived from the names the live
//! daemon already serves, and reproduces all 50 of them exactly with zero
//! collisions — measured against the live `keylessd.json` on 2026-09-12 and
//! re-verified there by a third independent reader. That file is root-owned and
//! holds the coordinates of every credential on the machine, so this suite must
//! not read it and no CI runner could.
//!
//! The fixture below therefore stands in for it, and it is INVENTED rather than
//! transcribed. `tests/publication.rs` refuses a real item title, vault name or
//! field label anywhere in this repository, and it is right to: a scrub that
//! replaced an item's title once already left two of its field labels behind.
//!
//! What the fixture reproduces is the CHARACTER CLASSES that make the rule hard,
//! which is the whole of what the awkward live names have in common — a
//! non-ASCII letter inside a word, a leading digit, spaces beside hyphens, a
//! multi-word custom field label, and the bare-password case. A rule that gets
//! these right gets the plain ones right by construction; a rule that gets one
//! of them wrong is wrong on the live machine.

#[path = "catalogue/advice.rs"]
mod advice;
#[path = "catalogue/boundaries.rs"]
mod boundaries;
#[path = "catalogue/fixtures.rs"]
mod fixtures;
#[path = "catalogue/minting.rs"]
mod minting;
#[path = "catalogue/routing.rs"]
mod routing;
