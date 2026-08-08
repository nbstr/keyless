//! The complete verb set: [`run`], [`ls`], [`discover`], [`write`], [`doctor`].
//!
//! There is no `get`, no `read`, no `export`, no `show`, no `--reveal` and no
//! `--print`. This is the tool's defining constraint, and it is structural
//! rather than a policy: no function in this module returns a plaintext value
//! to a caller's stdout, so there is nothing to expose by adding a flag.
//!
//! That constraint is what the two newer modules are shaped around.
//! [`discover`] reports an item's field NAMES and never a value or a value's
//! length, and [`write`] puts a value into a store while printing only that it
//! did — including `new`, which generates a credential and then does not show it
//! to anybody.
//!
//! The reasoning is behavioural rather than theoretical. A CLI that already
//! reads its key from the environment still gets that key typed at it as a
//! literal flag, because the flag is one line and setting up the environment is
//! more than one. Availability of the safe path does not win. Only being the
//! *shortest* path wins — and a single verb that prints a value is always the
//! shortest path.

pub mod discover;
pub mod doctor;
pub mod ls;
pub mod run;
pub mod write;
