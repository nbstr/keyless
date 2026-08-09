//! The complete verb set: [`run`], [`ls`], [`discover`], [`write`], [`doctor`],
//! [`init`].
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
//!
//! [`init`] adds nothing to that surface. It detects which backends are
//! installed, writes a `stores` block, and proves it — it never asks for a value,
//! never accepts one, and there is no field in what it writes that a value fits
//! in. [`status`] is the shared vocabulary the reports are rendered with, and it
//! exists so that "what was proven" has exactly one spelling across every verb.
//!
//! [`refuse`] is the same constraint aimed at the person rather than the code.
//! An absence teaches nobody: somebody who types `keyless get` learns only that
//! a word was unrecognized, which is what a CLI says about a typo and about a
//! feature that has not been written yet. That module answers those words with
//! the reason, so the design states itself at the moment somebody tests it.

pub mod discover;
pub mod doctor;
pub mod init;
pub mod ls;
pub mod refuse;
pub mod run;
pub mod status;
pub mod write;
