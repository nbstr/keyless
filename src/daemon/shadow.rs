//! Which `keyless` a shell actually reaches, and whether it is the one this
//! daemon pins.
//!
//! # The failure this exists to catch
//!
//! `install/install.sh` puts the client in `/usr/local/bin` and pins its code
//! hash in `peer.allow_images`. Nothing anywhere makes `/usr/local/bin` the
//! first place a shell looks. A second copy of the same program — a
//! `cargo install` from months ago, a build somebody dropped in a personal bin
//! directory — sitting EARLIER on `PATH` is what the shell runs, and it is a
//! different binary with a different code hash, so the daemon refuses it.
//!
//! Both halves of that are quiet in the same direction:
//!
//! - **Run as a client**, the refusal says the image is not a pinned client.
//!   It names the peer's PATH, so the file being refused is at least
//!   identifiable — but only to somebody already connecting, and only after
//!   the run has degraded. Nothing tells the operator that the file the
//!   installer pinned is sitting a directory further along, unreached.
//! - **Run as anything else**, an old copy simply lacks whatever landed since
//!   it was built. Measured: `keylessd credential --name …` answered
//!   `unrecognized subcommand 'credential'` from a copy ten days old, while the
//!   binary carrying that verb sat installed and unreached. The error names a
//!   missing feature, so the first hypothesis is a bad build.
//!
//! # What establishes that a file is the pinned client
//!
//! Its code hash, and nothing else. `peer.allow_images` holds the code
//! directory hash of the exact image the daemon will accept, and
//! [`code_hash_of_file`] asks the kernel's own signing tooling for the same
//! number over a file. A file whose hash is in the set **is** that image, bit
//! for bit — not "looks like keyless", not "has our subcommands", which is a
//! test an old build fails precisely because it is old.
//!
//! The converse claim is never made. A file whose hash is not in the set is
//! reported as **not pinned** and as nothing else: that is equally true of a
//! stale `keyless` of ours and of a stranger's program that happens to carry
//! the name, and this module has no way to tell those apart and does not try.
//! It reads files and hashes them; it opens nothing for writing, executes
//! nothing, and prescribes nothing that would touch a file it cannot identify.
//!
//! # Why it walks `PATH` rather than asking `command -v`
//!
//! `command -v` is a shell builtin, so reaching it means spawning a shell,
//! whose answer is then filtered through that shell's own hash cache — the
//! cache that keeps resolving a deleted path until `hash -r`. Splitting `PATH`
//! and looking for the file is the resolution rule itself, with no cache in
//! front of it, and it can name every candidate rather than only the winner,
//! which is what turns "this one is wrong" into "this one is wrong and that one
//! is right".
//!
//! # It can miss, and it cannot invent
//!
//! The `PATH` it is given is one process's. The operator's next shell may
//! resolve differently, and no process can read a shell that has not started
//! yet. So a finding here is always true — the file is there, its hash is what
//! it is — while a clean answer is only as good as the `PATH` it was handed.
//! That asymmetry is why the clean answer is reported as unproven rather than
//! as a pass.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::NAME;
use crate::attest::Policy;
use crate::ipc::peer::live::code_hash_of_file;

/// How many candidates are hashed before the walk stops.
///
/// A bound rather than trust: each hash is a `codesign` spawn, and this runs
/// inside the one command an operator uses when something is already wrong. A
/// `PATH` with fifty entries naming `keyless` is not a case worth paying for,
/// and stopping early can only cost a finding, never invent one.
const MAX_CANDIDATES: usize = 8;

/// What a walk of `PATH` found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Client {
    /// There is no pin set to compare against, so the question cannot be asked.
    ///
    /// Carries why, because "the config pins nothing" and "the pins in the
    /// config do not parse" are different faults and both are already reported
    /// by rows of their own.
    NoPins {
        /// Which of the two it was, in the words the row prints.
        reason: &'static str,
    },
    /// `PATH` was unset, empty, or held no directory that exists.
    NoPath,
    /// No file named `keyless` is on `PATH` at all.
    NotOnPath,
    /// The first `keyless` on `PATH` is the pinned client.
    Pinned {
        /// Where it was found.
        reached: PathBuf,
    },
    /// The first `keyless` on `PATH` is not the pinned client, and the pinned
    /// client is further along the same `PATH`.
    ///
    /// The one verdict here that is unambiguously a fault: two files, one of
    /// them provably the image this daemon accepts, and the shell reaches the
    /// other.
    Shadowed {
        /// What a shell runs.
        reached: PathBuf,
        /// The pinned client, further along `PATH`.
        pinned: PathBuf,
    },
    /// A `keyless` is on `PATH` and none of the ones found is pinned.
    NonePinned {
        /// What a shell runs.
        reached: PathBuf,
        /// How many candidates were hashed.
        examined: usize,
    },
}

/// Walk `path` for `keyless` and compare each one found against `policy`.
///
/// Both inputs are injected rather than read here, for the reason
/// [`crate::cmd::doctor::DoctorRequest`] injects its freshness: a function that
/// reads the ambient environment makes every test that goes through it a test
/// of the machine it runs on, and the `PATH` under test is the whole subject.
///
/// `policy` is `None` when the config's pins would not parse — the policy row
/// says so already, and guessing a pin set from a config that has none would
/// invent an answer.
#[must_use]
pub fn look(path: Option<&OsStr>, policy: Option<&Policy>) -> Client {
    let Some(policy) = policy else {
        return Client::NoPins {
            reason: "the pinned images in this config do not parse",
        };
    };
    if policy.image_count() == 0 {
        return Client::NoPins {
            reason: "this config pins no image",
        };
    }
    let Some(path) = path else {
        return Client::NoPath;
    };

    let mut reached: Option<PathBuf> = None;
    let mut examined = 0usize;
    let mut seen: Vec<PathBuf> = Vec::new();

    for directory in std::env::split_paths(path) {
        // An empty entry means the working directory to a shell. It is skipped
        // rather than followed: a report whose verdict depends on where the
        // operator was standing is not a report about the install.
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(NAME);
        if !is_executable_file(&candidate) {
            continue;
        }
        // Two `PATH` entries can be the same directory through a symlink, and
        // hashing the same file twice would cost a spawn and could report a
        // file as shadowing itself.
        let identity = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
        if seen.contains(&identity) {
            continue;
        }
        seen.push(identity);

        if reached.is_none() {
            reached = Some(candidate.clone());
        }
        examined += 1;

        // A file that cannot be hashed — unsigned, unreadable, not a Mach-O —
        // is not the pinned image, because the pin IS a code hash. It counts as
        // examined and nothing more is claimed about it.
        if let Ok(hash) = code_hash_of_file(&candidate)
            && policy.pins_image(&hash)
        {
            let first = reached.expect("a candidate was recorded before any was hashed");
            return if first == candidate {
                Client::Pinned { reached: first }
            } else {
                Client::Shadowed {
                    reached: first,
                    pinned: candidate,
                }
            };
        }

        if examined == MAX_CANDIDATES {
            break;
        }
    }

    match reached {
        None => Client::NotOnPath,
        Some(reached) => Client::NonePinned { reached, examined },
    }
}

/// Whether cargo's own ledger records this file as a binary it installed for
/// the `keyless` package.
///
/// # Why a ledger and not the file
///
/// The pin settles what a file IS only in one direction: a hash in the set
/// identifies the image exactly, and a hash outside it identifies nothing at
/// all. So a stale build of this crate and a stranger's program of the same
/// name are, to a hash comparison, the same answer — and one of them may be
/// removed and the other may not.
///
/// `cargo install` writes down what it put where. `<CARGO_HOME>/.crates.toml`
/// maps a package to the binary names it installed into `<CARGO_HOME>/bin`,
/// and it is the record `cargo uninstall` itself reads. A file in that
/// directory, named in that package's list, has a provenance no property of
/// the bytes can supply — and it survives being old, which is exactly what a
/// behavioural test ("does it have our subcommands?") cannot do, since being
/// old is the defect.
///
/// # What it is used for, and what it is not
///
/// It selects a REMEDY, never an action taken here: nothing in this module
/// writes, and a false answer costs a sentence of advice. `false` is the
/// answer for anything it cannot read — no ledger, no entry, an unreadable
/// file — which keeps the "not identified, do not touch" branch the default.
#[must_use]
pub fn cargo_installed(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    // `<CARGO_HOME>/bin/<name>` — the ledger sits beside the `bin` directory,
    // so it is found from the file's own path and nothing needs to guess a home
    // directory. Under `sudo` that matters: `$HOME` there is root's.
    let Some(cargo_home) = path.parent().and_then(Path::parent) else {
        return false;
    };
    if path.parent().and_then(Path::file_name) != Some(OsStr::new("bin")) {
        return false;
    }
    let Ok(ledger) = std::fs::read_to_string(cargo_home.join(".crates.toml")) else {
        return false;
    };
    ledger.lines().any(|line| records(line, name))
}

/// Whether one `.crates.toml` line says the `keyless` package installed `name`.
///
/// The line's shape is `"<package> <version> (<source>)" = ["bin", …]`. Read by
/// hand rather than through a TOML parser: this crate's whole dependency list
/// is five crates and its auditability is the product, so a sixth for one line
/// of a file that is only ever consulted to phrase a suggestion is the wrong
/// trade. A shape this does not understand reads as `false`, which is the
/// cautious direction.
fn records(line: &str, name: &str) -> bool {
    let Some((key, installed)) = line.split_once('=') else {
        return false;
    };
    let package = key.trim().trim_matches('"');
    if package.split(' ').next() != Some(NAME) {
        return false;
    }
    installed
        .split(['[', ']', ',', '"', ' '])
        .any(|entry| entry == name)
}

/// Whether a path is a file some user could execute.
///
/// `metadata` follows symlinks, which is what a shell does: a `PATH` entry
/// pointing at a link to a build directory resolves to the build, and the
/// build is what gets hashed.
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two real, differently-signed executables to stand in for two builds of
    /// the client. Copies keep the signature they were built with, so each one
    /// has a stable code hash that `codesign` reports — which is exactly the
    /// property the pin rests on, exercised rather than mocked.
    const ONE: &str = "/bin/ls";
    const OTHER: &str = "/bin/cat";

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-shadow-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    /// Put a copy of `source` at `<dir>/<sub>/keyless` and return the directory
    /// it went in.
    fn plant(dir: &Path, sub: &str, source: &str) -> PathBuf {
        let bin = dir.join(sub);
        std::fs::create_dir_all(&bin).expect("bin dir");
        std::fs::copy(source, bin.join(NAME)).expect("copy");
        bin
    }

    fn joined(dirs: &[&Path]) -> std::ffi::OsString {
        std::env::join_paths(dirs.iter().map(|d| d.as_os_str())).expect("a PATH")
    }

    fn pinning(path: &Path) -> Policy {
        Policy::new()
            .allow_uid(0)
            .allow_image(code_hash_of_file(path).expect("a signed fixture"))
    }

    #[test]
    fn the_pinned_client_reached_first_is_the_pinned_client() {
        // The control. Without it, every assertion below that a shadow is found
        // is satisfied by a walk that never finds anything pinned.
        let dir = scratch("first");
        let good = plant(&dir, "good", ONE);
        let other = plant(&dir, "other", OTHER);
        let policy = pinning(&good.join(NAME));

        let found = look(Some(&joined(&[&good, &other])), Some(&policy));

        assert_eq!(
            found,
            Client::Pinned {
                reached: good.join(NAME)
            }
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unpinned_client_ahead_of_the_pinned_one_is_a_shadow() {
        let dir = scratch("shadow");
        let stale = plant(&dir, "stale", OTHER);
        let good = plant(&dir, "good", ONE);
        let policy = pinning(&good.join(NAME));

        let found = look(Some(&joined(&[&stale, &good])), Some(&policy));

        assert_eq!(
            found,
            Client::Shadowed {
                reached: stale.join(NAME),
                pinned: good.join(NAME),
            },
            "the same two files in the other order are the passing case above",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_not_the_pinned_client_is_read_and_never_written() {
        // A `keyless` on PATH that this daemon does not pin is somebody's file.
        // The walk hashes it, which reads it, and must do nothing else — so
        // this asserts the bytes and the modification time both survive the
        // question being asked.
        let dir = scratch("untouched");
        let stranger = plant(&dir, "stranger", OTHER);
        let file = stranger.join(NAME);
        let before = std::fs::read(&file).expect("fixture");
        let stamp = std::fs::metadata(&file).expect("stat").modified().ok();
        let good = plant(&dir, "good", ONE);
        let policy = pinning(&good.join(NAME));

        let found = look(Some(&joined(&[&stranger, &good])), Some(&policy));

        assert!(matches!(found, Client::Shadowed { .. }), "{found:?}");
        assert!(
            file.exists(),
            "a file this walk cannot identify was removed"
        );
        assert_eq!(before, std::fs::read(&file).expect("fixture"), "rewritten");
        assert_eq!(
            stamp,
            std::fs::metadata(&file).expect("stat").modified().ok(),
            "the file was opened for writing",
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_whose_clients_are_none_of_them_pinned_says_exactly_that() {
        let dir = scratch("nonepinned");
        let one = plant(&dir, "one", OTHER);
        let two = plant(&dir, "two", OTHER);
        let elsewhere = plant(&dir, "elsewhere", ONE);
        let policy = pinning(&elsewhere.join(NAME));

        let found = look(Some(&joined(&[&one, &two])), Some(&policy));

        assert_eq!(
            found,
            Client::NonePinned {
                reached: one.join(NAME),
                examined: 2,
            }
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_directory_reached_twice_is_hashed_once() {
        let dir = scratch("dedupe");
        let good = plant(&dir, "good", ONE);
        let policy = pinning(&good.join(NAME));

        let found = look(Some(&joined(&[&good, &good])), Some(&policy));

        assert_eq!(
            found,
            Client::Pinned {
                reached: good.join(NAME)
            }
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_with_no_client_on_it_is_not_a_finding() {
        let dir = scratch("empty");
        std::fs::create_dir_all(dir.join("bin")).expect("bin");
        let policy = pinning(Path::new(ONE));

        assert_eq!(
            look(Some(&joined(&[&dir.join("bin")])), Some(&policy)),
            Client::NotOnPath
        );
        assert_eq!(look(None, Some(&policy)), Client::NoPath);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_is_asked_of_a_config_with_no_pin_to_ask_it_against() {
        let dir = scratch("nopins");
        let good = plant(&dir, "good", ONE);

        assert!(matches!(
            look(Some(&joined(&[&good])), None),
            Client::NoPins { .. }
        ));
        assert!(matches!(
            look(Some(&joined(&[&good])), Some(&Policy::new())),
            Client::NoPins { .. }
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_entry_that_is_not_an_executable_file_is_skipped() {
        // A directory named `keyless`, and a file with no execute bit. A shell
        // runs neither, so neither may be reported as what a shell runs.
        let dir = scratch("notexec");
        let decoy = dir.join("decoy");
        std::fs::create_dir_all(decoy.join(NAME)).expect("a directory named keyless");
        let plain = dir.join("plain");
        std::fs::create_dir_all(&plain).expect("plain");
        std::fs::write(plain.join(NAME), b"not executable").expect("write");
        let good = plant(&dir, "good", ONE);
        let policy = pinning(&good.join(NAME));

        assert_eq!(
            look(Some(&joined(&[&decoy, &plain, &good])), Some(&policy)),
            Client::Pinned {
                reached: good.join(NAME)
            }
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod ledger_tests {
    use super::*;

    /// A cargo home with a `bin/keyless` in it and a ledger saying `body`.
    fn cargo_home(tag: &str, body: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!(
            "keyless-ledger-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("bin")).expect("bin");
        std::fs::copy("/bin/ls", home.join("bin").join(NAME)).expect("copy");
        if !body.is_empty() {
            std::fs::write(home.join(".crates.toml"), body).expect("ledger");
        }
        home
    }

    /// A `.crates.toml` line, in the shape cargo writes: a quoted
    /// `<package> <version> (<source>)` key, and the binary names it installed.
    fn line(package: &str, binaries: &str) -> String {
        format!("[v1]\n\"{package} 0.1.0 (path+file:///src)\" = [{binaries}]\n")
    }

    #[test]
    fn a_binary_this_package_installed_through_cargo_is_recognised() {
        // The control for every refusal below. Without it, a `cargo_installed`
        // that answered `false` to everything would satisfy all of them.
        let home = cargo_home("ours", &line(NAME, "\"keyless\", \"keylessd\""));
        assert!(cargo_installed(&home.join("bin").join(NAME)));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_binary_of_that_name_installed_by_a_different_package_is_not_ours() {
        // The case the remedy must not act on: somebody else's crate that
        // happens to install a binary called `keyless`. `cargo uninstall
        // keyless` would not remove it, and proposing it would be wrong.
        let home = cargo_home("theirs", &line("keyless-ui", "\"keyless\""));
        assert!(!cargo_installed(&home.join("bin").join(NAME)));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_ledger_that_does_not_list_this_binary_name_is_not_a_record_of_it() {
        let home = cargo_home("othername", &line(NAME, "\"keylessd\""));
        assert!(!cargo_installed(&home.join("bin").join(NAME)));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn no_ledger_and_no_bin_directory_both_read_as_no_record() {
        let home = cargo_home("noledger", "");
        assert!(!cargo_installed(&home.join("bin").join(NAME)));

        // Not under a directory called `bin`, so the file beside it is not
        // cargo's install root and the ledger there says nothing about it.
        let elsewhere = home.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("dir");
        std::fs::copy("/bin/ls", elsewhere.join(NAME)).expect("copy");
        std::fs::write(
            home.join(".crates.toml"),
            line(NAME, "\"keyless\", \"keylessd\""),
        )
        .expect("ledger");
        assert!(!cargo_installed(&elsewhere.join(NAME)));

        let _ = std::fs::remove_dir_all(&home);
    }
}
