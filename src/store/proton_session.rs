//! The on-disk layout of the daemon's Proton Pass identity, and who is reading
//! it right now.
//!
//! # The invariant this module exists to hold
//!
//! A directory the daemon serves reads from is written by exactly one
//! `pass-cli login`, before any other child is pointed at it, and is never
//! mutated or deleted by this process while it is current. A renewal
//! therefore never opens, mutates or deletes the directory reads are using —
//! it builds a fresh one beside it, and only swaps a pointer once the fresh
//! one has proved itself.
//!
//! Everything below serves that one property. `Generations` owns the layout —
//! a root directory holding a set of `gen-<millis>-<pid>` directories and a
//! `current` file naming which one is live — and a pass table counting, for
//! each generation, how many vendor children this process has in flight
//! against it. Nothing here spawns a vendor child; that is
//! [`crate::daemon::login`]'s and [`super::proton::ProtonStore`]'s job. This
//! module answers exactly two questions: which directory is current right
//! now, and is it safe to delete a directory that used to be.
//!
//! # Why the pointer is a validated NAME and not a path
//!
//! `<root>/current` holds a value this process is about to join to `root` and
//! hand to a child as `PROTON_PASS_SESSION_DIR`. A path in that file would let
//! whoever can write the root point every future child anywhere on the
//! filesystem — the pointer would BE a traversal primitive. So the file never
//! holds a path: it holds a name drawn from a closed alphabet
//! (`gen-<1..20 digits>-<1..10 digits>`, ASCII, ≤ 64 bytes), the name is
//! parsed before it is ever joined to anything, and a value that does not
//! parse is refused — never quoted back, never resolved to a path, never
//! substituted with a guess. A generation cannot live anywhere but under the
//! root, which is the point.
//!
//! # Why a read never waits
//!
//! [`Generations::enter`] takes a lock only long enough to read `current` and
//! increment one counter; it never blocks on another thread's work. Retirement
//! is what waits, and it waits for READERS, never the other way around: see
//! [`Generations::drain`].
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The name of the pointer file inside `<root>`.
const CURRENT_FILE: &str = "current";

/// The temporary name [`Generations::publish`] renames over [`CURRENT_FILE`].
///
/// Excluded from [`Generations::candidates`] by the parse rule alone — it does
/// not begin with [`GENERATION_PREFIX`], so nothing has to know its name to
/// keep it out of the retirement set.
const CURRENT_TEMP_FILE: &str = ".current.new";

/// Every generation directory's name begins with this.
const GENERATION_PREFIX: &str = "gen-";

/// The mode every generation directory, and [`CURRENT_FILE`]'s directory,
/// is created at.
///
/// The same `0700` [`crate::daemon::login::SESSION_DIR_MODE`] uses for the
/// root, for the same reason: the local encryption key lives inside a
/// generation under the `fs` key provider, and it is the whole of what stands
/// between anyone else on this machine and the vault. Not imported from
/// `daemon::login` — this module is `src/store/`, which `daemon` depends on
/// and not the reverse, so the mode is restated here rather than borrowed
/// against the grain of that layering.
const GENERATION_DIR_MODE: u32 = 0o700;

/// The mode [`CURRENT_FILE`] is written at.
const CURRENT_FILE_MODE: u32 = 0o600;

/// The longest a generation name may be, in bytes. Far above what
/// `gen-<20 digits>-<10 digits>` ever produces (35 bytes) — the cap is a
/// second, independent line of defence against a hand-edited pointer, not the
/// rule that is expected to fire.
const MAX_NAME_LEN: usize = 64;

/// The most of `<root>/current` this process will ever read.
///
/// A pointer is one short line. Reading more than this is never correct
/// behaviour on this process's part; it is either a name too long to be valid
/// or something other than this module wrote the file.
const MAX_CURRENT_BYTES: u64 = 256;

/// A validated generation name: `gen-<millis>-<pid>`, and nothing else.
///
/// The only way to obtain one is [`GenerationName::mint`] (a fresh name from
/// the clock and this process's pid) or [`GenerationName::parse`] (a name read
/// back off disk, checked against the alphabet before anything is done with
/// it). There is no `From<String>` and no public constructor from parts —
/// every name in this process either was minted here or survived the parser,
/// and those are the only two provenances the rest of this module trusts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenerationName(String);

impl GenerationName {
    /// A fresh name for a generation this process is about to create.
    ///
    /// `pid` makes two processes racing to create a generation in the same
    /// millisecond produce different names; `now` makes retirement's age
    /// question answerable without a second file to read. Two generations
    /// created by the SAME process inside one millisecond would still
    /// collide — [`Generations::create`] documents why that is not mitigated
    /// here.
    #[must_use]
    pub fn mint(now: SystemTime, pid: u32) -> Self {
        let millis = now
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_millis())
            .unwrap_or(0);
        GenerationName(format!("{GENERATION_PREFIX}{millis}-{pid}"))
    }

    /// Validate `text` against the closed alphabet, or say nothing about why
    /// it failed.
    ///
    /// # Why this returns `Option` and never a sentence
    ///
    /// A value that fails to parse is, by construction, either a stray file an
    /// operator left in the root or an attempt to steer this process at a path
    /// it does not own. Neither is served by an error message that echoes the
    /// input back — see [`CurrentFault::Malformed`], whose whole point is that
    /// the bytes that failed are never quoted anywhere a reader could see them
    /// joined to a path.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text.is_empty() || text.len() > MAX_NAME_LEN || !text.is_ascii() {
            return None;
        }
        let rest = text.strip_prefix(GENERATION_PREFIX)?;
        let (millis, pid) = rest.split_once('-')?;
        let is_digits = |part: &str, range: std::ops::RangeInclusive<usize>| {
            range.contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
        };
        if !is_digits(millis, 1..=20) || !is_digits(pid, 1..=10) {
            return None;
        }
        Some(GenerationName(text.to_owned()))
    }

    /// The name, as it is joined to a root and as it is written into
    /// `current`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The instant encoded in the name, when the clock that minted it could be
    /// trusted.
    ///
    /// `None` only when the encoded milliseconds overflow what this platform's
    /// clock can represent — a name this module minted can never do that, so
    /// the only way to see `None` is a hand-edited `current` file, and
    /// [`Generations::candidates`] treats that the way it treats every clock
    /// question it cannot answer: not eligible.
    #[must_use]
    pub fn created_at(&self) -> Option<SystemTime> {
        let rest = self.0.strip_prefix(GENERATION_PREFIX)?;
        let (millis, _pid) = rest.split_once('-')?;
        let millis: u64 = millis.parse().ok()?;
        UNIX_EPOCH.checked_add(Duration::from_millis(millis))
    }
}

impl std::fmt::Display for GenerationName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why [`Generations::current`] could not name a live generation.
///
/// Every variant is a reason a READ degrades — see the `Display` impl for the
/// exact sentence a caller hands to [`crate::error::StoreError::Unavailable`].
/// None of them is a reason to refuse a WRITE: [`Generations::create`] and
/// [`Generations::publish`] do not consult this type at all, because a fresh
/// root with nothing current yet is exactly the state the first login runs
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentFault {
    /// `<root>/current` does not exist. A fresh root, or a renewal that has
    /// not landed yet.
    Absent,
    /// It exists and does not hold a valid generation name — empty,
    /// oversized, more than one line, not ASCII, or shaped like a path rather
    /// than a name. The bytes that failed are never part of this value.
    Malformed,
    /// It names a generation, but nothing by that name is a directory under
    /// the root — a name whose directory was removed from outside this
    /// process, or a name pointing at a symlink or a file rather than a
    /// directory this process created.
    Missing(GenerationName),
}

impl std::fmt::Display for CurrentFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurrentFault::Absent => f.write_str(
                "no Proton session has been established yet; the renewal loop or \
                 `keylessd login` creates one",
            ),
            CurrentFault::Malformed => f.write_str(
                "`current` does not hold a generation name; the next renewal rewrites it",
            ),
            CurrentFault::Missing(name) => {
                write!(f, "`current` names `{name}`, which is not there")
            }
        }
    }
}

/// One retirement candidate: a generation that is not current, or the legacy
/// pre-generation layout.
///
/// `scope` is where a vendor child is pointed to log the candidate out —
/// `<root>/<name>` for an ordinary generation, `<root>` itself for the legacy
/// candidate, because the vendor appends its own `.session` subdirectory to
/// whatever it is given. `delete` is what [`Generations::remove`] actually
/// unlinks, which for the legacy candidate is `<root>/.session` and not
/// `<root>` — the root is never removed, ever.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// `None` marks the legacy `<root>/.session` layout, which no
    /// [`GenerationName`] ever names.
    name: Option<GenerationName>,
    scope: PathBuf,
    delete: PathBuf,
}

impl Candidate {
    /// The generation this candidate names, or `None` for the legacy layout.
    #[must_use]
    pub fn name(&self) -> Option<&GenerationName> {
        self.name.as_ref()
    }

    /// Where a vendor child is scoped to act on this candidate.
    #[must_use]
    pub fn scope(&self) -> &Path {
        &self.scope
    }

    /// What [`Generations::remove`] deletes.
    #[must_use]
    pub fn delete(&self) -> &Path {
        &self.delete
    }

    /// A word for this candidate in a report line — the generation's own name,
    /// or `legacy` for the pre-generation layout, which no name describes.
    #[must_use]
    pub fn label(&self) -> String {
        match &self.name {
            Some(name) => name.to_string(),
            None => "legacy".to_owned(),
        }
    }
}

/// The gate a [`Generations::drain`] that ran out of patience returns.
///
/// Carries nothing: the caller already knows which candidate it asked about,
/// and the remedy is uniform — skip this candidate this tick, and the next
/// sweep tries again once the readers it is waiting on have had more time to
/// finish. See [`Generations::drain`] for what "waiting on" means here.
#[derive(Debug)]
pub struct StillRead;

/// One vendor child's permission to read a generation directory.
///
/// Dropping it releases the generation's pass count, on the ordinary path and
/// on an unwinding panic alike, which is what makes [`Generations::drain`]
/// correct against a reader that panics mid-call rather than merely against
/// one that returns.
///
/// `held` is `None` on the one path that never touches a [`Generations`] at
/// all: a `keyless` SESSION, which inherits whatever identity is already
/// logged in and has no renewal loop to race. See
/// [`super::proton::ProtonStore::enter`].
pub struct Pass<'g> {
    dir: PathBuf,
    held: Option<(&'g Generations, GenerationName)>,
}

impl Pass<'_> {
    /// The directory a vendor child should be scoped at for this pass.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The generation this pass reads, or `None` on the session side, which
    /// has no generations to name.
    ///
    /// What [`super::proton::ProtonStore`]'s listing cache compares against, so
    /// a slot filled under one generation is never handed to a reader of the
    /// next one — see the `generation` field on that module's `Listed`.
    #[must_use]
    pub fn generation(&self) -> Option<&GenerationName> {
        self.held.as_ref().map(|(_, name)| name)
    }

    /// A pass over `dir` with no generation behind it, and nothing to notify
    /// on drop.
    ///
    /// The session side's own shape: [`super::proton::ProtonStore::enter`]
    /// calls this when it carries no [`Generations`] at all, so a
    /// `keyless` session's reads still go through one `Pass` type rather than
    /// branching on whether a generation exists at every call site.
    #[must_use]
    pub(crate) fn without_generation(dir: PathBuf) -> Pass<'static> {
        Pass { dir, held: None }
    }
}

impl Drop for Pass<'_> {
    fn drop(&mut self) {
        let Some((generations, name)) = self.held.take() else {
            return;
        };
        let mut passes = generations.lock();
        if let Some(count) = passes.get_mut(&name) {
            *count = count.saturating_sub(1);
        }
        drop(passes);
        generations.changed.notify_all();
    }
}

impl std::fmt::Debug for Pass<'_> {
    /// Hand-written rather than derived: deriving would require
    /// `Generations: Debug`, which would print the whole pass table for a
    /// value that is, in a test failure message, only ever about ONE
    /// generation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pass")
            .field("dir", &self.dir)
            .field("generation", &self.generation())
            .finish()
    }
}

/// The on-disk layout of one root's worth of Proton Pass generations, and the
/// in-process count of who is reading which one right now.
///
/// One instance is shared, behind an `Arc`, by every store that reads through
/// it and by the renewal loop that creates and retires generations — see
/// [`crate::daemon::mod::Daemon::bind`], the only place that constructs the
/// daemon's own shared instance. `keylessd check` and `keylessd login` each
/// build a PRIVATE `Generations` over the same root instead: they resolve in
/// their own process and renew nothing, so there is no pass count for them to
/// share with anybody.
pub struct Generations {
    root: PathBuf,
    passes: Mutex<BTreeMap<GenerationName, usize>>,
    changed: Condvar,
    /// Retirement failures this process has already told somebody about, so a
    /// candidate stuck failing to retire is reported once rather than once per
    /// tick. Keyed by [`Candidate::label`] rather than by [`GenerationName`]
    /// so the legacy candidate — which has no name — gets the same treatment.
    reported_failures: Mutex<BTreeSet<String>>,
}

impl Generations {
    /// A fresh instance over `root`. Creates nothing on disk — the root itself
    /// is [`crate::daemon::login::ensure_session_dir`]'s to create, before this
    /// type is asked to do anything.
    #[must_use]
    pub fn at(root: PathBuf) -> Self {
        Generations {
            root,
            passes: Mutex::new(BTreeMap::new()),
            changed: Condvar::new(),
            reported_failures: Mutex::new(BTreeSet::new()),
        }
    }

    /// The root every generation lives under.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<GenerationName, usize>> {
        // A panic elsewhere cannot corrupt this map's meaning — it holds
        // counters with no invariant spanning two entries — so refusing to
        // serve from it after an unrelated panic would degrade every read for
        // no safety gained. The same argument the listing cache makes
        // elsewhere in this crate.
        self.passes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Read `<root>/current`, validate it, and confirm the directory it names
    /// exists and is not a symlink.
    ///
    /// # Errors
    ///
    /// The reason there is no live generation to read, in a form fit to hand
    /// straight to a caller building [`crate::error::StoreError::Unavailable`].
    /// See [`CurrentFault`].
    pub fn current(&self) -> Result<GenerationName, CurrentFault> {
        let mut file = match fs::File::open(self.root.join(CURRENT_FILE)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CurrentFault::Absent);
            }
            // Any other open failure — permission denied, not a regular file —
            // is not a name this process can trust either. Read as `Absent`
            // rather than `Malformed`: there are no bytes to have failed to
            // parse, so the sentence naming a shape fault would be describing
            // something that never happened.
            Err(_) => return Err(CurrentFault::Absent),
        };
        let mut bytes = Vec::new();
        if Read::by_ref(&mut file)
            .take(MAX_CURRENT_BYTES)
            .read_to_end(&mut bytes)
            .is_err()
        {
            return Err(CurrentFault::Malformed);
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Err(CurrentFault::Malformed);
        };
        // Exactly one trailing newline is stripped — a second one leaves an
        // embedded `\n`, which the parser below refuses as not ASCII-digits,
        // so a two-line file is `Malformed` rather than silently read as its
        // first line.
        let trimmed = text.strip_suffix('\n').unwrap_or(text);
        let name = GenerationName::parse(trimmed).ok_or(CurrentFault::Malformed)?;

        match fs::symlink_metadata(self.root.join(name.as_str())) {
            Ok(meta) if meta.is_dir() => Ok(name),
            // Missing, or present but not a plain directory — a symlink or a
            // file. Read identically: the vendor would happily CREATE an empty
            // store at a missing directory (`pass-cli/src/utils.rs:53-86`),
            // and a symlink is a path this process did not create, so neither
            // is a directory anything here may hand to a child.
            _ => Err(CurrentFault::Missing(name)),
        }
    }

    /// Take a pass on the current generation. Never blocks.
    ///
    /// The returned [`Pass`] names whichever generation `current` held at the
    /// instant this call incremented its count, under the same lock — so a
    /// [`Generations::publish`] racing this call is fully ordered against it:
    /// either this call sees the old name and the new one's pass count starts
    /// at zero, or it sees the new name and the old one is exactly as free to
    /// retire as it was before this call ran.
    ///
    /// # Errors
    ///
    /// Whatever [`Generations::current`] could not establish.
    pub fn enter(&self) -> Result<Pass<'_>, CurrentFault> {
        let mut passes = self.lock();
        let name = self.current()?;
        *passes.entry(name.clone()).or_insert(0) += 1;
        drop(passes);
        let dir = self.root.join(name.as_str());
        Ok(Pass {
            dir,
            held: Some((self, name)),
        })
    }

    /// Create a fresh, empty generation directory. Does not touch `current`.
    ///
    /// # Same-millisecond collisions are not guarded against
    ///
    /// Two [`GenerationName::mint`] calls from this SAME process inside one
    /// millisecond produce the same name, and this call would then fail with
    /// `AlreadyExists`. Nothing in this crate's call pattern does that: a
    /// generation is created once per renewal attempt, and attempts are
    /// seconds apart at the tightest configured interval
    /// ([`crate::daemon::session`]'s `MIN_INTERVAL`). A second PROCESS minting
    /// in the same millisecond cannot collide at all — the pid is part of the
    /// name.
    ///
    /// # Errors
    ///
    /// Whatever creating or securing the directory failed at. Nothing is left
    /// half-made: a failure after the directory exists but before it is
    /// chowned removes it rather than leaving a directory an unexpected owner
    /// holds.
    pub fn create(&self, owner: Option<(u32, u32)>) -> io::Result<(GenerationName, PathBuf)> {
        let name = GenerationName::mint(SystemTime::now(), std::process::id());
        let dir = self.root.join(name.as_str());
        fs::DirBuilder::new()
            .mode(GENERATION_DIR_MODE)
            .create(&dir)?;
        // Re-asserted unconditionally rather than trusted to `.mode()`, which
        // `mkdir`'s own umask can narrow at creation time — the same defence
        // `crate::daemon::login::ensure_session_dir` takes for the root.
        if let Err(error) =
            fs::set_permissions(&dir, fs::Permissions::from_mode(GENERATION_DIR_MODE))
        {
            let _ = fs::remove_dir_all(&dir);
            return Err(error);
        }
        if let Some((uid, gid)) = owner
            && let Err(error) = std::os::unix::fs::lchown(&dir, Some(uid), Some(gid))
        {
            let _ = fs::remove_dir_all(&dir);
            return Err(error);
        }
        Ok((name, dir))
    }

    /// Make `name` current: write-temp, sync, chown, rename over
    /// [`CURRENT_FILE`].
    ///
    /// The same temp-then-rename-then-chown shape
    /// [`crate::daemon::credential::write_atomically`] uses for the daemon's
    /// own credential file, for the same reason — a reader of `current` sees
    /// the old pointer or the new one, never a partial write, and a failure
    /// here leaves the previous pointer exactly as it was.
    ///
    /// Runs under the pass-table lock so it is fully ordered against
    /// [`Generations::enter`] and [`Generations::candidates`]: neither call
    /// can observe a `current` that is mid-rename.
    ///
    /// # Errors
    ///
    /// The step that failed. The temporary file is removed on every failure
    /// path; `current` is untouched.
    pub fn publish(&self, name: &GenerationName, owner: Option<(u32, u32)>) -> io::Result<()> {
        let temp = self.root.join(CURRENT_TEMP_FILE);
        let body = format!("{name}\n");

        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(CURRENT_FILE_MODE)
            .open(&temp)?;
        // As in `write_atomically`: an existing temp file keeps its old mode
        // unless this is set unconditionally, since `.mode()` on `open()` only
        // applies when the file is newly created.
        if let Err(error) = file.set_permissions(fs::Permissions::from_mode(CURRENT_FILE_MODE)) {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
        if let Err(error) = write_all_and_sync(&file, body.as_bytes()) {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
        drop(file);

        if let Some((uid, gid)) = owner
            && let Err(error) = std::os::unix::fs::chown(&temp, Some(uid), Some(gid))
        {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }

        let _passes = self.lock();
        fs::rename(&temp, self.root.join(CURRENT_FILE)).inspect_err(|_| {
            let _ = fs::remove_file(&temp);
        })
    }

    /// Every generation eligible for retirement right now, oldest first, plus
    /// the legacy candidate while it exists.
    ///
    /// Never contains the current generation. Empty whenever
    /// [`Generations::current`] cannot name one — see that method's own
    /// [`CurrentFault`] — because retirement is computed relative to a valid
    /// pointer and nothing else: a corrupt or absent pointer must never widen
    /// the set of things this process is willing to delete.
    ///
    /// A name is eligible once `now - max(created_at, mtime(current)) ≥
    /// grace`. The `max` is the conservative direction on both axes: the
    /// candidate's OWN age is a lower bound on how long it has been retired
    /// (it cannot have stopped serving before it was born), and `current`'s
    /// mtime is the instant the MOST RECENT publish landed, which is no
    /// earlier than when this specific candidate was superseded. Taking the
    /// larger of the two — the more recent instant — means both have to be
    /// old enough before this candidate is judged old enough; a corrupt clock
    /// pushing either value into the future makes `duration_since` fail, and a
    /// failure here is read as NOT eligible, never as eligible with an unknown
    /// age.
    #[must_use]
    pub fn candidates(&self, now: SystemTime, grace: Duration) -> Vec<Candidate> {
        let Ok(current) = self.current() else {
            return Vec::new();
        };
        let current_mtime = fs::metadata(self.root.join(CURRENT_FILE))
            .and_then(|meta| meta.modified())
            .unwrap_or(now);

        let mut found = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().and_then(GenerationName::parse) else {
                    continue;
                };
                if name == current {
                    continue;
                }
                let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                    continue;
                };
                if !meta.is_dir() {
                    continue;
                }
                let Some(created_at) = name.created_at() else {
                    continue;
                };
                let anchor = created_at.max(current_mtime);
                let Ok(age) = now.duration_since(anchor) else {
                    continue;
                };
                if age < grace {
                    continue;
                }
                let dir = self.root.join(name.as_str());
                found.push(Candidate {
                    name: Some(name),
                    scope: dir.clone(),
                    delete: dir,
                });
            }
        }
        // By the CLOCK each name encodes, not by the name's own string order:
        // the millisecond count is unpadded, so a lexicographic sort would
        // place `gen-999-…` after `gen-1000-…` even though it is older. Real
        // timestamps stay the same digit count for centuries, so this only
        // bites a fixture that mints small, hand-picked values — which is
        // reason enough not to lean on it anywhere.
        found.sort_by_key(|candidate| candidate.name.as_ref().and_then(GenerationName::created_at));

        // The legacy layout carries no age of its own to check: it predates
        // this whole scheme, so there is no `created_at` to read and no
        // moment at which it was "superseded" the way a generation is.
        // Eligible the instant a first generation has been published — which
        // `current` being `Ok` already establishes — and never before, since a
        // root with no published generation yet has nowhere to have logged
        // out to.
        if fs::symlink_metadata(self.legacy_dir()).is_ok() {
            found.push(Candidate {
                name: None,
                scope: self.root.clone(),
                delete: self.legacy_dir(),
            });
        }

        found
    }

    /// `<root>/.session` — the pre-generation layout, scoped and deleted the
    /// way a generation candidate is, but named by nothing.
    fn legacy_dir(&self) -> PathBuf {
        self.root.join(super::proton::SESSION_SUBDIR)
    }

    /// Wait for every in-process pass on `name` to end, for at most `bound`.
    ///
    /// Waits only for `name`'s own count — a pass held on a different
    /// generation, current or otherwise, never delays this call. Once it
    /// returns `Ok`, no child THIS process spawned is reading `name`, and none
    /// can start: a pass requires `current() == name` at the instant it is
    /// taken, and a name eligible for [`Generations::candidates`] is by
    /// construction never the current one.
    ///
    /// # Errors
    ///
    /// [`StillRead`] once `bound` has passed with the count still above zero.
    /// The caller's remedy is to skip this candidate for this tick — see
    /// [`crate::daemon::login::sweep`].
    pub fn drain(&self, name: &GenerationName, bound: Duration) -> Result<(), StillRead> {
        let until = Instant::now() + bound;
        let mut passes = self.lock();
        loop {
            if passes.get(name).copied().unwrap_or(0) == 0 {
                return Ok(());
            }
            let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                return Err(StillRead);
            };
            let (guard, timeout) = self
                .changed
                .wait_timeout(passes, remaining)
                .unwrap_or_else(PoisonError::into_inner);
            passes = guard;
            if timeout.timed_out() && passes.get(name).copied().unwrap_or(0) > 0 {
                return Err(StillRead);
            }
        }
    }

    /// Delete a candidate's directory. `NotFound` is success.
    ///
    /// Re-reads `current` under the lock immediately before deleting anything,
    /// and refuses when it names this candidate — the last guard between a
    /// retirement decided a moment ago and a generation that has, in the
    /// meantime, been published. Every other caller in this crate reaches this
    /// only through [`Generations::candidates`], which already excludes the
    /// current name; this check is what makes the exclusion true even under a
    /// race a test constructs by hand.
    ///
    /// # Errors
    ///
    /// The delete failed, or `candidate` names the generation `current` names
    /// right now.
    pub fn remove(&self, candidate: &Candidate) -> io::Result<()> {
        let passes = self.lock();
        if let Some(name) = &candidate.name
            && self.current().as_ref() == Ok(name)
        {
            drop(passes);
            return Err(io::Error::other(format!(
                "refusing to remove `{name}`: it is the current generation"
            )));
        }
        drop(passes);
        match fs::remove_dir_all(&candidate.delete) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Whether a retirement failure for `candidate` has already been reported
    /// by this process. Marks it reported on the first call.
    ///
    /// `true` the first time a given candidate fails, `false` on every call
    /// after that — so a caller that only prints on `true` reports each
    /// candidate's failure once per process rather than once per tick, while a
    /// candidate that starts failing again after a successful retirement
    /// (impossible for a generation, since a retired name is gone for good,
    /// but not impossible for the legacy candidate under a repeated fault) is
    /// a fresh label and reports again.
    pub(crate) fn mark_failure_reported(&self, candidate: &Candidate) -> bool {
        let mut reported = self
            .reported_failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        reported.insert(candidate.label())
    }
}

fn write_all_and_sync(mut file: &fs::File, body: &[u8]) -> io::Result<()> {
    file.write_all(body)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "keyless-proton-session-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn owner() -> (u32, u32) {
        let meta = fs::metadata(std::env::temp_dir()).expect("stat temp dir");
        use std::os::unix::fs::MetadataExt;
        (meta.uid(), meta.gid())
    }

    /// Write `<root>/current` directly, bypassing `publish`, so a test can
    /// hand-construct a pointer a healthy daemon would never write.
    fn write_current(root: &Path, contents: &str) {
        fs::write(root.join(CURRENT_FILE), contents).expect("write current");
    }

    #[test]
    fn a_generation_name_is_minted_from_the_clock_and_the_pid_and_parses_back() {
        let now = SystemTime::now();
        let name = GenerationName::mint(now, 4242);
        assert!(name.as_str().starts_with("gen-"), "{name}");
        assert!(name.as_str().ends_with("-4242"), "{name}");

        let parsed = GenerationName::parse(name.as_str()).expect("a minted name must parse");
        assert_eq!(parsed, name);

        let created = name.created_at().expect("a minted name has a clock");
        let drift = created
            .duration_since(now)
            .unwrap_or_else(|error| error.duration());
        assert!(
            drift < Duration::from_secs(1),
            "the round trip through milliseconds drifted by {drift:?}"
        );
    }

    #[test]
    fn a_current_file_holding_anything_but_a_generation_name_is_refused_before_it_is_joined_to_a_path()
     {
        for bad in [
            "",
            "\n",
            "../etc",
            "/tmp/x",
            "gen-1-2/../..",
            "gen-a-1",
            "gen-1-999999999999999999999999999999999999999999999999999999999999999",
            "gen-1-2\nmore",
        ] {
            assert!(
                GenerationName::parse(bad).is_none(),
                "`{bad}` parsed as a generation name"
            );
        }

        // The same refusal through the full file-reading path: every bad value
        // above degrades `current()` as `Malformed`, and the sentence never
        // quotes what was in the file.
        let dir = scratch("current-malformed");
        let generations = Generations::at(dir.clone());
        for bad in ["", "\n", "../etc", "gen-1-2/../..", "gen-a-1"] {
            write_current(&dir, bad);
            let fault = generations
                .current()
                .expect_err(&format!("`{bad:?}` must not name a live generation"));
            assert_eq!(fault, CurrentFault::Malformed, "for {bad:?}");
            assert!(
                !fault.to_string().contains(bad) || bad.is_empty(),
                "the malformed bytes reached the message: {fault}"
            );
        }

        // The control: a well-formed name with exactly one trailing newline —
        // the shape `publish` itself writes — parses, once its directory
        // exists.
        let (name, _) = generations.create(None).expect("create a generation");
        write_current(&dir, &format!("{name}\n"));
        assert_eq!(generations.current(), Ok(name));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pointer_naming_a_generation_that_is_not_there_is_a_fault_and_not_a_directory_for_the_vendor_to_create()
     {
        let dir = scratch("current-missing");
        let generations = Generations::at(dir.clone());
        let name = GenerationName::mint(SystemTime::now(), 1);
        write_current(&dir, &format!("{name}\n"));

        assert!(
            generations.enter().is_err(),
            "a pass was issued over a generation with no directory"
        );

        fs::create_dir(dir.join(name.as_str())).expect("mkdir");
        assert!(
            generations.enter().is_ok(),
            "the same name still refuses once its directory exists"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlink_where_a_generation_should_be_is_refused() {
        let dir = scratch("current-symlink");
        let target = scratch("current-symlink-target");
        let generations = Generations::at(dir.clone());
        let name = GenerationName::mint(SystemTime::now(), 1);
        write_current(&dir, &format!("{name}\n"));

        std::os::unix::fs::symlink(&target, dir.join(name.as_str())).expect("symlink");
        assert!(
            generations.enter().is_err(),
            "a pass was issued over a symlink standing in for a generation"
        );

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&target);
    }

    #[test]
    fn a_pass_names_the_generation_current_held_at_the_instant_it_was_issued() {
        let dir = scratch("pass-names-current");
        let generations = Generations::at(dir.clone());
        let (a, _) = generations.create(None).expect("create A");
        generations.publish(&a, None).expect("publish A");

        let pass_a = generations.enter().expect("a pass over A");
        assert_eq!(pass_a.dir(), dir.join(a.as_str()));

        let (b, _) = generations.create(None).expect("create B");
        generations.publish(&b, None).expect("publish B");

        assert_eq!(
            pass_a.dir(),
            dir.join(a.as_str()),
            "a pass already issued changed which generation it named"
        );
        let pass_b = generations.enter().expect("a pass over B");
        assert_eq!(pass_b.dir(), dir.join(b.as_str()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_retirement_candidate_is_never_the_current_generation_and_never_anything_that_is_not_one() {
        let dir = scratch("candidates-membership");
        let generations = Generations::at(dir.clone());
        let far_past = SystemTime::now() - Duration::from_secs(3600);
        let grace = Duration::from_secs(1);

        // Minted an hour in the past directly, rather than through `create`,
        // which always mints from the real clock — this membership test is not
        // about the grace window, and an hour is comfortably past it.
        let a = GenerationName::mint(far_past, 1001);
        let c = GenerationName::mint(far_past, 1002);
        fs::create_dir(dir.join(a.as_str())).expect("mkdir A");
        fs::create_dir(dir.join(c.as_str())).expect("mkdir C");
        let (b, _) = generations.create(None).expect("create B");
        generations.publish(&b, None).expect("publish B");
        fs::create_dir(dir.join(super::super::proton::SESSION_SUBDIR)).expect("legacy dir");
        fs::write(dir.join("current.new"), b"decoy").expect("decoy temp file");
        fs::write(dir.join("notes.txt"), b"decoy").expect("decoy plain file");
        // Back-date `current`'s mtime too, so the grace check's `max` of both
        // anchors does not itself exclude A and C from this membership test.
        let file = fs::File::options()
            .write(true)
            .open(dir.join(CURRENT_FILE))
            .expect("open current");
        file.set_modified(far_past).expect("set mtime");

        let names: std::collections::BTreeSet<String> = generations
            .candidates(SystemTime::now(), grace)
            .into_iter()
            .map(|candidate| candidate.label())
            .collect();
        assert!(names.contains(&a.to_string()), "{names:?}");
        assert!(names.contains(&c.to_string()), "{names:?}");
        assert!(
            !names.contains(&b.to_string()),
            "the current generation was a candidate"
        );
        assert!(names.contains("legacy"), "{names:?}");
        assert_eq!(names.len(), 3, "{names:?}");

        // With `current` absent or malformed, candidates is empty — retirement
        // is computed relative to a valid pointer or not at all.
        fs::remove_file(dir.join(CURRENT_FILE)).expect("remove current");
        assert!(generations.candidates(SystemTime::now(), grace).is_empty());
        write_current(&dir, "not-a-name");
        assert!(generations.candidates(SystemTime::now(), grace).is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_generation_younger_than_the_grace_is_not_a_candidate_yet() {
        let dir = scratch("candidates-grace");
        let generations = Generations::at(dir.clone());
        let grace = Duration::from_secs(2);

        let (current, _) = generations.create(None).expect("create current");
        generations
            .publish(&current, None)
            .expect("publish current");

        // A generation minted NOW: too young on both anchors.
        let (young, young_dir) = generations.create(None).expect("create young");
        let _ = young_dir;
        let candidates = generations.candidates(SystemTime::now(), grace);
        assert!(
            !candidates.iter().any(|c| c.name() == Some(&young)),
            "a generation minted moments ago was already a candidate"
        );

        // A generation minted an hour ago, with `current`'s own mtime pushed
        // back an hour too — both anchors are old enough, so this one IS
        // eligible.
        let old = GenerationName::mint(SystemTime::now() - Duration::from_secs(3600), 9999);
        fs::create_dir(dir.join(old.as_str())).expect("mkdir old");
        let file = fs::File::options()
            .write(true)
            .open(dir.join(CURRENT_FILE))
            .expect("open current");
        file.set_modified(SystemTime::now() - Duration::from_secs(3600))
            .expect("set mtime");

        let candidates = generations.candidates(SystemTime::now(), grace);
        assert!(
            candidates.iter().any(|c| c.name() == Some(&old)),
            "an hour-old generation, with current's mtime also an hour back, was not a \
             candidate: {candidates:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn drain_waits_for_the_passes_of_that_generation_and_not_for_the_current_one() {
        use std::sync::Arc;

        let dir = scratch("drain-selective");
        let generations = Arc::new(Generations::at(dir.clone()));
        // A is never entered or published in this test — only credited a pass
        // by hand below — so it need not be a real `create()`d directory, and
        // minting it directly sidesteps racing B for the same millisecond.
        let a = GenerationName::mint(SystemTime::now(), 1);
        let (b, _) = generations.create(None).expect("create B");
        generations.publish(&b, None).expect("publish B");

        // Holding a pass on B — the CURRENT generation — must never delay a
        // drain of A.
        let pass_b = generations.enter().expect("pass over B");
        assert_eq!(pass_b.dir(), dir.join(b.as_str()));
        assert!(
            generations.drain(&a, Duration::from_millis(200)).is_ok(),
            "drain(A) waited for a pass held on B"
        );
        drop(pass_b);

        // Manually crediting A with a pass — there is no live generation A to
        // `enter()` since it was never published — proves the other half:
        // drain(A) blocks while A's own count is nonzero.
        {
            let mut passes = generations.lock();
            passes.insert(a.clone(), 1);
        }
        let waiting = Arc::clone(&generations);
        let a_for_thread = a.clone();
        let drain = std::thread::spawn(move || {
            waiting
                .drain(&a_for_thread, Duration::from_secs(5))
                .map(drop)
                .is_ok()
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !drain.is_finished(),
            "drain(A) returned while A still held a pass"
        );

        {
            let mut passes = generations.lock();
            passes.insert(a.clone(), 0);
        }
        generations.changed.notify_all();
        assert!(
            drain.join().expect("the drain thread panicked"),
            "drain(A) did not return once A's count reached zero"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pass_dropped_by_an_unwinding_reader_still_releases_its_generation() {
        let dir = scratch("drain-unwind");
        let generations = Generations::at(dir.clone());
        let (a, _) = generations.create(None).expect("create A");
        generations.publish(&a, None).expect("publish A");

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _pass = generations.enter().expect("a pass over A");
            panic!("the reader blew up mid-call");
        }));
        assert!(panicked.is_err(), "the test's own panic did not happen");

        assert!(
            generations.drain(&a, Duration::from_millis(200)).is_ok(),
            "drain(A) timed out after the only pass on A was dropped by an unwind"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_writes_current_by_rename_at_0600_and_leaves_no_temporary_behind() {
        let dir = scratch("publish-atomic");
        let generations = Generations::at(dir.clone());
        let (name, _) = generations.create(Some(owner())).expect("create");
        generations.publish(&name, Some(owner())).expect("publish");

        let current_path = dir.join(CURRENT_FILE);
        let mode = fs::metadata(&current_path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, CURRENT_FILE_MODE, "written at {mode:04o}");
        assert_eq!(
            fs::read_to_string(&current_path).expect("read current"),
            format!("{name}\n")
        );
        assert!(
            !dir.join(CURRENT_TEMP_FILE).exists(),
            "the temporary file was left behind"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_refuses_to_delete_the_generation_current_names() {
        let dir = scratch("remove-refuses-current");
        let generations = Generations::at(dir.clone());
        let (name, generation_dir) = generations.create(None).expect("create");
        generations.publish(&name, None).expect("publish");

        let candidate = Candidate {
            name: Some(name.clone()),
            scope: generation_dir.clone(),
            delete: generation_dir.clone(),
        };
        assert!(
            generations.remove(&candidate).is_err(),
            "the current generation was removed"
        );
        assert!(
            generation_dir.is_dir(),
            "the current generation's directory is gone"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_a_generation_that_is_already_gone_is_a_success() {
        let dir = scratch("remove-already-gone");
        let generations = Generations::at(dir.clone());
        let missing = dir.join("gen-1-1");
        let candidate = Candidate {
            name: GenerationName::parse("gen-1-1"),
            scope: missing.clone(),
            delete: missing,
        };
        assert!(generations.remove(&candidate).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_store_with_no_generations_reads_its_configured_directory_directly() {
        // The session-side shape: no `Generations` behind the store at all, so
        // `enter()` at the `ProtonStore` level hands back a pass with no
        // generation attached. Exercised here at this module's own seam: a
        // `Pass` with `held: None` costs no lock and releases nothing on drop.
        let dir = PathBuf::from("/tmp/keyless-tests-no-generations");
        let pass = Pass {
            dir: dir.clone(),
            held: None,
        };
        assert_eq!(pass.dir(), dir);
        drop(pass); // must not panic, and there is nothing to notify
    }
}
