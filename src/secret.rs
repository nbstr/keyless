//! The plaintext newtype.
//!
//! Every property of this type exists to make an accidental disclosure fail to
//! compile rather than fail in production:
//!
//! - No `Display`. `format!("{secret}")` does not compile.
//! - `Debug` prints a fixed string, so `dbg!`, `{:?}` and a derived `Debug` on
//!   any struct holding one are all safe by construction.
//! - No `Serialize`. A secret cannot be written into the audit log or any other
//!   JSON by forgetting a field.
//! - The buffer scrubs itself on drop, so the plaintext does not linger in
//!   freed memory for the rest of the process's life. See *the scrub* below for
//!   exactly how far that reaches.
//! - The one accessor is called [`Secret::expose`], which is deliberately
//!   conspicuous: `grep -rn 'expose('` is the complete list of places the
//!   plaintext is readable, and that list is short enough to audit by eye.
//!
//! # The scrub, and its two edges
//!
//! The scrub is a property of the **field's type**, not of a `Drop` body written
//! here. [`zeroize::Zeroizing`] cannot be constructed without it, so there is no
//! hand-written destructor to delete, empty, or forget to keep in step with a
//! new field. Deleting the scrub means changing the declared type, which the
//! compile-time assertion below refuses.
//!
//! What that does **not** reach, stated rather than implied:
//!
//! - **A panic does not run it.** This crate's release profile sets `panic =
//!   "abort"`, deliberately — see the `Threads` variant in `store::exec`, which
//!   exists because of it. An abort runs no destructor at all. Nothing lingers
//!   in *freed* memory, because nothing is freed and the process ends; the
//!   residual exposure is a core dump written from a still-populated address
//!   space. `the_release_profile_aborts_rather_than_unwinding` pins that fact so
//!   the sentence above cannot go quietly out of date.
//! - **Copies this type never owned.** The pipe buffer a backend wrote through,
//!   the environment block `std::process::Command` builds, and the kernel's copy
//!   of it are not ours to scrub.
//! - **Reallocation slack.** A buffer that grows leaves its old contents behind
//!   at the old address. Every buffer built from a secret in this crate is
//!   allocated once at a sufficient capacity for exactly that reason.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// A resolved credential value.
pub struct Secret(Zeroizing<String>);

/// Compile-time proof that the field scrubs itself when it is dropped.
///
/// This binds to the **actual field**, so it is not a comment that can drift:
/// swapping `Zeroizing<String>` for a plain `String` stops the crate compiling
/// rather than stopping it scrubbing. `ZeroizeOnDrop` is implemented by
/// `zeroize` for types whose `Drop` zeroizes, and cannot be implemented here by
/// accident.
const _: fn(&Secret) = |secret| {
    fn scrubs_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>(_: &T) {}
    scrubs_on_drop(&secret.0);
};

impl Secret {
    /// Wrap a plaintext value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Secret(Zeroizing::new(value))
    }

    /// Build a secret from bytes, zeroizing the input buffer.
    ///
    /// Backends hand us bytes read from a pipe. Converting through this
    /// function means the intermediate buffer is scrubbed instead of being left
    /// on the heap, which is otherwise the easiest copy to forget.
    ///
    /// Returns `None` when the bytes are not UTF-8, because an environment
    /// variable value must be representable as one on every platform we target.
    #[must_use]
    pub fn from_bytes(mut bytes: Vec<u8>) -> Option<Self> {
        let secret = std::str::from_utf8(&bytes)
            .ok()
            .map(|s| Secret::new(s.to_owned()));
        bytes.zeroize();
        secret
    }

    /// Read the plaintext.
    ///
    /// Named to be found. Every call site is a place the value can leave the
    /// type, so the audit for "where can this escape?" is a search for this
    /// method rather than a reading of the whole crate.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Length in bytes. Safe to log: it is metadata, not content.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the stored value is empty.
    ///
    /// An empty secret is worth noticing — it usually means a store returned a
    /// blank item rather than an absent one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
pub(crate) mod scrub_probe {
    //! Watch one heap block at the instant it is released.
    //!
    //! The scrub is only worth anything if the buffer is clean *when the
    //! allocator gets it back*, and that instant is the hard part to observe.
    //! Reading the buffer after the drop reads freed memory, which is undefined
    //! behaviour and would make the test worse than none. Reading it before the
    //! drop proves nothing at all.
    //!
    //! So the observation happens **inside the global allocator**, in `dealloc`,
    //! before the block is handed on to the system allocator. At that point the
    //! block is still ours: it has been offered back and not yet released. Two
    //! further rules keep it sound:
    //!
    //! - Only the ONE address a test names is examined, never every block that
    //!   passes through. A content search over arbitrary blocks would read the
    //!   uninitialised spare capacity of other allocations.
    //! - Only the byte range the test proved was initialised is read. The test
    //!   hands over a live `&[u8]`, so its length is initialised by definition.
    //!
    //! The allocator itself is a pass-through and exists only under `cfg(test)`,
    //! so no shipped binary contains it. Its cost on every other test is one
    //! relaxed atomic load per deallocation.

    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The address under observation, or 0 for none.
    static WATCH_PTR: AtomicUsize = AtomicUsize::new(0);
    /// How many bytes of it the test proved were initialised.
    static WATCH_LEN: AtomicUsize = AtomicUsize::new(0);
    /// 0 never released, 1 released holding only zero bytes, 2 released dirty.
    static VERDICT: AtomicUsize = AtomicUsize::new(0);
    /// One observation at a time: the three statics above are process-wide and
    /// the test binary runs its tests on parallel threads.
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

    struct Watcher;

    // SAFETY: every method forwards to `System`, which is a correct allocator.
    // The added read touches `WATCH_LEN` bytes of a block that has been handed
    // to `dealloc` and not yet freed, and only when the caller named that exact
    // address while the owning value was alive.
    unsafe impl GlobalAlloc for Watcher {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if WATCH_PTR.load(Ordering::Acquire) == ptr as usize && !ptr.is_null() {
                let len = WATCH_LEN.load(Ordering::Acquire).min(layout.size());
                let mut dirty = false;
                for offset in 0..len {
                    // Volatile so the read cannot be reasoned away as dead: the
                    // whole question is what is physically in this buffer.
                    if unsafe { ptr.add(offset).read_volatile() } != 0 {
                        dirty = true;
                        break;
                    }
                }
                VERDICT.store(usize::from(dirty) + 1, Ordering::Release);
                // One shot. An address is reused the moment it is free, and a
                // stale watch would report on a stranger's block.
                WATCH_PTR.store(0, Ordering::Release);
            }
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static WATCHER: Watcher = Watcher;

    /// What the allocator saw.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum Released {
        /// The block reached the allocator holding nothing but zero bytes.
        Scrubbed,
        /// The block reached the allocator still holding data.
        Dirty,
        /// The block never reached the allocator, so nothing was observed. A
        /// failure, not a pass: an unreleased buffer is an unproven claim.
        Never,
    }

    /// Build a value, confirm the bytes it is supposed to scrub really are
    /// `expected`, drop it, and report the state of that buffer at release.
    ///
    /// `locate` names the heap bytes to watch. Asserting them against
    /// `expected` first is what stops the whole probe being vacuous: a `locate`
    /// that pointed somewhere harmless would otherwise report `Scrubbed` for a
    /// type that scrubs nothing.
    pub(crate) fn released_state<T>(
        build: impl FnOnce() -> T,
        locate: impl for<'a> Fn(&'a T) -> &'a [u8],
        expected: &[u8],
    ) -> Released {
        assert!(!expected.is_empty(), "an empty buffer proves nothing");
        let _serialised = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let value = build();
        let (address, length) = {
            let watched = locate(&value);
            assert_eq!(
                watched, expected,
                "the probe is watching a buffer that never held the value"
            );
            (watched.as_ptr() as usize, watched.len())
        };

        VERDICT.store(0, Ordering::Release);
        WATCH_LEN.store(length, Ordering::Release);
        WATCH_PTR.store(address, Ordering::Release);
        drop(value);
        let seen = VERDICT.load(Ordering::Acquire);
        WATCH_PTR.store(0, Ordering::Release);

        match seen {
            1 => Released::Scrubbed,
            2 => Released::Dirty,
            _ => Released::Never,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;
    use super::scrub_probe::{Released, released_state};

    /// The value is a decoy and is deliberately its own exact allocation:
    /// `str::to_owned` allocates capacity equal to the length, so every byte of
    /// the block the probe watches is initialised by this string.
    const PLAINTEXT: &str = "decoy-scrub-probe-value-0123456789";

    #[test]
    fn the_buffer_reaches_the_allocator_scrubbed() {
        // The guarantee the whole type exists for, checked where it is actually
        // decidable: at the moment the plaintext's heap block is released.
        let state = released_state(
            || Secret::new(PLAINTEXT.to_owned()),
            |secret| secret.expose().as_bytes(),
            PLAINTEXT.as_bytes(),
        );
        assert_eq!(state, Released::Scrubbed);
    }

    #[test]
    fn the_probe_reports_an_unscrubbed_buffer() {
        // The negative control, in-tree and permanent. Without it, a probe that
        // could never say `Dirty` would report success for every type forever.
        // A bare `String` is the exact thing `Secret` would decay into if the
        // zeroizing wrapper were dropped from the field.
        let state = released_state(
            || PLAINTEXT.to_owned(),
            |plain: &String| plain.as_bytes(),
            PLAINTEXT.as_bytes(),
        );
        assert_eq!(
            state,
            Released::Dirty,
            "a plain String must come back dirty, or the probe proves nothing"
        );
    }

    #[test]
    fn the_release_profile_aborts_rather_than_unwinding() {
        // `panic = "abort"` runs no destructor, so the scrub is not a guarantee
        // on the panic path. That is a deliberate choice — `store::exec` carries
        // a whole error variant because of it — and the module documentation
        // above states the limit. This pins the fact the documentation rests on:
        // flipping the profile makes that paragraph wrong, and this test is what
        // makes the reader notice.
        let manifest = include_str!("../Cargo.toml");
        let release = manifest
            .split("[profile.release]")
            .nth(1)
            .expect("the release profile is declared");
        assert!(
            release.contains("panic = \"abort\""),
            "the release profile no longer aborts; the scrub limit documented in \
             this module and in the README must be revisited"
        );
    }

    #[test]
    fn debug_never_prints_the_value() {
        let secret = Secret::new("hunter2-decoy-value".to_owned());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn debug_of_a_containing_struct_is_also_safe() {
        // The fields are read only through the derived `Debug`, which is
        // precisely what this test is about.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: &'static str,
            value: Secret,
        }
        let holder = Holder {
            name: "DECOY_TOKEN",
            value: Secret::new("decoy-abcdef0123456789".to_owned()),
        };
        let rendered = format!("{holder:?}");
        assert!(rendered.contains("DECOY_TOKEN"));
        assert!(!rendered.contains("abcdef0123456789"));
    }

    #[test]
    fn from_bytes_rejects_non_utf8() {
        assert!(Secret::from_bytes(vec![0xff, 0xfe, 0xfd]).is_none());
    }

    #[test]
    fn from_bytes_round_trips_utf8() {
        let secret = Secret::from_bytes(b"decoy-value-\xc3\xa9".to_vec());
        assert_eq!(
            secret.map(|s| s.expose().to_owned()),
            Some("decoy-value-é".to_owned())
        );
    }
}
