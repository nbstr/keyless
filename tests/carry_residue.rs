//! The carry must not leave copies of itself in freed heap.
//!
//! `MaskingWriter` holds back the tail of the child's output so a secret split
//! across two writes is still caught. That held-back buffer — the carry — is
//! therefore the one place in this tool where the leading bytes of a secret sit
//! in plaintext for longer than a single call. It is declared as a type that
//! scrubs itself when it drops, and that is necessary but it is not sufficient.
//!
//! A scrub reaches the allocation the buffer is *holding*. It cannot reach one
//! the buffer has already abandoned. Growing a `Vec` allocates a bigger block,
//! copies the bytes across, and frees the old block untouched, so a carry that
//! is grown once per write leaves one verbatim copy of itself behind per write —
//! up to a full needle's worth of secret, in memory the process has handed back
//! to the allocator and will hand out again. zeroize documents this limit on its
//! own `Vec` impl: it "cannot ensure that previous reallocations did not leave
//! values on the heap".
//!
//! Nothing about the tool's output changes when that happens, which is exactly
//! why this file exists and why it is an allocator rather than an assertion
//! about bytes written. Every mask test in the suite passed while the leak was
//! there, and would pass again if the fix were reverted.
//!
//! # How the watch is defined behaviour rather than a lucky read
//!
//! Reading a freed block means reading memory whose initialisation this file
//! does not control, and reading uninitialised memory is undefined. So the
//! allocator below zero-fills every block it hands out, through `alloc_zeroed`,
//! including the ones requested through plain `alloc`. Every byte of every block
//! is then initialised from the moment it exists, and the read at `dealloc` is
//! defined for the whole layout.
//!
//! `realloc` is deliberately **not** forwarded to the system's. The default
//! `GlobalAlloc::realloc` is written in terms of `self.alloc`, a copy, and
//! `self.dealloc`, so leaving it alone is what routes a `Vec`'s growth through
//! the watch. Forwarding it to `System` would let the old block be freed by code
//! this file cannot see, and the leak would become invisible again — the check
//! would go green by looking away.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use keyless::mask::{Masker, MaskingWriter};
use keyless::secret::Secret;

/// The decoy the writer is driven with.
///
/// Long enough that the carry can hold [`MARK`] whole, and made only of bytes
/// that appear in no other allocation in this binary.
const VALUE: &str = "decoy-carry-residue-marker-9c4f1ab2e7";

/// The fragment hunted for in freed memory.
///
/// A prefix of [`VALUE`] rather than the whole of it, because the carry holds a
/// PREFIX: the bytes that arrived before the write boundary. Demanding the whole
/// value would be a check that could only ever pass.
const MARK: &[u8] = b"decoy-carry-residue-marker";

/// Set while a block that is being freed is worth reading.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Set when a freed block still held [`MARK`].
static RESIDUE: AtomicBool = AtomicBool::new(false);

/// How many blocks the watch actually read.
///
/// Without this a watch that never ran and a watch that ran and found nothing
/// are the same green. Every case below asserts it moved.
static INSPECTED: AtomicUsize = AtomicUsize::new(0);

/// Serialises the armed windows, because the harness runs these cases in
/// parallel threads and the flags above are process-wide.
static WATCH: Mutex<()> = Mutex::new(());

struct Watch;

#[global_allocator]
static ALLOCATOR: Watch = Watch;

// SAFETY: every method forwards to `System`, which is a correct global
// allocator, and adds only reads of memory this allocator itself initialised.
unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Zeroed even here, so that a block read at `dealloc` is initialised no
        // matter which entry point produced it.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) && layout.size() >= MARK.len() {
            // SAFETY: the block is live until the forward below, and every byte
            // of it was initialised by `alloc_zeroed` above.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            INSPECTED.fetch_add(1, Ordering::Relaxed);
            if block.windows(MARK.len()).any(|window| window == MARK) {
                RESIDUE.store(true, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Run `body` with the watch armed. Returns whether a freed block held [`MARK`],
/// and how many blocks were read.
fn watched(body: impl FnOnce()) -> (bool, usize) {
    let _guard = WATCH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    RESIDUE.store(false, Ordering::Relaxed);
    INSPECTED.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    body();
    ARMED.store(false, Ordering::Relaxed);
    (
        RESIDUE.load(Ordering::Relaxed),
        INSPECTED.load(Ordering::Relaxed),
    )
}

fn masker() -> Arc<Masker> {
    let secret = Secret::new(VALUE.to_owned());
    Arc::new(Masker::from_secrets([("DECOY", &secret)]))
}

/// Feed the decoy one byte at a time, which is the worst case for the carry: it
/// grows by one byte per write and every byte of it is a secret byte.
fn drive_one_byte_at_a_time(masker: Arc<Masker>) -> Vec<u8> {
    let mut sink: Vec<u8> = Vec::new();
    {
        let mut writer = MaskingWriter::new(masker, &mut sink);
        for byte in VALUE.as_bytes() {
            writer
                .write_all(&[*byte])
                .expect("a write to a Vec cannot fail");
        }
        writer.finish().expect("finish on a Vec cannot fail");
    }
    sink
}

#[test]
fn no_freed_block_still_holds_the_carry() {
    // The masker is built BEFORE the window opens. Compiling a secret into
    // needles allocates and frees its own derived copies, and those frees are a
    // different question from this one.
    let masker = masker();
    let mut output = Vec::new();

    let (residue, inspected) = watched(|| {
        output = drive_one_byte_at_a_time(Arc::clone(&masker));
    });

    // Prove the drive actually happened before believing anything about the
    // heap. A writer that wrote nothing frees nothing and reads clean.
    let rendered = String::from_utf8(output).expect("the output stays valid utf-8");
    assert_eq!(
        rendered, "[keyless:DECOY]",
        "the decoy was not masked, so this case never exercised the carry"
    );
    assert!(
        inspected > 0,
        "the watch read no block at all, so its verdict is about nothing"
    );

    assert!(
        !residue,
        "a block was freed still holding {} bytes of the decoy. The carry was \
         grown rather than rebuilt, so it abandoned an unscrubbed copy of \
         itself: see `Sealed` in src/mask/mod.rs.",
        MARK.len()
    );
}

#[test]
fn the_watch_sees_a_carry_that_was_grown_instead_of_rebuilt() {
    // The negative control, and the reason the case above is not vacuous. This
    // reproduces the shape `MaskingWriter::push` had — append the new chunk to
    // the buffer, then rebuild it at exactly its own length — over the same
    // decoy, and requires the watch to notice.
    //
    // Scrubbing the buffer at the end changes nothing, which is the whole
    // point: a scrub reaches the block still held, never the ones already
    // abandoned.
    let (residue, inspected) = watched(|| {
        let mut grown: Vec<u8> = Vec::new();
        for byte in VALUE.as_bytes() {
            grown.extend_from_slice(&[*byte]);
            grown = grown.as_slice().to_vec();
        }
        zeroize::Zeroize::zeroize(&mut grown);
        drop(grown);
    });

    assert!(
        inspected > 0,
        "the watch read no block at all, so it cannot have seen anything"
    );
    assert!(
        residue,
        "the watch did not see a leak that is planted in front of it. It is \
         reading the wrong memory, or it is not being reached at all, and the \
         case above is passing for no reason."
    );
}

#[test]
fn the_watch_is_silent_when_nothing_is_freed_with_the_mark_in_it() {
    // The other half of the control. A detector that fires on everything is as
    // useless as one that fires on nothing, and both look identical from the
    // green case alone.
    let (residue, inspected) = watched(|| {
        let mut plain: Vec<u8> = Vec::new();
        for _ in 0..VALUE.len() {
            plain.extend_from_slice(b"-");
            plain = plain.as_slice().to_vec();
        }
        drop(plain);
    });

    assert!(
        inspected > 0,
        "the watch read no block, so this case proves nothing about silence"
    );
    assert!(
        !residue,
        "the watch fired on a buffer that never held the decoy"
    );
}
