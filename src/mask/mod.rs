//! Streaming redaction of a child process's output.
//!
//! This is a **filter, not a control**. It defends against accident — a tool
//! that echoes its configuration, a stack trace carrying a connection string, a
//! `curl -v` printing a header. It does not defend against intent:
//! `keyless run -- sh -c 'echo $TOKEN | base64 | rev'` defeats it, and no
//! amount of pattern matching would change that. The threat model is a capable
//! agent taking the shortest path, not an adversary.
//!
//! # The carry
//!
//! A child writes when it wants to, not on token boundaries. A 40-character
//! token can arrive as `wri` + `te(2)` calls that split it anywhere, including
//! mid-UTF-8-sequence. So the writer holds bytes back until enough following
//! bytes have arrived to rule out a match. That is the entire trick, and it is
//! why [`MaskingWriter::flush`] deliberately does **not** flush the carry:
//! flushing it would emit the exact bytes the carry exists to hold.
//!
//! *How much* is held back is [`Masker::carry_point`], and it is content-aware
//! rather than a flat `N - 1` bytes. Bytes that cannot begin any needle are
//! released the moment they arrive. That matters far beyond throughput: on the
//! pty path the stream is a live terminal, and a flat withhold truncates the
//! tail of every prompt — `Password: ` arrives as `Passwo` and the session looks
//! hung. The guarantee is unchanged; only the pessimism is gone.

pub mod encodings;

use std::io::{self, ErrorKind, Read, Write};
use std::sync::Arc;

use zeroize::{Zeroize, Zeroizing};

use crate::secret::Secret;

/// Needles shorter than this are dropped.
///
/// A three-byte secret produces three-byte needles that match constantly, which
/// turns the output into noise and teaches the reader to ignore the mask token.
/// A secret that short is not a secret.
pub const MIN_NEEDLE_LEN: usize = 4;

struct Needle {
    /// A needle is a *derived* form of the plaintext and just as sensitive, so
    /// the buffer scrubs itself when it is dropped.
    ///
    /// The scrub lives in the **type**, not in a `Drop` body written here. A
    /// hand-written destructor is one edit away from being emptied, and nothing
    /// in a test suite notices an empty destructor — the observable behaviour of
    /// this struct is identical either way. Declaring the field as a type that
    /// cannot exist without the scrub moves the guarantee somewhere an edit to
    /// this file cannot reach.
    bytes: Zeroizing<Vec<u8>>,
    /// Pre-rendered `[keyless:NAME]`, shared between the needles of one secret.
    replacement: Arc<str>,
}

/// Compile-time proof of the paragraph above, bound to the actual field.
const _: fn(&Needle) = |needle| {
    fn scrubs_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>(_: &T) {}
    scrubs_on_drop(&needle.bytes);
};

/// A compiled set of byte patterns to redact.
///
/// Deliberately has no `Debug`: it holds encoded copies of every secret.
#[derive(Default)]
pub struct Masker {
    needles: Vec<Needle>,
    /// Bucketed by first byte so a scan touches only plausible needles.
    ///
    /// The order **within** a bucket carries no meaning. It used to: the bucket
    /// was sorted longest-first and [`Masker::match_at`] took the first hit, so
    /// the sort was the only thing making the longest match win. See that
    /// method for why an invariant spread across two functions was the wrong
    /// place to keep it.
    buckets: Vec<Vec<usize>>,
    max_len: usize,
}

impl Masker {
    /// An empty masker. Scanning through it is an identity transform.
    #[must_use]
    pub fn new() -> Self {
        Masker {
            needles: Vec::new(),
            buckets: Vec::new(),
            max_len: 0,
        }
    }

    /// Compile every encoding of every named secret into one needle set.
    #[must_use]
    pub fn from_secrets<'a, I>(items: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a Secret)>,
    {
        let mut masker = Masker::new();
        for (name, secret) in items {
            masker.add(name, secret);
        }
        masker.finish_build();
        masker
    }

    /// Add one secret's variants. Call [`Masker::finish_build`] afterwards.
    ///
    /// A value shorter than [`MIN_NEEDLE_LEN`] contributes nothing at all, not
    /// even through its encodings. Base64 of three bytes is four characters,
    /// which would pass a per-needle length filter while being exactly as
    /// collision-prone as the three raw bytes were — the filter has to apply to
    /// the secret, not only to the strings derived from it.
    pub fn add(&mut self, name: &str, secret: &Secret) {
        if secret.len() < MIN_NEEDLE_LEN {
            return;
        }
        let replacement: Arc<str> = Arc::from(format!("[{}:{}]", crate::NAME, name).as_str());
        for (_, rendered) in encodings::variants(secret.expose()) {
            // Both rejections are decided on the rendering, which scrubs itself
            // when this iteration ends. Copying first and rejecting afterwards
            // left a plain `Vec<u8>` holding a derived form of the plaintext to
            // be freed unscrubbed, once per rejected variant.
            let candidate: &[u8] = rendered.as_bytes();
            if candidate.len() < MIN_NEEDLE_LEN {
                continue;
            }
            if self.needles.iter().any(|n| n.bytes.as_slice() == candidate) {
                continue;
            }
            self.max_len = self.max_len.max(candidate.len());
            self.needles.push(Needle {
                bytes: Zeroizing::new(candidate.to_vec()),
                replacement: Arc::clone(&replacement),
            });
        }
    }

    /// Build the first-byte index. Idempotent.
    ///
    /// A bucket is a *set*. Nothing downstream reads the order of one, so there
    /// is no order to establish here and none to get wrong.
    pub fn finish_build(&mut self) {
        let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); 256];
        for (index, needle) in self.needles.iter().enumerate() {
            if let Some(&first) = needle.bytes.first() {
                buckets[usize::from(first)].push(index);
            }
        }
        self.buckets = buckets;
    }

    /// Whether there is anything to redact.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.needles.is_empty()
    }

    /// Number of compiled needles. Metadata only — safe to print.
    #[must_use]
    pub fn len(&self) -> usize {
        self.needles.len()
    }

    /// Length of the longest needle, which is how much the writer must hold back.
    #[must_use]
    pub fn max_needle_len(&self) -> usize {
        self.max_len
    }

    /// How many leading bytes of `buf` it is safe to emit mid-stream.
    ///
    /// The blunt answer is `buf.len() - (max_needle_len - 1)`: hold back a whole
    /// needle's worth, because a needle *could* start anywhere in that tail.
    /// That is safe and it is what this used to do. It is also wrong for a live
    /// terminal — it truncates the tail of every write, so a child that prints
    /// `Password: ` and blocks on input leaves the user staring at `Passwo`
    /// with no cursor. On the pty path that is the difference between a usable
    /// tool and an unusable one.
    ///
    /// The precise answer costs nothing in safety: hold back from the FIRST
    /// tail position that could still *grow* into a needle, and release
    /// everything before it. A position that no needle can begin at carries no
    /// risk, so withholding it buys nothing.
    ///
    /// This never releases a byte that could yet be part of a match, which is
    /// the whole guarantee. The split-at-every-position, split-in-three,
    /// byte-at-a-time and split-mid-rune tests are unchanged and are the proof.
    #[must_use]
    pub fn carry_point(&self, buf: &[u8]) -> usize {
        let tail_start = buf.len().saturating_sub(self.max_len.saturating_sub(1));
        (tail_start..buf.len())
            .find(|&at| self.could_grow_into_a_needle(&buf[at..]))
            .unwrap_or(buf.len())
    }

    /// Whether more bytes could turn `tail` into a match.
    ///
    /// True only for a *proper* prefix. A tail that is already a complete needle
    /// and is a prefix of nothing longer needs no carry at all: [`Masker::scan`]
    /// replaces it on this very pass.
    fn could_grow_into_a_needle(&self, tail: &[u8]) -> bool {
        let Some(&first) = tail.first() else {
            return false;
        };
        let Some(bucket) = self.buckets.get(usize::from(first)) else {
            return false;
        };
        bucket.iter().copied().any(|index| {
            let needle = &self.needles[index].bytes;
            needle.len() > tail.len() && needle.starts_with(tail)
        })
    }

    /// The needle to replace at `at`: the **longest** one that matches there.
    ///
    /// Longest wins, or a `0x`-prefixed hex value is masked leaving its `0x`
    /// behind, and — far worse — a declared value that is a prefix of another
    /// declared value swallows only the prefix and prints the remainder of the
    /// longer secret in clear.
    ///
    /// That rule is enforced *here*, by asking for the longest match. It used to
    /// live in [`Masker::finish_build`], as a sort that put the longest needle
    /// first so that taking the first hit happened to take the longest one. An
    /// invariant held jointly by a sort in one function and an iterator adaptor
    /// in another is an invariant nothing owns: reversing that sort left the
    /// whole suite green and made the binary leak. Order-independence is not a
    /// tidier way to state the same guarantee — it deletes the way to break it.
    ///
    /// There is no tie to break. [`Masker::add`] drops a needle whose bytes are
    /// already present, so two needles of equal length cannot both match at one
    /// position: matching there with the same length means being the same bytes.
    fn match_at(&self, buf: &[u8], at: usize) -> Option<usize> {
        let first = *buf.get(at)?;
        let bucket = self.buckets.get(usize::from(first))?;
        bucket
            .iter()
            .copied()
            .filter(|&index| buf[at..].starts_with(&self.needles[index].bytes))
            .max_by_key(|&index| self.needles[index].bytes.len())
    }

    /// Redact `buf`, emitting only the bytes it is safe to release.
    ///
    /// Returns the redacted output and the number of input bytes consumed.
    /// Anything after `consumed` must be carried into the next call, because a
    /// needle could still begin inside it.
    ///
    /// `emit_limit` is the highest start position the scan may consider. The
    /// caller sets it to `buf.len() - (max_needle_len - 1)` mid-stream, which
    /// guarantees every position examined has a full needle's worth of bytes
    /// after it, and to `buf.len()` at end of stream.
    #[must_use]
    pub fn scan(&self, buf: &[u8], emit_limit: usize) -> (Vec<u8>, usize) {
        let limit = emit_limit.min(buf.len());
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        while i < limit {
            if let Some(index) = self.match_at(buf, i) {
                out.extend_from_slice(self.needles[index].replacement.as_bytes());
                i += self.needles[index].bytes.len();
            } else {
                out.push(buf[i]);
                i += 1;
            }
        }
        (out, i.min(buf.len()))
    }

    /// Redact a complete buffer in one shot. For text that is already whole,
    /// such as an argv element on its way into the audit log.
    #[must_use]
    pub fn mask_bytes(&self, buf: &[u8]) -> Vec<u8> {
        let (out, _) = self.scan(buf, buf.len());
        out
    }

    /// Redact a complete string.
    ///
    /// UTF-8 validity survives: every needle is itself valid UTF-8 and UTF-8 is
    /// self-synchronising, so a byte-level match inside valid UTF-8 always
    /// begins and ends on a character boundary.
    #[must_use]
    pub fn mask_str(&self, input: &str) -> String {
        String::from_utf8_lossy(&self.mask_bytes(input.as_bytes())).into_owned()
    }
}

/// A `Write` that redacts on the way through, holding back a suffix so a value
/// split across writes is still caught.
pub struct MaskingWriter<W: Write> {
    masker: Arc<Masker>,
    carry: Vec<u8>,
    inner: W,
}

impl<W: Write> MaskingWriter<W> {
    /// Wrap `inner`.
    pub fn new(masker: Arc<Masker>, inner: W) -> Self {
        MaskingWriter {
            masker,
            carry: Vec::new(),
            inner,
        }
    }

    /// Release the carry and flush.
    ///
    /// This is the terminal operation. Until it is called, up to
    /// `max_needle_len - 1` bytes of the stream have not been written. Failing
    /// to call it truncates the output — which is why the child pump owns a
    /// writer for the whole of its life and calls this on EOF.
    pub fn finish(&mut self) -> io::Result<()> {
        self.push(&[], true)?;
        self.inner.flush()
    }

    fn push(&mut self, chunk: &[u8], end_of_stream: bool) -> io::Result<()> {
        self.carry.extend_from_slice(chunk);
        let mut buf = std::mem::take(&mut self.carry);
        let masker = Arc::clone(&self.masker);
        let emit_limit = if end_of_stream {
            buf.len()
        } else {
            masker.carry_point(&buf)
        };
        let (out, consumed) = masker.scan(&buf, emit_limit);
        self.carry = buf[consumed..].to_vec();
        buf.zeroize();
        self.inner.write_all(&out)
    }
}

impl<W: Write> Write for MaskingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.push(buf, false)?;
        Ok(buf.len())
    }

    /// Flushes the inner writer only.
    ///
    /// The carry is intentionally not released here. `flush` is called by
    /// generic code at arbitrary moments, and a flush that emitted the carry
    /// would defeat the split-write protection at exactly the moments it
    /// matters. Use [`MaskingWriter::finish`] to end the stream.
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Drop for MaskingWriter<W> {
    fn drop(&mut self) {
        self.carry.zeroize();
    }
}

/// Copy one stream through the masker until it ends.
///
/// Lives here rather than beside its caller because there are now two callers:
/// the pipe path reads two streams (the child's stdout and its stderr) and the
/// pty path reads the one merged stream a terminal provides. Both need
/// identical carry behaviour, and the only way to guarantee "identical" is for
/// there to be one copy of it.
pub fn pump<R: Read, W: Write>(mut reader: R, writer: W, masker: Arc<Masker>) -> io::Result<()> {
    let mut writer = MaskingWriter::new(masker, writer);
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => {
                writer.write_all(&buf[..read])?;
                // Flush the inner writer so output stays prompt. The carry is
                // deliberately untouched by this.
                writer.flush()?;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            // A pty master reports the death of the last slave as EIO rather
            // than as end-of-file, and does so on Linux while macOS returns 0
            // for the same event. Both mean the same thing — nothing will ever
            // be readable again — so both end the stream. On a pipe EIO is
            // equally terminal, so this costs the pipe path nothing.
            Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => break,
            Err(error) => {
                buf.zeroize();
                return Err(error);
            }
        }
    }
    buf.zeroize();
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::{Masker, MaskingWriter};
    use crate::secret::Secret;
    use std::io::Write;
    use std::sync::Arc;

    fn masker_for(value: &str) -> Arc<Masker> {
        let secret = Secret::new(value.to_owned());
        Arc::new(Masker::from_secrets([("DECOY", &secret)]))
    }

    fn stream(masker: &Arc<Masker>, chunks: &[&[u8]]) -> String {
        let mut sink: Vec<u8> = Vec::new();
        {
            let mut writer = MaskingWriter::new(Arc::clone(masker), &mut sink);
            for chunk in chunks {
                writer.write_all(chunk).expect("write to a Vec cannot fail");
            }
            writer.finish().expect("finish on a Vec cannot fail");
        }
        String::from_utf8(sink).expect("output stays valid utf-8")
    }

    #[test]
    fn a_short_secret_produces_no_needles() {
        let masker = masker_for("abc");
        assert!(masker.is_empty(), "3-byte values must not become needles");
    }

    #[test]
    fn the_0x_prefixed_hex_form_is_a_needle_of_its_own() {
        // The `0x` disappears because the prefixed form is compiled as a whole
        // needle, not because anything chose between two candidates: `0x…` and
        // the raw value begin with different bytes, so they are indexed under
        // different first bytes and never compete. This test was once named for
        // the longest-match rule and could not exercise it; the rule is checked
        // by the test below, where the two forms DO compete.
        let masker = masker_for("decoy-value-1234");
        let hex = super::encodings::Encoding::HexPrefixedLower.encode("decoy-value-1234");
        let masked = stream(&masker, &[hex.as_bytes()]);
        assert_eq!(masked, "[keyless:DECOY]");
    }

    #[test]
    fn one_secret_being_a_prefix_of_another_does_not_leak_the_remainder() {
        // The failure this guards is total, not cosmetic: choose the SHORTER of
        // two competing needles and the tail of the longer secret is printed in
        // clear, with a mask token in front of it making the line look handled.
        const SHORT: &str = "decoy-prefix-collision-11111";
        const LONG: &str = "decoy-prefix-collision-11111-and-the-tail-in-clear";

        // The fixture, asserted rather than assumed. Both conditions are needed
        // for the two needles to compete at one position, and a fixture that
        // quietly stopped meeting them would leave a test that passes for no
        // reason — which is exactly how this rule went unguarded.
        assert!(LONG.starts_with(SHORT), "one must be a prefix of the other");
        assert_eq!(
            SHORT.as_bytes()[0],
            LONG.as_bytes()[0],
            "sharing a first byte is what puts them in one bucket"
        );

        let short = Secret::new(SHORT.to_owned());
        let long = Secret::new(LONG.to_owned());
        let masker = Arc::new(Masker::from_secrets([("SHORT", &short), ("LONG", &long)]));

        let masked = stream(&masker, &[format!("token={LONG} end").as_bytes()]);
        assert_eq!(masked, "token=[keyless:LONG] end");
        assert!(
            !masked.contains("-and-the-tail-in-clear"),
            "the longer secret's tail survived masking: {masked:?}"
        );
    }

    #[test]
    fn pump_releases_the_carry_at_the_end_of_the_stream() {
        // A child's last bytes live in the carry until something declares the
        // stream over. `pump` owns that declaration, and dropping it truncates
        // the output silently — no error, no short write, just missing text.
        let value = "decoy-pump-finish-value-13579";
        let masker = masker_for(value);
        let tail = &value[..12];
        let source = format!("a={value} tail={tail}");

        // Not vacuous: while the stream is open those trailing bytes are still
        // withheld, because they could yet grow into a match. So they can only
        // appear below if the end of the stream was actually announced.
        assert_eq!(
            seen_so_far(&masker, &[source.as_bytes()]),
            "a=[keyless:DECOY] tail="
        );

        let mut sink: Vec<u8> = Vec::new();
        super::pump(source.as_bytes(), &mut sink, Arc::clone(&masker))
            .expect("pump over a Vec cannot fail");
        assert_eq!(
            String::from_utf8_lossy(&sink),
            format!("a=[keyless:DECOY] tail={tail}")
        );
    }

    #[test]
    fn a_needle_buffer_reaches_the_allocator_scrubbed() {
        // A needle holds a derived form of the plaintext for as long as the
        // masker lives. This watches the raw form's buffer at the one instant
        // the guarantee is decidable — see `secret::scrub_probe`.
        const PLAINTEXT: &str = "decoy-needle-scrub-value-2468";
        let state = crate::secret::scrub_probe::released_state(
            || {
                let secret = Secret::new(PLAINTEXT.to_owned());
                Masker::from_secrets([("DECOY", &secret)])
            },
            |masker: &Masker| {
                masker
                    .needles
                    .iter()
                    .find(|needle| needle.bytes.as_slice() == PLAINTEXT.as_bytes())
                    .expect("the raw form is always compiled as a needle")
                    .bytes
                    .as_slice()
            },
            PLAINTEXT.as_bytes(),
        );
        assert_eq!(state, crate::secret::scrub_probe::Released::Scrubbed);
    }

    #[test]
    fn split_at_every_position_is_still_caught() {
        let value = "decoy-splittable-value-9876543210";
        let masker = masker_for(value);
        let line = format!("before {value} after");
        for split in 0..line.len() {
            let (head, tail) = line.split_at(split);
            let masked = stream(&masker, &[head.as_bytes(), tail.as_bytes()]);
            assert!(
                !masked.contains(value),
                "leaked when split at byte {split}: {masked:?}"
            );
            assert_eq!(masked, "before [keyless:DECOY] after", "split at {split}");
        }
    }

    #[test]
    fn split_into_three_pieces_is_still_caught() {
        let value = "decoy-triple-split-abcdef123456";
        let masker = masker_for(value);
        let line = format!("x{value}y");
        for first in 0..line.len() {
            for second in first..line.len() {
                let masked = stream(
                    &masker,
                    &[
                        &line.as_bytes()[..first],
                        &line.as_bytes()[first..second],
                        &line.as_bytes()[second..],
                    ],
                );
                assert!(
                    !masked.contains(value),
                    "leaked when split at {first}/{second}"
                );
            }
        }
    }

    #[test]
    fn byte_at_a_time_is_still_caught() {
        let value = "decoy-one-byte-at-a-time-00112233";
        let masker = masker_for(value);
        let line = format!("[{value}]");
        let chunks: Vec<&[u8]> = line.as_bytes().chunks(1).collect();
        let masked = stream(&masker, &chunks);
        assert_eq!(masked, "[[keyless:DECOY]]");
    }

    #[test]
    fn a_multibyte_character_split_mid_sequence_is_still_caught() {
        let value = "decoy-café-über-naïve-secret";
        let masker = masker_for(value);
        let line = format!("log: {value}!");
        // Split inside the two-byte é (its first byte is at index 11 of `value`,
        // so 16 of `line`); a naive line-oriented matcher loses it here.
        for split in 0..line.len() {
            let masked = stream(
                &masker,
                &[&line.as_bytes()[..split], &line.as_bytes()[split..]],
            );
            assert!(!masked.contains(value), "leaked at split {split}");
        }
    }

    #[test]
    fn nothing_is_withheld_forever() {
        let masker = masker_for("decoy-value-that-never-appears-here");
        let masked = stream(&masker, &[b"hello ", b"world"]);
        assert_eq!(masked, "hello world");
    }

    #[test]
    fn flush_does_not_release_the_carry() {
        // This is the property that makes the split-write defence work. If a
        // future refactor makes `flush` drain the carry, this test fails.
        let value = "decoy-carry-must-survive-flush-01";
        let masker = masker_for(value);
        let mut sink: Vec<u8> = Vec::new();
        {
            let mut writer = MaskingWriter::new(Arc::clone(&masker), &mut sink);
            let bytes = value.as_bytes();
            writer.write_all(&bytes[..5]).expect("write");
            writer.flush().expect("flush");
            writer.write_all(&bytes[5..]).expect("write");
            writer.finish().expect("finish");
        }
        assert_eq!(String::from_utf8_lossy(&sink), "[keyless:DECOY]");
    }

    /// Everything written so far, without ending the stream.
    ///
    /// This is what a terminal has actually displayed mid-run — the distinction
    /// `finish()` erases, and the one the pty path lives or dies by.
    fn seen_so_far(masker: &Arc<Masker>, chunks: &[&[u8]]) -> String {
        let mut sink: Vec<u8> = Vec::new();
        {
            let mut writer = MaskingWriter::new(Arc::clone(masker), &mut sink);
            for chunk in chunks {
                writer.write_all(chunk).expect("write to a Vec cannot fail");
            }
            writer.flush().expect("flush to a Vec cannot fail");
        }
        String::from_utf8_lossy(&sink).into_owned()
    }

    #[test]
    fn text_that_cannot_begin_a_secret_is_released_immediately() {
        // The property the pty path depends on. A child that prints a prompt and
        // blocks on input must have that prompt on screen, whole, before its
        // next write — which may never come. Holding back a flat `N - 1` bytes
        // would show the user `Passwo` and a cursor that never moves.
        let masker = masker_for("decoy-prompt-latency-value-4242");
        assert_eq!(seen_so_far(&masker, &[b"Password: "]), "Password: ");
    }

    #[test]
    fn a_tail_that_could_still_become_a_secret_is_withheld() {
        // The other side of the same rule, and the reason it is safe. Bytes that
        // could yet grow into a match stay in the carry no matter how long the
        // child pauses.
        let masker = masker_for("decoy-partial-prefix-value-7777");
        assert_eq!(seen_so_far(&masker, &[b"token: decoy-partial"]), "token: ");
    }

    #[test]
    fn the_carry_point_is_never_beyond_what_is_provably_safe() {
        // A direct check on the rule itself rather than on its effect: for every
        // prefix of a line containing the value, nothing released mid-stream may
        // be a position from which the value could still start.
        let value = "decoy-carry-point-invariant-31337";
        let masker = masker_for(value);
        let line = format!("prefix {value} suffix");
        for length in 0..=line.len() {
            let buf = &line.as_bytes()[..length];
            let point = masker.carry_point(buf);
            assert!(point <= buf.len());
            for at in point..buf.len() {
                // Everything held back must be held back for a reason: some
                // position at or after the carry point begins a possible match.
                let held = &buf[at..];
                if masker.could_grow_into_a_needle(held) {
                    assert_eq!(at, point, "the carry started later than it had to");
                    break;
                }
            }
        }
    }

    #[test]
    fn two_secrets_are_masked_with_their_own_names() {
        let one = Secret::new("decoy-first-value-aaaa".to_owned());
        let two = Secret::new("decoy-second-value-bbbb".to_owned());
        let masker = Arc::new(Masker::from_secrets([("FIRST", &one), ("SECOND", &two)]));
        let masked = stream(
            &masker,
            &[b"a=decoy-first-value-aaaa b=decoy-second-value-bbbb"],
        );
        assert_eq!(masked, "a=[keyless:FIRST] b=[keyless:SECOND]");
    }

    #[test]
    fn mask_str_handles_argv_shaped_input() {
        let masker = masker_for("decoy-argv-value-4321");
        assert_eq!(
            masker.mask_str("--token=decoy-argv-value-4321"),
            "--token=[keyless:DECOY]"
        );
    }
}
