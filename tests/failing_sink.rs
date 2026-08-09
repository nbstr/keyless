//! What a `MaskingWriter` does when the sink underneath it refuses.
//!
//! Every `MaskingWriter` in this suite wraps a `Vec`, and a `Vec` cannot fail.
//! So `push`'s error path had never been executed by any test, and the question
//! this file exists to settle had never been asked: when the write fails, does
//! anything of the secret escape, and what is lost?
//!
//! The instrument is a sink that refuses on demand. It is the missing piece,
//! and it is deliberately more than this one question needs — it can refuse on
//! any call, and it can accept some bytes before refusing, because a partial
//! write followed by an error is the shape that loses data most quietly.
//!
//! # What the answer turns out to be
//!
//! Nothing of the secret escapes, and the bytes that are lost are the MASKED
//! output of the region already scanned. The carry keeps exactly the bytes that
//! were not emitted, so it is coherent afterwards and a sink that recovers picks
//! up where it left off.
//!
//! That is a property of the ORDER `push` writes in, and the order is not
//! interchangeable. `push` assigns the carry and then writes:
//!
//! ```text
//! self.carry = Sealed::holding(&buf[consumed..]);   // the tail NOT emitted
//! self.inner.write_all(&out)                        // the masked head
//! ```
//!
//! The two halves are disjoint by construction: `out` is the scanned form of
//! `buf[..consumed]` and the carry is `buf[consumed..]`. Swapping the lines so
//! the write happens first — the intuitive "do not drop it until it is
//! delivered" ordering — leaves the carry holding a region whose masked form was
//! already handed to the sink. On the next pass that region is emitted a second
//! time, and if it is a PROPER PREFIX of a secret rather than a whole one, the
//! end of the stream emits it in CLEAR, because a proper prefix matches no
//! needle. [`a_failed_write_leaks_no_plaintext_even_after_the_stream_ends`] is
//! the test that catches it, and it catches it in that direction only.

use std::io::{self, ErrorKind, Write};
use std::sync::Arc;

use keyless::mask::{MIN_NEEDLE_LEN, Masker, MaskingWriter};
use keyless::secret::Secret;

const VALUE: &str = "decoy-failing-sink-value-77f3a1c8";

/// A sink that refuses when told to.
struct RefusingSink {
    /// Everything the sink actually accepted, in order.
    received: Vec<u8>,
    /// The 1-based `write` call that refuses. `None` never refuses.
    refuse_on_call: Option<usize>,
    /// Bytes to accept before refusing, so a PARTIAL write can be modelled.
    accept_before_refusing: usize,
    calls: usize,
    /// Set once the sink has actually refused, so a test can prove it did.
    refused: bool,
}

impl RefusingSink {
    fn refusing_on(call: usize) -> Self {
        RefusingSink {
            received: Vec::new(),
            refuse_on_call: Some(call),
            accept_before_refusing: 0,
            calls: 0,
            refused: false,
        }
    }

    fn never_refusing() -> Self {
        RefusingSink {
            received: Vec::new(),
            refuse_on_call: None,
            accept_before_refusing: 0,
            calls: 0,
            refused: false,
        }
    }

    fn seen(&self) -> String {
        String::from_utf8_lossy(&self.received).into_owned()
    }
}

impl Write for RefusingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.refuse_on_call == Some(self.calls) {
            let taken = self.accept_before_refusing.min(buf.len());
            self.received.extend_from_slice(&buf[..taken]);
            self.refused = true;
            return Err(io::Error::new(ErrorKind::BrokenPipe, "the sink refused"));
        }
        self.received.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn masker() -> Arc<Masker> {
    let secret = Secret::new(VALUE.to_owned());
    Arc::new(Masker::from_secrets([("DECOY", &secret)]))
}

/// Every run of `MIN_NEEDLE_LEN` or more bytes of the decoy found in `seen`.
///
/// Short runs are excluded because they are not what the masker promises to
/// catch — a needle shorter than that is dropped at construction, so demanding
/// their absence would assert something the tool never claimed.
fn plaintext_fragments(seen: &str) -> Vec<String> {
    let value = VALUE.as_bytes();
    let mut found = Vec::new();
    for len in (MIN_NEEDLE_LEN..=value.len()).rev() {
        for start in 0..=value.len() - len {
            let fragment = &VALUE[start..start + len];
            if seen.contains(fragment) {
                found.push(fragment.to_owned());
                return found;
            }
        }
    }
    found
}

#[test]
fn the_sink_can_actually_refuse() {
    // The instrument's own control. A sink that silently accepted everything
    // would make every case below pass while testing nothing, and it would look
    // exactly like a clean result.
    let mut sink = RefusingSink::refusing_on(1);
    let outcome = sink.write(b"anything");
    assert!(
        outcome.is_err(),
        "the refusing sink accepted a write it was told to refuse, so every \
         error path below was never entered"
    );
    assert!(sink.refused, "the sink did not record its own refusal");

    let mut ok = RefusingSink::never_refusing();
    assert!(
        ok.write(b"anything").is_ok(),
        "the sink refuses unconditionally, so a green case proves nothing"
    );
}

#[test]
fn a_failed_write_leaks_no_plaintext_even_after_the_stream_ends() {
    // The question this file was written to answer, and the one that
    // discriminates the current ordering inside `push` from the intuitive one.
    //
    // The decoy is split so the carry is holding a PROPER PREFIX of it when the
    // refusal lands. A proper prefix matches no needle, so if the carry were
    // still holding it at end of stream it would be emitted verbatim — the leak
    // is not hypothetical, it is what a proper prefix does when nothing masks
    // it.
    let masker = masker();
    let mut sink = RefusingSink::refusing_on(2);
    {
        let mut writer = MaskingWriter::new(Arc::clone(&masker), &mut sink);
        let head = format!("aaa {}", &VALUE[..8]);
        // Call 1: emits "aaa ", carries the 8-byte prefix.
        let _ = writer.write(head.as_bytes());
        // Call 2: completes the decoy, so the whole of it is scanned and
        // replaced — and the sink refuses that write.
        let tail = format!("{} done", &VALUE[8..]);
        let refused = writer.write(tail.as_bytes());
        assert!(
            refused.is_err(),
            "the write that was supposed to be refused succeeded, so this case \
             never exercised the error path at all"
        );
        // The stream still ends, which is where a retained prefix would escape.
        let _ = writer.finish();
    }

    assert!(
        sink.refused,
        "the sink never refused; this case proved nothing"
    );
    let seen = sink.seen();
    let fragments = plaintext_fragments(&seen);
    assert!(
        fragments.is_empty(),
        "a failed write let {} bytes of the decoy reach the sink in clear: {:?}\n\
         The sink saw: {:?}\n\
         The carry must hold only the region whose masked form was NOT handed \
         to the sink. Holding a region that was already emitted means emitting \
         it again, and a proper prefix of a secret matches no needle, so the \
         end of the stream prints it verbatim.",
        fragments.first().map_or(0, |f| f.len()),
        fragments,
        seen
    );
}

#[test]
fn a_failed_write_costs_the_masked_output_and_never_the_carry() {
    // What IS lost, stated rather than implied. `out` is the masked form of the
    // region already scanned; when the sink refuses it, those bytes are gone and
    // no retry can recover them, because the plaintext they came from has been
    // consumed. That is truncation of already-safe output, and it is the correct
    // trade — a sink that refuses cannot be delivered to by any ordering.
    //
    // The carry is the half that must NOT be lost, and this pins it: with the
    // refusal on the first call, the decoy is still withheld afterwards, and a
    // sink that never refuses receives it masked exactly once.
    let masker = masker();

    let mut refusing = RefusingSink::refusing_on(1);
    {
        let mut writer = MaskingWriter::new(Arc::clone(&masker), &mut refusing);
        let _ = writer.write(format!("aaa {VALUE}").as_bytes());
        let _ = writer.finish();
    }
    assert!(refusing.refused, "the sink never refused");
    assert!(
        plaintext_fragments(&refusing.seen()).is_empty(),
        "plaintext reached a refusing sink: {:?}",
        refusing.seen()
    );

    let mut healthy = RefusingSink::never_refusing();
    {
        let mut writer = MaskingWriter::new(Arc::clone(&masker), &mut healthy);
        let _ = writer.write(format!("aaa {VALUE}").as_bytes());
        writer
            .finish()
            .expect("a sink that never refuses cannot fail");
    }
    let seen = healthy.seen();
    assert_eq!(
        seen, "aaa [keyless:DECOY]",
        "the healthy path is the control for the refusing one: if this shape is \
         wrong, the assertions above are about the wrong bytes"
    );
    assert_eq!(
        seen.matches("[keyless:DECOY]").count(),
        1,
        "the decoy was emitted more than once, which is what re-emitting an \
         already-delivered region looks like"
    );
}

#[test]
fn a_partial_write_before_the_refusal_still_leaks_nothing() {
    // The quietest shape: the sink takes some of the masked output and then
    // refuses. `write_all` cannot report how much it placed, so the stream is
    // truncated mid-token. That is ugly and it is not a leak — the bytes on the
    // wire are a prefix of a REPLACEMENT, never of a secret.
    let masker = masker();
    let mut sink = RefusingSink::refusing_on(2);
    sink.accept_before_refusing = 6;
    {
        let mut writer = MaskingWriter::new(Arc::clone(&masker), &mut sink);
        let head = format!("aaa {}", &VALUE[..8]);
        let _ = writer.write(head.as_bytes());
        let tail = format!("{} done", &VALUE[8..]);
        let _ = writer.write(tail.as_bytes());
        let _ = writer.finish();
    }
    assert!(
        sink.refused,
        "the sink never refused; this case proved nothing"
    );
    assert!(
        plaintext_fragments(&sink.seen()).is_empty(),
        "a partial write before a refusal put decoy bytes on the wire: {:?}",
        sink.seen()
    );
}
