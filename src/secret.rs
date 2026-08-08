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
//! - `Drop` zeroizes, so the plaintext does not linger in freed memory for the
//!   rest of the process's life.
//! - The one accessor is called [`Secret::expose`], which is deliberately
//!   conspicuous: `grep -rn 'expose('` is the complete list of places the
//!   plaintext is readable, and that list is short enough to audit by eye.

use std::fmt;

use zeroize::Zeroize;

/// A resolved credential value.
pub struct Secret(String);

impl Secret {
    /// Wrap a plaintext value.
    #[must_use]
    pub fn new(value: String) -> Self {
        Secret(value)
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
            .map(|s| Secret(s.to_owned()));
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
        &self.0
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

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

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
