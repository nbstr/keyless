//! Every representation of a secret that a program might print.
//!
//! Masking by substring only catches a form it was told to look for. A value
//! that arrives base64-encoded in an `Authorization` header, or percent-encoded
//! in a URL path, or `<`-escaped inside a JSON body, is the *same secret*
//! and is invisible to a matcher that only knows the raw bytes.
//!
//! Each encoding below models a specific, real producer rather than a
//! hypothetical one — the comment on each variant names it. That is deliberate:
//! an unbounded list of clever transformations is unmaintainable, while a list
//! of "things that actually print secrets in the wild" stays finite.
//!
//! # What this cannot catch, ever
//!
//! Substring matching sees bytes. It therefore cannot catch any encoding that
//! does not preserve a contiguous byte image of the value:
//!
//! - **Compression** — gzip, zstd, brotli. A gzipped response body containing a
//!   token has no substring in common with the token.
//! - **Encryption or hashing** — TLS payloads, an HMAC computed *from* the
//!   secret, a bcrypt digest.
//! - **Chunked or reordered transport** — a value split across two frames of a
//!   protocol we do not parse, and reassembled by the reader.
//! - **Lossy re-rendering** — a value line-wrapped by a pretty-printer, or with
//!   an ANSI colour escape inserted into the middle of it.
//!
//! These are accepted limits, written down rather than papered over. The threat
//! model is a competent agent taking a shortcut, not an adversary; an adversary
//! defeats masking in three tokens with `sh -c 'echo $TOKEN > /tmp/x'`.

/// A representation a secret can take on its way to a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// The value exactly as stored.
    Raw,
    /// ASCII-lowercased. Some CLIs normalise identifiers before echoing them.
    Lowercase,
    /// ASCII-uppercased, same reason.
    Uppercase,
    /// RFC 4648 base64 with padding — Kubernetes `data:` values, most SDK
    /// encoders. **Not HTTP Basic**, which encodes `user:password` as one
    /// string: base64 is 3-byte aligned, so the encoding of the password alone
    /// is a substring of that only when `user:` is a multiple of three bytes.
    Base64Std,
    /// RFC 4648 base64 without padding — JWT segments, many Go encoders.
    Base64StdNoPad,
    /// RFC 4648 §5 URL-safe base64 with padding.
    Base64Url,
    /// RFC 4648 §5 URL-safe base64 without padding — JWTs, `base64url` in JOSE.
    Base64UrlNoPad,
    /// RFC 4648 §6 base32 with padding — TOTP seeds, some Kubernetes tooling.
    Base32,
    /// RFC 4648 §6 base32 without padding.
    Base32NoPad,
    /// Lowercase hex — Python `bytes.hex()`, Rust `{:x}`, Node
    /// `toString("hex")`.
    ///
    /// **Not a hex dump.** `xxd` separates two-byte columns with spaces and
    /// `xxd -p` wraps at 60 characters, so neither leaves a contiguous image of
    /// a value longer than 30 bytes for a substring match to find.
    HexLower,
    /// Uppercase hex — some Java formatting, `openssl` with `-upper`.
    HexUpper,
    /// `0x`-prefixed lowercase hex — Ethereum tooling, C-style dumps.
    HexPrefixedLower,
    /// `0x`-prefixed uppercase hex.
    HexPrefixedUpper,
    /// Go's `url.QueryEscape`: space becomes `+`. Query strings.
    UrlQuery,
    /// Go's `url.PathEscape`: space becomes `%20` and `$&+:=@` stay literal.
    /// This is the one the reference implementation missed.
    UrlPath,
    /// Strict RFC 3986: only unreserved characters survive, space is `%20`.
    UrlStrict,
    /// `serde_json` / `JSON.stringify` defaults.
    JsonMinimal,
    /// Go's `encoding/json` default, which HTML-escapes `&`, `<` and `>`.
    JsonHtml,
    /// PHP's `json_encode` default, which escapes `/` as `\/`.
    JsonSlash,
    /// Python's `json.dumps` default (`ensure_ascii=True`): every non-ASCII
    /// character becomes a `\uXXXX` escape.
    JsonAsciiOnly,
}

/// Every encoding, in a stable order. Tests iterate this so a new variant
/// cannot be added without the table test covering it.
pub const ALL: &[Encoding] = &[
    Encoding::Raw,
    Encoding::Lowercase,
    Encoding::Uppercase,
    Encoding::Base64Std,
    Encoding::Base64StdNoPad,
    Encoding::Base64Url,
    Encoding::Base64UrlNoPad,
    Encoding::Base32,
    Encoding::Base32NoPad,
    Encoding::HexLower,
    Encoding::HexUpper,
    Encoding::HexPrefixedLower,
    Encoding::HexPrefixedUpper,
    Encoding::UrlQuery,
    Encoding::UrlPath,
    Encoding::UrlStrict,
    Encoding::JsonMinimal,
    Encoding::JsonHtml,
    Encoding::JsonSlash,
    Encoding::JsonAsciiOnly,
];

impl Encoding {
    /// Stable identifier, used in test output and documentation.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Encoding::Raw => "raw",
            Encoding::Lowercase => "lowercase",
            Encoding::Uppercase => "uppercase",
            Encoding::Base64Std => "base64-std",
            Encoding::Base64StdNoPad => "base64-std-nopad",
            Encoding::Base64Url => "base64-url",
            Encoding::Base64UrlNoPad => "base64-url-nopad",
            Encoding::Base32 => "base32",
            Encoding::Base32NoPad => "base32-nopad",
            Encoding::HexLower => "hex-lower",
            Encoding::HexUpper => "hex-upper",
            Encoding::HexPrefixedLower => "hex-0x-lower",
            Encoding::HexPrefixedUpper => "hex-0x-upper",
            Encoding::UrlQuery => "url-query",
            Encoding::UrlPath => "url-path",
            Encoding::UrlStrict => "url-strict",
            Encoding::JsonMinimal => "json-minimal",
            Encoding::JsonHtml => "json-html",
            Encoding::JsonSlash => "json-slash",
            Encoding::JsonAsciiOnly => "json-ascii-only",
        }
    }

    /// Render `value` in this encoding.
    #[must_use]
    pub fn encode(self, value: &str) -> String {
        let bytes = value.as_bytes();
        match self {
            Encoding::Raw => value.to_owned(),
            Encoding::Lowercase => value.to_lowercase(),
            Encoding::Uppercase => value.to_uppercase(),
            Encoding::Base64Std => base64(bytes, B64_STD, true),
            Encoding::Base64StdNoPad => base64(bytes, B64_STD, false),
            Encoding::Base64Url => base64(bytes, B64_URL, true),
            Encoding::Base64UrlNoPad => base64(bytes, B64_URL, false),
            Encoding::Base32 => base32(bytes, true),
            Encoding::Base32NoPad => base32(bytes, false),
            Encoding::HexLower => hex_lower(bytes),
            Encoding::HexUpper => hex_upper(bytes),
            Encoding::HexPrefixedLower => format!("0x{}", hex_lower(bytes)),
            Encoding::HexPrefixedUpper => format!("0x{}", hex_upper(bytes)),
            Encoding::UrlQuery => url_escape(bytes, UrlMode::Query),
            Encoding::UrlPath => url_escape(bytes, UrlMode::Path),
            Encoding::UrlStrict => url_escape(bytes, UrlMode::Strict),
            Encoding::JsonMinimal => json_escape(value, JsonMode::Minimal),
            Encoding::JsonHtml => json_escape(value, JsonMode::Html),
            Encoding::JsonSlash => json_escape(value, JsonMode::Slash),
            Encoding::JsonAsciiOnly => json_escape(value, JsonMode::AsciiOnly),
        }
    }
}

/// Every distinct rendering of `value`, paired with the encoding that produced it.
///
/// Duplicates are dropped: for a value with no letters, `raw`, `lowercase` and
/// `uppercase` collapse to one needle, and there is no point scanning for the
/// same bytes three times.
#[must_use]
pub fn variants(value: &str) -> Vec<(Encoding, String)> {
    let mut seen: Vec<String> = Vec::with_capacity(ALL.len());
    let mut out = Vec::with_capacity(ALL.len());
    for &encoding in ALL {
        let rendered = encoding.encode(value);
        if seen.iter().any(|existing| existing == &rendered) {
            continue;
        }
        seen.push(rendered.clone());
        out.push((encoding, rendered));
    }
    out
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn base64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        // 1 input byte yields 2 characters, 2 yields 3, 3 yields 4.
        let significant = chunk.len() + 1;
        for i in 0..4 {
            if i < significant {
                let index = ((n >> (18 - i * 6)) & 0x3f) as usize;
                out.push(alphabet[index] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn base32(data: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        // Each input byte contributes 8 bits, each output character consumes 5.
        let significant = (chunk.len() * 8).div_ceil(5);
        for i in 0..8 {
            if i < significant {
                let index = ((n >> (35 - i * 5)) & 0x1f) as usize;
                out.push(B32[index] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Lowercase hex. Shared with the audit log's chain hashes.
#[must_use]
pub fn hex_lower(data: &[u8]) -> String {
    hex_with(data, HEX_LOWER)
}

/// Uppercase hex.
#[must_use]
pub fn hex_upper(data: &[u8]) -> String {
    hex_with(data, HEX_UPPER)
}

fn hex_with(data: &[u8], table: &[u8; 16]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(table[usize::from(byte >> 4)] as char);
        out.push(table[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[derive(Clone, Copy)]
enum UrlMode {
    Query,
    Path,
    Strict,
}

fn url_escape(data: &[u8], mode: UrlMode) -> String {
    let mut out = String::with_capacity(data.len());
    for &byte in data {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        let literal = match mode {
            UrlMode::Query | UrlMode::Strict => unreserved,
            // Go's encodePathSegment keeps the sub-delims that carry no meaning
            // inside a single segment.
            UrlMode::Path => unreserved || matches!(byte, b'$' | b'&' | b'+' | b':' | b'=' | b'@'),
        };
        if literal {
            out.push(byte as char);
        } else if byte == b' ' && matches!(mode, UrlMode::Query) {
            out.push('+');
        } else {
            out.push('%');
            out.push(HEX_UPPER[usize::from(byte >> 4)] as char);
            out.push(HEX_UPPER[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonMode {
    Minimal,
    Html,
    Slash,
    AsciiOnly,
}

/// The *contents* of a JSON string, without the surrounding quotes.
///
/// The quotes are excluded on purpose: a masker looking for `"value"` misses
/// the same value inside a concatenated log line, whereas the bare escaped body
/// matches in both places.
fn json_escape(value: &str, mode: JsonMode) -> String {
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '/' if mode == JsonMode::Slash => out.push_str("\\/"),
            '&' | '<' | '>' if mode == JsonMode::Html => push_u_escape(&mut out, ch),
            c if (c as u32) < 0x20 => push_u_escape(&mut out, c),
            c if !c.is_ascii() && mode == JsonMode::AsciiOnly => push_u_escape(&mut out, c),
            c => out.push(c),
        }
    }
    out
}

/// Push `\uXXXX`, using a surrogate pair for characters outside the BMP, which
/// is what every JSON encoder that escapes non-ASCII does.
fn push_u_escape(out: &mut String, ch: char) {
    let mut units = [0u16; 2];
    for unit in ch.encode_utf16(&mut units) {
        out.push_str("\\u");
        for shift in [12, 8, 4, 0] {
            out.push(HEX_LOWER[usize::from((*unit >> shift) & 0xf)] as char);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ALL, B64_STD, B64_URL, Encoding, base32, base64, hex_lower, variants};

    // RFC 4648 §10 test vectors. These are the whole reason to hand-roll the
    // codecs instead of taking three dependencies: correctness is checkable.
    #[test]
    fn base64_matches_rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                base64(input.as_bytes(), B64_STD, true),
                expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn base64_unpadded_drops_only_the_padding() {
        assert_eq!(base64(b"foob", B64_STD, false), "Zm9vYg");
        assert_eq!(base64(b"fooba", B64_STD, false), "Zm9vYmE");
    }

    #[test]
    fn base64_url_alphabet_differs_where_it_should() {
        // 0xfb 0xff encodes to "+/" in the standard alphabet.
        let data = [0xfb_u8, 0xff, 0xfe];
        assert_eq!(base64(&data, B64_STD, true), "+//+");
        assert_eq!(base64(&data, B64_URL, true), "-__-");
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ];
        for (input, expected) in cases {
            assert_eq!(base32(input.as_bytes(), true), expected, "input {input:?}");
        }
        assert_eq!(base32(b"foobar", false), "MZXW6YTBOI");
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn url_query_and_path_disagree_about_space_and_sub_delims() {
        // The exact gap that leaked in the reference implementation.
        let value = "a b&c=d/e";
        assert_eq!(Encoding::UrlQuery.encode(value), "a+b%26c%3Dd%2Fe");
        assert_eq!(Encoding::UrlPath.encode(value), "a%20b&c=d%2Fe");
        assert_eq!(Encoding::UrlStrict.encode(value), "a%20b%26c%3Dd%2Fe");
    }

    #[test]
    fn json_modes_produce_the_documented_shapes() {
        assert_eq!(
            Encoding::JsonMinimal.encode("a\"b\\c/d<e"),
            "a\\\"b\\\\c/d<e"
        );
        assert_eq!(
            Encoding::JsonHtml.encode("a<b>c&d"),
            "a\\u003cb\\u003ec\\u0026d"
        );
        assert_eq!(Encoding::JsonSlash.encode("a/b"), "a\\/b");
        assert_eq!(Encoding::JsonAsciiOnly.encode("café"), "caf\\u00e9");
        assert_eq!(Encoding::JsonMinimal.encode("café"), "café");
    }

    #[test]
    fn json_ascii_only_uses_surrogate_pairs_beyond_the_bmp() {
        assert_eq!(
            Encoding::JsonAsciiOnly.encode("\u{1f600}"),
            "\\ud83d\\ude00"
        );
    }

    #[test]
    fn json_escapes_control_characters() {
        assert_eq!(Encoding::JsonMinimal.encode("a\u{1}b\nc"), "a\\u0001b\\nc");
    }

    #[test]
    fn every_encoding_has_a_distinct_label() {
        let mut labels: Vec<&str> = ALL.iter().map(|e| e.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "two encodings share a label");
    }

    #[test]
    fn variants_deduplicate_identical_renderings() {
        // A digit-only value renders identically as raw, lowercase and uppercase.
        let rendered = variants("12345678");
        let raws = rendered.iter().filter(|(_, v)| v == "12345678").count();
        assert_eq!(raws, 1);
    }
}
