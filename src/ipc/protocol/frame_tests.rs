use super::{MAX_FRAME_BYTES, ProtocolError, read_frame};
use std::io::BufReader;

#[test]
fn frames_split_at_newlines() {
    let stream: &[u8] = b"{\"a\":1}\n{\"b\":2}\n";
    let mut reader = BufReader::new(stream);
    assert_eq!(
        read_frame(&mut reader).expect("first"),
        Some(b"{\"a\":1}".to_vec())
    );
    assert_eq!(
        read_frame(&mut reader).expect("second"),
        Some(b"{\"b\":2}".to_vec())
    );
    assert_eq!(read_frame(&mut reader).expect("eof"), None);
}

#[test]
fn a_frame_that_never_ends_is_refused_at_the_cap() {
    let huge = vec![b'x'; MAX_FRAME_BYTES + 64];
    let mut reader = BufReader::new(huge.as_slice());
    assert!(matches!(
        read_frame(&mut reader),
        Err(ProtocolError::Framing(_))
    ));
}

#[test]
fn a_stream_that_stops_mid_frame_is_an_error_not_a_short_message() {
    let mut reader = BufReader::new(&b"{\"partial\":"[..]);
    assert!(matches!(
        read_frame(&mut reader),
        Err(ProtocolError::Framing(_))
    ));
}
