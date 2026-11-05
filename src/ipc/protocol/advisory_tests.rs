use super::{Reply, decode_advisory};
use crate::secret::Secret;

#[test]
fn an_advisory_rides_alongside_any_status_and_never_replaces_it() {
    let frame = Reply::Value(Secret::new("decoy-value".to_owned()))
        .encode_with_advisory(Some("the token expires soon"))
        .expect("encode");
    assert_eq!(
        decode_advisory(&frame[..frame.len() - 1]),
        Some("the token expires soon".to_owned())
    );
    match Reply::decode(&frame[..frame.len() - 1]).expect("decode") {
        Reply::Value(secret) => assert_eq!(secret.expose(), "decoy-value"),
        other => panic!("expected a value, got {other:?}"),
    }
}

#[test]
fn no_advisory_means_no_advisory_field_and_no_advisory_read_back() {
    let frame = Reply::Absent.encode().expect("encode");
    assert!(
        !String::from_utf8_lossy(&frame).contains("advisory"),
        "an absent advisory must not appear on the wire at all"
    );
    assert_eq!(decode_advisory(&frame[..frame.len() - 1]), None);
}

#[test]
fn a_frame_from_a_build_that_predates_advisories_reads_back_none() {
    let raw = br#"{"v":1,"status":"absent"}"#;
    assert_eq!(decode_advisory(raw), None);
}
