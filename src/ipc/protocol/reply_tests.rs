use super::{ProtocolError, Reply};
use crate::secret::Secret;

#[test]
fn a_value_round_trips_and_survives_json_escaping() {
    // Quotes, backslashes and a newline are exactly what a naive
    // hand-rolled encoder would corrupt or truncate.
    let awkward = "decoy\"with\\quotes\nand-a-newline-\u{e9}";
    let frame = Reply::Value(Secret::new(awkward.to_owned()))
        .encode()
        .expect("encode");
    match Reply::decode(&frame[..frame.len() - 1]).expect("decode") {
        Reply::Value(secret) => assert_eq!(secret.expose(), awkward),
        other => panic!("expected a value, got {other:?}"),
    }
}

#[test]
fn a_reply_debug_never_prints_the_value() {
    let reply = Reply::Value(Secret::new("decoy-must-not-appear-9911".to_owned()));
    let rendered = format!("{reply:?}");
    assert!(
        !rendered.contains("9911"),
        "the value reached a Debug: {rendered}"
    );
}

#[test]
fn a_denial_reason_round_trips() {
    let frame = Reply::Denied("unknown-image".to_owned())
        .encode()
        .expect("encode");
    match Reply::decode(&frame[..frame.len() - 1]).expect("decode") {
        Reply::Denied(reason) => assert_eq!(reason, "unknown-image"),
        other => panic!("expected a denial, got {other:?}"),
    }
}

#[test]
fn a_heartbeat_round_trips_and_carries_nothing() {
    let frame = Reply::Working.encode().expect("encode");
    assert!(matches!(
        Reply::decode(&frame[..frame.len() - 1]).expect("decode"),
        Reply::Working
    ));
    let rendered = String::from_utf8_lossy(&frame).into_owned();
    assert!(!rendered.contains("value"), "{rendered}");
    assert!(!rendered.contains("reason"), "{rendered}");
}

#[test]
fn an_ok_reply_with_no_value_is_malformed_rather_than_empty() {
    let raw = br#"{"v":1,"status":"ok"}"#;
    assert!(matches!(
        Reply::decode(raw),
        Err(ProtocolError::Malformed(_))
    ));
}
