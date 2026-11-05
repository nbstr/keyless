use super::{Op, ProtocolError, Reply, Request};

#[test]
fn a_request_round_trips() {
    let request = Request::resolve("DECOY_NAME");
    let frame = request.encode().expect("encode");
    assert_eq!(frame.last(), Some(&b'\n'));
    let parsed = Request::decode(&frame[..frame.len() - 1]).expect("decode");
    assert_eq!(parsed.op, Op::Resolve);
    assert_eq!(parsed.name, "DECOY_NAME");
}

#[test]
fn a_request_from_a_build_that_predates_heartbeats_asks_for_none() {
    // The version number is unchanged on purpose, so a client installed
    // before this field existed still talks to a daemon that has it. What
    // stops that pair breaking is this default: no field means no
    // heartbeats, which is exactly the exchange that client can read.
    let raw = br#"{"v":1,"op":"resolve","name":"DECOY"}"#;
    let request = Request::decode(raw).expect("decode");
    assert!(!request.progress);
}

#[test]
fn a_version_mismatch_is_refused_rather_than_guessed() {
    let raw = br#"{"v":99,"op":"resolve","name":"X"}"#;
    assert!(matches!(
        Request::decode(raw),
        Err(ProtocolError::Version(99))
    ));
    let raw = br#"{"v":99,"status":"ok","value":"decoy"}"#;
    assert!(matches!(
        Reply::decode(raw),
        Err(ProtocolError::Version(99))
    ));
}
