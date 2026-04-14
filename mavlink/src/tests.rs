use heapless::Vec;

use crate::mavlink::{
    sign_frame, verify_frame, MavLinkFrame, MavLinkState, SignError, VerifyError,
    MAX_PAYLOAD_SIZE, SIGNED_FLAG,
};

// 32-byte key used across tests (same as the demo in main.rs)
const KEY: &[u8; 32] = b"\xaa\x53\x4a\x45\x7a\xb5\xe0\x43\x53\x0f\x82\xaa\x5c\x20\xf8\xd9\xd6\x71\xdd\xa7\x84\xaf\x5c\x40\x93\x1e\x70\x65\x58\x40\xfe\x67";

// Same length as KEY but different first byte — triggers HmacMismatch, not InvalidKey
const WRONG_KEY: &[u8; 32] = b"\xbb\x53\x4a\x45\x7a\xb5\xe0\x43\x53\x0f\x82\xaa\x5c\x20\xf8\xd9\xd6\x71\xdd\xa7\x84\xaf\x5c\x40\x93\x1e\x70\x65\x58\x40\xfe\x67";

const MSG_ID: [u8; 3] = [0x00, 0x00, 0x00]; // HEARTBEAT
const CURRENT_TS: [u8; 6] = [20, 0, 0, 0, 0, 0]; // current time = 20 units

fn make_frame(timestamp: [u8; 6]) -> MavLinkFrame {
    let mut payload: Vec<u8, MAX_PAYLOAD_SIZE> = Vec::new();
    payload.push(0x01).unwrap();
    payload.push(0x02).unwrap();
    payload.push(0x03).unwrap();

    MavLinkFrame::new(0x00, 42, 1, 191, MSG_ID, payload, [0x00, 0x00], 0, timestamp)
}

fn make_test_frame() -> MavLinkFrame {
    make_frame([10, 0, 0, 0, 0, 0]) // frame_ts = 10, safely inside CURRENT_TS window
}

// --- happy path ---

#[test]
fn test_sign_and_verify_valid() {
    let mut frame = make_test_frame();
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();

    assert!(frame.inc_flags & SIGNED_FLAG != 0);
    assert_eq!(verify_frame(&frame, KEY, &CURRENT_TS, &mut state), Ok(()));
    assert_eq!(state.last_accepted_timestamp, frame.timestamp);
}

// --- key errors ---

#[test]
fn test_sign_invalid_key_length_rejected() {
    let mut frame = make_test_frame();
    assert_eq!(
        sign_frame(&mut frame, b"tooshort"),
        Err(SignError::InvalidKey),
    );
}

#[test]
fn test_sign_unknown_msg_id_rejected() {
    let mut payload: Vec<u8, MAX_PAYLOAD_SIZE> = Vec::new();
    payload.push(0x01).unwrap();
    let mut frame = MavLinkFrame::new(0x00, 1, 1, 1, [0xFF, 0xFF, 0xFF], payload, [0x00, 0x00], 0, [10, 0, 0, 0, 0, 0]);
    assert_eq!(
        sign_frame(&mut frame, KEY),
        Err(SignError::UnknownMessage),
    );
}

#[test]
fn test_wrong_key_fails() {
    let mut frame = make_test_frame();
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();

    assert_eq!(
        verify_frame(&frame, WRONG_KEY, &CURRENT_TS, &mut state),
        Err(VerifyError::HmacMismatch),
    );
    // state must NOT advance on failure
    assert_eq!(state.last_accepted_timestamp, [0u8; 6]);
}

#[test]
fn test_verify_invalid_key_length_rejected() {
    let mut frame = make_test_frame();
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();

    assert_eq!(
        verify_frame(&frame, b"tooshort", &CURRENT_TS, &mut state),
        Err(VerifyError::InvalidKey),
    );
}

#[test]
fn test_verify_unknown_msg_id_rejected() {
    let mut frame = make_test_frame();
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();
    frame.msg_id = [0xFF, 0xFF, 0xFF]; // unknown after signing

    assert_eq!(
        verify_frame(&frame, KEY, &CURRENT_TS, &mut state),
        Err(VerifyError::UnknownMessage),
    );
}

// --- tamper detection ---

#[test]
fn test_tampered_payload_fails() {
    let mut frame = make_test_frame();
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();
    frame.payload[0] ^= 0xFF; // flip one byte — CRC no longer matches

    assert_eq!(
        verify_frame(&frame, KEY, &CURRENT_TS, &mut state),
        Err(VerifyError::ChecksumMismatch),
    );
}

#[test]
fn test_tampered_signature_fails() {
    let mut frame = make_test_frame();
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();
    frame.signature[0] ^= 0xFF; // CRC unaffected; HMAC check catches this

    assert_eq!(
        verify_frame(&frame, KEY, &CURRENT_TS, &mut state),
        Err(VerifyError::HmacMismatch),
    );
}

// --- flag / link checks ---

#[test]
fn test_unsigned_frame_rejected() {
    let frame = make_test_frame(); // inc_flags = 0
    let mut state = MavLinkState::new(0);

    assert_eq!(
        verify_frame(&frame, KEY, &CURRENT_TS, &mut state),
        Err(VerifyError::NotSigned),
    );
}

#[test]
fn test_wrong_link_id_fails() {
    let mut frame = make_test_frame(); // frame.link_id = 0
    let mut state = MavLinkState::new(1); // expects link 1

    sign_frame(&mut frame, KEY).unwrap();

    assert_eq!(
        verify_frame(&frame, KEY, &CURRENT_TS, &mut state),
        Err(VerifyError::WrongLink),
    );
}

// --- timestamp / replay checks ---

#[test]
fn test_future_timestamp_fails() {
    let mut frame = make_test_frame(); // frame_ts = 10
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();

    let past_current: [u8; 6] = [5, 0, 0, 0, 0, 0]; // current_ts=5 < frame_ts=10
    assert_eq!(
        verify_frame(&frame, KEY, &past_current, &mut state),
        Err(VerifyError::FutureTimestamp),
    );
}

#[test]
fn test_too_old_timestamp_fails() {
    let mut frame = make_test_frame(); // frame_ts = 10
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();

    // current_ts = 10 + REPLAY_WINDOW + 1 = 1_000_011 units
    let far_future: [u8; 6] = {
        let b = 1_000_011_u64.to_le_bytes();
        [b[0], b[1], b[2], b[3], b[4], b[5]]
    };
    assert_eq!(
        verify_frame(&frame, KEY, &far_future, &mut state),
        Err(VerifyError::TooOld),
    );
}

#[test]
fn test_state_prevents_replay() {
    let mut frame = make_test_frame();
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();

    assert_eq!(verify_frame(&frame, KEY, &CURRENT_TS, &mut state), Ok(()));
    assert_eq!(
        verify_frame(&frame, KEY, &CURRENT_TS, &mut state),
        Err(VerifyError::Replay),
    );
}

#[test]
fn test_non_increasing_timestamp_fails() {
    let mut frame_later = make_frame([15, 0, 0, 0, 0, 0]);
    let mut frame_early = make_frame([10, 0, 0, 0, 0, 0]);
    let mut state = MavLinkState::new(0);
    let current: [u8; 6] = [20, 0, 0, 0, 0, 0];

    sign_frame(&mut frame_later, KEY).unwrap();
    sign_frame(&mut frame_early, KEY).unwrap();

    assert_eq!(verify_frame(&frame_later, KEY, &current, &mut state), Ok(()));
    assert_eq!(
        verify_frame(&frame_early, KEY, &current, &mut state),
        Err(VerifyError::Replay),
    );
}

// --- serialisation ---

#[test]
fn test_from_bytes_roundtrip() {
    let mut frame = make_test_frame();
    let mut state = MavLinkState::new(0);

    sign_frame(&mut frame, KEY).unwrap();

    let buf = frame.to_bytes();
    let parsed = MavLinkFrame::from_bytes(&buf).unwrap();

    assert_eq!(verify_frame(&parsed, KEY, &CURRENT_TS, &mut state), Ok(()));
}

#[test]
fn test_from_bytes_wrong_stx_returns_none() {
    let frame = make_test_frame();
    let mut buf = frame.to_bytes();
    buf[0] = 0xAB;
    assert!(MavLinkFrame::from_bytes(&buf).is_none());
}

#[test]
fn test_from_bytes_too_short_returns_none() {
    assert!(MavLinkFrame::from_bytes(&[]).is_none());
    assert!(MavLinkFrame::from_bytes(&[0xFD; 5]).is_none());
}
