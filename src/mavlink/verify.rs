use hmac::{KeyInit, Mac};

use super::frame::MavLinkFrame;
use super::state::MavLinkState;
use super::constants::*;
use super::signature_input::{feed_signing_bytes, HmacSha256, timestamp_to_u64};
use super::errors::VerifyError;

// Replay window: 10 seconds in MAVLink timestamp units (10 µs each).
const REPLAY_WINDOW: u64 = 1_000_000;


pub fn verify_frame(
    frame: &MavLinkFrame, 
    secret_key: &[u8],
    current_timestamp: &[u8; TIMESTAMP_SIZE],
    state: &mut MavLinkState, 
) -> Result<(), VerifyError> {

    // CHECK 1: message must be signed
    if (frame.inc_flags & SIGNED_FLAG) == 0 {
        return Err(VerifyError::NotSigned);
    }

    // CHECK 2: link_id must match expected physical link
    // if link_id is is wrong still HMAC will fail,
    // but we can fail faster here
    if frame.link_id != state.expected_link_id {
        return Err(VerifyError::WrongLink);
    }

    // CHECK 3: HMAC verification 
    // Note: verification should be done in Constant Time!
    assert!(secret_key.len() == 32, "Secret key must be 32 bytes for HMAC-SHA256");

    let mut mac = HmacSha256::new_from_slice(secret_key)
        .expect("HMAC can take key of any size");

    feed_signing_bytes(&mut mac, frame);

    let full_signature = mac.finalize().into_bytes();
    let expected_signature = &full_signature[..SIGNATURE_FIELD_SIZE];

    if frame.signature != expected_signature {
        return Err(VerifyError::HmacMismatch);
    }


    // CHECK 4: timestamp checks for replay protection
    let frame_ts = timestamp_to_u64(&frame.timestamp);
    let now = timestamp_to_u64(current_timestamp);
    let last_ts    = timestamp_to_u64(&state.last_accepted_timestamp);

    if frame_ts > now {
        return Err(VerifyError::FutureTimestamp);
    }

    if now - frame_ts > REPLAY_WINDOW {
        return Err(VerifyError::TooOld);
    }

    if frame_ts <= last_ts {
        return Err(VerifyError::Replay);
    }

    // Update state on successful verification
    state.update_timestamp(frame.timestamp.clone());

    Ok(())
}