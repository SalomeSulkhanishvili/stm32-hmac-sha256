use hmac::{KeyInit, Mac};
use subtle::ConstantTimeEq;

use super::checksum::crc_extra_for;
use super::frame::MavLinkFrame;
use super::state::MavLinkState;
use super::constants::*;
use super::signature_input::{feed_signing_bytes, HmacSha256, timestamp_to_u64};
use super::errors::VerifyError;

const REPLAY_WINDOW: u64 = 1_000_000; // 10 seconds in MAVLink units (10 µs each)


pub fn verify_frame(
    frame: &MavLinkFrame,
    secret_key: &[u8],
    current_timestamp: &[u8; TIMESTAMP_SIZE],
    state: &mut MavLinkState,
) -> Result<(), VerifyError> {

    if !frame.is_signed() {
        return Err(VerifyError::NotSigned);
    }

    if frame.link_id != state.expected_link_id {
        return Err(VerifyError::WrongLink);
    }

    if secret_key.len() != 32 {
        return Err(VerifyError::InvalidKey);
    }

    let crc_extra = crc_extra_for(frame.msg_id).ok_or(VerifyError::UnknownMessage)?;

    if frame.checksum != frame.compute_checksum(crc_extra) {
        return Err(VerifyError::ChecksumMismatch);
    }

    let mut mac = HmacSha256::new_from_slice(secret_key).unwrap();

    feed_signing_bytes(&mut mac, frame);

    let full_signature = mac.finalize().into_bytes();
    let expected_signature = &full_signature[..SIGNATURE_FIELD_SIZE];

    if expected_signature.ct_eq(&frame.signature).unwrap_u8() == 0 {
        return Err(VerifyError::HmacMismatch);
    }

    let frame_ts = timestamp_to_u64(&frame.timestamp);
    let now = timestamp_to_u64(current_timestamp);

    if frame_ts > now {
        return Err(VerifyError::FutureTimestamp);
    }

    if now - frame_ts > REPLAY_WINDOW {
        return Err(VerifyError::TooOld);
    }

    critical_section::with(|_| {
        let last_ts = timestamp_to_u64(state.last_accepted_timestamp());
        if frame_ts <= last_ts {
            return Err(VerifyError::Replay);
        }
        state.update_timestamp(frame.timestamp);
        Ok(())
    })
}
