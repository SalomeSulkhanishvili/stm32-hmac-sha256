use hmac::{KeyInit, Mac};

use super::checksum::crc_extra_for;
use super::constants::*;
use super::errors::SignError;
use super::frame::MavLinkFrame;
use super::signature_input::{feed_signing_bytes, HmacSha256};


pub fn sign_frame(frame: &mut MavLinkFrame, secret_key: &[u8]) -> Result<(), SignError> {
    if secret_key.len() != 32 {
        return Err(SignError::InvalidKey);
    }

    let crc_extra = crc_extra_for(frame.msg_id).ok_or(SignError::UnknownMessage)?;

    frame.inc_flags |= SIGNED_FLAG;
    frame.set_checksum(crc_extra);

    let mut mac = HmacSha256::new_from_slice(secret_key).unwrap();

    feed_signing_bytes(&mut mac, frame);

    let full_signature = mac.finalize().into_bytes();
    frame.signature.copy_from_slice(&full_signature[..SIGNATURE_FIELD_SIZE]);

    Ok(())
}