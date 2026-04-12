use hmac::{KeyInit, Mac};

use super::constants::*;
use super::frame::MavLinkFrame;
use super::signature_input::{feed_signing_bytes, HmacSha256};


pub fn sign_frame(frame: &mut MavLinkFrame, secret_key: &[u8], crc_extra: u8) {
    debug_assert!(secret_key.len() == 32, "Secret key must be 32 bytes");

    frame.inc_flags |= SIGNED_FLAG;
    frame.set_checksum(crc_extra);

    let mut mac = HmacSha256::new_from_slice(secret_key).unwrap();

    feed_signing_bytes(&mut mac, frame);

    let full_signature = mac.finalize().into_bytes();
    frame.signature.copy_from_slice(&full_signature[..SIGNATURE_FIELD_SIZE]);
}