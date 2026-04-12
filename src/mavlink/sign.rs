use hmac::{KeyInit, Mac};

use super::constants::*;
use super::frame::MavLinkFrame;
use super::signature_input::{feed_signing_bytes, HmacSha256};


pub fn sign_frame(frame: &mut MavLinkFrame, secret_key: &[u8]) {
    assert!(secret_key.len() == 32, "Secret key must be 32 bytes for HMAC-SHA256");

    // Create HMAC instance with the secret key
    frame.inc_flags |= SIGNED_FLAG; // Set the signed flag

    let mut mac = HmacSha256::new_from_slice(secret_key)
        .expect("HMAC can take key of any size");

    feed_signing_bytes(&mut mac, frame);

    let full_signature = mac.finalize().into_bytes();

    // MavLink signature is the first 6 bytes of the HMAC output
    frame.signature.copy_from_slice(&full_signature[..SIGNATURE_FIELD_SIZE]);
}