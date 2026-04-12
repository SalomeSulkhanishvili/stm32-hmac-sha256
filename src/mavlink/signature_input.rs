use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::frame::MavLinkFrame;
use super::constants::*;

// HMAC-SHA256 type alias used by sign and verify
pub(crate) type HmacSha256 = Hmac<Sha256>;

// Convert a 6-byte little-endian MAVLink timestamp to u64
pub(crate) fn timestamp_to_u64(ts: &[u8; TIMESTAMP_SIZE]) -> u64 {
    u64::from_le_bytes([ts[0], ts[1], ts[2], ts[3], ts[4], ts[5], 0, 0])
}



// Feed the MAVLink signing byte sequence directly into an HMAC instance.
//
// Streams bytes in wire order without any intermediate buffer:
//   header (10) + payload (0–255) + checksum (2) + link_id (1) + timestamp (6)
//
// signature is NOT included — it is the output, not the input.
//
// Using mac.update() multiple times is identical to feeding all bytes at once;
// HMAC processes input in a streaming fashion internally.
pub fn feed_signing_bytes(mac: &mut HmacSha256, frame: &MavLinkFrame) {

    // Header fields in wire order
    mac.update(&[
        frame.stx,
        frame.len,
        frame.inc_flags,
        frame.cmp_flags,
        frame.seq,
        frame.sys_id,
        frame.comp_id,
    ]);

    mac.update(&frame.msg_id);

    // Payload
    mac.update(&frame.payload);

    // Checksum
    mac.update(&frame.checksum);

    // Link ID and Timestamp
    mac.update(&[frame.link_id]);
    mac.update(&frame.timestamp); 
}