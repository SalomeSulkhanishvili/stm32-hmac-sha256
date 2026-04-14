
// Signed frame Flag 0 => 0: not signed, 1: signed
pub(crate) const SIGNED_FLAG: u8 = 0x01;


// ===== MavLink 2.0 frame structure constants ===

// HEADER: STX (1) + LEN (1) + INC_FLAGS (1) + SEQ (1) + SYS_ID (1) + COMP_ID (1) + MSG_ID (3)
pub(crate) const HEADER_SIZE: usize = 10;

pub const MAX_PAYLOAD_SIZE: usize = 255;
pub(crate) const CHECKSUM_SIZE: usize = 2;

// SIGNATURE: Link ID (1) + Timestamp (6) + Signature (6)
pub(crate) const LINK_ID_SIZE: usize = 1;
pub(crate) const TIMESTAMP_SIZE: usize = 6;
pub(crate) const SIGNATURE_FIELD_SIZE: usize = 6;
pub(crate) const SIGNATURE_SIZE: usize = LINK_ID_SIZE + TIMESTAMP_SIZE + SIGNATURE_FIELD_SIZE;

// Total Frame Size: 280 bytes
pub const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_PAYLOAD_SIZE + CHECKSUM_SIZE + SIGNATURE_SIZE;
