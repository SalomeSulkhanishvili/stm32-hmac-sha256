
#[cfg_attr(not(test), derive(defmt::Format))]
#[derive(Debug, PartialEq)]
pub enum SignError {
    InvalidKey,      // secret key is not 32 bytes
    UnknownMessage,  // msg_id has no registered crc_extra
}

#[cfg_attr(not(test), derive(defmt::Format))]
#[derive(Debug, PartialEq)]
pub enum VerifyError {
    NotSigned,        // inc_flags SIGNED_FLAG bit not set
    WrongLink,        // link_id does not match expected physical link
    InvalidKey,       // secret key is not 32 bytes
    ChecksumMismatch, // CRC-16 over header+payload does not match
    HmacMismatch,     // HMAC verification failed - wrong key or tampered frame
    FutureTimestamp,  // frame timestamp is ahead of current time
    TooOld,           // frame timestamp is outside the replay window
    Replay,           // timestamp is not strictly greater than last accepted
    UnknownMessage,   // msg_id has no registered crc_extra
}