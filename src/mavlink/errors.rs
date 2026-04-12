

#[derive(Debug, PartialEq, defmt::Format)]
pub enum VerifyError {
    NotSigned,       // inc_flags SIGNED_FLAG bit not set
    WrongLink,       // link_id does not match expected physical link
    HmacMismatch,    // HMAC verification failed — wrong key or tampered frame
    FutureTimestamp, // frame timestamp is ahead of current time
    TooOld,          // frame timestamp is outside the replay window
    Replay,          // timestamp is not strictly greater than last accepted
}