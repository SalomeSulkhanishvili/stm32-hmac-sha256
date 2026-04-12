

// Example CRC extra values for common MAVLink messages (msg_id as 3-byte array)
pub fn crc_extra_for(msg_id: [u8; 3]) -> Option<u8> {
    match msg_id {
        [0, 0, 0]   => Some(50),  // HEARTBEAT
        [1, 0, 0]   => Some(124), // SYS_STATUS
        [2, 0, 0]   => Some(137), // SYSTEM_TIME
        [3, 0, 0]   => Some(237), // PING
        [4, 0, 0]   => Some(237), // MOTOR_STATUS
        _           => None,
    }
}

// MAVLink 2.0 CRC-16/MCRF4XX implementation
pub fn crc_accumulate(data: u8, crc: u16) -> u16 {
    let tmp = (data ^ (crc as u8)) as u16;
    let tmp2 = tmp ^ (tmp << 4);
    (crc >> 8) ^ (tmp2 << 8) ^ (tmp2 << 3) ^ (tmp2 >> 4)
}