
use super::constants::TIMESTAMP_SIZE;

pub struct MavLinkState {
    pub last_accepted_timestamp: [u8; TIMESTAMP_SIZE],
    pub expected_link_id: u8,
}


impl MavLinkState {
    pub fn new(expected_link_id: u8) -> Self {
        Self {
            last_accepted_timestamp: [0; TIMESTAMP_SIZE],
            expected_link_id,
        }
    }

    pub fn update_timestamp(&mut self, timestamp: [u8; TIMESTAMP_SIZE]) {
        self.last_accepted_timestamp = timestamp;
    }
}