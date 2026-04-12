use heapless::Vec;

use super::constants::*;
use super::checksum::*;

pub struct MavLinkFrame {
    // Header fields
    pub stx: u8,
    pub len: u8,
    pub inc_flags: u8,
    pub cmp_flags: u8,
    pub seq: u8,
    pub sys_id: u8,
    pub comp_id: u8,
    pub msg_id: [u8; 3],

    // Payload
    pub payload: Vec<u8, MAX_PAYLOAD_SIZE>,

    // Checksum
    pub checksum: [u8; CHECKSUM_SIZE],

    // Signature
    pub link_id: u8,
    pub timestamp: [u8; TIMESTAMP_SIZE],
    pub signature: [u8; SIGNATURE_FIELD_SIZE],
}


impl MavLinkFrame {
    // Constructor for creating a new MAVLink frame
    pub fn new(
        cmp_flags: u8, 
        seq: u8, 
        sys_id: u8, 
        comp_id: u8, 
        msg_id: [u8; 3],
        payload: Vec<u8, MAX_PAYLOAD_SIZE>,
        checksum: [u8; CHECKSUM_SIZE],
        link_id: u8,
        timestamp: [u8; TIMESTAMP_SIZE],    
    ) -> Self {
        MavLinkFrame {
            stx: 0xFD, // Start of Frame
            len: payload.len() as u8,
            inc_flags: 0, // 0 => normal packer, 1 => include signature
            cmp_flags,
            seq,
            sys_id,
            comp_id,
            msg_id,
            payload,
            checksum,
            link_id,
            timestamp,
            signature: [0; SIGNATURE_FIELD_SIZE], // Placeholder, set after signing
        }
    }

    pub fn compute_checksum(&self, crc_extra: u8) -> [u8; CHECKSUM_SIZE] {
        let mut crc: u16 = 0xFFFF;
        for &b in &[self.len, self.inc_flags, self.cmp_flags, self.seq, self.sys_id, self.comp_id] {
            crc = crc_accumulate(b, crc);
        }
        for &b in &self.msg_id {
            crc = crc_accumulate(b, crc);
        }
        for &b in self.payload.iter() {
            crc = crc_accumulate(b, crc);
        }
        crc = crc_accumulate(crc_extra, crc);
        [(crc & 0xFF) as u8, (crc >> 8) as u8]
    }

    pub fn set_checksum(&mut self, crc_extra: u8) {
        self.checksum = self.compute_checksum(crc_extra);
    }

    // Method to parse a MAVLink frame from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_SIZE + CHECKSUM_SIZE {
            return None; // Not enough data for header and checksum
        }

        if bytes[0] != 0xFD {
            return None; // Invalid start of frame
        }

        let len = bytes[1] as usize;
        let inc_flags = bytes[2];
        let has_sig = (inc_flags & SIGNED_FLAG) != 0;

        // Calculate expected total length
        let expected_len = HEADER_SIZE + len + CHECKSUM_SIZE + if has_sig { SIGNATURE_SIZE } else { 0 };

        if bytes.len() < expected_len {
            return None; // Not enough data for full frame
        }

        let mut payload: Vec<u8, MAX_PAYLOAD_SIZE> = Vec::new();
        for &b in &bytes[HEADER_SIZE..HEADER_SIZE + len] {
            payload.push(b).ok()?;
        }

        Some(Self {
            stx: bytes[0],
            len: bytes[1],
            inc_flags,
            cmp_flags: bytes[3],
            seq: bytes[4],
            sys_id: bytes[5],
            comp_id: bytes[6],
            msg_id: [bytes[7], bytes[8], bytes[9]],
            payload,
            checksum: [bytes[HEADER_SIZE + len], bytes[HEADER_SIZE + len + 1]],
            link_id: if has_sig { bytes[HEADER_SIZE + len + CHECKSUM_SIZE] } else { 0 },
            timestamp: if has_sig { 
                let mut ts = [0; TIMESTAMP_SIZE];
                ts.copy_from_slice(&bytes[HEADER_SIZE + len + CHECKSUM_SIZE + LINK_ID_SIZE..HEADER_SIZE + len + CHECKSUM_SIZE + LINK_ID_SIZE + TIMESTAMP_SIZE]);
                ts
            } else { [0; TIMESTAMP_SIZE] },
            signature: if has_sig {
                let mut sig = [0; SIGNATURE_FIELD_SIZE];
                sig.copy_from_slice(&bytes[HEADER_SIZE + len + CHECKSUM_SIZE + LINK_ID_SIZE + TIMESTAMP_SIZE..expected_len]);
                sig
            } else { [0; SIGNATURE_FIELD_SIZE] },
        })
    }

    // Method to serialize the MAVLink frame into bytes
    pub fn to_bytes(&self) -> Vec<u8, MAX_FRAME_SIZE> {
        let mut bytes: Vec<u8, MAX_FRAME_SIZE> = Vec::new();

        // Header
        bytes.extend_from_slice(&[
            self.stx,
            self.len,
            self.inc_flags,
            self.cmp_flags,
            self.seq,
            self.sys_id,
            self.comp_id,
        ]).ok();

        bytes.extend_from_slice(&self.msg_id).ok();

        // Payload and Checksum
        bytes.extend_from_slice(&self.payload).ok();
        bytes.extend_from_slice(&self.checksum).ok();

        // Signature (if included)
        if (self.inc_flags & SIGNED_FLAG) != 0 {
            bytes.push(self.link_id).ok();
            bytes.extend_from_slice(&self.timestamp).ok();
            bytes.extend_from_slice(&self.signature).ok();
        }

        bytes
    }
}