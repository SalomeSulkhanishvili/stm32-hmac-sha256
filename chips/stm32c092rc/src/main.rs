#![no_std]
#![no_main]

use cortex_m_rt::entry;
use defmt::info;
use {defmt_rtt as _, panic_probe as _};

use heapless::Vec;
use mavlink::mavlink::{MavLinkFrame, MavLinkState, sign_frame, verify_frame, crc_extra_for};


#[entry]
fn main() -> ! {
    info!("MAVLink signing demo");

    // simple key for testing
    let key = b"\xaa\x53\x4a\x45\x7a\xb5\xe0\x43\x53\x0f\x82\xaa\x5c\x20\xf8\xd9\xd6\x71\xdd\xa7\x84\xaf\x5c\x40\x93\x1e\x70\x65\x58\x40\xfe\x67";

    let mut payload = Vec::new();
    payload.push(0x01).unwrap();
    payload.push(0x02).unwrap();
    payload.push(0x03).unwrap();

    let msg_id = [0x00, 0x00, 0x00];
    let crc_extra = crc_extra_for(msg_id).expect("unknown msg_id");

    let mut frame = MavLinkFrame::new(
        0x00,
        1,
        22,
        1,
        msg_id,
        payload,
        [0x00, 0x00],
        0,
        [10, 0, 0, 0, 0, 0],
    );

    sign_frame(&mut frame, key, crc_extra);
    info!("Frame signed");

    let current_ts = [20, 0, 0, 0, 0, 0];
    let mut state = MavLinkState::new(0);

    match verify_frame(&frame, key, &current_ts, &mut state, crc_extra) {
        Ok(())   => info!("Verification passed"),
        Err(e)   => info!("Verification FAILED: {}", e),
    }

    loop {
        cortex_m::asm::nop();
    }
}
