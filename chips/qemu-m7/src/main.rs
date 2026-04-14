#![no_std]
#![no_main]

use cortex_m_rt::entry;

#[cfg(feature = "logging")]
use {defmt_semihosting as _, panic_semihosting as _};
#[cfg(not(feature = "logging"))]
use panic_halt as _;

use heapless::Vec;
use mavlink::mavlink::{MavLinkFrame, MavLinkState, sign_frame, verify_frame};


#[entry]
fn main() -> ! {
    #[cfg(feature = "logging")]
    defmt::info!("MAVLink signing demo");

    // simple key for testing
    let key = b"\xaa\x53\x4a\x45\x7a\xb5\xe0\x43\x53\x0f\x82\xaa\x5c\x20\xf8\xd9\xd6\x71\xdd\xa7\x84\xaf\x5c\x40\x93\x1e\x70\x65\x58\x40\xfe\x67";

    let mut payload = Vec::new();
    payload.push(0x01).unwrap();
    payload.push(0x02).unwrap();
    payload.push(0x03).unwrap();

    let mut frame = MavLinkFrame::new(
        0x00,
        1,
        22,
        1,
        [0x00, 0x00, 0x00],
        payload,
        [0x00, 0x00],
        0,
        [10, 0, 0, 0, 0, 0],
    );

    sign_frame(&mut frame, key).expect("sign_frame failed");
    #[cfg(feature = "logging")]
    defmt::info!("Frame signed");

    let current_ts = [20, 0, 0, 0, 0, 0];
    let mut state = MavLinkState::new(0);

    #[cfg(feature = "logging")]
    match verify_frame(&frame, key, &current_ts, &mut state) {
        Ok(())  => defmt::info!("Verification passed"),
        Err(e)  => defmt::info!("Verification FAILED: {}", e),
    }
    #[cfg(not(feature = "logging"))]
    let _ = verify_frame(&frame, key, &current_ts, &mut state);

    loop {
        cortex_m::asm::nop();
    }
}
