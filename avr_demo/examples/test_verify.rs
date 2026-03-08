#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use avr_demo as _;
use avr_demo::stack_measurement::*;
use fixed_bigint::FixedUInt;

// --- Test vectors ---

const PUBLIC_KEY: [u8; 32] = [
    0x33, 0xbc, 0x91, 0xa3, 0xca, 0xb8, 0x87, 0xc8, 0xbf, 0x3c, 0x63, 0x61, 0x46, 0xd2, 0xe3, 0x8d,
    0x58, 0xd0, 0xca, 0xf3, 0x3b, 0x77, 0x86, 0x25, 0xc7, 0x95, 0x2b, 0xc7, 0x6f, 0xc0, 0x73, 0xac,
];
const SIGNATURE: [u8; 64] = [
    0x2f, 0xec, 0x62, 0xdf, 0x49, 0x4f, 0xf5, 0x70, 0x5f, 0x5c, 0xee, 0x45, 0xbc, 0x5e, 0x89, 0xc2,
    0x32, 0xc1, 0x61, 0x88, 0x37, 0x87, 0xce, 0x50, 0xa2, 0x9b, 0xe8, 0x8c, 0xb1, 0x92, 0xc8, 0x81,
    0x25, 0x62, 0x74, 0xed, 0xd7, 0x67, 0x2a, 0xa5, 0x52, 0x79, 0x57, 0xeb, 0x0d, 0xdc, 0x0e, 0x60,
    0x95, 0x23, 0x74, 0x36, 0x22, 0x32, 0x85, 0xf6, 0xd9, 0x30, 0x6b, 0x96, 0x63, 0x14, 0x86, 0x02,
];
const MESSAGE: &[u8] = b"Hello world!\n";

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    // Use TC1 (16-bit) in normal mode, prescaler 1024 → 15625 Hz at 16MHz
    // Max measurable: 65536/15625 = 4.19 seconds. 1 tick = 64µs.
    let tc1 = &dp.TC1;
    tc1.tccr1b.write(|w| w.cs1().prescale_1024());

    unsafe { fill_stack_with_watermark() };

    let start: u16 = tc1.tcnt1.read().bits();
    let result = ed25519_heapless::verify::<FixedUInt<u8, 32>>(PUBLIC_KEY, MESSAGE, SIGNATURE);
    let end: u16 = tc1.tcnt1.read().bits();

    let stack_used = unsafe { measure_stack_usage() };

    // ticks * 1000 / 15625 = ms, but use integer math: ticks * 8 / 125
    let ticks = end.wrapping_sub(start);
    let ms = (ticks as u32) * 8 / 125;

    if result {
        ufmt::uwriteln!(&mut serial, "ACCEPT").ok();
    } else {
        ufmt::uwriteln!(&mut serial, "REJECT").ok();
    }
    ufmt::uwriteln!(&mut serial, "Time: {} ms ({} ticks)", ms, ticks).ok();
    ufmt::uwriteln!(&mut serial, "Max stack usage: {} bytes", stack_used).ok();

    loop {
        unsafe { core::arch::asm!("sleep") }
    }
}
