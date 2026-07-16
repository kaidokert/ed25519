#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use avr_demo as _;
use avr_demo::stack_measurement::*;
use avr_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};
use embedded_measure::report::{Field, StackRecord, write_stack_ufmt};
#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    // Use TC1 (16-bit) in normal mode, prescaler 1024 → 15625 Hz at 16MHz
    // Max measurable: 65536/15625 = 4.19 seconds. 1 tick = 64µs.
    let tc1 = &dp.TC1;
    tc1.tccr1b.write(|w| w.cs1().prescale_1024());

    let stack_probe = fill_stack_with_watermark();

    let start: u16 = tc1.tcnt1.read().bits();
    let result = {
        #[cfg(feature = "baseline")]
        {
            avr_demo::fake_verify(PUBLIC_KEY, MESSAGE, SIGNATURE)
        }
        #[cfg(not(feature = "baseline"))]
        {
            ed25519_heapless::verify::<FixedUInt<u8, 32>>(PUBLIC_KEY, MESSAGE, SIGNATURE)
        }
    };
    let end: u16 = tc1.tcnt1.read().bits();

    let stack = measure_stack(&stack_probe);
    write_stack_ufmt(
        &mut serial,
        &StackRecord {
            benchmark: "ed25519-footprint",
            measurement: stack,
            fields: &[Field::token("target", "atmega2560")],
        },
    )
    .unwrap();

    // ticks * 1000 / 15625 = ms, but use integer math: ticks * 8 / 125
    let ticks = end.wrapping_sub(start);
    let ms = (ticks as u32) * 8 / 125;

    if result {
        ufmt::uwriteln!(&mut serial, "ACCEPT").ok();
    } else {
        ufmt::uwriteln!(&mut serial, "REJECT").ok();
    }
    ufmt::uwriteln!(&mut serial, "Time: {} ms ({} ticks)", ms, ticks).ok();
    ufmt::uwriteln!(
        &mut serial,
        "Max stack usage: {} bytes",
        stack.high_water_bytes
    )
    .ok();

    loop {
        unsafe { core::arch::asm!("sleep") }
    }
}
