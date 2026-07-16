#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use avr_demo as _;
use avr_demo::stack_measurement::*;
use avr_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};
use embedded_measure::avr::timer_measurement;
use embedded_measure::report::{
    Field, MeasurementRecord, StackRecord, write_measurement_ufmt, write_stack_ufmt,
};
#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    let tc1 = &dp.TC1;

    let stack_probe = fill_stack_with_watermark();

    let counter = avr_demo::cyclecount::CycleCounter::start(tc1);
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
    let ticks = counter.elapsed_ticks(tc1);

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
    write_measurement_ufmt(
        &mut serial,
        &MeasurementRecord {
            benchmark: "ed25519-footprint",
            measurement: timer_measurement(ticks, 15_625, false),
            fields: &[Field::token("target", "atmega2560")],
        },
    )
    .unwrap();

    let ms = ticks * 8 / 125;

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
