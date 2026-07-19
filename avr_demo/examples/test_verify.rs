#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use avr_demo as _;
use avr_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};
#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;
use krabi_caliper::avr::timer_measurement;
use krabi_caliper::report::{Field, UfmtReporter};

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let serial = arduino_hal::default_serial!(dp, pins, 57600);

    let tc1 = &dp.TC1;

    // SAFETY: ATmega2560 SRAM above `_end` is reserved for this single stack.
    let stack_probe =
        unsafe { krabi_caliper::stack::paint_avr_runtime::<64>(0x2200, 0xce) }.unwrap();

    let counter = krabi_caliper::avr::Atmega2560Timer1Counter::start(tc1);
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
    let ticks = counter.elapsed_ticks();

    let stack = stack_probe.measure();
    let fields = [Field::token("target", "atmega2560")];
    let mut reporter = UfmtReporter::new(serial);
    krabi_caliper::report_completed!(
        &mut reporter,
        benchmark: "ed25519-footprint",
        passed: result,
        fields: &fields,
        stack: stack,
        measurements: [("timer1", timer_measurement(ticks, 15_625, false))]
    )
    .unwrap();
    let mut serial = reporter.into_inner();

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
