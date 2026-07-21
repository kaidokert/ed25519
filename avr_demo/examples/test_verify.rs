#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use avr_demo as _;
use avr_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};
#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;
use krabi_caliper::avr::FootprintConfig;
use krabi_caliper::report::{Field, UfmtReporter};

#[arduino_hal::entry]
fn main() -> ! {
    let mut dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let serial = arduino_hal::default_serial!(dp, pins, 57600);

    let fields = [Field::token("target", "atmega2560")];
    let mut reporter = UfmtReporter::new(serial);
    // SAFETY: ATmega2560 SRAM above `_end` is reserved for this single stack.
    unsafe {
        krabi_caliper::avr::run_atmega2560_footprint::<64, _>(
            &mut dp.TC1,
            &mut reporter,
            FootprintConfig::new("ed25519-footprint", &fields).sentinel(0xce),
            || {
                #[cfg(feature = "baseline")]
                {
                    avr_demo::fake_verify(PUBLIC_KEY, MESSAGE, SIGNATURE)
                }
                #[cfg(not(feature = "baseline"))]
                {
                    ed25519_heapless::verify::<FixedUInt<u8, 32>>(PUBLIC_KEY, MESSAGE, SIGNATURE)
                }
            },
        )
    }
    .unwrap();
    krabi_caliper::avr::park_simavr(&dp.CPU)
}
