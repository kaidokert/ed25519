#![no_main]
#![no_std]

use cortex_m_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};
use cortex_m_rt::entry;
use fixed_bigint::FixedUInt;

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        || ed25519_heapless::verify::<FixedUInt<u8, 32>>(PUBLIC_KEY, MESSAGE, SIGNATURE),
        "u8",
    );
    loop {}
}
