#![no_main]
#![no_std]

use cortex_m_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};
use cortex_m_rt::entry;
#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        || {
            #[cfg(feature = "baseline")]
            {
                cortex_m_demo::fake_verify(PUBLIC_KEY, MESSAGE, SIGNATURE)
            }
            #[cfg(not(feature = "baseline"))]
            {
                ed25519_heapless::verify::<FixedUInt<u32, 16>>(PUBLIC_KEY, MESSAGE, SIGNATURE)
            }
        },
        "u32",
    );
    loop {}
}
