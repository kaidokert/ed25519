#![no_main]
#![no_std]

use cortex_m_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};
use cortex_m_rt::entry;
#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;
#[cfg(not(feature = "baseline"))]
use signature::Verifier;

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
                ed25519_heapless::VerifyingKey::<FixedUInt<u8, 32>>::from_bytes(PUBLIC_KEY)
                    .verify(MESSAGE, &SIGNATURE)
                    .is_ok()
            }
        },
        "ed25519",
        "u8",
    );
    loop {}
}
