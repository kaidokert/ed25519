#![no_main]
#![no_std]

#[cfg(not(feature = "baseline"))]
use const_num_traits::Ct;
use cortex_m_demo::{ALICE_PRIVATE, BOB_PUBLIC, EXPECTED_SHARED};
use cortex_m_rt::entry;
#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        || {
            #[cfg(feature = "baseline")]
            {
                cortex_m_demo::fake_x25519(ALICE_PRIVATE, BOB_PUBLIC) == EXPECTED_SHARED
            }
            #[cfg(not(feature = "baseline"))]
            {
                ed25519_heapless::x25519::<FixedUInt<u8, 32, Ct>>(&ALICE_PRIVATE, &BOB_PUBLIC)
                    == EXPECTED_SHARED
            }
        },
        "x25519",
        "u8",
    );
    loop {}
}
