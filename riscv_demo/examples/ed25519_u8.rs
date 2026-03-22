#![no_main]
#![no_std]

#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;
use riscv_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};

#[riscv_rt::entry]
fn main() -> ! {
    riscv_demo::test_fixture(
        || {
            #[cfg(feature = "baseline")]
            {
                riscv_demo::fake_verify(PUBLIC_KEY, MESSAGE, SIGNATURE)
            }
            #[cfg(not(feature = "baseline"))]
            {
                ed25519_heapless::verify::<FixedUInt<u8, 32>>(PUBLIC_KEY, MESSAGE, SIGNATURE)
            }
        },
        "u8",
    );
}
