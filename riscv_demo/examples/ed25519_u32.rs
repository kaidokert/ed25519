#![no_main]
#![no_std]

#[cfg(not(feature = "baseline"))]
use fixed_bigint::FixedUInt;
use riscv_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};
#[cfg(not(feature = "baseline"))]
use signature::Verifier;

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
                ed25519_heapless::VerifyingKey::<FixedUInt<u32, 16>>::from_bytes(PUBLIC_KEY)
                    .verify(MESSAGE, &SIGNATURE)
                    .is_ok()
            }
        },
        "u32",
    );
}
