#![no_main]
#![no_std]

use fixed_bigint::FixedUInt;
use riscv_demo::{MESSAGE, PUBLIC_KEY, SIGNATURE};

#[riscv_rt::entry]
fn main() -> ! {
    riscv_demo::test_fixture(
        || ed25519_heapless::verify::<FixedUInt<u8, 32>>(PUBLIC_KEY, MESSAGE, SIGNATURE),
        "u8",
    );
}
