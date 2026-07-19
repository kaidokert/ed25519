#![no_main]
#![no_std]

use const_num_traits::Ct;
use core::hint::black_box;
use cortex_m_rt::entry;
use ed25519_heapless::{SigningKey, sign, x25519, x25519_base};
use krabi_caliper::cortex_m::DwtCycleCounter;
use krabi_caliper::report::Field;
use krabi_caliper::suite::{PairedSuite, PairedSuiteConfig, PairedSuiteFields};
use fixed_bigint::FixedUInt;

const TRIALS: usize = 4;
const BATCHES: usize = 1;
// Calibrated on the STM32F407/J-Trace path: positive operations varied by
// 7–20 cycles over 26–477 million-cycle calls, with overlapping A/B ranges.
// Keep this absolute and deliberately small; every raw bound is reported.
const MAX_POSITIVE_SPREAD: u32 = 32;

const SECRET_A: [u8; 32] = [0; 32];
const SECRET_B: [u8; 32] = [
    0x55, 0xaa, 0x33, 0xcc, 0x0f, 0xf0, 0x69, 0x96, 0xa5, 0x5a, 0x3c, 0xc3, 0x87, 0x78, 0x1e, 0xe1,
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];
const PUBLIC_U: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const _: () = assert!(
    cfg!(feature = "carrier-u32x8") as usize
        + cfg!(feature = "carrier-u32x16") as usize
        + cfg!(feature = "carrier-u8x32") as usize
        == 1,
    "enable exactly one carrier feature",
);

#[cfg(feature = "carrier-u32x8")]
type Carrier = FixedUInt<u32, 8, Ct>;
#[cfg(feature = "carrier-u32x8")]
const CARRIER: &str = "u32x8";

#[cfg(feature = "carrier-u32x16")]
type Carrier = FixedUInt<u32, 16, Ct>;
#[cfg(feature = "carrier-u32x16")]
const CARRIER: &str = "u32x16";

#[cfg(feature = "carrier-u8x32")]
type Carrier = FixedUInt<u8, 32, Ct>;
#[cfg(feature = "carrier-u8x32")]
const CARRIER: &str = "u8x32";

#[inline(never)]
fn fixture_keygen(seed: &[u8; 32]) -> bool {
    match SigningKey::<Carrier>::from_seed(black_box(seed)) {
        Ok(key) => {
            let _ = black_box(key.public_key());
            true
        }
        Err(_) => false,
    }
}

#[inline(never)]
fn fixture_sign(seed: &[u8; 32]) -> bool {
    let Ok(key) = SigningKey::<Carrier>::from_seed(black_box(seed)) else {
        return false;
    };
    match sign(black_box(&key), black_box(b"CYCCNT fixture message")) {
        Ok(signature) => {
            let _ = black_box(signature);
            true
        }
        Err(_) => false,
    }
}

#[inline(never)]
fn fixture_x25519(secret: &[u8; 32]) -> bool {
    let output = x25519::<Carrier>(black_box(secret), black_box(&PUBLIC_U));
    let _ = black_box(output);
    true
}

#[inline(never)]
fn fixture_x25519_base(secret: &[u8; 32]) -> bool {
    let output = x25519_base::<Carrier>(black_box(secret));
    let _ = black_box(output);
    true
}

#[inline(never)]
fn fixture_negative_early_exit(secret: &[u8; 32]) -> bool {
    let mut leading_zeroes = 0u32;
    for &byte in black_box(secret).iter() {
        if byte != 0 {
            break;
        }
        leading_zeroes += 1;
    }
    let _ = black_box(leading_zeroes);
    true
}

#[entry]
fn main() -> ! {
    let mut reporter = krabi_caliper::rtt::init_ct_compatible();
    let mut peripherals = cortex_m::Peripherals::take().unwrap();
    let mut counter =
        DwtCycleCounter::enable(&mut peripherals.DCB, &mut peripherals.DWT, Some(16_000_000))
            .unwrap();
    let run_fields = [
        Field::token("carrier", CARRIER),
        Field::u64("trials", TRIALS as u64),
        Field::u64("max_positive_spread", MAX_POSITIVE_SPREAD as u64),
    ];
    let fixture_fields = [Field::token("carrier", CARRIER)];
    let summary_fields = [Field::token("carrier", CARRIER)];
    let mut suite = PairedSuite::<_, _, TRIALS>::start(
        &mut counter,
        &mut reporter,
        PairedSuiteConfig {
            suite: "ed25519-cyccnt",
            target: "thumbv7em-none-eabihf",
            board: Some("stm32f407vg"),
            unit: krabi_caliper::Unit::CoreCycles,
            frequency_hz: Some(16_000_000),
            warmup_blocks: 1,
            batches: BATCHES,
            positive_max_spread: MAX_POSITIVE_SPREAD as u64,
            positive_require_overlap: true,
            fields: PairedSuiteFields {
                run: &run_fields,
                fixture: &fixture_fields,
                summary: &summary_fields,
            },
        },
    )
    .unwrap();
    suite
        .positive(
            "signing_key_from_seed",
            &SECRET_A,
            &SECRET_B,
            fixture_keygen,
        )
        .unwrap();
    suite
        .positive("sign", &SECRET_A, &SECRET_B, fixture_sign)
        .unwrap();
    suite
        .positive("x25519", &SECRET_A, &SECRET_B, fixture_x25519)
        .unwrap();
    suite
        .positive("x25519_base", &SECRET_A, &SECRET_B, fixture_x25519_base)
        .unwrap();
    suite
        .negative(
            "negative_early_exit",
            &SECRET_A,
            &SECRET_B,
            fixture_negative_early_exit,
        )
        .unwrap();
    suite.finish().unwrap();
    loop {
        cortex_m::asm::nop();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    krabi_caliper::rtt::print(format_args!("PANIC: {}\n", info));
    loop {
        cortex_m::asm::nop();
    }
}
