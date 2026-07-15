#![no_main]
#![no_std]

use const_num_traits::Ct;
use core::hint::black_box;
use cortex_m::peripheral::DWT;
use cortex_m_rt::entry;
use ed25519_heapless::{SigningKey, sign, x25519, x25519_base};
use fixed_bigint::FixedUInt;
use rtt_target::{rprintln, rtt_init_print};

const TRIALS: usize = 4;
// Calibrated on the STM32F407/J-Trace path: positive operations varied by
// 7–20 cycles over 26–477 million-cycle calls, with overlapping A/B ranges.
// Keep this absolute and deliberately small; every raw bound is reported.
const MAX_POSITIVE_SPREAD: u32 = 32;
const ORDER: [bool; TRIALS * 2] = [false, true, true, false, true, false, false, true];

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

#[derive(Clone, Copy)]
struct Samples {
    a: [u32; TRIALS],
    b: [u32; TRIALS],
    outputs_ok: bool,
}

#[inline(always)]
fn measure_once(mut operation: impl FnMut() -> bool) -> (u32, bool) {
    cortex_m::interrupt::free(|_| {
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        let start = DWT::cycle_count();
        let ok = operation();
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        let elapsed = DWT::cycle_count().wrapping_sub(start);
        (elapsed, ok)
    })
}

fn measure_pair(mut operation: impl FnMut(&[u8; 32]) -> bool) -> Samples {
    // Equal warm-up for flash/ART state before the recorded ABBA sequence.
    let _ = black_box(operation(black_box(&SECRET_A)));
    let _ = black_box(operation(black_box(&SECRET_B)));
    let _ = black_box(operation(black_box(&SECRET_B)));
    let _ = black_box(operation(black_box(&SECRET_A)));

    let mut samples = Samples {
        a: [0; TRIALS],
        b: [0; TRIALS],
        outputs_ok: true,
    };
    let mut ai = 0;
    let mut bi = 0;
    for use_b in ORDER {
        let secret = if use_b { &SECRET_B } else { &SECRET_A };
        let (cycles, ok) = measure_once(|| operation(black_box(secret)));
        samples.outputs_ok &= ok;
        if use_b {
            samples.b[bi] = cycles;
            bi += 1;
        } else {
            samples.a[ai] = cycles;
            ai += 1;
        }
    }
    samples
}

fn bounds(values: &[u32; TRIALS]) -> (u32, u32) {
    let mut min = u32::MAX;
    let mut max = 0;
    for &value in values {
        min = min.min(value);
        max = max.max(value);
    }
    (min, max)
}

fn report(name: &str, class: &str, samples: Samples, expect_equal: bool) -> bool {
    let (a_min, a_max) = bounds(&samples.a);
    let (b_min, b_max) = bounds(&samples.b);
    let combined_min = a_min.min(b_min);
    let combined_max = a_max.max(b_max);
    let spread = combined_max - combined_min;
    let ranges_overlap = a_min <= b_max && b_min <= a_max;
    let timing_ok = if expect_equal {
        ranges_overlap && spread <= MAX_POSITIVE_SPREAD
    } else {
        a_max < b_min || b_max < a_min
    };
    let passed = samples.outputs_ok && timing_ok;
    rprintln!(
        "CT_RESULT fixture:{} carrier:{} class:{} a_min:{} a_max:{} b_min:{} b_max:{} spread:{} output_ok:{} status:{}",
        name,
        CARRIER,
        class,
        a_min,
        a_max,
        b_min,
        b_max,
        spread,
        samples.outputs_ok as u8,
        if passed { "PASS" } else { "FAIL" }
    );
    passed
}

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
    rtt_init_print!();
    let mut peripherals = cortex_m::Peripherals::take().unwrap();
    assert!(DWT::has_cycle_counter());
    peripherals.DCB.enable_trace();
    peripherals.DWT.set_cycle_count(0);
    peripherals.DWT.enable_cycle_counter();
    cortex_m::asm::dsb();
    cortex_m::asm::isb();

    rprintln!(
        "CT_BEGIN suite:ed25519-cyccnt carrier:{} trials:{} max_positive_spread:{}",
        CARRIER,
        TRIALS,
        MAX_POSITIVE_SPREAD
    );
    let mut passed = 0u32;
    let mut failed = 0u32;
    for ok in [
        report(
            "signing_key_from_seed",
            "positive",
            measure_pair(fixture_keygen),
            true,
        ),
        report("sign", "positive", measure_pair(fixture_sign), true),
        report("x25519", "positive", measure_pair(fixture_x25519), true),
        report(
            "x25519_base",
            "positive",
            measure_pair(fixture_x25519_base),
            true,
        ),
        report(
            "negative_early_exit",
            "negative",
            measure_pair(fixture_negative_early_exit),
            false,
        ),
    ] {
        if ok { passed += 1 } else { failed += 1 }
    }
    rprintln!(
        "CT_SUMMARY carrier:{} passed:{} failed:{}",
        CARRIER,
        passed,
        failed
    );
    loop {
        cortex_m::asm::nop();
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    rprintln!("PANIC: {}", info);
    loop {
        cortex_m::asm::nop();
    }
}
