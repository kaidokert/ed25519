#![no_std]

use core::{fmt::Write, hint::black_box};
use embedded_measure::report::{Field, MeasurementRecord, Reporter, StackRecord, TextReporter};
#[cfg(feature = "jtrace-f407")]
use embedded_measure::rtt::RttWriter as OutputWriter;
#[cfg(not(feature = "jtrace-f407"))]
use embedded_measure::semihosting::SemihostingWriter as OutputWriter;
use embedded_measure::{Measurement, Unit};

pub mod cyclecount;
pub mod stack;

// Ed25519 test vector ("Hello world!\n" / kaidokert key)
pub const PUBLIC_KEY: [u8; 32] = [
    0x33, 0xbc, 0x91, 0xa3, 0xca, 0xb8, 0x87, 0xc8, 0xbf, 0x3c, 0x63, 0x61, 0x46, 0xd2, 0xe3, 0x8d,
    0x58, 0xd0, 0xca, 0xf3, 0x3b, 0x77, 0x86, 0x25, 0xc7, 0x95, 0x2b, 0xc7, 0x6f, 0xc0, 0x73, 0xac,
];
pub const SIGNATURE: [u8; 64] = [
    0x2f, 0xec, 0x62, 0xdf, 0x49, 0x4f, 0xf5, 0x70, 0x5f, 0x5c, 0xee, 0x45, 0xbc, 0x5e, 0x89, 0xc2,
    0x32, 0xc1, 0x61, 0x88, 0x37, 0x87, 0xce, 0x50, 0xa2, 0x9b, 0xe8, 0x8c, 0xb1, 0x92, 0xc8, 0x81,
    0x25, 0x62, 0x74, 0xed, 0xd7, 0x67, 0x2a, 0xa5, 0x52, 0x79, 0x57, 0xeb, 0x0d, 0xdc, 0x0e, 0x60,
    0x95, 0x23, 0x74, 0x36, 0x22, 0x32, 0x85, 0xf6, 0xd9, 0x30, 0x6b, 0x96, 0x63, 0x14, 0x86, 0x02,
];
pub const MESSAGE: &[u8] = b"Hello world!\n";

// X25519 test vector (RFC 7748 §6.1: Alice's priv × Bob's pub -> shared secret)
pub const ALICE_PRIVATE: [u8; 32] = [
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
];
pub const BOB_PUBLIC: [u8; 32] = [
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
];
pub const EXPECTED_SHARED: [u8; 32] = [
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
];

use cyclecount::CycleCounter;
use stack::paint_stack;

pub fn target_arch_name() -> &'static str {
    #[cfg(thumbv6m)]
    {
        "thumbv6m"
    }
    #[cfg(thumbv7m)]
    {
        "thumbv7m"
    }
    #[cfg(thumbv7em)]
    {
        "thumbv7em"
    }
}

pub fn test_fixture(testable: fn() -> bool, algo: &str, backend: &str) {
    let stack_probe = paint_stack::<256>();
    let counter = CycleCounter::new();
    let result = testable();
    let measurement = counter.elapsed();
    // Cycle counts are printed in thousands so the METRIC line stays compact;
    // consumers (run_suite.py) treat the `cycles:` field as "k" units.
    let elapsed = measurement.systick / 1000;
    let stack = stack_probe.measure();
    let fields = [
        Field::token("target", target_arch_name()),
        Field::token("algo", algo),
        Field::token("backend", backend),
    ];

    #[cfg(not(feature = "jtrace-f407"))]
    let mut output: OutputWriter = embedded_measure::semihosting::init().unwrap().into_inner();
    #[cfg(feature = "jtrace-f407")]
    let mut output: OutputWriter = embedded_measure::rtt::init_blocking().into_inner();
    let mut reporter = TextReporter::new(&mut output);
    reporter
        .stack_measurement(&StackRecord {
            benchmark: "ed25519-footprint",
            measurement: stack,
            fields: &fields,
        })
        .unwrap();
    let cycles = Measurement::new(measurement.systick, Unit::CoreCycles);
    #[cfg(feature = "jtrace-f407")]
    let cycles = cycles.with_frequency(16_000_000);
    let systick_fields = [
        Field::token("target", target_arch_name()),
        Field::token("algo", algo),
        Field::token("backend", backend),
        Field::token("counter", "systick"),
    ];
    reporter
        .measurement(&MeasurementRecord {
            benchmark: "ed25519-footprint",
            measurement: cycles,
            fields: &systick_fields,
        })
        .unwrap();
    #[cfg(feature = "jtrace-f407")]
    reporter
        .measurement(&MeasurementRecord {
            benchmark: "ed25519-footprint",
            measurement: Measurement::new(measurement.dwt as u64, Unit::CoreCycles)
                .with_frequency(16_000_000),
            fields: &[
                Field::token("target", target_arch_name()),
                Field::token("algo", algo),
                Field::token("backend", backend),
                Field::token("counter", "dwt"),
            ],
        })
        .unwrap();
    writeln!(
        output,
        "{} {}",
        algo,
        if result { "ACCEPT" } else { "REJECT" }
    )
    .unwrap();
    write!(
        output,
        "METRIC stack:{} cycles:{} target:{} algo:{} backend:{}",
        stack.high_water_bytes,
        elapsed,
        target_arch_name(),
        algo,
        backend
    )
    .unwrap();
    #[cfg(feature = "jtrace-f407")]
    write!(
        output,
        " dwt_cycles:{} systick_cycles:{}",
        measurement.dwt, measurement.systick
    )
    .unwrap();
    writeln!(output).unwrap();

    #[cfg(not(feature = "jtrace-f407"))]
    if result {
        embedded_measure::semihosting::exit_success();
    } else {
        embedded_measure::semihosting::exit_failure();
    }
}

#[inline(never)]
pub fn fake_verify(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool {
    let folded = public[0] ^ signature[0] ^ signature[32] ^ (msg.len() as u8);
    black_box(folded);
    true
}

#[inline(never)]
pub fn fake_x25519(k: [u8; 32], u: [u8; 32]) -> [u8; 32] {
    let folded = k[0] ^ k[31] ^ u[0] ^ u[31];
    black_box(folded);
    EXPECTED_SHARED
}

#[cfg(not(feature = "jtrace-f407"))]
use panic_semihosting as _;

#[cfg(feature = "jtrace-f407")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    embedded_measure::rtt::print(format_args!("PANIC: {}\n", info));
    loop {
        cortex_m::asm::nop();
    }
}
