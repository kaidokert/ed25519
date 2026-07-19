#![no_main]
#![no_std]

use core::hint::black_box;

use cortex_m_demo as _;
#[cfg(not(feature = "external-measurement"))]
use cortex_m_demo::cyclecount::CycleCounter;
use cortex_m_rt::entry;
use embedded_measure::Benchmark;
#[cfg(not(feature = "external-measurement"))]
use embedded_measure::CounterPlatform;

#[inline(never)]
fn portable_workload() -> bool {
    let mut state = black_box(0x1234_5678_u32);
    for value in 0..4096_u32 {
        state = state.rotate_left(5) ^ value.wrapping_mul(0x9e37_79b9);
    }
    black_box(state) != 0
}

#[entry]
fn main() -> ! {
    let benchmark = Benchmark::<3>::new("portable-workload").warmups(1);
    let mut reporter = embedded_measure::semihosting::init().unwrap();

    #[cfg(feature = "external-measurement")]
    let passed = benchmark
        .run_external(&mut reporter, portable_workload)
        .unwrap()
        .passed;

    #[cfg(not(feature = "external-measurement"))]
    let passed = {
        let mut platform = CounterPlatform::new(CycleCounter::new());
        benchmark
            .run(&mut platform, &mut reporter, portable_workload)
            .unwrap()
            .passed
    };

    if passed {
        embedded_measure::semihosting::exit_success();
    } else {
        embedded_measure::semihosting::exit_failure();
    }
}
