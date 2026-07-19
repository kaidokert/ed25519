#![no_main]
#![no_std]

use core::hint::black_box;

use cortex_m_demo as _;
#[cfg(not(feature = "external-measurement"))]
use cortex_m_demo::cyclecount::CycleCounter;
use cortex_m_rt::entry;
use krabi_caliper::Benchmark;
#[cfg(not(feature = "external-measurement"))]
use krabi_caliper::CounterPlatform;

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
    let mut reporter = krabi_caliper::semihosting::init().unwrap();

    #[cfg(feature = "external-measurement")]
    let passed = benchmark
        .run_external(&mut reporter, portable_workload)
        .unwrap()
        .passed;

    #[cfg(not(feature = "external-measurement"))]
    let passed = {
        let mut platform = CounterPlatform::new(CycleCounter::start(false, None).unwrap());
        benchmark
            .run(&mut platform, &mut reporter, portable_workload)
            .unwrap()
            .passed
    };

    if passed {
        krabi_caliper::semihosting::exit_success();
    } else {
        krabi_caliper::semihosting::exit_failure();
    }
}
