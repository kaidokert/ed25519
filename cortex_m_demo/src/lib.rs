#![no_std]

use cortex_m_semihosting::{debug, hprintln};

pub mod cyclecount;
pub mod stack;

use cyclecount::CycleCounter;
use stack::{check_stack_high_water_mark, paint_stack};

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

pub fn test_fixture(testable: fn() -> bool, backend: &str) {
    paint_stack();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed = counter.elapsed() / 1000;
    let stack = check_stack_high_water_mark();
    if result {
        hprintln!("ed25519 ACCEPT");
    } else {
        hprintln!("ed25519 REJECT");
    }
    hprintln!(
        "METRIC stack:{} cycles:{} target:{} backend:{}",
        stack,
        elapsed,
        target_arch_name(),
        backend
    );
    if result {
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        debug::exit(debug::EXIT_FAILURE);
    }
}

use panic_halt as _;
