use core::arch::asm;

/// Read the 64-bit mcycle counter on RV32 with consistency check.
fn read_mcycle() -> u64 {
    loop {
        let hi1: u32;
        let lo: u32;
        let hi2: u32;
        unsafe {
            asm!("csrr {}, mcycleh", out(reg) hi1);
            asm!("csrr {}, mcycle", out(reg) lo);
            asm!("csrr {}, mcycleh", out(reg) hi2);
        }
        if hi1 == hi2 {
            return ((hi1 as u64) << 32) | (lo as u64);
        }
    }
}

pub struct CycleCounter {
    start: u64,
}

impl CycleCounter {
    pub fn new() -> Self {
        Self {
            start: read_mcycle(),
        }
    }

    pub fn elapsed(&self) -> u64 {
        read_mcycle() - self.start
    }
}
