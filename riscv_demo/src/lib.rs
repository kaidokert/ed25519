#![no_std]

use core::fmt::Write;
use core::hint::black_box;

pub mod cyclecount;
pub mod stack;
pub mod uart;

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

use cyclecount::CycleCounter;
use stack::{check_stack_high_water_mark, paint_stack};
use uart::{UartWriter, uart_init};

pub fn test_fixture(testable: fn() -> bool, backend: &str) -> ! {
    uart_init();

    paint_stack();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed = counter.elapsed() / 1000;
    let stack = check_stack_high_water_mark();

    let mut w = UartWriter;
    if result {
        let _ = writeln!(w, "ed25519 ACCEPT");
    } else {
        let _ = writeln!(w, "ed25519 REJECT");
    }
    let _ = writeln!(
        w,
        "METRIC stack:{} cycles:{} target:riscv32 backend:{}",
        stack, elapsed, backend
    );

    // sifive_e has no exit mechanism — loop forever, wrapper kills QEMU
    loop {
        unsafe { core::arch::asm!("wfi") }
    }
}

#[inline(never)]
pub fn fake_verify(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool {
    let folded = public[0] ^ signature[0] ^ signature[32] ^ (msg.len() as u8);
    black_box(folded) != 0
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    uart_init();
    let mut w = UartWriter;
    let _ = writeln!(w, "PANIC: {}", info);
    loop {
        unsafe { core::arch::asm!("wfi") }
    }
}
