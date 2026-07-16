#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use avr_demo as _;
use avr_demo::stack_measurement::*;
use fixed_bigint::FixedUInt;

const PUBLIC_KEY: [u8; 32] = [
    0x33, 0xbc, 0x91, 0xa3, 0xca, 0xb8, 0x87, 0xc8, 0xbf, 0x3c, 0x63, 0x61, 0x46, 0xd2, 0xe3, 0x8d,
    0x58, 0xd0, 0xca, 0xf3, 0x3b, 0x77, 0x86, 0x25, 0xc7, 0x95, 0x2b, 0xc7, 0x6f, 0xc0, 0x73, 0xac,
];
const SIGNATURE: [u8; 64] = [
    0x2f, 0xec, 0x62, 0xdf, 0x49, 0x4f, 0xf5, 0x70, 0x5f, 0x5c, 0xee, 0x45, 0xbc, 0x5e, 0x89, 0xc2,
    0x32, 0xc1, 0x61, 0x88, 0x37, 0x87, 0xce, 0x50, 0xa2, 0x9b, 0xe8, 0x8c, 0xb1, 0x92, 0xc8, 0x81,
    0x25, 0x62, 0x74, 0xed, 0xd7, 0x67, 0x2a, 0xa5, 0x52, 0x79, 0x57, 0xeb, 0x0d, 0xdc, 0x0e, 0x60,
    0x95, 0x23, 0x74, 0x36, 0x22, 0x32, 0x85, 0xf6, 0xd9, 0x30, 0x6b, 0x96, 0x63, 0x14, 0x86, 0x02,
];
const MESSAGE: &[u8] = b"Hello world!\n";

const RAMEND_ADDR: u16 = 0x21FF;

unsafe extern "C" {
    static mut _end: u8;
}

/// Print a visual map of stack usage in 64-byte chunks
/// Shows '#' for used (watermark overwritten) and '.' for unused (watermark intact)
fn print_stack_map(serial: &mut impl ufmt::uWrite) {
    let stack_start = unsafe { &raw mut _end as *const u8 };
    let stack_end = RAMEND_ADDR as *const u8;
    let total = unsafe { stack_end.offset_from(stack_start) as u16 };

    ufmt::uwriteln!(serial, "Stack map ({} bytes, 32B/char):", total).ok();
    ufmt::uwrite!(serial, "LO|").ok();

    let chunk_size: u16 = 32;
    let mut addr = stack_start;
    let mut chunk_idx: u16 = 0;

    while (addr as u16) < (stack_end as u16) {
        // Count watermark bytes in this chunk
        let chunk_end_addr = (addr as u16)
            .saturating_add(chunk_size)
            .min(stack_end as u16);
        let mut watermark_count: u16 = 0;
        let mut scan = addr;
        while (scan as u16) < chunk_end_addr {
            if unsafe { core::ptr::read_volatile(scan) } == 0xCE {
                watermark_count += 1;
            }
            scan = unsafe { scan.add(1) };
        }

        // '#' = mostly used, '.' = mostly unused, ':' = partial
        let actual_chunk_size = chunk_end_addr - (addr as u16);
        if watermark_count == actual_chunk_size {
            ufmt::uwrite!(serial, ".").ok();
        } else if watermark_count == 0 {
            ufmt::uwrite!(serial, "#").ok();
        } else {
            ufmt::uwrite!(serial, ":").ok();
        }

        addr = chunk_end_addr as *const u8;
        chunk_idx += 1;
        if chunk_idx % 80 == 0 {
            ufmt::uwriteln!(serial, "").ok();
            ufmt::uwrite!(serial, "   ").ok();
        }
    }
    ufmt::uwriteln!(serial, "|HI").ok();

    // Also print per-256B region summary with byte counts
    ufmt::uwriteln!(serial, "").ok();
    ufmt::uwriteln!(serial, "Per-256B region (used/256):").ok();
    let mut region_addr = stack_start;
    let mut region_idx: u16 = 0;
    while (region_addr as u16) < (stack_end as u16) {
        let region_end = ((region_addr as u16).saturating_add(256)).min(stack_end as u16);
        let mut used: u16 = 0;
        let mut scan = region_addr;
        while (scan as u16) < region_end {
            if unsafe { core::ptr::read_volatile(scan) } != 0xCE {
                used += 1;
            }
            scan = unsafe { scan.add(1) };
        }
        let region_size = region_end - region_addr as u16;
        ufmt::uwriteln!(
            serial,
            "  {:04X}: {}/{}",
            region_addr as u16,
            used,
            region_size
        )
        .ok();
        region_addr = region_end as *const u8;
        region_idx += 1;
    }
    ufmt::uwriteln!(serial, "  Total free RAM: {}", total).ok();
}

#[arduino_hal::entry]
fn main() -> ! {
    let dp = arduino_hal::Peripherals::take().unwrap();
    let pins = arduino_hal::pins!(dp);
    let mut serial = arduino_hal::default_serial!(dp, pins, 57600);

    let stack_probe = fill_stack_with_watermark();

    let result = ed25519_heapless::verify::<FixedUInt<u8, 32>>(PUBLIC_KEY, MESSAGE, SIGNATURE);

    let stack_used = measure_stack_usage(&stack_probe);

    if result {
        ufmt::uwriteln!(&mut serial, "ACCEPT").ok();
    } else {
        ufmt::uwriteln!(&mut serial, "REJECT").ok();
    }
    ufmt::uwriteln!(&mut serial, "Max stack usage: {} bytes", stack_used).ok();

    print_stack_map(&mut serial);

    loop {
        unsafe { core::arch::asm!("sleep") }
    }
}
