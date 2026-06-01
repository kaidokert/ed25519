unsafe extern "C" {
    static _stack_start: u32;
    static _ram_length: u32;
}

const SAFE_ZONE_BYTES: usize = 256;

#[inline(always)]
pub fn paint_stack() {
    paint_stack_inner::<SAFE_ZONE_BYTES>();
}

#[inline(always)]
pub fn check_stack_high_water_mark() -> usize {
    check_stack_high_water_mark_inner::<SAFE_ZONE_BYTES>()
}

// See cortex_m_demo/src/stack.rs for the implementation rationale (this is
// the RISC-V mirror, differing only in the inline-asm instruction used to
// read SP: `mv` instead of ARM's `mov`).

pub fn paint_stack_inner<const SAFE: usize>() {
    unsafe {
        let stack_start_addr = &_stack_start as *const u32 as usize;
        let stack_size = &_ram_length as *const u32 as usize;
        let stack_end_addr = stack_start_addr.saturating_sub(stack_size);
        let safe_stack_end_addr = stack_end_addr.saturating_add(SAFE);

        // Read current SP and clamp the paint endpoint to `sp - SAFE` so we
        // never overwrite the live stack frame.
        let sp: usize;
        core::arch::asm!("mv {}, sp", out(reg) sp, options(nomem, nostack));
        let live_limit = sp.saturating_sub(SAFE);

        let paint_end_addr = if live_limit < safe_stack_end_addr {
            safe_stack_end_addr
        } else {
            live_limit
        };
        let bytes_to_write = paint_end_addr.saturating_sub(safe_stack_end_addr);

        if bytes_to_write > 0 {
            // Derive the write pointer from `_stack_start` (valid allocation
            // provenance) via wrapping pointer arithmetic.
            let stack_start_ptr = &_stack_start as *const u32 as *mut u8;
            let safe_stack_end_ptr = stack_start_ptr.wrapping_sub(stack_size.saturating_sub(SAFE));
            core::ptr::write_bytes(safe_stack_end_ptr, 0xAA, bytes_to_write);
        }
    }
}

pub fn check_stack_high_water_mark_inner<const SAFE: usize>() -> usize {
    unsafe {
        let stack_size = &_ram_length as *const u32 as usize;
        let stack_start_ptr = &_stack_start as *const u32 as *mut u8;
        let safe_stack_end_ptr = stack_start_ptr.wrapping_sub(stack_size.saturating_sub(SAFE));

        let mut current = safe_stack_end_ptr;
        while current < stack_start_ptr && *current == 0xAA {
            current = current.wrapping_add(1);
        }

        stack_start_ptr.offset_from(current) as usize
    }
}
