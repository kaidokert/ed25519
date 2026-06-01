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

// Implementation notes:
//
// - All address arithmetic is done in `usize` (no pointer arithmetic on
//   integer-cast pointers), then the single `*mut u8` we hand to
//   `write_bytes` is derived from the linker symbol via
//   `<*mut u8>::wrapping_sub` — pointer arithmetic *with* provenance
//   inherited from `&_stack_start`. This avoids the strict-provenance
//   UB of taking `sp` (a raw integer) and calling `.offset` on a
//   pointer cast from it.
// - `_stack_start` is the linker-defined top-of-stack symbol; its
//   ADDRESS is the value (so `&_stack_start as ... as usize` is correct,
//   never `_stack_start`). Same for `_ram_length`.

pub fn paint_stack_inner<const SAFE: usize>() {
    unsafe {
        let stack_start_addr = &_stack_start as *const u32 as usize;
        let stack_size = &_ram_length as *const u32 as usize;
        let stack_end_addr = stack_start_addr.saturating_sub(stack_size);
        let safe_stack_end_addr = stack_end_addr.saturating_add(SAFE);

        // Read current SP and clamp the paint endpoint to `sp - SAFE` so we
        // never overwrite the live stack frame. Without this guard the paint
        // would extend up to `stack_start - SAFE`, clobbering saved registers
        // / return address when the call site's frame is bigger than SAFE
        // (silent hang in qemu — no panic).
        let sp: usize;
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
        let live_limit = sp.saturating_sub(SAFE);

        let paint_end_addr = if live_limit < safe_stack_end_addr {
            safe_stack_end_addr
        } else {
            live_limit
        };
        let bytes_to_write = paint_end_addr.saturating_sub(safe_stack_end_addr);

        if bytes_to_write > 0 {
            // Derive the write pointer from `_stack_start` (which has valid
            // allocation provenance) via wrapping pointer arithmetic, rather
            // than casting `safe_stack_end_addr as *mut u8` (no provenance).
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
        // Same provenance-preserving derivation as in paint_stack_inner.
        let safe_stack_end_ptr = stack_start_ptr.wrapping_sub(stack_size.saturating_sub(SAFE));

        let mut current = safe_stack_end_ptr;
        while current < stack_start_ptr && *current == 0xAA {
            current = current.wrapping_add(1);
        }

        stack_start_ptr.offset_from(current) as usize
    }
}
