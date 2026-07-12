//! Deliberately-panicky fixtures for harness self-test.
//!
//! These `#[no_mangle] pub extern "C"` symbols each contain a panic
//! path the walker regex must catch (`panic_bounds_check`,
//! `unwrap_failed`, `expect_failed`). `check.sh` builds this crate a
//! second time with `--features neg-controls` and asserts every
//! `panic_audit__neg__*` section fires in the output — if any doesn't,
//! the walker's regex or caller-attribution is broken.
//!
//! Each fixture emits its panic call site DIRECTLY inside the fixture
//! body (not via a helper), because the walker attributes panic
//! reachability to the section holding the relocation. Panic paths
//! that route through upstream helper shims (e.g. `copy_from_slice`
//! → `copy_from_slice_impl` → `len_mismatch_fail`) are known to be
//! missed by this transitive shape — that's a documented gap this
//! audit does not currently cover.
//!
//! The panic-inducing input is passed through `black_box` so LLVM
//! can't fold it through and DCE the panic path at compile time.

use core::hint::black_box;

/// Bounds check → `panic_bounds_check` / `slice_index_fail`.
#[unsafe(no_mangle)]
pub extern "C" fn panic_audit__neg__bounds_check(idx: usize, out: *mut u8) {
    if out.is_null() {
        return;
    }
    let arr: [u8; 32] = black_box([0u8; 32]);
    let v = arr[black_box(idx)];
    unsafe { *out = black_box(v) }
}

/// `Option::unwrap` on a runtime `None` → `unwrap_failed`.
#[unsafe(no_mangle)]
pub extern "C" fn panic_audit__neg__unwrap(out: *mut u8) {
    if out.is_null() {
        return;
    }
    let x: Option<u8> = black_box(None);
    let v = x.unwrap();
    unsafe { *out = black_box(v) }
}

/// `Option::expect` on a runtime `None` → `expect_failed`.
#[unsafe(no_mangle)]
pub extern "C" fn panic_audit__neg__expect(out: *mut u8) {
    if out.is_null() {
        return;
    }
    let x: Option<u8> = black_box(None);
    let v = x.expect("neg control expect");
    unsafe { *out = black_box(v) }
}
