//! Linker-DCE audit for ed25519_heapless's secret-touching surface.
//!
//! Each `#[no_mangle] pub extern "C"` symbol exercises one entry point
//! the way a deployed consumer would — no `unwrap`, no `expect`, all
//! `Result` outcomes observed as booleans. After cross-building with
//! the workspace release profile, `check.sh` asserts the resulting
//! archive contains no `core::panicking` machinery: for CT code a
//! reachable panic is both a DoS edge and a timing oracle (the panic
//! formatting path's cost depends on the values being formatted).
//!
//! `black_box` at every boundary so the optimizer can't fold inputs
//! through and DCE the body wholesale. Each fixture null-guards its
//! pointer parameters so the compiler can't reason `deref of `*const T`
//! is UB if null, therefore null is impossible, therefore ... DCE the
//! body`. That's not just paranoia — Rust's noundef load rules let
//! LLVM propagate exactly those assumptions.

#![cfg_attr(feature = "panic-handler", no_std)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::hint::black_box;

use const_num_traits::{Ct, Nct};
use ed25519_heapless::{SigningKey, sign, verify, x25519, x25519_base};
use fixed_bigint::FixedUInt;

// Ct carrier for the sign / x25519 secret-touching paths.
type TCt = FixedUInt<u32, 8, Ct>;
// Nct carrier for `verify` — the verify path takes only public
// inputs and is bounded on `T: modmath::NonCt`.
type TNct = FixedUInt<u32, 8, Nct>;

/// Derive a signing key from a 32-byte seed. `Result::is_ok()`
/// observed as a byte — no unwrap.
#[unsafe(no_mangle)]
pub extern "C" fn panic_audit__signing_key_from_seed(
    seed: *const [u8; 32],
    out_pubkey: *mut [u8; 32],
) -> u8 {
    if seed.is_null() || out_pubkey.is_null() {
        return 0;
    }
    let seed = unsafe { *seed };
    let sk = SigningKey::<TCt>::from_seed(black_box(&seed));
    if let Ok(ref k) = sk {
        unsafe { *out_pubkey = black_box(k.public_key()) }
    }
    black_box(sk.is_ok() as u8)
}

/// Full sign path: from_seed → sign. Both `Result` outcomes observed
/// without extraction. `msg` is a caller-owned slice; length passed
/// explicitly because slices aren't FFI-safe.
#[unsafe(no_mangle)]
pub extern "C" fn panic_audit__sign_from_seed(
    seed: *const [u8; 32],
    msg: *const u8,
    msg_len: usize,
    out_sig: *mut [u8; 64],
) -> u8 {
    if seed.is_null() || out_sig.is_null() {
        return 0;
    }
    let seed = unsafe { *seed };
    // `from_raw_parts(null, 0)` is UB even at length 0.
    let msg: &[u8] = if msg.is_null() {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(black_box(msg), black_box(msg_len)) }
    };
    let Ok(sk) = SigningKey::<TCt>::from_seed(black_box(&seed)) else {
        return 0;
    };
    let sig = sign(black_box(&sk), msg);
    if let Ok(s) = sig {
        unsafe { *out_sig = black_box(s) }
        1
    } else {
        0
    }
}

/// Verify path. `bool` return observed through `black_box`.
#[unsafe(no_mangle)]
pub extern "C" fn panic_audit__verify(
    public: *const [u8; 32],
    msg: *const u8,
    msg_len: usize,
    signature: *const [u8; 64],
) -> u8 {
    if public.is_null() || signature.is_null() {
        return 0;
    }
    let public = unsafe { *public };
    let signature = unsafe { *signature };
    let msg: &[u8] = if msg.is_null() {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(black_box(msg), black_box(msg_len)) }
    };
    let ok = verify::<TNct>(black_box(public), msg, black_box(signature));
    black_box(ok as u8)
}

/// X25519 scalar × counterparty coordinate.
#[unsafe(no_mangle)]
pub extern "C" fn panic_audit__x25519(
    k: *const [u8; 32],
    u_in: *const [u8; 32],
    out: *mut [u8; 32],
) {
    if k.is_null() || u_in.is_null() || out.is_null() {
        return;
    }
    let k = unsafe { *k };
    let u_in = unsafe { *u_in };
    let r = x25519::<TCt>(black_box(&k), black_box(&u_in));
    unsafe { *out = black_box(r) }
}

/// X25519 scalar × basepoint (public-key derivation).
#[unsafe(no_mangle)]
pub extern "C" fn panic_audit__x25519_base(k: *const [u8; 32], out: *mut [u8; 32]) {
    if k.is_null() || out.is_null() {
        return;
    }
    let k = unsafe { *k };
    let r = x25519_base::<TCt>(black_box(&k));
    unsafe { *out = black_box(r) }
}

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
