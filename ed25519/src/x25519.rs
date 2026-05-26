//! X25519 ECDH key exchange (RFC 7748 §5).
//!
//! Shares the field machinery — `UnsignedModularInt`, `MontgomeryCtx`,
//! `lazy_field` — with the Ed25519 verifier next door, since both curves
//! live in F_p where p = 2^255 - 19. The X25519-specific bits (Montgomery
//! curve constants, scalar clamp, ladder) live in this module.
//!
//! All field arithmetic is done in Montgomery form via `MontgomeryCtx`.
//! Add / sub remain plain modular operations (`lazy_field`); only the
//! multiplications and squarings go through Montgomery REDC.

use crate::lazy_field::{lazy_mod_add, lazy_mod_sub};
use crate::montgomery_ctx::MontgomeryCtx;
use crate::{P_BYTES, UnsignedModularInt};

// =========================================================================
// X25519-specific constants
// =========================================================================

/// a24 = (A - 2) / 4 where A = 486662 is the Montgomery curve coefficient.
/// a24 = 121665 = 0x0001_DB41, little-endian.
pub const A24_BYTES: [u8; 32] = [
    0x41, 0xdb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The u-coordinate of the X25519 base point. u = 9, little-endian.
pub const BASE_U_BYTES: [u8; 32] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Apply the RFC 7748 scalar clamp: clear the bottom three bits of byte 0,
/// clear the top bit of byte 31, and set bit 254.
pub const fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Compute `k * G` where `G` is the X25519 base point (u = 9).
/// Convenience for public-key derivation.
pub fn x25519_base<T>(k: [u8; 32]) -> [u8; 32]
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    x25519::<T>(k, BASE_U_BYTES)
}

/// Compute the X25519 shared secret `k * u`.
///
/// Inputs are 32-byte little-endian encodings of the secret scalar and the
/// peer's u-coordinate. Output is the 32-byte little-endian encoding of the
/// resulting u-coordinate.
///
/// The scalar is clamped and the high bit of `u_in[31]` is masked here, so
/// callers do not need to pre-process either input (RFC 7748 §5).
#[inline(never)]
pub fn x25519<T>(k: [u8; 32], u_in: [u8; 32]) -> [u8; 32]
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    // Guard: T must be wide enough to hold 256-bit field elements
    if modmath::type_bit_width::<T>() < 256 {
        return [0u8; 32];
    }

    let p = T::from_bytes_le(&P_BYTES);
    let ctx = MontgomeryCtx::new(p).unwrap();

    // RFC 7748 §5: clamp scalar, mask high bit of u-coordinate
    let k = clamp(k);
    let mut u_bytes = u_in;
    u_bytes[31] &= 0x7f;
    let u = T::from_bytes_le(&u_bytes);

    // x1 stays constant throughout the ladder (= peer u in Montgomery form)
    let x1_m = ctx.to_mont(u);
    let a24_m = ctx.to_mont(T::from_bytes_le(&A24_BYTES));

    // Initial ladder state in Montgomery form:
    //   (x2, z2) = (1, 0)   -- the point at infinity
    //   (x3, z3) = (u, 1)   -- the input point
    // Note: 0 in Montgomery form is still 0.
    let one_m = ctx.to_mont(T::one());
    let mut x2 = one_m;
    let mut z2 = T::zero();
    let mut x3 = x1_m;
    let mut z3 = one_m;
    let mut swap: u8 = 0;

    // Process scalar bits 254..=0 (255 iterations).
    for t in (0..255).rev() {
        let k_t = (k[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        if swap == 1 {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }
        swap = k_t;

        // RFC 7748 §5 doubling-and-differential-addition step.
        // All multiplications go through Montgomery REDC; add/sub stay lazy.
        let a = lazy_mod_add(x2, &z2, &p);
        let aa = ctx.mont_mul(&a, &a);
        let b = lazy_mod_sub(x2, &z2, &p);
        let bb = ctx.mont_mul(&b, &b);
        let e = lazy_mod_sub(aa, &bb, &p);
        let c = lazy_mod_add(x3, &z3, &p);
        let d = lazy_mod_sub(x3, &z3, &p);
        let da = ctx.mont_mul(&d, &a);
        let cb = ctx.mont_mul(&c, &b);

        let da_plus_cb = lazy_mod_add(da, &cb, &p);
        x3 = ctx.mont_mul(&da_plus_cb, &da_plus_cb);

        let da_minus_cb = lazy_mod_sub(da, &cb, &p);
        let dmc_sq = ctx.mont_mul(&da_minus_cb, &da_minus_cb);
        z3 = ctx.mont_mul(&x1_m, &dmc_sq);

        x2 = ctx.mont_mul(&aa, &bb);

        let a24e = ctx.mont_mul(&a24_m, &e);
        let aa_plus_a24e = lazy_mod_add(aa, &a24e, &p);
        z2 = ctx.mont_mul(&e, &aa_plus_a24e);
    }

    // Final conditional swap based on the last scalar bit
    if swap == 1 {
        core::mem::swap(&mut x2, &mut x3);
        core::mem::swap(&mut z2, &mut z3);
    }

    // Return x2 * z2^{-1} mod p, encoded little-endian.
    // mont_inv expects normal form and returns normal form, so round-trip z2.
    let z2_normal = ctx.from_mont(z2);
    let z2_inv_normal = ctx.mont_inv(z2_normal);
    let z2_inv_m = ctx.to_mont(z2_inv_normal);
    let result_m = ctx.mont_mul(&x2, &z2_inv_m);
    let result = ctx.from_mont(result_m);

    // T can be wider than 32 bytes (e.g. FixedUInt<u32, 16> is 64 bytes). Serialize
    // into a max-width scratch buffer and copy out the low 32 bytes — the field
    // element is < p < 2^255 so the high half is zero.
    let mut scratch = [0u8; 64];
    let bytes = result.to_bytes_le(&mut scratch);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}
