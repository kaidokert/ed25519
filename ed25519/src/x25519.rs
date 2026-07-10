//! X25519 ECDH key exchange (RFC 7748 §5).
//!
//! Uses [`FieldCt`]-tagged constant-time field arithmetic throughout — every
//! ladder operation produces and consumes [`ResidueCt`] values. The type
//! system prevents accidentally feeding ladder values into a non-CT field
//! operation: a `ResidueCt` from this module's `FieldCt` can never be passed
//! to a `Field::mul` call.
//!
//! The ladder's conditional swap is branchless (constant-time with respect
//! to the secret scalar). All field multiplications and squarings go through
//! `FieldCt::mul`, which uses `subtle::ConditionallySelectable` for the
//! final REDC reduction. Add/sub use `FieldCt::add` / `sub`, which are also
//! branchless. The remaining gap to formal CT certification is in
//! `fixed-bigint`'s per-limb primitives — see CLAUDE.md for the audit.

use crate::curve25519_field::Curve25519FieldCt;
use crate::{P_BYTES, UnsignedModularInt};
use modmath::ResidueCt;
use subtle::Choice;

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

/// Universal blinding modulus: `lcm(curve_order, twist_order) = 8·ℓ·ℓ'`
/// where `ℓ` is the curve subgroup order and `ℓ'` is the twist
/// subgroup order. Annihilates every point on Curve25519 *and* its
/// twist, so the blinded path matches the unblinded path for every
/// 32-byte u-coordinate the X25519 ladder accepts. `8·ℓ` alone would
/// only work for curve points; using the LCM costs ~2× ladder
/// iterations but eliminates the twist-conformance gap.
pub const BLINDING_MODULUS_BYTES: [u8; 64] = [
    0xc8, 0xce, 0xb3, 0x29, 0x3b, 0xb8, 0xf4, 0x0b, 0xd9, 0xb1, 0xd1, 0x00, 0x00, 0x92, 0x10, 0xa1,
    0x13, 0xa4, 0x80, 0xde, 0xc2, 0x38, 0x11, 0x23, 0x5c, 0xf6, 0x3c, 0x48, 0xee, 0x6b, 0xc6, 0x64,
    0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
];

/// Backends wider than this are rejected at runtime. 64 bytes covers all
/// currently registered `FixedUInt` impls (u32×16, u64×8, u64×4, u8×32) and
/// bounds the scratch buffers below.
const MAX_T_BYTES: usize = 64;

/// `k + r·(8·ℓ·ℓ')` fits in 68 bytes for a 32-bit blinder `r`
/// (worst case 540 bits).
const BLINDED_SCALAR_BYTES: usize = 68;

const BLINDED_BIT_COUNT: usize = BLINDED_SCALAR_BYTES * 8;

/// Apply the RFC 7748 scalar clamp: clear the bottom three bits of byte 0,
/// clear the top bit of byte 31, and set bit 254.
pub const fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Compute `k' = k + r·(8·ℓ·ℓ')` little-endian. Schoolbook in
/// `u8`/`u16`/`u64` to avoid dragging in a wider `FixedUInt`.
fn compute_blinded_scalar(
    k_clamped: &[u8; 32],
    r: u32,
) -> zeroize::Zeroizing<[u8; BLINDED_SCALAR_BYTES]> {
    let mut out = zeroize::Zeroizing::new([0u8; BLINDED_SCALAR_BYTES]);
    let r = r as u64;

    let mut carry: u64 = 0;
    for i in 0..64 {
        let prod = r * (BLINDING_MODULUS_BYTES[i] as u64) + carry;
        out[i] = prod as u8;
        carry = prod >> 8;
    }
    for byte in out.iter_mut().skip(64) {
        carry += *byte as u64;
        *byte = carry as u8;
        carry >>= 8;
    }
    debug_assert_eq!(carry, 0);

    let mut c: u16 = 0;
    for (i, &kb) in k_clamped.iter().enumerate() {
        let s = (out[i] as u16) + (kb as u16) + c;
        out[i] = s as u8;
        c = s >> 8;
    }
    for byte in out.iter_mut().skip(32) {
        let s = (*byte as u16) + c;
        *byte = s as u8;
        c = s >> 8;
    }
    debug_assert_eq!(c, 0);

    out
}

/// Compute `k * G` where `G` is the X25519 base point (u = 9).
/// Convenience for public-key derivation.
///
/// `k` is borrowed (not consumed) so the caller can wrap their long-lived
/// secret in a `Zeroizing<[u8; 32]>` and have it cleared on drop without
/// forcing an extra copy across the API boundary.
pub fn x25519_base<T>(k: &[u8; 32]) -> [u8; 32]
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + modmath::Parity
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = T>
        + const_num_traits::WrappingMul<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    x25519::<T>(k, &BASE_U_BYTES)
}

/// Compute the X25519 shared secret `k * u`.
///
/// Inputs are 32-byte little-endian encodings of the secret scalar and the
/// peer's u-coordinate. Output is the 32-byte little-endian encoding of the
/// resulting u-coordinate.
///
/// `k` is borrowed (not consumed); see the note on `x25519_base` for the
/// rationale around long-lived secrets and `Zeroizing<[u8; 32]>`. The
/// peer's `u_in` is also borrowed for API symmetry. The internal clamped
/// copy of `k` lives in a `Zeroizing` wrapper so it's wiped on function
/// exit, closing the obvious "scalar bytes in a stack frame" leak path.
///
/// The scalar is clamped and the high bit of `u_in[31]` is masked here, so
/// callers do not need to pre-process either input (RFC 7748 §5).
///
/// # Panics
///
/// Panics if `T` is narrower than 256 bits (cannot hold a Curve25519 field
/// element) or wider than 512 bits (exceeds the internal scratch buffers).
/// Both conditions indicate a backend-selection bug and would otherwise
/// produce a meaningless result.
#[inline(never)]
pub fn x25519<T>(k: &[u8; 32], u_in: &[u8; 32]) -> [u8; 32]
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + modmath::Parity
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = T>
        + const_num_traits::WrappingMul<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    // Backend width is a static property of T. Const-evaluate at
    // monomorphization so wrong backends fail at compile time and the
    // runtime panic path doesn't reach the linker.
    const {
        assert!(
            modmath::type_bit_width::<T>() >= 256,
            "x25519: backend T is too narrow for the Curve25519 prime (need >= 256 bits)"
        );
        assert!(
            modmath::type_bit_width::<T>() <= MAX_T_BYTES * 8,
            "x25519: backend T is wider than the fixed-size scratch buffer (MAX_T_BYTES * 8)"
        );
    }

    // The entry-point const-block guards the width case; the Odd
    // proof inside the factory is statically true for the Curve25519
    // prime — both Err arms are unreachable here. Fail-closed to
    // an all-zero shared secret rather than pulling in a panic
    // string (RFC 7748 §5 tells callers to reject all-zero output
    // as a suspected attack, so the fallback signals cleanly).
    let field = match Curve25519FieldCt::curve25519() {
        Ok(f) => f,
        Err(_) => return [0u8; 32],
    };

    // RFC 7748 §5: clamp scalar, mask high bit of u-coordinate.
    let k = zeroize::Zeroizing::new(clamp(*k));
    let mut u_bytes = *u_in;
    u_bytes[31] &= 0x7f;
    let u = crate::from_le_bytes::<T>(&u_bytes);

    // x1 stays constant throughout the ladder (= peer u in the field).
    // Peer u is public, but every downstream op is CT-typed, so it flows
    // through the CT field and gets the same residue type as everything else.
    let x1 = field.reduce(&u);
    let a24 = field.reduce(&crate::from_le_bytes::<T>(&A24_BYTES));

    let (x2, z2) = montgomery_ladder(
        &field,
        &x1,
        &a24,
        &*k,
        255,
        field.one(),
        field.zero(),
        x1.clone(),
        field.one(),
    );

    // Return x2 * z2^{-1} mod p, encoded little-endian.
    // All CT — z2 is secret-derived.
    let z2_inv = field.inv(&z2);
    let result_res = field.mul(&x2, &z2_inv);
    // Wrap the owned `T` returned by `into_raw` in `Zeroizing` so the
    // shared-secret bytes don't sit on the stack after this function
    // returns. `T` is `Copy` (precluding `ZeroizeOnDrop` directly), but
    // `T: zeroize::Zeroize` is implied by `UnsignedModularInt`'s
    // `MontStorage` supertrait when modmath's `zeroize` feature is on
    // — which we require — so `Zeroizing<T>` works without extra bounds.
    let result = zeroize::Zeroizing::new(field.into_raw(&result_res));

    // Shared secret is sensitive; route through `to_le_bytes_ct(&*result)`
    // so no owned `T` copy of the shared secret materializes off the
    // `Zeroizing<T>` stack slot. Value is < p < 2^255 so the low 32
    // bytes carry it.
    let bytes = crate::to_le_bytes_ct(&*result);
    let bytes_slice: &[u8] = bytes.as_ref();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes_slice[..32]);
    out
}

/// X25519 shared secret with full per-invocation blinding:
///
/// * **Scalar blinding** — replaces `k` with `k' = k + r·(8·ℓ·ℓ')`
///   for a fresh 32-bit `r`. Defeats multi-trace DPA aggregation
///   against a long-lived secret scalar.
/// * **Projective coordinate re-randomization** — scales the starting
///   ladder state by a random nonzero `λ ∈ F_p`. Defeats single-trace
///   correlation analysis between ladder iterations.
///
/// Output equals [`x25519`] for every accepted u-coordinate, curve or
/// twist — see [`BLINDING_MODULUS_BYTES`].
///
/// `R: CryptoRng` is required — a predictable RNG is worse than no
/// blinding (attacker recovers PRNG state from traces, removes the
/// blinding offline). Typical pattern: seed `ChaCha20Rng` from HW RNG
/// at startup, pass the `ChaCha20Rng` here.
///
/// Cost: ~2× [`x25519`] (544 vs 255 ladder iterations); the projective
/// re-randomization adds one extra multiplication, negligible vs the
/// ladder body.
#[inline(never)]
pub fn x25519_blinded<T, R>(rng: &mut R, k: &[u8; 32], u_in: &[u8; 32]) -> [u8; 32]
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + modmath::Parity
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = T>
        + const_num_traits::WrappingMul<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
    R: rand_core::CryptoRng,
{
    const {
        assert!(
            modmath::type_bit_width::<T>() >= 256,
            "x25519_blinded: backend T is too narrow for the Curve25519 prime (need >= 256 bits)"
        );
        assert!(
            modmath::type_bit_width::<T>() <= MAX_T_BYTES * 8,
            "x25519_blinded: backend T is wider than the fixed-size scratch buffer (MAX_T_BYTES * 8)"
        );
    }

    // The entry-point const-block guards the width case; the Odd
    // proof inside the factory is statically true for the Curve25519
    // prime — both Err arms are unreachable here. Fail-closed to
    // an all-zero shared secret rather than pulling in a panic
    // string (RFC 7748 §5 tells callers to reject all-zero output
    // as a suspected attack, so the fallback signals cleanly).
    let field = match Curve25519FieldCt::curve25519() {
        Ok(f) => f,
        Err(_) => return [0u8; 32],
    };

    let k_clamped = zeroize::Zeroizing::new(clamp(*k));
    let r = rng.next_u32();
    let k_prime = compute_blinded_scalar(&k_clamped, r);

    let mut u_bytes = *u_in;
    u_bytes[31] &= 0x7f;
    let u = crate::from_le_bytes::<T>(&u_bytes);
    let x1 = field.reduce(&u);
    let a24 = field.reduce(&crate::from_le_bytes::<T>(&A24_BYTES));

    // Projective re-randomization: scale the starting state by a random
    // nonzero λ ∈ F_p. Same geometric points, different bit patterns
    // through the ladder — defeats single-trace correlation. Replace
    // λ_t ∈ {0, p} with 1 in constant time, since both reduce to 0
    // and a zero λ degenerates the initial state to (0, 0, 0, 0).
    let mut lambda_bytes = zeroize::Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *lambda_bytes);
    lambda_bytes[31] &= 0x7f;
    let p_t = crate::from_le_bytes::<T>(&P_BYTES);
    let mut lambda_t = zeroize::Zeroizing::new(crate::from_le_bytes::<T>(&*lambda_bytes));
    let is_zero = subtle::ConstantTimeEq::ct_eq(&*lambda_t, &T::zero());
    let is_p = subtle::ConstantTimeEq::ct_eq(&*lambda_t, &p_t);
    *lambda_t = T::conditional_select(&*lambda_t, &T::one(), is_zero | is_p);
    let lambda = field.reduce(&*lambda_t);
    let lx1 = field.mul(&lambda, &x1);

    let (x2, z2) = montgomery_ladder(
        &field,
        &x1,
        &a24,
        &*k_prime,
        BLINDED_BIT_COUNT,
        lambda.clone(),
        field.zero(),
        lx1,
        lambda,
    );

    let z2_inv = field.inv(&z2);
    let result_res = field.mul(&x2, &z2_inv);
    let result = zeroize::Zeroizing::new(field.into_raw(&result_res));

    let bytes = crate::to_le_bytes_ct(&*result);
    let bytes_slice: &[u8] = bytes.as_ref();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes_slice[..32]);
    out
}

/// Compute `k * G` (where `G` is the X25519 base point) with scalar
/// blinding. See [`x25519_blinded`] for the threat model and RNG
/// requirement.
pub fn x25519_base_blinded<T, R>(rng: &mut R, k: &[u8; 32]) -> [u8; 32]
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + modmath::Parity
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = T>
        + const_num_traits::WrappingMul<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
    R: rand_core::CryptoRng,
{
    x25519_blinded::<T, R>(rng, k, &BASE_U_BYTES)
}

/// Shared ladder body. Caller supplies the initial projective state
/// `(x2, z2, x3, z3)` so the blinded path can scale by a random λ.
/// `x1` and `a24` are borrowed so the caller's `ZeroizeOnDrop` wipe
/// still fires at its scope end.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn montgomery_ladder<'f, T>(
    field: &'f Curve25519FieldCt<T>,
    x1: &ResidueCt<'f, T>,
    a24: &ResidueCt<'f, T>,
    scalar: &[u8],
    bit_count: usize,
    mut x2: ResidueCt<'f, T>,
    mut z2: ResidueCt<'f, T>,
    mut x3: ResidueCt<'f, T>,
    mut z3: ResidueCt<'f, T>,
) -> (ResidueCt<'f, T>, ResidueCt<'f, T>)
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + modmath::Parity
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = T>
        + const_num_traits::WrappingMul<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    let mut swap: u8 = 0;

    for t in (0..bit_count).rev() {
        let k_t = (scalar[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        let choice = Choice::from(swap);
        ResidueCt::cswap(choice, &mut x2, &mut x3);
        ResidueCt::cswap(choice, &mut z2, &mut z3);
        swap = k_t;

        let a = field.add(&x2, &z2);
        let aa = field.mul(&a, &a);
        let b = field.sub(&x2, &z2);
        let bb = field.mul(&b, &b);
        let e = field.sub(&aa, &bb);
        let c = field.add(&x3, &z3);
        let d = field.sub(&x3, &z3);
        let da = field.mul(&d, &a);
        let cb = field.mul(&c, &b);

        let da_plus_cb = field.add(&da, &cb);
        x3 = field.mul(&da_plus_cb, &da_plus_cb);

        let da_minus_cb = field.sub(&da, &cb);
        let dmc_sq = field.mul(&da_minus_cb, &da_minus_cb);
        z3 = field.mul(x1, &dmc_sq);

        x2 = field.mul(&aa, &bb);

        let a24e = field.mul(a24, &e);
        let aa_plus_a24e = field.add(&aa, &a24e);
        z2 = field.mul(&e, &aa_plus_a24e);
    }

    let final_choice = Choice::from(swap);
    ResidueCt::cswap(final_choice, &mut x2, &mut x3);
    ResidueCt::cswap(final_choice, &mut z2, &mut z3);

    (x2, z2)
}
