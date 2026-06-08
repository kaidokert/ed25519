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

/// Full curve group order `8·ℓ`, used as the scalar-blinding modulus.
///
/// `ℓ` alone would not work: `ℓ mod 8 = 5`, so `r·ℓ` is not a multiple
/// of 8 in general, which would break the RFC 7748 clamp invariant
/// (clamped scalars must be multiples of 8 to clear cofactor torsion).
/// `8·ℓ` is always a multiple of 8 and annihilates any point on the
/// curve. Twist points are not annihilated — blinded results may
/// diverge from unblinded for twist u-coords.
pub const GROUP_ORDER_BYTES: [u8; 32] = [
    0x68, 0x9f, 0xae, 0xe7, 0xd2, 0x18, 0x93, 0xc0, 0xb2, 0xe6, 0xbc, 0x17, 0xf5, 0xce, 0xf7, 0xa6,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
];

/// Backends wider than this are rejected at runtime. 64 bytes covers all
/// currently registered `FixedUInt` impls (u32×16, u64×8, u64×4, u8×32) and
/// bounds the scratch buffers below.
const MAX_T_BYTES: usize = 64;

/// `k + r·(8·ℓ)` fits in 36 bytes for a 32-bit blinder `r`.
const BLINDED_SCALAR_BYTES: usize = 36;

const BLINDED_BIT_COUNT: usize = BLINDED_SCALAR_BYTES * 8;

/// Apply the RFC 7748 scalar clamp: clear the bottom three bits of byte 0,
/// clear the top bit of byte 31, and set bit 254.
pub const fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Compute `k' = k + r·(8·ℓ)` little-endian. Schoolbook in
/// `u8`/`u16`/`u64` to avoid dragging in a wider `FixedUInt`.
fn compute_blinded_scalar(k_clamped: &[u8; 32], r: u32) -> [u8; BLINDED_SCALAR_BYTES] {
    let mut out = [0u8; BLINDED_SCALAR_BYTES];
    let r = r as u64;

    let mut carry: u64 = 0;
    for i in 0..32 {
        let prod = r * (GROUP_ORDER_BYTES[i] as u64) + carry;
        out[i] = prod as u8;
        carry = prod >> 8;
    }
    for byte in out.iter_mut().skip(32) {
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
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + core::ops::Sub<Output = T>,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
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
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + core::ops::Sub<Output = T>,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    // Guard: T must be wide enough to hold a 256-bit Curve25519 field element
    // *and* narrow enough to fit in the fixed-size scratch buffers used by
    // the ladder's cswap mask and the final serialization step. Failing
    // either is a backend-selection bug, not a runtime input error — panic so
    // it surfaces immediately rather than silently producing a wrong secret.
    let bits = modmath::type_bit_width::<T>();
    assert!(
        bits >= 256,
        "x25519: backend T is {} bits, need at least 256",
        bits
    );
    assert!(
        bits <= MAX_T_BYTES * 8,
        "x25519: backend T is {} bits, exceeds supported maximum of {}",
        bits,
        MAX_T_BYTES * 8
    );

    let p = T::from_bytes_le(&P_BYTES);
    let field = Curve25519FieldCt::new(p).unwrap();

    // RFC 7748 §5: clamp scalar, mask high bit of u-coordinate.
    // Wrap the clamped scalar in Zeroizing so it gets zeroed when this
    // function returns (best-effort against later stack reuse exposing
    // the bits — see api_debt_x25519 for what this does *not* address).
    let k = zeroize::Zeroizing::new(clamp(*k));
    let mut u_bytes = *u_in;
    u_bytes[31] &= 0x7f;
    let u = T::from_bytes_le(&u_bytes);

    // x1 stays constant throughout the ladder (= peer u in the field).
    // Peer u is public, but every downstream op is CT-typed, so it flows
    // through the CT field and gets the same residue type as everything else.
    let x1 = field.reduce(&u);
    let a24 = field.reduce(&T::from_bytes_le(&A24_BYTES));

    // Initial ladder state:
    //   (x2, z2) = (1, 0)   -- point at infinity
    //   (x3, z3) = (u, 1)   -- the input point
    let (x2, z2) = montgomery_ladder(&field, &x1, &a24, &*k, 255);

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

    // T can be wider than 32 bytes (e.g. FixedUInt<u32, 16> is 64 bytes). The
    // MAX_T_BYTES guard above bounds the scratch size; copy out the low 32
    // bytes — the field element is < p < 2^255 so the high half is zero.
    let mut scratch = zeroize::Zeroizing::new([0u8; MAX_T_BYTES]);
    let bytes = result.to_bytes_le(&mut *scratch);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

/// X25519 shared secret with scalar blinding: replaces `k` with
/// `k' = k + r·(8·ℓ)` for a fresh 32-bit `r`. Output equals
/// [`x25519`] for any curve-subgroup `u_in`; twist-point inputs may
/// diverge — see [`GROUP_ORDER_BYTES`].
///
/// Defends against multi-trace DPA aggregation on a long-lived secret
/// scalar. For single-trace correlation, combine with projective
/// coordinate re-randomization (future).
///
/// `R: CryptoRng` is required — a predictable RNG is worse than no
/// blinding (attacker recovers PRNG state from traces, removes the
/// blinding offline). Typical pattern: seed `ChaCha20Rng` from HW RNG
/// at startup, pass the `ChaCha20Rng` here.
///
/// Cost: ~12% over [`x25519`] (288 vs 255 ladder iterations).
#[inline(never)]
pub fn x25519_blinded<T, R>(rng: &mut R, k: &[u8; 32], u_in: &[u8; 32]) -> [u8; 32]
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + modmath::Parity
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + core::ops::Sub<Output = T>,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
    R: rand_core::CryptoRng,
{
    let bits = modmath::type_bit_width::<T>();
    assert!(
        bits >= 256,
        "x25519_blinded: backend T is {} bits, need at least 256",
        bits
    );
    assert!(
        bits <= MAX_T_BYTES * 8,
        "x25519_blinded: backend T is {} bits, exceeds supported maximum of {}",
        bits,
        MAX_T_BYTES * 8
    );

    let p = T::from_bytes_le(&P_BYTES);
    let field = Curve25519FieldCt::new(p).unwrap();

    let k_clamped = zeroize::Zeroizing::new(clamp(*k));
    let r = rng.next_u32();
    let k_prime = zeroize::Zeroizing::new(compute_blinded_scalar(&k_clamped, r));

    let mut u_bytes = *u_in;
    u_bytes[31] &= 0x7f;
    let u = T::from_bytes_le(&u_bytes);
    let x1 = field.reduce(&u);
    let a24 = field.reduce(&T::from_bytes_le(&A24_BYTES));

    let (x2, z2) = montgomery_ladder(&field, &x1, &a24, &*k_prime, BLINDED_BIT_COUNT);

    let z2_inv = field.inv(&z2);
    let result_res = field.mul(&x2, &z2_inv);
    let result = zeroize::Zeroizing::new(field.into_raw(&result_res));

    let mut scratch = zeroize::Zeroizing::new([0u8; MAX_T_BYTES]);
    let bytes = result.to_bytes_le(&mut *scratch);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
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
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + core::ops::Sub<Output = T>,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
    R: rand_core::CryptoRng,
{
    x25519_blinded::<T, R>(rng, k, &BASE_U_BYTES)
}

/// Shared ladder body. `x1` and `a24` are borrowed so the caller's
/// `ZeroizeOnDrop` wipe still fires at its scope end — moving them in
/// would leave the source bindings holding unwiped bytes.
#[inline(never)]
fn montgomery_ladder<'f, T>(
    field: &'f Curve25519FieldCt<T>,
    x1: &ResidueCt<'f, T>,
    a24: &ResidueCt<'f, T>,
    scalar: &[u8],
    bit_count: usize,
) -> (ResidueCt<'f, T>, ResidueCt<'f, T>)
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + modmath::Parity
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + core::ops::Sub<Output = T>,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    let mut x2 = field.one();
    let mut z2 = field.zero();
    let mut x3 = x1.clone();
    let mut z3 = field.one();
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
