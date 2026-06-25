//! Ed25519 signing primitives — CT counterparts of the point ops in
//! [`crate::strict`].
//!
//! Verify operates on public inputs; its NAF double-scalar mult is
//! variable-time. Sign operates on the long-term secret scalar `a` and
//! a per-signature secret nonce `r`. Both scalars must drive a CT
//! single-scalar multiplication on the Edwards curve, so the point
//! arithmetic and the ladder live here in `ResidueCt` form.

use crate::curve25519_field::Curve25519FieldCt;
use crate::{D_BYTES, UnsignedModularInt};
use modmath::ResidueCt;
use subtle::Choice;

// =========================================================================
// Type aliases — CT analogs of strict.rs's EdPoint / NielsPoint
// =========================================================================

pub(crate) type EdPointCt<'f, T> = (
    ResidueCt<'f, T>,
    ResidueCt<'f, T>,
    ResidueCt<'f, T>,
    ResidueCt<'f, T>,
);

pub(crate) type NielsPointCt<'f, T> = (ResidueCt<'f, T>, ResidueCt<'f, T>, ResidueCt<'f, T>);

// =========================================================================
// Point operations on Curve25519FieldCt
// =========================================================================

#[inline(never)]
pub(crate) fn point_double_ct<'f, T>(
    pp: &EdPointCt<'f, T>,
    field: &'f Curve25519FieldCt<T>,
) -> EdPointCt<'f, T>
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
    // a = X²; b = Y²; c = 2·Z²; d = −A (a = −1 for Ed25519)
    // e = (X+Y)² − a − b; g = d + b; f = g − c; h = d − b
    // X' = e·f; Y' = g·h; Z' = f·g; T' = e·h
    let a = field.mul(&pp.0, &pp.0);
    let b = field.mul(&pp.1, &pp.1);
    let z_sq = field.mul(&pp.2, &pp.2);
    let c = field.add(&z_sq, &z_sq);
    let zero = field.zero();
    let d = field.sub(&zero, &a);
    let x_plus_y = field.add(&pp.0, &pp.1);
    let xy_sq = field.mul(&x_plus_y, &x_plus_y);
    let e_tmp = field.sub(&xy_sq, &a);
    let e = field.sub(&e_tmp, &b);
    let g = field.add(&d, &b);
    let f = field.sub(&g, &c);
    let h = field.sub(&d, &b);
    (
        field.mul(&e, &f),
        field.mul(&g, &h),
        field.mul(&f, &g),
        field.mul(&e, &h),
    )
}

pub(crate) fn to_niels_ct<'f, T>(
    pp: &EdPointCt<'f, T>,
    d_raw: T,
    field: &'f Curve25519FieldCt<T>,
) -> NielsPointCt<'f, T>
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
    let y_plus_x = field.add(&pp.1, &pp.0);
    let y_minus_x = field.sub(&pp.1, &pp.0);
    let d = field.reduce(&d_raw);
    let dt = field.mul(&d, &pp.3);
    let two_dt = field.add(&dt, &dt);
    (y_plus_x, y_minus_x, two_dt)
}

#[inline(never)]
pub(crate) fn point_add_niels_ct<'f, T>(
    pp: &EdPointCt<'f, T>,
    niels: &NielsPointCt<'f, T>,
    field: &'f Curve25519FieldCt<T>,
) -> EdPointCt<'f, T>
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
    // A = (Y₁−X₁)·(y−x); B = (Y₁+X₁)·(y+x); C = T₁·2dt; D = 2·Z₁
    let pp_y_minus_x = field.sub(&pp.1, &pp.0);
    let a = field.mul(&pp_y_minus_x, &niels.1);
    let pp_y_plus_x = field.add(&pp.1, &pp.0);
    let b = field.mul(&pp_y_plus_x, &niels.0);
    let c = field.mul(&pp.3, &niels.2);
    let d = field.add(&pp.2, &pp.2);
    // E = B − A; F = D − C; G = D + C; H = B + A
    let e = field.sub(&b, &a);
    let f = field.sub(&d, &c);
    let g = field.add(&d, &c);
    let h = field.add(&b, &a);
    (
        field.mul(&e, &f),
        field.mul(&g, &h),
        field.mul(&f, &g),
        field.mul(&e, &h),
    )
}

/// Branchless conditional swap of two Edwards points. Identical-shape
/// to the cswap on Montgomery ladder state in x25519, just applied to
/// each of the four extended-twisted projective coords.
#[inline]
pub(crate) fn point_cswap_ct<'f, T>(
    choice: Choice,
    a: &mut EdPointCt<'f, T>,
    b: &mut EdPointCt<'f, T>,
) where
    T: subtle::ConditionallySelectable + modmath::MontStorage,
{
    ResidueCt::cswap(choice, &mut a.0, &mut b.0);
    ResidueCt::cswap(choice, &mut a.1, &mut b.1);
    ResidueCt::cswap(choice, &mut a.2, &mut b.2);
    ResidueCt::cswap(choice, &mut a.3, &mut b.3);
}

// =========================================================================
// CT scalar multiplication on the Edwards curve
// =========================================================================

/// `k · base` on the Edwards curve. Branchless Montgomery-ladder shape
/// on extended-twisted projective points. Constant-time with respect
/// to `k`: every iteration runs one doubling + one niels addition and
/// one cswap; the cswap pattern matches the scalar bit but does not
/// branch on it.
///
/// `scalar` is read MSB-first across `bit_count` bits. Leading zero
/// bits are CT-safe — the cswap stays at identity until the first set
/// bit appears, after which the accumulator carries the partial sum.
#[inline(never)]
pub(crate) fn scalar_mult_ct<'f, T>(
    field: &'f Curve25519FieldCt<T>,
    base: &EdPointCt<'f, T>,
    scalar: &[u8],
    bit_count: usize,
) -> EdPointCt<'f, T>
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
    let d_raw = T::from_bytes_le(&D_BYTES);
    let base_niels = to_niels_ct(base, d_raw, field);

    // Identity in extended-twisted Edwards: (0, 1, 1, 0).
    let mut acc: EdPointCt<'f, T> = (field.zero(), field.one(), field.one(), field.zero());

    for t in (0..bit_count).rev() {
        acc = point_double_ct(&acc, field);
        let bit = (scalar[t >> 3] >> (t & 7)) & 1;
        // "Add-always" via CT cswap: compute the sum, then conditionally
        // swap it into the accumulator based on the bit.
        let mut sum = point_add_niels_ct(&acc, &base_niels, field);
        point_cswap_ct(Choice::from(bit), &mut acc, &mut sum);
    }

    acc
}

// =========================================================================
// Point compression
// =========================================================================

/// Encode an extended-twisted projective Edwards point as 32 bytes
/// per RFC 8032 §5.1.2. Computes affine `(x, y)` via one inversion,
/// emits `y` little-endian with the high bit of byte 31 set to the
/// parity of `x`.
pub(crate) fn point_compress_ct<'f, T>(
    pp: &EdPointCt<'f, T>,
    field: &'f Curve25519FieldCt<T>,
) -> [u8; 32]
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
        + core::ops::Sub<Output = T>
        + core::ops::ShrAssign<usize>,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    const {
        // x25519.rs caps T at 64 bytes; the same bound applies here so
        // the scratch buffer below can be a stack array.
        assert!(core::mem::size_of::<T>() <= 64);
    }

    let z_inv = field.inv(&pp.2);
    let x = field.mul(&pp.0, &z_inv);
    let y = field.mul(&pp.1, &z_inv);

    let x_raw = field.into_raw(&x);
    let y_raw = field.into_raw(&y);

    let parity = (x_raw & T::one()) == T::one();

    // T may be wider than 32 bytes (e.g. FixedUInt<u32, 16> is 64
    // bytes); to_bytes_le needs a buffer matching T's width. y < p <
    // 2^255 fits in the low 32 bytes, the rest is zero.
    let mut scratch = zeroize::Zeroizing::new([0u8; 64]);
    let bytes = y_raw.to_bytes_le(&mut *scratch);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    // RFC 8032 §5.1.2: y is 255 bits; the high bit of byte 31 carries
    // the parity of x. y < p < 2^255 so bit 7 of byte 31 is zero before
    // we OR in the parity.
    out[31] |= (parity as u8) << 7;
    out
}

// =========================================================================
// CT scalar reduction mod q
// =========================================================================

/// `SHA-512(parts...) mod q`, constant-time over the hash bytes. Sign
/// derives its per-signature nonce `r = SHA-512(prefix || M) mod q`
/// where the input is secret-dependent (`prefix` is part of the
/// expanded long-term key), so the modular reduction has to be CT.
///
/// Same bit-by-bit Horner as `strict::sha512_modq`, but every branch
/// becomes a `subtle::ConditionallySelectable` choice on `T`.
#[inline(never)]
pub(crate) fn sha512_modq_ct<T>(parts: &[&[u8]], q: &T) -> T
where
    T: UnsignedModularInt
        + Copy
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingSub
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    #[cfg(all(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
    compile_error!(
        "ed25519_heapless: enable at most one SHA-512 backend feature — both `sha512-hmac-sha512` and `sha512-sha2` were enabled"
    );
    #[cfg(not(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2")))]
    compile_error!(
        "ed25519_heapless: enable exactly one of the SHA-512 backend features `sha512-hmac-sha512` or `sha512-sha2`"
    );
    #[cfg(all(feature = "sha512-hmac-sha512", not(feature = "sha512-sha2")))]
    let hash: zeroize::Zeroizing<[u8; 64]> = {
        let mut compact_sha = hmac_sha512::Hash::new();
        for part in parts {
            compact_sha.update(part);
        }
        zeroize::Zeroizing::new(compact_sha.finalize())
    };
    #[cfg(all(feature = "sha512-sha2", not(feature = "sha512-hmac-sha512")))]
    let hash: zeroize::Zeroizing<[u8; 64]> = {
        use sha2::Digest;
        let mut compact_sha = sha2::Sha512::new();
        for part in parts {
            compact_sha.update(part);
        }
        zeroize::Zeroizing::new(compact_sha.finalize().into())
    };

    let zero = T::zero();
    let one = T::one();
    let mut acc = T::zero();

    for byte_idx in (0..64).rev() {
        for bit_idx in (0..8).rev() {
            // acc *= 2
            let (doubled, _overflow) = acc.overflowing_add(&acc);
            acc = doubled;

            // acc += bit (branchlessly)
            let bit_val = (hash[byte_idx] >> bit_idx) & 1;
            let bit_t = T::conditional_select(&zero, &one, Choice::from(bit_val));
            let (with_bit, _) = acc.overflowing_add(&bit_t);
            acc = with_bit;

            // CT reduce: acc < 2q + 1 after the increment, so at most
            // two conditional subtractions reach the canonical range.
            for _ in 0..2 {
                let candidate = acc.wrapping_sub(q);
                let needs_sub = !acc.ct_lt(q);
                acc = T::conditional_select(&acc, &candidate, needs_sub);
            }
        }
    }
    acc
}

// =========================================================================
// Tests
// =========================================================================

/// The Ed25519 base point `G` in extended-twisted projective form
/// over a CT field instance. Constants from `G_X_BYTES` / `G_Y_BYTES`
/// / `G_T_BYTES`, projective `Z = 1`.
pub(crate) fn base_point_ct<'f, T>(field: &'f Curve25519FieldCt<T>) -> EdPointCt<'f, T>
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
        + subtle::ConstantTimeLess,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    let gx = field.reduce(&T::from_bytes_le(&crate::G_X_BYTES));
    let gy = field.reduce(&T::from_bytes_le(&crate::G_Y_BYTES));
    let one = field.one();
    let gt = field.reduce(&T::from_bytes_le(&crate::G_T_BYTES));
    (gx, gy, one, gt)
}

#[cfg(all(test, feature = "fixed-bigint"))]
mod tests {
    use super::*;
    use crate::curve25519_field::Curve25519FieldCt;
    use fixed_bigint::FixedUInt;

    type T = FixedUInt<u32, 16, fixed_bigint::Ct>;

    /// Two projective points are geometrically equal iff
    /// `X1·Z2 == X2·Z1` and `Y1·Z2 == Y2·Z1`. Comparing the projective
    /// coordinates directly would miss equivalent representations.
    fn projective_eq<'f>(
        a: &EdPointCt<'f, T>,
        b: &EdPointCt<'f, T>,
        field: &'f Curve25519FieldCt<T>,
    ) -> bool {
        let lhs_x = field.mul(&a.0, &b.2);
        let rhs_x = field.mul(&b.0, &a.2);
        let lhs_y = field.mul(&a.1, &b.2);
        let rhs_y = field.mul(&b.1, &a.2);
        lhs_x == rhs_x && lhs_y == rhs_y
    }

    #[test]
    fn double_matches_add_self() {
        let field = Curve25519FieldCt::<T>::curve25519().unwrap();
        let g = base_point_ct(&field);
        let d_raw = T::from_bytes_le(&D_BYTES);
        let g_niels = to_niels_ct(&g, d_raw, &field);

        let doubled = point_double_ct(&g, &field);
        let added = point_add_niels_ct(&g, &g_niels, &field);

        assert!(projective_eq(&doubled, &added, &field));
    }

    #[test]
    fn scalar_mult_by_one_returns_base() {
        let field = Curve25519FieldCt::<T>::curve25519().unwrap();
        let g = base_point_ct(&field);

        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        let result = scalar_mult_ct(&field, &g, &scalar, 256);

        assert!(projective_eq(&result, &g, &field));
    }

    #[test]
    fn scalar_mult_by_two_matches_double() {
        let field = Curve25519FieldCt::<T>::curve25519().unwrap();
        let g = base_point_ct(&field);

        let mut scalar = [0u8; 32];
        scalar[0] = 2;
        let result = scalar_mult_ct(&field, &g, &scalar, 256);
        let doubled = point_double_ct(&g, &field);

        assert!(projective_eq(&result, &doubled, &field));
    }
}
