//! Carrier-generic cross-backend equivalence suite.
//!
//! Each test is a generic `inner::<T>()` body run against every
//! deployment carrier — `FixedUInt` and `HeaplessBigInt`, both
//! personalities, at the widths downstream actually ships. A test
//! asserting a KNOWN answer (not merely cross-carrier agreement)
//! means the FIRST failing `(test, carrier)` pair names both the
//! broken layer and the exact carrier configuration.
//!
//! Carriers under test:
//!   - `FixedUInt<u32, 8, {Ct,Nct}>` — the reference fixed carrier.
//!   - `HeaplessBigInt<u32, 8, {Ct,Nct}>` — narrow runtime-length.
//!   - `HeaplessBigInt<u32, 16, {Ct,Nct}>` — wide runtime-length
//!     (512-bit box holding a 255-bit value → `len < CAP`), the
//!     cortex_m / riscv deploy shape.

#![cfg(all(
    feature = "fixed-bigint",
    any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"),
))]

use const_num_traits::{
    CarryingMul, Ct, FromByteSlice, Nct, One, OverflowingAdd, ToBytes, WrappingSub, Zero,
};
use ed25519_heapless::{
    Curve25519Field, Curve25519FieldCt, D_BYTES, G_Y_BYTES, Q_BYTES, SigningKey,
    UnsignedModularInt, sign, verify, x25519_base,
};
use fixed_bigint::{FixedUInt, HeaplessBigInt};
use modmath::{CiosMontMul, CiosMontMulCt};

// ---------------------------------------------------------------------------
// Carrier bound bundles.
// ---------------------------------------------------------------------------

/// Full CT sign / x25519 carrier bound (the personality verify does
/// NOT use).
trait CtCarrier:
    UnsignedModularInt
    + Copy
    + PartialEq
    + modmath::WideMul
    + CiosMontMulCt
    + const_num_traits::CtIsZero
    + subtle::ConditionallySelectable
    + subtle::ConstantTimeLess
where
    for<'a> &'a Self: const_num_traits::WrappingAdd<Output = Self> + WrappingSub<Output = Self>,
{
}
impl<T> CtCarrier for T
where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + CiosMontMulCt
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T> + WrappingSub<Output = T>,
{
}

/// Full Nct verify carrier bound.
trait NctCarrier:
    UnsignedModularInt + Copy + PartialEq + modmath::WideMul + CiosMontMul + modmath::NonCt
where
    for<'a> &'a Self: const_num_traits::WrappingAdd<Output = Self> + WrappingSub<Output = Self>,
{
}
impl<T> NctCarrier for T
where
    T: UnsignedModularInt + Copy + PartialEq + modmath::WideMul + CiosMontMul + modmath::NonCt,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T> + WrappingSub<Output = T>,
{
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Encode a `T` to its low 32 little-endian bytes.
fn le32<T: ToBytes + Copy>(v: &T) -> [u8; 32] {
    let bytes = (*v).to_le_bytes();
    let slice: &[u8] = bytes.as_ref();
    let mut out = [0u8; 32];
    let n = slice.len().min(32);
    out[..n].copy_from_slice(&slice[..n]);
    out
}

/// A 32-byte LE buffer with `v` in the low byte.
fn small(v: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = v;
    b
}

fn decode<T: FromByteSlice>(bytes: &[u8; 32]) -> T {
    <T as FromByteSlice>::from_le_slice(bytes).expect("from_le_slice")
}

// ---------------------------------------------------------------------------
// 1. Byte roundtrip — FromByteSlice + ToBytes.
// ---------------------------------------------------------------------------

#[test]
fn byte_roundtrip() {
    fn inner<T: FromByteSlice + ToBytes + Copy>() {
        let input = {
            let mut b = [0u8; 32];
            b[0] = 42;
            b[15] = 0x5a;
            b[30] = 0x3c;
            b
        };
        assert_eq!(le32(&decode::<T>(&input)), input);
    }
    inner::<FixedUInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 16, Ct>>();
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

// ---------------------------------------------------------------------------
// 2. Widening multiply primitive.
// ---------------------------------------------------------------------------

#[test]
fn carrying_mul_38() {
    // 38 * 38 = 1444 = 0x05a4, hi = 0. The exact operand pair
    // Curve25519's r2_mod_n setup feeds through the widening mul.
    fn inner<T>()
    where
        T: FromByteSlice + ToBytes + Copy + Zero + CarryingMul<Unsigned = T, Output = T>,
    {
        let a = decode::<T>(&small(38));
        let b = decode::<T>(&small(38));
        let (lo, hi) = <T as CarryingMul>::carrying_mul(a, b, <T as Zero>::zero());
        let mut expected_lo = [0u8; 32];
        expected_lo[0] = 0xa4;
        expected_lo[1] = 0x05;
        assert_eq!(le32(&lo), expected_lo, "carrying_mul lo");
        assert_eq!(le32(&hi), [0u8; 32], "carrying_mul hi");
    }
    inner::<FixedUInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 16, Ct>>();
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

#[test]
fn wide_mul_38() {
    fn inner<T: FromByteSlice + ToBytes + Copy + modmath::WideMul>() {
        let a = decode::<T>(&small(38));
        let b = decode::<T>(&small(38));
        let (lo, hi) = a.wide_mul(&b);
        let mut expected_lo = [0u8; 32];
        expected_lo[0] = 0xa4;
        expected_lo[1] = 0x05;
        assert_eq!(le32(&lo), expected_lo, "wide_mul lo");
        assert_eq!(le32(&hi), [0u8; 32], "wide_mul hi");
    }
    inner::<FixedUInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 16, Ct>>();
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

// ---------------------------------------------------------------------------
// 3. Ct field: reduce / mul / inv (the sign / x25519 personality).
// ---------------------------------------------------------------------------

#[test]
fn ct_field_reduce_roundtrips() {
    fn inner<T: CtCarrier>()
    where
        for<'a> &'a T: const_num_traits::WrappingAdd<Output = T> + WrappingSub<Output = T>,
    {
        let field = Curve25519FieldCt::<T>::curve25519().expect("curve25519");
        let r = field.reduce(&decode::<T>(&small(7)));
        assert_eq!(le32(&field.into_raw(&r)), small(7));
    }
    inner::<FixedUInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 16, Ct>>();
}

#[test]
fn ct_field_mul_small() {
    fn inner<T: CtCarrier>()
    where
        for<'a> &'a T: const_num_traits::WrappingAdd<Output = T> + WrappingSub<Output = T>,
    {
        let field = Curve25519FieldCt::<T>::curve25519().expect("curve25519");
        let a = field.reduce(&decode::<T>(&small(6)));
        let b = field.reduce(&decode::<T>(&small(7)));
        assert_eq!(le32(&field.into_raw(&field.mul(&a, &b))), small(42));
    }
    inner::<FixedUInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 8, Ct>>();
    inner::<HeaplessBigInt<u32, 16, Ct>>();
}

// ---------------------------------------------------------------------------
// 4. Nct field: reduce / mul / inv (the VERIFY personality (Nct) — the
//    Ct probes above never covered it).
// ---------------------------------------------------------------------------

#[test]
fn nct_field_reduce_roundtrips() {
    fn inner<T: NctCarrier>()
    where
        for<'a> &'a T: const_num_traits::WrappingAdd<Output = T> + WrappingSub<Output = T>,
    {
        let field = Curve25519Field::<T>::curve25519().expect("curve25519");
        let r = field.reduce(&decode::<T>(&small(7)));
        assert_eq!(le32(&field.into_raw(&r)), small(7));
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

#[test]
fn nct_field_mul_small() {
    fn inner<T: NctCarrier>()
    where
        for<'a> &'a T: const_num_traits::WrappingAdd<Output = T> + WrappingSub<Output = T>,
    {
        let field = Curve25519Field::<T>::curve25519().expect("curve25519");
        let a = field.reduce(&decode::<T>(&small(6)));
        let b = field.reduce(&decode::<T>(&small(7)));
        assert_eq!(le32(&field.into_raw(&field.mul(&a, &b))), small(42));
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

#[test]
fn nct_field_inv_known_answer() {
    // inv is Fermat exponentiation a^(p-2); inv(a)*a == 1.
    fn inner<T: NctCarrier>()
    where
        for<'a> &'a T: const_num_traits::WrappingAdd<Output = T> + WrappingSub<Output = T>,
    {
        let field = Curve25519Field::<T>::curve25519().expect("curve25519");
        let a = field.reduce(&decode::<T>(&small(7)));
        let a_inv = field.inv(&a);
        assert_eq!(le32(&field.into_raw(&field.mul(&a, &a_inv))), small(1));
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

// ---------------------------------------------------------------------------
// 5. Raw-`T` scalar arithmetic (sha512_modq shape) — outside the field
//    abstraction, directly on the carrier's runtime-length limbs. This
//    is what verify's scalar reduction and the `s >= q` / `acc >= q`
//    range checks exercise.
// ---------------------------------------------------------------------------

#[test]
fn raw_scalar_reduce_over_q() {
    // acc = q + 1; `acc >= q` must be true; `acc - q` must be 1.
    fn inner<T: UnsignedModularInt + Copy + PartialOrd>() {
        let q = decode::<T>(&Q_BYTES);
        let one = <T as One>::one();
        let (acc, _ovf) = <T as OverflowingAdd>::overflowing_add(q, one);
        assert!(acc >= q, "q+1 >= q comparison wrong");
        let reduced = <T as WrappingSub>::wrapping_sub(acc, q);
        assert_eq!(le32(&reduced), small(1), "(q+1) - q != 1");
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

// ---------------------------------------------------------------------------
// 6. Chained Nct field computation — the `recover_x` phase-1 formula
//     x² = (y² − 1) / (d·y² + 1) on a real 255-bit input (base point y).
//     Seven chained ops (reduce/mul/sub/mul/add/inv/mul) reusing
//     residues, vs single-op probes above. Discriminates "chained
//     field arithmetic" from the point-op / NAF / point_equal layer.
// ---------------------------------------------------------------------------

fn recover_x2_bytes<T>() -> [u8; 32]
where
    T: NctCarrier,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T> + WrappingSub<Output = T>,
{
    let field = Curve25519Field::<T>::curve25519().expect("curve25519");
    let y = field.reduce(&decode::<T>(&G_Y_BYTES));
    let d = field.reduce(&decode::<T>(&D_BYTES));
    let y2 = field.mul(&y, &y);
    let one = field.one();
    let numerator = field.sub(&y2, &one);
    let dy2 = field.mul(&d, &y2);
    let denominator = field.add(&dy2, &one);
    let inv_denom = field.inv(&denominator);
    let x2 = field.mul(&numerator, &inv_denom);
    le32(&field.into_raw(&x2))
}

#[test]
fn nct_recover_x2_chain_matches_reference() {
    let reference = recover_x2_bytes::<FixedUInt<u32, 8, Nct>>();
    assert_eq!(
        recover_x2_bytes::<HeaplessBigInt<u32, 8, Nct>>(),
        reference,
        "HeaplessBigInt<u32,8,Nct> recover_x² chain diverges"
    );
    assert_eq!(
        recover_x2_bytes::<HeaplessBigInt<u32, 16, Nct>>(),
        reference,
        "HeaplessBigInt<u32,16,Nct> recover_x² chain diverges"
    );
}

// ---------------------------------------------------------------------------
// 7. `&T: BitAnd` — used ONLY by the verify-side NAF recoding
//      (`jsf.rs` does `&s & &one`, `&s & &three`), never by sign or
//      x25519. Verify's where-clause is the only one that bounds
//      `for<'a> &'a T: BitAnd`. If the runtime-length `&T & &T` impl
//      is wrong, NAF digits are corrupt → wrong double-scalar-mul →
//      verify returns false.
// ---------------------------------------------------------------------------

#[test]
fn ref_bitand_known_answers() {
    fn inner<T>()
    where
        T: FromByteSlice + ToBytes + Copy + PartialEq + One,
        for<'a> &'a T: core::ops::BitAnd<Output = T>,
    {
        let one = <T as One>::one();
        // 0b...0111 & 0b...0011 = 0b...0011  (7 & 3 == 3)
        let seven = decode::<T>(&small(7));
        let three = decode::<T>(&small(3));
        assert_eq!(le32(&(&seven & &three)), small(3), "7 & 3 != 3");
        // low bit: 7 & 1 == 1, 6 & 1 == 0 — exactly the NAF parity test.
        assert_eq!(le32(&(&seven & &one)), small(1), "7 & 1 != 1");
        let six = decode::<T>(&small(6));
        assert_eq!(le32(&(&six & &one)), small(0), "6 & 1 != 0");
        // A wide operand: bit 200 set, & with 3 clears it → 0.
        let mut widebits = [0u8; 32];
        widebits[25] = 1 << 1; // bit 201
        let wide = decode::<T>(&widebits);
        assert_eq!(le32(&(&wide & &three)), small(0), "highbit & 3 != 0");
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

// ---------------------------------------------------------------------------
// 8. `Shr<usize>` / `ShrAssign<usize>` on the raw scalar — the NAF
//     recoding does `s_working >>= 1` up to 256× to consume the scalar
//     bit by bit; `recover_x` does `p3 >> 3`. Sign traverses the
//     scalar as bytes and never shifts a `T`, so this is a verify-only
//     path: a wrong runtime-length `Shr` corrupts NAF and fails verify
//     while leaving sign untouched.
// ---------------------------------------------------------------------------

#[test]
fn shr_by_value_known_answers() {
    fn inner<T>()
    where
        T: FromByteSlice + ToBytes + Copy + core::ops::Shr<usize, Output = T>,
    {
        // 8 >> 1 == 4, 8 >> 3 == 1.
        assert_eq!(
            le32(&(decode::<T>(&small(8)) >> 1)),
            small(4),
            "8 >> 1 != 4"
        );
        assert_eq!(
            le32(&(decode::<T>(&small(8)) >> 3)),
            small(1),
            "8 >> 3 != 1"
        );
        // Bit 200 >> 200 == 1.
        let mut hb = [0u8; 32];
        hb[25] = 1; // bit 200
        assert_eq!(
            le32(&(decode::<T>(&hb) >> 200)),
            small(1),
            "bit200 >> 200 != 1"
        );
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

#[test]
fn shr_assign_bit_walk() {
    // Mirror the NAF consume loop: shift a high bit down one step at a
    // time and check it lands where expected, then falls off to zero.
    fn inner<T>()
    where
        T: FromByteSlice + ToBytes + Copy + PartialEq + Zero + core::ops::ShrAssign<usize>,
    {
        let mut hb = [0u8; 32];
        hb[25] = 1; // bit 200
        let mut v = decode::<T>(&hb);
        for _ in 0..200 {
            v >>= 1;
        }
        assert_eq!(le32(&v), small(1), "after 200 >>=1 steps != 1");
        v >>= 1;
        assert_eq!(le32(&v), small(0), "after 201 >>=1 steps != 0");
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

// ---------------------------------------------------------------------------
// 9. Full `sha512_modq` Horner reduction — the raw-`T` scalar-mod-q path
//     VERIFY uses (sign reduces mod q through modmath's Ct field).
// ---------------------------------------------------------------------------

fn horner_mod_q<T>(hash: &[u8; 64]) -> [u8; 32]
where
    T: UnsignedModularInt + Copy + PartialOrd,
    for<'a> &'a T: WrappingSub<Output = T>,
{
    let q = decode::<T>(&Q_BYTES);
    let one = <T as One>::one();
    // Seed at q's width, not `zero()`'s minimal width, so the accumulator
    // has room to carry.
    let mut acc = <&T as WrappingSub>::wrapping_sub(&q, &q);
    for byte_idx in (0..64).rev() {
        for bit_idx in (0..8).rev() {
            let (doubled, _ovf) = <T as OverflowingAdd>::overflowing_add(acc, acc);
            acc = doubled;
            if (hash[byte_idx] >> bit_idx) & 1 == 1 {
                let (added, _) = <T as OverflowingAdd>::overflowing_add(acc, one);
                acc = added;
            }
            if acc >= q {
                acc = <T as WrappingSub>::wrapping_sub(acc, q);
            }
            if acc >= q {
                acc = <T as WrappingSub>::wrapping_sub(acc, q);
            }
        }
    }
    le32(&acc)
}

#[test]
fn mixed_len_compare_against_q() {
    // The Horner loop compares a swinging-width `acc` against full-len
    // `q`. Test PartialOrd with a SHORT-len operand (7, len 1) vs the
    // full-len q — the config the single-step reduce test (acc = q+1,
    // len 8) never hit.
    fn inner<T: FromByteSlice + Copy + PartialOrd>() {
        let q = decode::<T>(&Q_BYTES);
        let seven = decode::<T>(&small(7));
        assert!(seven < q, "7 < q should hold (short-len vs full-len)");
        assert!(!(seven >= q), "7 >= q should be false");
        assert!(q >= seven, "q >= 7 should hold");
        assert!(q > seven, "q > 7 should hold");
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

#[test]
fn overflowing_add_self_double() {
    // Self-doubling a value that was decoded (so it has the width of
    // its bytes) grows correctly across limb boundaries. Doubling only
    // "loses" bits when the value is minimal-width to begin with — see
    // the seed-width note on `horner_mod_q`.
    fn inner<T: FromByteSlice + ToBytes + Copy + OverflowingAdd<Output = T>>() {
        // 1 doubled 40× = 2^40, which lands in byte 5 (bit 40).
        let mut v = decode::<T>(&small(1));
        for _ in 0..40 {
            let (d, _ovf) = <T as OverflowingAdd>::overflowing_add(v, v);
            v = d;
        }
        let mut expected = [0u8; 32];
        expected[5] = 1; // 2^40 = bit 40 = byte 5, bit 0
        assert_eq!(le32(&v), expected, "1 doubled 40x != 2^40");
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

#[test]
fn overflowing_add_self_double_to_cap() {
    // Double `1` all the way to the top bit the carrier holds. On
    // u32×8 (CAP=8) that's 2^255 (byte 31, bit 7) after 255 steps —
    // len grows 1→8 across every limb boundary. A `len`-vs-`CAP`
    // overflow bug (doubling wraps at the current len instead of
    // extending) would collapse the value here.
    fn inner<T: FromByteSlice + ToBytes + Copy + OverflowingAdd<Output = T>>(steps: usize) {
        let mut v = decode::<T>(&small(1));
        for _ in 0..steps {
            let (d, _ovf) = <T as OverflowingAdd>::overflowing_add(v, v);
            v = d;
        }
        let mut expected = [0u8; 32];
        let bit = steps;
        expected[bit / 8] = 1 << (bit % 8);
        assert_eq!(le32(&v), expected, "1 doubled {steps}x != 2^{steps}");
    }
    // u32×8 tops out at 2^255 (bit 255). u32×16 has headroom to 2^511
    // but the ed25519 scalars only reach ~2^254, so 255 is the
    // deployment-relevant ceiling for both.
    inner::<FixedUInt<u32, 8, Nct>>(255);
    inner::<HeaplessBigInt<u32, 8, Nct>>(255);
    inner::<HeaplessBigInt<u32, 16, Nct>>(255);
}

#[test]
fn add_carry_into_second_limb() {
    // A single carry from limb 0 into limb 1 is handled correctly on a
    // decoded (byte-width) value: `0xC000_0000 + 0xC000_0000 =
    // 0x1_8000_0000` preserves bit 32 on both carriers.
    fn inner<T: FromByteSlice + ToBytes + Copy + OverflowingAdd<Output = T>>() {
        let mut x = [0u8; 32];
        x[3] = 0xc0; // 0xC000_0000 in limb 0
        let v = decode::<T>(&x);
        let (sum, _ovf) = <T as OverflowingAdd>::overflowing_add(v, v);
        let mut expected = [0u8; 32];
        expected[3] = 0x80; // limb 0 = 0x8000_0000
        expected[4] = 0x01; // limb 1 = 1  (the carry bit 32)
        assert_eq!(
            le32(&sum),
            expected,
            "0xC0000000 doubled lost the carry into limb 1"
        );
    }
    inner::<FixedUInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 8, Nct>>();
    inner::<HeaplessBigInt<u32, 16, Nct>>();
}

#[test]
fn double_dense_value() {
    // Double `q` (a dense ~253-bit value, not a clean power of two).
    // 2*q must equal q + q. Cross-checked heapless vs fixed. The
    // self-double probes used single-bit values; the Horner loop
    // doubles DENSE accumulators.
    fn dbl<T: FromByteSlice + ToBytes + Copy + OverflowingAdd<Output = T>>() -> [u8; 32] {
        let q = decode::<T>(&Q_BYTES);
        let (d, _ovf) = <T as OverflowingAdd>::overflowing_add(q, q);
        le32(&d)
    }
    let reference = dbl::<FixedUInt<u32, 8, Nct>>();
    assert_eq!(
        dbl::<HeaplessBigInt<u32, 8, Nct>>(),
        reference,
        "2*q dense-double diverges on u32x8"
    );
    assert_eq!(
        dbl::<HeaplessBigInt<u32, 16, Nct>>(),
        reference,
        "2*q dense-double diverges on u32x16"
    );
}

// Raw-`T` `sha512_modq` Horner must agree across carriers.
#[test]
fn horner_mod_q_matches_reference() {
    // A realistic full-width hash-shaped input (not all-zero, MSB set).
    let mut hash = [0u8; 64];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let reference = horner_mod_q::<FixedUInt<u32, 8, Nct>>(&hash);
    assert_eq!(
        horner_mod_q::<HeaplessBigInt<u32, 8, Nct>>(&hash),
        reference,
        "HeaplessBigInt<u32,8,Nct> sha512_modq Horner diverges"
    );
    assert_eq!(
        horner_mod_q::<HeaplessBigInt<u32, 16, Nct>>(&hash),
        reference,
        "HeaplessBigInt<u32,16,Nct> sha512_modq Horner diverges"
    );
}

// ---------------------------------------------------------------------------
// 10. End-to-end: x25519, sign-side pubkey, and the full Nct verify path.
// ---------------------------------------------------------------------------

#[test]
fn x25519_base_matches_reference() {
    let k = [3u8; 32];
    let expected = x25519_base::<FixedUInt<u32, 8, Ct>>(&k).unwrap();
    fn inner<T: CtCarrier>(k: &[u8; 32], expected: &[u8; 32])
    where
        for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
            + WrappingSub<Output = T>
            + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
        <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
        T: modmath::Parity,
    {
        assert_eq!(&x25519_base::<T>(k).unwrap(), expected);
    }
    inner::<HeaplessBigInt<u32, 8, Ct>>(&k, &expected);
    inner::<HeaplessBigInt<u32, 16, Ct>>(&k, &expected);
}

#[test]
fn sign_pubkey_matches_reference() {
    let seed = [7u8; 32];
    let expected = SigningKey::<FixedUInt<u32, 8, Ct>>::from_seed(&seed)
        .expect("from_seed reference")
        .public_key();
    fn inner<T>(seed: &[u8; 32], expected: &[u8; 32])
    where
        T: ed25519_heapless::SignBackend,
        for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
            + WrappingSub<Output = T>
            + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
        <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
    {
        let pk = SigningKey::<T>::from_seed(seed)
            .expect("from_seed")
            .public_key();
        assert_eq!(&pk, expected);
    }
    inner::<HeaplessBigInt<u32, 8, Ct>>(&seed, &expected);
    inner::<HeaplessBigInt<u32, 16, Ct>>(&seed, &expected);
}

#[test]
fn verify_accepts_valid_signature() {
    // Produce a valid (pk, msg, sig) with a known-good Ct carrier.
    let seed = [7u8; 32];
    let sk = SigningKey::<HeaplessBigInt<u32, 8, Ct>>::from_seed(&seed).expect("from_seed");
    let pk = sk.public_key();
    let msg = b"krabitls certificate_verify";
    let sig = sign(&sk, msg).expect("sign");

    fn inner<T: NctCarrier>(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64], label: &str)
    where
        for<'a> &'a T: core::ops::BitAnd<Output = T>
            + const_num_traits::WrappingAdd<Output = T>
            + WrappingSub<Output = T>,
    {
        assert!(
            verify::<T>(*pk, msg, *sig),
            "verify rejected a valid signature on {label}"
        );
    }
    inner::<FixedUInt<u32, 8, Nct>>(&pk, msg, &sig, "FixedUInt<u32,8,Nct>");
    inner::<HeaplessBigInt<u32, 8, Nct>>(&pk, msg, &sig, "HeaplessBigInt<u32,8,Nct>");
    inner::<HeaplessBigInt<u32, 16, Nct>>(&pk, msg, &sig, "HeaplessBigInt<u32,16,Nct>");
}

// The Ct-field verify path (`verify_with_field` on `Curve25519FieldCt`)
// must accept exactly what the default Nct `verify` accepts and reject
// what it rejects — verify is public-data-only, so the personality is a
// speed choice, not a correctness one. This is the single-carrier
// deployment: one `…, Ct` monomorphization signs AND verifies.
#[test]
fn verify_ct_field_matches_nct() {
    use ed25519_heapless::{Curve25519FieldCt, verify_with_field};

    type C = HeaplessBigInt<u32, 16, Ct>;

    let seed = [7u8; 32];
    let sk = SigningKey::<C>::from_seed(&seed).expect("from_seed");
    let pk = sk.public_key();
    let msg = b"single-carrier verify";
    let good = sign(&sk, msg).expect("sign");
    // A tampered signature the valid path must reject.
    let mut bad = good;
    bad[0] ^= 0x01;

    let field = Curve25519FieldCt::<C>::curve25519().expect("ct field");

    // Ct-field verify accepts the valid signature ...
    assert!(
        verify_with_field(&field, pk, msg, good),
        "Ct-field verify rejected a valid signature"
    );
    // ... and rejects the tampered one.
    assert!(
        !verify_with_field(&field, pk, msg, bad),
        "Ct-field verify accepted a tampered signature"
    );
    // Same verdict as the default Nct path on the matching carrier.
    assert!(verify::<HeaplessBigInt<u32, 16, Nct>>(pk, msg, good));
    assert!(!verify::<HeaplessBigInt<u32, 16, Nct>>(pk, msg, bad));
}
