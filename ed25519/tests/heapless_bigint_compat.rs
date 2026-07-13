//! Cross-backend equivalence probes against `FixedUInt<u32, 8, _>` vs
//! `HeaplessBigInt<u32, 8, _>`, from smallest primitive to full
//! ed25519 entry point. Every backend-independent property should hold
//! between the two carriers — the FIRST test in this file that fails
//! localizes the bug to the layer named in the test.
//!
//! Ordering (outer → inner is the READING order; the actual
//! localization is inner → outer):
//!
//! 1. `byte_roundtrip_bytes_match` — `FromByteSlice` + `ToBytes` on T
//!    alone. Fails ⇒ backend disagrees on canonical encoding; nothing
//!    below can be right.
//! 2. `field_reduce_of_small_value_matches` — `Field::reduce(&raw)`
//!    then `Field::into_raw(&residue)` on a value < modulus. Fails ⇒
//!    Montgomery form / R conversion disagrees.
//! 3. `field_mul_by_one_is_identity` — CIOS multiplication vs the
//!    field's `one()`. Fails ⇒ CIOS is broken for this shape.
//! 4. `field_mul_of_two_small_values_matches` — CIOS on two
//!    reduce'd small integers. Fails ⇒ general CIOS.
//! 5. `x25519_base_output_matches` — output of the Curve25519 scalar
//!    ladder with the base point. Fails ⇒ ladder / field composition.
//! 6. `signing_key_public_matches` — end-to-end ed25519 sign-side
//!    pubkey derivation.
//!
//! On the `experiment/heapless-runtime-len` branch as of writing,
//! items 2 onward fail; item 1 passes. That places the divergence
//! inside modmath's Ct field constructor / reducer against the
//! runtime-length HeaplessBigInt.

#![cfg(all(
    feature = "fixed-bigint",
    any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"),
))]

use const_num_traits::{CarryingMul, Ct, FromByteSlice, ToBytes, Zero};
use ed25519_heapless::{Curve25519FieldCt, P_BYTES, SigningKey, x25519_base};
use fixed_bigint::{FixedUInt, HeaplessBigInt};
use modmath::CiosMontMulCt;

type FCt = FixedUInt<u32, 8, Ct>;
type HCt = HeaplessBigInt<u32, 8, Ct>;

/// Encode a `T` to its 32-byte little-endian form.
fn le_bytes<T: ToBytes + Copy>(v: &T) -> [u8; 32] {
    let bytes = (*v).to_le_bytes();
    let slice: &[u8] = bytes.as_ref();
    let mut out = [0u8; 32];
    // Backends may zero-extend or truncate to their T::BYTE_WIDTH;
    // copy up to 32 bytes and pad with zero. Both sides do the
    // same thing so any difference reflects a real disagreement.
    let n = slice.len().min(32);
    out[..n].copy_from_slice(&slice[..n]);
    out
}

// ---------------------------------------------------------------------------
// 1. Byte roundtrip — FromByteSlice + ToBytes
// ---------------------------------------------------------------------------

#[test]
fn byte_roundtrip_bytes_match() {
    // A value < p so no reduction is even conceptually involved.
    let mut input = [0u8; 32];
    input[0] = 42;
    input[15] = 0x5a;
    input[30] = 0x3c;

    let f: FCt = FCt::from_le_slice(&input).expect("FixedUInt from_le_slice");
    let h: HCt = HCt::from_le_slice(&input).expect("HeaplessBigInt from_le_slice");

    assert_eq!(le_bytes(&f), input, "FixedUInt bytes didn't roundtrip");
    assert_eq!(le_bytes(&h), input, "HeaplessBigInt bytes didn't roundtrip");
    assert_eq!(
        le_bytes(&f),
        le_bytes(&h),
        "same input encoded differently between backends"
    );
}

// ---------------------------------------------------------------------------
// 1.5 Direct `CarryingMul` primitive: exactly the shape modmath's
//     WideMul blanket calls through — `carrying_mul(a, b, zero)`.
//     If the fix in alpha.16 landed and modmath's blanket resolves
//     to it, `38 * 38` here must produce identical `lo`/`hi` on both
//     carriers.
// ---------------------------------------------------------------------------

fn carrying_mul_bytes<T>(a: u8, b: u8) -> ([u8; 32], [u8; 32])
where
    T: FromByteSlice + ToBytes + Copy + Zero + CarryingMul<Unsigned = T, Output = T>,
{
    let mut a_bytes = [0u8; 32];
    a_bytes[0] = a;
    let mut b_bytes = [0u8; 32];
    b_bytes[0] = b;
    let av = <T as FromByteSlice>::from_le_slice(&a_bytes).expect("from a");
    let bv = <T as FromByteSlice>::from_le_slice(&b_bytes).expect("from b");
    let (lo, hi) = <T as CarryingMul>::carrying_mul(av, bv, <T as Zero>::zero());
    (le_bytes(&lo), le_bytes(&hi))
}

#[test]
fn carrying_mul_of_38_matches_between_backends() {
    // 38 * 38 = 1444 = 0x5a4. Should land entirely in lo[0..2],
    // hi should be all zeros. This is the exact operand pair
    // Curve25519's `r2_mod_n = (2^256 mod p)^2 mod p` setup uses.
    let (fb_lo, fb_hi) = carrying_mul_bytes::<FCt>(38, 38);
    let (hb_lo, hb_hi) = carrying_mul_bytes::<HCt>(38, 38);
    assert_eq!(fb_lo, hb_lo, "carrying_mul(38, 38): lo disagrees");
    assert_eq!(fb_hi, hb_hi, "carrying_mul(38, 38): hi disagrees");
    // Also assert the expected numeric answer so the test is
    // meaningful even if both backends agree on the wrong value.
    let mut expected_lo = [0u8; 32];
    expected_lo[0] = 0xa4;
    expected_lo[1] = 0x05;
    let expected_hi = [0u8; 32];
    assert_eq!(
        fb_lo, expected_lo,
        "FixedUInt carrying_mul(38,38) lo != 1444"
    );
    assert_eq!(fb_hi, expected_hi, "FixedUInt carrying_mul(38,38) hi != 0");
}

// ---------------------------------------------------------------------------
// 1.75 modmath's `WideMul::wide_mul` on the same tiny inputs — the
//     blanket impl over `CarryingMul` should produce the same
//     `(lo, hi)` split. If this passes on both backends but field
//     reduce still fails, the divergence is inside modmath's
//     Montgomery machinery further up (r2_mod_n setup, or the
//     Montgomery-reduction loop itself).
// ---------------------------------------------------------------------------

fn wide_mul_bytes<T>(a: u8, b: u8) -> ([u8; 32], [u8; 32])
where
    T: FromByteSlice + ToBytes + Copy + modmath::WideMul,
{
    let mut a_bytes = [0u8; 32];
    a_bytes[0] = a;
    let mut b_bytes = [0u8; 32];
    b_bytes[0] = b;
    let av = <T as FromByteSlice>::from_le_slice(&a_bytes).expect("from a");
    let bv = <T as FromByteSlice>::from_le_slice(&b_bytes).expect("from b");
    let (lo, hi) = av.wide_mul(&bv);
    (le_bytes(&lo), le_bytes(&hi))
}

#[test]
fn wide_mul_of_38_matches_between_backends() {
    let (fb_lo, fb_hi) = wide_mul_bytes::<FCt>(38, 38);
    let (hb_lo, hb_hi) = wide_mul_bytes::<HCt>(38, 38);
    assert_eq!(fb_lo, hb_lo, "wide_mul(38, 38): lo disagrees");
    assert_eq!(fb_hi, hb_hi, "wide_mul(38, 38): hi disagrees");
    let mut expected_lo = [0u8; 32];
    expected_lo[0] = 0xa4;
    expected_lo[1] = 0x05;
    let expected_hi = [0u8; 32];
    assert_eq!(fb_lo, expected_lo, "FixedUInt wide_mul(38,38) lo != 1444");
    assert_eq!(fb_hi, expected_hi, "FixedUInt wide_mul(38,38) hi != 0");
}

// ---------------------------------------------------------------------------
// 2. Field reduce roundtrip
// ---------------------------------------------------------------------------

fn field_reduce_bytes<T>(input: &[u8; 32]) -> [u8; 32]
where
    T: ed25519_heapless::UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + CiosMontMulCt
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    let field = Curve25519FieldCt::<T>::curve25519().expect("curve25519");
    let raw = <T as FromByteSlice>::from_le_slice(input).expect("from_le_slice");
    let residue = field.reduce(&raw);
    let out = field.into_raw(&residue);
    le_bytes(&out)
}

#[test]
fn field_reduce_of_small_value_matches() {
    let mut input = [0u8; 32];
    input[0] = 7;
    let fb = field_reduce_bytes::<FCt>(&input);
    let hb = field_reduce_bytes::<HCt>(&input);
    assert_eq!(fb, input, "FixedUInt reduce(7) didn't roundtrip to 7");
    assert_eq!(hb, input, "HeaplessBigInt reduce(7) didn't roundtrip to 7");
    assert_eq!(
        fb, hb,
        "reduce/into_raw of the same small value disagrees between backends"
    );
}

// ---------------------------------------------------------------------------
// 3. Field mul by one is identity
// ---------------------------------------------------------------------------

fn field_mul_by_one_bytes<T>(input: &[u8; 32]) -> [u8; 32]
where
    T: ed25519_heapless::UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + CiosMontMulCt
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    let field = Curve25519FieldCt::<T>::curve25519().expect("curve25519");
    let raw = <T as FromByteSlice>::from_le_slice(input).expect("from_le_slice");
    let residue = field.reduce(&raw);
    let one = field.one();
    let product = field.mul(&residue, &one);
    let out = field.into_raw(&product);
    le_bytes(&out)
}

#[test]
fn field_mul_by_one_is_identity() {
    let mut input = [0u8; 32];
    input[0] = 7;
    let fb = field_mul_by_one_bytes::<FCt>(&input);
    let hb = field_mul_by_one_bytes::<HCt>(&input);
    assert_eq!(fb, input, "FixedUInt mul-by-one didn't preserve 7");
    assert_eq!(hb, input, "HeaplessBigInt mul-by-one didn't preserve 7");
    assert_eq!(fb, hb, "mul-by-one output disagrees between backends");
}

// ---------------------------------------------------------------------------
// 4. Field mul of two small values
// ---------------------------------------------------------------------------

fn field_mul_bytes<T>(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32]
where
    T: ed25519_heapless::UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + CiosMontMulCt
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    let field = Curve25519FieldCt::<T>::curve25519().expect("curve25519");
    let a_raw = <T as FromByteSlice>::from_le_slice(a).expect("from_le_slice a");
    let b_raw = <T as FromByteSlice>::from_le_slice(b).expect("from_le_slice b");
    let ra = field.reduce(&a_raw);
    let rb = field.reduce(&b_raw);
    let product = field.mul(&ra, &rb);
    let out = field.into_raw(&product);
    le_bytes(&out)
}

#[test]
fn field_mul_of_two_small_values_matches() {
    // 6 * 7 = 42, no reduction needed; if backends disagree here it's
    // pure schoolbook CIOS on tiny values.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a[0] = 6;
    b[0] = 7;
    let mut expected = [0u8; 32];
    expected[0] = 42;
    let fb = field_mul_bytes::<FCt>(&a, &b);
    let hb = field_mul_bytes::<HCt>(&a, &b);
    assert_eq!(fb, expected, "FixedUInt 6*7 != 42");
    assert_eq!(hb, expected, "HeaplessBigInt 6*7 != 42");
    assert_eq!(fb, hb, "6*7 output disagrees between backends");
}

// ---------------------------------------------------------------------------
// 5. x25519 base ladder output
// ---------------------------------------------------------------------------

#[test]
fn x25519_base_output_matches() {
    let k = [3u8; 32];
    let fb = x25519_base::<FCt>(&k);
    let hb = x25519_base::<HCt>(&k);
    assert_eq!(fb, hb, "x25519_base(k=3) output disagrees between backends");
}

// ---------------------------------------------------------------------------
// 6. Ed25519 public-key derivation from a seed
// ---------------------------------------------------------------------------

#[test]
fn signing_key_public_matches() {
    let seed = [7u8; 32];
    let fb = SigningKey::<FCt>::from_seed(&seed)
        .expect("from_seed FixedUInt")
        .public_key();
    let hb = SigningKey::<HCt>::from_seed(&seed)
        .expect("from_seed HeaplessBigInt")
        .public_key();
    assert_eq!(
        fb, hb,
        "SigningKey::from_seed pubkey disagrees between backends"
    );
}

// Sanity: make sure the P_BYTES import is used (silences dead-code
// warning if we ever trim the file down).
const _: [u8; 32] = P_BYTES;
