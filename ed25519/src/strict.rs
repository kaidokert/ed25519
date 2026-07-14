use crate::UnsignedModularInt;
use crate::curve25519_field::{Curve25519Field, VerifyField};
use crate::jsf::NafSign;

// Tuples of field residues. Lifetime `'f` binds them to the producing
// field instance — the type system prevents mixing residues from a
// different field. Generic over the verify field `F` so the whole path
// runs on either the Nct field (default) or the Ct field.
type Res<'f, F, T> = <F as VerifyField<T>>::Residue<'f>;
type EdPoint<'f, F, T> = (Res<'f, F, T>, Res<'f, F, T>, Res<'f, F, T>, Res<'f, F, T>);

// Niels coordinates: (Y+X, Y-X, 2dT) — optimized for point additions.
// Reduces point addition from 10M to 8M multiplications.
type NielsPoint<'f, F, T> = (Res<'f, F, T>, Res<'f, F, T>, Res<'f, F, T>);

use crate::{D_BYTES, G_T_BYTES, G_X_BYTES, G_Y_BYTES, MODP_SQRT_M1_BYTES, Q_BYTES};

#[inline(never)]
fn sha512_modq<T: UnsignedModularInt>(parts: &[&[u8]], q: &T) -> T
where
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    // Enforce "exactly one" SHA-512 backend at compile time. Two
    // mutually-exclusive arms + two compile_error! guards cover all four
    // feature-flag combinations cleanly.
    #[cfg(all(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
    compile_error!(
        "ed25519_heapless: enable at most one SHA-512 backend feature — both `sha512-hmac-sha512` and `sha512-sha2` were enabled"
    );
    #[cfg(not(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2")))]
    compile_error!(
        "ed25519_heapless: enable exactly one of the SHA-512 backend features `sha512-hmac-sha512` or `sha512-sha2`"
    );
    #[cfg(all(feature = "sha512-hmac-sha512", not(feature = "sha512-sha2")))]
    let hash: [u8; 64] = {
        let mut compact_sha = hmac_sha512::Hash::new();
        for part in parts {
            compact_sha.update(part);
        }
        compact_sha.finalize()
    };
    #[cfg(all(feature = "sha512-sha2", not(feature = "sha512-hmac-sha512")))]
    let hash: [u8; 64] = {
        use sha2::Digest;
        let mut compact_sha = sha2::Sha512::new();
        for part in parts {
            compact_sha.update(part);
        }
        compact_sha.finalize().into()
    };
    let hash = hash.as_slice();

    // Bit-by-bit Horner reduction modulo q (the scalar/group order, *not*
    // the field prime p — that's why this stays as raw `T` arithmetic
    // rather than going through `Field`). Processes the full 512-bit hash
    // without requiring T to hold all 64 bytes. Works for any T >= 253 bits
    // (> q). At each step acc < q, so 2*acc < 2q < 2^254, which fits in
    // 256-bit T.
    //
    // Seed the accumulator at `q`'s width, not `T::zero()`. On a
    // runtime-width backend `zero()` is minimal-width (it can't guess
    // the intended width), so `2*acc` would wrap at the low limb and
    // the reduction would silently compute a truncated result. `q - q`
    // is a zero carrying q's full width, so the doubling has room to
    // carry. (Fixed-width backends are unaffected: their `zero()` is
    // already full width.)
    let mut acc = <&T as const_num_traits::WrappingSub>::wrapping_sub(q, q);
    let one = T::one();
    // Process from most significant bit (byte 63, bit 7) to least (byte 0, bit 0)
    // Hash is little-endian: byte 63 is MSB
    for byte_idx in (0..64).rev() {
        for bit_idx in (0..8).rev() {
            // acc = 2*acc + bit, then reduce. Since `acc` is reassigned
            // on the next line, the original can be moved into `rhs` —
            // only the `self` receiver needs to clone. Saves ~512
            // big-integer clones per SHA-512(m) reduction.
            let (doubled, _overflow) = acc.clone().overflowing_add(acc);
            acc = doubled;
            if (hash[byte_idx] >> bit_idx) & 1 == 1 {
                let (added, _) = acc.overflowing_add(one.clone());
                acc = added;
            }
            // acc < 2q + 1 here, so at most two subtractions needed.
            if &acc >= q {
                acc = acc.wrapping_sub(q.clone());
            }
            if &acc >= q {
                acc = acc.wrapping_sub(q.clone());
            }
        }
    }
    acc
}

// =========================================================================
// Edwards point operations
// =========================================================================
// All point coordinates are `Residue<'f, T>` values — internally Montgomery
// form, but that's opaque to this code. Add/sub/mul/inv all go through the
// `Field<T>` methods, which keep things in Montgomery form between calls so
// there's no round-trip cost across chains of operations.

#[inline(never)]
fn recover_x<'f, F, T>(y_raw: T, sign: u8, d_raw: T, field: &'f F) -> Option<Res<'f, F, T>>
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    // Phase 1: x² = (y² − 1) / (d·y² + 1)
    let x2 = {
        let y = field.reduce(&y_raw);
        let d = field.reduce(&d_raw);
        let y2 = field.mul(&y, &y);
        let one = field.one();
        let numerator = field.sub(&y2, &one);
        let dy2 = field.mul(&d, &y2);
        let denominator = field.add(&dy2, &one);
        let inv_denom = field.inv(&denominator);
        field.mul(&numerator, &inv_denom)
    };

    let zero = field.zero();
    if x2 == zero {
        return if sign > 0 { None } else { Some(zero) };
    }

    // Phase 2: exponent (p+3)/8. p = 2^255 − 19 → (p+3)/8 = 2^252 − 2,
    // exactly divisible by 8 so we use `>> 3` (no division on T required).
    let exp = {
        let three = T::one().wrapping_add(T::one()).wrapping_add(T::one());
        // UFCS on `<&T as WrappingAdd>` forces dispatch to fixed-bigint's
        // `impl WrappingAdd for &FixedUInt<W, N, P>` — reads limbs through
        // the reference, returns a fresh owned `T`.
        let p3 = <&T as const_num_traits::WrappingAdd>::wrapping_add(field.modulus(), &three);
        p3 >> 3
    };

    // Phase 3: candidate square root via Fermat: x = x²^((p+3)/8)
    let mut x = field.exp(&x2, &exp);

    // Phase 4: verify x² = x2; if not, multiply by sqrt(−1).
    {
        let check = field.mul(&x, &x);
        let diff = field.sub(&check, &x2);
        if diff != zero {
            let sqrt_m1 = field.reduce(&crate::from_le_bytes::<T>(&MODP_SQRT_M1_BYTES));
            x = field.mul(&x, &sqrt_m1);
        }
    }

    // Phase 5: final check — if still wrong, reject.
    {
        let check = field.mul(&x, &x);
        let diff = field.sub(&check, &x2);
        if diff != zero {
            return None;
        }
    }

    // Phase 6: choose sign. Parity is a property of the *normal-form* value,
    // not the Montgomery encoding, so round-trip through `into_raw`.
    let x_raw = field.into_raw(&x);
    let parity = (x_raw & T::one()) == T::one();
    let x = if (parity as u8) != sign {
        let reduced = field.reduce(&x_raw);
        field.sub(&zero, &reduced)
    } else {
        field.reduce(&x_raw)
    };

    Some(x)
}

#[inline(never)]
fn decompress_edward_point<'f, F, T>(
    encoded: [u8; 32],
    d_raw: T,
    field: &'f F,
) -> Option<EdPoint<'f, F, T>>
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    let mut bytes = encoded;
    let sign = bytes[31] >> 7;
    bytes[31] &= 0b0111_1111;
    let y_raw = crate::from_le_bytes::<T>(&bytes);

    if &y_raw >= field.modulus() {
        return None;
    }

    let x = recover_x(y_raw, sign, d_raw, field)?;
    let y = field.reduce(&y_raw);
    let one = field.one();
    let t = field.mul(&x, &y);
    Some((x, y, one, t))
}

#[inline(never)]
fn point_double<'f, F, T>(pp: &EdPoint<'f, F, T>, field: &'f F) -> EdPoint<'f, F, T>
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    // Edwards curve doubling on extended-twisted coordinates.
    // A = X²; B = Y²; C = 2·Z²; D = −A (a = −1 for Ed25519)
    // E = (X+Y)² − A − B; G = D + B; F = G − C; H = D − B
    // X' = E·F; Y' = G·H; Z' = F·G; T' = E·H
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

fn to_niels<'f, F, T>(pp: &EdPoint<'f, F, T>, d_raw: T, field: &'f F) -> NielsPoint<'f, F, T>
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    let y_plus_x = field.add(&pp.1, &pp.0);
    let y_minus_x = field.sub(&pp.1, &pp.0);
    let d = field.reduce(&d_raw);
    let dt = field.mul(&d, &pp.3);
    let two_dt = field.add(&dt, &dt);
    (y_plus_x, y_minus_x, two_dt)
}

#[inline(never)]
fn point_add_niels<'f, F, T>(
    pp: &EdPoint<'f, F, T>,
    niels: &NielsPoint<'f, F, T>,
    field: &'f F,
) -> EdPoint<'f, F, T>
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
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

#[inline(never)]
fn point_equal<'f, F, T>(pp: &EdPoint<'f, F, T>, qq: &EdPoint<'f, F, T>, field: &'f F) -> bool
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    // Projective equality: X₁/Z₁ = X₂/Z₂ ↔ X₁·Z₂ = X₂·Z₁ (and same for Y).
    let t1 = field.mul(&pp.0, &qq.2);
    let t2 = field.mul(&qq.0, &pp.2);
    let t3 = field.mul(&pp.1, &qq.2);
    let t4 = field.mul(&qq.1, &pp.2);
    let zero = field.zero();
    field.sub(&t1, &t2) == zero && field.sub(&t3, &t4) == zero
}

#[inline(never)]
fn naf_double_scalar_mul<'f, F, T>(
    s: T,
    g: &EdPoint<'f, F, T>,
    h: T,
    a: &EdPoint<'f, F, T>,
    d_raw: T,
    field: &'f F,
) -> EdPoint<'f, F, T>
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>,
{
    // NAF operates on raw scalars (s, h ∈ Z_q), not field elements.
    let naf = crate::jsf::NafIterator::new(s, h);

    // Identity in extended-twisted Edwards: (0, 1, 1, 0).
    let zero = field.zero();
    let mut result: EdPoint<'f, F, T> = (field.zero(), field.one(), field.one(), field.zero());

    // Precompute Niels form of base points + their negations.
    let g_niels = to_niels(g, d_raw, field);
    let a_niels = to_niels(a, d_raw, field);
    let neg_g_niels = (
        g_niels.1.clone(),
        g_niels.0.clone(),
        field.sub(&zero, &g_niels.2),
    );
    let neg_a_niels = (
        a_niels.1.clone(),
        a_niels.0.clone(),
        field.sub(&zero, &a_niels.2),
    );

    for digit in naf.digits_msb_first() {
        result = point_double(&result, field);
        match digit.s_digit {
            NafSign::Pos => result = point_add_niels(&result, &g_niels, field),
            NafSign::Neg => result = point_add_niels(&result, &neg_g_niels, field),
            NafSign::Zero => {}
        }
        match digit.h_digit {
            NafSign::Pos => result = point_add_niels(&result, &a_niels, field),
            NafSign::Neg => result = point_add_niels(&result, &neg_a_niels, field),
            NafSign::Zero => {}
        }
    }

    result
}

/// Verify an Ed25519 signature.
///
/// Convenience entry point — builds a fresh [`Curve25519Field`] internally,
/// which costs ~150k cycles on Cortex-M3 (R mod N + R² mod N precompute).
/// Callers that verify more than once against the same curve (TLS chains,
/// batch verification, anything walking a cert tree) should build the
/// field once via [`Curve25519Field::curve25519`] and call
/// [`verify_with_field`] instead, amortizing the precompute.
pub fn verify<T>(public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool
where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + modmath::NonCt
        + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>,
{
    let field = match Curve25519Field::curve25519() {
        Ok(f) => f,
        Err(_) => return false,
    };
    verify_with_field::<Curve25519Field<T>, T>(&field, public, msg, signature)
}

/// Verify with a caller-supplied field, skipping the per-call
/// precompute. Build the field once (e.g. at firmware boot, or at the
/// top of a TLS handshake) and reuse across every verify against the
/// same curve.
///
/// Generic over the field personality via [`VerifyField`]: pass a
/// [`Curve25519Field`] for the default non-constant-time verify, or a
/// [`Curve25519FieldCt`] to run verify on the constant-time carrier
/// (a single-monomorphization deployment that already links the CT
/// carrier for signing — verify only touches public data, so this is
/// purely a code-size-vs-speed trade, never a correctness one).
///
/// ```ignore
/// use ed25519_heapless::{Curve25519Field, verify_with_field};
/// let Ok(field) = Curve25519Field::<MyT>::curve25519() else { return false };
/// for (pk, msg, sig) in chain {
///     if !verify_with_field(&field, pk, msg, sig) { return false; }
/// }
/// ```
pub fn verify_with_field<F, T>(field: &F, public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>,
{
    verify_inner::<F, T>(field, public, msg, signature)
}

#[inline(never)]
fn verify_inner<F, T>(field: &F, public: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool
where
    F: VerifyField<T>,
    T: UnsignedModularInt + Copy + const_num_traits::WrappingSub<Output = T>,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>,
{
    // Guard: T must be at least 256 bits wide for Ed25519 constants.
    // `verify_with_field` and the `Verifier` blanket both bottom out
    // in this inner fn, and either could be handed a narrow `T` via
    // a caller-built `Curve25519Field::new` bypass. The const-assert
    // makes that a compile error at monomorphization instead of a
    // runtime branch — matches the pattern used by `sign_with_fields`
    // and the x25519 entry points, and removes both the runtime
    // check and the panic path from `from_le_bytes` at this site
    // (any monomorphization that reaches the `D_BYTES` load has
    // `T::BYTE_WIDTH >= 32` by construction).
    assert!(
        (const_num_traits::BitsPrecision::bits_precision(crate::from_le_bytes::<T>(&crate::P_BYTES))
            as usize)
            >= 256,
        "verify: backend T is too narrow for the Curve25519 prime (need >= 256 bits)"
    );

    let d = crate::from_le_bytes::<T>(&D_BYTES);

    // Phase 1: decompress the public key A, then negate (we'll check
    // s·B − h·A = R rather than s·B = h·A + R).
    let neg_aa = match decompress_edward_point(public, d, field) {
        Some(aa) => {
            let zero = field.zero();
            (field.sub(&zero, &aa.0), aa.1, aa.2, field.sub(&zero, &aa.3))
        }
        None => return false,
    };

    // `signature: [u8; 64]` slice halves are provably 32 bytes at
    // compile time, but `try_into().expect(...)` pulls in a panic
    // string per site. Fail-closed to `[0u8; 32]` via
    // `unwrap_or_default` — downstream `decompress_edward_point`
    // or field-arithmetic checks reject the zero-sig case; no
    // panic runtime reference from here.
    let rrs: [u8; 32] = signature[0..32].try_into().unwrap_or_default();

    // Phase 2: decompress R.
    let rr = match decompress_edward_point(rrs, d, field) {
        Some(rr) => rr,
        None => return false,
    };

    let s_bytes: [u8; 32] = signature[32..64].try_into().unwrap_or_default();
    let s = crate::from_le_bytes::<T>(&s_bytes);

    // Phase 3: hash to scalar. `q` is the curve order — separate from the
    // field prime `p`, so it doesn't live inside the field abstraction.
    let h = {
        let q = crate::from_le_bytes::<T>(&Q_BYTES);
        if s >= q {
            return false;
        }
        sha512_modq(&[rrs.as_slice(), public.as_slice(), msg], &q)
    };

    // Phase 4: base point G in field form.
    let g: EdPoint<'_, F, T> = (
        field.reduce(&crate::from_le_bytes::<T>(&G_X_BYTES)),
        field.reduce(&crate::from_le_bytes::<T>(&G_Y_BYTES)),
        field.one(),
        field.reduce(&crate::from_le_bytes::<T>(&G_T_BYTES)),
    );

    // Phase 5: paired NAF double-scalar multiplication. Computes s·G + h·(−A).
    let sb_minus_ha = naf_double_scalar_mul(s, &g, h, &neg_aa, d, field);

    // Phase 6: final check.
    point_equal(&sb_minus_ha, &rr, field)
}
