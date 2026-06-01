//! Curve25519 specialization of [`modmath::Field`] / [`modmath::FieldCt`].
//!
//! Adds curve-specific fast paths that depend on properties of
//! `p = 2^255 − 19`:
//!
//! - **Lazy `add` / `sub`** — skip the wrapping/borrow detection that
//!   `modmath::Field::add` does, since `2 * p < 2^256` always fits in our
//!   `T`. Generic [`modmath::Field`] can't make this assumption (RSA-CRT
//!   runs at full type width with no slack); the lazy variants live here.
//! - **`inv` via Fermat** — only valid for prime modulus, so it's
//!   curve-specific rather than generic.
//!
//! Everything else (`reduce`, `into_raw`, `zero`, `one`, `mul`, `exp`,
//! `residue_from_mont`) flows through `Deref` to the wrapped
//! [`modmath::Field`] / [`modmath::FieldCt`].
//!
//! # Use the curve methods, not the generic ones
//!
//! When both an inherent method (curve-specific lazy `add`) and a
//! `Deref`-inherited method (generic cond-sub `add`) are in scope, Rust's
//! method-dispatch rules prefer the inherent one — so `field.add(a, b)`
//! always calls the lazy variant. The only way to accidentally call the
//! generic add is to take a `&modmath::Field<T>` reference and call
//! through that. Don't.

use modmath::{
    CiosMontMul, CiosMontMulCt, FieldCt, FieldNct, Parity, ResidueCt, ResidueNct, WideMul,
};

use crate::{P_BYTES, UnsignedModularInt};

// =========================================================================
// NCT — for ed25519 verify (public data, fast path)
// =========================================================================

/// Variable-time field over `F_{2^255 − 19}`.
pub struct Curve25519Field<T> {
    inner: FieldNct<T>,
    /// Cached copy of the modulus. `Field::modulus` returns by value (= a
    /// copy of `T`); we cache to avoid copying a 256-bit value on every
    /// `add` / `sub` call.
    modulus: T,
}

impl<T> Curve25519Field<T>
where
    T: Copy
        + PartialEq
        + PartialOrd
        + num_traits::Zero
        + num_traits::One
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + Parity
        + WideMul
        + CiosMontMul,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    pub fn new(modulus: T) -> Option<Self> {
        FieldNct::new(modulus).map(|inner| Curve25519Field { inner, modulus })
    }

    /// Build the Curve25519 field — the canonical use case. Identical to
    /// `Curve25519Field::new(T::from_bytes_le(&P_BYTES))` but hides the
    /// modulus-byte plumbing. Build once at startup and reuse across
    /// every verify against this curve (TLS chains, batch verification).
    pub fn curve25519() -> Self
    where
        T: UnsignedModularInt,
    {
        let p = T::from_bytes_le(&P_BYTES);
        Self::new(p).expect(
            "Curve25519 prime is odd and nonzero — Field::new can't fail; \
             this unwrap is unreachable",
        )
    }

    /// Cached modulus accessor. Returns a borrow rather than a copy (unlike
    /// [`Field::modulus`], which returns by value), since callers often want
    /// to compute `&p + &small` without paying for a 256-bit clone.
    pub fn modulus(&self) -> &T {
        &self.modulus
    }

    /// Lazy add: assumes `2 * modulus < 2^T::BITS` so the unreduced sum
    /// never overflows `T`. One comparison + at most one subtract. Compare
    /// to `modmath::Field::add` which is wrapping-add + cond-sub for
    /// full-width moduli.
    #[inline]
    pub fn add<'f>(&'f self, a: &ResidueNct<'f, T>, b: &ResidueNct<'f, T>) -> ResidueNct<'f, T> {
        let a_m = (*a).mont_value();
        let b_m = (*b).mont_value();
        let sum = a_m + b_m;
        let reduced = if sum >= self.modulus {
            sum - self.modulus
        } else {
            sum
        };
        self.inner.residue_from_mont(reduced)
    }

    /// Lazy sub: when `a < b`, add `modulus` first (still fits in `T` by
    /// the same 2-p slack); otherwise straight subtract.
    #[inline]
    pub fn sub<'f>(&'f self, a: &ResidueNct<'f, T>, b: &ResidueNct<'f, T>) -> ResidueNct<'f, T> {
        let a_m = (*a).mont_value();
        let b_m = (*b).mont_value();
        let diff = if a_m >= b_m {
            a_m - b_m
        } else {
            (a_m + self.modulus) - b_m
        };
        self.inner.residue_from_mont(diff)
    }

    /// Fermat inverse: `a^{-1} mod p = a^{p − 2} mod p`. Only valid for
    /// prime modulus (true for Curve25519).
    pub fn inv<'f>(&'f self, a: &ResidueNct<'f, T>) -> ResidueNct<'f, T>
    where
        T: core::ops::Sub<Output = T> + core::ops::ShrAssign<usize>,
    {
        let exp = self.modulus - T::one() - T::one();
        self.inner.exp(a, &exp)
    }
}

impl<T> core::ops::Deref for Curve25519Field<T> {
    type Target = FieldNct<T>;
    fn deref(&self) -> &FieldNct<T> {
        &self.inner
    }
}

// =========================================================================
// CT — for x25519 (secret scalar, constant-time)
// =========================================================================

/// Constant-time field over `F_{2^255 − 19}`. Same lazy fast paths as
/// [`Curve25519Field`] but the conditional in lazy `add` / `sub` is done
/// branchlessly with `subtle::ConditionallySelectable`.
pub struct Curve25519FieldCt<T> {
    inner: FieldCt<T>,
    modulus: T,
}

impl<T> Curve25519FieldCt<T>
where
    T: Copy
        + PartialEq
        + PartialOrd
        + num_traits::Zero
        + num_traits::One
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + Parity
        + WideMul
        + CiosMontMulCt
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    pub fn new(modulus: T) -> Option<Self> {
        FieldCt::new(modulus).map(|inner| Curve25519FieldCt { inner, modulus })
    }

    /// Build the constant-time Curve25519 field. Same shape as
    /// [`Curve25519Field::curve25519`] — build once per long-lived
    /// secret-handling context (typically a key, or the lifetime of a
    /// device) and reuse.
    pub fn curve25519() -> Self
    where
        T: UnsignedModularInt,
    {
        let p = T::from_bytes_le(&P_BYTES);
        Self::new(p).expect(
            "Curve25519 prime is odd and nonzero — FieldCt::new can't fail; \
             this unwrap is unreachable",
        )
    }

    /// Cached modulus accessor — see [`Curve25519Field::modulus`].
    pub fn modulus(&self) -> &T {
        &self.modulus
    }

    /// CT lazy add: always compute both `sum` and `sum − modulus`, select
    /// branchlessly. No overflow possible (2·p fits in T).
    #[inline]
    pub fn add<'f>(&'f self, a: &ResidueCt<'f, T>, b: &ResidueCt<'f, T>) -> ResidueCt<'f, T> {
        let a_m = (*a).mont_value();
        let b_m = (*b).mont_value();
        let sum = a_m + b_m;
        let reduced = sum - self.modulus;
        // sum < modulus  →  keep sum;  otherwise → use sum − modulus.
        let needs_reduce = !sum.ct_lt(&self.modulus);
        let result = T::conditional_select(&sum, &reduced, needs_reduce);
        self.inner.residue_from_mont(result)
    }

    /// CT lazy sub: compute both `a − b` (mod 2^W) and `a + modulus − b`,
    /// select branchlessly based on whether `a < b`.
    #[inline]
    pub fn sub<'f>(&'f self, a: &ResidueCt<'f, T>, b: &ResidueCt<'f, T>) -> ResidueCt<'f, T> {
        let a_m = (*a).mont_value();
        let b_m = (*b).mont_value();
        let diff_no_borrow = a_m - b_m;
        let diff_with_borrow = (a_m + self.modulus) - b_m;
        let needs_add_p = a_m.ct_lt(&b_m);
        let result = T::conditional_select(&diff_no_borrow, &diff_with_borrow, needs_add_p);
        self.inner.residue_from_mont(result)
    }

    /// CT Fermat inverse: `a^{-1} mod p = a^{p − 2} mod p`. The exponent
    /// `p − 2` is a public compile-time constant, so this routes through
    /// [`FieldCt::exp_public_exp`] — CT in the base, variable-time in the
    /// (public) exponent. The fixed-iteration [`FieldCt::exp`] would be
    /// conservative-but-defensible here, but pays an unnecessary
    /// per-bit conditional-select cost for a property this caller doesn't
    /// need.
    pub fn inv<'f>(&'f self, a: &ResidueCt<'f, T>) -> ResidueCt<'f, T>
    where
        T: core::ops::Sub<Output = T>
            + core::ops::Shr<usize, Output = T>
            + core::ops::BitAnd<Output = T>,
    {
        let exp = self.modulus - T::one() - T::one();
        self.inner.exp_public_exp(a, &exp)
    }
}

impl<T> core::ops::Deref for Curve25519FieldCt<T> {
    type Target = FieldCt<T>;
    fn deref(&self) -> &FieldCt<T> {
        &self.inner
    }
}

#[cfg(all(test, feature = "fixed-bigint"))]
mod tests {
    use super::*;
    use fixed_bigint::{Ct, FixedUInt, Nct};

    type T256 = FixedUInt<u8, 32, Nct>;
    type T256Ct = FixedUInt<u8, 32, Ct>;

    fn curve_field() -> Curve25519Field<T256> {
        let p = T256::from_bytes_le(&P_BYTES);
        Curve25519Field::new(p).unwrap()
    }

    fn curve_field_ct() -> Curve25519FieldCt<T256Ct> {
        let p = T256Ct::from_bytes_le(&P_BYTES);
        Curve25519FieldCt::new(p).unwrap()
    }

    #[test]
    fn lazy_add_matches_generic() {
        let f = curve_field();
        let a_raw = T256::from(123u8);
        let b_raw = T256::from(45u8);
        let a = f.reduce(&a_raw);
        let b = f.reduce(&b_raw);
        let lazy = f.into_raw(&f.add(&a, &b));
        let generic = f.into_raw(&f.inner.add(&a, &b));
        assert_eq!(lazy, generic);
    }

    #[test]
    fn lazy_sub_matches_generic() {
        let f = curve_field();
        let a_raw = T256::from(45u8);
        let b_raw = T256::from(123u8); // a < b → borrow path
        let a = f.reduce(&a_raw);
        let b = f.reduce(&b_raw);
        let lazy = f.into_raw(&f.sub(&a, &b));
        let generic = f.into_raw(&f.inner.sub(&a, &b));
        assert_eq!(lazy, generic);
    }

    #[test]
    fn inv_round_trip() {
        let f = curve_field();
        let a = f.reduce(&T256::from(7u8));
        let a_inv = f.inv(&a);
        let product = f.mul(&a, &a_inv);
        assert_eq!(f.into_raw(&product), T256::from(1u8));
    }

    #[test]
    fn ct_lazy_matches_nct_lazy() {
        let f = curve_field();
        let fct = curve_field_ct();
        let a_raw_nct = T256::from(200u8);
        let b_raw_nct = T256::from(100u8);
        let a_raw_ct: T256Ct = a_raw_nct.into();
        let b_raw_ct: T256Ct = b_raw_nct.into();
        let nct_sum = f.into_raw(&f.add(&f.reduce(&a_raw_nct), &f.reduce(&b_raw_nct)));
        let ct_sum_residue = fct.into_raw(&fct.add(&fct.reduce(&a_raw_ct), &fct.reduce(&b_raw_ct)));
        // Compare raw byte representations across personalities via .forget_ct().
        let ct_sum_as_nct: T256 = ct_sum_residue.forget_ct();
        assert_eq!(nct_sum, ct_sum_as_nct);
    }

    #[test]
    fn deref_forwards_to_field() {
        let f = curve_field();
        // Call through Deref: reduce/into_raw/mul/one are not inherent on
        // Curve25519Field, so dispatch goes through modmath::Field.
        let a = f.reduce(&T256::from(3u8));
        let b = f.reduce(&T256::from(4u8));
        let prod = f.mul(&a, &b);
        assert_eq!(f.into_raw(&prod), T256::from(12u8));
    }
}
