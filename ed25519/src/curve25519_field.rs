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

/// Reasons the [`Curve25519Field::curve25519`] / [`Curve25519FieldCt::curve25519`]
/// factories can refuse to construct a field. Both arms are unreachable
/// for any well-formed backend: `BackendTooNarrow` is a backend-selection
/// bug, and `InvalidModulus` would require `modmath::Field::new` to
/// reject `p = 2^255 − 19`. The factories return `Result` for the paths
/// that need runtime handling — notably [`crate::sign_with_fields`] via
/// [`crate::SigningKey::from_seed`], which propagates the error into
/// [`crate::SignError::FieldSetup`]. Entry points that can afford it
/// (`strict::verify`, `sign_with_fields`, and every x25519 fn) now use
/// a `const { assert!(type_bit_width::<T>() >= 256, ...) }` guard, so
/// a too-narrow `T` is a compile error at monomorphization and the
/// `Result` handling on those paths is provably dead code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveSetupError {
    BackendTooNarrow,
    InvalidModulus,
}

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
        + const_num_traits::Zero
        + const_num_traits::One
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = T>
        + const_num_traits::WrappingMul<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + Parity
        + WideMul
        + CiosMontMul
        + modmath::MontStorage
        + modmath::NonCt,
{
    pub fn new(modulus: T) -> Option<Self> {
        FieldNct::new(modulus).map(|inner| Curve25519Field { inner, modulus })
    }

    /// Infallible constructor from a proven-odd modulus. The
    /// [`modmath::Odd`] typestate discharges the parity / non-zero
    /// check at the trust boundary instead of inside the field
    /// constructor — see modmath's `Field::new_odd`.
    pub fn new_odd(modulus: modmath::Odd<T>) -> Self {
        let raw = modulus.get();
        let inner = FieldNct::new_odd(modulus);
        Curve25519Field {
            inner,
            modulus: raw,
        }
    }

    /// Build the Curve25519 field. Returns [`CurveSetupError`] when the
    /// backend `T` is too narrow to hold the 256-bit prime, or in the
    /// theoretical-but-unreachable case where `Odd::new` rejects
    /// `p = 2^255 − 19`. The fallible signature exists because callers
    /// like [`crate::SigningKey::from_seed`] propagate the error into
    /// [`crate::SignError`]. [`crate::strict::verify`] rejects narrow
    /// `T` at monomorphization via a `const {}` guard on its inner
    /// path, so the `Result` handling there is provably unreachable
    /// but kept for uniformity with the other factory-consuming paths.
    pub fn curve25519() -> Result<Self, CurveSetupError>
    where
        T: UnsignedModularInt,
    {
        if modmath::type_bit_width::<T>() < 256 {
            return Err(CurveSetupError::BackendTooNarrow);
        }
        let p = crate::from_le_bytes::<T>(&P_BYTES);
        let odd = modmath::Odd::new(p).ok_or(CurveSetupError::InvalidModulus)?;
        Ok(Self::new_odd(odd))
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
    ///
    /// Uses `.wrapping_add` / `.wrapping_sub` explicitly. The `2 * modulus
    /// < 2^W` slack means the wrap can't fire in the add and the `sum >=
    /// modulus` predicate means the sub can't underflow — naming
    /// wrap-around at the trait boundary avoids the backend's `Sub` impl
    /// choosing panic-on-underflow (crypto-bigint) or dispatching through
    /// an overflow mode (bnum).
    #[inline]
    pub fn add<'f>(&'f self, a: &ResidueNct<'f, T>, b: &ResidueNct<'f, T>) -> ResidueNct<'f, T> {
        let a_m = *(*a).mont_value();
        let b_m = *(*b).mont_value();
        let sum = a_m.wrapping_add(b_m);
        let reduced = if sum >= self.modulus {
            sum.wrapping_sub(self.modulus)
        } else {
            sum
        };
        self.inner.residue_from_mont(reduced)
    }

    /// Lazy sub: when `a < b`, add `modulus` first (still fits in `T` by
    /// the same 2-p slack); otherwise straight subtract. Same wrap
    /// contract as [`Self::add`].
    #[inline]
    pub fn sub<'f>(&'f self, a: &ResidueNct<'f, T>, b: &ResidueNct<'f, T>) -> ResidueNct<'f, T> {
        let a_m = *a.mont_value();
        let b_m = *b.mont_value();
        let diff = if a_m >= b_m {
            a_m.wrapping_sub(b_m)
        } else {
            a_m.wrapping_add(self.modulus).wrapping_sub(b_m)
        };
        self.inner.residue_from_mont(diff)
    }

    /// Fermat inverse: `a^{-1} mod p = a^{p − 2} mod p`. Only valid for
    /// prime modulus (true for Curve25519).
    pub fn inv<'f>(&'f self, a: &ResidueNct<'f, T>) -> ResidueNct<'f, T>
    where
        T: core::ops::ShrAssign<usize>,
    {
        let exp = self.modulus.wrapping_sub(T::one()).wrapping_sub(T::one());
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
        + const_num_traits::Zero
        + const_num_traits::One
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = T>
        + const_num_traits::WrappingMul<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + Parity
        + WideMul
        + CiosMontMulCt
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + modmath::MontStorage
        + const_num_traits::CtIsZero,
    for<'a> &'a T:
        const_num_traits::WrappingAdd<Output = T> + const_num_traits::WrappingSub<Output = T>,
{
    pub fn new(modulus: T) -> Option<Self> {
        FieldCt::new(modulus).map(|inner| Curve25519FieldCt { inner, modulus })
    }

    /// Infallible constructor from a proven-odd modulus — see
    /// [`Curve25519Field::new_odd`].
    pub fn new_odd(modulus: modmath::Odd<T>) -> Self {
        let raw = modulus.get();
        let inner = FieldCt::new_odd(modulus);
        Curve25519FieldCt {
            inner,
            modulus: raw,
        }
    }

    /// Build the constant-time Curve25519 field. Same fallible shape as
    /// [`Curve25519Field::curve25519`] — see [`CurveSetupError`].
    pub fn curve25519() -> Result<Self, CurveSetupError>
    where
        T: UnsignedModularInt,
    {
        if modmath::type_bit_width::<T>() < 256 {
            return Err(CurveSetupError::BackendTooNarrow);
        }
        let p = crate::from_le_bytes::<T>(&P_BYTES);
        let odd = modmath::Odd::new(p).ok_or(CurveSetupError::InvalidModulus)?;
        Ok(Self::new_odd(odd))
    }

    /// Cached modulus accessor — see [`Curve25519Field::modulus`].
    pub fn modulus(&self) -> &T {
        &self.modulus
    }

    /// CT lazy add: always compute both `sum` and `sum − modulus`, select
    /// branchlessly. No overflow possible on `sum` (2·p fits in T). The
    /// `sum - self.modulus` candidate underflows when `sum < modulus` —
    /// that's load-bearing for constant-time: under the `Ct` personality
    /// `FixedUInt::Sub` discards the overflow flag (silent wrap) by
    /// typestate design, so the underflowing branch never panics even
    /// in debug builds. See `ct_add_sub_never_panic_on_underflow_path`
    /// test for the regression guard.
    #[inline]
    pub fn add<'f>(&'f self, a: &ResidueCt<'f, T>, b: &ResidueCt<'f, T>) -> ResidueCt<'f, T> {
        // Stay in `&T` for the secret-derived operands so no implicit
        // `T: Copy` materializations land on the stack. `.wrapping_add`
        // / `.wrapping_sub` on `&T` receivers dispatch to fixed-bigint's
        // `impl Wrapping{Add,Sub} for &FixedUInt<W, N, P>` (added in
        // v0.5.0-alpha.3), which reads limbs through the reference and
        // produces a fresh owned `T` — same shape as the previous
        // `&T + &T` operator dispatch, but with the wrap-around
        // contract in the trait name.
        use const_num_traits::{WrappingAdd, WrappingSub};
        let a_m = a.mont_value();
        let b_m = b.mont_value();
        // Explicit UFCS on `<&T as WrappingAdd>` forces dispatch to
        // fixed-bigint's `impl WrappingAdd for &FixedUInt<W, N, P>`
        // (v0.5.0-alpha.3) instead of falling back to the by-value
        // impl through autoderef of the receiver.
        let sum = zeroize::Zeroizing::new(<&T as WrappingAdd>::wrapping_add(a_m, b_m));
        let reduced =
            zeroize::Zeroizing::new(<&T as WrappingSub>::wrapping_sub(&*sum, &self.modulus));
        // sum < modulus  →  keep sum;  otherwise → use sum − modulus.
        let needs_reduce = !sum.ct_lt(&self.modulus);
        let result = zeroize::Zeroizing::new(T::conditional_select(&*sum, &*reduced, needs_reduce));
        // The deref-copy into `residue_from_mont` materializes one bare
        // `T` briefly during the call — but the new `ResidueCt` is
        // `ZeroizeOnDrop`, so the bytes land inside a wiped allocation
        // immediately. Our local `result` is also wiped on drop.
        self.inner.residue_from_mont(*result)
    }

    /// CT lazy sub: compute both `a − b` (mod 2^W) and `a + modulus − b`,
    /// select branchlessly based on whether `a < b`. Like
    /// [`Self::add`], the `a_m - b_m` candidate underflows when
    /// `a_m < b_m` — silent wrap under the `Ct` personality by typestate
    /// design.
    #[inline]
    pub fn sub<'f>(&'f self, a: &ResidueCt<'f, T>, b: &ResidueCt<'f, T>) -> ResidueCt<'f, T> {
        // Same wrap-everything-in-`Zeroizing` discipline as [`Self::add`],
        // and same explicit `<&T as Wrapping…>` UFCS dispatch to force
        // the read-through-ref impl on the `&T` operands.
        use const_num_traits::{WrappingAdd, WrappingSub};
        let a_m = a.mont_value();
        let b_m = b.mont_value();
        let diff_no_borrow = zeroize::Zeroizing::new(<&T as WrappingSub>::wrapping_sub(a_m, b_m));
        let diff_with_borrow = zeroize::Zeroizing::new({
            let with_modulus =
                zeroize::Zeroizing::new(<&T as WrappingAdd>::wrapping_add(a_m, &self.modulus));
            <&T as WrappingSub>::wrapping_sub(&*with_modulus, b_m)
        });
        let needs_add_p = a_m.ct_lt(b_m);
        let result = zeroize::Zeroizing::new(T::conditional_select(
            &*diff_no_borrow,
            &*diff_with_borrow,
            needs_add_p,
        ));
        self.inner.residue_from_mont(*result)
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
        T: core::ops::Shr<usize, Output = T> + core::ops::BitAnd<Output = T>,
    {
        // Exponent `p − 2`. Explicit `.wrapping_sub` names the wrap
        // contract; `p > 2` so the wrap can't fire in practice.
        let exp = self.modulus.wrapping_sub(T::one()).wrapping_sub(T::one());
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
    use const_num_traits::{Ct, Nct};
    use fixed_bigint::FixedUInt;

    type T256 = FixedUInt<u8, 32, Nct>;
    type T256Ct = FixedUInt<u8, 32, Ct>;

    fn curve_field() -> Curve25519Field<T256> {
        let p = crate::from_le_bytes::<T256>(&P_BYTES);
        Curve25519Field::new(p).unwrap()
    }

    fn curve_field_ct() -> Curve25519FieldCt<T256Ct> {
        let p = crate::from_le_bytes::<T256Ct>(&P_BYTES);
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

    /// Regression test for the CT add/sub "unconditional underflow"
    /// concern raised by reviewers (Codex P1, Gemini medium) on
    /// `Curve25519FieldCt::add` / `sub`: the CT body computes both
    /// candidate results unconditionally (including `sum - modulus`
    /// when `sum < modulus` and `a - b` when `a < b`) and then
    /// `conditional_select`s. The reviewers worried this would
    /// panic in debug builds.
    ///
    /// Under the `Ct` personality, `FixedUInt::Sub` discards the
    /// overflow flag via `maybe_panic_if::<Ct>` (which dispatches on
    /// `P::TAG` and explicitly drops `overflow` for Ct). The wrap is
    /// by typestate design — that's the constant-time contract.
    /// This test drives both add and sub through the underflow path
    /// and asserts neither panics, with both producing the field-
    /// correct result.
    #[test]
    fn ct_add_sub_never_panic_on_underflow_path() {
        let fct = curve_field_ct();
        // Use residues whose Montgomery values are deliberately small —
        // so `sum + sum < modulus` for add, and `small - large` triggers
        // the borrow path for sub. The escape hatch `residue_from_mont`
        // lets us pin the Montgomery values directly.
        let small = fct.inner.residue_from_mont(T256Ct::from(5u8));
        let smaller = fct.inner.residue_from_mont(T256Ct::from(3u8));

        // add path: sum = 5 + 3 = 8, sum < p, so candidate `sum - p`
        // underflows. Must not panic.
        let added = fct.add(&small, &smaller);
        // Result Montgomery value should equal 8 (no reduction needed).
        assert_eq!(*added.mont_value(), T256Ct::from(8u8));

        // sub path: a - b = 5 - 3 = 2, no borrow case. Also exercise
        // the borrow path directly.
        let subbed = fct.sub(&small, &smaller);
        assert_eq!(*subbed.mont_value(), T256Ct::from(2u8));

        let borrow = fct.sub(&smaller, &small); // 3 - 5 → borrow path
        // Result = p + 3 - 5 = p - 2 (in Montgomery form).
        let p: T256Ct = T256Ct::from_le_bytes(&P_BYTES);
        let expected = p - T256Ct::from(2u8);
        assert_eq!(*borrow.mont_value(), expected);
    }
}
