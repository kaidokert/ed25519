// Precomputed Montgomery parameters for a fixed modulus.
// Only available when T: Copy + WideMul (i.e., fixed-bigint with wide-mul).

use modmath::{
    WideMul,
    type_bit_width,
    compute_n_prime_newton,
    compute_r_mod_n,
    compute_r2_mod_n,
    wide_redc,
    wide_montgomery_mul,
};

/// Precomputed Montgomery parameters for a fixed modulus.
pub struct MontgomeryCtx<T> {
    pub modulus: T,
    pub n_prime: T,      // -N^{-1} mod 2^W
    pub r_mod_n: T,      // 2^W mod N  (= Montgomery form of 1)
    pub r2_mod_n: T,     // 2^{2W} mod N (for converting to Montgomery form)
    pub two_mont: T,     // 2 in Montgomery form (precomputed for point ops)
}

impl<T> MontgomeryCtx<T>
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + WideMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + core::ops::Add<Output = T>,
{
    /// Precompute all Montgomery parameters for the given modulus.
    /// Modulus must be odd and non-zero.
    pub fn new(modulus: T) -> Self {
        let w = type_bit_width::<T>();
        let n_prime = compute_n_prime_newton(modulus, w);
        let r_mod_n = compute_r_mod_n(modulus, w);
        let r2_mod_n = compute_r2_mod_n(r_mod_n, modulus, w);
        let two = T::one() + T::one();
        let (lo, hi) = two.wide_mul(&r2_mod_n);
        let two_mont = wide_redc(lo, hi, modulus, n_prime);
        MontgomeryCtx { modulus, n_prime, r_mod_n, r2_mod_n, two_mont }
    }

    /// Convert a value to Montgomery form: REDC(a * R²)
    #[inline]
    pub fn to_mont(&self, a: T) -> T {
        let (lo, hi) = a.wide_mul(&self.r2_mod_n);
        wide_redc(lo, hi, self.modulus, self.n_prime)
    }

    /// Convert from Montgomery form back to normal: REDC(a_mont, 0)
    #[inline]
    pub fn from_mont(&self, a_mont: T) -> T {
        wide_redc(a_mont, T::zero(), self.modulus, self.n_prime)
    }

    /// Montgomery multiplication: both inputs already in Montgomery form
    #[inline]
    pub fn mont_mul(&self, a: T, b: T) -> T {
        wide_montgomery_mul(a, b, self.modulus, self.n_prime)
    }
}
