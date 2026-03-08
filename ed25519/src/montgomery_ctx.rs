// Precomputed Montgomery parameters for a fixed modulus.
// Only available when T: Copy + WideMul (i.e., fixed-bigint with wide-mul).

use modmath::{
    CiosMontMul, WideMul, compute_n_prime_newton, compute_r_mod_n, compute_r2_mod_n,
    type_bit_width, wide_redc,
};

/// Precomputed Montgomery parameters for a fixed modulus.
pub struct MontgomeryCtx<T> {
    pub modulus: T,
    pub n_prime: T,  // -N^{-1} mod 2^W
    pub r_mod_n: T,  // 2^W mod N  (= Montgomery form of 1)
    pub r2_mod_n: T, // 2^{2W} mod N (for converting to Montgomery form)
}

impl<T> MontgomeryCtx<T>
where
    T: Copy
        + num_traits::Zero
        + num_traits::One
        + PartialEq
        + PartialOrd
        + WideMul
        + CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + core::ops::Add<Output = T>
        + core::ops::BitAnd<Output = T>,
{
    /// Precompute all Montgomery parameters for the given modulus.
    /// Returns `None` if the modulus is zero or even (Montgomery form requires an odd modulus).
    pub fn new(modulus: T) -> Option<Self> {
        if modulus == T::zero() || (modulus & T::one()) == T::zero() {
            return None;
        }
        let w = type_bit_width::<T>();
        let n_prime = compute_n_prime_newton(modulus, w);
        let r_mod_n = compute_r_mod_n(modulus, w);
        let r2_mod_n = compute_r2_mod_n(r_mod_n, modulus, w);
        Some(MontgomeryCtx {
            modulus,
            n_prime,
            r_mod_n,
            r2_mod_n,
        })
    }

    /// Convert a value to Montgomery form: REDC(a * R²)
    pub fn to_mont(&self, a: T) -> T {
        let (lo, hi) = a.wide_mul(&self.r2_mod_n);
        wide_redc(lo, hi, self.modulus, self.n_prime)
    }

    /// Convert from Montgomery form back to normal: REDC(a_mont, 0)
    #[allow(clippy::wrong_self_convention)]
    pub fn from_mont(&self, a_mont: T) -> T {
        wide_redc(a_mont, T::zero(), self.modulus, self.n_prime)
    }

    /// Montgomery multiplication: both inputs already in Montgomery form.
    /// Uses CIOS (Coarsely Integrated Operand Scanning) for ~25% fewer limb multiplies.
    pub fn mont_mul(&self, a: &T, b: &T) -> T {
        // None only for zero-width types, which can't represent a modulus
        CiosMontMul::cios_mont_mul(a, b, &self.modulus, &self.n_prime).unwrap()
    }

    /// Montgomery exponentiation: base^exponent mod modulus
    /// Input base is in normal form, exponent is in normal form.
    /// Returns result in normal form.
    /// Zero divisions — all multiplications use Montgomery REDC.
    pub fn mont_exp(&self, base: T, exponent: T) -> T
    where
        T: core::ops::Shr<usize, Output = T> + core::ops::BitAnd<Output = T>,
    {
        // Convert base to Montgomery form
        let mut base_m = self.to_mont(base);
        // 1 in Montgomery form = R mod N
        let mut result_m = self.r_mod_n;
        let mut exp = exponent;
        let one = T::one();

        while exp > T::zero() {
            if (exp & one) == one {
                result_m = self.mont_mul(&result_m, &base_m);
            }
            exp = exp >> 1;
            if exp > T::zero() {
                base_m = self.mont_mul(&base_m, &base_m);
            }
        }

        // Convert back to normal form
        self.from_mont(result_m)
    }

    /// Montgomery-based modular inverse via Fermat's little theorem.
    /// Computes a^{-1} mod p = a^{p-2} mod p (only valid when modulus is prime).
    /// Zero divisions — uses mont_exp internally.
    pub fn mont_inv(&self, a: T) -> T
    where
        T: core::ops::Sub<Output = T>
            + core::ops::Shr<usize, Output = T>
            + core::ops::BitAnd<Output = T>,
    {
        // p - 2
        let exp = self.modulus - T::one() - T::one();
        self.mont_exp(a, exp)
    }
}
