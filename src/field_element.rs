use crate::ed25519;
use crate::num_bigint::BigInt;
use num_traits::Zero;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
    value: BigInt,
}

impl FieldElement {
    pub fn new(value: BigInt) -> Self {
        Self::from_reduced(Self::reduce(value))
    }

    pub fn zero() -> Self {
        Self::new(BigInt::zero())
    }

    pub fn one() -> Self {
        Self::new(BigInt::from(1i32))
    }

    pub fn modulus() -> BigInt {
        ed25519::p()
    }

    pub fn reduce(value: BigInt) -> BigInt {
        let modulus = Self::modulus();
        value.rem_euclid(&modulus)
    }

    fn from_reduced(value: BigInt) -> Self {
        let modulus = Self::modulus();
        debug_assert!(value < modulus);
        Self { value }
    }

    pub fn inv(&self) -> Option<Self> {
        let modulus = Self::modulus();
        self.value.mod_inv(&modulus).map(Self::from_reduced)
    }

    pub fn as_bigint(&self) -> &BigInt {
        &self.value
    }

    pub fn into_bigint(self) -> BigInt {
        self.value
    }
}

impl From<BigInt> for FieldElement {
    fn from(value: BigInt) -> Self {
        Self::new(value)
    }
}

impl From<u8> for FieldElement {
    fn from(value: u8) -> Self {
        Self::new(BigInt::from(value))
    }
}

impl From<i32> for FieldElement {
    fn from(value: i32) -> Self {
        Self::new(BigInt::from(value))
    }
}

impl core::ops::Add for FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: Self) -> FieldElement {
        let modulus = Self::modulus();
        let value = self.value.mod_add(&rhs.value, &modulus);
        FieldElement::from_reduced(value)
    }
}

impl core::ops::Sub for FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: Self) -> FieldElement {
        let modulus = Self::modulus();
        let value = self.value.mod_sub(&rhs.value, &modulus);
        FieldElement::from_reduced(value)
    }
}

impl core::ops::Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: Self) -> FieldElement {
        let modulus = Self::modulus();
        let value = self.value.mod_mul(&rhs.value, &modulus);
        FieldElement::from_reduced(value)
    }
}

impl core::ops::Neg for FieldElement {
    type Output = FieldElement;

    fn neg(self) -> FieldElement {
        let modulus = Self::modulus();
        let value = modulus.mod_sub(&self.value, &modulus);
        FieldElement::from_reduced(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_canonicalizes_values() {
        let p = FieldElement::modulus();
        let reduced = FieldElement::new(p + BigInt::from(1i32));
        assert_eq!(reduced, FieldElement::from(1i32));
        assert!(reduced.as_bigint() < &p);
    }

    #[test]
    fn add_sub_mul_basic_identities() {
        let a = FieldElement::from(123i32);
        let b = FieldElement::from(456i32);
        assert_eq!(a.clone() + b.clone(), FieldElement::from(579i32));
        assert_eq!(b.clone() - a.clone(), FieldElement::from(333i32));
        assert_eq!(a.clone() * b.clone(), FieldElement::from(56088i32));
    }

    #[test]
    fn add_wraps_modulus() {
        let p = FieldElement::modulus();
        let a = FieldElement::from(p - BigInt::from(1i32));
        let b = FieldElement::from(2i32);
        assert_eq!(a + b, FieldElement::from(1i32));
    }

    #[test]
    fn sub_wraps_modulus() {
        let a = FieldElement::from(1i32);
        let b = FieldElement::from(2i32);
        let p = FieldElement::modulus();
        assert_eq!(a - b, FieldElement::from(p - BigInt::from(1i32)));
    }

    #[test]
    fn negation_behaves_as_expected() {
        let p = FieldElement::modulus();
        let a = FieldElement::from(7i32);
        assert_eq!(-a.clone(), FieldElement::from(p - BigInt::from(7i32)));
        assert_eq!(-FieldElement::zero(), FieldElement::zero());
    }

    #[test]
    fn inv_returns_none_for_zero() {
        assert!(FieldElement::zero().inv().is_none());
    }

    #[test]
    fn inv_multiplies_to_one() {
        let a = FieldElement::from(5i32);
        let inv = a.inv().expect("5 is invertible modulo p");
        assert_eq!(a * inv, FieldElement::one());
    }

    #[test]
    fn into_bigint_roundtrip() {
        let a = FieldElement::from(42i32);
        let b = a.into_bigint();
        assert_eq!(b, BigInt::from(42i32));
    }
}
