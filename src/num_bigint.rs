use fixed_bigint::FixedUInt;

type Inner = FixedUInt<u32, 64>;

use num_traits::Euclid;
use num_traits::Num;
use num_traits::One;
use num_traits::PrimInt;
use num_traits::ToBytes;
use num_traits::Zero;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBigIntError(pub <Inner as Num>::FromStrRadixErr);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BigInt {
    inner: Inner,
}

impl BigInt {
    pub fn new() -> Self {
        Self {
            inner: FixedUInt::new(),
        }
    }

    fn from_inner(value: Inner) -> Self {
        Self { inner: value }
    }

    pub fn mod_sub(self, rhs: &Self, modulus: &Self) -> Self {
        Self::from_inner(modmath::strict_mod_sub(
            self.inner,
            &rhs.inner,
            &modulus.inner,
        ))
    }

    pub fn mod_add(self, rhs: &Self, modulus: &Self) -> Self {
        Self::from_inner(modmath::strict_mod_add(
            self.inner,
            &rhs.inner,
            &modulus.inner,
        ))
    }

    pub fn mod_mul(self, rhs: &Self, modulus: &Self) -> Self {
        Self::from_inner(modmath::strict_mod_mul(
            self.inner,
            &rhs.inner,
            &modulus.inner,
        ))
    }

    pub fn mod_inv(self, modulus: &Self) -> Option<Self> {
        modmath::strict_mod_inv(self.inner, &modulus.inner).map(Self::from_inner)
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let me = Inner::from_le_bytes(bytes);
        Self { inner: me }
    }

    pub fn bits(&self) -> usize {
        self.inner.bit_length() as usize
    }

    // TODO: FixedUInt has no `bit()` method to delegate to; manual bit-test is required.
    pub fn bit(&self, n: u64) -> bool {
        (self.inner >> n as usize) & Inner::one() == Inner::one()
    }

    pub fn to_le_bytes(self) -> [u8; 32] {
        let f = <Inner as ToBytes>::to_le_bytes(&self.inner);
        let res = f.as_ref();
        debug_assert!(
            res[32..].iter().all(|&b| b == 0),
            "value too large for 32 bytes; truncation would lose data"
        );
        let mut output = [0u8; 32];
        output.copy_from_slice(&res[..32]);
        output
    }

    pub fn pow(&self, exp: u64) -> Self {
        let exp_u32 = u32::try_from(exp).expect("exponent must fit in a u32");
        Self::from_inner(self.inner.pow(exp_u32))
    }

    pub fn modpow(&self, exp: &Self, modulus: &Self) -> Self {
        let mp = modmath::strict_mod_exp(self.inner, &exp.inner, &modulus.inner);
        Self::from_inner(mp)
    }

    pub fn div_euclid(&self, rhs: &Self) -> Self {
        Self::from_inner(self.inner.div_euclid(&rhs.inner))
    }

    pub fn rem_euclid(self, rhs: &Self) -> Self {
        Self::from_inner(self.inner.rem_euclid(&rhs.inner))
    }

    pub fn from_str_radix(s: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        Inner::from_str_radix(s, radix)
            .map(Self::from_inner)
            .map_err(ParseBigIntError)
    }
}

impl From<u8> for BigInt {
    fn from(value: u8) -> Self {
        Self {
            inner: Inner::from(value),
        }
    }
}

impl From<i32> for BigInt {
    fn from(value: i32) -> Self {
        assert!(
            value >= 0,
            "BigInt cannot be created from a negative number"
        );
        let u32_value = value as u32;
        Self::from_inner(Inner::from(u32_value))
    }
}

impl Zero for BigInt {
    fn zero() -> Self {
        Self::new()
    }

    fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }
}

impl One for BigInt {
    fn one() -> Self {
        Self::from(1i32)
    }
}

impl num_traits::ops::overflowing::OverflowingAdd for BigInt {
    fn overflowing_add(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = self.inner.overflowing_add(&rhs.inner);
        (Self::from_inner(value), overflow)
    }
}

impl num_traits::ops::overflowing::OverflowingSub for BigInt {
    fn overflowing_sub(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = self.inner.overflowing_sub(&rhs.inner);
        (Self::from_inner(value), overflow)
    }
}

macro_rules! impl_binop_all {
    ($trait:ident, $method:ident) => {
        impl core::ops::$trait for BigInt {
            type Output = BigInt;
            fn $method(self, rhs: Self) -> BigInt {
                BigInt::from_inner(self.inner.$method(rhs.inner))
            }
        }
        impl<'a> core::ops::$trait<BigInt> for &'a BigInt {
            type Output = BigInt;
            fn $method(self, rhs: BigInt) -> BigInt {
                BigInt::from_inner(self.inner.$method(rhs.inner))
            }
        }
        impl<'a> core::ops::$trait<&'a BigInt> for BigInt {
            type Output = BigInt;
            fn $method(self, rhs: &'a BigInt) -> BigInt {
                BigInt::from_inner(self.inner.$method(rhs.inner))
            }
        }
        impl<'a> core::ops::$trait<&'a BigInt> for &'a BigInt {
            type Output = BigInt;
            fn $method(self, rhs: &'a BigInt) -> BigInt {
                BigInt::from_inner(self.inner.$method(rhs.inner))
            }
        }
    };
}
impl_binop_all!(Add, add);
impl_binop_all!(Sub, sub);
impl_binop_all!(Mul, mul);
impl_binop_all!(Rem, rem);
impl_binop_all!(BitAnd, bitand);

impl core::ops::BitOrAssign for BigInt {
    fn bitor_assign(&mut self, rhs: Self) {
        self.inner.bitor_assign(rhs.inner);
    }
}
impl core::ops::BitAndAssign for BigInt {
    fn bitand_assign(&mut self, rhs: Self) {
        self.inner.bitand_assign(rhs.inner);
    }
}
impl core::ops::AddAssign<&BigInt> for BigInt {
    fn add_assign(&mut self, rhs: &BigInt) {
        self.inner.add_assign(&rhs.inner);
    }
}

impl core::ops::SubAssign<&BigInt> for BigInt {
    fn sub_assign(&mut self, rhs: &BigInt) {
        self.inner.sub_assign(&rhs.inner);
    }
}

impl core::ops::RemAssign<&BigInt> for BigInt {
    fn rem_assign(&mut self, rhs: &BigInt) {
        self.inner.rem_assign(&rhs.inner);
    }
}
impl core::ops::Shr<usize> for BigInt {
    type Output = BigInt;
    fn shr(self, rhs: usize) -> BigInt {
        BigInt::from_inner(self.inner.shr(rhs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_and_serialization() {
        assert_eq!(BigInt::new(), BigInt::from(0i32));
        assert_eq!(BigInt::from(42u8), BigInt::from(42i32));
        assert_eq!(
            BigInt::from_str_radix("ff", 16).unwrap(),
            BigInt::from(255u8)
        );
        assert_eq!(
            BigInt::from_str_radix("100", 10).unwrap(),
            BigInt::from(100i32)
        );
        assert!(BigInt::from_str_radix("zz", 16).is_err());
        // Bytes round-trip
        let mut bytes = [0u8; 32];
        bytes[0] = 0x42;
        bytes[1] = 0x01;
        assert_eq!(BigInt::from_bytes_le(&bytes).to_le_bytes(), bytes);
        let max = [0xFFu8; 32];
        assert_eq!(BigInt::from_bytes_le(&max).to_le_bytes(), max);
        // Ordering
        assert!(BigInt::from(5i32) < BigInt::from(10i32));
    }

    #[test]
    #[allow(clippy::op_ref)]
    fn arithmetic_and_refs() {
        let (a, b) = (BigInt::from(10i32), BigInt::from(20i32));
        assert_eq!(a + b, BigInt::from(30i32));
        assert_eq!(b - a, BigInt::from(10i32));
        assert_eq!(BigInt::from(6i32) * BigInt::from(7i32), BigInt::from(42i32));
        assert_eq!(
            BigInt::from(17i32) % &BigInt::from(5i32),
            BigInt::from(2i32)
        );
        assert_eq!(BigInt::from(16i32) >> 1, BigInt::from(8i32));
        // Reference combinations for Add/Sub/Mul
        let (a, b) = (BigInt::from(3i32), BigInt::from(4i32));
        assert_eq!(&a + b, BigInt::from(7i32));
        assert_eq!(a + &b, BigInt::from(7i32));
        assert_eq!(&a + &b, BigInt::from(7i32));
        let (a, b) = (BigInt::from(10i32), BigInt::from(3i32));
        assert_eq!(a - &b, BigInt::from(7i32));
        assert_eq!(&a - &b, BigInt::from(7i32));
        assert_eq!(&a - b, BigInt::from(7i32));
        let (a, b) = (BigInt::from(5i32), BigInt::from(8i32));
        assert_eq!(&a * &b, BigInt::from(40i32));
        // BitOrAssign, BitAndAssign
        let mut v = BigInt::from(0b1010i32);
        v |= BigInt::from(0b0101i32);
        assert_eq!(v, BigInt::from(0b1111i32));
        v &= BigInt::from(0b1010i32);
        assert_eq!(v, BigInt::from(0b1010i32));
        // bits() and bit()
        assert_eq!(BigInt::new().bits(), 0);
        assert_eq!(BigInt::from(255u8).bits(), 8);
        assert!(!BigInt::from(0b10110i32).bit(0));
        assert!(BigInt::from(0b10110i32).bit(1));
        assert!(BigInt::from(0b10110i32).bit(4));
    }

    #[test]
    fn modular_ops() {
        let m = BigInt::from(10i32);
        assert_eq!(
            BigInt::from(7i32).mod_add(&BigInt::from(8i32), &m),
            BigInt::from(5i32)
        );
        assert_eq!(
            BigInt::from(3i32).mod_sub(&BigInt::from(8i32), &m),
            BigInt::from(5i32)
        );
        // 3^4=81, 81%5=1
        assert_eq!(
            BigInt::from(3i32).modpow(&BigInt::from(4i32), &BigInt::from(5i32)),
            BigInt::from(1i32)
        );
        // Fermat's little theorem: 7^12 ≡ 1 (mod 13)
        assert_eq!(
            BigInt::from(7i32).modpow(&BigInt::from(12i32), &BigInt::from(13i32)),
            BigInt::from(1i32)
        );
        assert_eq!(BigInt::from(2i32).pow(10), BigInt::from(1024i32));
        assert_eq!(
            BigInt::from(17i32).div_euclid(&BigInt::from(5i32)),
            BigInt::from(3i32)
        );
        assert_eq!(
            BigInt::from(17i32).rem_euclid(&BigInt::from(5i32)),
            BigInt::from(2i32)
        );
        assert_eq!(
            BigInt::from(7i32).mod_mul(&BigInt::from(6i32), &m),
            BigInt::from(2i32)
        );
        let modulus = BigInt::from(13i32);
        assert_eq!(
            BigInt::from(5i32).mod_inv(&modulus),
            Some(BigInt::from(8i32))
        );
        assert_eq!(BigInt::from(0i32).mod_inv(&modulus), None);
    }
}
