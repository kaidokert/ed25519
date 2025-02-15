
use fixed_bigint::FixedUInt;

type Inner = FixedUInt<u32, 32>;

use num_traits::Num;
use num_traits::PrimInt;

#[derive(PartialEq)]
pub enum Sign {
    Plus,
    Minus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParseBigIntError;

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
    fn from_self(value: Inner) -> Self {
        Self { inner: value }
    }
    pub fn from_bytes_le(sign: Sign, bytes: &[u8]) -> Self {
        assert!(sign == Sign::Plus);
        let me = Inner::from_le_bytes(bytes);
        Self { inner: me }
    }

    pub fn bits(&self) -> usize {
        todo!()
    }
    pub fn bit(&self, n: u64) -> bool {
        todo!()
    }
    pub fn to_le_bytes(&self) -> [u8; 32] {
        todo!()
    }
    pub fn to_signed_bytes_le(&self) -> [u8; 32] { 
        todo!()
    }
    pub fn pow(&self, exp: u64) -> Self {
        Self::from_self(self.inner.pow(exp as u32))
    }
    pub fn modpow(&self, exp: &Self, modulus: &Self) -> Self {
        todo!()
    }
    pub fn div_euclid(&self, rhs: &Self) -> Self {
        todo!()
    }
    pub fn rem_euclid(self, rhs: &Self) -> Self {
        todo!()
    }
    pub fn from_str_radix(s: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        let inside = Inner::from_str_radix(s, radix).map(Self::from_self);
        inside.map_err(|_| ParseBigIntError)
    }
    #[cfg(test)]
    pub fn to_str_radix(&self, radix: u32) -> String {
        todo!()
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
        todo!()
    }
}
impl From<i64> for BigInt {
    fn from(value: i64) -> Self {
        todo!()
    }
}

impl core::ops::Add for BigInt {
    type Output = BigInt;

    fn add(self, rhs: Self) -> Self::Output {
        BigInt::from_self(self.inner.add(rhs.inner))
    }
}
impl<'a> core::ops::Add<BigInt> for &'a BigInt {
    type Output = BigInt;

    fn add(self, rhs: BigInt) -> Self::Output {
        BigInt::from_self(self.inner.add(rhs.inner))
    }
}
// one missing here
impl<'a> core::ops::Add<&'a BigInt> for &'a BigInt {
    type Output = BigInt;

    fn add(self, rhs: &'a BigInt) -> Self::Output {
        BigInt::from_self(self.inner.add(rhs.inner))
    }
}

impl core::ops::Sub for BigInt {
    type Output = BigInt;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::from_self(self.inner.sub(rhs.inner))
    }
}
impl<'a> core::ops::Sub<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn sub(self, rhs: &'a Self) -> Self::Output {
        BigInt::from_self(self.inner.sub(rhs.inner))
    }
}
impl<'a> core::ops::Sub<&'a BigInt> for &'a BigInt {
    type Output = BigInt;

    fn sub(self, rhs: Self) -> Self::Output {
        BigInt::from_self(self.inner.sub(rhs.inner))
    }
}
impl<'a> core::ops::Sub<BigInt> for &'a BigInt {
    type Output = BigInt;

    fn sub(self, rhs: BigInt) -> Self::Output {
        BigInt::from_self(self.inner.sub(rhs.inner))
    }
}
impl<'a> core::ops::Sub<u8> for &'a BigInt {
    type Output = BigInt;

    fn sub(self, rhs: u8) -> Self::Output {
        let rhs = BigInt::from(rhs);
        BigInt::from_self(self.inner.sub(rhs.inner))
    }
}

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

impl core::ops::Mul for BigInt {
    type Output = BigInt;

    fn mul(self, rhs: Self) -> Self::Output {
        BigInt::from_self(self.inner.mul(rhs.inner))
    }
}
impl<'a> core::ops::Mul<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn mul(self, rhs: &'a BigInt) -> Self::Output {
        BigInt::from_self(self.inner.mul(rhs.inner))
    }
}
impl<'a> core::ops::Mul for &'a BigInt {
    type Output = BigInt;

    fn mul(self, rhs: Self) -> Self::Output {
        BigInt::from_self(self.inner.mul(rhs.inner))
    }
}

impl<'a> core::ops::Mul<BigInt> for &'a BigInt {
    type Output = BigInt;

    fn mul(self, rhs: BigInt) -> Self::Output {
        BigInt::from_self(self.inner.mul(rhs.inner))
    }
}

impl<'a> core::ops::Rem<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn rem(self, rhs: &'a BigInt) -> Self::Output {
        BigInt::from_self(self.inner.rem(rhs.inner))
    }
}

impl core::ops::Shr<usize> for BigInt {
    type Output = BigInt;

    fn shr(self, rhs: usize) -> Self::Output {
        BigInt::from_self(self.inner.shr(rhs))
    }
}
