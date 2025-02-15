use fixed_bigint::FixedUInt;

type Inner = FixedUInt<u32, 32>;

use num_traits::Num;
use num_traits::PrimInt;
use num_traits::ToBytes;
use num_traits::Zero;
use num_traits::One;
use num_traits::Euclid;

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
        let mut count = 0;
        let mut value = self.inner;
        while value != Inner::zero() {
            value = value >> 1usize;
            count += 1;
        }
        count
    }
    pub fn bit(&self, n: u64) -> bool {
        // shift n times and check if the last bit is 1
        (self.inner >> n as usize) & Inner::one() == Inner::one()
    }
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let f= <Inner as ToBytes>::to_le_bytes(&self.inner);
        let res = f.as_ref();
        let mut output = [0u8; 32];
        let len = output.len();
        output.copy_from_slice(&res[..len]);
        output
    }
    pub fn to_signed_bytes_le(&self) -> [u8; 32] { 
        // if the most significant bit is 1, we need to sign extend
        let mut output = self.to_le_bytes();
        todo!()
    }
    pub fn pow(&self, exp: u64) -> Self {
        Self::from_self(self.inner.pow(exp as u32))
    }
    pub fn modpow(&self, exp: &Self, modulus: &Self) -> Self {
        let mp = modmath::basic_mod_exp( self.inner, exp.inner, modulus.inner);
        Self::from_self(mp)
    }
    pub fn div_euclid(&self, rhs: &Self) -> Self {
        let res = self.inner.div_euclid(&rhs.inner);
        Self::from_self(res)
    }
    pub fn rem_euclid(self, rhs: &Self) -> Self {
        let res = self.inner.rem_euclid(&rhs.inner);
        Self::from_self(res)
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
        if value < 0 {
            assert!(value >= 0, "Negative value");
        }
        let u32_value = value as u32;
        Self::from_self(Inner::from(u32_value))
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
