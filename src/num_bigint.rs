use fixed_bigint::FixedUInt;

type Inner = FixedUInt<u32, 16>;

use num_traits::One;

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
    pub fn mod_mul(self, rhs: &Self, modulus: &Self) -> Self {
        Self::from_self(modmath::strict_mod_mul(self.inner, &rhs.inner, &modulus.inner))
    }
    pub fn mod_sub(self, rhs: &Self, modulus: &Self) -> Self {
        Self::from_self(modmath::strict_mod_sub(self.inner, &rhs.inner, &modulus.inner))
    }
    pub fn mod_add(self, rhs: &Self, modulus: &Self) -> Self {
        Self::from_self(modmath::strict_mod_add(self.inner, &rhs.inner, &modulus.inner))
    }
    pub fn modpow(&self, exp: &Self, modulus: &Self) -> Self {
        let mp = modmath::strict_mod_exp ( self.inner, &exp.inner, &modulus.inner);
        Self::from_self(mp)
    }

    fn from_self(value: Inner) -> Self {
        Self { inner: value }
    }
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let me = Inner::from_le_bytes(bytes);
        Self { inner: me }
    }
    pub fn is_odd(&self) -> bool {
        self.inner & Inner::one() == Inner::one()
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

impl core::ops::Div for BigInt {
    type Output = BigInt;

    fn div(self, rhs: Self) -> Self::Output {
        BigInt::from_self(self.inner.div(rhs.inner))
    }
}
impl<'a> core::ops::Div<&'a BigInt> for BigInt {
    type Output = BigInt;

    fn div(self, rhs: &'a BigInt) -> Self::Output {
        BigInt::from_self(self.inner.div(rhs.inner))
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
impl<'a> core::ops::Add<&'a BigInt> for BigInt {
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
impl core::ops::ShrAssign<usize> for BigInt {
    fn shr_assign(&mut self, rhs: usize) {
        self.inner.shr_assign(rhs);
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
