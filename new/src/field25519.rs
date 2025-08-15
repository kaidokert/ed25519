// Specialized field arithmetic for Ed25519 prime p = 2^255 - 19
// Optimized for minimal code size and maximum performance

use core::ops::{Add, Sub, Mul, BitAnd, Rem, Div, AddAssign, SubAssign, RemAssign, DivAssign, ShrAssign, ShlAssign};
use num_traits::{Zero, One};
use num_traits::ops::overflowing::{OverflowingAdd, OverflowingSub};

/// Field element for Ed25519 prime p = 2^255 - 19
/// Uses 4 × u64 limbs in little-endian order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F25519 {
    /// 4 limbs in little-endian: [low, ..., high]
    limbs: [u64; 4],
}

// Ed25519 prime: p = 2^255 - 19
const P_LIMBS: [u64; 4] = [
    0xffffffffffffffed, // p[0] = 2^64 - 19
    0xffffffffffffffff, // p[1] = 2^64 - 1  
    0xffffffffffffffff, // p[2] = 2^64 - 1
    0x7fffffffffffffff, // p[3] = 2^63 - 1 (MSB = 0 for 255 bits)
];

impl F25519 {
    /// Create zero element
    pub const fn zero() -> Self {
        F25519 { limbs: [0, 0, 0, 0] }
    }
    
    /// Create one element
    pub const fn one() -> Self {
        F25519 { limbs: [1, 0, 0, 0] }
    }
    
    /// Create from Ed25519 prime p
    pub const fn prime() -> Self {
        F25519 { limbs: P_LIMBS }
    }
    
    /// Create from little-endian bytes (32 bytes)
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 32, "Need at least 32 bytes");
        
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut limb = 0u64;
            for j in 0..8 {
                limb |= (bytes[i * 8 + j] as u64) << (j * 8);
            }
            limbs[i] = limb;
        }
        
        let mut result = F25519 { limbs };
        result.reduce();
        result
    }
    
    /// Convert to little-endian bytes (32 bytes)
    pub fn to_bytes_le<'a>(&self, buffer: &'a mut [u8]) -> &'a [u8] {
        assert!(buffer.len() >= 32, "Buffer too small");
        
        for i in 0..4 {
            let limb = self.limbs[i];
            for j in 0..8 {
                buffer[i * 8 + j] = ((limb >> (j * 8)) & 0xff) as u8;
            }
        }
        
        &buffer[..32]
    }
    
    /// Fast modular reduction using 2^255 ≡ 19 (mod p)
    /// This is the key optimization!
    fn reduce(&mut self) {
        // Check if we need reduction
        if self.limbs[3] < 0x8000000000000000 {
            // High bit is 0, so we're already < 2^255
            return;
        }
        
        // We have overflow beyond 2^255
        // Extract the overflow bits and multiply by 19
        let overflow = self.limbs[3] >> 63; // Extract bit 255+
        self.limbs[3] &= 0x7fffffffffffffff; // Clear overflow bits
        
        // Add overflow * 19 to the result
        let mut carry = overflow * 19;
        for i in 0..4 {
            let sum = self.limbs[i] as u128 + carry as u128;
            self.limbs[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        
        // Handle final carry if needed
        if carry > 0 {
            // Add carry * 19 again
            let mut carry2 = carry * 19;
            for i in 0..4 {
                let sum = self.limbs[i] as u128 + carry2 as u128;
                self.limbs[i] = sum as u64;
                carry2 = (sum >> 64) as u64;
            }
        }
        
        // Final check: if result >= p, subtract p
        let prime = F25519::prime();
        if *self >= prime {
            *self = *self - prime;
        }
    }
    
    /// Check if this element is zero
    pub fn is_zero(&self) -> bool {
        self.limbs[0] == 0 && self.limbs[1] == 0 && self.limbs[2] == 0 && self.limbs[3] == 0
    }
}

impl Add for F25519 {
    type Output = F25519;
    
    fn add(self, rhs: F25519) -> F25519 {
        let mut result = F25519::zero();
        let mut carry = 0u64;
        
        for i in 0..4 {
            let sum = self.limbs[i] as u128 + rhs.limbs[i] as u128 + carry as u128;
            result.limbs[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        
        // Handle final carry using 2^256 ≡ 2*19 = 38 (mod p)
        if carry > 0 {
            let mut carry2 = carry * 38;
            for i in 0..4 {
                let sum = result.limbs[i] as u128 + carry2 as u128;
                result.limbs[i] = sum as u64;
                carry2 = (sum >> 64) as u64;
            }
        }
        
        result.reduce();
        result
    }
}

impl Sub for F25519 {
    type Output = F25519;
    
    fn sub(self, rhs: F25519) -> F25519 {
        let mut result = F25519::zero();
        let mut borrow = 0i128;
        
        for i in 0..4 {
            let diff = self.limbs[i] as i128 - rhs.limbs[i] as i128 - borrow;
            if diff < 0 {
                result.limbs[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result.limbs[i] = diff as u64;
                borrow = 0;
            }
        }
        
        // If we borrowed from position beyond the field, add p
        if borrow > 0 {
            result = result + F25519::prime();
        }
        
        result
    }
}

impl Mul for F25519 {
    type Output = F25519;
    
    fn mul(self, rhs: F25519) -> F25519 {
        // Schoolbook multiplication: 4×4 limbs -> 8 limb result
        let mut result = [0u64; 8];
        
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let prod = (self.limbs[i] as u128) * (rhs.limbs[j] as u128) + 
                          (result[i + j] as u128) + (carry as u128);
                result[i + j] = prod as u64;
                carry = (prod >> 64) as u64;
            }
            result[i + 4] = carry;
        }
        
        // Reduce using 2^255 ≡ 19 (mod p)
        // Split into low 255 bits and high bits
        let mut reduced = F25519::zero();
        
        // Copy low 4 limbs
        reduced.limbs[0] = result[0];
        reduced.limbs[1] = result[1]; 
        reduced.limbs[2] = result[2];
        reduced.limbs[3] = result[3] & 0x7fffffffffffffff; // Mask to 255 bits
        
        // Handle high bits: multiply by 19 and add
        let _high_bit_255 = (result[3] >> 63) & 1;
        let high_limbs = [
            (result[3] >> 63) | (result[4] << 1),
            (result[4] >> 63) | (result[5] << 1),
            (result[5] >> 63) | (result[6] << 1),
            (result[6] >> 63) | (result[7] << 1),
        ];
        
        // Multiply high part by 19
        let mut carry = 0u64;
        for i in 0..4 {
            let prod = (high_limbs[i] as u128) * 19u128 + carry as u128;
            carry = (prod >> 64) as u64;
            
            let sum = reduced.limbs[i] as u128 + (prod as u64) as u128;
            reduced.limbs[i] = sum as u64;
            if sum >> 64 > 0 {
                carry += (sum >> 64) as u64;
            }
        }
        
        reduced.reduce();
        reduced
    }
}

// Comparison operations
impl PartialOrd for F25519 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for F25519 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                core::cmp::Ordering::Equal => continue,
                other => return other,
            }
        }
        core::cmp::Ordering::Equal
    }
}

// Implement required traits for BrigIntStrict compatibility
impl BitAnd for F25519 {
    type Output = F25519;
    
    fn bitand(self, rhs: F25519) -> F25519 {
        F25519 {
            limbs: [
                self.limbs[0] & rhs.limbs[0],
                self.limbs[1] & rhs.limbs[1], 
                self.limbs[2] & rhs.limbs[2],
                self.limbs[3] & rhs.limbs[3],
            ]
        }
    }
}

impl Rem for F25519 {
    type Output = F25519;
    
    fn rem(self, _rhs: F25519) -> F25519 {
        // For field elements, a % p = a (assuming a is already reduced)
        self
    }
}

impl Div for F25519 {
    type Output = F25519;
    
    fn div(self, _rhs: F25519) -> F25519 {
        // Division in field: a / b = a * b^(-1)
        // For now, just return self (will need proper inversion)
        self
    }
}

// Implement shift operations
impl core::ops::Shr<usize> for F25519 {
    type Output = F25519;
    
    fn shr(self, rhs: usize) -> F25519 {
        let mut result = F25519::zero();
        let limb_shift = rhs / 64;
        let bit_shift = rhs % 64;
        
        if limb_shift >= 4 {
            return result; // Shifted away everything
        }
        
        for i in 0..(4 - limb_shift) {
            result.limbs[i] = self.limbs[i + limb_shift] >> bit_shift;
            if i + limb_shift + 1 < 4 && bit_shift > 0 {
                result.limbs[i] |= self.limbs[i + limb_shift + 1] << (64 - bit_shift);
            }
        }
        
        result
    }
}

impl core::ops::Shl<usize> for F25519 {
    type Output = F25519;
    
    fn shl(self, rhs: usize) -> F25519 {
        let mut result = self;
        // Simple left shift - may overflow beyond field
        for _ in 0..rhs {
            let mut carry = 0;
            for i in 0..4 {
                let new_carry = result.limbs[i] >> 63;
                result.limbs[i] = (result.limbs[i] << 1) | carry;
                carry = new_carry;
            }
        }
        result.reduce();
        result
    }
}

// Implement num_traits
impl Zero for F25519 {
    fn zero() -> Self {
        F25519::zero()
    }
    
    fn is_zero(&self) -> bool {
        self.is_zero()
    }
}

impl One for F25519 {
    fn one() -> Self {
        F25519::one()
    }
}

// Implement overflowing operations
impl OverflowingAdd for F25519 {
    fn overflowing_add(&self, v: &Self) -> (Self, bool) {
        let result = *self + *v;
        // In a field, we never really "overflow" since everything is mod p
        (result, false)
    }
}

impl OverflowingSub for F25519 {
    fn overflowing_sub(&self, v: &Self) -> (Self, bool) {
        let result = *self - *v;
        // In a field, we never really "overflow" since everything is mod p
        (result, false)
    }
}

// Implement assignment operations
impl AddAssign for F25519 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<'a> AddAssign<&'a F25519> for F25519 {
    fn add_assign(&mut self, rhs: &'a F25519) {
        *self = *self + *rhs;
    }
}

impl SubAssign for F25519 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl RemAssign for F25519 {
    fn rem_assign(&mut self, _rhs: Self) {
        // Field elements are already reduced
    }
}

impl<'a> RemAssign<&'a F25519> for F25519 {
    fn rem_assign(&mut self, _rhs: &'a F25519) {
        // Field elements are already reduced
    }
}

impl DivAssign for F25519 {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<'a> DivAssign<&'a F25519> for F25519 {
    fn div_assign(&mut self, rhs: &'a F25519) {
        *self = *self / *rhs;
    }
}

impl ShrAssign<usize> for F25519 {
    fn shr_assign(&mut self, rhs: usize) {
        *self = *self >> rhs;
    }
}

impl ShlAssign<usize> for F25519 {
    fn shl_assign(&mut self, rhs: usize) {
        *self = *self << rhs;
    }
}

// Implement reference operations
impl<'a> Add<&'a F25519> for F25519 {
    type Output = F25519;
    
    fn add(self, rhs: &'a F25519) -> F25519 {
        self + *rhs
    }
}

impl<'a> Sub<&'a F25519> for F25519 {
    type Output = F25519;
    
    fn sub(self, rhs: &'a F25519) -> F25519 {
        self - *rhs
    }
}

impl<'a> Mul<&'a F25519> for F25519 {
    type Output = F25519;
    
    fn mul(self, rhs: &'a F25519) -> F25519 {
        self * *rhs
    }
}

impl<'a> Rem<&'a F25519> for F25519 {
    type Output = F25519;
    
    fn rem(self, _rhs: &'a F25519) -> F25519 {
        self // Already reduced
    }
}

impl<'a> Div<&'a F25519> for F25519 {
    type Output = F25519;
    
    fn div(self, rhs: &'a F25519) -> F25519 {
        self / *rhs
    }
}

impl<'a> BitAnd<&'a F25519> for F25519 {
    type Output = F25519;
    
    fn bitand(self, rhs: &'a F25519) -> F25519 {
        self & *rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_arithmetic() {
        let zero = F25519::zero();
        let one = F25519::one();
        
        assert_eq!(zero + zero, zero);
        assert_eq!(one + zero, one);
        assert_eq!(one - one, zero);
    }
    
    #[test] 
    fn test_prime_properties() {
        let p = F25519::prime();
        let zero = F25519::zero();
        
        // p should reduce to 0 mod p
        assert_eq!(p - p, zero);
    }
}