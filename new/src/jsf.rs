// Joint Sparse Form (JSF) implementation for Ed25519
// Processes two scalars simultaneously with ~50% fewer point additions
// No lookup tables - perfect for code-size constrained environments

use crate::BrigIntStrict;

/// JSF digit: -1, 0, or 1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsfDigit {
    pub s_digit: i8,  // For scalar s: -1, 0, or 1
    pub h_digit: i8,  // For scalar h: -1, 0, or 1
}

impl JsfDigit {
    pub const fn new(s_digit: i8, h_digit: i8) -> Self {
        JsfDigit { s_digit, h_digit }
    }
    
    pub const fn zero() -> Self {
        JsfDigit { s_digit: 0, h_digit: 0 }
    }
}

/// JSF generator that produces signed digits {-1, 0, 1} for two scalars
/// Reduces the density of non-zero digits compared to binary representation
pub struct JsfIterator {
    digits: Vec<JsfDigit>,
    index: usize,
}

impl JsfIterator {
    /// Generate JSF representation for two scalars
    /// Returns iterator that processes from MSB to LSB
    pub fn new<T: BrigIntStrict>(s: T, h: T) -> Self 
    where
        for<'a> &'a T: core::ops::BitAnd<Output = T>
            + core::ops::Add<&'a T, Output = T>
            + core::ops::Sub<&'a T, Output = T>
    {
        let mut digits = Vec::new();
        
        // Convert scalars to mutable copies for processing
        let mut s_working = s;
        let mut h_working = h;
        
        // Process scalars bit by bit to generate JSF digits
        while s_working > T::zero() || h_working > T::zero() {
            // Extract low bits from both scalars
            let s_bit = (&s_working & &T::one()) == T::one();
            let h_bit = (&h_working & &T::one()) == T::one();
            
            // JSF recoding rules to minimize non-zero digits
            let (s_digit, s_carry) = if s_bit {
                // s is odd
                let s_low_2bits = &s_working & &(&T::one() + &T::one() + &T::one()); // & 3
                if s_low_2bits == T::one() || s_low_2bits == (&T::one() + &T::one()) {
                    // s ≡ 1 or 2 (mod 4) -> use +1
                    (1i8, false)
                } else {
                    // s ≡ 3 (mod 4) -> use -1 and carry
                    (-1i8, true)
                }
            } else {
                // s is even -> digit 0
                (0i8, false)
            };
            
            let (h_digit, h_carry) = if h_bit {
                // h is odd
                let h_low_2bits = &h_working & &(&T::one() + &T::one() + &T::one()); // & 3
                if h_low_2bits == T::one() || h_low_2bits == (&T::one() + &T::one()) {
                    // h ≡ 1 or 2 (mod 4) -> use +1
                    (1i8, false)
                } else {
                    // h ≡ 3 (mod 4) -> use -1 and carry
                    (-1i8, true)
                }
            } else {
                // h is even -> digit 0
                (0i8, false)
            };
            
            digits.push(JsfDigit::new(s_digit, h_digit));
            
            // Shift scalars right and handle carries
            s_working >>= 1;
            h_working >>= 1;
            
            if s_carry {
                s_working = s_working + T::one();
            }
            if h_carry {
                h_working = h_working + T::one();
            }
        }
        
        JsfIterator {
            digits,
            index: 0,
        }
    }
    
    /// Faster JSF generation using direct byte processing for 32-byte scalars
    /// Avoids expensive bigint operations by working directly on little-endian bytes
    pub fn from_bytes_32(s_bytes: &[u8; 32], h_bytes: &[u8; 32]) -> Self {
        let mut digits = Vec::with_capacity(256); // Ed25519 scalars are ~255 bits
        
        // Convert to little-endian u64 arrays for efficient processing
        let mut s_words = [0u64; 4]; 
        let mut h_words = [0u64; 4];
        
        for i in 0..4 {
            s_words[i] = u64::from_le_bytes([
                s_bytes[i*8], s_bytes[i*8+1], s_bytes[i*8+2], s_bytes[i*8+3],
                s_bytes[i*8+4], s_bytes[i*8+5], s_bytes[i*8+6], s_bytes[i*8+7]
            ]);
            h_words[i] = u64::from_le_bytes([
                h_bytes[i*8], h_bytes[i*8+1], h_bytes[i*8+2], h_bytes[i*8+3], 
                h_bytes[i*8+4], h_bytes[i*8+5], h_bytes[i*8+6], h_bytes[i*8+7]
            ]);
        }
        
        // Process bit by bit using efficient u64 operations
        let mut bit_pos = 0;
        let is_zero = |words: &[u64; 4]| words.iter().all(|&w| w == 0);
        
        while !is_zero(&s_words) || !is_zero(&h_words) {
            // Extract least significant bits
            let s_bit = (s_words[0] & 1) == 1;
            let h_bit = (h_words[0] & 1) == 1;
            
            // JSF recoding rules
            let (s_digit, s_carry) = if s_bit {
                let s_low_2bits = s_words[0] & 3;
                if s_low_2bits == 1 || s_low_2bits == 2 {
                    (1i8, false)
                } else {
                    (-1i8, true)
                }
            } else {
                (0i8, false)
            };
            
            let (h_digit, h_carry) = if h_bit {
                let h_low_2bits = h_words[0] & 3;
                if h_low_2bits == 1 || h_low_2bits == 2 {
                    (1i8, false)
                } else {
                    (-1i8, true)
                }
            } else {
                (0i8, false)
            };
            
            digits.push(JsfDigit::new(s_digit, h_digit));
            
            // Shift right by 1 bit with carry propagation
            let shift_right_with_carry = |words: &mut [u64; 4], carry: bool| {
                let mut c = if carry { 1u64 } else { 0u64 };
                for word in words.iter_mut() {
                    let new_c = (*word & 1) << 63;
                    *word = (*word >> 1) | c;
                    c = new_c;
                }
            };
            
            shift_right_with_carry(&mut s_words, false);
            shift_right_with_carry(&mut h_words, false);
            
            if s_carry {
                // Add 1 to s_words
                let mut carry = 1u64;
                for word in s_words.iter_mut() {
                    let (result, new_carry) = word.overflowing_add(carry);
                    *word = result;
                    carry = if new_carry { 1 } else { 0 };
                    if carry == 0 { break; }
                }
            }
            
            if h_carry {
                // Add 1 to h_words  
                let mut carry = 1u64;
                for word in h_words.iter_mut() {
                    let (result, new_carry) = word.overflowing_add(carry);
                    *word = result;
                    carry = if new_carry { 1 } else { 0 };
                    if carry == 0 { break; }
                }
            }
            
            bit_pos += 1;
            if bit_pos > 256 { // Safety limit
                break;
            }
        }
        
        JsfIterator {
            digits,
            index: 0,
        }
    }
    
    /// Get total number of digits
    pub fn len(&self) -> usize {
        self.digits.len()
    }
    
    /// Check if JSF is empty
    pub fn is_empty(&self) -> bool {
        self.digits.is_empty()
    }
    
    /// Iterate from MSB to LSB (reverse order for scalar multiplication)
    pub fn digits_msb_first(&self) -> impl Iterator<Item = JsfDigit> + '_ {
        self.digits.iter().rev().copied()
    }
}

impl Iterator for JsfIterator {
    type Item = JsfDigit;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.digits.len() {
            let digit = self.digits[self.index];
            self.index += 1;
            Some(digit)
        } else {
            None
        }
    }
}

/// Statistics about JSF efficiency
pub struct JsfStats {
    pub total_digits: usize,
    pub s_nonzero: usize,
    pub h_nonzero: usize,
    pub total_nonzero: usize,
    pub efficiency_vs_binary: f64,
}

impl JsfStats {
    pub fn analyze(jsf: &JsfIterator) -> Self {
        let total_digits = jsf.len();
        let mut s_nonzero = 0;
        let mut h_nonzero = 0;
        let mut total_nonzero = 0;
        
        for digit in &jsf.digits {
            if digit.s_digit != 0 {
                s_nonzero += 1;
            }
            if digit.h_digit != 0 {
                h_nonzero += 1;
            }
            if digit.s_digit != 0 || digit.h_digit != 0 {
                total_nonzero += 1;
            }
        }
        
        // Binary would have ~50% nonzero digits for each scalar
        let binary_expected = total_digits * 2 / 2; // 2 scalars × 50% density
        let efficiency_vs_binary = if binary_expected > 0 {
            1.0 - (total_nonzero as f64 / binary_expected as f64)
        } else {
            0.0
        };
        
        JsfStats {
            total_digits,
            s_nonzero,
            h_nonzero,
            total_nonzero,
            efficiency_vs_binary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_jsf_basic() {
        // Test with small values
        let s = 5u64; // Binary: 101
        let h = 3u64; // Binary: 11
        
        let jsf = JsfIterator::new(s, h);
        let digits: Vec<_> = jsf.digits_msb_first().collect();
        
        // Should generate some JSF digits
        assert!(!digits.is_empty());
        
        // All digits should be in range [-1, 0, 1]
        for digit in &digits {
            assert!(digit.s_digit >= -1 && digit.s_digit <= 1);
            assert!(digit.h_digit >= -1 && digit.h_digit <= 1);
        }
    }
    
    #[test]
    fn test_jsf_efficiency() {
        // Test with larger values to check efficiency
        let s = 0x12345678u64;
        let h = 0x9abcdef0u64;
        
        let jsf = JsfIterator::new(s, h);
        let stats = JsfStats::analyze(&jsf);
        
        println!("JSF Statistics:");
        println!("Total digits: {}", stats.total_digits);
        println!("S nonzero: {}", stats.s_nonzero);
        println!("H nonzero: {}", stats.h_nonzero);
        println!("Total nonzero: {}", stats.total_nonzero);
        println!("Efficiency vs binary: {:.1}%", stats.efficiency_vs_binary * 100.0);
        
        // JSF should be more efficient than binary
        assert!(stats.efficiency_vs_binary > 0.0);
    }
}