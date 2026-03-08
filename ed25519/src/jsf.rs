// Joint Sparse Form (JSF) implementation for Ed25519
// Processes two scalars simultaneously with ~50% fewer point additions
// No lookup tables - perfect for code-size constrained environments

/// JSF digit: -1, 0, or 1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsfDigit {
    pub s_digit: i8, // For scalar s: -1, 0, or 1
    pub h_digit: i8, // For scalar h: -1, 0, or 1
}

// Max JSF digits: Ed25519 scalars are ~255 bits, carry can add 1
const MAX_JSF_DIGITS: usize = 258;

// Packed storage: 2 bits per digit value {-1,0,1}, 4 bits per (s,h) pair, 2 pairs per byte
// Encoding: -1 → 0b11, 0 → 0b00, 1 → 0b01 (zero-init gives all-zeros = all digit 0)
const PACKED_JSF_BYTES: usize = MAX_JSF_DIGITS.div_ceil(2); // 129

/// Encode a digit value {-1, 0, 1} into 2 bits
const fn encode_digit(d: i8) -> u8 {
    (d as u8) & 0x03
}

/// Decode 2 bits back to a digit value {-1, 0, 1}
const fn decode_digit(raw: u8) -> i8 {
    // Sign-extend from 2-bit two's complement: 00→0, 01→1, 11→-1
    ((raw << 6) as i8) >> 6
}

/// JSF generator that produces signed digits {-1, 0, 1} for two scalars
/// Reduces the density of non-zero digits compared to binary representation
/// Digits are packed: 4 bits per (s,h) pair, 129 bytes total vs 516 unpacked
pub struct JsfIterator {
    packed: [u8; PACKED_JSF_BYTES],
    len: usize,
    index: usize,
}

impl JsfIterator {
    /// Store a digit pair at the given index
    fn pack_set(&mut self, idx: usize, s_digit: i8, h_digit: i8) {
        let byte_idx = idx / 2;
        let nibble = (encode_digit(s_digit) << 2) | encode_digit(h_digit);
        if idx.is_multiple_of(2) {
            self.packed[byte_idx] = (self.packed[byte_idx] & 0xF0) | nibble;
        } else {
            self.packed[byte_idx] = (self.packed[byte_idx] & 0x0F) | (nibble << 4);
        }
    }

    /// Read a digit pair from the given index
    fn pack_get(&self, idx: usize) -> JsfDigit {
        let byte_idx = idx / 2;
        let nibble = if idx.is_multiple_of(2) {
            self.packed[byte_idx] & 0x0F
        } else {
            self.packed[byte_idx] >> 4
        };
        JsfDigit {
            s_digit: decode_digit((nibble >> 2) & 0x03),
            h_digit: decode_digit(nibble & 0x03),
        }
    }

    /// Generate JSF representation for two scalars
    /// Returns iterator that processes from MSB to LSB
    pub fn new<T>(s: T, h: T) -> Self
    where
        T: num_traits::Zero
            + num_traits::One
            + PartialOrd
            + PartialEq
            + core::ops::ShrAssign<usize>
            + core::ops::Add<Output = T>,
        for<'a> &'a T: core::ops::BitAnd<Output = T>
            + core::ops::Add<&'a T, Output = T>
            + core::ops::Sub<&'a T, Output = T>,
    {
        let mut iter = JsfIterator {
            packed: [0u8; PACKED_JSF_BYTES],
            len: 0,
            index: 0,
        };

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
                let s_low_2bits = &s_working & &(T::one() + T::one() + T::one()); // & 3
                if s_low_2bits == T::one() || s_low_2bits == (T::one() + T::one()) {
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
                let h_low_2bits = &h_working & &(T::one() + T::one() + T::one()); // & 3
                if h_low_2bits == T::one() || h_low_2bits == (T::one() + T::one()) {
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

            if iter.len < MAX_JSF_DIGITS {
                iter.pack_set(iter.len, s_digit, h_digit);
                iter.len += 1;
            }

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

        iter
    }

    /// Iterate from MSB to LSB (reverse order for scalar multiplication)
    pub fn digits_msb_first(&self) -> impl Iterator<Item = JsfDigit> + '_ {
        (0..self.len).rev().map(move |i| self.pack_get(i))
    }
}

impl Iterator for JsfIterator {
    type Item = JsfDigit;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.len {
            let digit = self.pack_get(self.index);
            self.index += 1;
            Some(digit)
        } else {
            None
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
    fn test_jsf_encode_decode_roundtrip() {
        for d in [-1i8, 0, 1] {
            let encoded = encode_digit(d);
            let decoded = decode_digit(encoded);
            assert_eq!(d, decoded, "roundtrip failed for {d}: encoded={encoded}");
        }
    }

    #[test]
    fn test_jsf_pack_roundtrip() {
        let mut iter = JsfIterator {
            packed: [0u8; PACKED_JSF_BYTES],
            len: 0,
            index: 0,
        };
        // Test all 9 combinations of (s, h) digit pairs
        let vals = [-1i8, 0, 1];
        let mut idx = 0;
        for &s in &vals {
            for &h in &vals {
                iter.pack_set(idx, s, h);
                let got = iter.pack_get(idx);
                assert_eq!(got.s_digit, s, "s mismatch at idx {idx}");
                assert_eq!(got.h_digit, h, "h mismatch at idx {idx}");
                idx += 1;
            }
        }
    }
}
