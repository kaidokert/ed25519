// Paired NAF (Non-Adjacent Form) recoding for double-scalar multiplication.
// Each scalar is independently recoded into signed digits {-1, 0, 1} using NAF,
// then the two digit streams are paired for simultaneous processing.
// No lookup tables - perfect for code-size constrained environments.
//
// TODO: implement true Joint Sparse Form (JSF / Solinas) which makes joint
// decisions when both scalars are odd, guaranteeing at most one non-zero digit
// per position. This would reduce point additions by ~33% vs paired NAF.

/// NAF digit pair: -1, 0, or 1 for each of two scalars
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NafDigit {
    pub s_digit: i8, // For scalar s: -1, 0, or 1
    pub h_digit: i8, // For scalar h: -1, 0, or 1
}

// Max NAF digits: Ed25519 scalars are ~255 bits, carry can add 1
const MAX_NAF_DIGITS: usize = 258;

// Packed storage: 2 bits per digit value {-1,0,1}, 4 bits per (s,h) pair, 2 pairs per byte
// Encoding: -1 → 0b11, 0 → 0b00, 1 → 0b01 (zero-init gives all-zeros = all digit 0)
const PACKED_NAF_BYTES: usize = MAX_NAF_DIGITS.div_ceil(2); // 129

/// Encode a digit value {-1, 0, 1} into 2 bits
const fn encode_digit(d: i8) -> u8 {
    (d as u8) & 0x03
}

/// Decode 2 bits back to a digit value {-1, 0, 1}
const fn decode_digit(raw: u8) -> i8 {
    // Sign-extend from 2-bit two's complement: 00→0, 01→1, 11→-1
    ((raw << 6) as i8) >> 6
}

/// Paired NAF generator that produces signed digits {-1, 0, 1} for two scalars.
/// Reduces the density of non-zero digits compared to binary representation.
/// Digits are packed: 4 bits per (s,h) pair, 129 bytes total vs 516 unpacked.
pub struct NafIterator {
    packed: [u8; PACKED_NAF_BYTES],
    len: usize,
    index: usize,
}

impl NafIterator {
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
    fn pack_get(&self, idx: usize) -> NafDigit {
        let byte_idx = idx / 2;
        let nibble = if idx.is_multiple_of(2) {
            self.packed[byte_idx] & 0x0F
        } else {
            self.packed[byte_idx] >> 4
        };
        NafDigit {
            s_digit: decode_digit((nibble >> 2) & 0x03),
            h_digit: decode_digit(nibble & 0x03),
        }
    }

    /// Generate paired NAF representation for two scalars.
    /// Returns iterator that processes from MSB to LSB.
    pub fn new<T>(s: T, h: T) -> Self
    where
        T: num_traits::Zero
            + num_traits::One
            + Copy
            + PartialOrd
            + PartialEq
            + core::ops::ShrAssign<usize>
            + core::ops::Add<Output = T>,
        for<'a> &'a T: core::ops::BitAnd<Output = T>
            + core::ops::Add<&'a T, Output = T>
            + core::ops::Sub<&'a T, Output = T>,
    {
        let mut iter = NafIterator {
            packed: [0u8; PACKED_NAF_BYTES],
            len: 0,
            index: 0,
        };

        // Convert scalars to mutable copies for processing
        let mut s_working = s;
        let mut h_working = h;

        // Hoist loop-invariant constants
        let zero = T::zero();
        let one = T::one();
        let two = one + one;
        let three = two + one;

        // Process scalars bit by bit to generate NAF digits
        while s_working > zero || h_working > zero {
            // Extract low bits from both scalars
            let s_bit = (&s_working & &one) == one;
            let h_bit = (&h_working & &one) == one;

            // NAF recoding rules to minimize non-zero digits
            let (s_digit, s_carry) = if s_bit {
                let s_low_2bits = &s_working & &three; // & 3
                if s_low_2bits == one || s_low_2bits == two {
                    (1i8, false) // s ≡ 1 or 2 (mod 4)
                } else {
                    (-1i8, true) // s ≡ 3 (mod 4)
                }
            } else {
                (0i8, false)
            };

            let (h_digit, h_carry) = if h_bit {
                let h_low_2bits = &h_working & &three; // & 3
                if h_low_2bits == one || h_low_2bits == two {
                    (1i8, false) // h ≡ 1 or 2 (mod 4)
                } else {
                    (-1i8, true) // h ≡ 3 (mod 4)
                }
            } else {
                (0i8, false)
            };

            if iter.len < MAX_NAF_DIGITS {
                iter.pack_set(iter.len, s_digit, h_digit);
                iter.len += 1;
            }

            // Shift scalars right and handle carries
            s_working >>= 1;
            h_working >>= 1;

            if s_carry {
                s_working = s_working + one;
            }
            if h_carry {
                h_working = h_working + one;
            }
        }

        iter
    }

    /// Iterate from MSB to LSB (reverse order for scalar multiplication)
    pub fn digits_msb_first(&self) -> impl Iterator<Item = NafDigit> + '_ {
        (0..self.len).rev().map(move |i| self.pack_get(i))
    }
}

impl Iterator for NafIterator {
    type Item = NafDigit;

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
    fn test_naf_basic() {
        // Test with small values
        let s = 5u64; // Binary: 101
        let h = 3u64; // Binary: 11

        let naf = NafIterator::new(s, h);
        let digits: Vec<_> = naf.digits_msb_first().collect();

        // Should generate some NAF digits
        assert!(!digits.is_empty());

        // All digits should be in range [-1, 0, 1]
        for digit in &digits {
            assert!(digit.s_digit >= -1 && digit.s_digit <= 1);
            assert!(digit.h_digit >= -1 && digit.h_digit <= 1);
        }
    }

    #[test]
    fn test_naf_encode_decode_roundtrip() {
        for d in [-1i8, 0, 1] {
            let encoded = encode_digit(d);
            let decoded = decode_digit(encoded);
            assert_eq!(d, decoded, "roundtrip failed for {d}: encoded={encoded}");
        }
    }

    #[test]
    fn test_naf_pack_roundtrip() {
        let mut iter = NafIterator {
            packed: [0u8; PACKED_NAF_BYTES],
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
