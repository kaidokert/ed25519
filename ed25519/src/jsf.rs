// Paired NAF (Non-Adjacent Form) recoding for double-scalar multiplication.
// Each scalar is independently recoded into signed digits {-1, 0, 1} using NAF,
// then the two digit streams are paired for simultaneous processing.
// No lookup tables - perfect for code-size constrained environments.
//
// TODO: implement true Joint Sparse Form (JSF / Solinas) which makes joint
// decisions when both scalars are odd, guaranteeing at most one non-zero digit
// per position. This would reduce point additions by ~33% vs paired NAF.

/// Signed NAF digit. `encode_digit` only ever emits `0b00`, `0b01`, or
/// `0b11`; the `0b10` bit pattern is unused. Consumers can match
/// exhaustively on the enum and skip the runtime `_ => unreachable!()`
/// arm the old `i8` shape required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NafSign {
    Zero = 0b00,
    Pos = 0b01,
    Neg = 0b11,
}

/// NAF digit pair: one [`NafSign`] for each of two scalars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NafDigit {
    pub s_digit: NafSign,
    pub h_digit: NafSign,
}

// Max NAF digits: Ed25519 scalars are ~255 bits, carry can add 1
const MAX_NAF_DIGITS: usize = 258;

// Packed storage: 2 bits per digit value, 4 bits per (s,h) pair, 2 pairs per byte.
// Zero-init gives all-zeros = all digit Zero.
const PACKED_NAF_BYTES: usize = MAX_NAF_DIGITS.div_ceil(2); // 129

/// Encode a [`NafSign`] into 2 bits matching its `repr(u8)`.
const fn encode_digit(d: NafSign) -> u8 {
    d as u8
}

/// Decode 2 bits back to a [`NafSign`]. The `0b10` bit pattern is never
/// written by [`encode_digit`]; if it ever shows up here (storage
/// corruption) we treat it as `Zero`. That's a wrong-answer mode for
/// the verifier (a valid signature could be rejected) but it's
/// panic-free and doesn't introduce UB.
const fn decode_digit(raw: u8) -> NafSign {
    match raw & 0b11 {
        0b00 => NafSign::Zero,
        0b01 => NafSign::Pos,
        0b10 => NafSign::Zero,
        0b11 => NafSign::Neg,
        _ => NafSign::Zero,
    }
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
    fn pack_set(&mut self, idx: usize, s_digit: NafSign, h_digit: NafSign) {
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
            // s is odd → s & 3 is 1 or 3; use +1 for ≡1, use -1 (with carry) for ≡3
            let (s_digit, s_carry) = if s_bit {
                if (&s_working & &three) == one {
                    (NafSign::Pos, false)
                } else {
                    (NafSign::Neg, true)
                }
            } else {
                (NafSign::Zero, false)
            };

            // h is odd → h & 3 is 1 or 3; same logic
            let (h_digit, h_carry) = if h_bit {
                if (&h_working & &three) == one {
                    (NafSign::Pos, false)
                } else {
                    (NafSign::Neg, true)
                }
            } else {
                (NafSign::Zero, false)
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
        // s = 5 = 0b101, h = 3 = 0b011. NAF recoding produces, from
        // MSB to LSB: (Pos, Pos), (Zero, Zero), (Pos, Neg).
        let s = 5u64;
        let h = 3u64;

        let naf = NafIterator::new(s, h);
        let digits: Vec<_> = naf.digits_msb_first().collect();

        assert_eq!(
            digits,
            vec![
                NafDigit {
                    s_digit: NafSign::Pos,
                    h_digit: NafSign::Pos
                },
                NafDigit {
                    s_digit: NafSign::Zero,
                    h_digit: NafSign::Zero
                },
                NafDigit {
                    s_digit: NafSign::Pos,
                    h_digit: NafSign::Neg
                },
            ]
        );
    }

    #[test]
    fn test_naf_encode_decode_roundtrip() {
        for d in [NafSign::Neg, NafSign::Zero, NafSign::Pos] {
            let encoded = encode_digit(d);
            let decoded = decode_digit(encoded);
            assert_eq!(d, decoded, "roundtrip failed for {d:?}: encoded={encoded}");
        }
    }

    #[test]
    fn test_naf_pack_roundtrip() {
        let mut iter = NafIterator {
            packed: [0u8; PACKED_NAF_BYTES],
            len: 0,
            index: 0,
        };
        let vals = [NafSign::Neg, NafSign::Zero, NafSign::Pos];
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

    #[test]
    fn test_decode_corrupted_0b10_is_zero() {
        // encode_digit never emits 0b10. If storage corruption produces
        // it, decode_digit must return Zero — not panic, not UB.
        assert_eq!(decode_digit(0b10), NafSign::Zero);
    }
}
