pub mod strict;
pub mod constrained;

// Common traits and types

// Trait for strict modmath operations (requires OverflowingAdd/OverflowingSub)
pub trait CoreIntStrict:
    Sized
    + core::cmp::PartialOrd
    + num_traits::One
    + num_traits::Zero
    + num_traits::ops::overflowing::OverflowingAdd
    + num_traits::ops::overflowing::OverflowingSub
    + core::ops::Shr<usize, Output = Self>
    + core::ops::Shl<usize, Output = Self>
    + core::ops::Add<Output = Self>
    + core::ops::Sub<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::ShrAssign<usize>
    + for<'a> core::ops::RemAssign<&'a Self>
    + for<'a> core::ops::DivAssign<&'a Self>
    + for<'a> core::ops::Rem<&'a Self, Output = Self>
    + for<'a> core::ops::Div<&'a Self, Output = Self>
    + for<'a> core::ops::Mul<&'a Self, Output = Self>
    + for<'a> core::ops::Add<&'a Self, Output = Self>
    + for<'a> core::ops::Sub<&'a Self, Output = Self>
    + for<'a> core::ops::AddAssign<&'a Self>
{
}

impl<T> CoreIntStrict for T
where
    T: Sized
        + core::cmp::PartialOrd
        + num_traits::One
        + num_traits::Zero
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::ops::overflowing::OverflowingSub
        + core::ops::Shr<usize, Output = T>
        + core::ops::Shl<usize, Output = T>
        + core::ops::Add<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::BitAnd<Output = T>
        + core::ops::ShrAssign<usize>
        + for<'a> core::ops::RemAssign<&'a T>
        + for<'a> core::ops::DivAssign<&'a T>
        + for<'a> core::ops::Rem<&'a T, Output = T>
        + for<'a> core::ops::Div<&'a T, Output = T>
        + for<'a> core::ops::Mul<&'a T, Output = T>
        + for<'a> core::ops::Add<&'a T, Output = T>
        + for<'a> core::ops::Sub<&'a T, Output = T>
        + for<'a> core::ops::AddAssign<&'a T>,
{
}

// Trait for constrained modmath operations (requires WrappingAdd/WrappingSub)
pub trait CoreIntConstrained:
    Sized
    + Clone
    + core::cmp::PartialOrd
    + num_traits::One
    + num_traits::Zero
    + num_traits::ops::wrapping::WrappingAdd
    + num_traits::ops::wrapping::WrappingSub
    + core::ops::Shr<usize, Output = Self>
    + core::ops::Shl<usize, Output = Self>
    + core::ops::Add<Output = Self>
    + core::ops::Sub<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::ShrAssign<usize>
    + for<'a> core::ops::Rem<&'a Self, Output = Self>
    + for<'a> core::ops::Div<&'a Self, Output = Self>
    + for<'a> core::ops::RemAssign<&'a Self>
    + for<'a> core::ops::DivAssign<&'a Self>
    + for<'a> core::ops::Add<&'a Self, Output = Self>
    + for<'a> core::ops::Sub<&'a Self, Output = Self>
    + for<'a> core::ops::Mul<&'a Self, Output = Self>
{
}

impl<T> CoreIntConstrained for T
where
    T: Sized
        + Clone
        + core::cmp::PartialOrd
        + num_traits::One
        + num_traits::Zero
        + num_traits::ops::wrapping::WrappingAdd
        + num_traits::ops::wrapping::WrappingSub
        + core::ops::Shr<usize, Output = T>
        + core::ops::Shl<usize, Output = T>
        + core::ops::Add<Output = T>
        + core::ops::Sub<Output = T>
        + core::ops::BitAnd<Output = T>
        + core::ops::ShrAssign<usize>
        + for<'a> core::ops::Rem<&'a T, Output = T>
        + for<'a> core::ops::Div<&'a T, Output = T>
        + for<'a> core::ops::RemAssign<&'a T>
        + for<'a> core::ops::DivAssign<&'a T>
        + for<'a> core::ops::Add<&'a T, Output = T>
        + for<'a> core::ops::Sub<&'a T, Output = T>
        + for<'a> core::ops::Mul<&'a T, Output = T>,
{
}

pub type Point<T> = (T, T, T, T);

// BrigInt trait for strict mode (used with CoreIntStrict)
pub trait BrigIntStrict: CoreIntStrict + Clone {
    fn from_bytes_le(bytes: &[u8]) -> Self;
    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8];
}

// BrigInt trait for constrained mode (used with CoreIntConstrained)  
pub trait BrigIntConstrained: CoreIntConstrained + Clone {
    fn from_bytes_le(bytes: &[u8]) -> Self;
    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8];
}

// Keep old names for backwards compatibility - but as trait aliases
pub use CoreIntStrict as CoreInt;
pub use BrigIntStrict as BrigInt;

#[cfg(feature = "fixed-bigint")]
impl BrigIntStrict for fixed_bigint::FixedUInt<u32, 16> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl BrigIntConstrained for fixed_bigint::FixedUInt<u32, 16> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl BrigIntStrict for fixed_bigint::FixedUInt<u64, 8> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl BrigIntConstrained for fixed_bigint::FixedUInt<u64, 8> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "bnum")]
impl BrigIntConstrained for bnum::types::U512 {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        // Use simple implementation: assume 32 bytes and create directly
        let mut result = bnum::types::U512::ZERO;
        for (i, &byte) in bytes.iter().enumerate() {
            if i < 64 {  // U512 is 64 bytes, but only use first 32 for ed25519
                result |= bnum::types::U512::from(byte as u64) << (i * 8);
            }
        }
        result
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        // Simple implementation: extract bytes using conversion
        let mut temp = *self;
        for i in 0..core::cmp::min(64, out.len()) {
            let byte_val = temp & bnum::types::U512::from(0xff_u64);
            // Convert BUint to primitive by checking if it equals known values
            let mut byte = 0u8;
            for val in 0..=255u8 {
                if byte_val == bnum::types::U512::from(val as u64) {
                    byte = val;
                    break;
                }
            }
            out[i] = byte;
            temp = temp >> 8;
        }
        &out[..core::cmp::min(64, out.len())]
    }
}

// ED25519 constants
pub const P_BYTES: [u8; 32] = [
    237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
];
pub const D_BYTES: [u8; 32] = [
    163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0, 152, 232, 121, 119, 121,
    64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82,
];
pub const Q_BYTES: [u8; 32] = [
    237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 16,
];

pub const G_X_BYTES: [u8; 32] = [
    26, 213, 37, 143, 96, 45, 86, 201, 178, 167, 37, 149, 96, 199, 44, 105, 92, 220, 214, 253, 49,
    226, 164, 192, 254, 83, 110, 205, 211, 54, 105, 33,
];
pub const G_Y_BYTES: [u8; 32] = [
    88, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
    102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102, 102,
];
pub const G_T_BYTES: [u8; 32] = [
    163, 221, 183, 165, 179, 138, 222, 109, 245, 82, 81, 119, 128, 159, 240, 32, 125, 227, 171,
    100, 142, 78, 234, 102, 101, 118, 139, 215, 15, 95, 135, 103,
];

// Precomputed modp_sqrt_m1 = 2^((p-1)/4) mod p for Ed25519  
// This is sqrt(-1) mod p used in point decompression
// Value: b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b (hex, big-endian)
pub const MODP_SQRT_M1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

// Re-export both implementations
pub use strict::verify as verify_strict;
pub use constrained::verify as verify_constrained;

// Default to strict implementation for backwards compatibility
pub use verify_strict as verify;