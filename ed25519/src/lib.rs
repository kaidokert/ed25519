//! Ed25519 signature verification, generic over bigint backends.
//!
//! This crate provides Ed25519 signature verification using trait-generic
//! arithmetic, allowing the same verify code to work with different bigint
//! backends (e.g., `fixed-bigint` with various word sizes).
//!
//! # Usage
//!
//! ```ignore
//! use ed25519_heapless::verify;
//! use fixed_bigint::FixedUInt;
//!
//! type T = FixedUInt<u32, 16>;
//! let valid = verify::<T>(public_key, message, signature);
//! ```
//!
//! # Features
//!
//! - `std` (default) — enables logging and timing
//! - `fixed-bigint` — enables the `fixed-bigint` backend
//! - `no_std` compatible with `--no-default-features`

#![cfg_attr(not(feature = "std"), no_std)]

pub(crate) mod jsf;
pub(crate) mod lazy_field;
pub(crate) mod montgomery_ctx;
pub(crate) mod strict;

use core::marker::PhantomData;

/// Trait for unsigned integer types supporting modular arithmetic and byte serialization.
///
/// This is the main generic constraint for Ed25519 verification.
/// Any type implementing these bounds can serve as a bigint backend.
pub trait UnsignedModularInt:
    Sized
    + Clone
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
    /// Deserialize from little-endian bytes. Reads up to the type's width from `bytes`.
    fn from_bytes_le(bytes: &[u8]) -> Self;
    /// Serialize to little-endian bytes. `out` must be at least as large as the type's
    /// byte width, otherwise the implementation may panic.
    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8];
}

/// Extended twisted Edwards point: (X, Y, Z, T) coordinates.
pub type Point<T> = (T, T, T, T);

#[cfg(feature = "fixed-bigint")]
impl UnsignedModularInt for fixed_bigint::FixedUInt<u32, 16> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl UnsignedModularInt for fixed_bigint::FixedUInt<u64, 8> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl UnsignedModularInt for fixed_bigint::FixedUInt<u64, 4> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl UnsignedModularInt for fixed_bigint::FixedUInt<u8, 32> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
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
// Value: 2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0 (hex, big-endian)
pub const MODP_SQRT_M1_BYTES: [u8; 32] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// Verify an Ed25519 signature.
///
/// Returns `true` if the signature is valid for the given public key and message.
///
/// # Arguments
/// - `public` — 32-byte Ed25519 public key
/// - `msg` — message bytes (arbitrary length)
/// - `signature` — 64-byte Ed25519 signature
pub use strict::verify;

/// Verifying key wrapper that implements `signature` crate traits.
pub struct VerifyingKey<T> {
    public: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T> VerifyingKey<T> {
    /// Construct a verifying key from raw Ed25519 public key bytes.
    pub const fn from_bytes(public: [u8; 32]) -> Self {
        Self {
            public,
            _marker: PhantomData,
        }
    }

    /// Return the wrapped public key bytes.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.public
    }
}

impl<T> From<[u8; 32]> for VerifyingKey<T> {
    fn from(public: [u8; 32]) -> Self {
        Self::from_bytes(public)
    }
}

fn parse_signature(signature: &[u8]) -> Result<[u8; 64], signature::Error> {
    signature.try_into().map_err(|_| signature::Error::new())
}

impl<T, S> signature::Verifier<S> for VerifyingKey<T>
where
    S: AsRef<[u8]>,
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    fn verify(&self, msg: &[u8], signature: &S) -> Result<(), signature::Error> {
        let signature = parse_signature(signature.as_ref())?;
        if verify::<T>(self.public, msg, signature) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

impl<T, D, S> signature::DigestVerifier<D, S> for VerifyingKey<T>
where
    D: signature::digest::Digest,
    S: AsRef<[u8]>,
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMul
        + num_traits::ops::overflowing::OverflowingAdd
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + core::ops::Rem<&'a T, Output = T>
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>
        + core::ops::Mul<&'a T, Output = T>
        + core::ops::Div<&'a T, Output = T>,
{
    fn verify_digest(&self, digest: D, signature: &S) -> Result<(), signature::Error> {
        let prehashed_msg = digest.finalize();
        let signature = parse_signature(signature.as_ref())?;
        if verify::<T>(self.public, prehashed_msg.as_ref(), signature) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}
