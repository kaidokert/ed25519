//! Curve25519 primitives for embedded targets, generic over bigint backends.
//!
//! Provides two operations on top of a shared field machinery:
//!
//! - **Ed25519 signature verification** (`verify`, `VerifyingKey`) — twisted
//!   Edwards form, SHA-512 challenge, NAF double-scalar multiplication.
//! - **X25519 ECDH key exchange** (`x25519`, `x25519_base`) — Montgomery form,
//!   x-only ladder, RFC 7748.
//!
//! Both curves live in F_p where p = 2^255 - 19, so they share the same
//! `UnsignedModularInt` trait, `MontgomeryCtx`, and lazy-reduction helpers.
//!
//! # Usage
//!
//! ```ignore
//! use ed25519_heapless::{verify, x25519};
//! use fixed_bigint::FixedUInt;
//!
//! type T = FixedUInt<u32, 16>;
//! let valid  = verify::<T>(public_key, message, signature);
//! let shared = x25519::<T>(my_secret, peer_public);
//! ```
//!
//! # Features
//!
//! - `std` (default) — enables logging and timing
//! - `fixed-bigint` — enables the `fixed-bigint` backend
//! - `no_std` compatible with `--no-default-features`
//!
//! # Constant-time scope
//!
//! Ed25519 verification operates on public data only; constant-time isn't a
//! requirement there. For X25519 the secret scalar is sensitive: the ladder's
//! conditional swap is branchless, but the underlying field arithmetic
//! (`MontgomeryCtx`, `lazy_field`) has not been audited as constant-time and
//! may exhibit data-dependent timing on some backends. Suitable for embedded
//! bring-up; not yet hardened against side-channel adversaries.

#![cfg_attr(not(feature = "std"), no_std)]

pub(crate) mod curve25519_field;
// `strict` (Ed25519 verify) depends on the SHA-512 challenge hash; gate it
// behind the SHA-512 backend features so x25519-only consumers (which don't
// need any SHA-512) can build with `default-features = false` + only an
// x25519-relevant fixed-bigint feature.
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
pub(crate) mod jsf;
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
pub(crate) mod scalar_field;
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
pub(crate) mod signing_key;
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
pub(crate) mod strict;
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
pub(crate) mod strict_sign;

#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
pub use signing_key::{SignError, SigningKey, sign, sign_with_fields};
pub(crate) mod x25519;

pub use curve25519_field::{Curve25519Field, Curve25519FieldCt};
pub use modmath::{Field, FieldCt, FieldNct, Residue, ResidueCt, ResidueNct};

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
    + core::ops::Shr<usize, Output = Self>
    + core::ops::Add<Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::ShrAssign<usize>
    + modmath::MontStorage
{
    /// Deserialize from little-endian bytes. Reads up to the type's width from `bytes`.
    fn from_bytes_le(bytes: &[u8]) -> Self;
    /// Serialize to little-endian bytes. `out` must be at least as large as the type's
    /// byte width, otherwise the implementation may panic.
    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8];
}

#[cfg(feature = "fixed-bigint")]
impl<P: fixed_bigint::Personality> UnsignedModularInt for fixed_bigint::FixedUInt<u32, 16, P> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl<P: fixed_bigint::Personality> UnsignedModularInt for fixed_bigint::FixedUInt<u64, 8, P> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl<P: fixed_bigint::Personality> UnsignedModularInt for fixed_bigint::FixedUInt<u64, 4, P> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

#[cfg(feature = "fixed-bigint")]
impl<P: fixed_bigint::Personality> UnsignedModularInt for fixed_bigint::FixedUInt<u8, 32, P> {
    fn from_bytes_le(bytes: &[u8]) -> Self {
        fixed_bigint::FixedUInt::from_le_bytes(bytes)
    }

    fn to_bytes_le<'a>(&self, out: &'a mut [u8]) -> &'a [u8] {
        self.to_le_bytes(out).unwrap()
    }
}

/// Aggregate bound bundle for the constant-time sign path: CT field
/// arithmetic on Curve25519, byte (de)serialization, branchless
/// selection, and `Zeroize` for secret-intermediate wiping.
///
/// `SigningKey<T>`, `sign`, `sign_with_fields`, and every CT point /
/// scalar primitive in `strict_sign` would otherwise repeat the same
/// 13-trait `where` clause. Auto-implemented for any backend that
/// satisfies the listed bounds, so consumers don't write an explicit
/// impl. The `for<'a> &'a T: …` HRTB stays at the call site because
/// supertrait-elaboration of HRTBs is not yet reliable enough to
/// propagate it automatically.
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
pub trait SignBackend:
    UnsignedModularInt
    + Copy
    + PartialEq
    + modmath::WideMul
    + modmath::CiosMontMulCt
    + modmath::Parity
    + num_traits::WrappingMul
    + num_traits::WrappingAdd
    + num_traits::WrappingSub
    + subtle::ConditionallySelectable
    + subtle::ConstantTimeLess
    + core::ops::Sub<Output = Self>
    + zeroize::DefaultIsZeroes
{
}

#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
impl<T> SignBackend for T where
    T: UnsignedModularInt
        + Copy
        + PartialEq
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + modmath::Parity
        + num_traits::WrappingMul
        + num_traits::WrappingAdd
        + num_traits::WrappingSub
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + core::ops::Sub<Output = T>
        + zeroize::DefaultIsZeroes
{
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
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
pub use strict::{verify, verify_with_field};

/// Compute the X25519 shared secret `k * u` (RFC 7748 §5).
///
/// Both `k` and `u_in` are 32-byte little-endian encodings. The scalar `k`
/// is clamped per RFC 7748 and the high bit of `u_in[31]` is masked off
/// before the ladder runs, so callers do not need to pre-process either
/// input.
pub use x25519::{
    A24_BYTES, BASE_U_BYTES, BLINDING_MODULUS_BYTES, clamp, x25519, x25519_base,
    x25519_base_blinded, x25519_blinded,
};

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

impl<T> Copy for VerifyingKey<T> {}

impl<T> Clone for VerifyingKey<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> PartialEq for VerifyingKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

impl<T> Eq for VerifyingKey<T> {}

impl<T> core::fmt::Debug for VerifyingKey<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("public", &self.public)
            .finish()
    }
}

#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
fn parse_signature(signature: &[u8]) -> Result<[u8; 64], signature::Error> {
    signature.try_into().map_err(|_| signature::Error::new())
}

#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
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
        + core::ops::Add<&'a T, Output = T>
        + core::ops::Sub<T, Output = T>
        + core::ops::Sub<&'a T, Output = T>,
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

#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
impl<T> signature::Signer<[u8; 64]> for SigningKey<T>
where
    T: SignBackend,
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<[u8; 64], signature::Error> {
        sign::<T>(self, msg).map_err(|_| signature::Error::new())
    }
}
