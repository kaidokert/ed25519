//! Curve25519 primitives for embedded targets, generic over bigint backends.
//!
//! Provides two operations on top of a shared field machinery, exposed through
//! standard RustCrypto traits:
//!
//! - **Ed25519 signing / verification** — [`SigningKey`] via `signature::Signer`
//!   (deterministic) and `RandomizedSigner` (hedged + blinded); [`VerifyingKey`]
//!   via `signature::Verifier`. Twisted Edwards form, SHA-512 challenge, NAF
//!   double-scalar multiplication.
//! - **X25519 key agreement** — the KEM [`x25519_kem::X25519Kem`] (`kem::Kem`),
//!   with an [`Unblinded`](x25519_kem::Unblinded) default and a
//!   [`Blinded`](x25519_kem::Blinded) personality. Montgomery x-only ladder,
//!   RFC 7748.
//!
//! Raw scalar-mult primitives (`x25519`, `x25519_blinded`, …) and the
//! amortized-field `sign`/`verify` live in [`hazmat`] — reach there only for
//! static-static DH or custom protocols. There is no top-level free-function API.
//!
//! Both curves live in F_p where p = 2^255 - 19, so they share the same
//! `UnsignedModularInt` trait, `MontgomeryCtx`, and lazy-reduction helpers.
//!
//! # Usage
//!
//! ```ignore
//! use ed25519_heapless::VerifyingKey;
//! use signature::Verifier;
//! use fixed_bigint::FixedUInt;
//!
//! type T = FixedUInt<u32, 16>;
//! let valid = VerifyingKey::<T>::from_bytes(public_key)
//!     .verify(message, &signature)
//!     .is_ok();
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
pub use signing_key::{SignError, SigningKey};
// `sign` stays crate-internal (backs the `Signer` impl); `sign_with_fields` moves
// to `hazmat`. The top-level free `sign` is gone — use the `Signer` trait.
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
use signing_key::sign;
pub(crate) mod x25519;
pub mod x25519_kem;

pub use curve25519_field::{
    Curve25519Field, Curve25519FieldCt, CurveSetupError, VerifyField, curve25519_schoolbook,
};
pub use modmath::{Field, FieldCt, FieldNct, Residue, ResidueCt, ResidueNct};

use core::marker::PhantomData;

/// Bound bundle for the generic bigint backend Ed25519 verify + X25519
/// build on. Pure marker trait: no methods, just a named alias for the
/// supertrait union. Byte (de)serialization goes through
/// [`const_num_traits::FromByteSlice`] (fallible slice-in) and
/// [`const_num_traits::ToBytes`] (owned bytes with `AsRef<[u8]>`),
/// which any conforming backend implements without ed25519 knowing the
/// backend type.
pub trait UnsignedModularInt:
    Sized
    + Clone
    + core::cmp::PartialOrd
    + const_num_traits::One
    + const_num_traits::Zero
    + const_num_traits::BitsPrecision
    + const_num_traits::WithPrecision
    + const_num_traits::ops::overflowing::OverflowingAdd<Output = Self>
    + const_num_traits::WrappingAdd<Output = Self>
    + const_num_traits::WrappingSub<Output = Self>
    + const_num_traits::WrappingMul<Output = Self>
    + core::ops::Shr<usize, Output = Self>
    + core::ops::BitAnd<Output = Self>
    + core::ops::ShrAssign<usize>
    + modmath::MontStorage
    + modmath::Parity
    + const_num_traits::FromByteSlice
    + const_num_traits::ToBytes
{
}

impl<T> UnsignedModularInt for T where
    T: Sized
        + Clone
        + core::cmp::PartialOrd
        + const_num_traits::One
        + const_num_traits::Zero
        + const_num_traits::BitsPrecision
        + const_num_traits::WithPrecision
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = Self>
        + const_num_traits::WrappingAdd<Output = Self>
        + const_num_traits::WrappingSub<Output = Self>
        + const_num_traits::WrappingMul<Output = Self>
        + core::ops::Shr<usize, Output = Self>
        + core::ops::BitAnd<Output = Self>
        + core::ops::ShrAssign<usize>
        + modmath::MontStorage
        + modmath::Parity
        + const_num_traits::FromByteSlice
        + const_num_traits::ToBytes
{
}

/// Carrier bound bundle for the **verify** path. Verify is variable-time on
/// public data, so — unlike [`SignBackend`] — it needs neither `Copy` nor
/// `subtle`: a `Clone` heap carrier (e.g. num-bigint) satisfies it. This is the
/// `Clone` / consume-self / by-reference subset of [`UnsignedModularInt`] that
/// verify's own code exercises, minus the Montgomery-only ops (those live on
/// the field's `VerifyField` impl, not here). Any `UnsignedModularInt` carrier
/// also satisfies it, so the fixed-width `Copy` verify path is unaffected.
pub trait VerifyBackend:
    Clone
    + PartialOrd
    + const_num_traits::One
    + const_num_traits::Zero
    + const_num_traits::BitsPrecision
    + const_num_traits::WithPrecision
    + const_num_traits::ops::overflowing::OverflowingAdd<Output = Self>
    + const_num_traits::WrappingAdd<Output = Self>
    + const_num_traits::WrappingSub<Output = Self>
    + core::ops::Shr<usize, Output = Self>
    + core::ops::ShrAssign<usize>
    + modmath::Parity
    + const_num_traits::FromByteSlice
{
}

impl<T> VerifyBackend for T where
    T: Clone
        + PartialOrd
        + const_num_traits::One
        + const_num_traits::Zero
        + const_num_traits::BitsPrecision
        + const_num_traits::WithPrecision
        + const_num_traits::ops::overflowing::OverflowingAdd<Output = Self>
        + const_num_traits::WrappingAdd<Output = Self>
        + const_num_traits::WrappingSub<Output = Self>
        + core::ops::Shr<usize, Output = Self>
        + core::ops::ShrAssign<usize>
        + modmath::Parity
        + const_num_traits::FromByteSlice
{
}

/// Load a static crypto-constant byte sequence into `T`.
///
/// Wraps `FromByteSlice::from_le_slice`. The `curve25519()` factories reject a
/// narrow backend before any constant load, so with `BYTE_WIDTH >= 32` the `Err`
/// branch is structurally unreachable. The fail-closed `T::zero()` fallback keeps
/// `panic_fmt` unlinked; a `T = 0` from a genuinely invalid backend selection
/// fails the verify / sign consistency checks downstream rather than panicking.
#[inline]
pub(crate) fn from_le_bytes<T>(bytes: &[u8]) -> T
where
    T: const_num_traits::FromByteSlice + const_num_traits::Zero,
{
    <T as const_num_traits::FromByteSlice>::from_le_slice(bytes).unwrap_or_else(|_| T::zero())
}

/// Read `x`'s little-endian byte encoding through a `&T` receiver — no
/// unwrapped `T` value materializes on the stack. Wraps the returned
/// `Bytes` in `Zeroizing` for defense-in-depth.
///
/// The awkward incantation this hides — `<&T as ToBytes>::to_le_bytes(x)` —
/// exists because `x.to_le_bytes()` and `(*x).to_le_bytes()` both auto-deref
/// and dispatch to the owned impl, copying `T` off the `Zeroizing<T>` stack
/// slot before consuming it — the exact leak the `&T` impl prevents.
#[inline]
pub(crate) fn to_le_bytes_ct<T>(
    x: &T,
) -> zeroize::Zeroizing<<T as const_num_traits::ToBytes>::Bytes>
where
    T: const_num_traits::ToBytes,
    for<'a> &'a T: const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    zeroize::Zeroizing::new(<&T as const_num_traits::ToBytes>::to_le_bytes(x))
}

/// Additive scalar blinding: `out = scalar + blinder·modulus`, little-endian and
/// unreduced. When `modulus` annihilates the target group (`modulus·G = 𝒪`),
/// `out·G = scalar·G`, but `out` — wider and varying with `blinder` per call —
/// makes a fixed-base ladder process a different bit pattern each execution,
/// defeating DPA trace averaging on the secret scalar.
///
/// 32-bit-limb schoolbook via [`const_num_traits::CarryingMul`], which widens
/// through `u64` (no software 128-bit math on AVR / Cortex-M0). The scalar add
/// is folded into the multiply-accumulate: `blinder·m + carry + s ≤ (2³²−1)² +
/// 2·(2³²−1) < 2⁶⁴`, so `(lo, hi)` are one limb each and `hi` is the running
/// carry. Word-aligned: `modulus` is a whole number of `u32` limbs and `N` a
/// multiple of 4 holding `scalar + blinder·modulus` (one limb past it).
///
/// Shared by the x25519 (`8·ℓ·ℓ'`) and Ed25519-sign (`ℓ`) blinded paths.
pub(crate) fn blind_scalar<const N: usize>(
    scalar: &[u8; 32],
    blinder: u32,
    modulus: &[u8],
) -> zeroize::Zeroizing<[u8; N]> {
    // Fail-closed limb read; the chunk is always 4 bytes (`chunks_exact`).
    fn read_le_u32(c: &[u8]) -> u32 {
        <[u8; 4]>::try_from(c).map(u32::from_le_bytes).unwrap_or(0)
    }
    debug_assert_eq!(N % 4, 0);
    debug_assert_eq!(modulus.len() % 4, 0);

    let mut out = zeroize::Zeroizing::new([0u8; N]);
    let mut mod_limbs = modulus.chunks_exact(4);
    let mut scalar_limbs = scalar.chunks_exact(4);
    let mut carry: u32 = 0;
    for out_limb in out.chunks_exact_mut(4) {
        let m = mod_limbs.next().map(read_le_u32).unwrap_or(0);
        let s = scalar_limbs.next().map(read_le_u32).unwrap_or(0);
        let (lo, hi) = const_num_traits::CarryingMul::carrying_mul_add(blinder, m, carry, s);
        out_limb.copy_from_slice(&lo.to_le_bytes());
        carry = hi;
    }
    debug_assert_eq!(carry, 0);

    out
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
    + modmath::WideMul
    + modmath::CiosMontMulCt
    + const_num_traits::CtIsZero
    + subtle::ConditionallySelectable
    + subtle::ConstantTimeLess
    + zeroize::DefaultIsZeroes
{
}

#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
impl<T> SignBackend for T where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + zeroize::DefaultIsZeroes
{
}

// ED25519 constants. Hex text is big-endian (matches every reference —
// RFC 8032, dalek, `python -c 'print(hex(p))'` — so bytes can be
// checked by eye); `hx_le` reverses to the little-endian byte order
// the rest of the crate uses. Compile-time only: bad hex or wrong
// length is a build error, and rodata is identical to a hand-written
// LE array.
pub(crate) const fn hx_le<const N: usize>(s: &str) -> [u8; N] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit in curve constant"),
        }
    }
    let s = s.as_bytes();
    assert!(s.len() == 2 * N, "hex length must be 2*N chars");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        // byte j of the big-endian text lands at index N-1-j in the LE array.
        out[N - 1 - i] = (nib(s[2 * i]) << 4) | nib(s[2 * i + 1]);
        i += 1;
    }
    out
}

// p = 2^255 - 19 (field prime).
pub const P_BYTES: [u8; 32] =
    hx_le("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
// d = -121665/121666 mod p (twist coefficient of the edwards form).
pub const D_BYTES: [u8; 32] =
    hx_le("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
// q = 2^252 + 27742317777372353535851937790883648493 (scalar order).
pub const Q_BYTES: [u8; 32] =
    hx_le("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

// Base point B = (Gx, Gy) with Gy = 4/5 mod p, plus Gt = Gx·Gy for
// the extended-twisted-edwards coordinate that carries the precomputed
// product.
pub const G_X_BYTES: [u8; 32] =
    hx_le("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a");
pub const G_Y_BYTES: [u8; 32] =
    hx_le("6666666666666666666666666666666666666666666666666666666666666658");
pub const G_T_BYTES: [u8; 32] =
    hx_le("67875f0fd78b766566ea4e8e64abe37d20f09f80775152f56dde8ab3a5b7dda3");

// modp_sqrt_m1 = 2^((p-1)/4) mod p = sqrt(-1) mod p, used in point decompression.
pub const MODP_SQRT_M1_BYTES: [u8; 32] =
    hx_le("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0");

// `verify` stays crate-internal (backs the `Verifier` impl below); the top-level
// free `verify` is gone — use the `Verifier` trait. `verify_with_field` moves to
// `hazmat`.
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
use strict::verify;

/// X25519 constants (RFC 7748). The scalar-mult primitives live in [`hazmat`].
pub use x25519::{A24_BYTES, BASE_U_BYTES, BLINDING_MODULUS_BYTES};

/// Low-level primitives with no safe trait wrapper — the RustCrypto `hazmat`
/// convention (cf. `signature::hazmat`). Prefer the KEM ([`x25519_kem`]) and the
/// `signature` traits; reach here only for the raw scalar-mult (static-static DH,
/// custom protocols) or the amortized-field sign/verify.
pub mod hazmat {
    pub use crate::x25519::{clamp, x25519, x25519_base, x25519_base_blinded, x25519_blinded};

    #[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
    pub use crate::signing_key::sign_with_fields;
    #[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
    pub use crate::strict::verify_with_field;
}

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
    T: UnsignedModularInt + Copy + modmath::WideMul + modmath::CiosMontMul + modmath::NonCt,
    for<'a> &'a T: core::ops::BitAnd<Output = T>
        + const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>,
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
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    fn try_sign(&self, msg: &[u8]) -> Result<[u8; 64], signature::Error> {
        sign::<T>(self, msg).map_err(|_| signature::Error::new())
    }
}

/// Hedged, side-channel-blinded Ed25519 signing. Produces a standard RFC 8032
/// signature (any verifier accepts it), but the nonce is hedged with RNG output
/// so the output is non-deterministic, and the `r·G` scalar multiply is scalar-
/// and coordinate-blinded. The blinding is best-effort against physical power/EM
/// analysis and is not validated by leakage-measurement hardware. For plain
/// deterministic RFC 8032 signing, use the [`signature::Signer`] impl.
#[cfg(any(feature = "sha512-hmac-sha512", feature = "sha512-sha2"))]
impl<T> signature::RandomizedSigner<[u8; 64]> for SigningKey<T>
where
    T: SignBackend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    fn try_sign_with_rng<R: rand_core::TryCryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<[u8; 64], signature::Error> {
        signing_key::sign_blinded::<T, R>(rng, self, msg).map_err(|_| signature::Error::new())
    }
}
