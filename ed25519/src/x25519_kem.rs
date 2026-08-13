//! X25519 as a key-encapsulation mechanism ([`kem::Kem`]).
//!
//! DH-KEM shape: an [`EncapsulationKey`] holds a peer's X25519 public
//! u-coordinate. Encapsulation picks an ephemeral scalar `e`, returns `e·G` as
//! the ciphertext and `e·pk` as the shared key; decapsulation with secret `sk`
//! recovers `sk·(e·G) = e·pk`.
//!
//! Encapsulation is blinded — [`x25519_base_blinded`] yields the ciphertext and
//! [`x25519_blinded`] the shared key, both driven by the caller's `CryptoRng`, so
//! the ephemeral scalar and the ladder blinding draw on one RNG. Decapsulation
//! is the RNG-free [`TryDecapsulate`] path over the unblinded [`x25519`] ladder:
//! the trait carries no per-call RNG, so a blinded raw DH stays the inherent
//! [`x25519_blinded`] function.
//!
//! `T` must be wide enough to hold the 256-bit prime — a runtime property of
//! the carrier, so there is no const guard. Decode ([`TryKeyInit`]) and
//! decapsulation propagate [`CurveSetupError`] on a too-narrow `T`; the
//! infallible key-generation and encapsulation paths, whose trait signatures
//! can't return it, `debug_assert` the width and fail closed to a zeroed output
//! in release. A ≥256-bit `T` reaches none of these paths.
//!
//! Low-order inputs are refused: a decoded encapsulation key or a decapsulated
//! ciphertext whose shared secret is the all-zero (publicly known) value is
//! rejected (RFC 7748 §6.1).

use core::fmt;
use core::marker::PhantomData;

use kem::common::array::Array;
use kem::consts::U32;
use kem::{
    Ciphertext, Decapsulator, Encapsulate, Generate, InvalidKey, Kem, Key, KeyExport, KeyInit,
    KeySizeUser, SharedKey, TryDecapsulate, TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::UnsignedModularInt;
use crate::curve25519_field::CurveSetupError;
use crate::x25519::{x25519, x25519_base, x25519_base_blinded, x25519_blinded};

/// Fixed, non-secret scalar used to validate a decoded encapsulation key. Any
/// clamped scalar is a multiple of 8, which annihilates every order-≤8 point, so
/// `x25519(this, pk)` is all-zero exactly when `pk` is low-order.
const KEY_VALIDATION_SCALAR: [u8; 32] = [0x0a; 32];

/// Decapsulation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecapsulateError {
    /// The backend `T` is too narrow to hold the 256-bit field.
    BackendTooNarrow,
    /// The ciphertext is a low-order point: the shared secret is the all-zero
    /// value, which is publicly known, so the ciphertext is rejected.
    LowOrderPoint,
}

impl From<CurveSetupError> for DecapsulateError {
    fn from(_: CurveSetupError) -> Self {
        Self::BackendTooNarrow
    }
}

impl fmt::Display for DecapsulateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BackendTooNarrow => "backend too narrow for the 256-bit field",
            Self::LowOrderPoint => "low-order ciphertext (all-zero shared secret)",
        })
    }
}

impl core::error::Error for DecapsulateError {}

/// Backend bound for the X25519 KEM: the ladder bounds [`x25519_blinded`] needs,
/// minus the higher-ranked `&T` clause. Rust does not propagate a `for<'a> &'a T`
/// where-bound through a trait alias, so every impl below still spells that clause
/// out; this alias captures the rest. `PartialEq` comes via `PartialOrd`.
pub trait X25519Backend:
    UnsignedModularInt
    + Copy
    + modmath::WideMul
    + modmath::CiosMontMulCt
    + const_num_traits::CtIsZero
    + subtle::ConditionallySelectable
    + subtle::ConstantTimeLess
    + 'static
{
}

impl<T> X25519Backend for T where
    T: UnsignedModularInt
        + Copy
        + modmath::WideMul
        + modmath::CiosMontMulCt
        + const_num_traits::CtIsZero
        + subtle::ConditionallySelectable
        + subtle::ConstantTimeLess
        + 'static
{
}

/// Public u-coordinate from a secret scalar, for the infallible key-construction
/// paths. `T` must be ≥256 bits wide; the [`kem`] construction traits can't
/// surface that runtime requirement as an error, so a too-narrow backend is a
/// debug-asserted misconfiguration and fails closed to zero in release.
fn derive_public<T>(sk: &[u8; 32]) -> [u8; 32]
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    x25519_base::<T>(sk).unwrap_or_else(|_| {
        debug_assert!(false, "X25519 KEM backend must be ≥256 bits wide");
        [0u8; 32]
    })
}

/// KEM marker for X25519 over backend `T`. Zero-sized; `PhantomData<fn() -> T>`
/// keeps its auto-traits independent of `T`.
pub struct X25519Kem<T>(PhantomData<fn() -> T>);

impl<T> Clone for X25519Kem<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for X25519Kem<T> {}
impl<T> fmt::Debug for X25519Kem<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519Kem")
    }
}
impl<T> Default for X25519Kem<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}
impl<T> PartialEq for X25519Kem<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl<T> Eq for X25519Kem<T> {}
impl<T> PartialOrd for X25519Kem<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for X25519Kem<T> {
    fn cmp(&self, _: &Self) -> core::cmp::Ordering {
        core::cmp::Ordering::Equal
    }
}

/// X25519 public key (peer u-coordinate) — the encapsulation key.
pub struct EncapsulationKey<T> {
    pk: [u8; 32],
    _t: PhantomData<fn() -> T>,
}

impl<T> Clone for EncapsulationKey<T> {
    fn clone(&self) -> Self {
        Self {
            pk: self.pk,
            _t: PhantomData,
        }
    }
}
impl<T> fmt::Debug for EncapsulationKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncapsulationKey").finish_non_exhaustive()
    }
}
impl<T> PartialEq for EncapsulationKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
}
impl<T> Eq for EncapsulationKey<T> {}

/// X25519 secret key with its public — the decapsulation key. `sk` is wiped on
/// drop via [`Zeroizing`].
pub struct DecapsulationKey<T> {
    sk: Zeroizing<[u8; 32]>,
    ek: EncapsulationKey<T>,
}

impl<T> fmt::Debug for DecapsulationKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecapsulationKey").finish_non_exhaustive()
    }
}

impl<T> Kem for X25519Kem<T>
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    type DecapsulationKey = DecapsulationKey<T>;
    type EncapsulationKey = EncapsulationKey<T>;
    type SharedKeySize = U32;
    type CiphertextSize = U32;
}

impl<T> KeySizeUser for EncapsulationKey<T> {
    type KeySize = U32;
}

impl<T> KeySizeUser for DecapsulationKey<T> {
    type KeySize = U32;
}

impl<T> KeyInit for DecapsulationKey<T>
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    /// Load a decapsulation key from a stored 32-byte X25519 secret; the public
    /// is re-derived. Also drives [`kem::FromSeed`] (the secret is the seed).
    fn new(key: &Key<Self>) -> Self {
        let sk = Zeroizing::new((*key).into());
        let pk = derive_public::<T>(&sk);
        Self {
            sk,
            ek: EncapsulationKey {
                pk,
                _t: PhantomData,
            },
        }
    }
}

impl<T> TryKeyInit for EncapsulationKey<T>
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        let pk: [u8; 32] = (*key).into();
        // Encapsulation is infallible, so a bad key would silently produce a
        // broken/public shared secret there — validate at decode instead. Probe
        // with a fixed clamped scalar: a too-narrow backend errors, and a
        // low-order point gives an all-zero result (constant-time compared).
        let probe = x25519::<T>(&KEY_VALIDATION_SCALAR, &pk).map_err(|_| InvalidKey)?;
        if bool::from(probe.ct_eq(&[0u8; 32])) {
            return Err(InvalidKey);
        }
        Ok(Self {
            pk,
            _t: PhantomData,
        })
    }
}

impl<T> KeyExport for EncapsulationKey<T> {
    fn to_bytes(&self) -> Key<Self> {
        Array::from(self.pk)
    }
}

impl<T> Encapsulate for EncapsulationKey<T>
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    type Kem = X25519Kem<T>;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: CryptoRng + ?Sized,
    {
        // Fresh ephemeral scalar; clamped inside the ladder.
        let mut e = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(e.as_mut_slice());
        // ct = e·G, ss = e·pk, both blinded off the same RNG. `&mut &mut *rng`
        // reborrows the `?Sized` R as a `Sized` `&mut R`, which impls `CryptoRng`.
        // A too-narrow `T` can't surface through this infallible trait; it's
        // debug-asserted and fails closed in release (unreachable at ≥256 bits).
        let ct = x25519_base_blinded::<T, &mut R>(&mut &mut *rng, &e).unwrap_or_else(|_| {
            debug_assert!(false, "X25519 KEM backend must be ≥256 bits wide");
            [0u8; 32]
        });
        let ss = x25519_blinded::<T, &mut R>(&mut &mut *rng, &e, &self.pk).unwrap_or_else(|_| {
            debug_assert!(false, "X25519 KEM backend must be ≥256 bits wide");
            [0u8; 32]
        });
        (Array::from(ct), Array::from(ss))
    }
}

impl<T> Decapsulator for DecapsulationKey<T>
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    type Kem = X25519Kem<T>;

    fn encapsulation_key(&self) -> &EncapsulationKey<T> {
        &self.ek
    }
}

impl<T> TryDecapsulate for DecapsulationKey<T>
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    type Error = DecapsulateError;

    fn try_decapsulate(
        &self,
        ct: &Ciphertext<Self::Kem>,
    ) -> Result<SharedKey<Self::Kem>, DecapsulateError> {
        let ct_bytes: [u8; 32] = (*ct).into();
        let ss = x25519::<T>(&self.sk, &ct_bytes)?;
        // A low-order ciphertext yields an all-zero, publicly-known shared secret;
        // reject it (constant-time) so a forged ciphertext can't masquerade as a
        // valid encapsulation (RFC 7748 §6.1).
        if bool::from(ss.ct_eq(&[0u8; 32])) {
            return Err(DecapsulateError::LowOrderPoint);
        }
        Ok(Array::from(ss))
    }
}

impl<T> Generate for DecapsulationKey<T>
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut sk = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(sk.as_mut_slice())?;
        let pk = derive_public::<T>(&sk);
        Ok(Self {
            sk,
            ek: EncapsulationKey {
                pk,
                _t: PhantomData,
            },
        })
    }
}
