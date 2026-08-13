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
//! X25519 returns [`CurveSetupError`] for a backend too narrow to hold the
//! 256-bit prime. Width is a runtime property of the carrier, so there is no
//! const guard: decapsulation propagates the error, and encapsulation — whose
//! trait signature is infallible — fails closed to a zeroed output on that
//! path, which a ≥256-bit `T` never reaches.

use core::fmt;
use core::marker::PhantomData;

use kem::common::array::Array;
use kem::consts::U32;
use kem::{
    Ciphertext, Decapsulator, Encapsulate, Generate, InvalidKey, Kem, Key, KeyExport, KeyInit,
    KeySizeUser, SharedKey, TryDecapsulate, TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};
use zeroize::Zeroizing;

use crate::UnsignedModularInt;
use crate::curve25519_field::CurveSetupError;
use crate::x25519::{x25519, x25519_base, x25519_base_blinded, x25519_blinded};

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
        let pk = x25519_base::<T>(&sk).unwrap_or([0u8; 32]);
        Self {
            sk,
            ek: EncapsulationKey {
                pk,
                _t: PhantomData,
            },
        }
    }
}

impl<T> TryKeyInit for EncapsulationKey<T> {
    fn new(key: &Key<Self>) -> Result<Self, InvalidKey> {
        // Every 32-byte string is a valid X25519 u-coordinate (RFC 7748 §5).
        Ok(Self {
            pk: (*key).into(),
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
        let ct = x25519_base_blinded::<T, &mut R>(&mut &mut *rng, &e).unwrap_or([0u8; 32]);
        let ss = x25519_blinded::<T, &mut R>(&mut &mut *rng, &e, &self.pk).unwrap_or([0u8; 32]);
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
    type Error = CurveSetupError;

    fn try_decapsulate(
        &self,
        ct: &Ciphertext<Self::Kem>,
    ) -> Result<SharedKey<Self::Kem>, CurveSetupError> {
        let ct_bytes: [u8; 32] = (*ct).into();
        let ss = x25519::<T>(&self.sk, &ct_bytes)?;
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
        // Unblinded base mult for the public; fails closed on a too-narrow T
        // (a misconfiguration a ≥256-bit backend never hits).
        let pk = x25519_base::<T>(&sk).unwrap_or([0u8; 32]);
        Ok(Self {
            sk,
            ek: EncapsulationKey {
                pk,
                _t: PhantomData,
            },
        })
    }
}
