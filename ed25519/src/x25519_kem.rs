//! X25519 as a key-encapsulation mechanism ([`kem::Kem`]).
//!
//! DH-KEM shape: an [`EncapsulationKey`] holds a peer's X25519 public
//! u-coordinate. Encapsulation picks an ephemeral scalar `e`, returns `e·G` as
//! the ciphertext and `e·pk` as the shared key; decapsulation with secret `sk`
//! recovers `sk·(e·G) = e·pk`.
//!
//! Both directions are blinded. Encapsulation draws a fresh `CryptoRng` per call
//! ([`x25519_base_blinded`] for the ciphertext, [`x25519_blinded`] for the shared
//! key) — inherently fresh-per-call and single-use. Decapsulation's
//! [`TryDecapsulate`] carries no per-call RNG, so the [`DecapsulationKey`] instead
//! stores fixed blinders drawn at generation and spends them **once**: a fixed
//! blind is only sound single-use, so a second decapsulate refuses. This fits
//! X25519 KX, where keys are ephemeral (generate → one DH → drop).
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

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;

use kem::common::array::Array;
use kem::consts::U32;
use kem::{
    Ciphertext, Decapsulator, Encapsulate, Generate, InvalidKey, Kem, Key, KeyExport, KeySizeUser,
    SharedKey, TryDecapsulate, TryKeyInit,
};
use rand_core::{CryptoRng, TryCryptoRng};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::UnsignedModularInt;
use crate::curve25519_field::CurveSetupError;
use crate::x25519::{
    x25519, x25519_base, x25519_base_blinded, x25519_blinded, x25519_blinded_from_parts,
};

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
    /// The decapsulation key was already spent. It carries a fixed DPA blinder
    /// sound only for a single decapsulation, so it is one-shot by design.
    Spent,
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
            Self::Spent => "decapsulation key already spent (single-use)",
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

/// True when `u` is a low-order point — `x25519(KEY_VALIDATION_SCALAR, u)` is the
/// all-zero (publicly known) shared secret. The probe scalar is fixed and
/// non-secret, so this is safe on attacker-supplied input; `Err` propagates a
/// too-narrow backend.
fn is_low_order_u<T>(u: &[u8; 32]) -> Result<bool, CurveSetupError>
where
    T: X25519Backend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    let probe = x25519::<T>(&KEY_VALIDATION_SCALAR, u)?;
    Ok(bool::from(probe.ct_eq(&[0u8; 32])))
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

/// X25519 secret key with its public — the decapsulation key. `sk` and the
/// blinders are wiped on drop via [`Zeroizing`].
///
/// One-shot: it carries fixed DPA blinders (`scalar_blind` r, `coord_blind` λ)
/// drawn at generation and spent by the first [`TryDecapsulate::try_decapsulate`].
/// A fixed blind is only sound single-use — reusing it would let power traces be
/// averaged against one constant ladder scalar — so a second decapsulate refuses.
/// This suits X25519 KX, where keys are ephemeral (generate → one DH → drop).
pub struct DecapsulationKey<T> {
    sk: Zeroizing<[u8; 32]>,
    ek: EncapsulationKey<T>,
    scalar_blind: Zeroizing<[u8; 4]>,
    coord_blind: Zeroizing<[u8; 32]>,
    /// One-shot latch. A `Cell`, not an `AtomicBool`: the no-atomic MCU targets
    /// (thumbv6m, AVR, riscv32imc) lack atomic read-modify-write. The key is
    /// thus `!Sync`, immaterial for a one-shot ephemeral key never shared across
    /// threads (it stays `Send`).
    spent: Cell<bool>,
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
        // broken/public shared secret there — validate at decode instead. A
        // too-narrow backend errors; a low-order point is rejected.
        if is_low_order_u::<T>(&pk).map_err(|_| InvalidKey)? {
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
        // Reject a low-order ciphertext (RFC 7748 §6.1) before claiming the key,
        // so a forged ct can't burn the one-shot. Probes with a public scalar —
        // no secret involved.
        if is_low_order_u::<T>(&ct_bytes)? {
            return Err(DecapsulateError::LowOrderPoint);
        }
        // Claim the key before the ladder runs: a second decapsulate refuses
        // rather than rerun under the same (r, λ) and let power traces be
        // averaged against one constant scalar.
        if self.spent.replace(true) {
            return Err(DecapsulateError::Spent);
        }
        let r = u32::from_le_bytes(*self.scalar_blind);
        let ss = x25519_blinded_from_parts::<T>(&self.sk, &ct_bytes, r, &self.coord_blind)?;
        // Backstop for any low-order point the pre-check missed.
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
        // DPA blinders spent once at decapsulate, drawn from the same generation
        // RNG. A weak blinder only weakens masking, never correctness, so no
        // rejection is needed.
        let mut scalar_blind = Zeroizing::new([0u8; 4]);
        let mut coord_blind = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(scalar_blind.as_mut_slice())?;
        rng.try_fill_bytes(coord_blind.as_mut_slice())?;
        Ok(Self {
            sk,
            ek: EncapsulationKey {
                pk,
                _t: PhantomData,
            },
            scalar_blind,
            coord_blind,
            spent: Cell::new(false),
        })
    }
}

#[cfg(all(test, feature = "fixed-bigint"))]
mod tests {
    use super::*;
    use fixed_bigint::FixedUInt;

    type T = FixedUInt<u32, 8, const_num_traits::Ct>;

    fn hex32(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn key_from_sk(
        sk_bytes: [u8; 32],
        scalar_blind: [u8; 4],
        coord_blind: [u8; 32],
    ) -> DecapsulationKey<T> {
        let sk = Zeroizing::new(sk_bytes);
        let pk = derive_public::<T>(&sk);
        DecapsulationKey {
            sk,
            ek: EncapsulationKey {
                pk,
                _t: PhantomData,
            },
            scalar_blind: Zeroizing::new(scalar_blind),
            coord_blind: Zeroizing::new(coord_blind),
            spent: Cell::new(false),
        }
    }

    // RFC 7748 §5.2 vector 1: scalar · u = output. Decapsulation is sk · ct, so
    // loading sk = scalar and decapsulating ct = u reproduces the vector. Zero
    // blinders (r = 0, λ guarded to 1) make the blinded ladder match unblinded.
    #[test]
    fn rfc7748_vector_through_decapsulate() {
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        let dk = key_from_sk(scalar, [0u8; 4], [0u8; 32]);
        let ct: Ciphertext<X25519Kem<T>> = u.into();
        let ss = dk.try_decapsulate(&ct).expect("decapsulate");
        assert_eq!(ss.as_slice(), expected.as_slice());
    }

    // Nonzero blinders must not change the result: blinded decapsulate equals the
    // plain unblinded ladder for the same (sk, ct).
    #[test]
    fn blinded_decapsulate_matches_unblinded() {
        let sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let dk = key_from_sk(sk, [0x11, 0x22, 0x33, 0x44], [0x9au8; 32]);
        let ct: Ciphertext<X25519Kem<T>> = u.into();
        let blinded = dk.try_decapsulate(&ct).expect("decapsulate");
        let unblinded = x25519::<T>(&sk, &u).unwrap();
        assert_eq!(blinded.as_slice(), unblinded.as_slice());
    }
}
