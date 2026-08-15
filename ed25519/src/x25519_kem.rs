//! X25519 as a key-encapsulation mechanism ([`kem::Kem`]).
//!
//! DH-KEM shape: an [`EncapsulationKey`] holds a peer's X25519 public
//! u-coordinate. Encapsulation picks an ephemeral scalar `e`, returns `e·G` as
//! the ciphertext and `e·pk` as the shared key; decapsulation with secret `sk`
//! recovers `sk·(e·G) = e·pk`.
//!
//! **Blinding is a personality** [`B: Blinding`](Blinding), defaulting to
//! [`Unblinded`]:
//!
//! - [`X25519Kem<T>`] (= `X25519Kem<T, Unblinded>`) — plain ladder, reusable key,
//!   fast. The default.
//! - [`X25519Kem<T, Blinded>`] — scalar + projective blinding on both directions,
//!   and the decapsulation key is **single-use**: it stores a fixed blinder drawn
//!   at generation and spends it once (a fixed blind is only sound single-use), so
//!   a second decapsulate refuses. This fits ephemeral KX (generate → one DH →
//!   drop) and hardens against power/EM analysis.
//!
//! `B` gates on a compile-time [`Blinding::BLIND`], so the `Unblinded`
//! monomorphization strips the blinder draws, the blinded ladder, and the latch
//! entirely. Ciphertext/shared-secret shapes don't depend on `B`, so a `Blinded`
//! encapsulator and an `Unblinded` decapsulator still interoperate on the wire.
//!
//! `T` must be wide enough to hold the 256-bit prime — a runtime property of the
//! carrier, so there is no const guard. Decode ([`TryKeyInit`]) and decapsulation
//! propagate [`CurveSetupError`] on a too-narrow `T`; the infallible
//! key-generation and encapsulation paths `debug_assert` the width and fail closed
//! to a zeroed output in release. A ≥256-bit `T` reaches none of these paths.
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

mod sealed {
    pub trait Sealed {}
}

/// Per-key blinder storage, carried by [`Blinding::State`]. [`Unblinded`] uses the
/// zero-sized `()` (so the key stays `Sync` with no blinder state); [`Blinded`]
/// uses [`Blinders`]. The accessors are only ever reached under `BLIND`, so `()`'s
/// are inert placeholders stripped at monomorphization.
#[doc(hidden)]
pub trait BlindState: Sized {
    /// Draw the blinders from the generation RNG (a no-op for `()`).
    fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error>;
    /// 32-bit scalar blinder `r`.
    fn scalar_blind(&self) -> u32;
    /// Projective blinder `λ`.
    fn coord_blind(&self) -> [u8; 32];
    /// Claim the one-shot latch; `true` if already spent (`()` never spends).
    fn claim(&self) -> bool;
}

impl BlindState for () {
    fn generate<R: TryCryptoRng + ?Sized>(_: &mut R) -> Result<Self, R::Error> {
        Ok(())
    }
    fn scalar_blind(&self) -> u32 {
        0
    }
    fn coord_blind(&self) -> [u8; 32] {
        [0u8; 32]
    }
    fn claim(&self) -> bool {
        false
    }
}

/// Fixed DPA blinders + one-shot latch for a [`Blinded`] decapsulation key. The
/// `Cell` (not `AtomicBool`, which the no-atomic MCU targets thumbv6m/AVR/riscv32imc
/// lack) makes a `Blinded` key `!Sync` — fine for a one-shot ephemeral key. An
/// `Unblinded` key carries none of this and stays `Sync`.
#[doc(hidden)]
pub struct Blinders {
    scalar_blind: Zeroizing<[u8; 4]>,
    coord_blind: Zeroizing<[u8; 32]>,
    spent: Cell<bool>,
}

impl BlindState for Blinders {
    fn generate<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        // A weak blinder only weakens masking, never correctness, so no rejection.
        let mut scalar_blind = Zeroizing::new([0u8; 4]);
        let mut coord_blind = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(scalar_blind.as_mut_slice())?;
        rng.try_fill_bytes(coord_blind.as_mut_slice())?;
        Ok(Self {
            scalar_blind,
            coord_blind,
            spent: Cell::new(false),
        })
    }
    fn scalar_blind(&self) -> u32 {
        u32::from_le_bytes(*self.scalar_blind)
    }
    fn coord_blind(&self) -> [u8; 32] {
        *self.coord_blind
    }
    fn claim(&self) -> bool {
        self.spent.replace(true)
    }
}

/// Blinding personality of the X25519 KEM — a sealed type-level tag selecting the
/// [`Unblinded`] or [`Blinded`] engine. Gated at [`BLIND`](Blinding::BLIND), a
/// compile-time const, so the unused path is stripped at monomorphization; the
/// blinder storage lives in [`State`](Blinding::State), so `Unblinded` carries none.
pub trait Blinding: sealed::Sealed + 'static {
    /// Whether this personality blinds the ladder and makes the key single-use.
    const BLIND: bool;
    /// Per-key blinder storage — `()` for `Unblinded`, [`Blinders`] for `Blinded`.
    #[doc(hidden)]
    type State: BlindState;
}

/// Unblinded personality (default): plain ladder, reusable `Sync` decapsulation key.
pub enum Unblinded {}
/// Blinded personality: DPA-hardened ladder, single-use (`!Sync`) decapsulation key.
pub enum Blinded {}

impl sealed::Sealed for Unblinded {}
impl sealed::Sealed for Blinded {}
impl Blinding for Unblinded {
    const BLIND: bool = false;
    type State = ();
}
impl Blinding for Blinded {
    const BLIND: bool = true;
    type State = Blinders;
}

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
    /// The decapsulation key was already spent. Only a [`Blinded`] key is
    /// single-use; it carries a fixed DPA blinder sound only for one decapsulation.
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

/// KEM marker for X25519 over backend `T` and blinding personality `B`. Zero-sized;
/// `PhantomData<fn() -> (T, B)>` keeps its auto-traits independent of `T`/`B`.
pub struct X25519Kem<T, B = Unblinded>(PhantomData<fn() -> (T, B)>);

impl<T, B> Clone for X25519Kem<T, B> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T, B> Copy for X25519Kem<T, B> {}
impl<T, B> fmt::Debug for X25519Kem<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519Kem")
    }
}
impl<T, B> Default for X25519Kem<T, B> {
    fn default() -> Self {
        Self(PhantomData)
    }
}
impl<T, B> PartialEq for X25519Kem<T, B> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl<T, B> Eq for X25519Kem<T, B> {}
impl<T, B> PartialOrd for X25519Kem<T, B> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T, B> Ord for X25519Kem<T, B> {
    fn cmp(&self, _: &Self) -> core::cmp::Ordering {
        core::cmp::Ordering::Equal
    }
}

/// X25519 public key (peer u-coordinate) — the encapsulation key.
pub struct EncapsulationKey<T, B = Unblinded> {
    pk: [u8; 32],
    _tb: PhantomData<fn() -> (T, B)>,
}

impl<T, B> Clone for EncapsulationKey<T, B> {
    fn clone(&self) -> Self {
        Self {
            pk: self.pk,
            _tb: PhantomData,
        }
    }
}
impl<T, B> fmt::Debug for EncapsulationKey<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncapsulationKey").finish_non_exhaustive()
    }
}
impl<T, B> PartialEq for EncapsulationKey<T, B> {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
}
impl<T, B> Eq for EncapsulationKey<T, B> {}

/// X25519 secret key with its public — the decapsulation key. `sk` (and the
/// blinders, for `Blinded`) are wiped on drop via [`Zeroizing`].
///
/// For `B = `[`Blinded`] it is **one-shot**: [`state`](Blinders) holds fixed DPA
/// blinders drawn at generation and spent by the first
/// [`TryDecapsulate::try_decapsulate`] (a fixed blind is only sound single-use);
/// the `Cell` latch makes it `!Sync`. For `B = `[`Unblinded`] the state is `()`, so
/// the key carries no blinder storage and stays reusable and `Sync`.
pub struct DecapsulationKey<T, B: Blinding = Unblinded> {
    sk: Zeroizing<[u8; 32]>,
    ek: EncapsulationKey<T, B>,
    state: B::State,
}

impl<T, B: Blinding> fmt::Debug for DecapsulationKey<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecapsulationKey").finish_non_exhaustive()
    }
}

impl<T, B> Kem for X25519Kem<T, B>
where
    T: X25519Backend,
    B: Blinding,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    type DecapsulationKey = DecapsulationKey<T, B>;
    type EncapsulationKey = EncapsulationKey<T, B>;
    type SharedKeySize = U32;
    type CiphertextSize = U32;
}

impl<T, B> KeySizeUser for EncapsulationKey<T, B> {
    type KeySize = U32;
}

impl<T, B: Blinding> KeySizeUser for DecapsulationKey<T, B> {
    type KeySize = U32;
}

impl<T, B> TryKeyInit for EncapsulationKey<T, B>
where
    T: X25519Backend,
    B: Blinding,
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
            _tb: PhantomData,
        })
    }
}

impl<T, B> KeyExport for EncapsulationKey<T, B> {
    fn to_bytes(&self) -> Key<Self> {
        Array::from(self.pk)
    }
}

impl<T, B> Encapsulate for EncapsulationKey<T, B>
where
    T: X25519Backend,
    B: Blinding,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    type Kem = X25519Kem<T, B>;

    fn encapsulate_with_rng<R>(&self, rng: &mut R) -> (Ciphertext<Self::Kem>, SharedKey<Self::Kem>)
    where
        R: CryptoRng + ?Sized,
    {
        // Fresh ephemeral scalar (drawn regardless of B); clamped inside the ladder.
        let mut e = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(e.as_mut_slice());
        let fail = || {
            debug_assert!(false, "X25519 KEM backend must be ≥256 bits wide");
            [0u8; 32]
        };
        let (ct, ss) = if B::BLIND {
            // ct = e·G, ss = e·pk, both blinded off the same RNG. `&mut &mut *rng`
            // reborrows the `?Sized` R as a `Sized` `&mut R`, which impls `CryptoRng`.
            let ct =
                x25519_base_blinded::<T, &mut R>(&mut &mut *rng, &e).unwrap_or_else(|_| fail());
            let ss = x25519_blinded::<T, &mut R>(&mut &mut *rng, &e, &self.pk)
                .unwrap_or_else(|_| fail());
            (ct, ss)
        } else {
            let ct = x25519_base::<T>(&e).unwrap_or_else(|_| fail());
            let ss = x25519::<T>(&e, &self.pk).unwrap_or_else(|_| fail());
            (ct, ss)
        };
        (Array::from(ct), Array::from(ss))
    }
}

impl<T, B> Decapsulator for DecapsulationKey<T, B>
where
    T: X25519Backend,
    B: Blinding,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    type Kem = X25519Kem<T, B>;

    fn encapsulation_key(&self) -> &EncapsulationKey<T, B> {
        &self.ek
    }
}

impl<T, B> TryDecapsulate for DecapsulationKey<T, B>
where
    T: X25519Backend,
    B: Blinding,
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
        let ss = if B::BLIND {
            // Reject a low-order ciphertext (RFC 7748 §6.1) before claiming the key,
            // so a forged ct can't burn the one-shot. Probes with a public scalar.
            if is_low_order_u::<T>(&ct_bytes)? {
                return Err(DecapsulateError::LowOrderPoint);
            }
            // Claim the key before the ladder: a second decapsulate refuses rather
            // than rerun under the same (r, λ) and let power traces be averaged.
            if self.state.claim() {
                return Err(DecapsulateError::Spent);
            }
            x25519_blinded_from_parts::<T>(
                &self.sk,
                &ct_bytes,
                self.state.scalar_blind(),
                &self.state.coord_blind(),
            )?
        } else {
            // Reusable plain decapsulate.
            x25519::<T>(&self.sk, &ct_bytes)?
        };
        // A low-order ciphertext yields the all-zero (publicly known) shared secret;
        // reject it so a forged ciphertext can't masquerade as a valid encapsulation.
        if bool::from(ss.ct_eq(&[0u8; 32])) {
            return Err(DecapsulateError::LowOrderPoint);
        }
        Ok(Array::from(ss))
    }
}

impl<T, B> Generate for DecapsulationKey<T, B>
where
    T: X25519Backend,
    B: Blinding,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        let mut sk = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(sk.as_mut_slice())?;
        let pk = derive_public::<T>(&sk);
        // `()` draws nothing; `Blinders` draws the scalar + projective blinder.
        let state = <B::State as BlindState>::generate(rng)?;
        Ok(Self {
            sk,
            ek: EncapsulationKey {
                pk,
                _tb: PhantomData,
            },
            state,
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

    fn key_from_sk<B: Blinding>(sk_bytes: [u8; 32], state: B::State) -> DecapsulationKey<T, B> {
        let sk = Zeroizing::new(sk_bytes);
        let pk = derive_public::<T>(&sk);
        DecapsulationKey {
            sk,
            ek: EncapsulationKey {
                pk,
                _tb: PhantomData,
            },
            state,
        }
    }

    // RFC 7748 §5.2 vector 1 through the Unblinded decapsulate (plain sk · ct).
    #[test]
    fn rfc7748_vector_through_decapsulate() {
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        let dk = key_from_sk::<Unblinded>(scalar, ());
        let ct: Ciphertext<X25519Kem<T>> = u.into();
        let ss = dk.try_decapsulate(&ct).expect("decapsulate");
        assert_eq!(ss.as_slice(), expected.as_slice());
    }

    // Blinded decapsulate with nonzero blinders equals the plain ladder.
    #[test]
    fn blinded_decapsulate_matches_unblinded() {
        let sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let dk = key_from_sk::<Blinded>(
            sk,
            Blinders {
                scalar_blind: Zeroizing::new([0x11, 0x22, 0x33, 0x44]),
                coord_blind: Zeroizing::new([0x9au8; 32]),
                spent: Cell::new(false),
            },
        );
        let ct: Ciphertext<X25519Kem<T, Blinded>> = u.into();
        let blinded = dk.try_decapsulate(&ct).expect("decapsulate");
        let unblinded = x25519::<T>(&sk, &u).unwrap();
        assert_eq!(blinded.as_slice(), unblinded.as_slice());
    }
}
