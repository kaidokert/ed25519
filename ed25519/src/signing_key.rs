//! Ed25519 signing key and `sign` entry points (RFC 8032 §5.1.5–§5.1.6).
//!
//! The long-term seed expands into a clamped scalar `a` plus a nonce
//! prefix; both are secrets and both live in `Zeroizing` wrappers
//! whose `Drop` wipes the underlying bytes. Pubkey derivation runs
//! once at `from_seed` time so each subsequent `sign` call performs a
//! single scalar mult (for `R = r·G`) instead of two.

use crate::curve25519_field::{Curve25519FieldCt, CurveSetupError};
use crate::strict_sign::{
    base_point_ct, point_compress_ct, scalar_mult_blinded_ct, scalar_mult_ct, sha512,
    sha512_modq_ct,
};
use crate::{P_BYTES, Q_BYTES, SignBackend, scalar_field};
use core::marker::PhantomData;
use modmath::FieldCt;

/// Errors from sign setup. `FieldSetup` covers the upstream
/// `CurveSetupError` from p-field or q-field construction; both arms
/// of `CurveSetupError` are unreachable for any well-formed backend,
/// but the `Result` shape keeps the panic-fmt symbol out of the
/// linked binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    FieldSetup(CurveSetupError),
    /// The caller's RNG failed while drawing blinding entropy for
    /// [`sign_blinded`]. Only the blinded path draws — deterministic
    /// [`sign`] never returns this.
    Rng,
}

impl From<CurveSetupError> for SignError {
    fn from(e: CurveSetupError) -> Self {
        SignError::FieldSetup(e)
    }
}

/// Ed25519 signing key. Holds the expanded clamped-scalar bytes and
/// nonce-prefix (`Zeroizing`-wiped on drop) plus the cached encoded
/// public key. The clamped scalar is stored as raw bytes rather than
/// as a typed `T` so the struct stays generic over the backend
/// without forcing `T: Zeroize` on the struct definition.
pub struct SigningKey<T> {
    /// Clamped scalar bytes derived from the seed. Long-term secret.
    a_bytes: zeroize::Zeroizing<[u8; 32]>,
    /// Nonce-derivation prefix from the seed. Long-term secret.
    prefix: zeroize::Zeroizing<[u8; 32]>,
    /// Compressed Edwards public key. Cached at construction.
    public: [u8; 32],
    _marker: PhantomData<T>,
}

impl<T> SigningKey<T>
where
    T: SignBackend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    /// Derive a signing key from a 32-byte seed (RFC 8032 §5.1.5).
    /// Runs `h = SHA-512(seed)`; splits into clamped scalar and nonce
    /// prefix; computes and caches the compressed public key.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, SignError> {
        let h = sha512(&[seed]);

        let mut a_bytes = zeroize::Zeroizing::new([0u8; 32]);
        a_bytes.copy_from_slice(&h[..32]);
        // RFC 8032 §5.1.5: clamp the low 32 bytes.
        a_bytes[0] &= 248;
        a_bytes[31] &= 127;
        a_bytes[31] |= 64;

        let mut prefix = zeroize::Zeroizing::new([0u8; 32]);
        prefix.copy_from_slice(&h[32..64]);

        // Cache the compressed pubkey: A = a·G then compress.
        let field = Curve25519FieldCt::<T>::curve25519()?;
        let g = base_point_ct(&field);
        let big_a = scalar_mult_ct(&field, &g, &*a_bytes);
        let public = point_compress_ct(&big_a, &field);

        Ok(SigningKey {
            a_bytes,
            prefix,
            public,
            _marker: PhantomData,
        })
    }

    /// Compressed Ed25519 public key (32 bytes).
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }
}

/// Sign `msg` under `sk`. Builds the p-field and q-field internally;
/// callers signing many messages with the same key should use
/// [`sign_with_fields`] to amortize construction.
pub fn sign<T>(sk: &SigningKey<T>, msg: &[u8]) -> Result<[u8; 64], SignError>
where
    T: SignBackend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    let p_field = Curve25519FieldCt::<T>::curve25519()?;
    let q_field = scalar_field::curve25519_ct::<T>()?;
    sign_with_fields(&p_field, &q_field, sk, msg)
}

/// Sign with pre-built p- and q-field instances. Amortizes the
/// Montgomery precompute across many signs against the same key.
pub fn sign_with_fields<T>(
    p_field: &Curve25519FieldCt<T>,
    q_field: &FieldCt<T>,
    sk: &SigningKey<T>,
    msg: &[u8],
) -> Result<[u8; 64], SignError>
where
    T: SignBackend,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    let q = crate::from_le_bytes::<T>(&Q_BYTES);

    // r = SHA-512(prefix || M) mod q. Secret-derived (prefix is part
    // of the expanded key); CT reduction required. `sha512_modq_ct`
    // returns `Zeroizing<T>` so r is wiped on drop.
    let r = sha512_modq_ct::<T>(&[&*sk.prefix, msg], &q);

    // R = r · G, compressed. Public after this point — but the
    // little-endian serialization of r passed to the ladder is still
    // the secret nonce. Route through `to_le_bytes_ct(&*r)` so no
    // owned `T` materializes off the `Zeroizing<T>` stack slot.
    let g = base_point_ct(p_field);
    let r_bytes = crate::to_le_bytes_ct(&*r);
    let r_bytes_slice: &[u8] = r_bytes.as_ref();
    let mut r_le = zeroize::Zeroizing::new([0u8; 32]);
    r_le.copy_from_slice(&r_bytes_slice[..32]);
    let r_point = scalar_mult_ct(p_field, &g, &*r_le);
    let r_encoded = point_compress_ct(&r_point, p_field);

    // k = SHA-512(R || A || M) mod q. Inputs are all public, but
    // running this through the CT helper keeps a single reduction
    // path; the per-sign cost is one mod-q reduction.
    let k = sha512_modq_ct::<T>(&[&r_encoded, &sk.public, msg], &q);

    // s = (r + k · a) mod q. Every operand is secret-derived; runs on
    // FieldCt over q.
    let a_t = zeroize::Zeroizing::new(crate::from_le_bytes::<T>(&*sk.a_bytes));
    let r_res = q_field.reduce(&*r);
    let k_res = q_field.reduce(&*k);
    let a_res = q_field.reduce(&*a_t);
    let ka = q_field.mul(&k_res, &a_res);
    let s_res = q_field.add(&r_res, &ka);
    let s = q_field.into_raw(&s_res);

    // Serialize s to 32 bytes (s < q < 2^253, fits with leading zeros).
    // s is public (part of the signature) but route through the same CT
    // path for uniformity — cost is one `Bytes` value on the stack, no `T` copy.
    let s_bytes = crate::to_le_bytes_ct(&s);
    let s_bytes_slice: &[u8] = s_bytes.as_ref();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_encoded);
    sig[32..64].copy_from_slice(&s_bytes_slice[..32]);
    Ok(sig)
}

/// `r + r₂·ℓ` fits in 36 bytes: `r₂ < 2³²` and `ℓ < 2²⁵³`, so `r₂·ℓ < 2²⁸⁵` and
/// `r + r₂·ℓ < 2²⁸⁶` — 36 bytes (288 bits) holds it.
const ED_BLINDED_SCALAR_BYTES: usize = 36;

/// Compute `r' = r + r₂·ℓ` little-endian, where `ℓ` is the Ed25519 group order
/// ([`Q_BYTES`]) and `r₂` is a 32-bit blinder. Since `ℓ·G = 𝒪`, `r'·G = r·G`,
/// but `r'` — wider and varying with `r₂` each sign — makes the fixed-base
/// ladder process a different bit pattern per execution, defeating DPA
/// averaging. Schoolbook in `u64`: a 32-bit `r₂` times a byte of `ℓ` is ≤ 2⁴⁰,
/// so no term overflows — a `u128` would only be needed for a 64-bit blinder,
/// which we avoid to keep AVR/Cortex-M0 off software 128-bit math. Matches the
/// x25519 blinded path's blinder width.
fn compute_blinded_ed_scalar(
    r_le: &[u8; 32],
    r2: u32,
) -> zeroize::Zeroizing<[u8; ED_BLINDED_SCALAR_BYTES]> {
    let mut out = zeroize::Zeroizing::new([0u8; ED_BLINDED_SCALAR_BYTES]);
    let r2 = r2 as u64;

    // out = r₂ · ℓ
    let mut carry: u64 = 0;
    for i in 0..32 {
        let prod = r2 * (Q_BYTES[i] as u64) + carry;
        out[i] = prod as u8;
        carry = prod >> 8;
    }
    for byte in out.iter_mut().skip(32) {
        carry += *byte as u64;
        *byte = carry as u8;
        carry >>= 8;
    }
    debug_assert_eq!(carry, 0);

    // out += r
    let mut c: u16 = 0;
    for (i, &rb) in r_le.iter().enumerate() {
        let s = (out[i] as u16) + (rb as u16) + c;
        out[i] = s as u8;
        c = s >> 8;
    }
    for byte in out.iter_mut().skip(32) {
        let s = (*byte as u16) + c;
        *byte = s as u8;
        c = s >> 8;
    }
    debug_assert_eq!(c, 0);

    out
}

/// Hedged, side-channel-blinded sign — the implementation behind
/// [`SigningKey`]'s [`signature::RandomizedSigner`] impl, which is the public
/// entry point. Builds the p- and q-fields per call; signing is rare enough
/// that batch amortization isn't worth a second public surface.
///
/// Unlike the deterministic [`sign`], the output is non-deterministic (a hedged
/// nonce) but still a standard RFC 8032 signature any verifier accepts.
/// Countermeasures, all driven by `rng`:
/// - **Hedged nonce.** `r = SHA-512(prefix ‖ Z ‖ M) mod ℓ` with a fresh 32-byte
///   `Z`. Randomizes the output per call; a weak or constant `Z` degrades to a
///   deterministic, message-dependent nonce (distinct from the RFC 8032 nonce,
///   which omits `Z`) — never to nonce reuse, so a broken RNG can't leak the key.
/// - **Scalar-blinded `r·G`.** `r' = r + r₂·ℓ` with a 64-bit `r₂` varies the
///   ladder scalar per sign; `r'·G = r·G`, so the signature is unchanged.
/// - **Projective re-randomization.** The ladder starts from a λ-scaled
///   identity, decorrelating intermediate coordinates.
/// - **Masked `k·a`.** The long-term scalar is additively split `a = a₁ + a₂
///   (mod ℓ)` so no modular multiply takes the bare secret as an operand.
///
/// The scalar/coordinate blinding is best-effort hardening against power/EM
/// differential analysis by a physical-access attacker. The constant-time
/// property is machine-checked; the blinding's effectiveness is **not** validated
/// by leakage (power-trace) measurement, which needs lab hardware. Deterministic
/// [`sign`] offers none of this and is the plain-`Signer` path.
///
/// Returns [`SignError::Rng`] if `rng` fails.
pub(crate) fn sign_blinded<T, R>(
    rng: &mut R,
    sk: &SigningKey<T>,
    msg: &[u8],
) -> Result<[u8; 64], SignError>
where
    T: SignBackend,
    R: rand_core::TryCryptoRng + ?Sized,
    for<'a> &'a T: const_num_traits::WrappingAdd<Output = T>
        + const_num_traits::WrappingSub<Output = T>
        + const_num_traits::ToBytes<Bytes = <T as const_num_traits::ToBytes>::Bytes>,
    <T as const_num_traits::ToBytes>::Bytes: zeroize::Zeroize,
{
    let p_field = Curve25519FieldCt::<T>::curve25519()?;
    let q_field = scalar_field::curve25519_ct::<T>()?;
    let p_field = &p_field;
    let q_field = &q_field;
    let q = crate::from_le_bytes::<T>(&Q_BYTES);

    // Hedged nonce.
    let mut z = zeroize::Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut *z).map_err(|_| SignError::Rng)?;
    let r = sha512_modq_ct::<T>(&[&*sk.prefix, &*z, msg], &q);

    // R = r·G, scalar-blinded with a projectively randomized ladder start.
    let r_bytes = crate::to_le_bytes_ct(&*r);
    let r_bytes_slice: &[u8] = r_bytes.as_ref();
    let mut r_le = zeroize::Zeroizing::new([0u8; 32]);
    r_le.copy_from_slice(&r_bytes_slice[..32]);
    let mut r2_bytes = [0u8; 4];
    rng.try_fill_bytes(&mut r2_bytes)
        .map_err(|_| SignError::Rng)?;
    let r_blinded = compute_blinded_ed_scalar(&r_le, u32::from_le_bytes(r2_bytes));

    // λ ∈ F_p \ {0}: mask the top bit, then CT-replace {0, p} (both reduce to 0
    // and degenerate the start) with 1.
    let mut lambda_bytes = zeroize::Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut *lambda_bytes)
        .map_err(|_| SignError::Rng)?;
    lambda_bytes[31] &= 0x7f;
    let p_t = crate::from_le_bytes::<T>(&P_BYTES);
    let mut lambda_t = zeroize::Zeroizing::new(crate::from_le_bytes::<T>(&*lambda_bytes));
    let is_zero = subtle::ConstantTimeEq::ct_eq(&*lambda_t, &T::zero());
    let is_p = subtle::ConstantTimeEq::ct_eq(&*lambda_t, &p_t);
    *lambda_t = T::conditional_select(&*lambda_t, &T::one(), is_zero | is_p);
    let lambda = p_field.reduce(&*lambda_t);

    let g = base_point_ct(p_field);
    let r_point = scalar_mult_blinded_ct(p_field, &g, &*r_blinded, &lambda);
    let r_encoded = point_compress_ct(&r_point, p_field);

    // k = SHA-512(R || A || M) mod q (public).
    let k = sha512_modq_ct::<T>(&[&r_encoded, &sk.public, msg], &q);

    // s = (r + k·a) mod q, with the k·a multiply additively masked.
    let a_t = zeroize::Zeroizing::new(crate::from_le_bytes::<T>(&*sk.a_bytes));
    let r_res = q_field.reduce(&*r);
    let k_res = q_field.reduce(&*k);
    let a_res = q_field.reduce(&*a_t);

    let mut mask_bytes = zeroize::Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(&mut *mask_bytes)
        .map_err(|_| SignError::Rng)?;
    mask_bytes[31] &= 0x7f;
    let a1 = q_field.reduce(&crate::from_le_bytes::<T>(&*mask_bytes));
    let a2 = q_field.sub(&a_res, &a1);
    let ka = q_field.add(&q_field.mul(&k_res, &a1), &q_field.mul(&k_res, &a2));
    let s_res = q_field.add(&r_res, &ka);
    let s = q_field.into_raw(&s_res);

    let s_bytes = crate::to_le_bytes_ct(&s);
    let s_bytes_slice: &[u8] = s_bytes.as_ref();

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_encoded);
    sig[32..64].copy_from_slice(&s_bytes_slice[..32]);
    Ok(sig)
}

#[cfg(all(test, feature = "fixed-bigint"))]
mod tests {
    use super::*;
    use fixed_bigint::FixedUInt;

    type T = FixedUInt<u32, 16, const_num_traits::Ct>;

    /// RFC 8032 §7.1 test vector 1.
    #[test]
    fn rfc8032_test_1() {
        let seed = hex_to_array("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public =
            hex_to_array("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_sig = hex_to_64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        let msg: &[u8] = &[];

        let sk = SigningKey::<T>::from_seed(&seed).expect("from_seed");
        assert_eq!(sk.public_key(), expected_public, "pubkey mismatch");

        let sig = sign(&sk, msg).expect("sign");
        assert_eq!(sig, expected_sig, "signature mismatch");
    }

    /// RFC 8032 §7.1 test vector 2.
    #[test]
    fn rfc8032_test_2() {
        let seed = hex_to_array("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let expected_public =
            hex_to_array("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let expected_sig = hex_to_64(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        let msg: &[u8] = &[0x72];

        let sk = SigningKey::<T>::from_seed(&seed).expect("from_seed");
        assert_eq!(sk.public_key(), expected_public);
        assert_eq!(sign(&sk, msg).expect("sign"), expected_sig);
    }

    /// RFC 8032 §7.1 test vector 3.
    #[test]
    fn rfc8032_test_3() {
        let seed = hex_to_array("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let expected_public =
            hex_to_array("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
        let expected_sig = hex_to_64(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );
        let msg: &[u8] = &[0xaf, 0x82];

        let sk = SigningKey::<T>::from_seed(&seed).expect("from_seed");
        assert_eq!(sk.public_key(), expected_public);
        assert_eq!(sign(&sk, msg).expect("sign"), expected_sig);
    }

    /// Non-Ct verify backend — signing is Ct, verify inputs are public.
    type V = FixedUInt<u32, 16, const_num_traits::Nct>;

    /// Seeded xorshift64 test RNG (nonzero state). Not a CSPRNG.
    struct XorRng(u64);
    impl XorRng {
        fn seeded(s: u64) -> Self {
            Self(s | 1)
        }
        fn step(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }
    impl rand_core::TryRng for XorRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.step() as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.step())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let b = self.step().to_le_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for XorRng {}

    /// Hedged + blinded sign: verifies, randomizes per RNG, and differs from
    /// the deterministic signature (the nonce is hedged).
    #[test]
    fn blinded_sign_verifies_hedged_and_valid() {
        let seed = hex_to_array("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let sk = SigningKey::<T>::from_seed(&seed).expect("from_seed");
        let pk = sk.public_key();
        let msg: &[u8] = &[0xaf, 0x82];

        let a = sign_blinded(&mut XorRng::seeded(1), &sk, msg).expect("sign_blinded a");
        let b = sign_blinded(&mut XorRng::seeded(2), &sk, msg).expect("sign_blinded b");
        // Hedged: distinct RNG streams → distinct signatures.
        assert_ne!(a, b);
        // Both are valid RFC 8032 signatures.
        assert!(crate::verify::<V>(pk, msg, a), "blinded sig a must verify");
        assert!(crate::verify::<V>(pk, msg, b), "blinded sig b must verify");
        // And neither matches the deterministic signature (hedged nonce).
        let det = sign(&sk, msg).expect("sign");
        assert_ne!(a, det);
        // A blinded signature must not verify against a different message.
        assert!(!crate::verify::<V>(pk, &[0x00], a));
    }

    /// A failing RNG surfaces as `SignError::Rng`, never a panic or a
    /// silently-unblinded signature.
    #[test]
    fn blinded_sign_propagates_rng_failure() {
        #[derive(Debug)]
        struct FailErr;
        impl core::fmt::Display for FailErr {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("rng failed")
            }
        }
        impl core::error::Error for FailErr {}

        struct FailRng;
        impl rand_core::TryRng for FailRng {
            type Error = FailErr;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Err(FailErr)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Err(FailErr)
            }
            fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Self::Error> {
                Err(FailErr)
            }
        }
        impl rand_core::TryCryptoRng for FailRng {}

        let sk = SigningKey::<T>::from_seed(&[7u8; 32]).expect("from_seed");
        assert_eq!(sign_blinded(&mut FailRng, &sk, b"m"), Err(SignError::Rng));
    }

    /// Max blinder `r₂ = u32::MAX` (all-ones RNG) drives the top of the 36-byte
    /// `r + r₂·ℓ` carry chain — must not panic and must still verify.
    #[test]
    fn blinded_sign_max_blinder_verifies() {
        struct OnesRng;
        impl rand_core::TryRng for OnesRng {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(u32::MAX)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(u64::MAX)
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                dst.fill(0xff);
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for OnesRng {}

        let sk = SigningKey::<T>::from_seed(&[9u8; 32]).expect("from_seed");
        let msg: &[u8] = b"max blinder";
        let sig = sign_blinded(&mut OnesRng, &sk, msg).expect("sign_blinded");
        assert!(crate::verify::<V>(sk.public_key(), msg, sig));
    }

    /// The blinded signature is carrier-independent: the same key + RNG stream
    /// yields an identical signature on the u32×16 and u8×64 backends.
    #[test]
    fn blinded_sign_matches_across_carriers() {
        type T8 = FixedUInt<u8, 64, const_num_traits::Ct>;
        let seed = hex_to_array("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
        let msg: &[u8] = &[0xaf, 0x82];

        let sk32 = SigningKey::<T>::from_seed(&seed).expect("from_seed u32");
        let sk8 = SigningKey::<T8>::from_seed(&seed).expect("from_seed u8");
        let sig32 = sign_blinded(&mut XorRng::seeded(42), &sk32, msg).expect("sign u32");
        let sig8 = sign_blinded(&mut XorRng::seeded(42), &sk8, msg).expect("sign u8");
        assert_eq!(sig32, sig8, "blinded signature must be carrier-independent");
        assert!(crate::verify::<V>(sk32.public_key(), msg, sig32));
    }

    fn hex_to_array(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    fn hex_to_64(s: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}
