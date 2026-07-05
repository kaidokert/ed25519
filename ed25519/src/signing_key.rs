//! Ed25519 signing key and `sign` entry points (RFC 8032 §5.1.5–§5.1.6).
//!
//! The long-term seed expands into a clamped scalar `a` plus a nonce
//! prefix; both are secrets and both live in `Zeroizing` wrappers
//! whose `Drop` wipes the underlying bytes. Pubkey derivation runs
//! once at `from_seed` time so each subsequent `sign` call performs a
//! single scalar mult (for `R = r·G`) instead of two.

use crate::curve25519_field::{Curve25519FieldCt, CurveSetupError};
use crate::strict_sign::{
    base_point_ct, point_compress_ct, scalar_mult_ct, sha512, sha512_modq_ct,
};
use crate::{Q_BYTES, SignBackend, scalar_field};
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
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
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
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
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
    for<'a> &'a T: core::ops::Add<&'a T, Output = T> + core::ops::Sub<&'a T, Output = T>,
{
    let q = T::from_bytes_le(&Q_BYTES);

    // r = SHA-512(prefix || M) mod q. Secret-derived (prefix is part
    // of the expanded key); CT reduction required. `sha512_modq_ct`
    // returns `Zeroizing<T>` so r is wiped on drop.
    let r = sha512_modq_ct::<T>(&[&*sk.prefix, msg], &q);

    // R = r · G, compressed. Public after this point — but the
    // little-endian serialization of r passed to the ladder is still
    // the secret nonce, so the scratch buffer must be zeroized.
    let g = base_point_ct(p_field);
    let mut r_bytes = zeroize::Zeroizing::new([0u8; 64]);
    let r_bytes_slice = r.to_bytes_le(&mut *r_bytes);
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
    let a_t = zeroize::Zeroizing::new(T::from_bytes_le(&*sk.a_bytes));
    let r_res = q_field.reduce(&*r);
    let k_res = q_field.reduce(&*k);
    let a_res = q_field.reduce(&*a_t);
    let ka = q_field.mul(&k_res, &a_res);
    let s_res = q_field.add(&r_res, &ka);
    let s = q_field.into_raw(&s_res);

    // Serialize s to 32 bytes (s < q < 2^253, fits with leading zeros).
    let mut s_scratch = zeroize::Zeroizing::new([0u8; 64]);
    let s_bytes_slice = s.to_bytes_le(&mut *s_scratch);

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
